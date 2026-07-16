use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use jsonwebtoken::{decode, decode_header, jwk::Jwk, DecodingKey, Validation};
use reqwest::{redirect::Policy, Client};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::error::{Oid4vciError, Oid4vciResult};

const CANVAS_OPENID_CONFIGURATION_PATH: &str = "/.well-known/openid-configuration";
const MAX_OPENID_CONFIGURATION_BYTES: u64 = 1024 * 1024;
const MAX_JWKS_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanvasLtiPlatformProbe {
    pub canvas_base_url: String,
    pub issuer: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub jwks_uri: String,
    pub registration_endpoint: Option<String>,
    pub raw_openid_configuration: Value,
    pub jwks_json: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedLtiLaunch {
    pub issuer: String,
    pub subject: String,
    pub audience: Vec<String>,
    pub deployment_id: String,
    pub nonce: Option<String>,
    pub issued_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub message_type: Option<String>,
    pub lti_version: Option<String>,
    pub target_link_uri: Option<String>,
    pub context: Option<Value>,
    pub roles: Vec<String>,
    pub learner_identity: Value,
    pub raw_claims: Value,
}

#[derive(Debug, Clone, Deserialize)]
struct CanvasOpenIdConfiguration {
    issuer: String,
    jwks_uri: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    registration_endpoint: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct LtiLaunchClaims {
    iss: String,
    sub: String,
    aud: Value,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/deployment_id")]
    deployment_id: String,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/context", default)]
    context: Option<Value>,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/roles", default)]
    roles: Option<Vec<String>>,
    #[serde(
        rename = "https://purl.imsglobal.org/spec/lti/claim/target_link_uri",
        default
    )]
    target_link_uri: Option<String>,
    #[serde(
        rename = "https://purl.imsglobal.org/spec/lti/claim/message_type",
        default
    )]
    message_type: Option<String>,
    #[serde(rename = "https://purl.imsglobal.org/spec/lti/claim/version", default)]
    lti_version: Option<String>,
}

fn invalid_request(message: impl Into<String>) -> Oid4vciError {
    Oid4vciError::InvalidRequest(message.into())
}

fn decode_audience(aud: &Value) -> Oid4vciResult<Vec<String>> {
    match aud {
        Value::String(single) => Ok(vec![single.clone()]),
        Value::Array(values) => {
            let mut audience = Vec::with_capacity(values.len());
            for value in values {
                let item = value
                    .as_str()
                    .ok_or_else(|| invalid_request("LTI audience entries must be strings"))?;
                audience.push(item.to_string());
            }
            if audience.is_empty() {
                return Err(invalid_request("LTI audience claim must not be empty"));
            }
            Ok(audience)
        }
        _ => Err(invalid_request(
            "LTI audience claim must be a string or string array",
        )),
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4 == Ipv4Addr::UNSPECIFIED
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || ((v6.segments()[0] & 0xfe00) == 0xfc00)
                || ((v6.segments()[0] & 0xffc0) == 0xfe80)
                || v6.is_multicast()
                || v6 == Ipv6Addr::LOCALHOST
        }
    }
}

fn is_loopback_hostname(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
}

fn validate_url(
    url: &Url,
    allow_private_networks: bool,
    allow_http_localhost: bool,
    require_origin_only: bool,
) -> Oid4vciResult<()> {
    match url.scheme() {
        "https" => {}
        "http" if allow_http_localhost => {}
        _ => {
            return Err(invalid_request(
                "Canvas URLs must use HTTPS, or HTTP localhost when explicitly enabled",
            ))
        }
    }

    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid_request(
            "Canvas URLs must not include query strings or fragments",
        ));
    }

    if require_origin_only && !(url.path().is_empty() || url.path() == "/") {
        return Err(invalid_request(
            "Canvas base URL must be an origin without a path segment",
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| invalid_request("Canvas URL must include a host"))?;

    if url.scheme() == "http" && !is_loopback_hostname(host) && host != "127.0.0.1" && host != "::1"
    {
        return Err(invalid_request(
            "HTTP Canvas URLs are only allowed for localhost in sandbox mode",
        ));
    }

    if is_loopback_hostname(host)
        && !allow_private_networks
        && !(allow_http_localhost && url.scheme() == "http")
    {
        return Err(invalid_request(
            "Canvas URL points to localhost but localhost access is disabled in hardened mode",
        ));
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip)
            && !allow_private_networks
            && !(allow_http_localhost && ip.is_loopback() && url.scheme() == "http")
        {
            return Err(invalid_request(
                "Canvas URL resolves to a private or loopback IP that is blocked in hardened mode",
            ));
        }
    }

    Ok(())
}

fn normalize_url(
    url_str: &str,
    allow_private_networks: bool,
    allow_http_localhost: bool,
    require_origin_only: bool,
) -> Oid4vciResult<String> {
    let trimmed = url_str.trim();
    if trimmed.is_empty() {
        return Err(invalid_request("Canvas URL is required"));
    }

    let mut url = Url::parse(trimmed)?;
    validate_url(
        &url,
        allow_private_networks,
        allow_http_localhost,
        require_origin_only,
    )?;

    if require_origin_only {
        url.set_path("/");
    } else {
        let normalized_path = url.path().trim_end_matches('/').to_string();
        if normalized_path.is_empty() {
            url.set_path("/");
        } else {
            url.set_path(&normalized_path);
        }
    }

    let mut normalized = url.to_string();
    if normalized.ends_with('/') {
        normalized.pop();
    }
    Ok(normalized)
}

async fn validate_resolved_host(
    url: &Url,
    allow_private_networks: bool,
    allow_http_localhost: bool,
) -> Oid4vciResult<()> {
    if allow_private_networks {
        return Ok(());
    }

    let host = url
        .host_str()
        .ok_or_else(|| invalid_request("Canvas URL must include a host"))?;

    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid_request("Canvas URL must include a resolvable port"))?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| invalid_request(format!("Failed to resolve Canvas host {host}: {e}")))?;

    let mut resolved_any = false;
    for address in addresses {
        resolved_any = true;
        let ip = address.ip();
        let allowed_localhost = allow_http_localhost
            && url.scheme() == "http"
            && ip.is_loopback()
            && is_loopback_hostname(host);
        if is_private_ip(ip) && !allowed_localhost {
            return Err(invalid_request(
                "Canvas host resolves to a private or loopback IP that is blocked in hardened mode",
            ));
        }
    }

    if !resolved_any {
        return Err(invalid_request(format!(
            "Canvas host {host} did not resolve to any addresses"
        )));
    }

    Ok(())
}

pub fn normalize_canvas_base_url(
    base_url: &str,
    allow_private_networks: bool,
    allow_http_localhost: bool,
) -> Oid4vciResult<String> {
    normalize_url(base_url, allow_private_networks, allow_http_localhost, true)
}

async fn fetch_limited_json(
    client: &Client,
    url: &str,
    label: &str,
    max_bytes: u64,
) -> Oid4vciResult<Value> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| invalid_request(format!("Failed to fetch Canvas {label}: {e}")))?;

    if response.status().is_redirection() {
        return Err(invalid_request(format!(
            "Canvas {label} returned a redirect; redirects are not allowed"
        )));
    }

    let response = response
        .error_for_status()
        .map_err(|e| invalid_request(format!("Canvas {label} returned an error: {e}")))?;

    if response
        .content_length()
        .is_some_and(|content_length| content_length > max_bytes)
    {
        return Err(invalid_request(format!(
            "Canvas {label} exceeds maximum response size"
        )));
    }

    let body = response
        .bytes()
        .await
        .map_err(|e| invalid_request(format!("Failed to read Canvas {label}: {e}")))?;
    if body.len() as u64 > max_bytes {
        return Err(invalid_request(format!(
            "Canvas {label} exceeds maximum response size"
        )));
    }

    serde_json::from_slice(&body)
        .map_err(|e| invalid_request(format!("Failed to decode Canvas {label}: {e}")))
}

pub async fn probe_canvas_lti_platform(
    base_url: &str,
    timeout_seconds: u64,
    allow_private_networks: bool,
    allow_http_localhost: bool,
) -> Oid4vciResult<CanvasLtiPlatformProbe> {
    let normalized_base_url =
        normalize_canvas_base_url(base_url, allow_private_networks, allow_http_localhost)?;
    let configuration_url = format!("{normalized_base_url}{CANVAS_OPENID_CONFIGURATION_PATH}");
    let parsed_configuration_url = Url::parse(&configuration_url)?;
    validate_resolved_host(
        &parsed_configuration_url,
        allow_private_networks,
        allow_http_localhost,
    )
    .await?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_seconds.max(1)))
        .redirect(Policy::none())
        .build()
        .map_err(|e| Oid4vciError::ConfigError(e.to_string()))?;

    let openid_configuration: Value = fetch_limited_json(
        &client,
        &configuration_url,
        "OpenID configuration",
        MAX_OPENID_CONFIGURATION_BYTES,
    )
    .await?;

    let parsed_configuration: CanvasOpenIdConfiguration =
        serde_json::from_value(openid_configuration.clone()).map_err(|e| {
            invalid_request(format!(
                "Canvas OpenID configuration is missing required fields: {e}"
            ))
        })?;

    let normalized_issuer = normalize_url(
        &parsed_configuration.issuer,
        allow_private_networks,
        allow_http_localhost,
        false,
    )?;
    let normalized_jwks_uri = normalize_url(
        &parsed_configuration.jwks_uri,
        allow_private_networks,
        allow_http_localhost,
        false,
    )?;
    let parsed_jwks_uri = Url::parse(&normalized_jwks_uri)?;
    validate_resolved_host(
        &parsed_jwks_uri,
        allow_private_networks,
        allow_http_localhost,
    )
    .await?;

    let jwks_json: Value =
        fetch_limited_json(&client, &normalized_jwks_uri, "JWKS", MAX_JWKS_BYTES).await?;

    if jwks_json
        .get("keys")
        .and_then(Value::as_array)
        .map_or(true, |keys| keys.is_empty())
    {
        return Err(invalid_request("Canvas JWKS does not include any keys"));
    }

    Ok(CanvasLtiPlatformProbe {
        canvas_base_url: normalized_base_url,
        issuer: normalized_issuer,
        authorization_endpoint: parsed_configuration.authorization_endpoint,
        token_endpoint: parsed_configuration.token_endpoint,
        jwks_uri: normalized_jwks_uri,
        registration_endpoint: parsed_configuration.registration_endpoint,
        raw_openid_configuration: openid_configuration,
        jwks_json,
    })
}

pub fn verify_lti_launch_jwt(
    id_token: &str,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_deployment_id: &str,
    jwks_json: &str,
    expected_nonce: Option<&str>,
    leeway_seconds: u64,
) -> Oid4vciResult<VerifiedLtiLaunch> {
    let header = decode_header(id_token)
        .map_err(|e| Oid4vciError::JwtError(format!("Failed to decode LTI JWT header: {e}")))?;
    let kid = header
        .kid
        .clone()
        .ok_or_else(|| invalid_request("LTI id_token is missing a kid header"))?;

    let jwks_value: Value = serde_json::from_str(jwks_json).map_err(|e| {
        invalid_request(format!(
            "Invalid JWKS JSON supplied for LTI verification: {e}"
        ))
    })?;
    let keys = jwks_value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_request("JWKS payload must include a keys array"))?;

    let jwk_value = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid.as_str()))
        .ok_or_else(|| invalid_request(format!("No JWKS entry found for LTI kid {kid}")))?;
    let jwk: Jwk = serde_json::from_value(jwk_value.clone()).map_err(|e| {
        invalid_request(format!("Failed to parse JWKS entry for LTI kid {kid}: {e}"))
    })?;

    let decoding_key = DecodingKey::from_jwk(&jwk)
        .map_err(|e| Oid4vciError::JwtError(format!("Failed to build LTI decoding key: {e}")))?;

    let mut validation = Validation::new(header.alg);
    validation.leeway = leeway_seconds;
    validation.validate_aud = false;
    validation.validate_exp = true;
    validation.validate_nbf = false;

    let raw_claims = decode::<Value>(id_token, &decoding_key, &validation)
        .map_err(|e| Oid4vciError::JwtError(format!("Failed to verify LTI id_token: {e}")))?
        .claims;

    let claims: LtiLaunchClaims = serde_json::from_value(raw_claims.clone()).map_err(|e| {
        invalid_request(format!(
            "Verified LTI id_token is missing expected claims: {e}"
        ))
    })?;

    if claims.iss != expected_issuer {
        return Err(invalid_request(
            "LTI issuer does not match connector configuration",
        ));
    }

    let audience = decode_audience(&claims.aud)?;
    if !audience
        .iter()
        .any(|candidate| candidate == expected_client_id)
    {
        return Err(invalid_request(
            "LTI audience does not include the configured client id",
        ));
    }

    if claims.deployment_id != expected_deployment_id {
        return Err(invalid_request(
            "LTI deployment id does not match connector configuration",
        ));
    }

    if let Some(expected_nonce) = expected_nonce {
        let actual_nonce = claims
            .nonce
            .as_deref()
            .ok_or_else(|| invalid_request("LTI nonce is required but missing"))?;
        if actual_nonce != expected_nonce {
            return Err(invalid_request(
                "LTI nonce does not match expected launch nonce",
            ));
        }
    }

    let learner_identity = json!({
        "issuer": claims.iss,
        "subject": claims.sub,
        "deployment_id": claims.deployment_id,
        "context": claims.context,
        "roles": claims.roles.clone().unwrap_or_default(),
    });

    Ok(VerifiedLtiLaunch {
        issuer: claims.iss,
        subject: claims.sub,
        audience,
        deployment_id: claims.deployment_id,
        nonce: claims.nonce,
        issued_at: claims.iat,
        expires_at: claims.exp,
        message_type: claims.message_type,
        lti_version: claims.lti_version,
        target_link_uri: claims.target_link_uri,
        context: claims.context,
        roles: claims.roles.unwrap_or_default(),
        learner_identity,
        raw_claims,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use serde_json::json;

    fn make_test_jwk(kid: &str, verifying_key: &VerifyingKey) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": kid,
            "alg": "EdDSA",
            "use": "sig",
            "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
        })
    }

    fn encode_jwt(signing_key: &SigningKey, kid: &str, claims: &Value) -> String {
        let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("{signing_input}.{signature_b64}")
    }

    #[test]
    fn normalize_canvas_base_url_rejects_private_hosts_by_default() {
        let err = normalize_canvas_base_url("https://127.0.0.1:3000", false, false).unwrap_err();
        assert!(err.to_string().contains("private or loopback"));
    }

    #[test]
    fn normalize_canvas_base_url_allows_http_localhost_when_enabled() {
        let normalized = normalize_canvas_base_url("http://localhost:3000/", false, true).unwrap();
        assert_eq!(normalized, "http://localhost:3000");
    }

    #[test]
    fn normalize_canvas_base_url_rejects_paths() {
        let err =
            normalize_canvas_base_url("https://canvas.example.edu/oidc", false, false).unwrap_err();
        assert!(err.to_string().contains("without a path segment"));
    }

    #[test]
    fn verify_lti_launch_jwt_accepts_valid_ed25519_token() {
        let kid = "canvas-lti-test";
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let jwks = json!({"keys": [make_test_jwk(kid, &verifying_key)]});
        let claims = json!({
            "iss": "https://canvas.example.edu",
            "sub": "student-123",
            "aud": ["client-123"],
            "exp": 4102444800u64,
            "iat": 1700000000u64,
            "nonce": "nonce-123",
            LTI_DEPLOYMENT_ID_CLAIM: "deployment-xyz",
            LTI_CONTEXT_CLAIM: {"id": "course-123", "label": "BIO101"},
            LTI_ROLES_CLAIM: ["Learner"],
            LTI_TARGET_LINK_URI_CLAIM: "https://tool.example.edu/launch",
            LTI_MESSAGE_TYPE_CLAIM: "LtiResourceLinkRequest",
            LTI_VERSION_CLAIM: "1.3.0"
        });

        let token = encode_jwt(&signing_key, kid, &claims);
        let verified = verify_lti_launch_jwt(
            &token,
            "https://canvas.example.edu",
            "client-123",
            "deployment-xyz",
            &jwks.to_string(),
            Some("nonce-123"),
            60,
        )
        .unwrap();

        assert_eq!(verified.subject, "student-123");
        assert_eq!(verified.deployment_id, "deployment-xyz");
        assert_eq!(verified.roles, vec!["Learner"]);
        assert_eq!(
            verified.target_link_uri.as_deref(),
            Some("https://tool.example.edu/launch")
        );
    }

    #[test]
    fn verify_lti_launch_jwt_rejects_wrong_deployment() {
        let kid = "canvas-lti-test";
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let jwks = json!({"keys": [make_test_jwk(kid, &verifying_key)]});
        let claims = json!({
            "iss": "https://canvas.example.edu",
            "sub": "student-123",
            "aud": "client-123",
            "exp": 4102444800u64,
            LTI_DEPLOYMENT_ID_CLAIM: "other-deployment"
        });

        let token = encode_jwt(&signing_key, kid, &claims);
        let err = verify_lti_launch_jwt(
            &token,
            "https://canvas.example.edu",
            "client-123",
            "deployment-xyz",
            &jwks.to_string(),
            None,
            60,
        )
        .unwrap_err();

        assert!(err.to_string().contains("deployment id"));
    }
}
