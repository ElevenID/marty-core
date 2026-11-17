//! Generic LTI launch JWT verification. Provider discovery belongs in connectors.
use crate::error::{Oid4vciError, Oid4vciResult};
use jsonwebtoken::{decode, decode_header, jwk::Jwk, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
fn contains_private_material(value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return true;
    }
    match value {
        Value::Object(fields) => {
            let private_jwk = fields.contains_key("kty")
                && ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "rsa_d"]
                    .iter()
                    .any(|name| fields.get(*name).is_some_and(|value| !value.is_null()));
            private_jwk
                || fields.iter().any(|(name, value)| {
                    let normalized = name
                        .chars()
                        .filter(|character| character.is_ascii_alphanumeric())
                        .flat_map(char::to_lowercase)
                        .collect::<String>();
                    (!value.is_null()
                        && (normalized.contains("privatekey")
                            || normalized.contains("privatejwk")
                            || normalized.contains("privatepem")
                            || normalized.contains("secretkey")
                            || normalized.contains("pkcs8")))
                        || contains_private_material(value, depth + 1)
                })
        }
        Value::Array(values) => values
            .iter()
            .any(|value| contains_private_material(value, depth + 1)),
        Value::String(text) => {
            if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
                return true;
            }
            let trimmed = text.trim_start();
            (trimmed.starts_with('{') || trimmed.starts_with('['))
                && serde_json::from_str::<Value>(trimmed)
                    .is_ok_and(|value| contains_private_material(&value, depth + 1))
        }
        _ => false,
    }
}
pub fn ensure_lti_metadata_public_only(jwks: &Value, configuration: &Value) -> Oid4vciResult<()> {
    if contains_private_material(jwks, 0) || contains_private_material(configuration, 0) {
        return Err(invalid_request(
            "LTI metadata contains private key material",
        ));
    }
    Ok(())
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

pub fn verify_lti_launch_jwt(
    id_token: &str,
    expected_issuer: &str,
    expected_client_id: &str,
    expected_deployment_id: &str,
    jwks_json: &str,
    expected_nonce: Option<&str>,
    leeway_seconds: u64,
) -> Oid4vciResult<VerifiedLtiLaunch> {
    sd_jwt_rs::install_crypto_provider().map_err(|error| {
        Oid4vciError::JwtError(format!("JWT verification backend unavailable: {error}"))
    })?;
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
    ensure_lti_metadata_public_only(&jwks_value, &Value::Null)?;
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
    #[cfg(not(target_family = "wasm"))]
    use crate::openbao_transit::{DisposableOpenBao, ScopedTransitSigner};
    #[cfg(not(target_family = "wasm"))]
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde_json::json;

    const LTI_DEPLOYMENT_ID_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/deployment_id";
    const LTI_CONTEXT_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/context";
    const LTI_ROLES_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/roles";
    const LTI_TARGET_LINK_URI_CLAIM: &str =
        "https://purl.imsglobal.org/spec/lti/claim/target_link_uri";
    const LTI_MESSAGE_TYPE_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/message_type";
    const LTI_VERSION_CLAIM: &str = "https://purl.imsglobal.org/spec/lti/claim/version";

    #[cfg(not(target_family = "wasm"))]
    fn make_test_jwk(kid: &str, signer: &ScopedTransitSigner) -> Value {
        let mut jwk: Value = serde_json::from_str(signer.public_jwk()).unwrap();
        jwk["kid"] = json!(kid);
        jwk["alg"] = json!("EdDSA");
        jwk["use"] = json!("sig");
        jwk
    }
    #[cfg(not(target_family = "wasm"))]
    fn encode_jwt(signer: &ScopedTransitSigner, kid: &str, claims: &Value) -> String {
        let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": kid});
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature = signer.sign_ed25519(signing_input.as_bytes()).unwrap();
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);
        format!("{signing_input}.{signature_b64}")
    }
    #[test]
    fn lti_metadata_rejects_private_material_without_echoing_values() {
        let public = json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "public"}]});
        assert!(ensure_lti_metadata_public_only(&public, &json!({"issuer": "public"})).is_ok());
        for (jwks, configuration) in [
            (
                json!({"keys": [{"kty": "EC", "d": "forbidden"}]}),
                Value::Null,
            ),
            (
                public.clone(),
                json!({"nested": [{"private_key": "forbidden"}]}),
            ),
            (
                public.clone(),
                json!({"nested": "{\"kty\":\"oct\",\"k\":\"forbidden\"}"}),
            ),
        ] {
            let error = ensure_lti_metadata_public_only(&jwks, &configuration).unwrap_err();
            assert!(error.to_string().contains("private key material"));
            assert!(!error.to_string().contains("forbidden"));
        }
    }
    #[test]
    fn lti_verification_rejects_private_jwks_before_key_selection() {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"EdDSA","kid":"public-1"}"#);
        let token = format!("{header}.e30.signature");
        let jwks =
            json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "public", "d": "forbidden"}]});
        let error = verify_lti_launch_jwt(
            &token,
            "https://lti.example.edu",
            "client-id",
            "deployment-id",
            &jwks.to_string(),
            None,
            0,
        )
        .unwrap_err();
        assert!(error.to_string().contains("private key material"));
        assert!(!error.to_string().contains("forbidden"));
    }
    #[cfg(not(target_family = "wasm"))]
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit"]
    fn verify_lti_launch_jwt_accepts_valid_ed25519_token() {
        let kid = "lti-test";
        let signer = DisposableOpenBao::from_marked_env().create_ed25519();
        let jwks = json!({"keys": [make_test_jwk(kid, &signer)]});
        let claims = json!({
            "iss": "https://lti.example.edu",
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

        let token = encode_jwt(&signer, kid, &claims);
        let verified = verify_lti_launch_jwt(
            &token,
            "https://lti.example.edu",
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
    #[cfg(not(target_family = "wasm"))]
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit"]
    fn verify_lti_launch_jwt_rejects_wrong_deployment() {
        let kid = "lti-test";
        let signer = DisposableOpenBao::from_marked_env().create_ed25519();
        let jwks = json!({"keys": [make_test_jwk(kid, &signer)]});
        let claims = json!({
            "iss": "https://lti.example.edu",
            "sub": "student-123",
            "aud": "client-123",
            "exp": 4102444800u64,
            LTI_DEPLOYMENT_ID_CLAIM: "other-deployment"
        });

        let token = encode_jwt(&signer, kid, &claims);
        let err = verify_lti_launch_jwt(
            &token,
            "https://lti.example.edu",
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
