//! Fail-closed OpenID Connect ID-token validation.
//!
//! Network discovery and caching remain caller concerns for now. This module
//! owns all security decisions once a provider JWKS has been obtained: key
//! selection, JOSE verification, issuer/audience/authorized-party policy,
//! nonce and time validation, and access-token hash binding.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::jose::{decode_unverified_compact_jwt_header, verify_compact_jwt_with_public_jwk};

const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_JWKS_KEYS: usize = 64;
const MAX_LEEWAY_SECONDS: u64 = 300;

/// Stable fail-closed errors returned by the canonical OIDC validator.
#[derive(Debug, thiserror::Error)]
pub enum OidcValidationError {
    #[error("OIDC.MALFORMED_TOKEN: {0}")]
    MalformedToken(String),
    #[error("OIDC.INVALID_JWKS: {0}")]
    InvalidJwks(String),
    #[error("OIDC.UNSUPPORTED_ALGORITHM: {0}")]
    UnsupportedAlgorithm(String),
    #[error("OIDC.KEY_NOT_FOUND: {0}")]
    KeyNotFound(String),
    #[error("OIDC.AMBIGUOUS_KEY: {0}")]
    AmbiguousKey(String),
    #[error("OIDC.INVALID_SIGNATURE: {0}")]
    InvalidSignature(String),
    #[error("OIDC.MISSING_CLAIM: {0}")]
    MissingClaim(String),
    #[error("OIDC.INVALID_ISSUER: {0}")]
    InvalidIssuer(String),
    #[error("OIDC.INVALID_AUDIENCE: {0}")]
    InvalidAudience(String),
    #[error("OIDC.INVALID_AUTHORIZED_PARTY: {0}")]
    InvalidAuthorizedParty(String),
    #[error("OIDC.INVALID_NONCE: {0}")]
    InvalidNonce(String),
    #[error("OIDC.TOKEN_EXPIRED: {0}")]
    TokenExpired(String),
    #[error("OIDC.TOKEN_NOT_YET_VALID: {0}")]
    TokenNotYetValid(String),
    #[error("OIDC.TOKEN_ISSUED_IN_FUTURE: {0}")]
    TokenIssuedInFuture(String),
    #[error("OIDC.INVALID_ACCESS_TOKEN_HASH: {0}")]
    InvalidAccessTokenHash(String),
    #[error("OIDC.RESOURCE_LIMIT: {0}")]
    ResourceLimit(String),
}

pub type OidcValidationResult<T> = Result<T, OidcValidationError>;

/// Stable JSON binding request for OIDC ID-token validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcIdTokenValidationRequest {
    pub compact_jwt: String,
    pub jwks: Value,
    pub expected_issuer: String,
    pub expected_audience: String,
    #[serde(default)]
    pub expected_nonce: Option<String>,
    #[serde(default)]
    pub access_token: Option<String>,
    #[serde(default = "default_allowed_algorithms")]
    pub allowed_algorithms: Vec<String>,
    #[serde(default = "default_leeway_seconds")]
    pub leeway_seconds: u64,
}

/// Policy supplied by the relying party for one ID-token validation.
#[derive(Debug, Clone)]
pub struct OidcIdTokenPolicy<'a> {
    pub expected_issuer: &'a str,
    pub expected_audience: &'a str,
    pub expected_nonce: Option<&'a str>,
    pub access_token: Option<&'a str>,
    pub allowed_algorithms: &'a [&'a str],
    pub leeway_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Value>,
}

fn default_allowed_algorithms() -> Vec<String> {
    vec!["RS256".into()]
}

const fn default_leeway_seconds() -> u64 {
    60
}

/// Validate a JSON binding request and return authenticated claims.
pub fn validate_id_token_request(request_json: &str) -> OidcValidationResult<Value> {
    let request: OidcIdTokenValidationRequest = serde_json::from_str(request_json)
        .map_err(|error| OidcValidationError::MalformedToken(error.to_string()))?;
    let jwks_json = serde_json::to_string(&request.jwks)
        .map_err(|error| OidcValidationError::InvalidJwks(error.to_string()))?;
    let allowed_algorithms: Vec<&str> = request
        .allowed_algorithms
        .iter()
        .map(String::as_str)
        .collect();
    let policy = OidcIdTokenPolicy {
        expected_issuer: &request.expected_issuer,
        expected_audience: &request.expected_audience,
        expected_nonce: request.expected_nonce.as_deref(),
        access_token: request.access_token.as_deref(),
        allowed_algorithms: &allowed_algorithms,
        leeway_seconds: request.leeway_seconds,
    };
    validate_id_token(&request.compact_jwt, &jwks_json, &policy)
}

/// Validate an OIDC ID token using the supplied provider JWKS and current time.
pub fn validate_id_token(
    compact_jwt: &str,
    jwks_json: &str,
    policy: &OidcIdTokenPolicy<'_>,
) -> OidcValidationResult<Value> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| OidcValidationError::MalformedToken(error.to_string()))?
        .as_secs() as i64;
    validate_id_token_at(compact_jwt, jwks_json, policy, now)
}

/// Validate an OIDC ID token at an explicit time.
///
/// This entry point makes time-boundary conformance tests deterministic. Runtime
/// bindings call [`validate_id_token`] so application code cannot choose time.
pub fn validate_id_token_at(
    compact_jwt: &str,
    jwks_json: &str,
    policy: &OidcIdTokenPolicy<'_>,
    now_unix: i64,
) -> OidcValidationResult<Value> {
    validate_limits(compact_jwt, jwks_json, policy)?;

    let header = decode_unverified_compact_jwt_header(compact_jwt)
        .map_err(|error| OidcValidationError::MalformedToken(error.to_string()))?;
    let algorithm = required_string(&header, "alg")?;
    if algorithm == "none" || !policy.allowed_algorithms.contains(&algorithm) {
        return Err(OidcValidationError::UnsupportedAlgorithm(
            algorithm.to_string(),
        ));
    }
    if let Some(token_type) = header.get("typ") {
        if token_type.as_str() != Some("JWT") {
            return Err(OidcValidationError::MalformedToken(
                "ID token typ must be JWT when present".into(),
            ));
        }
    }
    let kid = required_string(&header, "kid")?;
    let jwks: JwkSet = serde_json::from_str(jwks_json)
        .map_err(|error| OidcValidationError::InvalidJwks(error.to_string()))?;
    if jwks.keys.len() > MAX_JWKS_KEYS {
        return Err(OidcValidationError::ResourceLimit(format!(
            "JWKS contains more than {MAX_JWKS_KEYS} keys"
        )));
    }
    let matching_keys: Vec<&Value> = jwks
        .keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .collect();
    let selected_key = match matching_keys.as_slice() {
        [] => return Err(OidcValidationError::KeyNotFound(kid.to_string())),
        [key] => *key,
        _ => return Err(OidcValidationError::AmbiguousKey(kid.to_string())),
    };
    let selected_key_json = serde_json::to_string(selected_key)
        .map_err(|error| OidcValidationError::InvalidJwks(error.to_string()))?;
    let verified = verify_compact_jwt_with_public_jwk(compact_jwt, &selected_key_json, algorithm)
        .map_err(|error| OidcValidationError::InvalidSignature(error.to_string()))?;

    validate_claims(&verified.claims, algorithm, policy, now_unix)?;
    Ok(verified.claims)
}

fn validate_limits(
    compact_jwt: &str,
    jwks_json: &str,
    policy: &OidcIdTokenPolicy<'_>,
) -> OidcValidationResult<()> {
    if compact_jwt.len() > MAX_TOKEN_BYTES {
        return Err(OidcValidationError::ResourceLimit(format!(
            "ID token exceeds {MAX_TOKEN_BYTES} bytes"
        )));
    }
    if jwks_json.len() > MAX_JWKS_BYTES {
        return Err(OidcValidationError::ResourceLimit(format!(
            "JWKS exceeds {MAX_JWKS_BYTES} bytes"
        )));
    }
    if policy.expected_issuer.is_empty() || policy.expected_audience.is_empty() {
        return Err(OidcValidationError::MalformedToken(
            "expected issuer and audience must not be empty".into(),
        ));
    }
    if policy.allowed_algorithms.is_empty() {
        return Err(OidcValidationError::UnsupportedAlgorithm(
            "the allowlist must not be empty".into(),
        ));
    }
    let unique: HashSet<&str> = policy.allowed_algorithms.iter().copied().collect();
    if unique.len() != policy.allowed_algorithms.len() {
        return Err(OidcValidationError::UnsupportedAlgorithm(
            "the allowlist contains duplicates".into(),
        ));
    }
    if policy.leeway_seconds > MAX_LEEWAY_SECONDS {
        return Err(OidcValidationError::ResourceLimit(format!(
            "clock leeway exceeds {MAX_LEEWAY_SECONDS} seconds"
        )));
    }
    Ok(())
}

fn validate_claims(
    claims: &Value,
    algorithm: &str,
    policy: &OidcIdTokenPolicy<'_>,
    now_unix: i64,
) -> OidcValidationResult<()> {
    let issuer = required_string(claims, "iss")?;
    if issuer != policy.expected_issuer {
        return Err(OidcValidationError::InvalidIssuer(issuer.into()));
    }
    let subject = required_string(claims, "sub")?;
    if subject.is_empty() {
        return Err(OidcValidationError::MissingClaim("sub".into()));
    }

    let audiences = audiences(claims.get("aud"))?;
    if !audiences.contains(&policy.expected_audience) {
        return Err(OidcValidationError::InvalidAudience(
            policy.expected_audience.into(),
        ));
    }
    let authorized_party = claims.get("azp").and_then(Value::as_str);
    if audiences.len() > 1 && authorized_party.is_none() {
        return Err(OidcValidationError::MissingClaim("azp".into()));
    }
    if authorized_party.is_some_and(|value| value != policy.expected_audience) {
        return Err(OidcValidationError::InvalidAuthorizedParty(
            authorized_party.unwrap_or_default().into(),
        ));
    }

    let leeway = policy.leeway_seconds as i64;
    let expires_at = required_numeric_date(claims, "exp")?;
    if now_unix > expires_at.saturating_add(leeway) {
        return Err(OidcValidationError::TokenExpired(expires_at.to_string()));
    }
    let issued_at = required_numeric_date(claims, "iat")?;
    if issued_at > now_unix.saturating_add(leeway) {
        return Err(OidcValidationError::TokenIssuedInFuture(
            issued_at.to_string(),
        ));
    }
    if let Some(not_before) = optional_numeric_date(claims, "nbf")? {
        if not_before > now_unix.saturating_add(leeway) {
            return Err(OidcValidationError::TokenNotYetValid(
                not_before.to_string(),
            ));
        }
    }

    if let Some(expected_nonce) = policy.expected_nonce {
        let nonce = required_string(claims, "nonce")?;
        if nonce != expected_nonce {
            return Err(OidcValidationError::InvalidNonce(nonce.into()));
        }
    }

    if let Some(at_hash) = claims.get("at_hash") {
        let at_hash = at_hash.as_str().ok_or_else(|| {
            OidcValidationError::InvalidAccessTokenHash("at_hash must be a string".into())
        })?;
        let access_token = policy.access_token.ok_or_else(|| {
            OidcValidationError::InvalidAccessTokenHash(
                "access token is required when at_hash is present".into(),
            )
        })?;
        let expected = access_token_hash(access_token, algorithm)?;
        if at_hash != expected {
            return Err(OidcValidationError::InvalidAccessTokenHash(
                "at_hash does not match the access token".into(),
            ));
        }
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, name: &str) -> OidcValidationResult<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| OidcValidationError::MissingClaim(name.into()))
}

fn required_numeric_date(value: &Value, name: &str) -> OidcValidationResult<i64> {
    optional_numeric_date(value, name)?
        .ok_or_else(|| OidcValidationError::MissingClaim(name.into()))
}

fn optional_numeric_date(value: &Value, name: &str) -> OidcValidationResult<Option<i64>> {
    match value.get(name) {
        None => Ok(None),
        Some(number) => number.as_i64().map(Some).ok_or_else(|| {
            OidcValidationError::MalformedToken(format!("{name} must be an integer NumericDate"))
        }),
    }
}

fn audiences(value: Option<&Value>) -> OidcValidationResult<Vec<&str>> {
    match value {
        Some(Value::String(audience)) if !audience.is_empty() => Ok(vec![audience]),
        Some(Value::Array(values)) if !values.is_empty() => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .filter(|audience| !audience.is_empty())
                    .ok_or_else(|| {
                        OidcValidationError::InvalidAudience(
                            "aud array entries must be non-empty strings".into(),
                        )
                    })
            })
            .collect(),
        _ => Err(OidcValidationError::MissingClaim("aud".into())),
    }
}

fn access_token_hash(access_token: &str, algorithm: &str) -> OidcValidationResult<String> {
    let digest = match algorithm {
        "ES256" | "RS256" | "PS256" => Sha256::digest(access_token.as_bytes()).to_vec(),
        "ES384" => Sha384::digest(access_token.as_bytes()).to_vec(),
        "EdDSA" => Sha512::digest(access_token.as_bytes()).to_vec(),
        other => {
            return Err(OidcValidationError::UnsupportedAlgorithm(format!(
                "at_hash is not supported for {other}"
            )))
        }
    };
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;
    use p256::SecretKey;
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;

    fn signed_token(claim_overrides: Value) -> (String, String, String) {
        let secret = SecretKey::random(&mut rand::rngs::OsRng);
        let public = secret.public_key().to_encoded_point(false);
        let kid = "provider-key-1";
        let jwk = json!({
            "kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig",
            "key_ops":["verify"], "kid":kid,
            "x":URL_SAFE_NO_PAD.encode(public.x().expect("x coordinate")),
            "y":URL_SAFE_NO_PAD.encode(public.y().expect("y coordinate"))
        });
        let mut claims = json!({
            "iss":"https://issuer.example/realms/marty",
            "sub":"user-1",
            "aud":"marty-ui",
            "exp":NOW + 300,
            "iat":NOW - 10,
            "nonce":"nonce-1"
        });
        for (name, value) in claim_overrides.as_object().expect("claim overrides") {
            claims[name] = value.clone();
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.into());
        let der = secret.to_pkcs8_der().expect("PKCS#8 key");
        let token = encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes()))
            .expect("signed ID token");
        (token, json!({"keys":[jwk]}).to_string(), claims.to_string())
    }

    fn policy<'a>(access_token: Option<&'a str>) -> OidcIdTokenPolicy<'a> {
        OidcIdTokenPolicy {
            expected_issuer: "https://issuer.example/realms/marty",
            expected_audience: "marty-ui",
            expected_nonce: Some("nonce-1"),
            access_token,
            allowed_algorithms: &["ES256"],
            leeway_seconds: 30,
        }
    }

    #[test]
    fn validates_signature_registered_claims_nonce_and_at_hash() {
        let access_token = "access-token-1";
        let at_hash = access_token_hash(access_token, "ES256").expect("at_hash");
        let (token, jwks, _) = signed_token(json!({"at_hash":at_hash}));
        let claims = validate_id_token_at(&token, &jwks, &policy(Some(access_token)), NOW)
            .expect("valid ID token");
        assert_eq!(claims["sub"], "user-1");
    }

    #[test]
    fn rejects_tampering_unknown_keys_and_algorithm_confusion() {
        let (token, jwks, _) = signed_token(json!({}));
        let mut tampered = token.into_bytes();
        let index = tampered.len() - 1;
        tampered[index] = if tampered[index] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ASCII JWT");
        assert!(matches!(
            validate_id_token_at(&tampered, &jwks, &policy(None), NOW),
            Err(OidcValidationError::InvalidSignature(_))
        ));

        let (token, _, _) = signed_token(json!({}));
        assert!(matches!(
            validate_id_token_at(&token, r#"{"keys":[]}"#, &policy(None), NOW),
            Err(OidcValidationError::KeyNotFound(_))
        ));

        let disallowed = OidcIdTokenPolicy {
            allowed_algorithms: &["RS256"],
            ..policy(None)
        };
        assert!(matches!(
            validate_id_token_at(&token, &jwks, &disallowed, NOW),
            Err(OidcValidationError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn rejects_issuer_audience_nonce_and_time_failures() {
        let cases = [
            (json!({"iss":"https://evil.example"}), "OIDC.INVALID_ISSUER"),
            (json!({"aud":"another-client"}), "OIDC.INVALID_AUDIENCE"),
            (json!({"nonce":"wrong"}), "OIDC.INVALID_NONCE"),
            (json!({"exp":NOW - 31}), "OIDC.TOKEN_EXPIRED"),
            (json!({"iat":NOW + 31}), "OIDC.TOKEN_ISSUED_IN_FUTURE"),
            (json!({"nbf":NOW + 31}), "OIDC.TOKEN_NOT_YET_VALID"),
        ];
        for (overrides, expected_code) in cases {
            let (token, jwks, _) = signed_token(overrides);
            let error = validate_id_token_at(&token, &jwks, &policy(None), NOW)
                .expect_err("invalid claim must fail closed");
            assert!(error.to_string().starts_with(expected_code), "{error}");
        }
    }

    #[test]
    fn enforces_authorized_party_for_multiple_audiences() {
        let (token, jwks, _) = signed_token(json!({"aud":["marty-ui","account"]}));
        assert!(matches!(
            validate_id_token_at(&token, &jwks, &policy(None), NOW),
            Err(OidcValidationError::MissingClaim(name)) if name == "azp"
        ));

        let (token, jwks, _) = signed_token(json!({
            "aud":["marty-ui","account"], "azp":"marty-ui"
        }));
        validate_id_token_at(&token, &jwks, &policy(None), NOW)
            .expect("matching azp must validate");
    }

    #[test]
    fn rejects_duplicate_key_ids_and_private_jwks() {
        let (token, jwks, _) = signed_token(json!({}));
        let key = serde_json::from_str::<Value>(&jwks).expect("JWKS")["keys"][0].clone();
        let duplicate = json!({"keys":[key.clone(), key.clone()]}).to_string();
        assert!(matches!(
            validate_id_token_at(&token, &duplicate, &policy(None), NOW),
            Err(OidcValidationError::AmbiguousKey(_))
        ));

        let mut private_key = key;
        private_key["d"] = Value::String("private".into());
        let private_jwks = json!({"keys":[private_key]}).to_string();
        assert!(matches!(
            validate_id_token_at(&token, &private_jwks, &policy(None), NOW),
            Err(OidcValidationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn binding_request_rejects_unknown_fields_before_validation() {
        let error = validate_id_token_request(
            r#"{"compact_jwt":"token","jwks":{"keys":[]},"expected_issuer":"issuer","expected_audience":"audience","unexpected":true}"#,
        )
        .expect_err("unknown fields must fail closed");
        assert!(matches!(error, OidcValidationError::MalformedToken(_)));
    }
}
