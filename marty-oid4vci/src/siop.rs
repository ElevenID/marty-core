//! SIOPv2 JWK-thumbprint subject verification.
//!
//! This kernel owns untrusted JOSE parsing, public-key policy, signature
//! verification, and RFC 7638 subject binding. Transaction policy such as
//! nonce, audience, and time windows remains with the application service.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::jose::{decode_unverified_compact_jwt, verify_compact_jwt_with_public_jwk};

const MAX_ID_TOKEN_BYTES: usize = 256 * 1024;
pub const JWK_THUMBPRINT_SUBJECT_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SiopVerificationError {
    #[error("SIOP.ID_TOKEN_TOO_LARGE: ID token exceeds {MAX_ID_TOKEN_BYTES} bytes")]
    TokenTooLarge,
    #[error("SIOP.ID_TOKEN_MALFORMED: {0}")]
    MalformedToken(String),
    #[error("SIOP.ALGORITHM_UNSUPPORTED: ID token signing algorithm is not supported")]
    UnsupportedAlgorithm,
    #[error("SIOP.SUBJECT_SYNTAX_UNSUPPORTED: only JWK-thumbprint subjects are supported")]
    UnsupportedSubjectSyntax,
    #[error("SIOP.SUB_JWK_INVALID: {0}")]
    InvalidSubjectJwk(String),
    #[error("SIOP.SIGNATURE_INVALID: ID token signature validation failed")]
    InvalidSignature,
    #[error("SIOP.THUMBPRINT_MISMATCH: sub is not bound to the sub_jwk thumbprint")]
    ThumbprintMismatch,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSiopJwkIdToken {
    pub claims: Value,
    pub signing_algorithm: String,
}

/// Verify a draft-13 SIOPv2 token using its JWK-thumbprint subject key.
pub fn verify_jwk_thumbprint_id_token(
    id_token: &str,
) -> Result<VerifiedSiopJwkIdToken, SiopVerificationError> {
    if id_token.len() > MAX_ID_TOKEN_BYTES {
        return Err(SiopVerificationError::TokenTooLarge);
    }
    let (header, unverified_claims) = decode_unverified_compact_jwt(id_token)
        .map_err(|error| SiopVerificationError::MalformedToken(error.to_string()))?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(SiopVerificationError::UnsupportedAlgorithm)?;
    let expected_key_shape = match algorithm {
        "ES256" => ("EC", "P-256"),
        "EdDSA" => ("OKP", "Ed25519"),
        _ => return Err(SiopVerificationError::UnsupportedAlgorithm),
    };

    let subject = unverified_claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| subject.starts_with(&format!("{JWK_THUMBPRINT_SUBJECT_PREFIX}:")))
        .ok_or(SiopVerificationError::UnsupportedSubjectSyntax)?;
    let subject_jwk = unverified_claims
        .get("sub_jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            SiopVerificationError::InvalidSubjectJwk(
                "JWK-thumbprint subject requires a sub_jwk public key".to_owned(),
            )
        })?;
    if (
        subject_jwk.get("kty").and_then(Value::as_str),
        subject_jwk.get("crv").and_then(Value::as_str),
    ) != (Some(expected_key_shape.0), Some(expected_key_shape.1))
    {
        return Err(SiopVerificationError::InvalidSubjectJwk(
            "sub_jwk key type does not match the signing algorithm".to_owned(),
        ));
    }

    let subject_jwk_json = serde_json::to_string(subject_jwk).map_err(|error| {
        SiopVerificationError::InvalidSubjectJwk(format!("sub_jwk serialization failed: {error}"))
    })?;
    let verified = verify_compact_jwt_with_public_jwk(id_token, &subject_jwk_json, algorithm)
        .map_err(|_| SiopVerificationError::InvalidSignature)?;

    let thumbprint = jwk_thumbprint(subject_jwk, expected_key_shape)?;
    let expected_subject = format!("{JWK_THUMBPRINT_SUBJECT_PREFIX}:sha-256:{thumbprint}");
    if subject != expected_subject {
        return Err(SiopVerificationError::ThumbprintMismatch);
    }

    Ok(VerifiedSiopJwkIdToken {
        claims: verified.claims,
        signing_algorithm: algorithm.to_owned(),
    })
}

fn jwk_thumbprint(
    jwk: &serde_json::Map<String, Value>,
    expected_key_shape: (&str, &str),
) -> Result<String, SiopVerificationError> {
    let x = required_string(jwk, "x")?;
    let canonical = match expected_key_shape {
        ("EC", "P-256") => {
            let y = required_string(jwk, "y")?;
            format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        ("OKP", "Ed25519") => {
            format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#)
        }
        _ => return Err(SiopVerificationError::UnsupportedAlgorithm),
    };
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

fn required_string<'a>(
    jwk: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, SiopVerificationError> {
    jwk.get(field).and_then(Value::as_str).ok_or_else(|| {
        SiopVerificationError::InvalidSubjectJwk(format!("sub_jwk requires string {field}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::EncodePrivateKey;
    use p256::SecretKey;
    use serde_json::json;

    fn signed_token(subject_override: Option<&str>) -> String {
        let secret = SecretKey::random(&mut rand::rngs::OsRng);
        let public = secret.public_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(public.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(public.y().unwrap());
        let jwk = json!({"kty":"EC","crv":"P-256","alg":"ES256","x":x,"y":y});
        let thumbprint = jwk_thumbprint(jwk.as_object().unwrap(), ("EC", "P-256")).unwrap();
        let subject = subject_override
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{JWK_THUMBPRINT_SUBJECT_PREFIX}:sha-256:{thumbprint}"));
        let claims = json!({
            "iss": subject,
            "sub": subject,
            "sub_jwk": jwk,
            "aud": "https://verifier.example/client",
            "nonce": "nonce-1",
            "iat": 1,
            "exp": 2
        });
        let der = secret.to_pkcs8_der().unwrap();
        encode(
            &Header::new(Algorithm::ES256),
            &claims,
            &EncodingKey::from_ec_der(der.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn verifies_signature_and_jwk_thumbprint_subject() {
        let result = verify_jwk_thumbprint_id_token(&signed_token(None)).unwrap();
        assert_eq!(result.signing_algorithm, "ES256");
        assert_eq!(result.claims["nonce"], "nonce-1");
    }

    #[test]
    fn rejects_unsupported_subject_and_thumbprint_mismatch() {
        assert_eq!(
            verify_jwk_thumbprint_id_token(&signed_token(Some("did:key:holder"))).unwrap_err(),
            SiopVerificationError::UnsupportedSubjectSyntax
        );
        let wrong = format!("{JWK_THUMBPRINT_SUBJECT_PREFIX}:sha-256:wrong");
        assert_eq!(
            verify_jwk_thumbprint_id_token(&signed_token(Some(&wrong))).unwrap_err(),
            SiopVerificationError::ThumbprintMismatch
        );
    }

    #[test]
    fn rejects_malformed_unsigned_and_oversized_tokens() {
        assert!(matches!(
            verify_jwk_thumbprint_id_token("not-a-token"),
            Err(SiopVerificationError::MalformedToken(_))
        ));
        assert_eq!(
            verify_jwk_thumbprint_id_token(&"x".repeat(MAX_ID_TOKEN_BYTES + 1)).unwrap_err(),
            SiopVerificationError::TokenTooLarge
        );
    }
}
