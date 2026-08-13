//! ISO 18013-7 OpenID4VP handover construction.
//!
//! This module owns the protocol bytes used to bind an mdoc presentation to
//! verifier-controlled OpenID4VP request state. Callers must use these bytes
//! as the `SessionTranscript` supplied to device-authentication verification.

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

const HANDOVER_LABEL: &str = "OpenID4VPHandover";
const MAX_HANDOVER_STRING_BYTES: usize = 8 * 1024;
const MAX_JWK_MEMBER_BYTES: usize = 2 * 1024;

#[derive(Debug, Deserialize)]
struct EcResponseEncryptionJwk {
    crv: String,
    kty: String,
    x: String,
    y: String,
}

/// Non-reversible diagnostics for an OpenID4VP mdoc request binding.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct MdocBindingDigests {
    pub transcript_sha256: String,
    pub client_id_sha256: String,
    pub nonce_sha256: String,
    pub response_uri_sha256: String,
    pub response_key_thumbprint_sha256: String,
    pub presentation_sha256: String,
}

/// Return the raw RFC 7638 SHA-256 thumbprint for an EC response-encryption JWK.
///
/// Metadata members such as `alg`, `kid`, and `use` are intentionally excluded
/// from the canonical JWK, as required by RFC 7638.
pub fn response_encryption_jwk_thumbprint(jwk_json: &str) -> Result<[u8; 32]> {
    if jwk_json.len() > MAX_HANDOVER_STRING_BYTES {
        return Err(invalid_request("response-encryption JWK is too large"));
    }

    let jwk: EcResponseEncryptionJwk = serde_json::from_str(jwk_json)
        .map_err(|error| invalid_request(format!("invalid response-encryption JWK: {error}")))?;
    if jwk.kty != "EC" {
        return Err(invalid_request(
            "OpenID4VP response-encryption JWK must be an EC key",
        ));
    }
    for (name, value) in [
        ("crv", jwk.crv.as_str()),
        ("kty", jwk.kty.as_str()),
        ("x", jwk.x.as_str()),
        ("y", jwk.y.as_str()),
    ] {
        validate_required_string(name, value, MAX_JWK_MEMBER_BYTES)?;
    }

    // The literal key order is the RFC 7638 lexicographic order. serde_json
    // performs all required JSON string escaping without admitting metadata.
    let canonical = format!(
        "{{\"crv\":{},\"kty\":{},\"x\":{},\"y\":{}}}",
        serde_json::to_string(&jwk.crv).map_err(json_error)?,
        serde_json::to_string(&jwk.kty).map_err(json_error)?,
        serde_json::to_string(&jwk.x).map_err(json_error)?,
        serde_json::to_string(&jwk.y).map_err(json_error)?,
    );
    Ok(Sha256::digest(canonical.as_bytes()).into())
}

/// Build the ISO 18013-7 OpenID4VP `SessionTranscript` CBOR bytes.
///
/// The returned value encodes:
/// `[null, null, ["OpenID4VPHandover", SHA-256(CBOR(HandoverInfo))]]`, where
/// `HandoverInfo` is `[client_id, nonce, response_key_thumbprint, response_uri]`.
pub fn build_mdoc_session_transcript(
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    response_encryption_jwk_json: Option<&str>,
) -> Result<Vec<u8>> {
    validate_required_string("client_id", client_id, MAX_HANDOVER_STRING_BYTES)?;
    validate_required_string("nonce", nonce, MAX_HANDOVER_STRING_BYTES)?;
    validate_required_string("response_uri", response_uri, MAX_HANDOVER_STRING_BYTES)?;

    let response_key_thumbprint = response_encryption_jwk_json
        .map(response_encryption_jwk_thumbprint)
        .transpose()?;
    let handover_info = Value::Array(vec![
        Value::Text(client_id.to_owned()),
        Value::Text(nonce.to_owned()),
        response_key_thumbprint
            .map(|thumbprint| Value::Bytes(thumbprint.to_vec()))
            .unwrap_or(Value::Null),
        Value::Text(response_uri.to_owned()),
    ]);
    let handover_digest = Sha256::digest(encode_cbor(&handover_info)?);
    encode_cbor(&Value::Array(vec![
        Value::Null,
        Value::Null,
        Value::Array(vec![
            Value::Text(HANDOVER_LABEL.to_owned()),
            Value::Bytes(handover_digest.to_vec()),
        ]),
    ]))
}

/// Build non-reversible diagnostics without exposing verifier request state.
pub fn mdoc_binding_digests(
    session_transcript: &[u8],
    client_id: &str,
    nonce: &str,
    response_uri: &str,
    response_encryption_jwk_json: Option<&str>,
    presentation: &str,
) -> Result<MdocBindingDigests> {
    if session_transcript.is_empty() {
        return Err(invalid_request("session transcript must not be empty"));
    }
    validate_required_string("client_id", client_id, MAX_HANDOVER_STRING_BYTES)?;
    validate_required_string("nonce", nonce, MAX_HANDOVER_STRING_BYTES)?;
    validate_required_string("response_uri", response_uri, MAX_HANDOVER_STRING_BYTES)?;
    if presentation.is_empty() {
        return Err(invalid_request("presentation must not be empty"));
    }

    let response_key_thumbprint_sha256 = response_encryption_jwk_json
        .map(response_encryption_jwk_thumbprint)
        .transpose()?
        .map(|thumbprint| sha256_hex(&thumbprint))
        .unwrap_or_else(|| "none".to_owned());
    Ok(MdocBindingDigests {
        transcript_sha256: sha256_hex(session_transcript),
        client_id_sha256: sha256_hex(client_id.as_bytes()),
        nonce_sha256: sha256_hex(nonce.as_bytes()),
        response_uri_sha256: sha256_hex(response_uri.as_bytes()),
        response_key_thumbprint_sha256,
        presentation_sha256: sha256_hex(presentation.as_bytes()),
    })
}

fn encode_cbor(value: &Value) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded)?;
    Ok(encoded)
}

fn validate_required_string(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() {
        return Err(invalid_request(format!("{name} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(invalid_request(format!("{name} is too large")));
    }
    Ok(())
}

fn invalid_request(message: impl Into<String>) -> Error {
    Error::InvalidRequest(message.into())
}

fn json_error(error: serde_json::Error) -> Error {
    invalid_request(format!(
        "failed to canonicalize response-encryption JWK: {error}"
    ))
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct VectorSet {
        valid: Vec<ValidVector>,
        invalid: Vec<InvalidVector>,
    }

    #[derive(Deserialize)]
    struct ValidVector {
        name: String,
        client_id: String,
        nonce: String,
        response_uri: String,
        response_encryption_jwk: Option<serde_json::Value>,
        session_transcript_hex: String,
        presentation: Option<String>,
        binding_digests: Option<MdocBindingDigests>,
    }

    #[derive(Deserialize)]
    struct InvalidVector {
        name: String,
        client_id: String,
        nonce: String,
        response_uri: String,
        response_encryption_jwk: Option<serde_json::Value>,
    }

    fn vectors() -> VectorSet {
        serde_json::from_str(include_str!(
            "../../tests/vectors/openid4vp_mdoc_handover.json"
        ))
        .expect("valid OpenID4VP mdoc handover vectors")
    }

    fn jwk_json(value: &Option<serde_json::Value>) -> Option<String> {
        value.as_ref().map(serde_json::Value::to_string)
    }

    #[test]
    fn shared_vectors_define_exact_success_and_failure_behavior() {
        let vectors = vectors();
        for vector in vectors.valid {
            let jwk = jwk_json(&vector.response_encryption_jwk);
            let transcript = build_mdoc_session_transcript(
                &vector.client_id,
                &vector.nonce,
                &vector.response_uri,
                jwk.as_deref(),
            )
            .unwrap_or_else(|error| panic!("{} failed: {error}", vector.name));
            assert_eq!(hex::encode(&transcript), vector.session_transcript_hex);
            if let (Some(presentation), Some(expected)) =
                (vector.presentation.as_deref(), vector.binding_digests)
            {
                assert_eq!(
                    mdoc_binding_digests(
                        &transcript,
                        &vector.client_id,
                        &vector.nonce,
                        &vector.response_uri,
                        jwk.as_deref(),
                        presentation,
                    )
                    .unwrap_or_else(|error| panic!("{} digests failed: {error}", vector.name)),
                    expected,
                );
            }
        }
        for vector in vectors.invalid {
            let jwk = jwk_json(&vector.response_encryption_jwk);
            assert!(
                build_mdoc_session_transcript(
                    &vector.client_id,
                    &vector.nonce,
                    &vector.response_uri,
                    jwk.as_deref(),
                )
                .is_err(),
                "{} must fail closed",
                vector.name
            );
        }
    }

    #[test]
    fn thumbprint_ignores_jwk_metadata_and_input_order() {
        let first = response_encryption_jwk_thumbprint(
            r#"{"kty":"EC","crv":"P-256","x":"AQ","y":"Ag","kid":"one"}"#,
        )
        .unwrap();
        let second = response_encryption_jwk_thumbprint(
            r#"{"use":"enc","y":"Ag","x":"AQ","kty":"EC","crv":"P-256","kid":"two"}"#,
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn changing_verifier_state_changes_the_transcript() {
        let first_nonce = format!("test-{}", rand::random::<u64>());
        let second_nonce = format!("test-{}", rand::random::<u64>());
        let first =
            build_mdoc_session_transcript("client", &first_nonce, "https://example/response", None)
                .unwrap();
        let second = build_mdoc_session_transcript(
            "client",
            &second_nonce,
            "https://example/response",
            None,
        )
        .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_missing_or_invalid_inputs() {
        let valid_nonce = format!("test-{}", rand::random::<u64>());
        let empty_nonce = String::new();
        assert!(build_mdoc_session_transcript("", &valid_nonce, "https://example", None).is_err());
        assert!(
            build_mdoc_session_transcript("client", &empty_nonce, "https://example", None).is_err()
        );
        assert!(build_mdoc_session_transcript("client", &valid_nonce, "", None).is_err());
        assert!(build_mdoc_session_transcript(
            "client",
            &valid_nonce,
            "https://example",
            Some(r#"{"kty":"OKP","crv":"Ed25519","x":"AQ","y":"Ag"}"#),
        )
        .is_err());
        assert!(build_mdoc_session_transcript(
            "client",
            &valid_nonce,
            "https://example",
            Some(r#"{"kty":"EC","crv":"P-256","x":"AQ"}"#),
        )
        .is_err());
        let oversized = "x".repeat(MAX_HANDOVER_STRING_BYTES + 1);
        assert!(
            build_mdoc_session_transcript(&oversized, &valid_nonce, "https://example", None,)
                .is_err()
        );
    }
}
