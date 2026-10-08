//! JSON Web Signature (JWS) implementation.
//!
//! Implements RFC 7515 JWS for signing and verification.

use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::base64url_encode;
use super::{base64url_decode, Jwk};
use crate::{VerificationError, VerificationResult};

/// Largest compact JWS accepted by public parsing and verification APIs.
pub const MAX_COMPACT_JWS_BYTES: usize = 2 * 1024 * 1024;
/// Largest decoded protected JOSE header accepted by JWS APIs.
pub const MAX_JWS_PROTECTED_HEADER_BYTES: usize = 16 * 1024;
/// Largest decoded JWS payload accepted by JWS APIs.
pub const MAX_JWS_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Largest decoded JWS signature accepted (up to an 8192-bit RSA signature).
pub const MAX_JWS_SIGNATURE_BYTES: usize = 1024;

const fn max_encoded_len(decoded_len: usize) -> usize {
    decoded_len.saturating_add(2) / 3 * 4
}

// ============================================================================
// JWS Header
// ============================================================================

/// JWS Header (JOSE Header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    /// Algorithm used for signing
    pub alg: String,

    /// Type (typically "JWT" or omitted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Content type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,

    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// JWK Set URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,

    /// Embedded JWK
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    /// X.509 URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 certificate chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 certificate SHA-1 thumbprint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    /// X.509 certificate SHA-256 thumbprint
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,

    /// Critical headers
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crit: Option<Vec<String>>,
}

impl JwsHeader {
    /// Create a new JWS header with the specified algorithm.
    pub fn new(alg: &str) -> Self {
        Self {
            alg: alg.to_string(),
            typ: None,
            cty: None,
            kid: None,
            jku: None,
            jwk: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            crit: None,
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> VerificationResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            VerificationError::internal(format!("JWS header serialization failed: {}", e))
        })
    }

    /// Parse from JSON bytes.
    pub fn from_json(json: &[u8]) -> VerificationResult<Self> {
        if json.len() > MAX_JWS_PROTECTED_HEADER_BYTES {
            return Err(VerificationError::internal(
                "JWS protected header exceeds the configured size limit".to_string(),
            ));
        }
        let value = crate::key_attestation::parse_unique_json(json)
            .map_err(|e| VerificationError::internal(format!("JWS header parsing failed: {e}")))?;
        serde_json::from_value(value)
            .map_err(|e| VerificationError::internal(format!("JWS header parsing failed: {}", e)))
    }
}

// ============================================================================
// JWS Compact Serialization
// ============================================================================

/// Verify a JWS in compact serialization format.
///
/// # Arguments
///
/// * `jws` - JWS in compact serialization
/// * `key` - Verification key (JWK)
///
/// # Returns
///
/// (header, payload) tuple on success.
pub fn jws_verify(jws: &str, key: &Jwk) -> VerificationResult<(JwsHeader, Vec<u8>)> {
    let parts = split_compact_jws(jws)?;

    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let signature_b64 = parts[2];

    // Decode header
    let header_bytes = base64url_decode(header_b64)?;
    let header = JwsHeader::from_json(&header_bytes)?;
    validate_jws_header_policy(&header)?;

    // Verify signature
    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature = base64url_decode(signature_b64)?;

    verify_message(&header.alg, signing_input.as_bytes(), &signature, key)?;

    // Decode payload
    let payload = base64url_decode(payload_b64)?;

    Ok((header, payload))
}

/// Decode a JWS without verifying the signature.
///
/// **Warning**: Only use this for examining JWS content before verification.
pub fn jws_decode_unverified(jws: &str) -> VerificationResult<(JwsHeader, Vec<u8>)> {
    let parts = split_compact_jws(jws)?;

    let header_bytes = base64url_decode(parts[0])?;
    let header = JwsHeader::from_json(&header_bytes)?;
    validate_jws_header_policy(&header)?;
    let payload = base64url_decode(parts[1])?;

    Ok((header, payload))
}

/// Get the header from a JWS without verifying.
pub fn jws_get_header(jws: &str) -> VerificationResult<JwsHeader> {
    let parts = split_compact_jws(jws)?;

    let header_bytes = base64url_decode(parts[0])?;
    let header = JwsHeader::from_json(&header_bytes)?;
    validate_jws_header_policy(&header)?;
    Ok(header)
}

fn split_compact_jws(jws: &str) -> VerificationResult<[&str; 3]> {
    if jws.is_empty() || jws.len() > MAX_COMPACT_JWS_BYTES {
        return Err(VerificationError::internal(
            "JWS is empty or exceeds the configured size limit".to_string(),
        ));
    }
    let mut segments = jws.splitn(4, '.');
    let header = segments.next().unwrap_or_default();
    let payload = segments.next().ok_or_else(|| {
        VerificationError::internal("Invalid JWS format: expected 3 parts".to_string())
    })?;
    let signature = segments.next().ok_or_else(|| {
        VerificationError::internal("Invalid JWS format: expected 3 parts".to_string())
    })?;
    if segments.next().is_some() || header.is_empty() || signature.is_empty() {
        return Err(VerificationError::internal(
            "Invalid JWS format: expected 3 parts".to_string(),
        ));
    }
    if header.len() > max_encoded_len(MAX_JWS_PROTECTED_HEADER_BYTES)
        || payload.len() > max_encoded_len(MAX_JWS_PAYLOAD_BYTES)
        || signature.len() > max_encoded_len(MAX_JWS_SIGNATURE_BYTES)
    {
        return Err(VerificationError::internal(
            "JWS segment exceeds the configured size limit".to_string(),
        ));
    }
    Ok([header, payload, signature])
}

fn validate_jws_header_policy(header: &JwsHeader) -> VerificationResult<()> {
    if header.jku.is_some() || header.x5u.is_some() {
        return Err(VerificationError::internal(
            "Remote JWS key references are not supported".to_string(),
        ));
    }
    if header
        .crit
        .as_ref()
        .is_some_and(|members| !members.is_empty())
    {
        return Err(VerificationError::internal(
            "Critical JWS header parameters are not supported".to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// Signature Operations
// ============================================================================

/// Verify a message signature.
fn verify_message(
    alg: &str,
    message: &[u8],
    signature: &[u8],
    key: &Jwk,
) -> VerificationResult<()> {
    match alg {
        "ES256" => verify_es256(message, signature, key),
        "ES384" => verify_es384(message, signature, key),
        "EdDSA" => verify_eddsa(message, signature, key),
        "HS256" => verify_hs256(message, signature, key),
        "HS384" => verify_hs384(message, signature, key),
        "HS512" => verify_hs512(message, signature, key),
        "RS256" => verify_rs256(message, signature, key),
        "RS384" => verify_rs384(message, signature, key),
        "RS512" => verify_rs512(message, signature, key),
        "PS256" => verify_ps256(message, signature, key),
        _ => Err(VerificationError::internal(format!(
            "Unsupported JWS algorithm: {}",
            alg
        ))),
    }
}

// ============================================================================
// ECDSA Signatures
// ============================================================================

fn verify_es256(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::EncodedPoint;

    let x = key
        .x
        .as_ref()
        .ok_or_else(|| VerificationError::internal("ES256 requires x coordinate".to_string()))?;
    let y = key
        .y
        .as_ref()
        .ok_or_else(|| VerificationError::internal("ES256 requires y coordinate".to_string()))?;

    let x_bytes = base64url_decode(x)?;
    let y_bytes = base64url_decode(y)?;

    // Build uncompressed point
    let mut point_bytes = vec![0x04];
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);

    let point = EncodedPoint::from_bytes(&point_bytes)
        .map_err(|e| VerificationError::internal(format!("Invalid ES256 point: {}", e)))?;

    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| VerificationError::internal(format!("Invalid ES256 key: {}", e)))?;

    let sig = Signature::from_bytes(signature.into())
        .map_err(|e| VerificationError::internal(format!("Invalid ES256 signature: {}", e)))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|e| VerificationError::internal(format!("ES256 verification failed: {}", e)))
}

fn verify_es384(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p384::EncodedPoint;

    let x = key
        .x
        .as_ref()
        .ok_or_else(|| VerificationError::internal("ES384 requires x coordinate".to_string()))?;
    let y = key
        .y
        .as_ref()
        .ok_or_else(|| VerificationError::internal("ES384 requires y coordinate".to_string()))?;

    let x_bytes = base64url_decode(x)?;
    let y_bytes = base64url_decode(y)?;

    let mut point_bytes = vec![0x04];
    point_bytes.extend_from_slice(&x_bytes);
    point_bytes.extend_from_slice(&y_bytes);

    let point = EncodedPoint::from_bytes(&point_bytes)
        .map_err(|e| VerificationError::internal(format!("Invalid ES384 point: {}", e)))?;

    let verifying_key = VerifyingKey::from_encoded_point(&point)
        .map_err(|e| VerificationError::internal(format!("Invalid ES384 key: {}", e)))?;

    let sig = Signature::from_bytes(signature.into())
        .map_err(|e| VerificationError::internal(format!("Invalid ES384 signature: {}", e)))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|e| VerificationError::internal(format!("ES384 verification failed: {}", e)))
}

// ============================================================================
// EdDSA Signatures
// ============================================================================

fn verify_eddsa(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    use marty_crypto::ed25519::Ed25519VerifyingKey;

    if key.crv.as_deref() != Some("Ed25519") {
        return Err(VerificationError::internal(
            "EdDSA only supports Ed25519 curve".to_string(),
        ));
    }

    let x = key
        .x
        .as_ref()
        .ok_or_else(|| VerificationError::internal("EdDSA requires public key (x)".to_string()))?;
    let x_bytes = base64url_decode(x)?;

    let verifying_key = Ed25519VerifyingKey::from_bytes(&x_bytes)?;
    Ok(verifying_key.verify(message, signature)?)
}

// ============================================================================
// HMAC Signatures
// ============================================================================

fn sign_hmac(message: &[u8], key: &Jwk, hash_len: usize) -> VerificationResult<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::{Sha256, Sha384, Sha512};

    let k = key.k.as_ref().ok_or_else(|| {
        VerificationError::internal("HMAC requires symmetric key (k)".to_string())
    })?;
    let key_bytes = base64url_decode(k)?;

    let mac = match hash_len {
        256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes)
                .map_err(|e| VerificationError::internal(format!("HMAC key error: {}", e)))?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        384 => {
            let mut mac = Hmac::<Sha384>::new_from_slice(&key_bytes)
                .map_err(|e| VerificationError::internal(format!("HMAC key error: {}", e)))?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(&key_bytes)
                .map_err(|e| VerificationError::internal(format!("HMAC key error: {}", e)))?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            return Err(VerificationError::internal(
                "Invalid HMAC hash length".to_string(),
            ))
        }
    };

    Ok(mac)
}

fn verify_hmac(
    message: &[u8],
    signature: &[u8],
    key: &Jwk,
    hash_len: usize,
) -> VerificationResult<()> {
    let expected = sign_hmac(message, key, hash_len)?;

    // Constant-time comparison
    if signature.len() != expected.len() {
        return Err(VerificationError::internal(
            "HMAC verification failed".to_string(),
        ));
    }

    let mut result = 0u8;
    for (a, b) in signature.iter().zip(expected.iter()) {
        result |= a ^ b;
    }

    if result != 0 {
        return Err(VerificationError::internal(
            "HMAC verification failed".to_string(),
        ));
    }

    Ok(())
}

fn verify_hs256(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    verify_hmac(message, signature, key, 256)
}

fn verify_hs384(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    verify_hmac(message, signature, key, 384)
}

fn verify_hs512(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    verify_hmac(message, signature, key, 512)
}

// ============================================================================
// RSA Signatures (placeholder - needs RSA key import)
// ============================================================================

fn verify_rs256(_message: &[u8], _signature: &[u8], _key: &Jwk) -> VerificationResult<()> {
    Err(VerificationError::internal(
        "RS256 verification not yet implemented".to_string(),
    ))
}

fn verify_rs384(_message: &[u8], _signature: &[u8], _key: &Jwk) -> VerificationResult<()> {
    Err(VerificationError::internal(
        "RS384 verification not yet implemented".to_string(),
    ))
}

fn verify_rs512(_message: &[u8], _signature: &[u8], _key: &Jwk) -> VerificationResult<()> {
    Err(VerificationError::internal(
        "RS512 verification not yet implemented".to_string(),
    ))
}

fn verify_ps256(_message: &[u8], _signature: &[u8], _key: &Jwk) -> VerificationResult<()> {
    Err(VerificationError::internal(
        "PS256 verification not yet implemented".to_string(),
    ))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use marty_crypto_test_support::openbao_transit::{DisposableOpenBao, ScopedTransitSigner};

    fn public_es256_jwk() -> Jwk {
        Jwk {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(marty_crypto_test_support::P256_PUBLIC_JWK_X.to_string()),
            y: Some(marty_crypto_test_support::P256_PUBLIC_JWK_Y.to_string()),
            ..Default::default()
        }
    }

    fn remote_es256() -> (ScopedTransitSigner, Jwk) {
        let signer = DisposableOpenBao::from_marked_env().create_es256();
        let public = Jwk::from_json(signer.public_jwk()).expect("remote ES256 public JWK");
        (signer, public)
    }

    fn remote_eddsa() -> (ScopedTransitSigner, Jwk) {
        let signer = DisposableOpenBao::from_marked_env().create_ed25519();
        let public = Jwk::from_json(signer.public_jwk()).expect("remote EdDSA public JWK");
        (signer, public)
    }

    fn remotely_signed_jws(
        header: &JwsHeader,
        payload: &[u8],
        signer: &ScopedTransitSigner,
    ) -> String {
        let signing_input = format!(
            "{}.{}",
            base64url_encode(&header.to_json().unwrap()),
            base64url_encode(payload)
        );
        let signature = match header.alg.as_str() {
            "ES256" => marty_crypto::ecdsa::normalize_signature(
                &signer.sign_der(signing_input.as_bytes()).unwrap(),
                "ES256",
            )
            .unwrap(),
            "EdDSA" => signer.sign_ed25519(signing_input.as_bytes()).unwrap(),
            _ => panic!("unsupported remote JWS test algorithm"),
        };
        format!("{}.{}", signing_input, base64url_encode(&signature))
    }

    fn compact_with_placeholder_signature(header: &JwsHeader, payload: &[u8]) -> String {
        format!(
            "{}.{}.AA",
            base64url_encode(&header.to_json().unwrap()),
            base64url_encode(payload)
        )
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped JWS signer"]
    fn test_jws_es256_roundtrip() {
        let (signer, key) = remote_es256();
        let header = JwsHeader::new("ES256");
        let payload = b"Hello, JWS!";

        let jws = remotely_signed_jws(&header, payload, &signer);

        // Should be three base64url parts separated by dots
        assert_eq!(jws.split('.').count(), 3);

        // Verify
        let (verified_header, verified_payload) = jws_verify(&jws, &key).unwrap();
        assert_eq!(verified_header.alg, "ES256");
        assert_eq!(verified_payload, payload);
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped JWS signer"]
    fn test_jws_eddsa_roundtrip() {
        let (signer, key) = remote_eddsa();
        let header = JwsHeader::new("EdDSA");
        let payload = b"Hello, EdDSA!";

        let jws = remotely_signed_jws(&header, payload, &signer);
        let (_, verified_payload) = jws_verify(&jws, &key).unwrap();

        assert_eq!(verified_payload, payload);
    }

    #[test]
    fn test_jws_hs256_roundtrip() {
        let key = Jwk {
            kty: "oct".to_string(),
            k: Some("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY".to_string()),
            ..Default::default()
        };
        let payload = b"Hello, HMAC!";
        let jws =
            "eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIEhNQUMh.86Od18GLG_-oP5WLzPAyRpRgJkG26CThNkT9bJkoZWY";
        let (_, verified_payload) = jws_verify(jws, &key).unwrap();

        assert_eq!(verified_payload, payload);
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped JWS signer"]
    fn test_jws_wrong_key() {
        let (signer, key1) = remote_es256();
        let (_, key2) = remote_es256();
        let header = JwsHeader::new("ES256");
        let payload = b"Secret message";

        let jws = remotely_signed_jws(&header, payload, &signer);
        assert!(jws_verify(&jws, &key1).is_ok());

        // Verification with wrong key should fail
        assert!(jws_verify(&jws, &key2).is_err());
    }

    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped JWS signer"]
    fn test_jws_tampered_payload() {
        let (signer, key) = remote_es256();
        let header = JwsHeader::new("ES256");
        let payload = b"Original";

        let jws = remotely_signed_jws(&header, payload, &signer);

        // Tamper with the payload
        let parts: Vec<&str> = jws.split('.').collect();
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            base64url_encode(b"Tampered"),
            parts[2]
        );

        assert!(jws_verify(&tampered, &key).is_err());
    }

    #[test]
    fn test_jws_decode_unverified() {
        let header = JwsHeader::new("ES256");
        let payload = b"Test payload";
        let jws = compact_with_placeholder_signature(&header, payload);

        let (decoded_header, decoded_payload) = jws_decode_unverified(&jws).unwrap();
        assert_eq!(decoded_header.alg, "ES256");
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_jws_get_header() {
        let mut header = JwsHeader::new("ES256");
        header.kid = Some("my-key-id".to_string());
        let payload = b"Test";
        let jws = compact_with_placeholder_signature(&header, payload);

        let parsed_header = jws_get_header(&jws).unwrap();
        assert_eq!(parsed_header.kid, Some("my-key-id".to_string()));
    }

    #[test]
    fn public_jws_parsers_reject_many_segments_and_oversized_segments() {
        let key = public_es256_jwk();
        for malformed in ["a.b.c.d", "a.b.c.d.e"] {
            assert!(jws_get_header(malformed).is_err());
            assert!(jws_decode_unverified(malformed).is_err());
            assert!(jws_verify(malformed, &key).is_err());
        }

        let oversized_header = "a".repeat(max_encoded_len(MAX_JWS_PROTECTED_HEADER_BYTES) + 1);
        let malformed = format!("{oversized_header}.e30.AA");
        assert!(jws_get_header(&malformed).is_err());

        let oversized_payload = "a".repeat(max_encoded_len(MAX_JWS_PAYLOAD_BYTES) + 1);
        let malformed = format!("e30.{oversized_payload}.AA");
        assert!(jws_decode_unverified(&malformed).is_err());

        let oversized_signature = "a".repeat(max_encoded_len(MAX_JWS_SIGNATURE_BYTES) + 1);
        let malformed = format!("e30.e30.{oversized_signature}");
        assert!(jws_verify(&malformed, &key).is_err());
    }

    #[test]
    fn public_jws_parsers_reject_duplicate_and_unsupported_headers() {
        let duplicate = base64url_encode(br#"{"alg":"ES256","jwk":{"kty":"EC","kty":"OKP"}}"#);
        let duplicate_jws = format!("{duplicate}.e30.AA");
        assert!(jws_get_header(&duplicate_jws).is_err());

        for header in [
            br#"{"alg":"ES256","jku":"https://keys.invalid/jwks"}"#.as_slice(),
            br#"{"alg":"ES256","x5u":"https://keys.invalid/cert"}"#.as_slice(),
            br#"{"alg":"ES256","crit":["unknown"],"unknown":true}"#.as_slice(),
        ] {
            let compact = format!("{}.e30.AA", base64url_encode(header));
            assert!(jws_get_header(&compact).is_err());
            assert!(jws_decode_unverified(&compact).is_err());
        }
    }
}
