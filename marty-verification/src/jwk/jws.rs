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

/// Create a JWS in compact serialization format.
///
/// # Arguments
///
/// * `header` - JWS header
/// * `payload` - Payload bytes
/// * `key` - Signing key (JWK)
///
/// # Returns
///
/// JWS in compact serialization: BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
#[cfg(test)]
pub fn jws_sign(header: &JwsHeader, payload: &[u8], key: &Jwk) -> VerificationResult<String> {
    // Encode header and payload
    let header_b64 = base64url_encode(&header.to_json()?);
    let payload_b64 = base64url_encode(payload);

    // Create signing input
    let signing_input = format!("{}.{}", header_b64, payload_b64);

    // Sign based on algorithm
    let signature = sign_message(&header.alg, signing_input.as_bytes(), key)?;
    let signature_b64 = base64url_encode(&signature);

    Ok(format!("{}.{}", signing_input, signature_b64))
}

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

/// Sign a message using the specified algorithm and key.
#[cfg(test)]
fn sign_message(alg: &str, message: &[u8], key: &Jwk) -> VerificationResult<Vec<u8>> {
    match alg {
        "ES256" => sign_es256(message, key),
        "ES384" => sign_es384(message, key),
        "EdDSA" => sign_eddsa(message, key),
        "HS256" => sign_hs256(message, key),
        "HS384" => sign_hs384(message, key),
        "HS512" => sign_hs512(message, key),
        "RS256" => sign_rs256(message, key),
        "RS384" => sign_rs384(message, key),
        "RS512" => sign_rs512(message, key),
        "PS256" => sign_ps256(message, key),
        _ => Err(VerificationError::internal(format!(
            "Unsupported JWS algorithm: {}",
            alg
        ))),
    }
}

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

#[cfg(test)]
fn sign_es256(message: &[u8], key: &Jwk) -> VerificationResult<Vec<u8>> {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    let d = key
        .d
        .as_ref()
        .ok_or_else(|| VerificationError::internal("ES256 requires private key (d)".to_string()))?;
    let d_bytes = base64url_decode(d)?;

    let signing_key = SigningKey::from_slice(&d_bytes)
        .map_err(|e| VerificationError::internal(format!("Invalid ES256 key: {}", e)))?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
}

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

#[cfg(test)]
fn sign_es384(message: &[u8], key: &Jwk) -> VerificationResult<Vec<u8>> {
    use p384::ecdsa::{signature::Signer, Signature, SigningKey};

    let d = key
        .d
        .as_ref()
        .ok_or_else(|| VerificationError::internal("ES384 requires private key (d)".to_string()))?;
    let d_bytes = base64url_decode(d)?;

    let signing_key = SigningKey::from_slice(&d_bytes)
        .map_err(|e| VerificationError::internal(format!("Invalid ES384 key: {}", e)))?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_bytes().to_vec())
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

#[cfg(test)]
fn sign_eddsa(message: &[u8], key: &Jwk) -> VerificationResult<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};

    if key.crv.as_deref() != Some("Ed25519") {
        return Err(VerificationError::internal(
            "EdDSA only supports Ed25519 curve".to_string(),
        ));
    }

    let d = key
        .d
        .as_ref()
        .ok_or_else(|| VerificationError::internal("EdDSA requires private key (d)".to_string()))?;
    let d_bytes = base64url_decode(d)?;

    let secret: [u8; 32] = d_bytes.try_into().map_err(|_| {
        VerificationError::internal("Ed25519 private key must be 32 bytes".to_string())
    })?;
    Ok(SigningKey::from_bytes(&secret)
        .sign(message)
        .to_bytes()
        .to_vec())
}

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

#[cfg(test)]
fn sign_hs256(message: &[u8], key: &Jwk) -> VerificationResult<Vec<u8>> {
    sign_hmac(message, key, 256)
}

fn verify_hs256(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    verify_hmac(message, signature, key, 256)
}

#[cfg(test)]
fn sign_hs384(message: &[u8], key: &Jwk) -> VerificationResult<Vec<u8>> {
    sign_hmac(message, key, 384)
}

fn verify_hs384(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    verify_hmac(message, signature, key, 384)
}

#[cfg(test)]
fn sign_hs512(message: &[u8], key: &Jwk) -> VerificationResult<Vec<u8>> {
    sign_hmac(message, key, 512)
}

fn verify_hs512(message: &[u8], signature: &[u8], key: &Jwk) -> VerificationResult<()> {
    verify_hmac(message, signature, key, 512)
}

// ============================================================================
// RSA Signatures (placeholder - needs RSA key import)
// ============================================================================

#[cfg(test)]
fn sign_rs256(_message: &[u8], _key: &Jwk) -> VerificationResult<Vec<u8>> {
    Err(VerificationError::internal(
        "RS256 signing not yet implemented".to_string(),
    ))
}

fn verify_rs256(_message: &[u8], _signature: &[u8], _key: &Jwk) -> VerificationResult<()> {
    Err(VerificationError::internal(
        "RS256 verification not yet implemented".to_string(),
    ))
}

#[cfg(test)]
fn sign_rs384(_message: &[u8], _key: &Jwk) -> VerificationResult<Vec<u8>> {
    Err(VerificationError::internal(
        "RS384 signing not yet implemented".to_string(),
    ))
}

fn verify_rs384(_message: &[u8], _signature: &[u8], _key: &Jwk) -> VerificationResult<()> {
    Err(VerificationError::internal(
        "RS384 verification not yet implemented".to_string(),
    ))
}

#[cfg(test)]
fn sign_rs512(_message: &[u8], _key: &Jwk) -> VerificationResult<Vec<u8>> {
    Err(VerificationError::internal(
        "RS512 signing not yet implemented".to_string(),
    ))
}

fn verify_rs512(_message: &[u8], _signature: &[u8], _key: &Jwk) -> VerificationResult<()> {
    Err(VerificationError::internal(
        "RS512 verification not yet implemented".to_string(),
    ))
}

#[cfg(test)]
fn sign_ps256(_message: &[u8], _key: &Jwk) -> VerificationResult<Vec<u8>> {
    Err(VerificationError::internal(
        "PS256 signing not yet implemented".to_string(),
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
    use super::super::generate_ec_p256;
    use super::*;

    #[test]
    fn test_jws_es256_roundtrip() {
        let key = generate_ec_p256().unwrap();
        let header = JwsHeader::new("ES256");
        let payload = b"Hello, JWS!";

        let jws = jws_sign(&header, payload, &key).unwrap();

        // Should be three base64url parts separated by dots
        assert_eq!(jws.split('.').count(), 3);

        // Verify
        let (verified_header, verified_payload) = jws_verify(&jws, &key).unwrap();
        assert_eq!(verified_header.alg, "ES256");
        assert_eq!(verified_payload, payload);
    }

    #[test]
    fn test_jws_eddsa_roundtrip() {
        use super::super::generate_ed25519;

        let key = generate_ed25519().unwrap();
        let header = JwsHeader::new("EdDSA");
        let payload = b"Hello, EdDSA!";

        let jws = jws_sign(&header, payload, &key).unwrap();
        let (_, verified_payload) = jws_verify(&jws, &key).unwrap();

        assert_eq!(verified_payload, payload);
    }

    #[test]
    fn test_jws_hs256_roundtrip() {
        use super::super::generate_symmetric;

        let key = generate_symmetric(32).unwrap();
        let header = JwsHeader::new("HS256");
        let payload = b"Hello, HMAC!";

        let jws = jws_sign(&header, payload, &key).unwrap();
        let (_, verified_payload) = jws_verify(&jws, &key).unwrap();

        assert_eq!(verified_payload, payload);
    }

    #[test]
    fn test_jws_wrong_key() {
        let key1 = generate_ec_p256().unwrap();
        let key2 = generate_ec_p256().unwrap();
        let header = JwsHeader::new("ES256");
        let payload = b"Secret message";

        let jws = jws_sign(&header, payload, &key1).unwrap();

        // Verification with wrong key should fail
        assert!(jws_verify(&jws, &key2).is_err());
    }

    #[test]
    fn test_jws_tampered_payload() {
        let key = generate_ec_p256().unwrap();
        let header = JwsHeader::new("ES256");
        let payload = b"Original";

        let jws = jws_sign(&header, payload, &key).unwrap();

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
        let key = generate_ec_p256().unwrap();
        let header = JwsHeader::new("ES256");
        let payload = b"Test payload";

        let jws = jws_sign(&header, payload, &key).unwrap();

        let (decoded_header, decoded_payload) = jws_decode_unverified(&jws).unwrap();
        assert_eq!(decoded_header.alg, "ES256");
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn test_jws_get_header() {
        let key = generate_ec_p256().unwrap();
        let mut header = JwsHeader::new("ES256");
        header.kid = Some("my-key-id".to_string());
        let payload = b"Test";

        let jws = jws_sign(&header, payload, &key).unwrap();

        let parsed_header = jws_get_header(&jws).unwrap();
        assert_eq!(parsed_header.kid, Some("my-key-id".to_string()));
    }

    #[test]
    fn public_jws_parsers_reject_many_segments_and_oversized_segments() {
        let key = generate_ec_p256().unwrap().to_public();
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
