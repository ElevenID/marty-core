//! JSON Web Encryption (JWE) implementation.
//!
//! Implements RFC 7516 JWE for encryption and decryption.
//! Supports direct ECDH-ES key agreement with AES-GCM content encryption.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{base64url_decode, base64url_encode, Jwk};
use crate::{VerificationError, VerificationResult};

const MAX_JWE_PLAINTEXT_BYTES: usize = 1024 * 1024;
const MAX_COMPACT_JWE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PROTECTED_HEADER_BYTES: usize = 16 * 1024;
const MAX_PARTY_INFO_BYTES: usize = 1024;
const AES_GCM_IV_BYTES: usize = 12;
const AES_GCM_TAG_BYTES: usize = 16;

// ============================================================================
// JWE Header
// ============================================================================

/// JWE Header (JOSE Header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JweHeader {
    /// Algorithm for encrypting the CEK
    pub alg: String,

    /// Content encryption algorithm
    pub enc: String,

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

    /// Ephemeral public key (for ECDH)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epk: Option<Jwk>,

    /// Agreement PartyUInfo
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apu: Option<String>,

    /// Agreement PartyVInfo
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apv: Option<String>,

    /// Compression algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zip: Option<String>,

    /// Unsupported protected parameters are retained so strict operations can
    /// reject them instead of silently ignoring security-relevant headers.
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl JweHeader {
    /// Create a new JWE header.
    pub fn new(alg: &str, enc: &str) -> Self {
        Self {
            alg: alg.to_string(),
            enc: enc.to_string(),
            typ: None,
            cty: None,
            kid: None,
            jku: None,
            jwk: None,
            epk: None,
            apu: None,
            apv: None,
            zip: None,
            additional: HashMap::new(),
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_json(&self) -> VerificationResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| {
            VerificationError::internal(format!("JWE header serialization failed: {}", e))
        })
    }

    /// Parse from JSON bytes.
    pub fn from_json(json: &[u8]) -> VerificationResult<Self> {
        serde_json::from_slice(json)
            .map_err(|e| VerificationError::internal(format!("JWE header parsing failed: {}", e)))
    }
}

// ============================================================================
// JWE Compact Serialization
// ============================================================================

fn content_encryption_key_len(enc: &str) -> VerificationResult<usize> {
    match enc {
        "A128GCM" => Ok(16),
        "A256GCM" => Ok(32),
        _ => Err(VerificationError::internal(format!(
            "Unsupported content encryption: {enc}"
        ))),
    }
}

fn decode_party_info(value: Option<&str>) -> VerificationResult<Vec<u8>> {
    let decoded = match value {
        Some(value) => base64url_decode(value)?,
        None => Vec::new(),
    };
    if decoded.len() > MAX_PARTY_INFO_BYTES {
        return Err(VerificationError::internal(
            "JWE agreement-party information exceeds the configured size limit".to_string(),
        ));
    }
    Ok(decoded)
}

/// Generate a fresh P-256 key pair for one HAIP encrypted response.
///
/// The public and private JSON values carry the same random key identifier and
/// JOSE encryption metadata. Callers may wrap the private JSON with their KMS,
/// but key generation and JWK construction remain canonical Rust behavior.
pub fn generate_haip_response_encryption_jwk_pair() -> VerificationResult<(String, String)> {
    let mut private = super::generate_ec_p256()?;
    private.kid = Some(format!("oid4vp-haip-{}", uuid::Uuid::new_v4()));
    private.alg = Some("ECDH-ES".to_string());
    private.use_ = Some("enc".to_string());
    let public = private.to_public();
    Ok((public.to_json()?, private.to_json()?))
}

/// Decrypt a bounded ECDH-ES compact JWE using a P-256 private JWK JSON value.
pub fn decrypt_haip_response(
    compact_jwe: &str,
    private_jwk_json: &str,
) -> VerificationResult<Vec<u8>> {
    if private_jwk_json.len() > 16 * 1024 {
        return Err(VerificationError::internal(
            "HAIP private JWK exceeds the configured size limit".to_string(),
        ));
    }
    let private_jwk = Jwk::from_json(private_jwk_json)?;
    if private_jwk.kty != "EC"
        || private_jwk.crv.as_deref() != Some("P-256")
        || private_jwk.d.is_none()
        || private_jwk
            .alg
            .as_deref()
            .is_some_and(|alg| alg != "ECDH-ES")
        || private_jwk
            .use_
            .as_deref()
            .is_some_and(|usage| usage != "enc")
    {
        return Err(VerificationError::internal(
            "HAIP decryption requires a private P-256 ECDH-ES encryption JWK".to_string(),
        ));
    }
    validate_haip_response_header(compact_jwe)?;
    jwe_decrypt(compact_jwe, &private_jwk)
}

/// Validate a HAIP compact-JWE envelope before a caller performs KMS unwrap.
pub fn validate_haip_response_header(compact_jwe: &str) -> VerificationResult<JweHeader> {
    let (_, header, _) = parse_and_validate_direct_jwe(compact_jwe)?;
    let epk = header.epk.as_ref().ok_or_else(|| {
        VerificationError::internal("ECDH-ES requires ephemeral public key (epk)".to_string())
    })?;
    if epk.kty != "EC"
        || epk.crv.as_deref() != Some("P-256")
        || epk.is_private()
        || !epk.extra.is_empty()
    {
        return Err(VerificationError::internal(
            "HAIP ECDH-ES requires a public P-256 epk".to_string(),
        ));
    }
    let x = base64url_decode(
        epk.x
            .as_ref()
            .ok_or_else(|| VerificationError::jwk_missing_field("epk.x"))?,
    )?;
    let y = base64url_decode(
        epk.y
            .as_ref()
            .ok_or_else(|| VerificationError::jwk_missing_field("epk.y"))?,
    )?;
    if x.len() != 32 || y.len() != 32 {
        return Err(VerificationError::internal(
            "HAIP P-256 epk coordinates must be 32 bytes".to_string(),
        ));
    }
    let mut point = vec![0x04];
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&point)
        .map_err(|error| VerificationError::internal(format!("Invalid HAIP epk: {error}")))?;
    Ok(header)
}

/// Create a JWE in compact serialization format using direct key agreement.
///
/// Uses ECDH-ES for key agreement and AES-GCM for content encryption.
///
/// # Arguments
///
/// * `plaintext` - Data to encrypt
/// * `recipient_key` - Recipient's public key (JWK)
/// * `enc` - Content encryption algorithm (e.g., "A256GCM")
///
/// # Returns
///
/// JWE in compact serialization format.
pub fn jwe_encrypt_direct(
    plaintext: &[u8],
    recipient_key: &Jwk,
    enc: &str,
) -> VerificationResult<String> {
    if plaintext.len() > MAX_JWE_PLAINTEXT_BYTES {
        return Err(VerificationError::internal(
            "JWE plaintext exceeds the configured size limit".to_string(),
        ));
    }
    // Validate encryption algorithm
    let key_len = content_encryption_key_len(enc)?;

    // Generate ephemeral key pair based on recipient key type
    let (epk_public, shared_secret) =
        match (recipient_key.kty.as_str(), recipient_key.crv.as_deref()) {
            ("OKP", Some("X25519")) => {
                use marty_crypto::ecdh::x25519_ephemeral_agree;
                let recipient_x = recipient_key.x.as_ref().ok_or_else(|| {
                    VerificationError::internal("X25519 key missing x".to_string())
                })?;
                let recipient_bytes = base64url_decode(recipient_x)?;
                if recipient_bytes.len() != 32 {
                    return Err(VerificationError::internal(
                        "X25519 recipient key must be 32 bytes".to_string(),
                    ));
                }
                let (epk, shared) = x25519_ephemeral_agree(&recipient_bytes)?;

                let epk_jwk = Jwk {
                    kty: "OKP".to_string(),
                    crv: Some("X25519".to_string()),
                    x: Some(base64url_encode(&epk)),
                    ..Default::default()
                };
                (epk_jwk, shared.to_vec())
            }
            ("EC", Some("P-256")) => {
                use elliptic_curve::sec1::ToEncodedPoint;
                use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};
                use rand::rngs::OsRng;

                // Parse recipient public key
                let x_bytes = base64url_decode(
                    recipient_key
                        .x
                        .as_ref()
                        .ok_or_else(|| VerificationError::jwk_missing_field("x"))?,
                )?;
                let y_bytes = base64url_decode(
                    recipient_key
                        .y
                        .as_ref()
                        .ok_or_else(|| VerificationError::jwk_missing_field("y"))?,
                )?;
                if x_bytes.len() != 32 || y_bytes.len() != 32 {
                    return Err(VerificationError::internal(
                        "P-256 recipient coordinates must be 32 bytes".to_string(),
                    ));
                }

                let mut point_bytes = vec![0x04];
                point_bytes.extend_from_slice(&x_bytes);
                point_bytes.extend_from_slice(&y_bytes);

                let recipient_pk = PublicKey::from_sec1_bytes(&point_bytes).map_err(|e| {
                    VerificationError::internal(format!("Invalid P-256 key: {}", e))
                })?;

                // Generate ephemeral key
                let ephem_secret = SecretKey::random(&mut OsRng);
                let ephem_public = ephem_secret.public_key();
                let ephem_point = ephem_public.to_encoded_point(false);

                // Perform ECDH
                let shared =
                    diffie_hellman(ephem_secret.to_nonzero_scalar(), recipient_pk.as_affine());

                let epk_jwk = Jwk {
                    kty: "EC".to_string(),
                    crv: Some("P-256".to_string()),
                    x: Some(base64url_encode(ephem_point.x().unwrap())),
                    y: Some(base64url_encode(ephem_point.y().unwrap())),
                    ..Default::default()
                };
                (epk_jwk, shared.raw_secret_bytes().to_vec())
            }
            _ => {
                return Err(VerificationError::internal(
                    "Unsupported key type for ECDH-ES".to_string(),
                ))
            }
        };

    // RFC 7518 section 4.6.2: direct ECDH-ES uses `enc` as AlgorithmID.
    let cek =
        marty_crypto::kdf::concat_kdf_sha256(&shared_secret, enc.as_bytes(), &[], &[], key_len)?;

    // Generate IV
    use rand::RngCore;
    let mut iv = vec![0u8; AES_GCM_IV_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut iv);

    // Encrypt content
    use marty_crypto::symmetric::{aes_128_gcm_encrypt, aes_256_gcm_encrypt};

    let header = JweHeader {
        alg: "ECDH-ES".to_string(),
        enc: enc.to_string(),
        epk: Some(epk_public),
        ..JweHeader::new("ECDH-ES", enc)
    };
    let header_json = header.to_json()?;
    let protected = base64url_encode(&header_json);
    let aad = protected.as_bytes();

    let ciphertext_with_tag = match key_len {
        16 => aes_128_gcm_encrypt(&cek, &iv, plaintext, aad)?,
        32 => aes_256_gcm_encrypt(&cek, &iv, plaintext, aad)?,
        _ => {
            return Err(VerificationError::internal(
                "Unsupported key length".to_string(),
            ))
        }
    };

    // Split ciphertext and tag
    let tag_len = AES_GCM_TAG_BYTES;
    let ciphertext_len = ciphertext_with_tag.len() - tag_len;
    let ciphertext = &ciphertext_with_tag[..ciphertext_len];
    let tag = &ciphertext_with_tag[ciphertext_len..];

    // For ECDH-ES (direct), encrypted key is empty
    let encrypted_key = "";

    Ok(format!(
        "{}.{}.{}.{}.{}",
        protected,
        encrypted_key,
        base64url_encode(&iv),
        base64url_encode(ciphertext),
        base64url_encode(tag)
    ))
}

fn parse_and_validate_direct_jwe(jwe: &str) -> VerificationResult<(Vec<&str>, JweHeader, usize)> {
    if jwe.is_empty() || jwe.len() > MAX_COMPACT_JWE_BYTES {
        return Err(VerificationError::internal(
            "JWE is empty or exceeds the configured size limit".to_string(),
        ));
    }
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(VerificationError::internal(
            "Invalid JWE format: expected 5 parts".to_string(),
        ));
    }
    if parts[0].is_empty() || parts[0].len() > MAX_PROTECTED_HEADER_BYTES {
        return Err(VerificationError::internal(
            "JWE protected header is empty or exceeds the configured size limit".to_string(),
        ));
    }

    let header = JweHeader::from_json(&base64url_decode(parts[0])?)?;
    if header.alg != "ECDH-ES" {
        return Err(VerificationError::internal(format!(
            "Unsupported key algorithm: {}",
            header.alg
        )));
    }
    if !parts[1].is_empty() {
        return Err(VerificationError::internal(
            "Direct ECDH-ES requires an empty encrypted-key segment".to_string(),
        ));
    }
    if header.zip.is_some() {
        return Err(VerificationError::internal(
            "JWE compression is not supported".to_string(),
        ));
    }
    if !header.additional.is_empty() {
        return Err(VerificationError::internal(
            "Unsupported protected JWE header parameter".to_string(),
        ));
    }
    if header.jku.is_some() || header.jwk.is_some() {
        return Err(VerificationError::internal(
            "Embedded or remotely referenced JWE keys are not supported".to_string(),
        ));
    }

    let key_len = content_encryption_key_len(&header.enc)?;
    let iv = base64url_decode(parts[2])?;
    let _ciphertext = base64url_decode(parts[3])?;
    let tag = base64url_decode(parts[4])?;
    if iv.len() != AES_GCM_IV_BYTES || tag.len() != AES_GCM_TAG_BYTES {
        return Err(VerificationError::internal(
            "JWE AES-GCM IV or authentication tag has an invalid length".to_string(),
        ));
    }
    Ok((parts, header, key_len))
}

/// Decrypt a JWE in compact serialization format.
///
/// # Arguments
///
/// * `jwe` - JWE in compact serialization
/// * `recipient_key` - Recipient's private key (JWK)
///
/// # Returns
///
/// Decrypted plaintext.
pub fn jwe_decrypt(jwe: &str, recipient_key: &Jwk) -> VerificationResult<Vec<u8>> {
    let (parts, header, key_len) = parse_and_validate_direct_jwe(jwe)?;
    let protected_b64 = parts[0];
    let iv_b64 = parts[2];
    let ciphertext_b64 = parts[3];
    let tag_b64 = parts[4];

    // Decode components
    let iv = base64url_decode(iv_b64)?;
    let ciphertext = base64url_decode(ciphertext_b64)?;
    let tag = base64url_decode(tag_b64)?;

    // Derive shared secret from ECDH
    let shared_secret = match header.alg.as_str() {
        "ECDH-ES" => {
            let epk = header.epk.as_ref().ok_or_else(|| {
                VerificationError::internal(
                    "ECDH-ES requires ephemeral public key (epk)".to_string(),
                )
            })?;
            if epk.is_private() || !epk.extra.is_empty() {
                return Err(VerificationError::internal(
                    "ECDH-ES epk must be a public JWK without extension fields".to_string(),
                ));
            }

            match (recipient_key.kty.as_str(), recipient_key.crv.as_deref()) {
                ("OKP", Some("X25519")) => {
                    use marty_crypto::ecdh::X25519KeyPair;

                    if epk.kty != "OKP" || epk.crv.as_deref() != Some("X25519") {
                        return Err(VerificationError::internal(
                            "ECDH-ES epk does not match the X25519 recipient key".to_string(),
                        ));
                    }

                    let d = recipient_key.d.as_ref().ok_or_else(|| {
                        VerificationError::internal(
                            "X25519 key missing d (private key)".to_string(),
                        )
                    })?;
                    let d_bytes = base64url_decode(d)?;
                    if d_bytes.len() != 32 {
                        return Err(VerificationError::internal(
                            "X25519 private key must be 32 bytes".to_string(),
                        ));
                    }

                    let epk_x = epk
                        .x
                        .as_ref()
                        .ok_or_else(|| VerificationError::internal("EPK missing x".to_string()))?;
                    let epk_bytes = base64url_decode(epk_x)?;
                    if epk_bytes.len() != 32 {
                        return Err(VerificationError::internal(
                            "X25519 epk must be 32 bytes".to_string(),
                        ));
                    }

                    let keypair = X25519KeyPair::from_secret_key(&d_bytes)?;
                    let shared = keypair.agree(&epk_bytes)?;
                    shared.to_vec()
                }
                ("EC", Some("P-256")) => {
                    use elliptic_curve::sec1::ToEncodedPoint;
                    use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};

                    if epk.kty != "EC" || epk.crv.as_deref() != Some("P-256") {
                        return Err(VerificationError::internal(
                            "ECDH-ES epk does not match the P-256 recipient key".to_string(),
                        ));
                    }

                    let d = recipient_key.d.as_ref().ok_or_else(|| {
                        VerificationError::internal("P-256 key missing d".to_string())
                    })?;
                    let d_bytes = base64url_decode(d)?;
                    if d_bytes.len() != 32 {
                        return Err(VerificationError::internal(
                            "P-256 private key must be 32 bytes".to_string(),
                        ));
                    }

                    let epk_x = base64url_decode(
                        epk.x
                            .as_ref()
                            .ok_or_else(|| VerificationError::jwk_missing_field("epk.x"))?,
                    )?;
                    let epk_y = base64url_decode(
                        epk.y
                            .as_ref()
                            .ok_or_else(|| VerificationError::jwk_missing_field("epk.y"))?,
                    )?;
                    if epk_x.len() != 32 || epk_y.len() != 32 {
                        return Err(VerificationError::internal(
                            "P-256 epk coordinates must be 32 bytes".to_string(),
                        ));
                    }

                    let mut point_bytes = vec![0x04];
                    point_bytes.extend_from_slice(&epk_x);
                    point_bytes.extend_from_slice(&epk_y);

                    let secret = SecretKey::from_slice(&d_bytes).map_err(|e| {
                        VerificationError::internal(format!("Invalid P-256 key: {}", e))
                    })?;
                    match (&recipient_key.x, &recipient_key.y) {
                        (Some(x), Some(y)) => {
                            let expected = secret.public_key().to_encoded_point(false);
                            let supplied_x = base64url_decode(x)?;
                            let supplied_y = base64url_decode(y)?;
                            if supplied_x.as_slice() != expected.x().unwrap().as_slice()
                                || supplied_y.as_slice() != expected.y().unwrap().as_slice()
                            {
                                return Err(VerificationError::internal(
                                    "P-256 private and public JWK parameters do not match"
                                        .to_string(),
                                ));
                            }
                        }
                        (None, None) => {}
                        _ => {
                            return Err(VerificationError::internal(
                                "P-256 recipient JWK must contain both x and y or neither"
                                    .to_string(),
                            ))
                        }
                    }
                    let epk_public = PublicKey::from_sec1_bytes(&point_bytes)
                        .map_err(|e| VerificationError::internal(format!("Invalid EPK: {}", e)))?;

                    let shared = diffie_hellman(secret.to_nonzero_scalar(), epk_public.as_affine());
                    shared.raw_secret_bytes().to_vec()
                }
                _ => {
                    return Err(VerificationError::internal(
                        "Unsupported key type for ECDH".to_string(),
                    ))
                }
            }
        }
        _ => {
            return Err(VerificationError::internal(format!(
                "Unsupported key algorithm: {}",
                header.alg
            )))
        }
    };

    let party_u_info = decode_party_info(header.apu.as_deref())?;
    let party_v_info = decode_party_info(header.apv.as_deref())?;
    let cek = marty_crypto::kdf::concat_kdf_sha256(
        &shared_secret,
        header.enc.as_bytes(),
        &party_u_info,
        &party_v_info,
        key_len,
    )?;

    // Combine ciphertext and tag for decryption
    let mut ciphertext_with_tag = ciphertext;
    ciphertext_with_tag.extend_from_slice(&tag);

    // Decrypt
    use marty_crypto::symmetric::{aes_128_gcm_decrypt, aes_256_gcm_decrypt};
    let aad = protected_b64.as_bytes();

    let plaintext = match key_len {
        16 => aes_128_gcm_decrypt(&cek, &iv, &ciphertext_with_tag, aad)?,
        32 => aes_256_gcm_decrypt(&cek, &iv, &ciphertext_with_tag, aad)?,
        _ => {
            return Err(VerificationError::internal(
                "Unsupported key length".to_string(),
            ))
        }
    };

    Ok(plaintext)
}

/// Get the header from a JWE without decrypting.
pub fn jwe_get_header(jwe: &str) -> VerificationResult<JweHeader> {
    if jwe.is_empty() || jwe.len() > MAX_COMPACT_JWE_BYTES {
        return Err(VerificationError::internal(
            "JWE is empty or exceeds the configured size limit".to_string(),
        ));
    }
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 || parts[0].is_empty() || parts[0].len() > MAX_PROTECTED_HEADER_BYTES {
        return Err(VerificationError::internal(
            "Invalid JWE format".to_string(),
        ));
    }

    let header_bytes = base64url_decode(parts[0])?;
    JweHeader::from_json(&header_bytes)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::{generate_ec_p256, generate_x25519};
    use super::*;

    #[test]
    fn test_jwe_x25519_roundtrip() {
        let recipient = generate_x25519().unwrap();
        let plaintext = b"Secret message for JWE encryption!";

        let jwe = jwe_encrypt_direct(plaintext, &recipient.to_public(), "A256GCM").unwrap();

        // Should have 5 parts
        assert_eq!(jwe.split('.').count(), 5);

        let decrypted = jwe_decrypt(&jwe, &recipient).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_jwe_p256_roundtrip() {
        use super::super::generate_ec_p256;

        let recipient = generate_ec_p256().unwrap();
        let plaintext = b"Secret message with P-256!";

        let jwe = jwe_encrypt_direct(plaintext, &recipient.to_public(), "A256GCM").unwrap();
        let decrypted = jwe_decrypt(&jwe, &recipient).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_jwe_a128gcm() {
        let recipient = generate_x25519().unwrap();
        let plaintext = b"Testing A128GCM encryption";

        let jwe = jwe_encrypt_direct(plaintext, &recipient.to_public(), "A128GCM").unwrap();
        let decrypted = jwe_decrypt(&jwe, &recipient).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_jwe_wrong_key() {
        let sender_key = generate_x25519().unwrap();
        let wrong_key = generate_x25519().unwrap();
        let plaintext = b"Secret";

        let jwe = jwe_encrypt_direct(plaintext, &sender_key.to_public(), "A256GCM").unwrap();

        // Decryption with wrong key should fail
        assert!(jwe_decrypt(&jwe, &wrong_key).is_err());
    }

    #[test]
    fn test_jwe_get_header() {
        let recipient = generate_x25519().unwrap();
        let plaintext = b"Test";

        let jwe = jwe_encrypt_direct(plaintext, &recipient.to_public(), "A256GCM").unwrap();

        let header = jwe_get_header(&jwe).unwrap();
        assert_eq!(header.alg, "ECDH-ES");
        assert_eq!(header.enc, "A256GCM");
        assert!(header.epk.is_some());
    }

    #[test]
    fn generated_haip_key_pair_has_matching_metadata() {
        let (public_json, private_json) = generate_haip_response_encryption_jwk_pair().unwrap();
        let public = Jwk::from_json(&public_json).unwrap();
        let private = Jwk::from_json(&private_json).unwrap();

        assert!(!public.is_private());
        assert!(private.is_private());
        assert_eq!(public.kid, private.kid);
        assert_eq!(public.alg.as_deref(), Some("ECDH-ES"));
        assert_eq!(public.use_.as_deref(), Some("enc"));
        assert!(public_json.contains("\"use\":\"enc\""));
        assert!(!public_json.contains("\"use_\""));
        assert_eq!(public.x, private.x);
        assert_eq!(public.y, private.y);
    }

    #[test]
    fn haip_helper_decrypts_a256gcm() {
        let (public_json, private_json) = generate_haip_response_encryption_jwk_pair().unwrap();
        let public = Jwk::from_json(&public_json).unwrap();
        let compact =
            jwe_encrypt_direct(b"{\"vp_token\":\"fixture\"}", &public, "A256GCM").unwrap();

        assert_eq!(
            decrypt_haip_response(&compact, &private_json).unwrap(),
            b"{\"vp_token\":\"fixture\"}"
        );
    }

    #[test]
    fn decrypts_jwcrypto_interoperability_vector() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/haip_jwe.json")).unwrap();
        let private_jwk = serde_json::to_string(&vector["private_jwk"]).unwrap();
        validate_haip_response_header(vector["compact_jwe"].as_str().unwrap()).unwrap();
        let plaintext =
            decrypt_haip_response(vector["compact_jwe"].as_str().unwrap(), &private_jwk).unwrap();
        assert_eq!(plaintext, vector["plaintext"].as_str().unwrap().as_bytes());
    }

    #[test]
    fn direct_ecdh_es_rejects_wrapped_key_and_algorithm_confusion() {
        let recipient = generate_x25519().unwrap();
        let compact = jwe_encrypt_direct(b"secret", &recipient.to_public(), "A256GCM").unwrap();
        let mut parts: Vec<String> = compact.split('.').map(str::to_string).collect();
        parts[1] = base64url_encode(b"not-empty");
        assert!(jwe_decrypt(&parts.join("."), &recipient).is_err());

        let mut parts: Vec<String> = compact.split('.').map(str::to_string).collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&base64url_decode(&parts[0]).unwrap()).unwrap();
        header["alg"] = serde_json::json!("ECDH-ES+A256KW");
        parts[0] = base64url_encode(&serde_json::to_vec(&header).unwrap());
        assert!(jwe_decrypt(&parts.join("."), &recipient).is_err());
    }

    #[test]
    fn direct_ecdh_es_rejects_unsupported_headers_and_encryption() {
        let recipient = generate_x25519().unwrap();
        assert!(jwe_encrypt_direct(b"secret", &recipient.to_public(), "A192GCM").is_err());

        let compact = jwe_encrypt_direct(b"secret", &recipient.to_public(), "A128GCM").unwrap();
        let mut parts: Vec<String> = compact.split('.').map(str::to_string).collect();
        let mut header: serde_json::Value =
            serde_json::from_slice(&base64url_decode(&parts[0]).unwrap()).unwrap();
        header["crit"] = serde_json::json!(["unsupported"]);
        parts[0] = base64url_encode(&serde_json::to_vec(&header).unwrap());
        assert!(jwe_decrypt(&parts.join("."), &recipient).is_err());
        assert!(validate_haip_response_header(&compact).is_err());
    }

    #[test]
    fn haip_rejects_inconsistent_private_and_public_parameters() {
        let (_, private_json) = generate_haip_response_encryption_jwk_pair().unwrap();
        let mut private = Jwk::from_json(&private_json).unwrap();
        let other = generate_ec_p256().unwrap();
        private.x = other.x;
        private.y = other.y;
        let compact = jwe_encrypt_direct(b"secret", &private.to_public(), "A256GCM").unwrap();
        assert!(decrypt_haip_response(&compact, &private.to_json().unwrap()).is_err());
    }
}
