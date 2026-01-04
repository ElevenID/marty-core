//! JSON Web Encryption (JWE) implementation.
//!
//! Implements RFC 7516 JWE for encryption and decryption.
//! Supports key agreement (ECDH-ES) and key wrapping algorithms.

use serde::{Deserialize, Serialize};

use super::{base64url_decode, base64url_encode, Jwk};
use crate::{VerificationError, VerificationResult};

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
    // Validate encryption algorithm
    let (key_len, _iv_len, _tag_len) = match enc {
        "A128GCM" => (16, 12, 16),
        "A192GCM" => (24, 12, 16),
        "A256GCM" => (32, 12, 16),
        _ => {
            return Err(VerificationError::internal(format!(
                "Unsupported content encryption: {}",
                enc
            )))
        }
    };

    // Generate ephemeral key pair based on recipient key type
    let (epk_public, shared_secret) =
        match (recipient_key.kty.as_str(), recipient_key.crv.as_deref()) {
            ("OKP", Some("X25519")) => {
                use marty_crypto::ecdh::x25519_ephemeral_agree;
                let recipient_x = recipient_key.x.as_ref().ok_or_else(|| {
                    VerificationError::internal("X25519 key missing x".to_string())
                })?;
                let recipient_bytes = base64url_decode(recipient_x)?;
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

    // Derive CEK using Concat KDF (simplified - just use HKDF)
    use marty_crypto::kdf::hkdf_sha256;
    let info = format!("A{}GCM", key_len * 8);
    let cek = hkdf_sha256(&shared_secret, &[], info.as_bytes(), key_len)?;

    // Generate IV
    use rand::RngCore;
    let mut iv = vec![0u8; 12];
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
    let tag_len = 16;
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
    // Split into parts
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.len() != 5 {
        return Err(VerificationError::internal(
            "Invalid JWE format: expected 5 parts".to_string(),
        ));
    }

    let protected_b64 = parts[0];
    let _encrypted_key_b64 = parts[1];
    let iv_b64 = parts[2];
    let ciphertext_b64 = parts[3];
    let tag_b64 = parts[4];

    // Decode header
    let header_bytes = base64url_decode(protected_b64)?;
    let header = JweHeader::from_json(&header_bytes)?;

    // Decode components
    let iv = base64url_decode(iv_b64)?;
    let ciphertext = base64url_decode(ciphertext_b64)?;
    let tag = base64url_decode(tag_b64)?;

    // Get encryption parameters
    let (key_len, _iv_len, _tag_len) = match header.enc.as_str() {
        "A128GCM" => (16, 12, 16),
        "A192GCM" => (24, 12, 16),
        "A256GCM" => (32, 12, 16),
        _ => {
            return Err(VerificationError::internal(format!(
                "Unsupported content encryption: {}",
                header.enc
            )))
        }
    };

    // Derive shared secret from ECDH
    let shared_secret = match header.alg.as_str() {
        "ECDH-ES" | "ECDH-ES+A128KW" | "ECDH-ES+A256KW" => {
            let epk = header.epk.as_ref().ok_or_else(|| {
                VerificationError::internal(
                    "ECDH-ES requires ephemeral public key (epk)".to_string(),
                )
            })?;

            match (recipient_key.kty.as_str(), recipient_key.crv.as_deref()) {
                ("OKP", Some("X25519")) => {
                    use marty_crypto::ecdh::X25519KeyPair;

                    let d = recipient_key.d.as_ref().ok_or_else(|| {
                        VerificationError::internal(
                            "X25519 key missing d (private key)".to_string(),
                        )
                    })?;
                    let d_bytes = base64url_decode(d)?;

                    let epk_x = epk
                        .x
                        .as_ref()
                        .ok_or_else(|| VerificationError::internal("EPK missing x".to_string()))?;
                    let epk_bytes = base64url_decode(epk_x)?;

                    let keypair = X25519KeyPair::from_secret_key(&d_bytes)?;
                    let shared = keypair.agree(&epk_bytes)?;
                    shared.to_vec()
                }
                ("EC", Some("P-256")) => {
                    use p256::{ecdh::diffie_hellman, PublicKey, SecretKey};

                    let d = recipient_key.d.as_ref().ok_or_else(|| {
                        VerificationError::internal("P-256 key missing d".to_string())
                    })?;
                    let d_bytes = base64url_decode(d)?;

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

                    let mut point_bytes = vec![0x04];
                    point_bytes.extend_from_slice(&epk_x);
                    point_bytes.extend_from_slice(&epk_y);

                    let secret = SecretKey::from_slice(&d_bytes).map_err(|e| {
                        VerificationError::internal(format!("Invalid P-256 key: {}", e))
                    })?;
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

    // Derive CEK
    use marty_crypto::kdf::hkdf_sha256;
    let info = format!("A{}GCM", key_len * 8);
    let cek = hkdf_sha256(&shared_secret, &[], info.as_bytes(), key_len)?;

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
    let parts: Vec<&str> = jwe.split('.').collect();
    if parts.is_empty() {
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
    use super::super::generate_x25519;
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
}
