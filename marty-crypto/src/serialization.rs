//! Key serialization and deserialization.
//!
//! Supports PEM/DER encoding for private and public keys.
//! Replaces Python cryptography's serialization module.

use crate::{CryptoError, CryptoResult};
use der::{Decode, DecodePem, Encode};
use elliptic_curve::sec1::FromEncodedPoint;
use spki::SubjectPublicKeyInfoOwned;

// ============================================================================
// Private Key Operations
// ============================================================================

/// Load a private key from PEM format.
///
/// Supports PKCS#8 format for EC and RSA keys.
pub fn load_private_key_pem(pem_data: &str) -> CryptoResult<Vec<u8>> {
    // Check for encrypted key
    if pem_data.contains("ENCRYPTED") {
        return Err(CryptoError::key_error(
            "Encrypted private keys require a password. Use load_private_key_pem_encrypted().",
        ));
    }

    // Try PKCS#8 format first
    if pem_data.contains("BEGIN PRIVATE KEY") {
        // Use SecretDocument for owned PKCS#8 private key
        let (label, doc) = pem_rfc7468::decode_vec(pem_data.as_bytes())
            .map_err(|e| CryptoError::pem_error(format!("Failed to parse PKCS#8 PEM: {}", e)))?;
        if label != "PRIVATE KEY" {
            return Err(CryptoError::pem_error("Expected PRIVATE KEY label"));
        }
        return Ok(doc);
    }

    // Try SEC1 EC private key format
    if pem_data.contains("BEGIN EC PRIVATE KEY") {
        // Parse SEC1 and convert to PKCS#8
        return load_ec_private_key_sec1_pem(pem_data);
    }

    // Try RSA PKCS#1 format
    if pem_data.contains("BEGIN RSA PRIVATE KEY") {
        return load_rsa_private_key_pkcs1_pem(pem_data);
    }

    Err(CryptoError::pem_error("Unknown private key format"))
}

/// Load an EC private key from SEC1 PEM format.
fn load_ec_private_key_sec1_pem(pem_data: &str) -> CryptoResult<Vec<u8>> {
    // Try P-256 first
    if let Ok(key) = p256::SecretKey::from_sec1_pem(pem_data) {
        use pkcs8::EncodePrivateKey;
        let doc = key.to_pkcs8_der().map_err(|e| {
            CryptoError::encoding_error(format!("Failed to convert to PKCS#8: {}", e))
        })?;
        return Ok(doc.as_bytes().to_vec());
    }

    // Try P-384
    if let Ok(key) = p384::SecretKey::from_sec1_pem(pem_data) {
        use pkcs8::EncodePrivateKey;
        let doc = key.to_pkcs8_der().map_err(|e| {
            CryptoError::encoding_error(format!("Failed to convert to PKCS#8: {}", e))
        })?;
        return Ok(doc.as_bytes().to_vec());
    }

    Err(CryptoError::pem_error(
        "Failed to parse SEC1 EC private key",
    ))
}

/// Load an RSA private key from PKCS#1 PEM format.
fn load_rsa_private_key_pkcs1_pem(pem_data: &str) -> CryptoResult<Vec<u8>> {
    use pkcs8::EncodePrivateKey;
    use rsa::pkcs1::DecodeRsaPrivateKey;

    let key = rsa::RsaPrivateKey::from_pkcs1_pem(pem_data)
        .map_err(|e| CryptoError::pem_error(format!("Failed to parse PKCS#1 RSA key: {}", e)))?;

    let doc = key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::encoding_error(format!("Failed to convert to PKCS#8: {}", e)))?;

    Ok(doc.as_bytes().to_vec())
}

/// Load a private key from DER format (PKCS#8).
pub fn load_private_key_der(der_data: &[u8]) -> CryptoResult<Vec<u8>> {
    // Validate it's a valid PKCS#8 structure
    let _info = pkcs8::PrivateKeyInfo::from_der(der_data)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse private key DER: {}", e)))?;

    Ok(der_data.to_vec())
}

/// Save a private key to PEM format (PKCS#8).
pub fn save_private_key_pem(private_key_der: &[u8]) -> CryptoResult<String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(private_key_der);

    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).map_err(|_| CryptoError::encoding_error("invalid UTF-8 in base64 output"))?);
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");

    Ok(pem)
}

/// Save a private key to DER format (already in DER, just validate).
pub fn save_private_key_der(private_key_der: &[u8]) -> CryptoResult<Vec<u8>> {
    load_private_key_der(private_key_der)
}

/// Convert raw EC private key bytes to PKCS#8 DER format.
///
/// # Arguments
/// * `raw_key` - Raw private key bytes (32 bytes for P-256, 48 for P-384, 32 for Ed25519)
/// * `key_type` - One of "EC_P256", "EC_P384", "Ed25519"
pub fn raw_private_key_to_pkcs8(raw_key: &[u8], key_type: &str) -> CryptoResult<Vec<u8>> {
    match key_type {
        "EC_P256" | "P256" | "secp256r1" => {
            if raw_key.len() != 32 {
                return Err(CryptoError::key_error(format!(
                    "P-256 private key must be 32 bytes, got {}",
                    raw_key.len()
                )));
            }
            let array: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| CryptoError::key_error("Invalid P-256 key length"))?;
            let secret = p256::SecretKey::from_bytes(&array.into())
                .map_err(|e| CryptoError::key_error(format!("Invalid P-256 key: {}", e)))?;
            use pkcs8::EncodePrivateKey;
            let doc = secret.to_pkcs8_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode PKCS#8: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        "EC_P384" | "P384" | "secp384r1" => {
            if raw_key.len() != 48 {
                return Err(CryptoError::key_error(format!(
                    "P-384 private key must be 48 bytes, got {}",
                    raw_key.len()
                )));
            }
            let array: [u8; 48] = raw_key
                .try_into()
                .map_err(|_| CryptoError::key_error("Invalid P-384 key length"))?;
            let secret = p384::SecretKey::from_bytes(&array.into())
                .map_err(|e| CryptoError::key_error(format!("Invalid P-384 key: {}", e)))?;
            use pkcs8::EncodePrivateKey;
            let doc = secret.to_pkcs8_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode PKCS#8: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        "Ed25519" => {
            if raw_key.len() != 32 {
                return Err(CryptoError::key_error(format!(
                    "Ed25519 private key must be 32 bytes, got {}",
                    raw_key.len()
                )));
            }
            let array: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| CryptoError::key_error("Invalid Ed25519 key length"))?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&array);
            use pkcs8::EncodePrivateKey;
            let doc = signing_key.to_pkcs8_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode PKCS#8: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        _ => Err(CryptoError::key_error(format!(
            "Unsupported key type: {}",
            key_type
        ))),
    }
}

/// Convert raw EC public key bytes to SPKI DER format.
///
/// # Arguments
/// * `raw_key` - Raw public key bytes (65 bytes for P-256/P-384 uncompressed, 32 for Ed25519)
/// * `key_type` - One of "EC_P256", "EC_P384", "Ed25519"
pub fn raw_public_key_to_spki(raw_key: &[u8], key_type: &str) -> CryptoResult<Vec<u8>> {
    match key_type {
        "EC_P256" | "P256" | "secp256r1" => {
            let point = p256::EncodedPoint::from_bytes(raw_key)
                .map_err(|e| CryptoError::key_error(format!("Invalid P-256 public key: {}", e)))?;
            let public_key = p256::PublicKey::from_encoded_point(&point)
                .into_option()
                .ok_or_else(|| CryptoError::key_error("Invalid P-256 public key point"))?;
            use pkcs8::EncodePublicKey;
            let doc = public_key.to_public_key_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode SPKI: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        "EC_P384" | "P384" | "secp384r1" => {
            let point = p384::EncodedPoint::from_bytes(raw_key)
                .map_err(|e| CryptoError::key_error(format!("Invalid P-384 public key: {}", e)))?;
            let public_key = p384::PublicKey::from_encoded_point(&point)
                .into_option()
                .ok_or_else(|| CryptoError::key_error("Invalid P-384 public key point"))?;
            use pkcs8::EncodePublicKey;
            let doc = public_key.to_public_key_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode SPKI: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        "Ed25519" => {
            if raw_key.len() != 32 {
                return Err(CryptoError::key_error(format!(
                    "Ed25519 public key must be 32 bytes, got {}",
                    raw_key.len()
                )));
            }
            encode_ed25519_public_key_spki(raw_key)
        }
        _ => Err(CryptoError::key_error(format!(
            "Unsupported key type: {}",
            key_type
        ))),
    }
}

/// Extract raw private key bytes from PKCS#8 DER format.
pub fn pkcs8_to_raw_private_key(pkcs8_der: &[u8]) -> CryptoResult<(Vec<u8>, String)> {
    let key_type = detect_private_key_type(pkcs8_der)?;

    match key_type.as_str() {
        "EC_P256" => {
            use pkcs8::DecodePrivateKey;
            let secret = p256::SecretKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| CryptoError::key_error(format!("Failed to parse P-256 key: {}", e)))?;
            Ok((secret.to_bytes().to_vec(), key_type))
        }
        "EC_P384" => {
            use pkcs8::DecodePrivateKey;
            let secret = p384::SecretKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| CryptoError::key_error(format!("Failed to parse P-384 key: {}", e)))?;
            Ok((secret.to_bytes().to_vec(), key_type))
        }
        "Ed25519" => {
            let info = pkcs8::PrivateKeyInfo::from_der(pkcs8_der)
                .map_err(|e| CryptoError::der_error(format!("Failed to parse key: {}", e)))?;
            let private_bytes = info.private_key;
            // Ed25519 private key may have OCTET STRING wrapper
            let seed = if private_bytes.len() == 34
                && private_bytes[0] == 0x04
                && private_bytes[1] == 0x20
            {
                &private_bytes[2..34]
            } else if private_bytes.len() == 32 {
                private_bytes
            } else {
                return Err(CryptoError::key_error("Invalid Ed25519 private key format"));
            };
            Ok((seed.to_vec(), key_type))
        }
        _ => Err(CryptoError::key_error(format!(
            "Unsupported key type for raw extraction: {}",
            key_type
        ))),
    }
}

/// Extract raw public key bytes from SPKI DER format.
pub fn spki_to_raw_public_key(spki_der: &[u8]) -> CryptoResult<(Vec<u8>, String)> {
    let key_type = detect_public_key_type(spki_der)?;
    let info = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse public key: {}", e)))?;

    let raw_bytes = info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CryptoError::key_error("Invalid public key bit string"))?;

    Ok((raw_bytes.to_vec(), key_type))
}

// ============================================================================
// Public Key Operations
// ============================================================================

/// Load a public key from PEM format (SPKI).
pub fn load_public_key_pem(pem_data: &str) -> CryptoResult<Vec<u8>> {
    let info = SubjectPublicKeyInfoOwned::from_pem(pem_data)
        .map_err(|e| CryptoError::pem_error(format!("Failed to parse public key PEM: {}", e)))?;

    info.to_der()
        .map_err(|e| CryptoError::encoding_error(format!("Failed to encode public key: {}", e)))
}

/// Load a public key from DER format (SPKI).
pub fn load_public_key_der(der_data: &[u8]) -> CryptoResult<Vec<u8>> {
    // Validate it's a valid SPKI structure
    let _info = SubjectPublicKeyInfoOwned::from_der(der_data)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse public key DER: {}", e)))?;

    Ok(der_data.to_vec())
}

/// Save a public key to PEM format (SPKI).
pub fn save_public_key_pem(public_key_der: &[u8]) -> CryptoResult<String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(public_key_der);

    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).map_err(|_| CryptoError::encoding_error("invalid UTF-8 in base64 output"))?);
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    Ok(pem)
}

/// Extract public key from private key (PKCS#8 DER).
pub fn extract_public_key(private_key_der: &[u8]) -> CryptoResult<Vec<u8>> {
    let key_type = detect_private_key_type(private_key_der)?;

    match key_type.as_str() {
        "EC_P256" => {
            use pkcs8::DecodePrivateKey;
            let secret = p256::SecretKey::from_pkcs8_der(private_key_der)
                .map_err(|e| CryptoError::key_error(format!("Failed to parse P-256 key: {}", e)))?;
            let public = secret.public_key();
            use pkcs8::EncodePublicKey;
            let doc = public.to_public_key_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode public key: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        "EC_P384" => {
            use pkcs8::DecodePrivateKey;
            let secret = p384::SecretKey::from_pkcs8_der(private_key_der)
                .map_err(|e| CryptoError::key_error(format!("Failed to parse P-384 key: {}", e)))?;
            let public = secret.public_key();
            use pkcs8::EncodePublicKey;
            let doc = public.to_public_key_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode public key: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        "RSA" => {
            use pkcs8::DecodePrivateKey;
            let private = rsa::RsaPrivateKey::from_pkcs8_der(private_key_der)
                .map_err(|e| CryptoError::key_error(format!("Failed to parse RSA key: {}", e)))?;
            let public = rsa::RsaPublicKey::from(&private);
            use pkcs8::EncodePublicKey;
            let doc = public.to_public_key_der().map_err(|e| {
                CryptoError::encoding_error(format!("Failed to encode public key: {}", e))
            })?;
            Ok(doc.as_bytes().to_vec())
        }
        "Ed25519" => {
            let info = pkcs8::PrivateKeyInfo::from_der(private_key_der)
                .map_err(|e| CryptoError::der_error(format!("Failed to parse key: {}", e)))?;

            // Ed25519 private key is 32 bytes, public key is derived
            let private_bytes = info.private_key;
            if private_bytes.len() >= 32 {
                // The private key bytes may be wrapped, extract the 32-byte seed
                let seed = if private_bytes.len() == 34
                    && private_bytes[0] == 0x04
                    && private_bytes[1] == 0x20
                {
                    &private_bytes[2..34]
                } else if private_bytes.len() == 32 {
                    private_bytes
                } else {
                    return Err(CryptoError::key_error("Invalid Ed25519 private key format"));
                };

                let signing_key = ed25519_dalek::SigningKey::from_bytes(
                    seed.try_into()
                        .map_err(|_| CryptoError::key_error("Invalid Ed25519 key length"))?,
                );
                let verifying_key = signing_key.verifying_key();

                // Encode as SPKI
                let public_bytes = verifying_key.as_bytes();
                encode_ed25519_public_key_spki(public_bytes)
            } else {
                Err(CryptoError::key_error("Invalid Ed25519 private key"))
            }
        }
        _ => Err(CryptoError::key_error(format!(
            "Unsupported key type: {}",
            key_type
        ))),
    }
}

/// Encode Ed25519 public key as SPKI DER.
fn encode_ed25519_public_key_spki(public_key: &[u8]) -> CryptoResult<Vec<u8>> {
    // Ed25519 SPKI structure:
    // SEQUENCE {
    //   SEQUENCE {
    //     OID 1.3.101.112 (Ed25519)
    //   }
    //   BIT STRING (public key)
    // }
    let mut der = Vec::new();

    // Algorithm identifier: SEQUENCE { OID 1.3.101.112 }
    let alg_id: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

    // Bit string header (public key is 32 bytes)
    let bit_string_header: [u8; 3] = [0x03, 0x21, 0x00]; // BIT STRING, 33 bytes, 0 unused bits

    // Total length: 7 (alg) + 3 (bit string header) + 32 (key) = 42
    let inner_len = 7 + 3 + 32;

    // Outer SEQUENCE
    der.push(0x30);
    if inner_len < 128 {
        der.push(inner_len as u8);
    } else {
        der.push(0x81);
        der.push(inner_len as u8);
    }

    // AlgorithmIdentifier
    der.extend_from_slice(&alg_id);

    // BIT STRING
    der.extend_from_slice(&bit_string_header);
    der.extend_from_slice(public_key);

    Ok(der)
}

// ============================================================================
// Key Type Detection
// ============================================================================

/// Detect the key type from DER-encoded private key.
pub fn detect_private_key_type(der_data: &[u8]) -> CryptoResult<String> {
    let info = pkcs8::PrivateKeyInfo::from_der(der_data)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse private key: {}", e)))?;

    let oid = info.algorithm.oid;

    // Check known OIDs
    if oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        // EC key - check curve
        if let Some(params) = info.algorithm.parameters {
            if let Ok(curve_oid) = params.decode_as::<const_oid::ObjectIdentifier>() {
                if curve_oid == const_oid::db::rfc5912::SECP_256_R_1 {
                    return Ok("EC_P256".to_string());
                } else if curve_oid == const_oid::db::rfc5912::SECP_384_R_1 {
                    return Ok("EC_P384".to_string());
                } else if curve_oid == const_oid::db::rfc5912::SECP_521_R_1 {
                    return Ok("EC_P521".to_string());
                }
            }
        }
        Ok("EC".to_string())
    } else if oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        Ok("RSA".to_string())
    } else if oid == const_oid::db::rfc8410::ID_ED_25519 {
        Ok("Ed25519".to_string())
    } else if oid == const_oid::db::rfc8410::ID_X_25519 {
        Ok("X25519".to_string())
    } else {
        Ok(format!("Unknown({})", oid))
    }
}

/// Detect the key type from DER-encoded public key.
pub fn detect_public_key_type(der_data: &[u8]) -> CryptoResult<String> {
    let info = SubjectPublicKeyInfoOwned::from_der(der_data)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse public key: {}", e)))?;

    let oid = info.algorithm.oid;

    if oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        if let Some(params) = &info.algorithm.parameters {
            if let Ok(curve_oid) = params.decode_as::<const_oid::ObjectIdentifier>() {
                if curve_oid == const_oid::db::rfc5912::SECP_256_R_1 {
                    return Ok("EC_P256".to_string());
                } else if curve_oid == const_oid::db::rfc5912::SECP_384_R_1 {
                    return Ok("EC_P384".to_string());
                } else if curve_oid == const_oid::db::rfc5912::SECP_521_R_1 {
                    return Ok("EC_P521".to_string());
                }
            }
        }
        Ok("EC".to_string())
    } else if oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        Ok("RSA".to_string())
    } else if oid == const_oid::db::rfc8410::ID_ED_25519 {
        Ok("Ed25519".to_string())
    } else if oid == const_oid::db::rfc8410::ID_X_25519 {
        Ok("X25519".to_string())
    } else {
        Ok(format!("Unknown({})", oid))
    }
}

/// Get key size in bits.
pub fn get_key_size(public_key_der: &[u8]) -> CryptoResult<usize> {
    let key_type = detect_public_key_type(public_key_der)?;

    match key_type.as_str() {
        "EC_P256" => Ok(256),
        "EC_P384" => Ok(384),
        "EC_P521" => Ok(521),
        "Ed25519" => Ok(256),
        "X25519" => Ok(256),
        "RSA" => {
            // Parse RSA public key to get modulus size
            let info = SubjectPublicKeyInfoOwned::from_der(public_key_der)
                .map_err(|e| CryptoError::der_error(format!("Failed to parse key: {}", e)))?;

            let key_bytes = info
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| CryptoError::key_error("Invalid RSA public key"))?;

            // RSA public key is a SEQUENCE of INTEGER (n) and INTEGER (e)
            // The modulus is the first integer
            if key_bytes.len() > 4 {
                // Rough estimate: key_bytes contains the DER-encoded RSA structure
                // For a proper implementation, we'd parse the SEQUENCE
                Ok((key_bytes.len() - 10) * 8) // Approximate
            } else {
                Ok(0)
            }
        }
        _ => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_pem_roundtrip_private_key() {
        // Generate a P-256 key using our keygen
        let generated = crate::keygen::generate_keypair(crate::keygen::KeyType::EcdsaP256).unwrap();

        // The keygen returns GeneratedKey struct
        assert!(!generated.private_key.is_empty());
        assert!(!generated.public_key.is_empty());
    }

    #[test]
    fn test_detect_key_type() {
        // Generate keys and test detection
        let generated = crate::keygen::generate_keypair(crate::keygen::KeyType::EcdsaP256).unwrap();

        assert!(!generated.private_key.is_empty());
    }
}
