//! Public-key serialization and deserialization.
//!
//! PEM/DER public-key codecs only. Private-key import, export and conversion
//! are absent from production and test builds.

use crate::{CryptoError, CryptoResult};
use der::{Decode, DecodePem, Encode};
use elliptic_curve::sec1::FromEncodedPoint;
use spki::SubjectPublicKeyInfoOwned;

/// Marker documenting the public-key-only codec boundary.
///
/// Private-key import, export, and conversion do not exist in this build:
///
/// ```compile_fail
/// let _ = marty_crypto::serialization::load_private_key_der(&[]);
/// ```
pub struct PublicKeyOnly;

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
        pem.push_str(
            std::str::from_utf8(chunk)
                .map_err(|_| CryptoError::encoding_error("invalid UTF-8 in base64 output"))?,
        );
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");

    Ok(pem)
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
    } else if oid == const_oid::db::rfc8410::ID_ED_448 {
        Ok("Ed448".to_string())
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
    use der::{Decode, Encode};

    #[test]
    fn detects_public_key_type_and_size_from_certificate() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/certificate_parser_public.json"
        ))
        .unwrap();
        let certificate_der = hex::decode(
            vectors["pkd_metadata_certificate_der_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let certificate = x509_cert::Certificate::from_der(&certificate_der).unwrap();
        let public_key_der = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();

        assert_eq!(
            super::detect_public_key_type(&public_key_der).unwrap(),
            "EC_P256"
        );
        assert_eq!(super::get_key_size(&public_key_der).unwrap(), 256);
        assert!(super::detect_public_key_type(&[0x01, 0x02]).is_err());
    }
}
