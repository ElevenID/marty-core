//! ECDSA signature signing and verification for P-256, P-384, and P-521 curves.

use ecdsa::signature::Signer;
use p256::ecdsa::{
    signature::Verifier as P256Verifier, Signature as P256Signature, SigningKey as P256SigningKey,
    VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use rand::rngs::OsRng;

use crate::{CryptoError, CryptoResult};

// ============================================================================
// ECDSA Key Generation
// ============================================================================

/// Generate a new ECDSA P-256 key pair.
///
/// # Returns
///
/// Tuple of (private_key_bytes, public_key_bytes).
/// Private key is 32 bytes, public key is 65 bytes (uncompressed).
pub fn generate_p256_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let signing_key = P256SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    Ok((private_bytes, public_bytes))
}

/// Generate a new ECDSA P-384 key pair.
///
/// # Returns
///
/// Tuple of (private_key_bytes, public_key_bytes).
/// Private key is 48 bytes, public key is 97 bytes (uncompressed).
pub fn generate_p384_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let signing_key = P384SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    Ok((private_bytes, public_bytes))
}

/// Generate a new ECDSA P-521 key pair.
///
/// # Returns
///
/// Tuple of (private_key_bytes, public_key_bytes).
/// Private key is 66 bytes, public key is 133 bytes (uncompressed).
pub fn generate_p521_keypair() -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    let signing_key = P521SigningKey::random(&mut OsRng);
    // Get verifying key via the inner signing key's public key method
    let verifying_key = P521VerifyingKey::from(&signing_key);

    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    Ok((private_bytes, public_bytes))
}

// ============================================================================
// ECDSA Signing
// ============================================================================

/// Sign a message with ECDSA P-256 (ES256).
///
/// # Arguments
///
/// * `private_key` - 32-byte private key scalar
/// * `message` - Message to sign
///
/// # Returns
///
/// DER-encoded signature.
pub fn sign_p256_sha256(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    if private_key.len() != 32 {
        return Err(CryptoError::internal(
            "P-256 private key must be 32 bytes".to_string(),
        ));
    }

    let signing_key = P256SigningKey::from_slice(private_key)
        .map_err(|e| CryptoError::internal(format!("Invalid P-256 private key: {}", e)))?;

    let signature: P256Signature = signing_key.sign(message);

    Ok(signature.to_der().as_bytes().to_vec())
}

/// Sign a message with ECDSA P-384 (ES384).
///
/// # Arguments
///
/// * `private_key` - 48-byte private key scalar
/// * `message` - Message to sign
///
/// # Returns
///
/// DER-encoded signature.
pub fn sign_p384_sha384(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    if private_key.len() != 48 {
        return Err(CryptoError::internal(
            "P-384 private key must be 48 bytes".to_string(),
        ));
    }

    let signing_key = P384SigningKey::from_slice(private_key)
        .map_err(|e| CryptoError::internal(format!("Invalid P-384 private key: {}", e)))?;

    let signature: P384Signature = signing_key.sign(message);

    Ok(signature.to_der().as_bytes().to_vec())
}

/// Sign a message with ECDSA P-521 (ES512).
///
/// # Arguments
///
/// * `private_key` - 66-byte private key scalar
/// * `message` - Message to sign
///
/// # Returns
///
/// DER-encoded signature.
pub fn sign_p521_sha512(private_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    if private_key.len() != 66 {
        return Err(CryptoError::internal(
            "P-521 private key must be 66 bytes".to_string(),
        ));
    }

    let signing_key = P521SigningKey::from_slice(private_key)
        .map_err(|e| CryptoError::internal(format!("Invalid P-521 private key: {}", e)))?;

    let signature: P521Signature = signing_key.sign(message);

    Ok(signature.to_der().as_bytes().to_vec())
}

// ============================================================================
// ECDSA Verification
// ============================================================================

// ============================================================================
// ECDSA Verification
// ============================================================================

/// Verify ECDSA P-256 signature with SHA-256 (ES256).
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (DER or raw format)
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
pub fn verify_p256_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    // Try to parse as SubjectPublicKeyInfo
    let verifying_key = P256VerifyingKey::from_sec1_bytes(public_key_der)
        .or_else(|_| {
            // Try parsing as full SPKI
            use elliptic_curve::pkcs8::DecodePublicKey;
            P256VerifyingKey::from_public_key_der(public_key_der)
        })
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-256",
                format!("Invalid public key: {}", e),
            )
        })?;

    // Try DER-encoded signature first, then raw format
    let sig = P256Signature::from_der(signature)
        .or_else(|_| P256Signature::from_slice(signature))
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-256",
                format!("Invalid signature format: {}", e),
            )
        })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify ECDSA P-384 signature with SHA-384 (ES384).
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (DER or raw format)
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
pub fn verify_p384_sha384(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    // Try to parse as SEC1 bytes first
    let verifying_key = P384VerifyingKey::from_sec1_bytes(public_key_der)
        .or_else(|_| {
            // Try parsing as full SPKI
            use elliptic_curve::pkcs8::DecodePublicKey;
            P384VerifyingKey::from_public_key_der(public_key_der)
        })
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-384",
                format!("Invalid public key: {}", e),
            )
        })?;

    // Try DER-encoded signature first, then raw format
    let sig = P384Signature::from_der(signature)
        .or_else(|_| P384Signature::from_slice(signature))
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-384",
                format!("Invalid signature format: {}", e),
            )
        })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify ECDSA P-521 signature with SHA-512 (ES512).
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (DER or raw format)
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
pub fn verify_p521_sha512(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    use p521::ecdsa::signature::Verifier as P521Verifier;

    // Try to parse as SEC1 bytes first
    let verifying_key = P521VerifyingKey::from_sec1_bytes(public_key_der)
        .or_else(|_| {
            // Try parsing as full SPKI - extract the raw public key bytes
            use der::Decode;
            use x509_cert::spki::SubjectPublicKeyInfoOwned;

            let spki = SubjectPublicKeyInfoOwned::from_der(public_key_der)
                .map_err(|_e| p521::ecdsa::Error::new())?;
            let raw_bytes = spki.subject_public_key.raw_bytes();
            P521VerifyingKey::from_sec1_bytes(raw_bytes)
        })
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-521",
                format!("Invalid public key: {}", e),
            )
        })?;

    // Try DER-encoded signature first, then raw format
    let sig = P521Signature::from_der(signature)
        .or_else(|_| P521Signature::from_slice(signature))
        .map_err(|e| {
            CryptoError::invalid_signature_with_context(
                "ECDSA P-521",
                format!("Invalid signature format: {}", e),
            )
        })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Extract the raw public key bytes from a SubjectPublicKeyInfo structure.
///
/// This is useful when you need just the EC point for other operations.
pub fn extract_ec_point_from_spki(spki_der: &[u8]) -> CryptoResult<Vec<u8>> {
    use der::Decode;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| CryptoError::der_error(format!("Failed to parse SPKI: {}", e)))?;

    Ok(spki.subject_public_key.raw_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_p256_keypair().unwrap();

        let message = b"Hello, ECDSA!";
        let signature = sign_p256_sha256(&private_key, message).unwrap();

        let valid = verify_p256_sha256(&public_key, message, &signature).unwrap();
        assert!(valid, "Signature should be valid");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let invalid = verify_p256_sha256(&public_key, wrong_message, &signature).unwrap();
        assert!(!invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_p384_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_p384_keypair().unwrap();

        let message = b"Hello, ECDSA P-384!";
        let signature = sign_p384_sha384(&private_key, message).unwrap();

        let valid = verify_p384_sha384(&public_key, message, &signature).unwrap();
        assert!(valid, "Signature should be valid");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let invalid = verify_p384_sha384(&public_key, wrong_message, &signature).unwrap();
        assert!(!invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_p256_invalid_private_key_length() {
        let short_key = vec![0u8; 16]; // Too short
        let result = sign_p256_sha256(&short_key, b"message");
        assert!(result.is_err());
    }

    #[test]
    fn test_p384_invalid_private_key_length() {
        let short_key = vec![0u8; 32]; // Too short for P-384
        let result = sign_p384_sha384(&short_key, b"message");
        assert!(result.is_err());
    }

    #[test]
    fn test_p521_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_p521_keypair().unwrap();

        let message = b"Hello, ECDSA P-521!";
        let signature = sign_p521_sha512(&private_key, message).unwrap();

        let valid = verify_p521_sha512(&public_key, message, &signature).unwrap();
        assert!(valid, "Signature should be valid");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let invalid = verify_p521_sha512(&public_key, wrong_message, &signature).unwrap();
        assert!(!invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_p521_invalid_private_key_length() {
        let short_key = vec![0u8; 48]; // Too short for P-521 (needs 66 bytes)
        let result = sign_p521_sha512(&short_key, b"message");
        assert!(result.is_err());
    }

    #[test]
    fn test_p521_key_sizes() {
        let (private_key, public_key) = generate_p521_keypair().unwrap();

        // P-521 private key should be 66 bytes
        assert_eq!(
            private_key.len(),
            66,
            "P-521 private key should be 66 bytes"
        );
        // P-521 public key (uncompressed) should be 133 bytes (1 + 66 + 66)
        assert_eq!(
            public_key.len(),
            133,
            "P-521 public key should be 133 bytes"
        );
    }

    #[test]
    fn test_p521_signature_format() {
        let (private_key, _public_key) = generate_p521_keypair().unwrap();

        let message = b"Test message for signature format";
        let signature = sign_p521_sha512(&private_key, message).unwrap();

        // DER-encoded signature should start with 0x30 (SEQUENCE tag)
        assert_eq!(
            signature[0], 0x30,
            "DER signature should start with SEQUENCE tag"
        );
    }

    #[test]
    fn test_p521_cross_key_verification_fails() {
        let (private_key_1, _public_key_1) = generate_p521_keypair().unwrap();
        let (_private_key_2, public_key_2) = generate_p521_keypair().unwrap();

        let message = b"Message signed with key 1";
        let signature = sign_p521_sha512(&private_key_1, message).unwrap();

        // Verification with different public key should fail
        let invalid = verify_p521_sha512(&public_key_2, message, &signature).unwrap();
        assert!(
            !invalid,
            "Signature should be invalid with wrong public key"
        );
    }

    #[test]
    fn test_extract_ec_point_placeholder() {
        // Placeholder test - full tests need actual SPKI data
        let empty_spki: &[u8] = &[];
        assert!(extract_ec_point_from_spki(empty_spki).is_err());
    }
}
