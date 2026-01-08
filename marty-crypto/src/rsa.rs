//! RSA signature signing and verification (PKCS#1 v1.5 and PSS).

use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{
    pkcs1v15::{
        Signature as Pkcs1Signature, SigningKey as Pkcs1SigningKey,
        VerifyingKey as Pkcs1VerifyingKey,
    },
    pss::{
        Signature as PssSignature, SigningKey as PssSigningKey, VerifyingKey as PssVerifyingKey,
    },
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::{CryptoError, CryptoResult};

// ============================================================================
// RSA Key Generation
// ============================================================================

/// Generate a new RSA key pair.
///
/// # Arguments
///
/// * `bits` - Key size in bits (2048, 3072, or 4096)
///
/// # Returns
///
/// Tuple of (private_key_pkcs8_der, public_key_spki_der).
pub fn generate_rsa_keypair(bits: usize) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
    if bits < 2048 {
        return Err(CryptoError::internal(
            "RSA key size must be at least 2048 bits".to_string(),
        ));
    }

    let private_key = RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|e| CryptoError::internal(format!("RSA key generation failed: {}", e)))?;

    let public_key = private_key.to_public_key();

    use rsa::pkcs8::EncodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    let private_der = private_key
        .to_pkcs8_der()
        .map_err(|e| CryptoError::internal(format!("Failed to encode private key: {}", e)))?;

    let public_der = public_key
        .to_public_key_der()
        .map_err(|e| CryptoError::internal(format!("Failed to encode public key: {}", e)))?;

    Ok((
        private_der.as_bytes().to_vec(),
        public_der.as_bytes().to_vec(),
    ))
}

// ============================================================================
// RSA PKCS#1 v1.5 Signing
// ============================================================================

/// Sign a message with RSA PKCS#1 v1.5 and SHA-256 (RS256).
///
/// # Arguments
///
/// * `private_key_der` - PKCS#8 DER-encoded private key
/// * `message` - Message to sign
///
/// # Returns
///
/// Signature bytes.
pub fn sign_pkcs1_sha256(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let private_key = parse_rsa_private_key(private_key_der)?;
    let signing_key = Pkcs1SigningKey::<Sha256>::new(private_key);
    let signature: Pkcs1Signature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_bytes().into_vec())
}

/// Sign a message with RSA PKCS#1 v1.5 and SHA-384 (RS384).
pub fn sign_pkcs1_sha384(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let private_key = parse_rsa_private_key(private_key_der)?;
    let signing_key = Pkcs1SigningKey::<Sha384>::new(private_key);
    let signature: Pkcs1Signature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_bytes().into_vec())
}

/// Sign a message with RSA PKCS#1 v1.5 and SHA-512 (RS512).
pub fn sign_pkcs1_sha512(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let private_key = parse_rsa_private_key(private_key_der)?;
    let signing_key = Pkcs1SigningKey::<Sha512>::new(private_key);
    let signature: Pkcs1Signature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_bytes().into_vec())
}

// ============================================================================
// RSA-PSS Signing
// ============================================================================

/// Sign a message with RSA-PSS and SHA-256 (PS256).
///
/// Uses salt length equal to hash length (32 bytes).
pub fn sign_pss_sha256(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let private_key = parse_rsa_private_key(private_key_der)?;
    let signing_key = PssSigningKey::<Sha256>::new(private_key);
    let signature: PssSignature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_bytes().into_vec())
}

/// Sign a message with RSA-PSS and SHA-384 (PS384).
pub fn sign_pss_sha384(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let private_key = parse_rsa_private_key(private_key_der)?;
    let signing_key = PssSigningKey::<Sha384>::new(private_key);
    let signature: PssSignature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_bytes().into_vec())
}

/// Sign a message with RSA-PSS and SHA-512 (PS512).
pub fn sign_pss_sha512(private_key_der: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let private_key = parse_rsa_private_key(private_key_der)?;
    let signing_key = PssSigningKey::<Sha512>::new(private_key);
    let signature: PssSignature = signing_key.sign_with_rng(&mut OsRng, message);
    Ok(signature.to_bytes().into_vec())
}

// ============================================================================
// PKCS#1 v1.5 Signature Verification
// ============================================================================

/// Verify RSA PKCS#1 v1.5 signature with SHA-256 (RS256).
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo or RSAPublicKey
/// * `message` - The message that was signed
/// * `signature` - The signature bytes
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
pub fn verify_pkcs1_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    let verifying_key = Pkcs1VerifyingKey::<Sha256>::new(public_key);

    let sig = Pkcs1Signature::try_from(signature).map_err(|e| {
        CryptoError::invalid_signature_with_context(
            "RSA PKCS#1",
            format!("Invalid signature format: {}", e),
        )
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA PKCS#1 v1.5 signature with SHA-384 (RS384).
pub fn verify_pkcs1_sha384(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    let verifying_key = Pkcs1VerifyingKey::<Sha384>::new(public_key);

    let sig = Pkcs1Signature::try_from(signature).map_err(|e| {
        CryptoError::invalid_signature_with_context(
            "RSA PKCS#1",
            format!("Invalid signature format: {}", e),
        )
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA PKCS#1 v1.5 signature with SHA-512 (RS512).
pub fn verify_pkcs1_sha512(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    let verifying_key = Pkcs1VerifyingKey::<Sha512>::new(public_key);

    let sig = Pkcs1Signature::try_from(signature).map_err(|e| {
        CryptoError::invalid_signature_with_context(
            "RSA PKCS#1",
            format!("Invalid signature format: {}", e),
        )
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA PKCS#1 v1.5 signature with SHA-1 (RS1).
///
/// # Security Warning
///
/// SHA-1 is cryptographically weak and should NOT be used for new applications.
/// This function is provided ONLY for legacy eMRTD (ePassport) verification
/// where older documents may have been signed with SHA-1.
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo or RSAPublicKey
/// * `message` - The message that was signed
/// * `signature` - The signature bytes
///
/// # Returns
///
/// `Ok(true)` if valid, `Ok(false)` if invalid signature.
#[deprecated(note = "SHA-1 is cryptographically weak; use only for legacy eMRTD verification")]
pub fn verify_pkcs1_sha1(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    let verifying_key = Pkcs1VerifyingKey::<Sha1>::new(public_key);

    let sig = Pkcs1Signature::try_from(signature).map_err(|e| {
        CryptoError::invalid_signature_with_context(
            "RSA PKCS#1 SHA-1",
            format!("Invalid signature format: {}", e),
        )
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// RSA-PSS Signature Verification
// ============================================================================

/// Verify RSA-PSS signature with SHA-256 (PS256).
///
/// Uses default salt length equal to hash length.
pub fn verify_pss_sha256(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    let verifying_key = PssVerifyingKey::<Sha256>::new(public_key);

    let sig = PssSignature::try_from(signature).map_err(|e| {
        CryptoError::invalid_signature(format!("RSA-PSS: Invalid signature format: {}", e))
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA-PSS signature with SHA-384 (PS384).
pub fn verify_pss_sha384(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    let verifying_key = PssVerifyingKey::<Sha384>::new(public_key);

    let sig = PssSignature::try_from(signature).map_err(|e| {
        CryptoError::invalid_signature(format!("RSA-PSS: Invalid signature format: {}", e))
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify RSA-PSS signature with SHA-512 (PS512).
pub fn verify_pss_sha512(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    let verifying_key = PssVerifyingKey::<Sha512>::new(public_key);

    let sig = PssSignature::try_from(signature).map_err(|e| {
        CryptoError::invalid_signature(format!("RSA-PSS: Invalid signature format: {}", e))
    })?;

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Parse RSA public key from DER bytes.
///
/// Tries SubjectPublicKeyInfo format first, then RSAPublicKey format.
fn parse_rsa_public_key(der: &[u8]) -> CryptoResult<RsaPublicKey> {
    // Try SubjectPublicKeyInfo (SPKI) format first
    RsaPublicKey::from_public_key_der(der)
        .or_else(|_| {
            // Try PKCS#1 RSAPublicKey format
            use rsa::pkcs1::DecodeRsaPublicKey;
            RsaPublicKey::from_pkcs1_der(der)
        })
        .map_err(|e| CryptoError::invalid_signature(format!("RSA: Invalid public key: {}", e)))
}

/// Parse RSA private key from DER bytes.
///
/// Tries PKCS#8 format first, then PKCS#1 format.
fn parse_rsa_private_key(der: &[u8]) -> CryptoResult<RsaPrivateKey> {
    // Try PKCS#8 format first
    RsaPrivateKey::from_pkcs8_der(der)
        .or_else(|_| {
            // Try PKCS#1 RSAPrivateKey format
            use rsa::pkcs1::DecodeRsaPrivateKey;
            RsaPrivateKey::from_pkcs1_der(der)
        })
        .map_err(|e| CryptoError::internal(format!("Invalid RSA private key: {}", e)))
}

/// Get the RSA key size in bits.
pub fn get_rsa_key_size(public_key_der: &[u8]) -> CryptoResult<usize> {
    let public_key = parse_rsa_public_key(public_key_der)?;
    Ok(public_key.size() * 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_key() {
        let invalid_key = &[0u8; 32];
        assert!(parse_rsa_public_key(invalid_key).is_err());
    }

    #[test]
    fn test_verify_with_invalid_key() {
        let invalid_key = &[0u8; 32];
        let message = b"test message";
        let signature = &[0u8; 256];

        let result = verify_pkcs1_sha256(invalid_key, message, signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_rsa_pkcs1_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_rsa_keypair(2048).unwrap();

        let message = b"Hello, RSA PKCS#1!";
        let signature = sign_pkcs1_sha256(&private_key, message).unwrap();

        let valid = verify_pkcs1_sha256(&public_key, message, &signature).unwrap();
        assert!(valid, "PKCS#1 signature should be valid");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let invalid = verify_pkcs1_sha256(&public_key, wrong_message, &signature).unwrap();
        assert!(!invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_rsa_pss_sign_verify_roundtrip() {
        let (private_key, public_key) = generate_rsa_keypair(2048).unwrap();

        let message = b"Hello, RSA-PSS!";
        let signature = sign_pss_sha256(&private_key, message).unwrap();

        let valid = verify_pss_sha256(&public_key, message, &signature).unwrap();
        assert!(valid, "PSS signature should be valid");

        // Test with wrong message
        let wrong_message = b"Wrong message";
        let invalid = verify_pss_sha256(&public_key, wrong_message, &signature).unwrap();
        assert!(!invalid, "Signature should be invalid for wrong message");
    }

    #[test]
    fn test_rsa_key_size() {
        let (_, public_key) = generate_rsa_keypair(2048).unwrap();
        let size = get_rsa_key_size(&public_key).unwrap();
        assert_eq!(size, 2048);
    }
}
