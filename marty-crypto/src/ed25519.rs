//! Ed25519 signature operations.
//!
//! This module provides Ed25519 signing and verification using the ed25519-dalek crate.
//! Ed25519 is used in:
//! - DID document verification (did:key, did:web)
//! - SD-JWT signing
//! - Verifiable Credentials (EdDSA)
//!
//! # Security Properties
//!
//! - 128-bit security level
//! - Deterministic signatures (no random nonce needed)
//! - Fast verification (~15,000 ops/sec)
//! - Small signatures (64 bytes) and keys (32 bytes)

use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand::rngs::OsRng;

use crate::{CryptoError, CryptoResult};

// ============================================================================
// Key Types
// ============================================================================

/// Ed25519 key pair for signing and verification.
#[derive(Clone)]
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generate a new random Ed25519 key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a key pair from a 32-byte secret key.
    pub fn from_secret_key(secret: &[u8]) -> CryptoResult<Self> {
        if secret.len() != SECRET_KEY_LENGTH {
            return Err(CryptoError::internal(format!(
                "Ed25519 secret key must be {} bytes",
                SECRET_KEY_LENGTH
            )));
        }

        let bytes: [u8; SECRET_KEY_LENGTH] = secret
            .try_into()
            .map_err(|_| CryptoError::internal("Invalid secret key length".to_string()))?;

        let signing_key = SigningKey::from_bytes(&bytes);
        Ok(Self { signing_key })
    }

    /// Get the secret key bytes.
    pub fn secret_key(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        Ed25519VerifyingKey {
            key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Sign a message, returning the signature as a Vec.
    pub fn sign_vec(&self, message: &[u8]) -> Vec<u8> {
        self.sign(message).to_vec()
    }
}

/// Ed25519 public key for verification only.
#[derive(Clone)]
pub struct Ed25519VerifyingKey {
    key: VerifyingKey,
}

impl Ed25519VerifyingKey {
    /// Create from raw 32-byte public key.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(CryptoError::internal(format!(
                "Ed25519 public key must be {} bytes",
                PUBLIC_KEY_LENGTH
            )));
        }

        let bytes_array: [u8; PUBLIC_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| CryptoError::internal("Invalid public key length".to_string()))?;

        let key = VerifyingKey::from_bytes(&bytes_array).map_err(|e| {
            CryptoError::internal(format!("Invalid Ed25519 public key: {}", e))
        })?;

        Ok(Self { key })
    }

    /// Get the raw public key bytes.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.key.to_bytes()
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<()> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(CryptoError::internal(format!(
                "Ed25519 signature must be {} bytes",
                SIGNATURE_LENGTH
            )));
        }

        let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
            .try_into()
            .map_err(|_| CryptoError::internal("Invalid signature length".to_string()))?;

        let signature = Signature::from_bytes(&sig_bytes);

        self.key.verify(message, &signature).map_err(|e| {
            CryptoError::internal(format!("Ed25519 signature verification failed: {}", e))
        })
    }

    /// Verify a signature, returning a boolean instead of Result.
    pub fn verify_strict(&self, message: &[u8], signature: &[u8]) -> bool {
        self.verify(message, signature).is_ok()
    }
}

// ============================================================================
// Standalone Functions
// ============================================================================

/// Generate a new Ed25519 key pair.
///
/// Returns (secret_key, public_key) as 32-byte arrays.
pub fn generate_keypair() -> ([u8; SECRET_KEY_LENGTH], [u8; PUBLIC_KEY_LENGTH]) {
    let keypair = Ed25519KeyPair::generate();
    (keypair.secret_key(), keypair.public_key())
}

/// Sign a message with an Ed25519 secret key.
///
/// # Arguments
///
/// * `secret_key` - 32-byte secret key
/// * `message` - Message to sign
///
/// # Returns
///
/// 64-byte signature.
pub fn sign(secret_key: &[u8], message: &[u8]) -> CryptoResult<Vec<u8>> {
    let keypair = Ed25519KeyPair::from_secret_key(secret_key)?;
    Ok(keypair.sign_vec(message))
}

/// Verify an Ed25519 signature.
///
/// # Arguments
///
/// * `public_key` - 32-byte public key
/// * `message` - Original message
/// * `signature` - 64-byte signature
///
/// # Returns
///
/// Ok(()) if signature is valid.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<()> {
    let verifying_key = Ed25519VerifyingKey::from_bytes(public_key)?;
    verifying_key.verify(message, signature)
}

/// Verify an Ed25519 signature, returning a boolean.
pub fn verify_bool(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify(public_key, message, signature).is_ok()
}

/// Verify an Ed25519 signature using a SPKI-encoded public key.
///
/// This function accepts DER-encoded SubjectPublicKeyInfo format public keys,
/// which is the standard format used in X.509 certificates.
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo or raw 32-byte public key
/// * `message` - Original message
/// * `signature` - 64-byte signature
///
/// # Returns
///
/// `Ok(true)` if signature is valid, `Ok(false)` if invalid.
pub fn verify_ed25519_spki(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    // Try PKCS#8/SPKI parsing first using ed25519-dalek's built-in support
    use ed25519_dalek::pkcs8::DecodePublicKey;

    let verifying_key = if public_key_der.len() == PUBLIC_KEY_LENGTH {
        // Raw 32-byte public key
        let bytes_array: [u8; PUBLIC_KEY_LENGTH] = public_key_der
            .try_into()
            .map_err(|_| CryptoError::internal("Invalid public key length".to_string()))?;
        VerifyingKey::from_bytes(&bytes_array).map_err(|e| {
            CryptoError::internal(format!("Invalid Ed25519 public key: {}", e))
        })?
    } else {
        // Try SPKI DER format
        VerifyingKey::from_public_key_der(public_key_der).map_err(|e| {
            CryptoError::internal(format!("Invalid Ed25519 SPKI public key: {}", e))
        })?
    };

    if signature.len() != SIGNATURE_LENGTH {
        return Err(CryptoError::internal(format!(
            "Ed25519 signature must be {} bytes, got {}",
            SIGNATURE_LENGTH,
            signature.len()
        )));
    }

    let sig_bytes: [u8; SIGNATURE_LENGTH] = signature
        .try_into()
        .map_err(|_| CryptoError::internal("Invalid signature length".to_string()))?;

    let sig = Signature::from_bytes(&sig_bytes);

    match verifying_key.verify(message, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ============================================================================
// PEM/DER Support
// ============================================================================

/// Parse a PEM-encoded Ed25519 private key.
///
/// Supports PKCS#8 format: `-----BEGIN PRIVATE KEY-----`
pub fn parse_private_key_pem(pem: &str) -> CryptoResult<Ed25519KeyPair> {
    // Strip PEM headers and decode base64
    let lines: Vec<&str> = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let base64_data = lines.join("");

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&base64_data)
        .map_err(|e| CryptoError::internal(format!("Invalid PEM base64: {}", e)))?;

    parse_private_key_der(&der)
}

/// Parse a DER-encoded Ed25519 private key (PKCS#8 format).
pub fn parse_private_key_der(der: &[u8]) -> CryptoResult<Ed25519KeyPair> {
    // PKCS#8 structure for Ed25519:
    // SEQUENCE {
    //   INTEGER 0
    //   SEQUENCE { OID 1.3.101.112 }
    //   OCTET STRING { OCTET STRING { 32 bytes } }
    // }
    // The raw key is typically at offset 16 for 32 bytes

    // Simple parser: look for 32-byte key after the OID
    if der.len() < 48 {
        return Err(CryptoError::internal(
            "DER data too short for PKCS#8 Ed25519 key".to_string(),
        ));
    }

    // Try to find the 32-byte key - it's wrapped in OCTET STRING tags
    // The key is typically the last 32 bytes of the inner OCTET STRING
    let key_start = der.len() - 32;
    let secret = &der[key_start..];

    Ed25519KeyPair::from_secret_key(secret)
}

/// Parse a PEM-encoded Ed25519 public key.
pub fn parse_public_key_pem(pem: &str) -> CryptoResult<Ed25519VerifyingKey> {
    let lines: Vec<&str> = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let base64_data = lines.join("");

    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(&base64_data)
        .map_err(|e| CryptoError::internal(format!("Invalid PEM base64: {}", e)))?;

    parse_public_key_der(&der)
}

/// Parse a DER-encoded Ed25519 public key (SubjectPublicKeyInfo format).
pub fn parse_public_key_der(der: &[u8]) -> CryptoResult<Ed25519VerifyingKey> {
    // SPKI for Ed25519:
    // SEQUENCE {
    //   SEQUENCE { OID 1.3.101.112 }
    //   BIT STRING { 32 bytes }
    // }
    // The key is typically the last 32 bytes

    if der.len() < 44 {
        return Err(CryptoError::internal(
            "DER data too short for SPKI Ed25519 key".to_string(),
        ));
    }

    let key_start = der.len() - 32;
    let public = &der[key_start..];

    Ed25519VerifyingKey::from_bytes(public)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair() {
        let (secret, public) = generate_keypair();
        assert_eq!(secret.len(), 32);
        assert_eq!(public.len(), 32);

        // Keys should be different
        assert_ne!(secret, public);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Hello, Ed25519!";

        let signature = keypair.sign(message);
        assert_eq!(signature.len(), 64);

        // Verify with the public key
        let verifying_key = keypair.verifying_key();
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_sign_verify_standalone() {
        let (secret, public) = generate_keypair();
        let message = b"Test message for signing";

        let signature = sign(&secret, message).unwrap();
        assert_eq!(signature.len(), 64);

        // Verify
        assert!(verify(&public, message, &signature).is_ok());
        assert!(verify_bool(&public, message, &signature));
    }

    #[test]
    fn test_verify_wrong_message() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message);

        // Verification with wrong message should fail
        let verifying_key = keypair.verifying_key();
        assert!(verifying_key.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_wrong_signature() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Test message";

        let mut signature = keypair.sign(message);
        signature[0] ^= 0xFF; // Corrupt the signature

        let verifying_key = keypair.verifying_key();
        assert!(verifying_key.verify(message, &signature).is_err());
    }

    #[test]
    fn test_from_secret_key() {
        let original = Ed25519KeyPair::generate();
        let secret = original.secret_key();

        let restored = Ed25519KeyPair::from_secret_key(&secret).unwrap();
        assert_eq!(restored.public_key(), original.public_key());
    }

    #[test]
    fn test_deterministic_signatures() {
        let keypair = Ed25519KeyPair::generate();
        let message = b"Same message";

        let sig1 = keypair.sign(message);
        let sig2 = keypair.sign(message);

        // Ed25519 signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_invalid_key_lengths() {
        // Too short
        assert!(Ed25519KeyPair::from_secret_key(&[0u8; 16]).is_err());

        // Too long
        assert!(Ed25519KeyPair::from_secret_key(&[0u8; 64]).is_err());

        // Invalid public key
        assert!(Ed25519VerifyingKey::from_bytes(&[0u8; 16]).is_err());
    }

    #[test]
    fn test_invalid_signature_length() {
        let public_key = Ed25519KeyPair::generate().public_key();
        let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key).unwrap();

        // Too short signature
        assert!(verifying_key.verify(b"test", &[0u8; 32]).is_err());

        // Too long signature
        assert!(verifying_key.verify(b"test", &[0u8; 128]).is_err());
    }
}
