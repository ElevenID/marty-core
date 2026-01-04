//! Key generation for various cryptographic algorithms.
//!
//! This module provides unified key generation for:
//! - RSA (2048, 3072, 4096 bits)
//! - ECDSA/ECDH (P-256, P-384)
//! - Ed25519 (EdDSA)
//! - X25519 (key agreement)
//! - Symmetric (AES-128, AES-256, HMAC)
//!
//! # Example
//!
//! ```ignore
//! use marty_verification::crypto::keygen::{generate_keypair, KeyType};
//!
//! let keypair = generate_keypair(KeyType::Ed25519)?;
//! let keypair = generate_keypair(KeyType::EcdsaP256)?;
//! let keypair = generate_keypair(KeyType::Rsa2048)?;
//! ```

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{CryptoError, CryptoResult};

// ============================================================================
// Key Types
// ============================================================================

/// Supported key types for generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// Ed25519 signing key (32 bytes)
    Ed25519,
    /// X25519 key agreement (32 bytes)
    X25519,
    /// ECDSA/ECDH P-256 (32 bytes private, 65 bytes public uncompressed)
    EcdsaP256,
    /// ECDSA/ECDH P-384 (48 bytes private, 97 bytes public uncompressed)
    EcdsaP384,
    /// RSA 2048-bit
    Rsa2048,
    /// RSA 3072-bit
    Rsa3072,
    /// RSA 4096-bit
    Rsa4096,
    /// AES-128 symmetric key (16 bytes)
    Aes128,
    /// AES-256 symmetric key (32 bytes)
    Aes256,
    /// HMAC-SHA256 key (32 bytes)
    HmacSha256,
    /// HMAC-SHA384 key (48 bytes)
    HmacSha384,
    /// HMAC-SHA512 key (64 bytes)
    HmacSha512,
}

/// Generated key pair or symmetric key.
#[derive(Clone)]
pub struct GeneratedKey {
    /// Key type
    pub key_type: KeyType,
    /// Private/secret key bytes
    pub private_key: Vec<u8>,
    /// Public key bytes (empty for symmetric keys)
    pub public_key: Vec<u8>,
}

impl GeneratedKey {
    /// Check if this is an asymmetric key pair.
    pub fn is_asymmetric(&self) -> bool {
        !self.public_key.is_empty()
    }

    /// Check if this is a symmetric key.
    pub fn is_symmetric(&self) -> bool {
        self.public_key.is_empty()
    }

    /// Get the key size in bits.
    pub fn key_size_bits(&self) -> usize {
        match self.key_type {
            KeyType::Ed25519 | KeyType::X25519 => 256,
            KeyType::EcdsaP256 | KeyType::Aes256 | KeyType::HmacSha256 => 256,
            KeyType::EcdsaP384 | KeyType::HmacSha384 => 384,
            KeyType::HmacSha512 => 512,
            KeyType::Aes128 => 128,
            KeyType::Rsa2048 => 2048,
            KeyType::Rsa3072 => 3072,
            KeyType::Rsa4096 => 4096,
        }
    }
}

// ============================================================================
// Unified Key Generation
// ============================================================================

/// Generate a cryptographic key of the specified type.
pub fn generate_keypair(key_type: KeyType) -> CryptoResult<GeneratedKey> {
    match key_type {
        KeyType::Ed25519 => generate_ed25519(),
        KeyType::X25519 => generate_x25519(),
        KeyType::EcdsaP256 => generate_p256(),
        KeyType::EcdsaP384 => generate_p384(),
        KeyType::Rsa2048 => generate_rsa(2048),
        KeyType::Rsa3072 => generate_rsa(3072),
        KeyType::Rsa4096 => generate_rsa(4096),
        KeyType::Aes128 => generate_symmetric(16, KeyType::Aes128),
        KeyType::Aes256 => generate_symmetric(32, KeyType::Aes256),
        KeyType::HmacSha256 => generate_symmetric(32, KeyType::HmacSha256),
        KeyType::HmacSha384 => generate_symmetric(48, KeyType::HmacSha384),
        KeyType::HmacSha512 => generate_symmetric(64, KeyType::HmacSha512),
    }
}

// ============================================================================
// Ed25519
// ============================================================================

fn generate_ed25519() -> CryptoResult<GeneratedKey> {
    use crate::ed25519::Ed25519KeyPair;

    let keypair = Ed25519KeyPair::generate();

    Ok(GeneratedKey {
        key_type: KeyType::Ed25519,
        private_key: keypair.secret_key().to_vec(),
        public_key: keypair.public_key().to_vec(),
    })
}

/// Generate an Ed25519 key pair with PEM encoding.
pub fn generate_ed25519_pem() -> CryptoResult<(String, String)> {
    use base64::Engine;

    let keypair = generate_ed25519()?;

    // PKCS#8 DER structure for Ed25519 private key
    // This is a simplified version - proper ASN.1 encoding
    let mut private_der = vec![
        0x30, 0x2e, // SEQUENCE, length 46
        0x02, 0x01, 0x00, // INTEGER 0 (version)
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, length 34
        0x04, 0x20, // OCTET STRING, length 32
    ];
    private_der.extend_from_slice(&keypair.private_key);

    // SubjectPublicKeyInfo for Ed25519
    let mut public_der = vec![
        0x30, 0x2a, // SEQUENCE, length 42
        0x30, 0x05, // SEQUENCE, length 5
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x03, 0x21, 0x00, // BIT STRING, length 33 (unused bits = 0)
    ];
    public_der.extend_from_slice(&keypair.public_key);

    let private_pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&private_der)
    );

    let public_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&public_der)
    );

    Ok((private_pem, public_pem))
}

// ============================================================================
// X25519
// ============================================================================

fn generate_x25519() -> CryptoResult<GeneratedKey> {
    use crate::ecdh::x25519_generate_keypair;

    let (private_key, public_key) = x25519_generate_keypair();

    Ok(GeneratedKey {
        key_type: KeyType::X25519,
        private_key: private_key.to_vec(),
        public_key: public_key.to_vec(),
    })
}

// ============================================================================
// P-256
// ============================================================================

fn generate_p256() -> CryptoResult<GeneratedKey> {
    use crate::ecdh::p256_generate_keypair;

    let (private_key, public_key) = p256_generate_keypair();

    Ok(GeneratedKey {
        key_type: KeyType::EcdsaP256,
        private_key,
        public_key,
    })
}

/// Generate a P-256 key pair with PEM encoding.
pub fn generate_p256_pem() -> CryptoResult<(String, String)> {
    use base64::Engine;
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;

    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();

    // Encode private key as SEC1 DER
    let private_bytes = secret.to_bytes();

    // Build SEC1 ECPrivateKey structure
    let mut private_der = vec![
        0x30, 0x77, // SEQUENCE, approximate length
        0x02, 0x01, 0x01, // INTEGER 1 (version)
        0x04, 0x20, // OCTET STRING, length 32
    ];
    private_der.extend_from_slice(&private_bytes);

    // Add curve OID
    private_der.extend_from_slice(&[
        0xa0, 0x0a, // [0] EXPLICIT, length 10
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
    ]);

    // Add public key
    let public_point = public.to_encoded_point(false);
    let public_bytes = public_point.as_bytes();
    private_der.push(0xa1); // [1] EXPLICIT
    private_der.push((public_bytes.len() + 2) as u8);
    private_der.push(0x03); // BIT STRING
    private_der.push((public_bytes.len() + 1) as u8);
    private_der.push(0x00); // unused bits
    private_der.extend_from_slice(public_bytes);

    // Fix length
    private_der[1] = (private_der.len() - 2) as u8;

    // Build SubjectPublicKeyInfo
    let mut public_der = vec![
        0x30, 0x59, // SEQUENCE, length 89
        0x30, 0x13, // SEQUENCE, length 19
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
        0x03, 0x42, 0x00, // BIT STRING, length 66, unused bits = 0
    ];
    public_der.extend_from_slice(public_bytes);

    let private_pem = format!(
        "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&private_der)
    );

    let public_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::engine::general_purpose::STANDARD.encode(&public_der)
    );

    Ok((private_pem, public_pem))
}

// ============================================================================
// P-384
// ============================================================================

fn generate_p384() -> CryptoResult<GeneratedKey> {
    use crate::ecdh::p384_generate_keypair;

    let (private_key, public_key) = p384_generate_keypair();

    Ok(GeneratedKey {
        key_type: KeyType::EcdsaP384,
        private_key,
        public_key,
    })
}

// ============================================================================
// RSA
// ============================================================================

fn generate_rsa(bits: usize) -> CryptoResult<GeneratedKey> {
    use rsa::RsaPrivateKey;

    let private_key = RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|e| CryptoError::internal(format!("RSA key generation failed: {}", e)))?;

    // Serialize private key to PKCS#1 DER
    use rsa::pkcs1::EncodeRsaPrivateKey;
    let private_der = private_key.to_pkcs1_der().map_err(|e| {
        CryptoError::internal(format!("RSA private key encoding failed: {}", e))
    })?;

    // Serialize public key to PKCS#1 DER
    use rsa::pkcs1::EncodeRsaPublicKey;
    let public_key = private_key.to_public_key();
    let public_der = public_key.to_pkcs1_der().map_err(|e| {
        CryptoError::internal(format!("RSA public key encoding failed: {}", e))
    })?;

    let key_type = match bits {
        2048 => KeyType::Rsa2048,
        3072 => KeyType::Rsa3072,
        4096 => KeyType::Rsa4096,
        _ => {
            return Err(CryptoError::internal(format!(
                "Unsupported RSA key size: {}",
                bits
            )))
        }
    };

    Ok(GeneratedKey {
        key_type,
        private_key: private_der.as_bytes().to_vec(),
        public_key: public_der.as_bytes().to_vec(),
    })
}

/// Generate an RSA key pair with PEM encoding.
pub fn generate_rsa_pem(bits: usize) -> CryptoResult<(String, String)> {
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    let private_key = RsaPrivateKey::new(&mut OsRng, bits)
        .map_err(|e| CryptoError::internal(format!("RSA key generation failed: {}", e)))?;

    let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).map_err(|e| {
        CryptoError::internal(format!("RSA private key PEM encoding failed: {}", e))
    })?;

    let public_key = private_key.to_public_key();
    let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).map_err(|e| {
        CryptoError::internal(format!("RSA public key PEM encoding failed: {}", e))
    })?;

    Ok((private_pem.to_string(), public_pem))
}

// ============================================================================
// Symmetric Keys
// ============================================================================

fn generate_symmetric(size: usize, key_type: KeyType) -> CryptoResult<GeneratedKey> {
    let mut key = vec![0u8; size];
    OsRng.fill_bytes(&mut key);

    Ok(GeneratedKey {
        key_type,
        private_key: key,
        public_key: Vec::new(), // Symmetric keys have no public key
    })
}

/// Generate a random AES-256 key.
pub fn generate_aes256_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random AES-128 key.
pub fn generate_aes128_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate random bytes.
pub fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Generate a random nonce for AES-GCM (12 bytes).
pub fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Generate a random IV for AES-CBC (16 bytes).
pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    iv
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ed25519() {
        let keypair = generate_keypair(KeyType::Ed25519).unwrap();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
        assert!(keypair.is_asymmetric());
        assert_eq!(keypair.key_size_bits(), 256);
    }

    #[test]
    fn test_generate_x25519() {
        let keypair = generate_keypair(KeyType::X25519).unwrap();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 32);
    }

    #[test]
    fn test_generate_p256() {
        let keypair = generate_keypair(KeyType::EcdsaP256).unwrap();
        assert_eq!(keypair.private_key.len(), 32);
        assert_eq!(keypair.public_key.len(), 65); // Uncompressed
    }

    #[test]
    fn test_generate_p384() {
        let keypair = generate_keypair(KeyType::EcdsaP384).unwrap();
        assert_eq!(keypair.private_key.len(), 48);
        assert_eq!(keypair.public_key.len(), 97); // Uncompressed
    }

    #[test]
    fn test_generate_rsa2048() {
        let keypair = generate_keypair(KeyType::Rsa2048).unwrap();
        assert!(!keypair.private_key.is_empty());
        assert!(!keypair.public_key.is_empty());
        assert_eq!(keypair.key_size_bits(), 2048);
    }

    #[test]
    fn test_generate_aes256() {
        let keypair = generate_keypair(KeyType::Aes256).unwrap();
        assert_eq!(keypair.private_key.len(), 32);
        assert!(keypair.public_key.is_empty());
        assert!(keypair.is_symmetric());
    }

    #[test]
    fn test_generate_aes128() {
        let keypair = generate_keypair(KeyType::Aes128).unwrap();
        assert_eq!(keypair.private_key.len(), 16);
        assert!(keypair.is_symmetric());
    }

    #[test]
    fn test_generate_hmac_keys() {
        let sha256 = generate_keypair(KeyType::HmacSha256).unwrap();
        assert_eq!(sha256.private_key.len(), 32);

        let sha384 = generate_keypair(KeyType::HmacSha384).unwrap();
        assert_eq!(sha384.private_key.len(), 48);

        let sha512 = generate_keypair(KeyType::HmacSha512).unwrap();
        assert_eq!(sha512.private_key.len(), 64);
    }

    #[test]
    fn test_generate_random_bytes() {
        let bytes1 = generate_random_bytes(32);
        let bytes2 = generate_random_bytes(32);

        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different (extremely high probability)
    }

    #[test]
    fn test_generate_nonce_iv() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 12);

        let iv = generate_iv();
        assert_eq!(iv.len(), 16);
    }

    #[test]
    fn test_ed25519_pem() {
        let (private_pem, public_pem) = generate_ed25519_pem().unwrap();

        assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(private_pem.ends_with("-----END PRIVATE KEY-----\n"));

        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(public_pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    fn test_p256_pem() {
        let (private_pem, public_pem) = generate_p256_pem().unwrap();

        assert!(private_pem.contains("-----BEGIN EC PRIVATE KEY-----"));
        assert!(public_pem.contains("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn test_rsa_pem() {
        let (private_pem, public_pem) = generate_rsa_pem(2048).unwrap();

        assert!(private_pem.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(public_pem.contains("-----BEGIN RSA PUBLIC KEY-----"));
    }

    #[test]
    fn test_key_uniqueness() {
        // Generate multiple keys and ensure they're all different
        let keys: Vec<_> = (0..5)
            .map(|_| generate_keypair(KeyType::Aes256).unwrap())
            .collect();

        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i].private_key, keys[j].private_key);
            }
        }
    }
}
