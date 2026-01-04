//! Elliptic Curve Diffie-Hellman (ECDH) key agreement.
//!
//! This module provides ECDH key agreement for:
//! - X25519 (Curve25519) - Modern, fast, constant-time
//! - ECDH P-256 - NIST curve, widely compatible
//! - ECDH P-384 - NIST curve, higher security level
//!
//! # Usage
//!
//! ECDH is used for:
//! - PACE (Password Authenticated Connection Establishment) in eMRTD
//! - JWE (JSON Web Encryption) key agreement
//! - TLS key exchange
//! - Secure messaging in mDL and Verifiable Credentials

use elliptic_curve::sec1::ToEncodedPoint;
use p256::{
    ecdh::diffie_hellman as p256_dh, PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use p384::{
    ecdh::diffie_hellman as p384_dh, PublicKey as P384PublicKey, SecretKey as P384SecretKey,
};
use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

use crate::{CryptoError, CryptoResult};

// ============================================================================
// X25519 Key Agreement
// ============================================================================

/// X25519 key pair for key agreement.
pub struct X25519KeyPair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random X25519 key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from a 32-byte secret key.
    pub fn from_secret_key(secret_bytes: &[u8]) -> CryptoResult<Self> {
        if secret_bytes.len() != 32 {
            return Err(CryptoError::internal(
                "X25519 secret key must be 32 bytes".to_string(),
            ));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret_bytes);

        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);

        Ok(Self { secret, public })
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Perform key agreement with a peer's public key.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - 32-byte peer public key
    ///
    /// # Returns
    ///
    /// 32-byte shared secret.
    pub fn agree(&self, peer_public: &[u8]) -> CryptoResult<[u8; 32]> {
        if peer_public.len() != 32 {
            return Err(CryptoError::internal(
                "X25519 public key must be 32 bytes".to_string(),
            ));
        }

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(peer_public);

        let peer_key = X25519PublicKey::from(bytes);
        let shared = self.secret.diffie_hellman(&peer_key);

        Ok(shared.to_bytes())
    }
}

/// Generate an ephemeral X25519 key pair and perform key agreement.
///
/// This is useful for one-shot key agreement where you don't need to reuse the private key.
///
/// # Arguments
///
/// * `peer_public` - 32-byte peer public key
///
/// # Returns
///
/// (ephemeral_public_key, shared_secret) tuple.
pub fn x25519_ephemeral_agree(peer_public: &[u8]) -> CryptoResult<([u8; 32], [u8; 32])> {
    if peer_public.len() != 32 {
        return Err(CryptoError::internal(
            "X25519 public key must be 32 bytes".to_string(),
        ));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(peer_public);

    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = X25519PublicKey::from(&secret);
    let peer_key = X25519PublicKey::from(bytes);
    let shared = secret.diffie_hellman(&peer_key);

    Ok((public.to_bytes(), shared.to_bytes()))
}

/// Generate a new X25519 key pair.
///
/// # Returns
///
/// (secret_key, public_key) as 32-byte arrays.
pub fn x25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    // Generate from random 32 bytes since StaticSecret doesn't expose its bytes
    let mut secret_bytes = [0u8; 32];
    use rand::RngCore;
    OsRng.fill_bytes(&mut secret_bytes);

    let secret = StaticSecret::from(secret_bytes);
    let public = X25519PublicKey::from(&secret);

    (secret_bytes, public.to_bytes())
}

// ============================================================================
// ECDH P-256 Key Agreement
// ============================================================================

/// P-256 ECDH key pair.
pub struct P256KeyPair {
    secret: P256SecretKey,
}

impl P256KeyPair {
    /// Generate a new random P-256 key pair.
    pub fn generate() -> Self {
        let secret = P256SecretKey::random(&mut OsRng);
        Self { secret }
    }

    /// Create from a 32-byte secret key (scalar).
    pub fn from_secret_key(secret_bytes: &[u8]) -> CryptoResult<Self> {
        let secret = P256SecretKey::from_slice(secret_bytes)
            .map_err(|e| CryptoError::internal(format!("Invalid P-256 secret key: {}", e)))?;
        Ok(Self { secret })
    }

    /// Get the public key in uncompressed SEC1 format (65 bytes: 04 || x || y).
    pub fn public_key_uncompressed(&self) -> Vec<u8> {
        let public = self.secret.public_key();
        public.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Get the public key in compressed SEC1 format (33 bytes: 02/03 || x).
    pub fn public_key_compressed(&self) -> Vec<u8> {
        let public = self.secret.public_key();
        public.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Perform ECDH key agreement.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - Peer's public key in SEC1 format (compressed or uncompressed)
    ///
    /// # Returns
    ///
    /// 32-byte shared secret (x-coordinate of the shared point).
    pub fn agree(&self, peer_public: &[u8]) -> CryptoResult<Vec<u8>> {
        let peer_key = P256PublicKey::from_sec1_bytes(peer_public)
            .map_err(|e| CryptoError::internal(format!("Invalid P-256 public key: {}", e)))?;

        let shared = p256_dh(self.secret.to_nonzero_scalar(), peer_key.as_affine());

        Ok(shared.raw_secret_bytes().to_vec())
    }
}

/// Generate a new P-256 ECDH key pair.
///
/// # Returns
///
/// (secret_key, public_key_uncompressed) tuple.
pub fn p256_generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let keypair = P256KeyPair::generate();
    let secret = keypair.secret.to_bytes().to_vec();
    let public = keypair.public_key_uncompressed();
    (secret, public)
}

/// Perform P-256 ECDH key agreement.
pub fn p256_agree(secret_key: &[u8], peer_public: &[u8]) -> CryptoResult<Vec<u8>> {
    let keypair = P256KeyPair::from_secret_key(secret_key)?;
    keypair.agree(peer_public)
}

// ============================================================================
// ECDH P-384 Key Agreement
// ============================================================================

/// P-384 ECDH key pair.
pub struct P384KeyPair {
    secret: P384SecretKey,
}

impl P384KeyPair {
    /// Generate a new random P-384 key pair.
    pub fn generate() -> Self {
        let secret = P384SecretKey::random(&mut OsRng);
        Self { secret }
    }

    /// Create from a 48-byte secret key (scalar).
    pub fn from_secret_key(secret_bytes: &[u8]) -> CryptoResult<Self> {
        let secret = P384SecretKey::from_slice(secret_bytes)
            .map_err(|e| CryptoError::internal(format!("Invalid P-384 secret key: {}", e)))?;
        Ok(Self { secret })
    }

    /// Get the public key in uncompressed SEC1 format (97 bytes).
    pub fn public_key_uncompressed(&self) -> Vec<u8> {
        let public = self.secret.public_key();
        public.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Get the public key in compressed SEC1 format (49 bytes).
    pub fn public_key_compressed(&self) -> Vec<u8> {
        let public = self.secret.public_key();
        public.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Perform ECDH key agreement.
    pub fn agree(&self, peer_public: &[u8]) -> CryptoResult<Vec<u8>> {
        let peer_key = P384PublicKey::from_sec1_bytes(peer_public)
            .map_err(|e| CryptoError::internal(format!("Invalid P-384 public key: {}", e)))?;

        let shared = p384_dh(self.secret.to_nonzero_scalar(), peer_key.as_affine());

        Ok(shared.raw_secret_bytes().to_vec())
    }
}

/// Generate a new P-384 ECDH key pair.
pub fn p384_generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let keypair = P384KeyPair::generate();
    let secret = keypair.secret.to_bytes().to_vec();
    let public = keypair.public_key_uncompressed();
    (secret, public)
}

/// Perform P-384 ECDH key agreement.
pub fn p384_agree(secret_key: &[u8], peer_public: &[u8]) -> CryptoResult<Vec<u8>> {
    let keypair = P384KeyPair::from_secret_key(secret_key)?;
    keypair.agree(peer_public)
}

// ============================================================================
// ECIES-style Encryption (ECDH + AES-GCM)
// ============================================================================

/// Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme).
///
/// Uses X25519 for key agreement, HKDF for key derivation, and AES-256-GCM for encryption.
///
/// # Arguments
///
/// * `recipient_public` - 32-byte X25519 public key of the recipient
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (can be empty)
///
/// # Returns
///
/// Ciphertext format: ephemeral_public (32) || nonce (12) || ciphertext || tag (16)
pub fn ecies_encrypt(
    recipient_public: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    use crate::kdf::hkdf_sha256;
    use crate::symmetric::aes_256_gcm_encrypt;
    use rand::RngCore;

    // Generate ephemeral key pair
    let (ephem_public, shared_secret) = x25519_ephemeral_agree(recipient_public)?;

    // Derive encryption key using HKDF
    let info = b"ECIES-X25519-AES256GCM";
    let key = hkdf_sha256(&shared_secret, &[], info, 32)?;

    // Generate random nonce
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // Encrypt
    let ciphertext = aes_256_gcm_encrypt(&key, &nonce, plaintext, aad)?;

    // Combine: ephemeral_public || nonce || ciphertext
    let mut result = Vec::with_capacity(32 + 12 + ciphertext.len());
    result.extend_from_slice(&ephem_public);
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt ECIES-encrypted data.
///
/// # Arguments
///
/// * `recipient_secret` - 32-byte X25519 secret key
/// * `ciphertext` - Data encrypted with `ecies_encrypt`
/// * `aad` - Additional authenticated data (must match encryption)
pub fn ecies_decrypt(
    recipient_secret: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> CryptoResult<Vec<u8>> {
    use crate::kdf::hkdf_sha256;
    use crate::symmetric::aes_256_gcm_decrypt;

    if ciphertext.len() < 32 + 12 + 16 {
        return Err(CryptoError::internal(
            "ECIES ciphertext too short".to_string(),
        ));
    }

    // Parse components
    let ephem_public = &ciphertext[..32];
    let nonce = &ciphertext[32..44];
    let encrypted = &ciphertext[44..];

    // Perform key agreement
    let keypair = X25519KeyPair::from_secret_key(recipient_secret)?;
    let shared_secret = keypair.agree(ephem_public)?;

    // Derive decryption key
    let info = b"ECIES-X25519-AES256GCM";
    let key = hkdf_sha256(&shared_secret, &[], info, 32)?;

    // Decrypt
    aes_256_gcm_decrypt(&key, nonce, encrypted, aad)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_agreement() {
        // Alice generates a key pair
        let alice = X25519KeyPair::generate();

        // Bob generates a key pair
        let bob = X25519KeyPair::generate();

        // Both compute the shared secret
        let alice_shared = alice.agree(&bob.public_key_bytes()).unwrap();
        let bob_shared = bob.agree(&alice.public_key_bytes()).unwrap();

        // Shared secrets should match
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_x25519_ephemeral() {
        let recipient = X25519KeyPair::generate();

        // Sender performs ephemeral key agreement
        let (ephem_public, sender_shared) =
            x25519_ephemeral_agree(&recipient.public_key_bytes()).unwrap();

        // Recipient derives the same shared secret
        let recipient_shared = recipient.agree(&ephem_public).unwrap();

        assert_eq!(sender_shared, recipient_shared);
    }

    #[test]
    fn test_p256_key_agreement() {
        let alice = P256KeyPair::generate();
        let bob = P256KeyPair::generate();

        let alice_shared = alice.agree(&bob.public_key_uncompressed()).unwrap();
        let bob_shared = bob.agree(&alice.public_key_uncompressed()).unwrap();

        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 32);
    }

    #[test]
    fn test_p384_key_agreement() {
        let alice = P384KeyPair::generate();
        let bob = P384KeyPair::generate();

        let alice_shared = alice.agree(&bob.public_key_uncompressed()).unwrap();
        let bob_shared = bob.agree(&alice.public_key_uncompressed()).unwrap();

        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared.len(), 48);
    }

    #[test]
    fn test_p256_compressed_key() {
        let keypair = P256KeyPair::generate();

        let uncompressed = keypair.public_key_uncompressed();
        let compressed = keypair.public_key_compressed();

        assert_eq!(uncompressed.len(), 65);
        assert_eq!(compressed.len(), 33);
        assert_eq!(uncompressed[0], 0x04); // Uncompressed prefix
        assert!(compressed[0] == 0x02 || compressed[0] == 0x03); // Compressed prefix
    }

    #[test]
    fn test_ecies_roundtrip() {
        let plaintext = b"Secret message for ECIES encryption";
        let aad = b"additional data";

        // Generate keypair for encryption/decryption test
        let (secret, public) = x25519_generate_keypair();

        // Encrypt to recipient's public key
        let ciphertext = ecies_encrypt(&public, plaintext, aad).unwrap();

        // Ciphertext should be larger than plaintext
        assert!(ciphertext.len() > plaintext.len());

        // Decrypt with recipient's secret key
        let decrypted = ecies_decrypt(&secret, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecies_wrong_aad() {
        let (secret, public) = x25519_generate_keypair();
        let plaintext = b"Test data";

        let ciphertext = ecies_encrypt(&public, plaintext, b"correct aad").unwrap();

        // Decryption with wrong AAD should fail
        let result = ecies_decrypt(&secret, &ciphertext, b"wrong aad");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_x25519_key_length() {
        let keypair = X25519KeyPair::generate();

        // Too short
        assert!(keypair.agree(&[0u8; 16]).is_err());

        // Too long
        assert!(keypair.agree(&[0u8; 64]).is_err());
    }

    #[test]
    fn test_from_secret_key() {
        let (secret, public) = x25519_generate_keypair();

        let restored = X25519KeyPair::from_secret_key(&secret).unwrap();
        assert_eq!(restored.public_key_bytes(), public);
    }
}
