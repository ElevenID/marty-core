//! Field-level encryption for PII data

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;

use crate::error::StorageError;

/// PII field encryptor using AES-256-GCM
#[allow(dead_code)]
pub struct PiiEncryptor {
    cipher: Aes256Gcm,
}

#[allow(dead_code)]
impl PiiEncryptor {
    /// Create new encryptor with the given key
    pub fn new(key: &[u8]) -> Result<Self, StorageError> {
        if key.len() != 32 {
            return Err(StorageError::Encryption("Key must be 32 bytes".to_string()));
        }

        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|e| StorageError::Encryption(e.to_string()))?;

        Ok(Self { cipher })
    }

    /// Encrypt a string value
    /// Returns base64-encoded ciphertext with prepended nonce
    pub fn encrypt(&self, plaintext: &str) -> Result<String, StorageError> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| StorageError::Encryption(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);

        // Base64 encode
        use base64::Engine;
        Ok(base64::engine::general_purpose::STANDARD.encode(&result))
    }

    /// Decrypt a base64-encoded ciphertext
    pub fn decrypt(&self, ciphertext_b64: &str) -> Result<String, StorageError> {
        // Base64 decode
        use base64::Engine;
        let data = base64::engine::general_purpose::STANDARD
            .decode(ciphertext_b64)
            .map_err(|e| StorageError::Encryption(format!("Invalid base64: {}", e)))?;

        if data.len() < 12 {
            return Err(StorageError::Encryption("Ciphertext too short".to_string()));
        }

        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        // Decrypt
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::Encryption(format!("Decryption failed: {}", e)))?;

        String::from_utf8(plaintext)
            .map_err(|e| StorageError::Encryption(format!("Invalid UTF-8: {}", e)))
    }

    /// Hash a value for indexing (one-way)
    pub fn hash_for_index(value: &str) -> String {
        let hash = blake3::hash(value.as_bytes());
        hash.to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let encryptor = PiiEncryptor::new(&key).unwrap();

        let plaintext = "John Doe";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let key = [0u8; 32];
        let encryptor = PiiEncryptor::new(&key).unwrap();

        let plaintext = "Same text";
        let ct1 = encryptor.encrypt(plaintext).unwrap();
        let ct2 = encryptor.encrypt(plaintext).unwrap();

        // Different ciphertexts due to random nonces
        assert_ne!(ct1, ct2);

        // Both decrypt to same plaintext
        assert_eq!(encryptor.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(encryptor.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn test_hash_for_index() {
        let hash1 = PiiEncryptor::hash_for_index("test");
        let hash2 = PiiEncryptor::hash_for_index("test");
        let hash3 = PiiEncryptor::hash_for_index("different");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
