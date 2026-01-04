//! Platform keychain integration for secure key storage

use crate::error::StorageError;

const SERVICE_NAME: &str = "com.marty.verifier";
const DB_KEY_NAME: &str = "database_encryption_key";
const PII_KEY_NAME: &str = "pii_encryption_key";

/// Keychain manager for secure key storage
pub struct KeychainManager {
    service: String,
}

impl KeychainManager {
    /// Create new keychain manager
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
        }
    }

    /// Get or create the database encryption key
    pub fn get_or_create_db_key(&self) -> Result<Vec<u8>, StorageError> {
        self.get_or_create_key(DB_KEY_NAME)
    }

    /// Get or create the PII encryption key
    pub fn get_or_create_pii_key(&self) -> Result<Vec<u8>, StorageError> {
        self.get_or_create_key(PII_KEY_NAME)
    }

    /// Get or create a key by name
    fn get_or_create_key(&self, key_name: &str) -> Result<Vec<u8>, StorageError> {
        let entry = keyring::Entry::new(&self.service, key_name)
            .map_err(|e| StorageError::Keychain(e.to_string()))?;

        // Try to get existing key
        match entry.get_password() {
            Ok(key_b64) => {
                // Decode base64 key
                use base64::Engine;
                let key = base64::engine::general_purpose::STANDARD
                    .decode(&key_b64)
                    .map_err(|e| StorageError::Keychain(format!("Invalid key encoding: {}", e)))?;
                Ok(key)
            }
            Err(keyring::Error::NoEntry) => {
                // Generate new key
                let key = self.generate_key()?;

                // Store in keychain
                use base64::Engine;
                let key_b64 = base64::engine::general_purpose::STANDARD.encode(&key);
                entry
                    .set_password(&key_b64)
                    .map_err(|e| StorageError::Keychain(e.to_string()))?;

                tracing::info!(key_name, "Generated new encryption key");
                Ok(key)
            }
            Err(e) => Err(StorageError::Keychain(e.to_string())),
        }
    }

    /// Generate a new 256-bit encryption key
    fn generate_key(&self) -> Result<Vec<u8>, StorageError> {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    /// Delete all stored keys (for testing/reset)
    #[allow(dead_code)]
    pub fn delete_all_keys(&self) -> Result<(), StorageError> {
        for key_name in [DB_KEY_NAME, PII_KEY_NAME] {
            if let Ok(entry) = keyring::Entry::new(&self.service, key_name) {
                let _ = entry.delete_credential();
            }
        }
        Ok(())
    }
}

impl Default for KeychainManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires keychain access
    fn test_key_generation() {
        let km = KeychainManager::new();
        let key = km.generate_key().unwrap();
        assert_eq!(key.len(), 32);
    }
}
