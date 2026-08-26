//! Platform keychain integration for secure key storage

use crate::error::StorageError;

const SERVICE_NAME: &str = "com.marty.verifier";
const DB_KEY_NAME: &str = "database_encryption_key";
#[allow(dead_code)]
const PII_KEY_NAME: &str = "pii_encryption_key";

/// Keychain manager for secure key storage
pub struct KeychainManager {
    service: String,
    store_selection: StoreSelection,
}

#[derive(Clone, Copy)]
enum StoreSelection {
    Platform,
    InstalledDefault,
}

impl KeychainManager {
    /// Create new keychain manager
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
            store_selection: StoreSelection::Platform,
        }
    }

    pub(crate) fn with_installed_default_store() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
            store_selection: StoreSelection::InstalledDefault,
        }
    }

    /// Get or create the database encryption key
    pub fn get_or_create_db_key(&self) -> Result<Vec<u8>, StorageError> {
        self.get_or_create_key(DB_KEY_NAME)
    }

    /// Get or create the PII encryption key
    #[allow(dead_code)]
    pub fn get_or_create_pii_key(&self) -> Result<Vec<u8>, StorageError> {
        self.get_or_create_key(PII_KEY_NAME)
    }

    /// Get or create a key by name
    fn get_or_create_key(&self, key_name: &str) -> Result<Vec<u8>, StorageError> {
        if matches!(self.store_selection, StoreSelection::Platform) {
            if let Err(error) = keyring::Entry::store_status() {
                return Err(StorageError::Keychain(error.to_string()));
            }
        }
        let entry = keyring_core::Entry::new(&self.service, key_name)
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
            Err(keyring_core::Error::NoEntry) => {
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
}

impl Default for KeychainManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::SecureStorage;
    use std::sync::Arc;

    struct RestoreDefaultStore(Option<Arc<keyring_core::CredentialStore>>);

    impl Drop for RestoreDefaultStore {
        fn drop(&mut self) {
            keyring_core::unset_default_store();
            if let Some(previous) = self.0.take() {
                keyring_core::set_default_store(previous);
            }
        }
    }

    #[test]
    fn process_local_storage_requires_and_preserves_a_process_local_store() {
        let previous = keyring_core::unset_default_store();
        let _restore = RestoreDefaultStore(previous);

        let missing =
            SecureStorage::new_with_process_local_keyring(tempfile::tempdir().unwrap().path())
                .err()
                .expect("an explicitly installed process-local store is required");
        assert!(missing.to_string().contains("no default store"));

        let store: Arc<keyring_core::CredentialStore> = keyring_core::mock::Store::new().unwrap();
        let expected_id = store.id();
        keyring_core::set_default_store(store);
        let temporary = tempfile::tempdir().unwrap();
        let _storage = SecureStorage::new_with_process_local_keyring(temporary.path())
            .expect("the process-local store must support secure storage startup");

        let selected = keyring_core::get_default_store().expect("store must remain installed");
        assert_eq!(selected.id(), expected_id);
        assert!(matches!(
            selected.persistence(),
            keyring_core::CredentialPersistence::ProcessOnly
        ));
    }

    #[test]
    #[ignore] // Requires keychain access
    fn test_key_generation() {
        let km = KeychainManager::new();
        let key = km.generate_key().unwrap();
        assert_eq!(key.len(), 32);
    }
}
