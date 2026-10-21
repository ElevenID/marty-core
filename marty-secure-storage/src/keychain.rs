//! Platform keychain integration for secure key storage

use crate::error::StorageError;
use std::sync::{Arc, LazyLock};

const SERVICE_NAME: &str = "com.marty.verifier";
const DB_KEY_NAME: &str = "database_encryption_key";
const PII_KEY_NAME: &str = "pii_encryption_key";

/// An explicitly isolated platform-keychain namespace. Never aliases the default service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceNamespace(String);

impl InstanceNamespace {
    pub fn new(instance: &str) -> Result<Self, StorageError> {
        if instance.is_empty()
            || instance.len() > 64
            || !instance
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || !instance.as_bytes()[0].is_ascii_alphanumeric()
            || instance.ends_with('-')
            || matches!(instance, "default" | "production" | "prod")
        {
            return Err(StorageError::Keychain(
                "invalid isolated instance namespace".into(),
            ));
        }
        Ok(Self(format!("{SERVICE_NAME}.instance.{instance}")))
    }

    pub fn service_name(&self) -> &str {
        &self.0
    }

    /// Remove only this instance's keys, after its database has been retired.
    pub fn remove_keys(&self) -> Result<(), StorageError> {
        KeychainManager::for_instance(self).remove_instance_keys()
    }
}

/// Keychain manager for secure key storage
pub struct KeychainManager {
    service: String,
    store_selection: StoreSelection,
}

enum StoreSelection {
    Platform,
    Bound(Arc<keyring_core::CredentialStore>),
}

// Own the selected native store; another consumer may replace keyring-core's
// process-global default with a transient test store after native initialization.
static PLATFORM_STORE: LazyLock<keyring_core::Result<Arc<keyring_core::CredentialStore>>> =
    LazyLock::new(|| {
        #[cfg(target_os = "windows")]
        {
            windows_native_keyring_store::Store::new()
        }
        #[cfg(target_os = "macos")]
        {
            apple_native_keyring_store::keychain::Store::new()
        }
        #[cfg(all(
            unix,
            not(any(target_os = "macos", target_os = "ios", target_os = "android"))
        ))]
        {
            zbus_secret_service_keyring_store::Store::new()
        }
        #[cfg(not(all(any(unix, windows), not(any(target_os = "ios", target_os = "android")))))]
        Err(keyring_core::Error::Invalid(
            "platform".into(),
            "unsupported platform credential store".into(),
        ))
    });

impl KeychainManager {
    pub(crate) fn for_instance(instance: &InstanceNamespace) -> Self {
        Self {
            service: instance.0.clone(),
            store_selection: StoreSelection::Platform,
        }
    }

    fn remove_instance_keys(&self) -> Result<(), StorageError> {
        if !self
            .service
            .starts_with(&format!("{SERVICE_NAME}.instance."))
        {
            return Err(StorageError::Keychain(
                "refusing default key removal".into(),
            ));
        }
        for name in [DB_KEY_NAME, PII_KEY_NAME] {
            let entry = self.entry(name)?;
            match entry.delete_credential() {
                Ok(()) | Err(keyring_core::Error::NoEntry) => (),
                Err(e) => return Err(StorageError::Keychain(e.to_string())),
            }
        }
        Ok(())
    }

    fn entry(&self, name: &str) -> Result<keyring_core::Entry, StorageError> {
        let store = match &self.store_selection {
            StoreSelection::Platform => PLATFORM_STORE
                .as_ref()
                .map_err(|error| StorageError::Keychain(error.to_string()))?,
            StoreSelection::Bound(store) => store,
        };
        store
            .build(&self.service, name, None)
            .map_err(|error| StorageError::Keychain(error.to_string()))
    }
    /// Create new keychain manager
    pub fn new() -> Self {
        Self {
            service: SERVICE_NAME.to_string(),
            store_selection: StoreSelection::Platform,
        }
    }

    pub(crate) fn with_process_local_store() -> Result<Self, StorageError> {
        let store = keyring_core::get_default_store()
            .ok_or_else(|| StorageError::Keychain("no default store is installed".to_string()))?;
        if !matches!(
            store.persistence(),
            keyring_core::CredentialPersistence::ProcessOnly
        ) {
            return Err(StorageError::Keychain(
                "installed keyring is not process-local".to_string(),
            ));
        }
        Ok(Self {
            service: SERVICE_NAME.to_string(),
            store_selection: StoreSelection::Bound(store),
        })
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
        let entry = self.entry(key_name)?;

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
        assert!(crate::PiiEncryptor::from_process_local_keyring().is_err());

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
        let first = crate::PiiEncryptor::from_process_local_keyring().unwrap();
        let ciphertext = first.encrypt("persisted PII").unwrap();
        let reopened = crate::PiiEncryptor::from_process_local_keyring().unwrap();
        assert_eq!(reopened.decrypt(&ciphertext).unwrap(), "persisted PII");
        let pii_entry = keyring_core::Entry::new(SERVICE_NAME, PII_KEY_NAME).unwrap();
        pii_entry.set_password("invalid key encoding!").unwrap();
        assert!(crate::PiiEncryptor::from_process_local_keyring().is_err());
        assert_eq!(pii_entry.get_password().unwrap(), "invalid key encoding!");

        // Malformed default sentinels prove instance startup never reads default keys.
        let db_entry = keyring_core::Entry::new(SERVICE_NAME, DB_KEY_NAME).unwrap();
        db_entry.set_password("default DB sentinel").unwrap();
        let instance = InstanceNamespace::new("d09-test-1").unwrap();
        let other_instance = InstanceNamespace::new("d09-test-2").unwrap();
        let other_entry =
            keyring_core::Entry::new(other_instance.service_name(), DB_KEY_NAME).unwrap();
        other_entry.set_password("other instance sentinel").unwrap();
        let mut scoped = KeychainManager::for_instance(&instance);
        scoped.store_selection = StoreSelection::Bound(selected.clone());
        let db_key = scoped.get_or_create_db_key().unwrap();
        let pii_key = scoped.get_or_create_pii_key().unwrap();
        assert_eq!(db_key.len(), 32);
        assert_eq!(pii_key.len(), 32);
        assert_ne!(db_key, pii_key);
        assert_eq!(scoped.get_or_create_db_key().unwrap(), db_key);
        // Changing the global default must redirect neither instance reads nor
        // cleanup, and must preserve the replacement store's identically named keys.
        let replacement: Arc<keyring_core::CredentialStore> =
            keyring_core::mock::Store::new().unwrap();
        keyring_core::set_default_store(replacement.clone());
        for name in [DB_KEY_NAME, PII_KEY_NAME] {
            replacement
                .build(instance.service_name(), name, None)
                .unwrap()
                .set_password("replacement store sentinel")
                .unwrap();
        }
        assert_eq!(scoped.get_or_create_db_key().unwrap(), db_key);
        assert_eq!(first.decrypt(&ciphertext).unwrap(), "persisted PII");
        scoped.remove_instance_keys().unwrap();
        for name in [DB_KEY_NAME, PII_KEY_NAME] {
            assert!(matches!(
                selected
                    .build(instance.service_name(), name, None)
                    .unwrap()
                    .get_password(),
                Err(keyring_core::Error::NoEntry)
            ));
            assert_eq!(
                replacement
                    .build(instance.service_name(), name, None)
                    .unwrap()
                    .get_password()
                    .unwrap(),
                "replacement store sentinel"
            );
        }
        assert_eq!(db_entry.get_password().unwrap(), "default DB sentinel");
        assert_eq!(
            other_entry.get_password().unwrap(),
            "other instance sentinel"
        );
        assert_eq!(pii_entry.get_password().unwrap(), "invalid key encoding!");
        assert!(KeychainManager::with_process_local_store()
            .unwrap()
            .remove_instance_keys()
            .is_err());
    }

    #[test]
    fn instance_namespace_is_validated_and_cannot_alias_default() {
        for invalid in [
            "",
            "default",
            "prod",
            "production",
            "com.marty.verifier",
            "../x",
            "a/b",
            "a\\b",
            "A",
            "a b",
            "-a",
            "a-",
            " a",
            "a\0b",
        ] {
            assert!(InstanceNamespace::new(invalid).is_err(), "{invalid:?}");
        }
        assert!(InstanceNamespace::new(&"x".repeat(65)).is_err());
        for valid in ["d09", "run-123", "0"] {
            let namespace = InstanceNamespace::new(valid).unwrap();
            assert_ne!(namespace.service_name(), SERVICE_NAME);
            assert_eq!(
                namespace.service_name(),
                format!("{SERVICE_NAME}.instance.{valid}")
            );
        }
        assert_eq!(KeychainManager::new().service, SERVICE_NAME);
    }

    #[test]
    #[ignore] // Requires keychain access
    fn test_key_generation() {
        let km = KeychainManager::new();
        let key = km.generate_key().unwrap();
        assert_eq!(key.len(), 32);
    }
}
