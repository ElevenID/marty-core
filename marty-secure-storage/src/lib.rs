//! Marty Secure Storage
//!
//! Encrypted local storage for the Marty Verifier application.
//! Uses SQLCipher for encrypted SQLite and platform keychain for key storage.

mod database;
mod encryption;
mod error;
mod keychain;
mod migrations;
mod models;
mod schema;

pub use database::SecureStorage;
pub use encryption::PiiEncryptor;
pub use error::StorageError;
pub use keychain::InstanceNamespace;
pub use models::*;

/// The exact database types used by storage callbacks and errors.
pub use rusqlite;

/// Re-export for command handlers
pub use database::{OfflineQueueStatus, VerificationHistoryEntry};
