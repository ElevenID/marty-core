//! Marty Secure Storage
//!
//! Encrypted local storage for the Marty Verifier application.
//! Uses SQLCipher for encrypted SQLite and platform keychain for key storage.

mod database;
mod encryption;
mod error;
mod keychain;
mod models;
mod schema;

pub use database::SecureStorage;
pub use error::StorageError;
pub use models::*;

/// Re-export for command handlers
pub use database::{OfflineQueueStatus, VerificationHistoryEntry};
