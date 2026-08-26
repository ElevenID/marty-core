//! Storage error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Keychain error: {0}")]
    Keychain(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Record not found: {0}")]
    NotFound(String),

    #[error("Invalid offline queue batch: {0}")]
    InvalidQueueBatch(String),

    #[error("Invalid trust package: {0}")]
    InvalidTrustPackage(String),

    #[error("Trust package replay for domain {domain} at sequence {sequence}")]
    TrustPackageReplay { domain: String, sequence: u64 },

    #[error(
        "Trust package rollback for domain {domain}: current sequence {current_sequence}, attempted {attempted_sequence}"
    )]
    TrustPackageRollback {
        domain: String,
        current_sequence: u64,
        attempted_sequence: u64,
    },

    #[error("Trust package conflict: {0}")]
    TrustPackageConflict(String),

    #[error("Trust package signer change is not authorized for domain {0}")]
    TrustPackageSignerChange(String),

    #[error("Storage not initialized")]
    NotInitialized,
}

impl serde::Serialize for StorageError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
