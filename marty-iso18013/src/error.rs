//! Error types for ISO 18013 operations

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Session establishment failed: {0}")]
    SessionEstablishment(String),

    #[error("Invalid session state: {0}")]
    InvalidState(String),

    #[error("Session timeout")]
    Timeout,

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("CBOR encoding error: {0}")]
    CborEncode(#[from] ciborium::ser::Error<std::io::Error>),

    #[error("CBOR decoding error: {0}")]
    CborDecode(#[from] ciborium::de::Error<std::io::Error>),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] marty_crypto::CryptoError),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Transport not supported")]
    TransportNotSupported,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    #[error("QR code generation failed: {0}")]
    QrCode(String),

    #[error("Invalid engagement: {0}")]
    InvalidEngagement(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Credential not found")]
    CredentialNotFound,

    #[error("Consent denied")]
    ConsentDenied,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Other error: {0}")]
    Other(String),
}

#[cfg(feature = "python")]
impl From<Error> for pyo3::PyErr {
    fn from(err: Error) -> Self {
        pyo3::exceptions::PyRuntimeError::new_err(err.to_string())
    }
}
