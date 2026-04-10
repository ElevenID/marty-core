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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_variants() {
        let err = Error::SessionEstablishment("key mismatch".into());
        assert_eq!(err.to_string(), "Session establishment failed: key mismatch");

        let err = Error::InvalidState("wrong state".into());
        assert_eq!(err.to_string(), "Invalid session state: wrong state");

        let err = Error::Timeout;
        assert_eq!(err.to_string(), "Session timeout");

        let err = Error::Encryption("bad key".into());
        assert_eq!(err.to_string(), "Encryption error: bad key");

        let err = Error::Decryption("corrupt".into());
        assert_eq!(err.to_string(), "Decryption error: corrupt");

        let err = Error::Verification("cert expired".into());
        assert_eq!(err.to_string(), "Verification error: cert expired");

        let err = Error::Transport("BLE failed".into());
        assert_eq!(err.to_string(), "Transport error: BLE failed");

        let err = Error::TransportNotSupported;
        assert_eq!(err.to_string(), "Transport not supported");

        let err = Error::CredentialNotFound;
        assert_eq!(err.to_string(), "Credential not found");

        let err = Error::ConsentDenied;
        assert_eq!(err.to_string(), "Consent denied");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err: Error = io_err.into();
        assert!(err.to_string().contains("file missing"));
    }

    #[test]
    fn test_error_is_debug() {
        // Ensure Debug is implemented
        let err = Error::Other("test".into());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Other"));
    }
}
