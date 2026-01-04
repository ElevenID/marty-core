//! Error types for cryptographic operations.

use thiserror::Error;

/// Error type for cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// PEM parsing or encoding error
    #[error("PEM error: {0}")]
    Pem(String),

    /// DER parsing or encoding error
    #[error("DER error: {0}")]
    Der(String),

    /// Invalid key format or length
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureVerification(String),

    /// Signature creation failed
    #[error("Signature creation failed: {0}")]
    SignatureCreation(String),

    /// Unsupported algorithm
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Certificate parsing error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Encryption or decryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// PKCS#12 parsing error
    #[error("PKCS#12 error: {0}")]
    Pkcs12(String),

    /// CRL parsing error
    #[error("CRL error: {0}")]
    Crl(String),

    /// OCSP parsing error
    #[error("OCSP error: {0}")]
    Ocsp(String),

    /// Random number generation error
    #[error("RNG error: {0}")]
    Rng(String),

    /// Encoding error
    #[error("Encoding error: {0}")]
    Encoding(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for cryptographic operations.
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;

// Builder functions for convenient error construction
impl CryptoError {
    pub fn pem(msg: impl Into<String>) -> Self {
        Self::Pem(msg.into())
    }

    pub fn pem_error(msg: impl Into<String>) -> Self {
        Self::Pem(msg.into())
    }

    pub fn der(msg: impl Into<String>) -> Self {
        Self::Der(msg.into())
    }

    pub fn der_error(msg: impl Into<String>) -> Self {
        Self::Der(msg.into())
    }

    pub fn invalid_key(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    pub fn key_error(msg: impl Into<String>) -> Self {
        Self::InvalidKey(msg.into())
    }

    pub fn signature_verification(msg: impl Into<String>) -> Self {
        Self::SignatureVerification(msg.into())
    }

    pub fn invalid_signature(msg: impl Into<String>) -> Self {
        Self::SignatureVerification(msg.into())
    }

    pub fn invalid_signature_with_context(context: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::SignatureVerification(format!("{}: {}", context.into(), msg.into()))
    }

    pub fn signature_error(msg: impl Into<String>) -> Self {
        Self::SignatureCreation(msg.into())
    }

    pub fn signature_creation(msg: impl Into<String>) -> Self {
        Self::SignatureCreation(msg.into())
    }

    pub fn unsupported_algorithm(msg: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm(msg.into())
    }

    pub fn certificate(msg: impl Into<String>) -> Self {
        Self::Certificate(msg.into())
    }

    pub fn encryption(msg: impl Into<String>) -> Self {
        Self::Encryption(msg.into())
    }

    pub fn crypto_error(msg: impl Into<String>) -> Self {
        Self::Encryption(msg.into())
    }

    pub fn key_derivation(msg: impl Into<String>) -> Self {
        Self::KeyDerivation(msg.into())
    }

    pub fn pkcs12(msg: impl Into<String>) -> Self {
        Self::Pkcs12(msg.into())
    }

    pub fn crl(msg: impl Into<String>) -> Self {
        Self::Crl(msg.into())
    }

    pub fn ocsp(msg: impl Into<String>) -> Self {
        Self::Ocsp(msg.into())
    }

    pub fn rng(msg: impl Into<String>) -> Self {
        Self::Rng(msg.into())
    }

    pub fn encoding_error(msg: impl Into<String>) -> Self {
        Self::Encoding(msg.into())
    }

    pub fn parse_error(msg: impl Into<String>) -> Self {
        Self::Encoding(msg.into())
    }

    pub fn network_error(msg: impl Into<String>) -> Self {
        Self::Network(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}
