//! Offline X.509 certificate-chain verification, shared by standalone
//! consumers and the full Marty verification crate.

pub mod chain;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    Pem,
    Der,
    Internal,
}

#[derive(Debug)]
pub struct VerificationError {
    pub kind: ErrorKind,
    pub reason: String,
}

impl VerificationError {
    pub fn pem_error(reason: impl Into<String>) -> Box<Self> {
        Box::new(Self {
            kind: ErrorKind::Pem,
            reason: reason.into(),
        })
    }

    pub fn der_error(reason: impl Into<String>) -> Box<Self> {
        Box::new(Self {
            kind: ErrorKind::Der,
            reason: reason.into(),
        })
    }

    pub fn internal(reason: impl Into<String>) -> Box<Self> {
        Box::new(Self {
            kind: ErrorKind::Internal,
            reason: reason.into(),
        })
    }
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(f)
    }
}

impl std::error::Error for VerificationError {}

impl From<marty_crypto::CryptoError> for Box<VerificationError> {
    fn from(error: marty_crypto::CryptoError) -> Self {
        VerificationError::internal(error.to_string())
    }
}

pub type VerificationResult<T> = Result<T, Box<VerificationError>>;
