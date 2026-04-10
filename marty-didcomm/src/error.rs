use thiserror::Error;

#[derive(Debug, Error)]
pub enum DidcommError {
    #[error("DID resolution failed for {did}: {reason}")]
    ResolutionFailed { did: String, reason: String },

    #[error("Unsupported DID method: {method}")]
    UnsupportedMethod { method: String },

    #[error("No DIDComm service endpoint found in DID document for {did}")]
    NoServiceEndpoint { did: String },

    #[error("No suitable key agreement key found in DID document for {did}")]
    NoKeyAgreementKey { did: String },

    #[error("Envelope packing failed: {0}")]
    PackError(String),

    #[error("Envelope unpacking failed: {0}")]
    UnpackError(String),

    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type DidcommResult<T> = Result<T, DidcommError>;
