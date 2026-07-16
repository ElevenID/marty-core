//! Unified error types for the OID4VCI engine.

use std::fmt;

/// Result type alias for OID4VCI operations.
pub type Oid4vciResult<T> = Result<T, Oid4vciError>;

/// Errors that can occur during OID4VCI protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum Oid4vciError {
    /// Invalid credential offer configuration.
    #[error("Invalid offer: {0}")]
    InvalidOffer(String),

    /// Pre-authorized code is invalid, expired, or already redeemed.
    #[error("Invalid pre-authorized code: {0}")]
    InvalidPreAuthCode(String),

    /// Access token is invalid or expired.
    #[error("Invalid access token: {0}")]
    InvalidAccessToken(String),

    /// Proof of possession verification failed.
    #[error("Proof verification failed: {0}")]
    ProofVerificationFailed(String),

    /// The c_nonce provided in the proof does not match.
    #[error("Invalid c_nonce: expected {expected}, got {got}")]
    InvalidCNonce { expected: String, got: String },

    /// Unsupported credential format requested.
    #[error("Unsupported credential format: {0}")]
    UnsupportedFormat(String),

    /// Credential signing failed.
    #[error("Signing error: {0}")]
    SigningError(String),

    /// Invalid JWK or key material.
    #[error("Key error: {0}")]
    KeyError(String),

    /// JWT parsing or validation error.
    #[error("JWT error: {0}")]
    JwtError(String),

    /// mDoc/CBOR encoding error.
    #[error("mDoc error: {0}")]
    MdocError(String),

    /// SD-JWT construction error.
    #[error("SD-JWT error: {0}")]
    SdJwtError(String),

    /// Metadata generation error.
    #[error("Metadata error: {0}")]
    MetadataError(String),

    /// Internal serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid URL.
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Invalid request (wallet-side: malformed input, bad HTTP response, etc.).
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl From<serde_json::Error> for Oid4vciError {
    fn from(e: serde_json::Error) -> Self {
        Oid4vciError::SerializationError(e.to_string())
    }
}

impl From<url::ParseError> for Oid4vciError {
    fn from(e: url::ParseError) -> Self {
        Oid4vciError::InvalidUrl(e.to_string())
    }
}

impl From<base64::DecodeError> for Oid4vciError {
    fn from(e: base64::DecodeError) -> Self {
        Oid4vciError::JwtError(format!("Base64 decode error: {}", e))
    }
}

/// OID4VCI-specific HTTP error codes per spec.
/// These map to the `error` field in token/credential error responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Oid4vciErrorCode {
    /// The Authorization Server does not support the requested grant type.
    UnsupportedGrantType,
    /// The pre-authorized code is invalid/expired.
    InvalidGrant,
    /// The access token is invalid.
    InvalidToken,
    /// The credential request is invalid.
    InvalidCredentialRequest,
    /// The requested credential type is not supported.
    UnsupportedCredentialType,
    /// The requested credential format is not supported.
    UnsupportedCredentialFormat,
    /// The proof provided is invalid.
    InvalidProof,
    /// The c_nonce has expired.
    CNonceExpired,
}

impl fmt::Display for Oid4vciErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedGrantType => write!(f, "unsupported_grant_type"),
            Self::InvalidGrant => write!(f, "invalid_grant"),
            Self::InvalidToken => write!(f, "invalid_token"),
            Self::InvalidCredentialRequest => write!(f, "invalid_credential_request"),
            Self::UnsupportedCredentialType => write!(f, "unsupported_credential_type"),
            Self::UnsupportedCredentialFormat => write!(f, "unsupported_credential_format"),
            Self::InvalidProof => write!(f, "invalid_proof"),
            Self::CNonceExpired => write!(f, "c_nonce_expired"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Oid4vciError Display
    // ====================================================================

    #[test]
    fn test_error_display_messages() {
        let err = Oid4vciError::InvalidOffer("missing issuer".into());
        assert_eq!(err.to_string(), "Invalid offer: missing issuer");

        let err = Oid4vciError::ProofVerificationFailed("bad sig".into());
        assert_eq!(err.to_string(), "Proof verification failed: bad sig");

        let err = Oid4vciError::InvalidCNonce {
            expected: "abc".into(),
            got: "xyz".into(),
        };
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("xyz"));
    }

    #[test]
    fn test_error_from_serde_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err: Oid4vciError = json_err.into();
        match err {
            Oid4vciError::SerializationError(msg) => assert!(!msg.is_empty()),
            _ => panic!("expected SerializationError"),
        }
    }

    #[test]
    fn test_error_from_url_parse() {
        let url_err = url::Url::parse("://bad").unwrap_err();
        let err: Oid4vciError = url_err.into();
        match err {
            Oid4vciError::InvalidUrl(msg) => assert!(!msg.is_empty()),
            _ => panic!("expected InvalidUrl"),
        }
    }

    #[test]
    fn test_error_from_base64_decode() {
        use base64::Engine;
        let b64_err = base64::engine::general_purpose::STANDARD
            .decode("!!!invalid!!!")
            .unwrap_err();
        let err: Oid4vciError = b64_err.into();
        match err {
            Oid4vciError::JwtError(msg) => assert!(msg.contains("Base64")),
            _ => panic!("expected JwtError"),
        }
    }

    // ====================================================================
    // Oid4vciErrorCode Display
    // ====================================================================

    #[test]
    fn test_error_code_display() {
        assert_eq!(
            Oid4vciErrorCode::UnsupportedGrantType.to_string(),
            "unsupported_grant_type"
        );
        assert_eq!(Oid4vciErrorCode::InvalidGrant.to_string(), "invalid_grant");
        assert_eq!(Oid4vciErrorCode::InvalidToken.to_string(), "invalid_token");
        assert_eq!(
            Oid4vciErrorCode::InvalidCredentialRequest.to_string(),
            "invalid_credential_request"
        );
        assert_eq!(
            Oid4vciErrorCode::UnsupportedCredentialType.to_string(),
            "unsupported_credential_type"
        );
        assert_eq!(
            Oid4vciErrorCode::UnsupportedCredentialFormat.to_string(),
            "unsupported_credential_format"
        );
        assert_eq!(Oid4vciErrorCode::InvalidProof.to_string(), "invalid_proof");
        assert_eq!(
            Oid4vciErrorCode::CNonceExpired.to_string(),
            "c_nonce_expired"
        );
    }

    #[test]
    fn test_error_code_equality() {
        assert_eq!(
            Oid4vciErrorCode::InvalidGrant,
            Oid4vciErrorCode::InvalidGrant
        );
        assert_ne!(
            Oid4vciErrorCode::InvalidGrant,
            Oid4vciErrorCode::InvalidToken
        );
    }
}
