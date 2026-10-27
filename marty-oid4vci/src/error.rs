//! Unified error types for the OID4VCI engine.

use std::fmt;

/// Result type alias for OID4VCI operations.
pub type Oid4vciResult<T> = Result<T, Oid4vciError>;

/// Error bodies are untrusted. Keep only these public Flow identifiers, never
/// arbitrary descriptions, credential material, URLs or provider messages.
pub(crate) const MAX_REQUEST_OBJECT_ERROR_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RequestObjectEndpointError {
    http_status: u16,
    #[serde(rename = "error", skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'static str>,
}

impl RequestObjectEndpointError {
    pub fn from_public_response(http_status: u16, body: &[u8]) -> Self {
        #[derive(serde::Deserialize)]
        struct Envelope {
            error: Option<String>,
            detail: Option<String>,
            error_description: Option<String>,
        }
        let mut result = Self {
            http_status,
            code: None,
            detail: None,
        };
        if body.len() > MAX_REQUEST_OBJECT_ERROR_BYTES {
            return result;
        }
        let Ok(envelope) = serde_json::from_slice::<Envelope>(body) else {
            return result;
        };
        // Deployed Flow93b78d14 http_verification/http_read public error codes.
        result.code = [
            "verification_request_invalid",
            "verification_request_method_not_allowed",
            "invalid_stored_flow_state",
            "flow_reference_invalid",
            "flow_authorization_failed",
        ]
        .into_iter()
        .find(|code| envelope.error.as_deref() == Some(*code));
        if result.code.is_none() {
            return result;
        }
        let detail = match (
            envelope.detail.as_deref(),
            envelope.error_description.as_deref(),
        ) {
            (Some(a), Some(b)) if a != b => None,
            (Some(a), _) | (_, Some(a)) => Some(a),
            _ => None,
        };
        if let Some(detail) = detail {
            // Dynamic suffixes after ':' can contain provider/tenant material.
            // Return only an exact known identifier, never any suffix bytes.
            let identifier = detail.split_once(':').map_or(detail, |(prefix, _)| prefix);
            result.detail = [
                "FLOW.VERIFICATION_REQUEST_INVALID_STATE",
                "FLOW.VERIFICATION_REQUEST_UNSIGNED_TRANSPORT",
                "FLOW.VERIFICATION_REQUEST_METHOD_NOT_ALLOWED",
                "FLOW.VERIFICATION_REQUEST_WALLET_NONCE_REQUIRED",
                "FLOW.VERIFICATION_REQUEST_INVALID_CONTEXT",
                "FLOW.REQUEST_OBJECT_INVALID_INSTANCE",
                "FLOW.REQUEST_OBJECT_UNSUPPORTED_PROFILE",
                "FLOW.REQUEST_OBJECT_SERIALIZATION",
                "FLOW.REQUEST_OBJECT_INVALID_CLOCK",
                "FLOW.REQUEST_OBJECT_TOO_LARGE",
                "FLOW.REQUEST_OBJECT_INVALID_IDENTITY",
                "FLOW.PRESENTATION_REQUEST_INVALID_POLICY",
                "FLOW.PRESENTATION_REQUEST_POLICY_NOT_VISIBLE",
                "FLOW.PRESENTATION_REQUEST_POLICY_INACTIVE",
                "FLOW.PRESENTATION_REQUEST_INVALID_TEMPLATE",
                "FLOW.PRESENTATION_REQUEST_TEMPLATE_NOT_VISIBLE",
                "FLOW.PRESENTATION_REQUEST_TEMPLATE_INACTIVE",
                "FLOW.PRESENTATION_REQUEST_NATIVE",
                "FLOW.PROVIDER_NOT_FOUND",
                "FLOW.PROVIDER_CONFLICT",
                "FLOW.PROVIDER_REJECTED",
                "FLOW.PROVIDER_INVALID_RESPONSE",
                "FLOW.PROVIDER_UNAVAILABLE",
                "FLOW.PROVIDERS_MISSING",
            ]
            .into_iter()
            .find(|known| *known == identifier);
        }
        result
    }

    pub fn http_status(&self) -> u16 {
        self.http_status
    }
    pub fn code(&self) -> Option<&'static str> {
        self.code
    }
    pub fn detail(&self) -> Option<&'static str> {
        self.detail
    }
}

impl fmt::Display for RequestObjectEndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HTTP {}", self.http_status)?;
        if let Some(code) = self.code {
            write!(f, " ({code})")?;
        }
        if let Some(detail) = self.detail {
            write!(f, ": {detail}")?;
        }
        Ok(())
    }
}

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

    /// Bounded, allowlisted public request-object endpoint failure.
    #[error("Request object endpoint returned {0}")]
    RequestObjectRejected(RequestObjectEndpointError),

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

    #[test]
    fn request_object_diagnostics_preserve_only_known_public_identifiers() {
        let secret = uuid::Uuid::new_v4().to_string();
        let body = serde_json::json!({"error":"verification_request_invalid",
            "detail":format!("FLOW.REQUEST_OBJECT_INVALID_IDENTITY: {secret}"),
            "access_token":secret, "request":"untrusted request material"});
        let diagnostic =
            RequestObjectEndpointError::from_public_response(400, body.to_string().as_bytes());
        assert_eq!(diagnostic.http_status(), 400);
        assert_eq!(diagnostic.code(), Some("verification_request_invalid"));
        assert_eq!(
            diagnostic.detail(),
            Some("FLOW.REQUEST_OBJECT_INVALID_IDENTITY")
        );
        let public = serde_json::to_string(&diagnostic).unwrap();
        assert!(!public.contains(&secret));
        assert!(!format!("{diagnostic:?} {diagnostic}").contains(&secret));
        assert_eq!(
            serde_json::to_value(&diagnostic).unwrap(),
            serde_json::json!({
            "http_status":400,"error":"verification_request_invalid",
            "detail":"FLOW.REQUEST_OBJECT_INVALID_IDENTITY"})
        );
    }

    #[test]
    fn malformed_oversized_or_unknown_request_errors_do_not_echo_server_material() {
        let secret = uuid::Uuid::new_v4().to_string();
        for body in [
            format!("<html>{secret}</html>"),
            serde_json::json!({"error":secret,"detail":"FLOW.REQUEST_OBJECT_TOO_LARGE"})
                .to_string(),
            serde_json::json!({"error":"verification_request_invalid","detail":{"private":secret}})
                .to_string(),
            r#"{"error":"verification_request_invalid","error":"flow_reference_invalid"}"#
                .to_owned(),
            "x".repeat(MAX_REQUEST_OBJECT_ERROR_BYTES + 1),
        ] {
            let diagnostic = RequestObjectEndpointError::from_public_response(400, body.as_bytes());
            assert_eq!(
                serde_json::to_value(diagnostic).unwrap(),
                serde_json::json!({"http_status":400})
            );
        }
        for body in [
            serde_json::json!({"error":"verification_request_invalid","detail":format!("https://issuer.invalid/?token={secret}")}),
            serde_json::json!({"error":"verification_request_invalid","detail":"FLOW.REQUEST_OBJECT_TOO_LARGE",
                "error_description":"FLOW.REQUEST_OBJECT_INVALID_CLOCK"}),
        ] {
            let diagnostic =
                RequestObjectEndpointError::from_public_response(400, body.to_string().as_bytes());
            assert_eq!(diagnostic.code(), Some("verification_request_invalid"));
            assert_eq!(diagnostic.detail(), None);
            assert!(!format!("{diagnostic:?} {diagnostic}").contains(&secret));
        }
    }

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
