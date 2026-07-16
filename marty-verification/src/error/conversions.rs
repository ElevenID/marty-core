//! Type conversions for VerificationError.
//!
//! This module contains From implementations for converting other error types
//! into VerificationError and Box<VerificationError>.

use tracing_error::SpanTrace;

use super::codes;
use super::types::{CapturedBacktrace, ErrorContext};
use super::verification_error::VerificationError;

// =============================================================================
// From implementations for VerificationError (unboxed)
// =============================================================================

impl From<std::io::Error> for VerificationError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError {
            reason: err.to_string(),
            code: codes::IO_ERROR,
            context: ErrorContext::default(),
            source: Some(Box::new(err)),
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        }
    }
}

impl From<der::Error> for VerificationError {
    fn from(err: der::Error) -> Self {
        Self::DerError {
            reason: err.to_string(),
            code: codes::DER_ERROR,
            context: ErrorContext::default(),
            source: Some(Box::new(err)),
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        }
    }
}

impl From<anyhow::Error> for VerificationError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal {
            reason: format!("{:#}", err), // Use alternate format for full chain
            code: codes::INTERNAL_ERROR,
            source: None, // anyhow errors don't implement Send+Sync properly for Box<dyn Error>
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        }
    }
}

// =============================================================================
// From implementations for Box<VerificationError>
//
// These are needed for the ? operator to work with Result<_, Box<VerificationError>>
// =============================================================================

impl From<std::io::Error> for Box<VerificationError> {
    fn from(err: std::io::Error) -> Self {
        Box::new(VerificationError::IoError {
            reason: err.to_string(),
            code: codes::IO_ERROR,
            context: ErrorContext::default(),
            source: Some(Box::new(err)),
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        })
    }
}

impl From<der::Error> for Box<VerificationError> {
    fn from(err: der::Error) -> Self {
        Box::new(VerificationError::DerError {
            reason: err.to_string(),
            code: codes::DER_ERROR,
            context: ErrorContext::default(),
            source: Some(Box::new(err)),
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        })
    }
}

impl From<anyhow::Error> for Box<VerificationError> {
    fn from(err: anyhow::Error) -> Self {
        Box::new(VerificationError::Internal {
            reason: format!("{:#}", err),
            code: codes::INTERNAL_ERROR,
            source: None,
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        })
    }
}

#[cfg(feature = "python")]
impl From<VerificationError> for pyo3::PyErr {
    fn from(err: VerificationError) -> Self {
        use super::types::ErrorCategory;
        use pyo3::exceptions::*;

        // Build message with error info
        let mut message = format!("{} - {}", err.code(), err);

        // Include span trace for debugging if captured
        let span_trace = err.span_trace();
        if span_trace.status() == tracing_error::SpanTraceStatus::CAPTURED {
            message.push_str("\n\nSpan trace:\n");
            message.push_str(&format!("{}", span_trace));
        }

        // Map to appropriate Python exception type based on category
        match err.category() {
            ErrorCategory::CertificateChain => PyValueError::new_err(message),
            ErrorCategory::TrustAnchor => PyValueError::new_err(message),
            ErrorCategory::CertificateValidation => PyValueError::new_err(message),
            ErrorCategory::Authentication => PyPermissionError::new_err(message),
            ErrorCategory::ExternalService => PyConnectionError::new_err(message),
            ErrorCategory::Encoding => PyValueError::new_err(message),
            ErrorCategory::OpenBadges => PyValueError::new_err(message),
            ErrorCategory::Dtc => PyValueError::new_err(message),
            ErrorCategory::VdsNc => PyValueError::new_err(message),
            ErrorCategory::Io => PyIOError::new_err(message),
            ErrorCategory::Internal => PyRuntimeError::new_err(message),
        }
    }
}

#[cfg(feature = "python")]
impl From<Box<VerificationError>> for pyo3::PyErr {
    fn from(err: Box<VerificationError>) -> Self {
        (*err).into()
    }
}

// =============================================================================
// From implementations for marty_crypto::CryptoError
// =============================================================================

impl From<marty_crypto::CryptoError> for VerificationError {
    fn from(err: marty_crypto::CryptoError) -> Self {
        Self::Internal {
            reason: err.to_string(),
            code: codes::INTERNAL_ERROR,
            source: None,
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        }
    }
}

impl From<marty_crypto::CryptoError> for Box<VerificationError> {
    fn from(err: marty_crypto::CryptoError) -> Self {
        Box::new(VerificationError::Internal {
            reason: err.to_string(),
            code: codes::INTERNAL_ERROR,
            source: None,
            bt: CapturedBacktrace::capture(),
            span_trace: SpanTrace::capture(),
        })
    }
}
