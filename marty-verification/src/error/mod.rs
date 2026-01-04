//! Error types for trust chain verification.
//!
//! This module provides comprehensive error handling with:
//! - Unique error codes for programmatic handling
//! - Detailed context for debugging
//! - Source error preservation for tracing root causes
//! - Structured error data for logging and analysis
//! - Backtraces for debugging (when RUST_BACKTRACE=1)
//! - Span traces for tracing context (when ErrorLayer is registered)
//!
//! # Module Structure
//!
//! - [`types`] - Common types (CapturedBacktrace, ErrorSeverity, ErrorCategory, ErrorContext, ErrorReport)
//! - [`codes`] - Error code constants
//! - [`verification_error`] - The main VerificationError enum
//! - [`builders`] - Builder functions for creating errors
//! - [`conversions`] - From implementations for error conversion

mod builders;
pub mod codes;
mod conversions;
mod types;
mod verification_error;

// Re-export all public types at the module level for convenience
pub use types::{CapturedBacktrace, ErrorCategory, ErrorContext, ErrorReport, ErrorSeverity};
pub use verification_error::VerificationError;

/// Result type alias for verification operations.
///
/// Uses `Box<VerificationError>` to reduce stack size since the error type
/// contains debugging information (backtraces, span traces, context) that
/// makes individual variants quite large. Boxing the error keeps Result
/// at a fixed small size (typically 16 bytes) regardless of error variant.
pub type VerificationResult<T> = std::result::Result<T, Box<VerificationError>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        let err = VerificationError::x5chain_empty();
        assert_eq!(err.code(), "E103");
        assert_eq!(err.category(), ErrorCategory::CertificateChain);
    }

    #[test]
    fn test_error_display() {
        let err = VerificationError::no_trust_anchor("Checked 5 anchors, none matched");
        let display = err.to_string();
        assert!(display.contains("E201"));
        assert!(display.contains("No valid trust anchor"));
    }

    #[test]
    fn test_error_report() {
        let err = VerificationError::cert_expired("CN=Test", "2024-01-01");
        let report = err.to_structured();

        assert_eq!(report.code, "E301");
        assert_eq!(report.category, "CERT");
        assert!(report.message.contains("expired"));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: VerificationError = io_err.into();

        assert_eq!(err.code(), "E901");
        assert_eq!(err.category(), ErrorCategory::Io);
    }

    #[test]
    fn test_box_conversion() {
        let err = VerificationError::internal("test error");
        // Verify it's already boxed from the builder
        assert_eq!(err.code(), "E999");
    }
}
