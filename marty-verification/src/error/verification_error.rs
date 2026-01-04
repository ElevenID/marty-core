//! The main VerificationError enum and core implementations.
//!
//! This module contains the main error type used throughout the library.

use thiserror::Error;
use tracing_error::SpanTrace;

use super::types::{CapturedBacktrace, ErrorCategory, ErrorContext, ErrorReport, ErrorSeverity};

/// Unified error type for all verification operations.
#[derive(Error, Debug)]
pub enum VerificationError {
    // =========================================================================
    // X5Chain Errors
    // =========================================================================
    /// X5Chain is missing from the credential.
    #[error("[{code}] Certificate chain (x5chain) is missing from credential")]
    X5ChainMissing {
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        code: &'static str,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Failed to parse X5Chain.
    #[error("[{code}] Failed to parse certificate chain: {reason}")]
    X5ChainParseError {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// X5Chain is empty.
    #[error("[{code}] Certificate chain contains no certificates")]
    X5ChainEmpty {
        code: &'static str,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// X5Chain has invalid structure.
    #[error("[{code}] Certificate chain has invalid structure: {reason}")]
    X5ChainInvalid {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Trust Anchor Errors
    // =========================================================================
    /// No matching trust anchor found.
    #[error("[{code}] No valid trust anchor found for certificate chain. {details}")]
    NoTrustAnchor {
        details: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Failed to load trust anchor.
    #[error("[{code}] Failed to load trust anchor: {reason}")]
    TrustAnchorLoadError {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Trust anchor registry is empty.
    #[error("[{code}] Trust anchor registry contains no certificates. Load IACAs or CSCAs before verification.")]
    EmptyRegistry {
        code: &'static str,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Multiple trust anchors match (ambiguous).
    #[error("[{code}] Multiple trust anchors match certificate chain: {matches}")]
    AmbiguousTrustAnchor {
        matches: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Trust anchor is invalid or corrupted.
    #[error("[{code}] Trust anchor is invalid: {reason}")]
    InvalidTrustAnchor {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Certificate Validation Errors
    // =========================================================================
    /// Certificate has expired.
    #[error("[{code}] Certificate has expired: {subject} (expired at {expiry})")]
    CertificateExpired {
        subject: String,
        expiry: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Certificate is not yet valid.
    #[error("[{code}] Certificate is not yet valid: {subject} (valid from {valid_from})")]
    CertificateNotYetValid {
        subject: String,
        valid_from: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Certificate signature is invalid.
    #[error("[{code}] Certificate signature verification failed for {subject}: {reason}")]
    InvalidSignature {
        subject: String,
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Required certificate extension is missing.
    #[error("[{code}] Required extension {oid} missing from certificate {subject}")]
    MissingExtension {
        oid: String,
        subject: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Certificate extension has invalid value.
    #[error("[{code}] Extension {oid} has invalid value in {subject}: {reason}")]
    InvalidExtension {
        oid: String,
        subject: String,
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Certificate key usage doesn't match requirements.
    #[error("[{code}] Key usage mismatch for {subject}: expected {expected}, found {found}")]
    KeyUsageMismatch {
        subject: String,
        expected: String,
        found: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Country/jurisdiction name mismatch.
    #[error("[{code}] Name mismatch: {reason}")]
    NameMismatch {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Certificate chain is incomplete.
    #[error("[{code}] Certificate chain is incomplete: {reason}")]
    IncompleteChain {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Certificate revocation check failed.
    #[error("[{code}] Certificate revocation check failed for {subject}: {reason}")]
    RevocationCheckFailed {
        subject: String,
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // Issuer Authentication Errors
    // =========================================================================
    /// Issuer authentication failed.
    #[error("[{code}] Issuer authentication failed: {reason}")]
    IssuerAuthFailed {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Device authentication failed.
    #[error("[{code}] Device authentication failed: {reason}")]
    DeviceAuthFailed {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// COSE signature verification failed.
    #[error("[{code}] COSE signature verification failed: {reason}")]
    CoseSignatureFailed {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // PKD Client Errors
    // =========================================================================
    /// PKD fetch failed.
    #[error("[{code}] Failed to fetch from PKD ({endpoint}): {reason}")]
    PkdFetchError {
        endpoint: String,
        reason: String,
        code: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// PKD authentication failed.
    #[error("[{code}] PKD authentication failed: {reason}")]
    PkdAuthError {
        reason: String,
        code: &'static str,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// PKD response is invalid.
    #[error("[{code}] Invalid PKD response: {reason}")]
    PkdResponseInvalid {
        reason: String,
        code: &'static str,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    // =========================================================================
    // General Errors
    // =========================================================================
    /// DER encoding/decoding error.
    #[error("[{code}] DER encoding/decoding error: {reason}")]
    DerError {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// PEM encoding/decoding error.
    #[error("[{code}] PEM encoding/decoding error: {reason}")]
    PemError {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// CBOR encoding/decoding error.
    #[error("[{code}] CBOR encoding/decoding error: {reason}")]
    CborError {
        reason: String,
        code: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Open Badges error.
    #[error("[{code}] Open Badges error: {reason}")]
    OpenBadgesError {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Digital Travel Credential error.
    #[error("[{code}] DTC error: {reason}")]
    DtcError {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// I/O error.
    #[error("[{code}] I/O error: {reason}")]
    IoError {
        reason: String,
        code: &'static str,
        context: ErrorContext,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Configuration error.
    #[error("[{code}] Configuration error: {reason}")]
    ConfigError {
        reason: String,
        code: &'static str,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },

    /// Internal error.
    #[error("[{code}] Internal error: {reason}")]
    Internal {
        reason: String,
        code: &'static str,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
        bt: CapturedBacktrace,
        span_trace: SpanTrace,
    },
}

impl VerificationError {
    /// Get the error code for this error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::X5ChainMissing { code, .. } => code,
            Self::X5ChainParseError { code, .. } => code,
            Self::X5ChainEmpty { code, .. } => code,
            Self::X5ChainInvalid { code, .. } => code,
            Self::NoTrustAnchor { code, .. } => code,
            Self::TrustAnchorLoadError { code, .. } => code,
            Self::EmptyRegistry { code, .. } => code,
            Self::AmbiguousTrustAnchor { code, .. } => code,
            Self::InvalidTrustAnchor { code, .. } => code,
            Self::CertificateExpired { code, .. } => code,
            Self::CertificateNotYetValid { code, .. } => code,
            Self::InvalidSignature { code, .. } => code,
            Self::MissingExtension { code, .. } => code,
            Self::InvalidExtension { code, .. } => code,
            Self::KeyUsageMismatch { code, .. } => code,
            Self::NameMismatch { code, .. } => code,
            Self::IncompleteChain { code, .. } => code,
            Self::RevocationCheckFailed { code, .. } => code,
            Self::IssuerAuthFailed { code, .. } => code,
            Self::DeviceAuthFailed { code, .. } => code,
            Self::CoseSignatureFailed { code, .. } => code,
            Self::PkdFetchError { code, .. } => code,
            Self::PkdAuthError { code, .. } => code,
            Self::PkdResponseInvalid { code, .. } => code,
            Self::DerError { code, .. } => code,
            Self::PemError { code, .. } => code,
            Self::CborError { code, .. } => code,
            Self::OpenBadgesError { code, .. } => code,
            Self::DtcError { code, .. } => code,
            Self::IoError { code, .. } => code,
            Self::ConfigError { code, .. } => code,
            Self::Internal { code, .. } => code,
        }
    }

    /// Get the error category.
    pub fn category(&self) -> ErrorCategory {
        match self {
            Self::X5ChainMissing { .. }
            | Self::X5ChainParseError { .. }
            | Self::X5ChainEmpty { .. }
            | Self::X5ChainInvalid { .. } => ErrorCategory::CertificateChain,

            Self::NoTrustAnchor { .. }
            | Self::TrustAnchorLoadError { .. }
            | Self::EmptyRegistry { .. }
            | Self::AmbiguousTrustAnchor { .. }
            | Self::InvalidTrustAnchor { .. } => ErrorCategory::TrustAnchor,

            Self::CertificateExpired { .. }
            | Self::CertificateNotYetValid { .. }
            | Self::InvalidSignature { .. }
            | Self::MissingExtension { .. }
            | Self::InvalidExtension { .. }
            | Self::KeyUsageMismatch { .. }
            | Self::NameMismatch { .. }
            | Self::IncompleteChain { .. }
            | Self::RevocationCheckFailed { .. } => ErrorCategory::CertificateValidation,

            Self::IssuerAuthFailed { .. }
            | Self::DeviceAuthFailed { .. }
            | Self::CoseSignatureFailed { .. } => ErrorCategory::Authentication,

            Self::PkdFetchError { .. }
            | Self::PkdAuthError { .. }
            | Self::PkdResponseInvalid { .. } => ErrorCategory::ExternalService,

            Self::DerError { .. } | Self::PemError { .. } | Self::CborError { .. } => {
                ErrorCategory::Encoding
            }

            Self::OpenBadgesError { .. } => ErrorCategory::OpenBadges,
            Self::DtcError { .. } => ErrorCategory::Dtc,

            Self::IoError { .. } => ErrorCategory::Io,

            Self::ConfigError { .. } | Self::Internal { .. } => ErrorCategory::Internal,
        }
    }

    /// Get the error severity.
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            // Critical - cannot proceed at all
            Self::Internal { .. } => ErrorSeverity::Critical,

            // Errors - operation failed
            _ => ErrorSeverity::Error,
        }
    }

    /// Get a structured representation for logging/serialization.
    pub fn to_structured(&self) -> ErrorReport {
        use std::error::Error;
        ErrorReport {
            code: self.code().to_string(),
            category: self.category().to_string(),
            severity: self.severity().to_string(),
            message: self.to_string(),
            source: self.source().map(|e| e.to_string()),
        }
    }

    /// Get the backtrace for this error (if captured).
    pub fn backtrace(&self) -> &CapturedBacktrace {
        match self {
            Self::X5ChainMissing { bt, .. } => bt,
            Self::X5ChainParseError { bt, .. } => bt,
            Self::X5ChainEmpty { bt, .. } => bt,
            Self::X5ChainInvalid { bt, .. } => bt,
            Self::NoTrustAnchor { bt, .. } => bt,
            Self::TrustAnchorLoadError { bt, .. } => bt,
            Self::EmptyRegistry { bt, .. } => bt,
            Self::AmbiguousTrustAnchor { bt, .. } => bt,
            Self::InvalidTrustAnchor { bt, .. } => bt,
            Self::CertificateExpired { bt, .. } => bt,
            Self::CertificateNotYetValid { bt, .. } => bt,
            Self::InvalidSignature { bt, .. } => bt,
            Self::MissingExtension { bt, .. } => bt,
            Self::InvalidExtension { bt, .. } => bt,
            Self::KeyUsageMismatch { bt, .. } => bt,
            Self::NameMismatch { bt, .. } => bt,
            Self::IncompleteChain { bt, .. } => bt,
            Self::RevocationCheckFailed { bt, .. } => bt,
            Self::IssuerAuthFailed { bt, .. } => bt,
            Self::DeviceAuthFailed { bt, .. } => bt,
            Self::CoseSignatureFailed { bt, .. } => bt,
            Self::PkdFetchError { bt, .. } => bt,
            Self::PkdAuthError { bt, .. } => bt,
            Self::PkdResponseInvalid { bt, .. } => bt,
            Self::DerError { bt, .. } => bt,
            Self::PemError { bt, .. } => bt,
            Self::CborError { bt, .. } => bt,
            Self::OpenBadgesError { bt, .. } => bt,
            Self::DtcError { bt, .. } => bt,
            Self::IoError { bt, .. } => bt,
            Self::ConfigError { bt, .. } => bt,
            Self::Internal { bt, .. } => bt,
        }
    }

    /// Get the span trace for this error (if captured).
    pub fn span_trace(&self) -> &SpanTrace {
        match self {
            Self::X5ChainMissing { span_trace, .. } => span_trace,
            Self::X5ChainParseError { span_trace, .. } => span_trace,
            Self::X5ChainEmpty { span_trace, .. } => span_trace,
            Self::X5ChainInvalid { span_trace, .. } => span_trace,
            Self::NoTrustAnchor { span_trace, .. } => span_trace,
            Self::TrustAnchorLoadError { span_trace, .. } => span_trace,
            Self::EmptyRegistry { span_trace, .. } => span_trace,
            Self::AmbiguousTrustAnchor { span_trace, .. } => span_trace,
            Self::InvalidTrustAnchor { span_trace, .. } => span_trace,
            Self::CertificateExpired { span_trace, .. } => span_trace,
            Self::CertificateNotYetValid { span_trace, .. } => span_trace,
            Self::InvalidSignature { span_trace, .. } => span_trace,
            Self::MissingExtension { span_trace, .. } => span_trace,
            Self::InvalidExtension { span_trace, .. } => span_trace,
            Self::KeyUsageMismatch { span_trace, .. } => span_trace,
            Self::NameMismatch { span_trace, .. } => span_trace,
            Self::IncompleteChain { span_trace, .. } => span_trace,
            Self::RevocationCheckFailed { span_trace, .. } => span_trace,
            Self::IssuerAuthFailed { span_trace, .. } => span_trace,
            Self::DeviceAuthFailed { span_trace, .. } => span_trace,
            Self::CoseSignatureFailed { span_trace, .. } => span_trace,
            Self::PkdFetchError { span_trace, .. } => span_trace,
            Self::PkdAuthError { span_trace, .. } => span_trace,
            Self::PkdResponseInvalid { span_trace, .. } => span_trace,
            Self::DerError { span_trace, .. } => span_trace,
            Self::PemError { span_trace, .. } => span_trace,
            Self::CborError { span_trace, .. } => span_trace,
            Self::OpenBadgesError { span_trace, .. } => span_trace,
            Self::DtcError { span_trace, .. } => span_trace,
            Self::IoError { span_trace, .. } => span_trace,
            Self::ConfigError { span_trace, .. } => span_trace,
            Self::Internal { span_trace, .. } => span_trace,
        }
    }

    /// Get a full debug report including backtrace and span trace.
    ///
    /// This is useful for developer debugging - it includes the full backtrace
    /// (when RUST_BACKTRACE=1 or RUST_BACKTRACE=full) and span trace context.
    pub fn debug_report(&self) -> String {
        let mut report = format!("Error: {}\n", self);
        report.push_str(&format!("Code: {}\n", self.code()));
        report.push_str(&format!("Category: {}\n", self.category()));
        report.push_str(&format!("Severity: {}\n", self.severity()));

        // Include source error chain
        if let Some(source) = std::error::Error::source(self) {
            report.push_str("\nCaused by:\n");
            let mut current: Option<&dyn std::error::Error> = Some(source);
            let mut depth = 0;
            while let Some(err) = current {
                report.push_str(&format!("  {}: {}\n", depth, err));
                current = err.source();
                depth += 1;
            }
        }

        // Include span trace
        let span_trace = self.span_trace();
        if span_trace.status() == tracing_error::SpanTraceStatus::CAPTURED {
            report.push_str("\nSpan trace:\n");
            report.push_str(&format!("{}", span_trace));
        }

        // Include backtrace if captured
        let backtrace = self.backtrace();
        if backtrace.status() == std::backtrace::BacktraceStatus::Captured {
            report.push_str("\nBacktrace:\n");
            report.push_str(&format!("{}", backtrace));
        }

        report
    }
}
