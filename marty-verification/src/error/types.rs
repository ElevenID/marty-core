//! Common types used in error handling.
//!
//! This module contains supporting types for the error system:
//! - `CapturedBacktrace` - Wrapper for backtrace capture
//! - `ErrorSeverity` - Error severity levels
//! - `ErrorCategory` - Error categorization
//! - `ErrorContext` - Additional context for errors
//! - `ErrorReport` - Structured error reports

use std::fmt;

/// Wrapper around std::backtrace::Backtrace to avoid thiserror's unstable feature detection.
///
/// Thiserror 1.x tries to use unstable `error_generic_member_access` when it sees a
/// field named `backtrace` with type `std::backtrace::Backtrace`. This wrapper prevents that.
#[derive(Debug)]
pub struct CapturedBacktrace(std::backtrace::Backtrace);

impl CapturedBacktrace {
    /// Capture a backtrace at the current location.
    pub fn capture() -> Self {
        Self(std::backtrace::Backtrace::capture())
    }

    /// Get the status of this backtrace.
    pub fn status(&self) -> std::backtrace::BacktraceStatus {
        self.0.status()
    }
}

impl fmt::Display for CapturedBacktrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Error severity levels for categorizing issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Critical error - operation cannot proceed
    Critical,
    /// Error - operation failed but system is stable
    Error,
    /// Warning - operation succeeded with concerns
    Warning,
}

impl fmt::Display for ErrorSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSeverity::Critical => write!(f, "CRITICAL"),
            ErrorSeverity::Error => write!(f, "ERROR"),
            ErrorSeverity::Warning => write!(f, "WARNING"),
        }
    }
}

/// Error category for grouping related errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// X5Chain/certificate chain related
    CertificateChain,
    /// Trust anchor related
    TrustAnchor,
    /// Certificate validation related
    CertificateValidation,
    /// Authentication related
    Authentication,
    /// PKD/external service related
    ExternalService,
    /// Encoding/decoding related
    Encoding,
    /// Open Badges related
    OpenBadges,
    /// Digital Travel Credential related
    Dtc,
    /// I/O related
    Io,
    /// Internal/unexpected errors
    Internal,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::CertificateChain => write!(f, "CHAIN"),
            ErrorCategory::TrustAnchor => write!(f, "TRUST"),
            ErrorCategory::CertificateValidation => write!(f, "CERT"),
            ErrorCategory::Authentication => write!(f, "AUTH"),
            ErrorCategory::ExternalService => write!(f, "SERVICE"),
            ErrorCategory::Encoding => write!(f, "ENCODING"),
            ErrorCategory::OpenBadges => write!(f, "OPENBADGES"),
            ErrorCategory::Dtc => write!(f, "DTC"),
            ErrorCategory::Io => write!(f, "IO"),
            ErrorCategory::Internal => write!(f, "INTERNAL"),
        }
    }
}

/// Additional context that can be attached to errors.
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    /// Certificate subject that caused the error
    pub certificate_subject: Option<String>,
    /// Certificate issuer
    pub certificate_issuer: Option<String>,
    /// Certificate serial number
    pub certificate_serial: Option<String>,
    /// Jurisdiction code (e.g., "US-CA")
    pub jurisdiction: Option<String>,
    /// Country code (e.g., "US")
    pub country: Option<String>,
    /// OID that caused the error
    pub oid: Option<String>,
    /// File path if relevant
    pub file_path: Option<String>,
    /// Additional key-value pairs for custom context
    pub extra: Vec<(String, String)>,
}

impl ErrorContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.certificate_subject = Some(subject.into());
        self
    }

    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.certificate_issuer = Some(issuer.into());
        self
    }

    pub fn with_serial(mut self, serial: impl Into<String>) -> Self {
        self.certificate_serial = Some(serial.into());
        self
    }

    pub fn with_jurisdiction(mut self, jurisdiction: impl Into<String>) -> Self {
        self.jurisdiction = Some(jurisdiction.into());
        self
    }

    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    pub fn with_oid(mut self, oid: impl Into<String>) -> Self {
        self.oid = Some(oid.into());
        self
    }

    pub fn with_file_path(mut self, path: impl Into<String>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    pub fn with_extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push((key.into(), value.into()));
        self
    }

    /// Format context as a readable string
    pub fn format(&self) -> Option<String> {
        let mut parts = Vec::new();

        if let Some(ref s) = self.certificate_subject {
            parts.push(format!("subject={}", s));
        }
        if let Some(ref i) = self.certificate_issuer {
            parts.push(format!("issuer={}", i));
        }
        if let Some(ref s) = self.certificate_serial {
            parts.push(format!("serial={}", s));
        }
        if let Some(ref j) = self.jurisdiction {
            parts.push(format!("jurisdiction={}", j));
        }
        if let Some(ref c) = self.country {
            parts.push(format!("country={}", c));
        }
        if let Some(ref o) = self.oid {
            parts.push(format!("oid={}", o));
        }
        if let Some(ref p) = self.file_path {
            parts.push(format!("file={}", p));
        }
        for (k, v) in &self.extra {
            parts.push(format!("{}={}", k, v));
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(", "))
        }
    }
}

/// Structured error report for logging and serialization.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ErrorReport {
    pub code: String,
    pub category: String,
    pub severity: String,
    pub message: String,
    pub source: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_context() {
        let ctx = ErrorContext::new()
            .with_subject("CN=Test")
            .with_jurisdiction("US-CA")
            .with_extra("serial", "123456");

        let formatted = ctx.format().unwrap();
        assert!(formatted.contains("subject=CN=Test"));
        assert!(formatted.contains("jurisdiction=US-CA"));
        assert!(formatted.contains("serial=123456"));
    }

    #[test]
    fn test_error_severity_display() {
        assert_eq!(ErrorSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(ErrorSeverity::Error.to_string(), "ERROR");
        assert_eq!(ErrorSeverity::Warning.to_string(), "WARNING");
    }

    #[test]
    fn test_error_category_display() {
        assert_eq!(ErrorCategory::CertificateChain.to_string(), "CHAIN");
        assert_eq!(ErrorCategory::Dtc.to_string(), "DTC");
        assert_eq!(ErrorCategory::Internal.to_string(), "INTERNAL");
    }
}
