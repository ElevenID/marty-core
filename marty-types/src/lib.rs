//! Shared type definitions and constants for the Marty ecosystem
//!
//! This crate provides centralized type definitions, constants, and error codes
//! used across Marty components. It includes:
//!
//! - ISO 18013-5 mDL namespaces and document types
//! - W3C Verifiable Credentials contexts
//! - Credential format identifiers
//! - Hierarchical error codes
//!
//! ## Features
//!
//! - `python`: Enable PyO3 bindings for Python integration
//!
//! ## Generated Code
//!
//! Most of this crate's content is generated from YAML schemas in the `schema/` directory.
//! To regenerate, run: `python codegen/generate.py`

#[cfg(feature = "python")]
use pyo3::prelude::*;

pub mod generated;
pub mod open_badges;

// Re-export commonly used items
pub use generated::{error_codes, namespaces};

#[cfg(feature = "python")]
#[pymodule]
fn marty_types(m: &Bound<'_, PyModule>) -> PyResult<()> {
    generated::namespaces::register_namespace_module(m)?;
    generated::error_codes::register_error_code_module(m)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // ISO 18013-5 namespace constants
    // ====================================================================

    #[test]
    fn test_mdl_namespace_value() {
        assert_eq!(namespaces::iso18013::namespace::MDL, "org.iso.18013.5.1");
    }

    #[test]
    fn test_aamva_namespace_value() {
        assert_eq!(
            namespaces::iso18013::namespace::AAMVA,
            "org.iso.18013.5.1.aamva"
        );
    }

    #[test]
    fn test_mdl_doc_type() {
        assert_eq!(namespaces::iso18013::doc_type::MDL, "org.iso.18013.5.1.mDL");
    }

    #[test]
    fn test_mid_doc_type() {
        assert_eq!(namespaces::iso18013::doc_type::MID, "org.iso.18013.5.1.mID");
    }

    // ====================================================================
    // ISO 18013-5 data element identifiers
    // ====================================================================

    #[test]
    fn test_standard_element_names() {
        use namespaces::iso18013::element;
        assert_eq!(element::FAMILY_NAME, "family_name");
        assert_eq!(element::GIVEN_NAME, "given_name");
        assert_eq!(element::BIRTH_DATE, "birth_date");
        assert_eq!(element::EXPIRY_DATE, "expiry_date");
        assert_eq!(element::DOCUMENT_NUMBER, "document_number");
        assert_eq!(element::ISSUING_COUNTRY, "issuing_country");
        assert_eq!(element::PORTRAIT, "portrait");
    }

    #[test]
    fn test_age_verification_elements() {
        use namespaces::iso18013::element;
        assert_eq!(element::AGE_OVER_18, "age_over_18");
        assert_eq!(element::AGE_OVER_21, "age_over_21");
        assert_eq!(element::AGE_OVER_25, "age_over_25");
        assert_eq!(element::AGE_IN_YEARS, "age_in_years");
    }

    // ====================================================================
    // Error codes
    // ====================================================================

    #[test]
    fn test_error_code_full_code() {
        let err = error_codes::codes::cred::issuance_failed();
        assert_eq!(err.full_code(), "CRED.ISSUANCE_FAILED");
        assert_eq!(err.category, "CRED");
        assert_eq!(err.code, "ISSUANCE_FAILED");
        assert!(!err.retryable);
    }

    #[test]
    fn test_error_code_retryable_flag() {
        let non_retryable = error_codes::codes::cred::verification_failed();
        assert!(!non_retryable.retryable);

        let retryable = error_codes::codes::cred::revocation_check_failed();
        assert!(retryable.retryable);
    }

    #[test]
    fn test_error_code_severity() {
        use error_codes::ErrorSeverity;

        let err = error_codes::codes::cred::issuance_failed();
        assert_eq!(err.severity, ErrorSeverity::Error);

        let warn = error_codes::codes::cred::revocation_check_failed();
        assert_eq!(warn.severity, ErrorSeverity::Warning);
    }

    #[test]
    fn test_key_error_codes() {
        let err = error_codes::codes::key::not_found();
        assert_eq!(err.full_code(), "KEY.NOT_FOUND");

        let err = error_codes::codes::key::generation_failed();
        assert!(err.retryable);

        let err = error_codes::codes::key::access_denied();
        assert!(!err.retryable);
    }

    #[test]
    fn test_error_code_serialization() {
        let err = error_codes::codes::cred::expired();
        let json = serde_json::to_string(&err).unwrap();
        let back: error_codes::ErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(back.full_code(), "CRED.EXPIRED");
        assert_eq!(back.message, "Credential has expired");
    }

    #[test]
    fn test_error_code_equality() {
        let a = error_codes::codes::cred::expired();
        let b = error_codes::codes::cred::expired();
        assert_eq!(a, b);

        let c = error_codes::codes::cred::parse_error();
        assert_ne!(a, c);
    }
}
