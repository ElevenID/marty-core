//! Error code constants for programmatic error handling.
//!
//! These codes are stable and can be used for:
//! - Logging and monitoring
//! - Error tracking systems
//! - Programmatic error handling in calling code
//! - Internationalization of error messages
//!
//! # Error Code Ranges
//!
//! | Range | Category | Description |
//! |-------|----------|-------------|
//! | E1xx | X5Chain | Certificate chain parsing and structure errors |
//! | E2xx | Trust Anchor | Trust anchor loading and matching errors |
//! | E3xx | Certificate | Certificate validation errors (expiry, signature, etc.) |
//! | E4xx | Authentication | Issuer/device authentication errors |
//! | E5xx | PKD | Public Key Directory and external service errors |
//! | E6xx | Encoding | DER, PEM, CBOR encoding/decoding errors |
//! | E7xx | Open Badges | Open Badges verification/issuance errors |
//! | E8xx | DTC | Digital Travel Credential errors |
//! | E9xx | General | I/O, configuration, and internal errors |

//=========================================================================
// X5Chain errors (1xx) - Certificate chain parsing and structure
//=========================================================================

/// E101: Certificate chain (x5chain) is missing from the credential.
pub const X5CHAIN_MISSING: &str = "E101";

/// E102: Failed to parse the certificate chain data.
pub const X5CHAIN_PARSE_ERROR: &str = "E102";

/// E103: Certificate chain contains no certificates.
pub const X5CHAIN_EMPTY: &str = "E103";

/// E104: Certificate chain has invalid structure or format.
pub const X5CHAIN_INVALID: &str = "E104";

//=========================================================================
// Trust anchor errors (2xx) - Trust anchor loading and matching
//=========================================================================

/// E201: No valid trust anchor found for the certificate chain.
pub const TRUST_NO_ANCHOR: &str = "E201";

/// E202: Failed to load trust anchor from file or registry.
pub const TRUST_LOAD_ERROR: &str = "E202";

/// E203: Trust anchor registry is empty - load IACAs or CSCAs first.
pub const TRUST_EMPTY_REGISTRY: &str = "E203";

/// E204: Multiple trust anchors match the certificate chain (ambiguous).
pub const TRUST_AMBIGUOUS: &str = "E204";

/// E205: Trust anchor is invalid or corrupted.
pub const TRUST_INVALID_ANCHOR: &str = "E205";

//=========================================================================
// Certificate validation errors (3xx) - Certificate validation
//=========================================================================

/// E301: Certificate has expired.
pub const CERT_EXPIRED: &str = "E301";

/// E302: Certificate is not yet valid (notBefore date is in the future).
pub const CERT_NOT_YET_VALID: &str = "E302";

/// E303: Certificate signature verification failed.
pub const CERT_INVALID_SIGNATURE: &str = "E303";

/// E304: Required certificate extension is missing.
pub const CERT_MISSING_EXTENSION: &str = "E304";

/// E305: Certificate extension has an invalid value.
pub const CERT_INVALID_EXTENSION: &str = "E305";

/// E306: Certificate key usage does not match requirements.
pub const CERT_KEY_USAGE_MISMATCH: &str = "E306";

/// E307: Certificate name (subject/issuer) mismatch.
pub const CERT_NAME_MISMATCH: &str = "E307";

/// E308: Certificate chain is incomplete (missing intermediate CA).
pub const CERT_INCOMPLETE_CHAIN: &str = "E308";

/// E309: Certificate revocation check failed (CRL or OCSP).
pub const CERT_REVOCATION_FAILED: &str = "E309";

//=========================================================================
// Authentication errors (4xx) - Issuer/device authentication
//=========================================================================

/// E401: Issuer authentication failed (signature verification).
pub const AUTH_ISSUER_FAILED: &str = "E401";

/// E402: Device authentication failed (for mDL).
pub const AUTH_DEVICE_FAILED: &str = "E402";

/// E403: COSE signature verification failed.
pub const AUTH_COSE_FAILED: &str = "E403";

//=========================================================================
// PKD/external service errors (5xx) - External service errors
//=========================================================================

/// E501: Failed to fetch data from PKD (network or server error).
pub const PKD_FETCH_ERROR: &str = "E501";

/// E502: PKD authentication failed (invalid credentials).
pub const PKD_AUTH_ERROR: &str = "E502";

/// E503: PKD response is invalid or malformed.
pub const PKD_RESPONSE_INVALID: &str = "E503";

//=========================================================================
// Encoding errors (6xx) - Data encoding/decoding
//=========================================================================

/// E601: DER encoding/decoding error.
pub const DER_ERROR: &str = "E601";

/// E602: PEM encoding/decoding error.
pub const PEM_ERROR: &str = "E602";

/// E603: CBOR encoding/decoding error.
pub const CBOR_ERROR: &str = "E603";

//=========================================================================
// Open Badges errors (7xx) - Open Badges verification/issuance
//=========================================================================

/// E701: Open Badges payload is invalid or malformed.
pub const OPEN_BADGES_INVALID: &str = "E701";

/// E702: Required Open Badges context is missing or unsupported.
pub const OPEN_BADGES_CONTEXT_MISSING: &str = "E702";

/// E703: Open Badges signature verification failed.
pub const OPEN_BADGES_SIGNATURE_INVALID: &str = "E703";

/// E704: Open Badges proof verification failed.
pub const OPEN_BADGES_PROOF_INVALID: &str = "E704";

/// E705: Open Badges referenced document not found in offline store.
pub const OPEN_BADGES_DOCUMENT_MISSING: &str = "E705";

/// E706: Open Badges unsupported feature or algorithm.
pub const OPEN_BADGES_UNSUPPORTED: &str = "E706";

//=========================================================================
// DTC errors (8xx) - Digital Travel Credential
//=========================================================================

/// E801: DTC payload is invalid or malformed.
pub const DTC_INVALID: &str = "E801";

/// E802: Required DTC field is missing.
pub const DTC_MISSING_FIELD: &str = "E802";

/// E803: DTC uses unsupported algorithm or key type.
pub const DTC_UNSUPPORTED: &str = "E803";

/// E804: DTC signing failed.
pub const DTC_SIGNING_FAILED: &str = "E804";

/// E805: DTC signature verification failed.
pub const DTC_SIGNATURE_INVALID: &str = "E805";

/// E806: DTC trust chain validation failed.
pub const DTC_TRUST_CHAIN_INVALID: &str = "E806";

/// E807: DTC has expired (expiry_date or dtc_valid_until in the past).
pub const DTC_EXPIRED: &str = "E807";

/// E808: DTC is not yet valid (dtc_valid_from is in the future).
pub const DTC_NOT_YET_VALID: &str = "E808";

/// E809: DTC has been revoked.
pub const DTC_REVOKED: &str = "E809";

//=========================================================================
// Open Badges additional errors (7xx continued)
//=========================================================================

/// E707: Open Badges credential has been revoked.
pub const OPEN_BADGES_REVOKED: &str = "E707";

/// E708: Open Badges credential status check failed.
pub const OPEN_BADGES_STATUS_CHECK_FAILED: &str = "E708";

//=========================================================================
// I/O and general errors (9xx) - General errors
//=========================================================================

/// E901: I/O error (file read/write, network, etc.).
pub const IO_ERROR: &str = "E901";

/// E902: Configuration error (invalid settings).
pub const CONFIG_ERROR: &str = "E902";

/// E999: Internal error (unexpected condition).
pub const INTERNAL_ERROR: &str = "E999";

/// Generate a markdown reference table of all error codes.
///
/// This is useful for documentation generation and developer reference.
///
/// # Example
///
/// ```rust
/// use marty_verification::error::codes::error_codes_markdown;
/// let markdown = error_codes_markdown();
/// println!("{}", markdown);
/// ```
pub fn error_codes_markdown() -> String {
    let mut md = String::from("# Marty Verification Error Codes\n\n");
    md.push_str("This document lists all error codes used by the Marty verification library.\n\n");

    md.push_str("## X5Chain Errors (E1xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str(
        "| E101 | `X5CHAIN_MISSING` | Certificate chain (x5chain) is missing from the credential |\n",
    );
    md.push_str("| E102 | `X5CHAIN_PARSE_ERROR` | Failed to parse the certificate chain data |\n");
    md.push_str("| E103 | `X5CHAIN_EMPTY` | Certificate chain contains no certificates |\n");
    md.push_str(
        "| E104 | `X5CHAIN_INVALID` | Certificate chain has invalid structure or format |\n",
    );
    md.push('\n');

    md.push_str("## Trust Anchor Errors (E2xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str(
        "| E201 | `TRUST_NO_ANCHOR` | No valid trust anchor found for the certificate chain |\n",
    );
    md.push_str(
        "| E202 | `TRUST_LOAD_ERROR` | Failed to load trust anchor from file or registry |\n",
    );
    md.push_str("| E203 | `TRUST_EMPTY_REGISTRY` | Trust anchor registry is empty |\n");
    md.push_str(
        "| E204 | `TRUST_AMBIGUOUS` | Multiple trust anchors match the certificate chain |\n",
    );
    md.push_str("| E205 | `TRUST_INVALID_ANCHOR` | Trust anchor is invalid or corrupted |\n");
    md.push('\n');

    md.push_str("## Certificate Validation Errors (E3xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str("| E301 | `CERT_EXPIRED` | Certificate has expired |\n");
    md.push_str("| E302 | `CERT_NOT_YET_VALID` | Certificate is not yet valid |\n");
    md.push_str(
        "| E303 | `CERT_INVALID_SIGNATURE` | Certificate signature verification failed |\n",
    );
    md.push_str(
        "| E304 | `CERT_MISSING_EXTENSION` | Required certificate extension is missing |\n",
    );
    md.push_str(
        "| E305 | `CERT_INVALID_EXTENSION` | Certificate extension has an invalid value |\n",
    );
    md.push_str(
        "| E306 | `CERT_KEY_USAGE_MISMATCH` | Certificate key usage does not match requirements |\n",
    );
    md.push_str("| E307 | `CERT_NAME_MISMATCH` | Certificate name mismatch |\n");
    md.push_str("| E308 | `CERT_INCOMPLETE_CHAIN` | Certificate chain is incomplete |\n");
    md.push_str("| E309 | `CERT_REVOCATION_FAILED` | Certificate revocation check failed |\n");
    md.push('\n');

    md.push_str("## Authentication Errors (E4xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str("| E401 | `AUTH_ISSUER_FAILED` | Issuer authentication failed |\n");
    md.push_str("| E402 | `AUTH_DEVICE_FAILED` | Device authentication failed |\n");
    md.push_str("| E403 | `AUTH_COSE_FAILED` | COSE signature verification failed |\n");
    md.push('\n');

    md.push_str("## PKD/External Service Errors (E5xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str("| E501 | `PKD_FETCH_ERROR` | Failed to fetch data from PKD |\n");
    md.push_str("| E502 | `PKD_AUTH_ERROR` | PKD authentication failed |\n");
    md.push_str("| E503 | `PKD_RESPONSE_INVALID` | PKD response is invalid or malformed |\n");
    md.push('\n');

    md.push_str("## Encoding Errors (E6xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str("| E601 | `DER_ERROR` | DER encoding/decoding error |\n");
    md.push_str("| E602 | `PEM_ERROR` | PEM encoding/decoding error |\n");
    md.push_str("| E603 | `CBOR_ERROR` | CBOR encoding/decoding error |\n");
    md.push('\n');

    md.push_str("## Open Badges Errors (E7xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str("| E701 | `OPEN_BADGES_INVALID` | Open Badges payload is invalid or malformed |\n");
    md.push_str(
        "| E702 | `OPEN_BADGES_CONTEXT_MISSING` | Required Open Badges context is missing or unsupported |\n",
    );
    md.push_str("| E703 | `OPEN_BADGES_SIGNATURE_INVALID` | Open Badges signature verification failed |\n");
    md.push_str("| E704 | `OPEN_BADGES_PROOF_INVALID` | Open Badges proof verification failed |\n");
    md.push_str("| E705 | `OPEN_BADGES_DOCUMENT_MISSING` | Open Badges referenced document not found in offline store |\n");
    md.push_str("| E706 | `OPEN_BADGES_UNSUPPORTED` | Open Badges unsupported feature or algorithm |\n");
    md.push_str("| E707 | `OPEN_BADGES_REVOKED` | Open Badges credential has been revoked |\n");
    md.push_str("| E708 | `OPEN_BADGES_STATUS_CHECK_FAILED` | Open Badges credential status check failed |\n");
    md.push('\n');

    md.push_str("## DTC Errors (E8xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str("| E801 | `DTC_INVALID` | DTC payload is invalid or malformed |\n");
    md.push_str("| E802 | `DTC_MISSING_FIELD` | Required DTC field is missing |\n");
    md.push_str("| E803 | `DTC_UNSUPPORTED` | DTC uses unsupported algorithm or key type |\n");
    md.push_str("| E804 | `DTC_SIGNING_FAILED` | DTC signing failed |\n");
    md.push_str("| E805 | `DTC_SIGNATURE_INVALID` | DTC signature verification failed |\n");
    md.push_str("| E806 | `DTC_TRUST_CHAIN_INVALID` | DTC trust chain validation failed |\n");
    md.push_str("| E807 | `DTC_EXPIRED` | DTC has expired |\n");
    md.push_str("| E808 | `DTC_NOT_YET_VALID` | DTC is not yet valid |\n");
    md.push_str("| E809 | `DTC_REVOKED` | DTC has been revoked |\n");
    md.push('\n');

    md.push_str("## General Errors (E9xx)\n\n");
    md.push_str("| Code | Constant | Description |\n");
    md.push_str("|------|----------|-------------|\n");
    md.push_str("| E901 | `IO_ERROR` | I/O error |\n");
    md.push_str("| E902 | `CONFIG_ERROR` | Configuration error |\n");
    md.push_str("| E999 | `INTERNAL_ERROR` | Internal error |\n");
    md.push('\n');

    md.push_str("## Debugging Tips\n\n");
    md.push_str("1. Set `RUST_BACKTRACE=1` or `RUST_BACKTRACE=full` to capture backtraces\n");
    md.push_str("2. Register the `tracing_error::ErrorLayer` to capture span traces\n");
    md.push_str(
        "3. Use the `debug_report()` method on errors to get full diagnostic information\n",
    );

    md
}
