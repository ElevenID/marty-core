//! Trust chain verification for mDL (IACA) and eMRTD (CSCA).
//!
//! This crate provides native Rust implementation of X.509 certificate chain validation
//! for multiple document types:
//!
//! - **mDL (ISO 18013-5)**: IACA → Document Signer → mDoc
//! - **eMRTD (ICAO 9303)**: CSCA → DSC → SOD
//!
//! # Features
//!
//! - `iaca` (default): AAMVA mDL trust chain verification
//! - `csca` (default): ePassport/eMRTD trust chain verification
//! - `aamva-client`: Async client for AAMVA Digital Trust Service
//! - `icao-client`: Async client for ICAO PKD
//!
//! # Example
//!
//! ```rust,ignore
//! use marty_verification::trust_anchor::{TrustRegistry, IacaRegistry};
//! use marty_verification::verification::mdl::verify_mdl_issuer;
//!
//! // Load IACA certificates
//! let registry = IacaRegistry::from_pem_files("./certs/iaca/")?;
//!
//! // Verify an mDL credential
//! let result = verify_mdl_issuer(&x5chain, &registry)?;
//! assert!(result.is_valid());
//! ```

#[cfg(feature = "csca")]
pub mod active_authentication;
pub mod asn1;
#[cfg(feature = "csca")]
pub mod chip_io;
pub mod credential_format;
pub mod device_auth;
pub mod dtc;

/// KMS-only and verification builds do not expose in-process DTC signing.
///
/// ```compile_fail
/// use marty_verification::dtc::sign_dtc_json;
/// let _ = sign_dtc_json("{}");
/// ```
mod dtc_local_signing_compile_boundary {}
#[cfg(feature = "csca")]
pub mod eac;
#[cfg(feature = "csca")]
pub mod emrtd_data;
pub mod error;
pub mod evidence_policy;
pub mod evidence_reconciliation;
pub mod flow;
pub mod governance;
pub mod jwk;
pub mod key_attestation;
pub mod mdoc;
pub mod mrz;
pub mod oid4vp;
pub mod open_badges;
pub mod passport_integrity;
pub mod policy;
pub mod trust_anchor;
pub mod trust_sync;
pub mod vcdm;
pub mod verification;

#[cfg(any(feature = "aamva-client", feature = "icao-client"))]
pub mod pkd;

/// The default verifier surface intentionally has no authority issuance API.
///
/// ```compile_fail
/// use marty_verification::issuance::CscaAuthority;
/// ```
mod authority_issuance_compile_boundary {}

#[cfg(feature = "python")]
pub mod bindings;

// Test data module is only available when the test fixtures exist.
// The NIST PKITS fixtures must be downloaded separately.
// Gate behind a feature to avoid compilation errors when fixtures are missing.
#[cfg(all(test, feature = "test-fixtures"))]
pub mod testdata;

pub use error::{VerificationError, VerificationResult};
#[cfg(feature = "csca")]
pub use trust_anchor::CscaRegistry;
pub use trust_anchor::{BasicTrustRegistry, TrustAnchor, TrustPurpose, TrustRegistry};
pub use trust_anchor::{IacaRegistry, Jurisdiction};
pub use verification::vds_nc::{
    inspect_vds_nc, verify_vds_nc, verify_vds_nc_jwk_json, verify_vds_nc_profile_pem,
    verify_vds_nc_public_key_der, SignatureVerificationStatus, VdsNcProfileVerificationResult,
    VdsNcVerificationResult,
};

// Re-export commonly used types
#[cfg(feature = "csca")]
pub use verification::emrtd::{
    ChainStatus, EmrtdVerificationOptions, EmrtdVerificationResult, HashStatus, RevocationStatus,
    SignatureStatus,
};
pub use verification::mdl::{
    verify_device_authentication, AuthStatus, MdlDeviceAuthenticationResult, MdlVerificationResult,
};

// Re-export chip I/O types for government NFC integration
#[cfg(feature = "csca")]
pub use chip_io::{mrz_check_digit, ApduCommand, ApduResponse, MockPassportChip, PassportChip};
#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
pub use chip_io::{BacHandshake, BacSession, MrzKeyInfo, PaceCompatibilityHandshake};

// Re-export crypto primitives from marty-crypto
pub use marty_crypto::{verify_signature, HashAlgorithm, SignatureAlgorithm};

// Preserve legacy behavior and imported compliance suites as crate-internal
// tests. This lets them exercise test-only signing fixtures without restoring
// any production-selectable private-key API or modifying the imported sources.
#[cfg(test)]
extern crate self as marty_verification;
#[cfg(test)]
#[path = "../tests/dtc_tests.rs"]
mod dtc_behavior_tests;
#[cfg(all(test, feature = "csca", feature = "ephemeral-session-keys"))]
#[path = "../tests/eac_behavior.rs"]
mod eac_behavior_tests;
#[cfg(test)]
#[path = "../tests/open_badges_tests.rs"]
mod open_badges_behavior_tests;
#[cfg(test)]
#[path = "../tests/open_badges_conformance.rs"]
mod open_badges_conformance_tests;
#[cfg(all(test, feature = "csca", feature = "ephemeral-session-keys"))]
#[path = "../tests/passport_chip_behavior.rs"]
mod passport_chip_behavior_tests;
