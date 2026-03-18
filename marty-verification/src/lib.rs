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

pub mod asn1;
#[cfg(feature = "csca")]
pub mod chip_io;
pub mod dtc;
pub mod error;
pub mod jwk;
pub mod mdoc;
pub mod mrz;
pub mod open_badges;
pub mod policy;
pub mod trust_anchor;
pub mod verification;

#[cfg(any(feature = "aamva-client", feature = "icao-client"))]
pub mod pkd;

/// eMRTD issuance infrastructure (CSCA, DSC, EF.SOD builder).
///
/// Available when the `csca` feature is enabled.  Requires that the
/// `marty-crypto` dependency was compiled with the `sod-builder` and
/// `cert-builder` features (both are enabled by the default `Cargo.toml`).
#[cfg(feature = "csca")]
pub mod issuance;

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

// Re-export commonly used types
#[cfg(feature = "csca")]
pub use verification::emrtd::{ChainStatus, EmrtdVerificationOptions, EmrtdVerificationResult, HashStatus, RevocationStatus, SignatureStatus};
pub use verification::mdl::{AuthStatus, MdlVerificationResult};

// Re-export chip I/O types for government NFC integration
#[cfg(feature = "csca")]
pub use chip_io::{
    ApduCommand, ApduResponse, BacKeys, BacSession, MrzKeyInfo, MockPassportChip,
    PaceKeys, PacePassword, PaceSession, PassportChip, derive_bac_base_keys, mrz_check_digit,
};

// Re-export crypto primitives from marty-crypto
pub use marty_crypto::{verify_signature, HashAlgorithm, SignatureAlgorithm};
