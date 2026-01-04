//! Trust anchor management for certificate chain verification.
//!
//! This module provides a unified interface for managing trust anchors (root certificates)
//! across different document verification systems:
//!
//! - **IACA**: Issuing Authority Certificate Authority for mDL (ISO 18013-5)
//! - **CSCA**: Country Signing Certificate Authority for eMRTD (ICAO 9303)

pub mod iaca;
pub mod registry;

#[cfg(feature = "csca")]
pub mod csca;

pub use iaca::{IacaRegistry, Jurisdiction};
pub use registry::{BasicTrustRegistry, PemTrustAnchor, TrustAnchor, TrustPurpose, TrustRegistry};

#[cfg(feature = "csca")]
pub use csca::CscaRegistry;
