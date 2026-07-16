//! Document verification modules.
//!
//! This module contains verification logic for different document types:
//!
//! - **mDL**: ISO 18013-5 mobile driving license verification
//! - **eMRTD**: ICAO 9303 electronic travel document verification
//! - **VDS-NC**: ICAO visible digital seal verification
//! - **chain**: Generic X.509 certificate chain validation

pub mod chain;
pub mod mdl;
pub mod vds_nc;

#[cfg(feature = "csca")]
pub mod emrtd;

pub use chain::{ChainValidationResult, ChainValidator, ChainValidatorConfig, KeyUsage};
pub use vds_nc::{
    verify_vds_nc, verify_vds_nc_jwk_json, SignatureVerificationStatus, VdsNcVerificationResult,
};
