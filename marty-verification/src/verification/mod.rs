//! Document verification modules.
//!
//! This module contains verification logic for different document types:
//!
//! - **mDL**: ISO 18013-5 mobile driving license verification
//! - **eMRTD**: ICAO 9303 electronic travel document verification
//! - **chain**: Generic X.509 certificate chain validation

pub mod chain;
pub mod mdl;

#[cfg(feature = "csca")]
pub mod emrtd;

pub use chain::{ChainValidationResult, ChainValidator, ChainValidatorConfig, KeyUsage};
