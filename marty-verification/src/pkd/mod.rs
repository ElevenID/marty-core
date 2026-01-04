//! PKD (Public Key Directory) clients for certificate fetching.
//!
//! This module provides async clients for fetching trust anchor certificates
//! from PKD services:
//!
//! - **AAMVA DTS**: Digital Trust Service for US/Canadian mDL IACA certificates
//! - **ICAO PKD**: Public Key Directory for eMRTD CSCA/DSC certificates

#[cfg(feature = "aamva-client")]
pub mod aamva_dts;

#[cfg(feature = "icao-client")]
pub mod icao_pkd;
