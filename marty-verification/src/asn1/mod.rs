//! ASN.1 parsing for ICAO/eMRTD data structures.
//!
//! This module provides parsers for:
//! - Master List (ICAO PKD signed list of CSCAs)
//! - Certificate Revocation Lists (CRLs)
//! - Document Security Object (SOD)
//!
//! # ICAO 9303 References
//!
//! - Part 10: CSCA/DSC PKI architecture
//! - Part 11: Security mechanisms
//! - Part 12: Public key infrastructure

pub mod crl;
pub mod master_list;
pub mod sod;

pub use crl::{check_certificate_revocation, CrlInfo, RevokedCertificate};
pub use master_list::{parse_master_list, MasterList};
pub use sod::{parse_sod, DataGroupHash, LdsSecurityObject};
