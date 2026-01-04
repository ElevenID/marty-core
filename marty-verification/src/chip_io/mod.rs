//! Chip/NFC I/O helpers for eMRTD passports.
//!
//! This module defines a minimal reader abstraction and helpers to verify
//! passports directly from reader output.

use std::collections::HashMap;

use crate::trust_anchor::CscaRegistry;
use crate::verification::emrtd::{verify_emrtd, SecurityObject};
use crate::VerificationResult;

/// Result of reading a passport chip.
#[derive(Debug, Clone)]
pub struct ReadResult {
    /// Raw EF.SOD bytes.
    pub sod: Vec<u8>,
    /// Data group contents keyed by DG number (e.g., 1 for DG1).
    pub data_groups: HashMap<u8, Vec<u8>>,
    /// Optional country hint (ISO 3166).
    pub country: Option<String>,
}

/// Passport reader abstraction.
pub trait PassportReader: Send + Sync {
    /// Read passport data (SOD + DGs) from the chip.
    fn read_passport(&self) -> VerificationResult<ReadResult>;
}

/// Simple mock reader useful for tests or injected data.
pub struct MockPassportReader {
    data: ReadResult,
}

impl MockPassportReader {
    /// Create a mock reader from pre-parsed data.
    pub fn new(sod: Vec<u8>, data_groups: HashMap<u8, Vec<u8>>, country: Option<String>) -> Self {
        Self {
            data: ReadResult {
                sod,
                data_groups,
                country,
            },
        }
    }
}

impl PassportReader for MockPassportReader {
    fn read_passport(&self) -> VerificationResult<ReadResult> {
        Ok(self.data.clone())
    }
}

/// Read from a passport reader and verify using the CSCA registry.
pub fn verify_from_reader<R: PassportReader>(
    reader: &R,
    registry: &CscaRegistry,
) -> crate::verification::emrtd::EmrtdVerificationResult {
    match reader.read_passport() {
        Ok(read) => {
            let security_object = match SecurityObject::from_sod_der(&read.sod, read.country) {
                Ok(so) => so,
                Err(e) => {
                    let mut result = crate::verification::emrtd::EmrtdVerificationResult::default();
                    result.errors.push(e.to_string());
                    return result;
                }
            };
            verify_emrtd(&security_object, &read.data_groups, registry)
        }
        Err(e) => {
            let mut result = crate::verification::emrtd::EmrtdVerificationResult::default();
            result.errors.push(e.to_string());
            result
        }
    }
}
