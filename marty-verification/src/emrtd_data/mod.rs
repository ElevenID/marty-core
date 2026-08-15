//! Canonical parsing for eMRTD elementary files and biometric templates.
//!
//! The parsers in this module are deliberately transport-independent. They
//! accept complete EF payloads or ISO biometric records, enforce bounded
//! lengths, and return serializable models suitable for native bindings.

mod biometric;
mod dg15;
mod elementary;

pub use biometric::{
    parse_biometric_template, validate_template_quality, BiometricHeader, BiometricTemplate,
    BiometricType, FacialImageTemplate, FingerprintTemplate, ImageFormat, IrisTemplate,
    QualityReport,
};
pub use dg15::{inspect_rsa_public_key, parse_dg15, rsa_public_key_spki, Dg15Info};
pub use elementary::{
    parse_ef_com, parse_ef_dg1, parse_ef_dg2, parse_elementary_file, parse_tlv, BiometricInfo,
    EfCom, ElementaryFile, MrzInfo, Tlv,
};

use thiserror::Error;

/// Maximum accepted EF or biometric record size.
pub const MAX_EMRTD_DATA_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EmrtdDataError {
    #[error("EMRTD_DATA.EMPTY: {0}")]
    Empty(&'static str),
    #[error("EMRTD_DATA.OVERSIZED: {0}")]
    Oversized(&'static str),
    #[error("EMRTD_DATA.TRUNCATED: {0}")]
    Truncated(&'static str),
    #[error("EMRTD_DATA.INVALID_TLV: {0}")]
    InvalidTlv(String),
    #[error("EMRTD_DATA.INVALID_FORMAT: {0}")]
    InvalidFormat(String),
    #[error("EMRTD_DATA.UNSUPPORTED: {0}")]
    Unsupported(String),
    #[error("EMRTD_DATA.ENCODING: {0}")]
    Encoding(String),
}

pub type EmrtdDataResult<T> = Result<T, EmrtdDataError>;

pub(crate) fn ensure_bounded(data: &[u8], kind: &'static str) -> EmrtdDataResult<()> {
    if data.is_empty() {
        return Err(EmrtdDataError::Empty(kind));
    }
    if data.len() > MAX_EMRTD_DATA_BYTES {
        return Err(EmrtdDataError::Oversized(kind));
    }
    Ok(())
}
