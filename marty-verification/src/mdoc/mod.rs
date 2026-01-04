//! mDL (Mobile Driver License) document parsing and validation.
//!
//! This module provides a UniFFI-compatible wrapper around isomdl for
//! parsing and validating ISO 18013-5 mDL documents.

mod device_response;

pub use device_response::{
    DeviceResponse, Document, IssuerSignedItem, MdlNamespace, MobileSecurityObject, ValidityInfo,
};

use crate::VerificationResult;

/// Parse a CBOR-encoded DeviceResponse.
///
/// # Arguments
///
/// * `cbor_bytes` - The CBOR-encoded DeviceResponse
///
/// # Returns
///
/// A parsed `DeviceResponse` structure
pub fn parse_device_response(cbor_bytes: &[u8]) -> VerificationResult<DeviceResponse> {
    DeviceResponse::from_cbor(cbor_bytes)
}

/// Extract mDL namespace fields from a DeviceResponse.
///
/// # Arguments
///
/// * `response` - The parsed DeviceResponse
///
/// # Returns
///
/// A vector of (element_id, value) pairs from the org.iso.18013.5.1 namespace
pub fn extract_mdl_fields(
    response: &DeviceResponse,
) -> VerificationResult<Vec<(String, serde_json::Value)>> {
    response.get_mdl_fields()
}

/// Verify the mobile security object signature.
///
/// # Arguments
///
/// * `mso` - The MobileSecurityObject to verify
/// * `issuer_cert_der` - The DER-encoded issuer certificate
///
/// # Returns
///
/// `Ok(())` if signature is valid, error otherwise
pub fn verify_mso_signature(
    mso: &MobileSecurityObject,
    issuer_cert_der: &[u8],
) -> VerificationResult<()> {
    mso.verify_signature(issuer_cert_der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdl_namespace_constant() {
        assert_eq!(MdlNamespace::ISO_18013_5_1, "org.iso.18013.5.1");
    }
}
