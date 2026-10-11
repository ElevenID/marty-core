//! A minimal downstream X.509 trust-chain consumer with no runtime I/O.
//!
//! The caller owns the approved trust anchor, evidence chain, and validation
//! moment. This is a certificate-chain kernel, not a complete mDL/eMRTD/OB3
//! presentation verifier or a supported distribution.

use chrono::{DateTime, Utc};
use marty_verification::verification::{
    ChainValidationResult, ChainValidator, ChainValidatorConfig,
};
use marty_verification::VerificationResult;

/// Verify an ordered leaf-to-root DER chain against one locally provisioned CA.
/// This function performs no trust resolution, status fetch, or network I/O.
pub fn verify_chain_offline(
    chain_der: &[Vec<u8>],
    approved_root_der: &[u8],
    validation_moment: DateTime<Utc>,
) -> VerificationResult<ChainValidationResult> {
    let config = ChainValidatorConfig {
        validation_moment: Some(validation_moment),
        ..Default::default()
    };
    let mut verifier = ChainValidator::with_config(config);
    verifier.add_trust_anchor_der(approved_root_der)?;
    verifier.validate_chain_der(chain_der)
}
