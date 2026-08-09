//! Document verification modules.
//!
//! This module contains verification logic for different document types:
//!
//! - **mDL**: ISO 18013-5 mobile driving license verification
//! - **eMRTD**: ICAO 9303 electronic travel document verification
//! - **VDS-NC**: ICAO visible digital seal verification
//! - **chain**: Generic X.509 certificate chain validation

pub mod chain;
pub mod decision;
pub mod mdl;
pub mod result;
pub mod vds_nc;

#[cfg(feature = "csca")]
pub mod emrtd;

pub use chain::{ChainValidationResult, ChainValidator, ChainValidatorConfig, KeyUsage};
pub use decision::{
    reduce_required_checks, ReducedVerificationDecision, VerificationCategoryOutcome,
    VerificationCategorySummary, VerificationCheckCategory, VerificationCheckOutcome,
    VerificationCheckResult, VerificationDecision, VerificationDecisionCode,
    VerificationProcessingStatus, VerificationReductionError, REQUIRED_CHECK_REDUCER_ID,
    REQUIRED_CHECK_REDUCER_VERSION,
};
pub use result::{
    build_verification_decision_result, VerificationComponentVersion, VerificationContextMode,
    VerificationDecisionContext, VerificationDecisionResult, VerificationDecisionResultError,
    VerificationDecisionResultInput, VerificationProfileReference, VerificationReducerReference,
    MAX_CHECK_EVIDENCE_REFS, MAX_VERIFICATION_CHECKS, MAX_VERIFICATION_COMPONENTS,
    VERIFICATION_DECISION_SCHEMA_VERSION,
};
pub use vds_nc::{
    verify_vds_nc, verify_vds_nc_jwk_json, SignatureVerificationStatus, VdsNcVerificationResult,
};
