//! Open Badges verification and issuance helpers.
//!
//! Open Badges 3 (OB3) is the supported profile. Open Badges 2 issuance and
//! verification have been removed. An OB2 assertion must be reissued by its
//! issuer as OB3; changing its context or routing label is not a migration.
//!
//! # WASM Compatibility Note
//!
//! The synchronous OB3 functions (`issue_ob3_json` and `verify_ob3_json`) are **not available**
//! on `wasm32` targets because they use blocking async runtime internally (`futures::executor::block_on`),
//! which is incompatible with single-threaded WASM environments.
//!
//! For WASM targets, use the async versions:
//! - [`issue_ob3_json_async`] - Async OB3 credential issuance
//! - [`verify_ob3_json_async`] - Async OB3 credential verification
//! - [`verify_ob3_json_with_status_lists_async`] - Async OB3 verification with
//!   separately authenticated status-list inputs
//!
//! These async functions work in all environments when driven by an appropriate async runtime
//! (e.g., `wasm-bindgen-futures` for browser environments).
//!
//! # Feature Summary
//!
//! - OB3 Data Integrity proofs (JsonWebSignature2020, Ed25519Signature2018/2020)
//! - Authenticated W3C Bitstring Status List v1.0 revocation
//! - Offline, pinned JSON-LD contexts

mod contexts;
mod method_wrapper;
mod ob3;
mod status;
mod suite_wrapper;
mod types;
mod x509_suite;
mod x509_verification_method;

use serde_json::Value;

pub use crate::credential_format::is_retired_ob2;
pub use contexts::{ob3_context_uri, open_badges_context_loader};
pub use method_wrapper::{parse_open_badge_method, OpenBadgeMethod};
#[cfg(not(target_arch = "wasm32"))]
pub use ob3::{issue_ob3_json, verify_ob3_json, verify_ob3_json_with_status_lists};
pub use ob3::{
    issue_ob3_json_async, verify_ob3_json_async, verify_ob3_json_with_status_lists_async,
};
pub use suite_wrapper::OpenBadgeSuite;
pub use types::{
    ArtifactProvenance, AuthenticatedStatusList, DocumentStore, OpenBadgeStatusCheck,
    OpenBadgeStatusOutcome, OpenBadgesIssueResult, OpenBadgesVerificationResult, OpenBadgesVersion,
    StatusAuthorityProvenance,
};
pub use x509_suite::X509Signature2021;
pub use x509_verification_method::X509VerificationKey2021;

/// Detect the supported Open Badges profile; retired assertions are unknown.
///
/// Retired verification and issuance APIs are absent from the public surface.
///
/// ```compile_fail
/// use marty_verification::open_badges::verify_ob2_json;
/// ```
///
/// ```compile_fail
/// use marty_verification::open_badges::issue_ob2_json;
/// ```
pub fn detect_version(value: &Value) -> OpenBadgesVersion {
    if is_retired_ob2(value) {
        return OpenBadgesVersion::Unknown;
    }
    if has_context(value, ob3_context_uri())
        || has_context(value, "https://w3id.org/openbadges/v3")
        || has_context(
            value,
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        )
    {
        return OpenBadgesVersion::V3;
    }
    OpenBadgesVersion::Unknown
}

fn has_context(value: &Value, context_uri: &str) -> bool {
    match value.get("@context") {
        Some(Value::String(ctx)) => ctx == context_uri,
        Some(Value::Array(contexts)) => contexts
            .iter()
            .any(|ctx| ctx.as_str().map(|s| s == context_uri).unwrap_or(false)),
        _ => false,
    }
}
