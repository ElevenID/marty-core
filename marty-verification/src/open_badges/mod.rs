//! Open Badges verification and issuance helpers.
//!
//! This module provides helpers for issuing and verifying Open Badges v2 (OB2) and v3 (OB3)
//! credentials using JWS signatures (OB2) and Data Integrity proofs (OB3).
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
//!
//! These async functions work in all environments when driven by an appropriate async runtime
//! (e.g., `wasm-bindgen-futures` for browser environments).
//!
//! # Feature Summary
//!
//! | Feature | OB2 | OB3 |
//! |---------|-----|-----|
//! | JWS Signatures | ✓ (ES256, ES384, EdDSA) | — |
//! | Data Integrity Proofs | — | ✓ (JsonWebSignature2020, Ed25519Signature2018/2020) |
//! | Recipient Hashing | ✓ (SHA1, SHA256, SHA512) | — |
//! | Credential Status / Revocation | — | ✓ (StatusList2021, BitstringStatusListEntry, RevocationList2020) |
//! | Offline JSON-LD Contexts | ✓ | ✓ |

mod contexts;
mod ob2;
mod ob3;
mod types;

use serde_json::Value;

pub use contexts::{ob2_context_uri, ob3_context_uri, open_badges_context_loader};
pub use ob2::{issue_ob2_json, verify_ob2_json};
#[cfg(not(target_arch = "wasm32"))]
pub use ob3::{issue_ob3_json, verify_ob3_json};
pub use ob3::{issue_ob3_json_async, verify_ob3_json_async};
pub use types::{DocumentStore, OpenBadgesIssueResult, OpenBadgesVerificationResult, OpenBadgesVersion};

pub fn detect_version(value: &Value) -> OpenBadgesVersion {
    if has_context(value, ob2_context_uri()) {
        return OpenBadgesVersion::V2;
    }
    if has_context(value, ob3_context_uri()) || has_context(value, "https://w3id.org/openbadges/v3")
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
