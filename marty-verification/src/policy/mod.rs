//! Presentation Policy module for evaluating credential presentation requirements.
//!
//! This module provides policy-driven evaluation of verifiable credential presentations,
//! supporting:
//! - Claim constraint evaluation (required claims, predicates)
//! - Issuer constraint checking (allowlist, trust profile)
//! - Freshness validation (credential age, revocation)
//! - Minimum disclosure resolution (data minimization)
//! - Credential ranking (multi-credential scenarios)
//!
//! # Architecture
//!
//! The policy module mirrors the Python domain model but is implemented in Rust for:
//! - Performance-critical offline verification (marty-verifier)
//! - Mobile wallet policy evaluation (marty-authenticator via Flutter FFI)
//! - Consistent enforcement across all platforms
//!
//! # Example
//!
//! ```rust,ignore
//! use marty_verification::policy::{PresentationPolicy, PolicyEvaluator};
//!
//! // Load policy from sync endpoint
//! let policy: PresentationPolicy = serde_json::from_str(&policy_json)?;
//!
//! // Evaluate presentation request
//! let evaluator = PolicyEvaluator::new(&policy);
//! let result = evaluator.evaluate(&credential, &request)?;
//!
//! if result.is_satisfied {
//!     // Proceed with presentation
//! }
//! ```

pub mod claim_evaluator;
pub mod disclosure;
pub mod freshness;
pub mod issuer;
pub mod ranking;
pub mod types;

pub use types::{
    CredentialRankingStrategy, FreshnessRequirements, HolderBindingMethod, PolicyEvaluationResult,
    PresentationPolicy, RequiredClaim,
};

pub use claim_evaluator::ClaimConstraintEvaluator;
pub use disclosure::MinimumDisclosureResolver;
pub use freshness::FreshnessChecker;
pub use issuer::IssuerConstraintChecker;
pub use ranking::CredentialRanker;

/// Policy evaluator that orchestrates all constraint checks.
#[allow(dead_code)]
pub struct PolicyEvaluator {
    policy: PresentationPolicy,
    claim_evaluator: ClaimConstraintEvaluator,
    freshness_checker: FreshnessChecker,
    issuer_checker: IssuerConstraintChecker,
    disclosure_resolver: MinimumDisclosureResolver,
}

impl PolicyEvaluator {
    /// Create a new policy evaluator.
    pub fn new(policy: PresentationPolicy) -> Self {
        Self {
            claim_evaluator: ClaimConstraintEvaluator::new(&policy),
            freshness_checker: FreshnessChecker::new(&policy.freshness_requirements),
            issuer_checker: IssuerConstraintChecker::new(
                policy.trust_profile_id.as_ref(),
                &policy.allowed_issuers,
            ),
            disclosure_resolver: MinimumDisclosureResolver::new(&policy),
            policy,
        }
    }
}
