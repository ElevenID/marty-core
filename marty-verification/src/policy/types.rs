//! Core types for presentation policy evaluation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Presentation Policy defining what must be shown to satisfy a verification request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationPolicy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub purpose: String,

    /// Accepted credential types/templates
    pub accepted_credential_types: Vec<String>,

    /// Required claims with optional predicate support
    pub required_claims: Vec<RequiredClaim>,

    /// Holder binding requirement
    pub holder_binding: HolderBindingMethod,

    /// Trust constraints
    pub trust_profile_id: Option<String>,
    pub allowed_issuers: Vec<String>,

    /// Freshness constraints
    pub freshness_requirements: FreshnessRequirements,

    /// Data minimization rules
    pub prefer_predicates: bool,
    pub single_presentation: bool,
    pub derived_attribute_preferences: HashMap<String, String>,

    /// Credential ranking
    pub credential_ranking_strategy: CredentialRankingStrategy,
    pub credential_ranking_weights: HashMap<String, f64>,

    /// Extension point
    pub metadata: HashMap<String, serde_json::Value>,

    /// Version for sync conflict detection
    pub version: i32,
}

/// Required claim specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredClaim {
    pub claim_name: String,
    pub credential_type: String,
    pub accept_predicate: bool,
    pub required_value: Option<serde_json::Value>,
}

/// Holder binding method.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HolderBindingMethod {
    DeviceKey,
    SessionNonce,
    Biometric,
    None,
}

/// Credential ranking strategy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRankingStrategy {
    FreshestFirst,
    HighestTrustFirst,
    MinimumClaimsFirst,
    Custom,
}

/// Freshness requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreshnessRequirements {
    pub max_credential_age_seconds: Option<u64>,
    pub max_proof_age_seconds: u64,
    pub require_live_revocation_check: bool,
}

impl Default for FreshnessRequirements {
    fn default() -> Self {
        Self {
            max_credential_age_seconds: None,
            max_proof_age_seconds: 300, // 5 minutes
            require_live_revocation_check: true,
        }
    }
}

/// Verified facts supplied to the policy engine by protocol-specific code.
///
/// The policy engine never performs cryptographic verification itself. Callers
/// must supply the outcome of those checks explicitly, and required evidence
/// fails closed when it is absent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluationInput {
    pub credential_types: Vec<String>,
    pub claims: HashMap<String, serde_json::Value>,
    pub issuer_id: String,
    pub trust_profile_verified: bool,
    pub issued_at_epoch_seconds: Option<u64>,
    pub proof_epoch_seconds: Option<u64>,
    pub evaluation_time_epoch_seconds: u64,
    pub holder_binding_verified: bool,
    pub revocation_checked: bool,
    pub not_revoked: Option<bool>,
    pub presentation_count: usize,
}

/// Strict JSON request accepted by the native binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluationRequest {
    pub policy: PresentationPolicy,
    pub input: PolicyEvaluationInput,
}

/// Stable names for independently evaluated policy components.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PolicyComponent {
    CredentialType,
    Claims,
    Issuer,
    HolderBinding,
    CredentialFreshness,
    ProofFreshness,
    Revocation,
    PresentationCount,
}

/// Normalized status for a policy component.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyComponentStatusValue {
    Passed,
    Failed,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyComponentStatus {
    pub component: PolicyComponent,
    pub status: PolicyComponentStatusValue,
}

/// Machine-readable failure codes shared by every language binding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PolicyErrorCode {
    InvalidPolicy,
    CredentialTypeNotAccepted,
    ClaimRequirementNotSatisfied,
    IssuerNotAllowed,
    IssuerNotTrusted,
    HolderBindingRequired,
    CredentialTimestampMissing,
    CredentialStale,
    CredentialTimestampFuture,
    ProofTimestampMissing,
    ProofStale,
    ProofTimestampFuture,
    RevocationCheckRequired,
    RevocationStatusUnknown,
    CredentialRevoked,
    SinglePresentationRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvaluationError {
    pub code: PolicyErrorCode,
    pub component: PolicyComponent,
    pub message: String,
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationResult {
    pub is_satisfied: bool,
    pub component_statuses: Vec<PolicyComponentStatus>,
    pub errors: Vec<PolicyEvaluationError>,
    pub warnings: Vec<String>,
    pub missing_claims: Vec<String>,
    pub issuer_violations: Vec<String>,
    pub freshness_violations: Vec<String>,
    pub minimum_disclosure_set: Vec<String>,
}

impl PolicyEvaluationResult {
    pub fn status(&self, component: PolicyComponent) -> Option<PolicyComponentStatusValue> {
        self.component_statuses
            .iter()
            .find(|entry| entry.component == component)
            .map(|entry| entry.status)
    }
}
