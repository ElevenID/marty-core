//! Core types for presentation policy evaluation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Presentation Policy defining what must be shown to satisfy a verification request.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult {
    pub is_satisfied: bool,
    pub missing_claims: Vec<String>,
    pub issuer_violations: Vec<String>,
    pub freshness_violations: Vec<String>,
    pub minimum_disclosure_set: Vec<String>,
}

impl PolicyEvaluationResult {
    pub fn satisfied(minimum_disclosure_set: Vec<String>) -> Self {
        Self {
            is_satisfied: true,
            missing_claims: Vec::new(),
            issuer_violations: Vec::new(),
            freshness_violations: Vec::new(),
            minimum_disclosure_set,
        }
    }

    pub fn unsatisfied(
        missing_claims: Vec<String>,
        issuer_violations: Vec<String>,
        freshness_violations: Vec<String>,
    ) -> Self {
        Self {
            is_satisfied: false,
            missing_claims,
            issuer_violations,
            freshness_violations,
            minimum_disclosure_set: Vec::new(),
        }
    }
}
