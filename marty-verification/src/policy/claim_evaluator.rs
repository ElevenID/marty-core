//! Claim constraint evaluation logic.

use crate::policy::types::{PresentationPolicy, RequiredClaim};
use std::collections::HashMap;

/// Evaluates whether credentials satisfy required claim constraints.
pub struct ClaimConstraintEvaluator {
    required_claims: Vec<RequiredClaim>,
    #[allow(dead_code)]
    prefer_predicates: bool,
    derived_preferences: HashMap<String, String>,
}

impl ClaimConstraintEvaluator {
    pub fn new(policy: &PresentationPolicy) -> Self {
        Self {
            required_claims: policy.required_claims.clone(),
            prefer_predicates: policy.prefer_predicates,
            derived_preferences: policy.derived_attribute_preferences.clone(),
        }
    }

    /// Check if provided claims satisfy policy requirements.
    pub fn evaluate(&self, claims: &HashMap<String, serde_json::Value>) -> ClaimEvaluationResult {
        let mut missing = Vec::new();
        let mut satisfied = Vec::new();

        for required in &self.required_claims {
            // Check for derived attribute preference first
            if let Some(derived_name) = self.derived_preferences.get(&required.claim_name) {
                if claims.contains_key(derived_name) {
                    satisfied.push(derived_name.clone());
                    continue;
                }
            }

            // Check for direct claim
            if let Some(value) = claims.get(&required.claim_name) {
                // If a specific value is required, check it matches
                if let Some(ref required_value) = required.required_value {
                    if value != required_value {
                        missing.push(format!(
                            "{} (expected {}, got {})",
                            required.claim_name, required_value, value
                        ));
                        continue;
                    }
                }
                satisfied.push(required.claim_name.clone());
            } else {
                missing.push(required.claim_name.clone());
            }
        }

        ClaimEvaluationResult {
            is_satisfied: missing.is_empty(),
            missing_claims: missing,
            satisfied_claims: satisfied,
        }
    }

    /// Get preferred disclosure set (derived attributes over raw values).
    pub fn get_preferred_claims(&self, available_claims: &[String]) -> Vec<String> {
        let mut preferred = Vec::new();

        for claim_name in available_claims {
            // If there's a derived preference, use that instead
            if let Some(derived) = self.derived_preferences.get(claim_name) {
                if available_claims.contains(&derived.to_string()) {
                    if !preferred.contains(derived) {
                        preferred.push(derived.clone());
                    }
                    continue;
                }
            }
            
            // Otherwise use the original claim
            if !preferred.contains(&claim_name.to_string()) {
                preferred.push(claim_name.clone());
            }
        }

        preferred
    }
}

/// Result of claim constraint evaluation.
#[derive(Debug, Clone)]
pub struct ClaimEvaluationResult {
    pub is_satisfied: bool,
    pub missing_claims: Vec<String>,
    pub satisfied_claims: Vec<String>,
}
