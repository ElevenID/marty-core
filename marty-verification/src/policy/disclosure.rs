//! Minimum disclosure resolution for data minimization.

use crate::policy::types::{PresentationPolicy, RequiredClaim};
use std::collections::{HashMap, HashSet};

/// Resolves the minimum set of claims that satisfy policy requirements.
pub struct MinimumDisclosureResolver {
    required_claims: Vec<RequiredClaim>,
    #[allow(dead_code)]
    prefer_predicates: bool,
    derived_preferences: HashMap<String, String>,
}

impl MinimumDisclosureResolver {
    pub fn new(policy: &PresentationPolicy) -> Self {
        Self {
            required_claims: policy.required_claims.clone(),
            prefer_predicates: policy.prefer_predicates,
            derived_preferences: policy.derived_attribute_preferences.clone(),
        }
    }

    /// Compute minimum disclosure set from available credential claims.
    /// 
    /// Returns the smallest set of claims that satisfies policy requirements,
    /// preferring derived attributes over raw values when configured.
    pub fn resolve(&self, available_claims: &[String]) -> MinimumDisclosureSet {
        let mut selected = HashSet::new();
        let mut missing = Vec::new();

        for required in &self.required_claims {
            let mut found = false;

            // First, check for derived attribute preference
            if let Some(derived_name) = self.derived_preferences.get(&required.claim_name) {
                if available_claims.contains(derived_name) {
                    selected.insert(derived_name.clone());
                    found = true;
                }
            }

            // If not found via derived attribute, check for direct claim
            if !found && available_claims.contains(&required.claim_name) {
                selected.insert(required.claim_name.clone());
                found = true;
            }

            // Track missing required claims
            if !found {
                missing.push(required.claim_name.clone());
            }
        }

        MinimumDisclosureSet {
            claims: selected.into_iter().collect(),
            missing_required: missing,
        }
    }

    /// Get all claims that should be disclosed (including optional) with preferences applied.
    pub fn get_preferred_disclosure(
        &self,
        available_claims: &[String],
        include_optional: bool,
    ) -> Vec<String> {
        let mut result = Vec::new();

        for claim_name in available_claims {
            // Check if this claim has a derived preference
            if let Some(derived) = self.derived_preferences.get(claim_name) {
                if available_claims.contains(derived) {
                    if !result.contains(derived) {
                        result.push(derived.clone());
                    }
                    continue;
                }
            }

            // Check if this is a required claim
            let is_required = self
                .required_claims
                .iter()
                .any(|r| r.claim_name == *claim_name);

            if is_required || include_optional {
                if !result.contains(&claim_name.to_string()) {
                    result.push(claim_name.clone());
                }
            }
        }

        result
    }
}

/// Result of minimum disclosure resolution.
#[derive(Debug, Clone)]
pub struct MinimumDisclosureSet {
    pub claims: Vec<String>,
    pub missing_required: Vec<String>,
}

impl MinimumDisclosureSet {
    pub fn is_complete(&self) -> bool {
        self.missing_required.is_empty()
    }
}
