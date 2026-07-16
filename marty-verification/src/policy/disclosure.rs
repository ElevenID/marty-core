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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::*;
    use std::collections::HashMap;

    fn make_policy(
        required: Vec<RequiredClaim>,
        derived: HashMap<String, String>,
    ) -> PresentationPolicy {
        PresentationPolicy {
            id: "test-policy".to_string(),
            name: "Test".to_string(),
            description: None,
            purpose: "testing".to_string(),
            accepted_credential_types: vec![],
            required_claims: required,
            holder_binding: HolderBindingMethod::None,
            trust_profile_id: None,
            allowed_issuers: vec![],
            freshness_requirements: FreshnessRequirements::default(),
            prefer_predicates: false,
            single_presentation: false,
            derived_attribute_preferences: derived,
            credential_ranking_strategy: CredentialRankingStrategy::FreshestFirst,
            credential_ranking_weights: HashMap::new(),
            metadata: HashMap::new(),
            version: 1,
        }
    }

    fn required(name: &str) -> RequiredClaim {
        RequiredClaim {
            claim_name: name.to_string(),
            credential_type: "TestCredential".to_string(),
            accept_predicate: false,
            required_value: None,
        }
    }

    // ====================================================================
    // resolve()
    // ====================================================================

    #[test]
    fn test_resolve_empty_policy() {
        let policy = make_policy(vec![], HashMap::new());
        let resolver = MinimumDisclosureResolver::new(&policy);
        let result = resolver.resolve(&["name".to_string()]);
        assert!(result.is_complete());
        assert!(result.claims.is_empty());
    }

    #[test]
    fn test_resolve_all_required_present() {
        let policy = make_policy(
            vec![required("name"), required("birth_date")],
            HashMap::new(),
        );
        let resolver = MinimumDisclosureResolver::new(&policy);
        let available = vec![
            "name".to_string(),
            "birth_date".to_string(),
            "address".to_string(), // extra — should not be selected
        ];
        let result = resolver.resolve(&available);
        assert!(result.is_complete());
        assert_eq!(result.claims.len(), 2);
        assert!(result.claims.contains(&"name".to_string()));
        assert!(result.claims.contains(&"birth_date".to_string()));
        // "address" is NOT in minimum set
        assert!(!result.claims.contains(&"address".to_string()));
    }

    #[test]
    fn test_resolve_missing_required() {
        let policy = make_policy(vec![required("name"), required("ssn")], HashMap::new());
        let resolver = MinimumDisclosureResolver::new(&policy);
        let available = vec!["name".to_string()];
        let result = resolver.resolve(&available);
        assert!(!result.is_complete());
        assert_eq!(result.missing_required, vec!["ssn"]);
    }

    #[test]
    fn test_resolve_prefers_derived_attribute() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_21".to_string());

        let policy = make_policy(vec![required("birth_date")], derived);
        let resolver = MinimumDisclosureResolver::new(&policy);

        let available = vec!["birth_date".to_string(), "age_over_21".to_string()];
        let result = resolver.resolve(&available);
        assert!(result.is_complete());
        // Should pick derived over raw
        assert!(result.claims.contains(&"age_over_21".to_string()));
        assert!(!result.claims.contains(&"birth_date".to_string()));
    }

    #[test]
    fn test_resolve_derived_not_available_falls_back() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_21".to_string());

        let policy = make_policy(vec![required("birth_date")], derived);
        let resolver = MinimumDisclosureResolver::new(&policy);

        let available = vec!["birth_date".to_string()];
        let result = resolver.resolve(&available);
        assert!(result.is_complete());
        assert!(result.claims.contains(&"birth_date".to_string()));
    }

    // ====================================================================
    // get_preferred_disclosure()
    // ====================================================================

    #[test]
    fn test_preferred_disclosure_required_only() {
        let policy = make_policy(
            vec![required("name"), required("birth_date")],
            HashMap::new(),
        );
        let resolver = MinimumDisclosureResolver::new(&policy);

        let available = vec![
            "name".to_string(),
            "birth_date".to_string(),
            "address".to_string(),
        ];
        // include_optional = false → only required claims
        let result = resolver.get_preferred_disclosure(&available, false);
        assert!(result.contains(&"name".to_string()));
        assert!(result.contains(&"birth_date".to_string()));
        assert!(!result.contains(&"address".to_string()));
    }

    #[test]
    fn test_preferred_disclosure_include_optional() {
        let policy = make_policy(vec![required("name")], HashMap::new());
        let resolver = MinimumDisclosureResolver::new(&policy);

        let available = vec!["name".to_string(), "address".to_string()];
        let result = resolver.get_preferred_disclosure(&available, true);
        assert!(result.contains(&"name".to_string()));
        assert!(result.contains(&"address".to_string()));
    }

    #[test]
    fn test_preferred_disclosure_uses_derived() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_18".to_string());

        let policy = make_policy(vec![required("birth_date")], derived);
        let resolver = MinimumDisclosureResolver::new(&policy);

        let available = vec!["birth_date".to_string(), "age_over_18".to_string()];
        let result = resolver.get_preferred_disclosure(&available, false);
        assert!(result.contains(&"age_over_18".to_string()));
    }

    // ====================================================================
    // MinimumDisclosureSet
    // ====================================================================

    #[test]
    fn test_disclosure_set_is_complete() {
        let set = MinimumDisclosureSet {
            claims: vec!["name".to_string()],
            missing_required: vec![],
        };
        assert!(set.is_complete());
    }

    #[test]
    fn test_disclosure_set_incomplete() {
        let set = MinimumDisclosureSet {
            claims: vec![],
            missing_required: vec!["ssn".to_string()],
        };
        assert!(!set.is_complete());
    }
}
