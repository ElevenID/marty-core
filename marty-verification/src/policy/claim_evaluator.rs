//! Compatibility API for claim constraint evaluation.

use super::{
    compat::{neutral_input, neutral_policy},
    PolicyEvaluator,
};
use crate::policy::types::{PresentationPolicy, RequiredClaim};
use std::collections::HashMap;

/// Evaluates whether credentials satisfy required claim constraints.
pub struct ClaimConstraintEvaluator {
    policy: PresentationPolicy,
}

impl ClaimConstraintEvaluator {
    pub fn new(policy: &PresentationPolicy) -> Self {
        let mut compatibility_policy = neutral_policy();
        compatibility_policy.required_claims = policy.required_claims.clone();
        compatibility_policy.prefer_predicates = policy.prefer_predicates;
        compatibility_policy.derived_attribute_preferences =
            policy.derived_attribute_preferences.clone();
        Self {
            policy: compatibility_policy,
        }
    }

    /// Check if provided claims satisfy policy requirements.
    pub fn evaluate(&self, claims: &HashMap<String, serde_json::Value>) -> ClaimEvaluationResult {
        let credential_types: Vec<String> = self
            .policy
            .required_claims
            .iter()
            .map(|required| required.credential_type.clone())
            .collect();
        self.evaluate_for_credential_types(claims, &credential_types)
    }

    /// Check claims while enforcing the credential type attached to each requirement.
    pub fn evaluate_for_credential_types(
        &self,
        claims: &HashMap<String, serde_json::Value>,
        credential_types: &[String],
    ) -> ClaimEvaluationResult {
        let mut input = neutral_input();
        input.claims = claims.clone();
        input.credential_types = credential_types.to_vec();
        let canonical = PolicyEvaluator::new(self.policy.clone()).evaluate(&input);
        let mut missing = Vec::new();
        let mut satisfied = Vec::new();

        for required in &self.policy.required_claims {
            let mut single_policy = self.policy.clone();
            single_policy.required_claims = vec![required.clone()];
            let result = PolicyEvaluator::new(single_policy).evaluate(&input);
            if result.is_satisfied {
                satisfied.push(selected_claim_name(&self.policy, claims, required));
            } else {
                missing.push(
                    result
                        .missing_claims
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| required.claim_name.clone()),
                );
            }
        }

        ClaimEvaluationResult {
            is_satisfied: canonical.is_satisfied,
            missing_claims: missing,
            satisfied_claims: satisfied,
        }
    }

    /// Get preferred disclosure set (derived attributes over raw values).
    pub fn get_preferred_claims(&self, available_claims: &[String]) -> Vec<String> {
        let mut preferred = Vec::new();

        for claim_name in available_claims {
            // If there's a derived preference, use that instead
            if let Some(derived) = self.policy.derived_attribute_preferences.get(claim_name) {
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

fn selected_claim_name(
    policy: &PresentationPolicy,
    claims: &HashMap<String, serde_json::Value>,
    required: &RequiredClaim,
) -> String {
    if required.accept_predicate && required.required_value.is_none() {
        if let Some(derived) = policy
            .derived_attribute_preferences
            .get(&required.claim_name)
        {
            if claims.contains_key(derived) {
                return derived.clone();
            }
        }
    }
    required.claim_name.clone()
}

/// Result of claim constraint evaluation.
#[derive(Debug, Clone)]
pub struct ClaimEvaluationResult {
    pub is_satisfied: bool,
    pub missing_claims: Vec<String>,
    pub satisfied_claims: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::*;
    use serde_json::json;

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

    fn required_with_value(name: &str, value: serde_json::Value) -> RequiredClaim {
        RequiredClaim {
            claim_name: name.to_string(),
            credential_type: "TestCredential".to_string(),
            accept_predicate: false,
            required_value: Some(value),
        }
    }

    fn required_predicate(name: &str) -> RequiredClaim {
        RequiredClaim {
            accept_predicate: true,
            ..required(name)
        }
    }

    // ====================================================================
    // evaluate()
    // ====================================================================

    #[test]
    fn test_evaluate_empty_policy_always_satisfied() {
        let policy = make_policy(vec![], HashMap::new());
        let evaluator = ClaimConstraintEvaluator::new(&policy);
        let claims = HashMap::new();
        let result = evaluator.evaluate(&claims);
        assert!(result.is_satisfied);
        assert!(result.missing_claims.is_empty());
    }

    #[test]
    fn test_evaluate_all_claims_present() {
        let policy = make_policy(
            vec![required("name"), required("birth_date")],
            HashMap::new(),
        );
        let evaluator = ClaimConstraintEvaluator::new(&policy);
        let mut claims = HashMap::new();
        claims.insert("name".to_string(), json!("Alice"));
        claims.insert("birth_date".to_string(), json!("1990-01-01"));

        let result = evaluator.evaluate(&claims);
        assert!(result.is_satisfied);
        assert_eq!(result.satisfied_claims.len(), 2);
    }

    #[test]
    fn test_evaluate_missing_claim() {
        let policy = make_policy(
            vec![required("name"), required("birth_date")],
            HashMap::new(),
        );
        let evaluator = ClaimConstraintEvaluator::new(&policy);
        let mut claims = HashMap::new();
        claims.insert("name".to_string(), json!("Alice"));

        let result = evaluator.evaluate(&claims);
        assert!(!result.is_satisfied);
        assert_eq!(result.missing_claims, vec!["birth_date"]);
        assert_eq!(result.satisfied_claims, vec!["name"]);
    }

    #[test]
    fn test_evaluate_required_value_match() {
        let policy = make_policy(
            vec![required_with_value("country", json!("US"))],
            HashMap::new(),
        );
        let evaluator = ClaimConstraintEvaluator::new(&policy);
        let mut claims = HashMap::new();
        claims.insert("country".to_string(), json!("US"));

        let result = evaluator.evaluate(&claims);
        assert!(result.is_satisfied);
    }

    #[test]
    fn test_evaluate_required_value_mismatch() {
        let policy = make_policy(
            vec![required_with_value("country", json!("US"))],
            HashMap::new(),
        );
        let evaluator = ClaimConstraintEvaluator::new(&policy);
        let mut claims = HashMap::new();
        claims.insert("country".to_string(), json!("CA"));

        let result = evaluator.evaluate(&claims);
        assert!(!result.is_satisfied);
        assert!(result.missing_claims[0].contains("expected"));
    }

    #[test]
    fn test_evaluate_derived_attribute_preference() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_18".to_string());

        let policy = make_policy(vec![required_predicate("birth_date")], derived);
        let evaluator = ClaimConstraintEvaluator::new(&policy);

        let mut claims = HashMap::new();
        claims.insert("age_over_18".to_string(), json!(true));

        let result = evaluator.evaluate(&claims);
        assert!(result.is_satisfied);
        assert_eq!(result.satisfied_claims, vec!["age_over_18"]);
    }

    #[test]
    fn test_evaluate_derived_fallback_to_direct() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_18".to_string());

        let policy = make_policy(vec![required_predicate("birth_date")], derived);
        let evaluator = ClaimConstraintEvaluator::new(&policy);

        // Derived attr not present, but original is
        let mut claims = HashMap::new();
        claims.insert("birth_date".to_string(), json!("1990-01-01"));

        let result = evaluator.evaluate(&claims);
        assert!(result.is_satisfied);
        assert_eq!(result.satisfied_claims, vec!["birth_date"]);
    }

    #[test]
    fn test_predicate_does_not_satisfy_requirement_when_not_accepted() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_18".to_string());
        let policy = make_policy(vec![required("birth_date")], derived);
        let evaluator = ClaimConstraintEvaluator::new(&policy);
        let claims = [("age_over_18".to_string(), json!(true))]
            .into_iter()
            .collect();

        assert!(!evaluator.evaluate(&claims).is_satisfied);
    }

    #[test]
    fn test_claim_requirement_enforces_credential_type() {
        let policy = make_policy(vec![required("name")], HashMap::new());
        let evaluator = ClaimConstraintEvaluator::new(&policy);
        let claims = [("name".to_string(), json!("Alice"))].into_iter().collect();

        let result =
            evaluator.evaluate_for_credential_types(&claims, &["DifferentCredential".to_string()]);
        assert!(!result.is_satisfied);
        assert!(result.missing_claims[0].contains("TestCredential"));
    }

    // ====================================================================
    // get_preferred_claims()
    // ====================================================================

    #[test]
    fn test_preferred_claims_no_derived() {
        let policy = make_policy(vec![], HashMap::new());
        let evaluator = ClaimConstraintEvaluator::new(&policy);

        let available = vec!["name".to_string(), "birth_date".to_string()];
        let preferred = evaluator.get_preferred_claims(&available);
        assert_eq!(preferred, vec!["name", "birth_date"]);
    }

    #[test]
    fn test_preferred_claims_with_derived() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_21".to_string());

        let policy = make_policy(vec![], derived);
        let evaluator = ClaimConstraintEvaluator::new(&policy);

        let available = vec![
            "name".to_string(),
            "birth_date".to_string(),
            "age_over_21".to_string(),
        ];
        let preferred = evaluator.get_preferred_claims(&available);

        // birth_date should be replaced by age_over_21
        assert!(preferred.contains(&"name".to_string()));
        assert!(preferred.contains(&"age_over_21".to_string()));
        assert!(!preferred.contains(&"birth_date".to_string()));
    }

    #[test]
    fn test_preferred_claims_derived_not_available() {
        let mut derived = HashMap::new();
        derived.insert("birth_date".to_string(), "age_over_21".to_string());

        let policy = make_policy(vec![], derived);
        let evaluator = ClaimConstraintEvaluator::new(&policy);

        // age_over_21 not available → fall back to birth_date
        let available = vec!["name".to_string(), "birth_date".to_string()];
        let preferred = evaluator.get_preferred_claims(&available);
        assert!(preferred.contains(&"birth_date".to_string()));
    }
}
