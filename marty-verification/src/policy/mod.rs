//! Presentation policy evaluation.
//!
//! `service` is the single canonical decision kernel. The older
//! [`PresentationPolicy`] API is retained as a compatibility model and is
//! projected through the same kernel by [`PolicyEvaluator`]. Disclosure and
//! ranking modules are deterministic helpers; they do not make allow/deny
//! decisions.

pub mod claim_evaluator;
mod compat;
pub mod disclosure;
pub mod freshness;
pub mod issuer;
pub mod ranking;
pub mod service;
pub mod types;

pub use compat::PolicyEvaluator;
pub use service::{
    canonical_credential_format, evaluate_service_policy, ServicePolicyError,
    ServicePolicyEvaluationRequest,
};
pub use types::{
    CredentialRankingStrategy, FreshnessRequirements, HolderBindingMethod, PolicyComponent,
    PolicyComponentStatus, PolicyComponentStatusValue, PolicyErrorCode, PolicyEvaluationError,
    PolicyEvaluationInput, PolicyEvaluationRequest, PolicyEvaluationResult, PresentationPolicy,
    RequiredClaim,
};

pub use claim_evaluator::ClaimConstraintEvaluator;
pub use disclosure::MinimumDisclosureResolver;
pub use freshness::FreshnessChecker;
pub use issuer::IssuerConstraintChecker;
pub use ranking::CredentialRanker;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    fn policy() -> PresentationPolicy {
        PresentationPolicy {
            id: "policy-1".to_string(),
            name: "Employee access".to_string(),
            description: None,
            purpose: "Authorize access".to_string(),
            accepted_credential_types: vec!["EmployeeCredential".to_string()],
            required_claims: vec![RequiredClaim {
                claim_name: "birth_date".to_string(),
                credential_type: "EmployeeCredential".to_string(),
                accept_predicate: true,
                required_value: None,
            }],
            holder_binding: HolderBindingMethod::SessionNonce,
            trust_profile_id: Some("workforce".to_string()),
            allowed_issuers: vec!["did:example:issuer".to_string()],
            freshness_requirements: FreshnessRequirements {
                max_credential_age_seconds: Some(100),
                max_proof_age_seconds: 10,
                require_live_revocation_check: true,
            },
            prefer_predicates: true,
            single_presentation: true,
            derived_attribute_preferences: [("birth_date".to_string(), "age_over_18".to_string())]
                .into_iter()
                .collect(),
            credential_ranking_strategy: CredentialRankingStrategy::FreshestFirst,
            credential_ranking_weights: HashMap::new(),
            metadata: HashMap::new(),
            version: 1,
        }
    }

    fn valid_input() -> PolicyEvaluationInput {
        PolicyEvaluationInput {
            credential_types: vec!["EmployeeCredential".to_string()],
            claims: [("age_over_18".to_string(), json!(true))]
                .into_iter()
                .collect(),
            issuer_id: "did:example:issuer".to_string(),
            trust_profile_verified: true,
            issued_at_epoch_seconds: Some(950),
            proof_epoch_seconds: Some(995),
            evaluation_time_epoch_seconds: 1_000,
            holder_binding_verified: true,
            revocation_checked: true,
            not_revoked: Some(true),
            presentation_count: 1,
        }
    }

    #[test]
    fn compatibility_api_uses_canonical_kernel_and_resolves_disclosure() {
        let result = PolicyEvaluator::new(policy()).evaluate(&valid_input());

        assert!(result.is_satisfied);
        assert!(result.errors.is_empty());
        assert_eq!(result.component_statuses.len(), 8);
        assert_eq!(
            result.status(PolicyComponent::ProofFreshness),
            Some(PolicyComponentStatusValue::Passed)
        );
        assert_eq!(result.minimum_disclosure_set, vec!["age_over_18"]);
    }

    #[test]
    fn compatibility_api_fails_closed_for_missing_and_invalid_evidence() {
        let mut input = valid_input();
        input.credential_types = vec!["UnknownCredential".to_string()];
        input.trust_profile_verified = false;
        input.issued_at_epoch_seconds = Some(1_001);
        input.proof_epoch_seconds = None;
        input.holder_binding_verified = false;
        input.revocation_checked = false;
        input.not_revoked = None;
        input.presentation_count = 2;

        let result = PolicyEvaluator::new(policy()).evaluate(&input);
        let codes: Vec<PolicyErrorCode> = result.errors.iter().map(|error| error.code).collect();

        assert!(!result.is_satisfied);
        assert!(codes.contains(&PolicyErrorCode::CredentialTypeNotAccepted));
        assert!(codes.contains(&PolicyErrorCode::IssuerNotTrusted));
        assert!(codes.contains(&PolicyErrorCode::HolderBindingRequired));
        assert!(codes.contains(&PolicyErrorCode::CredentialTimestampFuture));
        assert!(codes.contains(&PolicyErrorCode::ProofTimestampMissing));
        assert!(codes.contains(&PolicyErrorCode::RevocationCheckRequired));
        assert!(codes.contains(&PolicyErrorCode::SinglePresentationRequired));
        assert!(result.minimum_disclosure_set.is_empty());
    }

    #[test]
    fn known_revocation_rejects_without_live_check_requirement() {
        let mut policy = policy();
        policy.freshness_requirements.require_live_revocation_check = false;
        let mut input = valid_input();
        input.revocation_checked = false;
        input.not_revoked = Some(false);

        let result = PolicyEvaluator::new(policy).evaluate(&input);

        assert!(!result.is_satisfied);
        assert!(result
            .errors
            .iter()
            .any(|error| error.code == PolicyErrorCode::CredentialRevoked));
    }
}
