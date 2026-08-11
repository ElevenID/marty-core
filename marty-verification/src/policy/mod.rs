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
pub mod service;
pub mod types;

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

/// Policy evaluator that orchestrates all constraint checks.
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

    /// Evaluate verified presentation facts against this policy.
    pub fn evaluate(&self, input: &PolicyEvaluationInput) -> PolicyEvaluationResult {
        let mut statuses = Vec::new();
        let mut errors = Vec::new();
        let mut missing_claims = Vec::new();
        let mut issuer_violations = Vec::new();
        let mut freshness_violations = Vec::new();

        let credential_type_status = if self.policy.accepted_credential_types.is_empty() {
            PolicyComponentStatusValue::NotApplicable
        } else if input.credential_types.iter().any(|credential_type| {
            self.policy
                .accepted_credential_types
                .contains(credential_type)
        }) {
            PolicyComponentStatusValue::Passed
        } else {
            errors.push(PolicyEvaluationError {
                code: PolicyErrorCode::CredentialTypeNotAccepted,
                component: PolicyComponent::CredentialType,
                message: "Presented credential type is not accepted by the policy".to_string(),
            });
            PolicyComponentStatusValue::Failed
        };
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::CredentialType,
            status: credential_type_status,
        });

        let claim_result = self
            .claim_evaluator
            .evaluate_for_credential_types(&input.claims, &input.credential_types);
        missing_claims.extend(claim_result.missing_claims.clone());
        for message in &claim_result.missing_claims {
            errors.push(PolicyEvaluationError {
                code: PolicyErrorCode::ClaimRequirementNotSatisfied,
                component: PolicyComponent::Claims,
                message: format!("Claim requirement not satisfied: {message}"),
            });
        }
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::Claims,
            status: if claim_result.is_satisfied {
                PolicyComponentStatusValue::Passed
            } else {
                PolicyComponentStatusValue::Failed
            },
        });

        let issuer_result = self
            .issuer_checker
            .check_issuer(&input.issuer_id, input.trust_profile_verified);
        let issuer_status = match issuer_result {
            issuer::IssuerCheckResult::Trusted if self.issuer_checker.has_constraints() => {
                PolicyComponentStatusValue::Passed
            }
            issuer::IssuerCheckResult::Trusted => PolicyComponentStatusValue::NotApplicable,
            issuer::IssuerCheckResult::NotAllowed(message) => {
                issuer_violations.push(message.clone());
                errors.push(PolicyEvaluationError {
                    code: PolicyErrorCode::IssuerNotAllowed,
                    component: PolicyComponent::Issuer,
                    message,
                });
                PolicyComponentStatusValue::Failed
            }
            issuer::IssuerCheckResult::NotTrusted(message) => {
                issuer_violations.push(message.clone());
                errors.push(PolicyEvaluationError {
                    code: PolicyErrorCode::IssuerNotTrusted,
                    component: PolicyComponent::Issuer,
                    message,
                });
                PolicyComponentStatusValue::Failed
            }
        };
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::Issuer,
            status: issuer_status,
        });

        let holder_binding_status = if self.policy.holder_binding == HolderBindingMethod::None {
            PolicyComponentStatusValue::NotApplicable
        } else if input.holder_binding_verified {
            PolicyComponentStatusValue::Passed
        } else {
            errors.push(PolicyEvaluationError {
                code: PolicyErrorCode::HolderBindingRequired,
                component: PolicyComponent::HolderBinding,
                message: format!(
                    "Required {:?} holder binding was not verified",
                    self.policy.holder_binding
                ),
            });
            PolicyComponentStatusValue::Failed
        };
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::HolderBinding,
            status: holder_binding_status,
        });

        let credential_freshness_status = match input.issued_at_epoch_seconds {
            Some(issued_at) => match self
                .freshness_checker
                .check_credential_age(issued_at, input.evaluation_time_epoch_seconds)
            {
                freshness::FreshnessCheckResult::Fresh => {
                    if self
                        .policy
                        .freshness_requirements
                        .max_credential_age_seconds
                        .is_some()
                    {
                        PolicyComponentStatusValue::Passed
                    } else {
                        PolicyComponentStatusValue::NotApplicable
                    }
                }
                freshness::FreshnessCheckResult::Stale(message) => {
                    freshness_violations.push(message.clone());
                    errors.push(PolicyEvaluationError {
                        code: PolicyErrorCode::CredentialStale,
                        component: PolicyComponent::CredentialFreshness,
                        message,
                    });
                    PolicyComponentStatusValue::Failed
                }
                freshness::FreshnessCheckResult::InvalidFuture(message) => {
                    freshness_violations.push(message.clone());
                    errors.push(PolicyEvaluationError {
                        code: PolicyErrorCode::CredentialTimestampFuture,
                        component: PolicyComponent::CredentialFreshness,
                        message,
                    });
                    PolicyComponentStatusValue::Failed
                }
            },
            None if self
                .policy
                .freshness_requirements
                .max_credential_age_seconds
                .is_some() =>
            {
                let message = "Credential issuance time is required by the policy".to_string();
                freshness_violations.push(message.clone());
                errors.push(PolicyEvaluationError {
                    code: PolicyErrorCode::CredentialTimestampMissing,
                    component: PolicyComponent::CredentialFreshness,
                    message,
                });
                PolicyComponentStatusValue::Failed
            }
            None => PolicyComponentStatusValue::NotApplicable,
        };
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::CredentialFreshness,
            status: credential_freshness_status,
        });

        let proof_freshness_status = if self.policy.holder_binding == HolderBindingMethod::None {
            PolicyComponentStatusValue::NotApplicable
        } else {
            match input.proof_epoch_seconds {
                Some(proof_time) => match self
                    .freshness_checker
                    .check_proof_age(proof_time, input.evaluation_time_epoch_seconds)
                {
                    freshness::FreshnessCheckResult::Fresh => PolicyComponentStatusValue::Passed,
                    freshness::FreshnessCheckResult::Stale(message) => {
                        freshness_violations.push(message.clone());
                        errors.push(PolicyEvaluationError {
                            code: PolicyErrorCode::ProofStale,
                            component: PolicyComponent::ProofFreshness,
                            message,
                        });
                        PolicyComponentStatusValue::Failed
                    }
                    freshness::FreshnessCheckResult::InvalidFuture(message) => {
                        freshness_violations.push(message.clone());
                        errors.push(PolicyEvaluationError {
                            code: PolicyErrorCode::ProofTimestampFuture,
                            component: PolicyComponent::ProofFreshness,
                            message,
                        });
                        PolicyComponentStatusValue::Failed
                    }
                },
                None => {
                    let message =
                        "Proof time is required for holder-bound presentations".to_string();
                    freshness_violations.push(message.clone());
                    errors.push(PolicyEvaluationError {
                        code: PolicyErrorCode::ProofTimestampMissing,
                        component: PolicyComponent::ProofFreshness,
                        message,
                    });
                    PolicyComponentStatusValue::Failed
                }
            }
        };
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::ProofFreshness,
            status: proof_freshness_status,
        });

        let revocation_status = if input.not_revoked == Some(false) {
            errors.push(PolicyEvaluationError {
                code: PolicyErrorCode::CredentialRevoked,
                component: PolicyComponent::Revocation,
                message: "Credential is revoked".to_string(),
            });
            PolicyComponentStatusValue::Failed
        } else if self.freshness_checker.requires_live_revocation_check()
            && !input.revocation_checked
        {
            errors.push(PolicyEvaluationError {
                code: PolicyErrorCode::RevocationCheckRequired,
                component: PolicyComponent::Revocation,
                message: "A live revocation check is required by the policy".to_string(),
            });
            PolicyComponentStatusValue::Failed
        } else if self.freshness_checker.requires_live_revocation_check()
            && input.not_revoked.is_none()
        {
            errors.push(PolicyEvaluationError {
                code: PolicyErrorCode::RevocationStatusUnknown,
                component: PolicyComponent::Revocation,
                message: "Revocation status is unknown".to_string(),
            });
            PolicyComponentStatusValue::Failed
        } else if input.not_revoked == Some(true) {
            PolicyComponentStatusValue::Passed
        } else {
            PolicyComponentStatusValue::NotApplicable
        };
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::Revocation,
            status: revocation_status,
        });

        let presentation_count_status = if !self.policy.single_presentation {
            PolicyComponentStatusValue::NotApplicable
        } else if input.presentation_count == 1 {
            PolicyComponentStatusValue::Passed
        } else {
            errors.push(PolicyEvaluationError {
                code: PolicyErrorCode::SinglePresentationRequired,
                component: PolicyComponent::PresentationCount,
                message: format!(
                    "Policy requires exactly one presentation, received {}",
                    input.presentation_count
                ),
            });
            PolicyComponentStatusValue::Failed
        };
        statuses.push(PolicyComponentStatus {
            component: PolicyComponent::PresentationCount,
            status: presentation_count_status,
        });

        let mut available_claims: Vec<String> = input.claims.keys().cloned().collect();
        available_claims.sort();
        let disclosure = self.disclosure_resolver.resolve(&available_claims);
        let is_satisfied = errors.is_empty();

        PolicyEvaluationResult {
            is_satisfied,
            component_statuses: statuses,
            errors,
            warnings: Vec::new(),
            missing_claims,
            issuer_violations,
            freshness_violations,
            minimum_disclosure_set: if is_satisfied {
                disclosure.claims
            } else {
                Vec::new()
            },
        }
    }
}

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
    fn evaluates_all_components_and_resolves_minimum_disclosure() {
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
    fn fails_closed_for_missing_and_invalid_evidence() {
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
    fn known_revocation_rejects_even_without_live_check_requirement() {
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
