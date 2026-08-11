use super::{
    disclosure::MinimumDisclosureResolver,
    service::{
        evaluate_service_policy, CredentialLifecycleStatus, ServiceAlternativeRequirement,
        ServiceClaimConstraint, ServiceConstraintType, ServiceCredentialRequirement,
        ServiceDecision, ServiceFreshnessPolicy, ServiceHolderBinding, ServicePolicyErrorCode,
        ServicePolicyEvaluationRequest, ServicePolicyViolation, ServicePresentationPolicy,
        ServiceRequestedClaim, VerifiedCredentialFacts,
    },
    types::{
        HolderBindingMethod, PolicyComponent, PolicyComponentStatus, PolicyComponentStatusValue,
        PolicyErrorCode, PolicyEvaluationError, PolicyEvaluationInput, PolicyEvaluationResult,
        PresentationPolicy, RequiredClaim,
    },
};
use std::collections::{BTreeMap, HashMap, HashSet};

const LEGACY_CREDENTIAL_ID: &str = "legacy-policy-credential";
const LEGACY_ANY_TYPE: &str = "__legacy_any_credential_type__";

pub(super) fn neutral_policy() -> PresentationPolicy {
    PresentationPolicy {
        id: "legacy-compatibility-policy".to_string(),
        name: "Legacy compatibility policy".to_string(),
        description: None,
        purpose: "Preserve the legacy helper API through the canonical policy kernel".to_string(),
        accepted_credential_types: Vec::new(),
        required_claims: Vec::new(),
        holder_binding: HolderBindingMethod::None,
        trust_profile_id: None,
        allowed_issuers: Vec::new(),
        freshness_requirements: super::types::FreshnessRequirements {
            max_credential_age_seconds: None,
            max_proof_age_seconds: 300,
            require_live_revocation_check: false,
        },
        prefer_predicates: false,
        single_presentation: false,
        derived_attribute_preferences: HashMap::new(),
        credential_ranking_strategy: super::types::CredentialRankingStrategy::FreshestFirst,
        credential_ranking_weights: HashMap::new(),
        metadata: HashMap::new(),
        version: 1,
    }
}

pub(super) fn neutral_input() -> PolicyEvaluationInput {
    PolicyEvaluationInput {
        credential_types: Vec::new(),
        claims: HashMap::new(),
        issuer_id: "legacy:compatibility-issuer".to_string(),
        trust_profile_verified: true,
        issued_at_epoch_seconds: None,
        proof_epoch_seconds: None,
        evaluation_time_epoch_seconds: 0,
        holder_binding_verified: false,
        revocation_checked: false,
        not_revoked: None,
        presentation_count: 1,
    }
}

/// Compatibility projection for the original wallet-facing policy model.
///
/// This type does not implement policy decisions. It maps the legacy DTO to
/// [`evaluate_service_policy`] and projects the canonical result back to the
/// stable legacy response shape.
pub struct PolicyEvaluator {
    policy: PresentationPolicy,
}

impl PolicyEvaluator {
    pub fn new(policy: PresentationPolicy) -> Self {
        Self { policy }
    }

    pub fn evaluate(&self, input: &PolicyEvaluationInput) -> PolicyEvaluationResult {
        let projection = LegacyProjection::new(&self.policy, input);
        let canonical = match evaluate_service_policy(projection.request.clone()) {
            Ok(result) => result,
            Err(error) => return invalid_policy_result(&self.policy, input, &error.to_string()),
        };

        let missing_claims = projection.missing_claims(&canonical.errors);
        let errors = projection.map_errors(&canonical.errors, &missing_claims);
        let is_satisfied = canonical.decision == ServiceDecision::Allow;
        let component_statuses = component_statuses(&self.policy, input, &errors);
        let issuer_violations = errors
            .iter()
            .filter(|error| error.component == PolicyComponent::Issuer)
            .map(|error| error.message.clone())
            .collect();
        let freshness_violations = errors
            .iter()
            .filter(|error| {
                matches!(
                    error.component,
                    PolicyComponent::CredentialFreshness | PolicyComponent::ProofFreshness
                )
            })
            .map(|error| error.message.clone())
            .collect();
        let minimum_disclosure_set = if is_satisfied {
            let mut available: Vec<String> = input.claims.keys().cloned().collect();
            available.sort();
            MinimumDisclosureResolver::new(&self.policy)
                .resolve(&available)
                .claims
        } else {
            Vec::new()
        };

        PolicyEvaluationResult {
            is_satisfied,
            component_statuses,
            errors,
            warnings: canonical.warnings,
            missing_claims,
            issuer_violations,
            freshness_violations,
            minimum_disclosure_set,
        }
    }
}

struct LegacyProjection<'a> {
    policy: &'a PresentationPolicy,
    input: &'a PolicyEvaluationInput,
    request: ServicePolicyEvaluationRequest,
    claim_requirements: BTreeMap<String, &'a RequiredClaim>,
}

impl<'a> LegacyProjection<'a> {
    fn new(policy: &'a PresentationPolicy, input: &'a PolicyEvaluationInput) -> Self {
        let mut claim_requirements = BTreeMap::new();
        let mut credential_requirements = vec![empty_requirement(
            "legacy-global-facts",
            LEGACY_ANY_TYPE.to_string(),
        )];
        credential_requirements.extend(policy.required_claims.iter().enumerate().map(
            |(index, claim)| {
                let id = format!("legacy-claim-{index}");
                claim_requirements.insert(id.clone(), claim);
                claim_requirement(&id, claim, policy, input)
            },
        ));
        let alternative_requirements = if policy.accepted_credential_types.is_empty() {
            Vec::new()
        } else {
            vec![ServiceAlternativeRequirement {
                id: "legacy-accepted-types".to_string(),
                name: "Accepted credential type".to_string(),
                credential_requirements: policy
                    .accepted_credential_types
                    .iter()
                    .enumerate()
                    .map(|(index, credential_type)| {
                        empty_requirement(
                            &format!("legacy-accepted-{index}"),
                            credential_type.clone(),
                        )
                    })
                    .collect(),
                min_satisfied: 1,
            }]
        };
        let holder_method = holder_method(policy.holder_binding);
        let holder_required = policy.holder_binding != HolderBindingMethod::None;
        let mut credential_template_ids = input.credential_types.clone();
        credential_template_ids.push(LEGACY_ANY_TYPE.to_string());
        credential_template_ids.sort();
        credential_template_ids.dedup();

        let request = ServicePolicyEvaluationRequest {
            policy: ServicePresentationPolicy {
                id: policy.id.clone(),
                name: policy.name.clone(),
                organization_id: "legacy-policy-compatibility".to_string(),
                credential_requirements,
                alternative_requirements,
                trust_profile_id: policy.trust_profile_id.clone(),
                holder_binding: ServiceHolderBinding {
                    required: holder_required,
                    binding_methods: holder_method.iter().cloned().collect(),
                    proof_profiles: Vec::new(),
                    challenge_required: false,
                    audience_binding_required: false,
                    replay_detection_required: false,
                    max_proof_age_seconds: holder_required
                        .then_some(policy.freshness_requirements.max_proof_age_seconds),
                },
                freshness: Some(ServiceFreshnessPolicy {
                    max_age_seconds: policy.freshness_requirements.max_credential_age_seconds,
                    require_not_revoked: policy
                        .freshness_requirements
                        .require_live_revocation_check,
                    revocation_grace_seconds: None,
                }),
                issuer_constraints: None,
                allowed_issuers: policy.allowed_issuers.clone(),
                single_presentation: policy.single_presentation,
            },
            credentials: vec![VerifiedCredentialFacts {
                credential_id: LEGACY_CREDENTIAL_ID.to_string(),
                credential_template_ids,
                credential_format: "legacy-policy-facts".to_string(),
                claims: input.claims.clone(),
                issuer_id: input.issuer_id.clone(),
                signature_verified: true,
                signature_failure_reason: None,
                trust_profile_verified: input.trust_profile_verified,
                trust_failure_reason: None,
                trust_level: None,
                compliance_statuses: Vec::new(),
                accreditations: Vec::new(),
                issued_at_epoch_seconds: input.issued_at_epoch_seconds,
                revocation_checked_at_epoch_seconds: input
                    .revocation_checked
                    .then_some(input.evaluation_time_epoch_seconds),
                not_revoked: input.not_revoked,
                credential_status: input.not_revoked.and_then(|not_revoked| {
                    (!not_revoked).then_some(CredentialLifecycleStatus::Revoked)
                }),
                warnings: Vec::new(),
            }],
            evaluation_time_epoch_seconds: input.evaluation_time_epoch_seconds,
            holder_binding_verified: input.holder_binding_verified,
            holder_binding_method: input
                .holder_binding_verified
                .then_some(holder_method)
                .flatten(),
            proof_profile: None,
            challenge_verified: false,
            audience_verified: false,
            replay_check_verified: false,
            proof_epoch_seconds: input.proof_epoch_seconds,
            external_authorization: None,
            presentation_count: Some(input.presentation_count),
        };

        Self {
            policy,
            input,
            request,
            claim_requirements,
        }
    }

    fn missing_claims(&self, violations: &[ServicePolicyViolation]) -> Vec<String> {
        let failed: HashSet<&str> = violations
            .iter()
            .filter(|violation| {
                matches!(
                    violation.code,
                    ServicePolicyErrorCode::ClaimMissing
                        | ServicePolicyErrorCode::ClaimConstraintFailed
                        | ServicePolicyErrorCode::CredentialMissing
                )
            })
            .filter_map(|violation| violation.requirement_id.as_deref())
            .collect();
        self.claim_requirements
            .iter()
            .filter(|(id, _)| failed.contains(id.as_str()))
            .map(|(_, claim)| missing_claim_message(self.policy, self.input, claim))
            .collect()
    }

    fn map_errors(
        &self,
        violations: &[ServicePolicyViolation],
        missing_claims: &[String],
    ) -> Vec<PolicyEvaluationError> {
        let mut output = Vec::new();
        let mut seen = HashSet::new();
        for violation in violations {
            let mapped = self.map_error(violation, missing_claims);
            let Some(error) = mapped else { continue };
            let key = (error.code, error.component, error.message.clone());
            if seen.insert(key) {
                output.push(error);
            }
        }
        output
    }

    fn map_error(
        &self,
        violation: &ServicePolicyViolation,
        missing_claims: &[String],
    ) -> Option<PolicyEvaluationError> {
        use ServicePolicyErrorCode as ServiceCode;
        let (code, component, message) = match violation.code {
            ServiceCode::CredentialMissing
                if violation
                    .requirement_id
                    .as_deref()
                    .is_some_and(|id| id.starts_with("legacy-accepted-")) =>
            {
                (
                    PolicyErrorCode::CredentialTypeNotAccepted,
                    PolicyComponent::CredentialType,
                    "Presented credential type is not accepted by the policy".to_string(),
                )
            }
            ServiceCode::AlternativeRequirementFailed => (
                PolicyErrorCode::CredentialTypeNotAccepted,
                PolicyComponent::CredentialType,
                "Presented credential type is not accepted by the policy".to_string(),
            ),
            ServiceCode::CredentialMissing
            | ServiceCode::ClaimMissing
            | ServiceCode::ClaimConstraintFailed => {
                let id = violation.requirement_id.as_deref()?;
                if !id.starts_with("legacy-claim-") {
                    return None;
                }
                let message = self
                    .claim_requirements
                    .get(id)
                    .map(|claim| missing_claim_message(self.policy, self.input, claim))
                    .or_else(|| missing_claims.first().cloned())
                    .unwrap_or_else(|| "Required claim is not satisfied".to_string());
                (
                    PolicyErrorCode::ClaimRequirementNotSatisfied,
                    PolicyComponent::Claims,
                    format!("Claim requirement not satisfied: {message}"),
                )
            }
            ServiceCode::IssuerNotAllowed => (
                PolicyErrorCode::IssuerNotAllowed,
                PolicyComponent::Issuer,
                format!(
                    "Issuer '{}' not in allowed issuers list",
                    self.input.issuer_id
                ),
            ),
            ServiceCode::TrustProfileNotVerified => (
                PolicyErrorCode::IssuerNotTrusted,
                PolicyComponent::Issuer,
                format!(
                    "Issuer '{}' not verified against trust profile",
                    self.input.issuer_id
                ),
            ),
            ServiceCode::HolderBindingRequired
            | ServiceCode::HolderBindingMethodNotAllowed
            | ServiceCode::ProofProfileNotAllowed
            | ServiceCode::ChallengeBindingRequired
            | ServiceCode::AudienceBindingRequired
            | ServiceCode::ReplayDetectionRequired => (
                PolicyErrorCode::HolderBindingRequired,
                PolicyComponent::HolderBinding,
                format!(
                    "Required {:?} holder binding was not verified",
                    self.policy.holder_binding
                ),
            ),
            ServiceCode::CredentialTimestampMissing => (
                PolicyErrorCode::CredentialTimestampMissing,
                PolicyComponent::CredentialFreshness,
                "Credential issuance time is required by the policy".to_string(),
            ),
            ServiceCode::CredentialStale => (
                PolicyErrorCode::CredentialStale,
                PolicyComponent::CredentialFreshness,
                credential_stale_message(self.policy, self.input),
            ),
            ServiceCode::CredentialTimestampFuture => (
                PolicyErrorCode::CredentialTimestampFuture,
                PolicyComponent::CredentialFreshness,
                "Credential issuance time is after evaluation time".to_string(),
            ),
            ServiceCode::ProofTimestampMissing => (
                PolicyErrorCode::ProofTimestampMissing,
                PolicyComponent::ProofFreshness,
                "Proof time is required for holder-bound presentations".to_string(),
            ),
            ServiceCode::ProofStale => (
                PolicyErrorCode::ProofStale,
                PolicyComponent::ProofFreshness,
                proof_stale_message(self.policy, self.input),
            ),
            ServiceCode::ProofTimestampFuture => (
                PolicyErrorCode::ProofTimestampFuture,
                PolicyComponent::ProofFreshness,
                "Proof time is after evaluation time".to_string(),
            ),
            ServiceCode::RevocationCheckRequired | ServiceCode::RevocationEvidenceStale => (
                PolicyErrorCode::RevocationCheckRequired,
                PolicyComponent::Revocation,
                "A live revocation check is required by the policy".to_string(),
            ),
            ServiceCode::RevocationStatusUnknown => (
                PolicyErrorCode::RevocationStatusUnknown,
                PolicyComponent::Revocation,
                "Revocation status is unknown".to_string(),
            ),
            ServiceCode::CredentialRevoked => (
                PolicyErrorCode::CredentialRevoked,
                PolicyComponent::Revocation,
                "Credential is revoked".to_string(),
            ),
            ServiceCode::SinglePresentationRequired => (
                PolicyErrorCode::SinglePresentationRequired,
                PolicyComponent::PresentationCount,
                format!(
                    "Policy requires exactly one presentation, received {}",
                    self.input.presentation_count
                ),
            ),
            ServiceCode::SignatureInvalid
            | ServiceCode::CredentialFormatMismatch
            | ServiceCode::IssuerTrustLevelInsufficient
            | ServiceCode::IssuerComplianceStatusMissing
            | ServiceCode::IssuerAccreditationMissing
            | ServiceCode::ExternalAuthorizationDenied
            | ServiceCode::ExternalAuthorizationNotEvaluated
            | ServiceCode::ConflictingVerifiedClaim => (
                PolicyErrorCode::InvalidPolicy,
                PolicyComponent::Claims,
                violation.message.clone(),
            ),
        };
        Some(PolicyEvaluationError {
            code,
            component,
            message,
        })
    }
}

fn empty_requirement(id: &str, credential_type: String) -> ServiceCredentialRequirement {
    ServiceCredentialRequirement {
        id: id.to_string(),
        credential_template_id: credential_type,
        required: true,
        credential_payload_format: None,
        requested_claims: Vec::new(),
        trust_profile_id: None,
        max_age_seconds: None,
        require_fresh_issuance: false,
    }
}

fn claim_requirement(
    id: &str,
    claim: &RequiredClaim,
    policy: &PresentationPolicy,
    input: &PolicyEvaluationInput,
) -> ServiceCredentialRequirement {
    let claim_name = selected_claim_name(policy, input, claim);
    let constraint = match &claim.required_value {
        Some(value) => ServiceClaimConstraint {
            claim_name: claim_name.clone(),
            constraint_type: ServiceConstraintType::Equals,
            value: Some(value.clone()),
        },
        None => ServiceClaimConstraint {
            claim_name: claim_name.clone(),
            constraint_type: ServiceConstraintType::Presence,
            value: None,
        },
    };
    ServiceCredentialRequirement {
        id: id.to_string(),
        credential_template_id: claim.credential_type.clone(),
        required: true,
        credential_payload_format: None,
        requested_claims: vec![ServiceRequestedClaim {
            claim_name,
            required: true,
            selective_disclosure: true,
            accept_derived: claim.accept_predicate,
            predicate_spec: None,
            constraints: vec![constraint],
        }],
        trust_profile_id: None,
        max_age_seconds: None,
        require_fresh_issuance: false,
    }
}

fn selected_claim_name(
    policy: &PresentationPolicy,
    input: &PolicyEvaluationInput,
    claim: &RequiredClaim,
) -> String {
    if claim.accept_predicate && claim.required_value.is_none() {
        if let Some(derived) = policy.derived_attribute_preferences.get(&claim.claim_name) {
            if input.claims.contains_key(derived) {
                return derived.clone();
            }
        }
    }
    claim.claim_name.clone()
}

fn missing_claim_message(
    policy: &PresentationPolicy,
    input: &PolicyEvaluationInput,
    claim: &RequiredClaim,
) -> String {
    if !claim.credential_type.is_empty() && !input.credential_types.contains(&claim.credential_type)
    {
        return format!(
            "{} (requires credential type {})",
            claim.claim_name, claim.credential_type
        );
    }
    let selected = selected_claim_name(policy, input, claim);
    match (input.claims.get(&selected), claim.required_value.as_ref()) {
        (Some(actual), Some(expected)) if actual != expected => format!(
            "{} (expected {}, got {})",
            claim.claim_name, expected, actual
        ),
        _ => claim.claim_name.clone(),
    }
}

fn holder_method(method: HolderBindingMethod) -> Option<String> {
    match method {
        HolderBindingMethod::DeviceKey => Some("device_key".to_string()),
        HolderBindingMethod::SessionNonce => Some("session_nonce".to_string()),
        HolderBindingMethod::Biometric => Some("biometric".to_string()),
        HolderBindingMethod::None => None,
    }
}

fn credential_stale_message(policy: &PresentationPolicy, input: &PolicyEvaluationInput) -> String {
    match (
        input.issued_at_epoch_seconds,
        policy.freshness_requirements.max_credential_age_seconds,
    ) {
        (Some(issued_at), Some(maximum)) if issued_at <= input.evaluation_time_epoch_seconds => {
            format!(
                "Credential is {} seconds old, maximum allowed is {}",
                input.evaluation_time_epoch_seconds - issued_at,
                maximum
            )
        }
        _ => "Credential is older than the policy permits".to_string(),
    }
}

fn proof_stale_message(policy: &PresentationPolicy, input: &PolicyEvaluationInput) -> String {
    match input.proof_epoch_seconds {
        Some(proof_time) if proof_time <= input.evaluation_time_epoch_seconds => format!(
            "Proof is {} seconds old, maximum allowed is {}",
            input.evaluation_time_epoch_seconds - proof_time,
            policy.freshness_requirements.max_proof_age_seconds
        ),
        _ => "Proof is older than the policy permits".to_string(),
    }
}

fn component_statuses(
    policy: &PresentationPolicy,
    input: &PolicyEvaluationInput,
    errors: &[PolicyEvaluationError],
) -> Vec<PolicyComponentStatus> {
    let components = [
        (
            PolicyComponent::CredentialType,
            !policy.accepted_credential_types.is_empty(),
        ),
        (PolicyComponent::Claims, true),
        (
            PolicyComponent::Issuer,
            policy.trust_profile_id.is_some() || !policy.allowed_issuers.is_empty(),
        ),
        (
            PolicyComponent::HolderBinding,
            policy.holder_binding != HolderBindingMethod::None,
        ),
        (
            PolicyComponent::CredentialFreshness,
            policy
                .freshness_requirements
                .max_credential_age_seconds
                .is_some()
                || input
                    .issued_at_epoch_seconds
                    .is_some_and(|issued_at| issued_at > input.evaluation_time_epoch_seconds),
        ),
        (
            PolicyComponent::ProofFreshness,
            policy.holder_binding != HolderBindingMethod::None,
        ),
        (
            PolicyComponent::Revocation,
            policy.freshness_requirements.require_live_revocation_check
                || input.not_revoked.is_some(),
        ),
        (
            PolicyComponent::PresentationCount,
            policy.single_presentation,
        ),
    ];
    components
        .into_iter()
        .map(|(component, applicable)| PolicyComponentStatus {
            component,
            status: if errors.iter().any(|error| error.component == component) {
                PolicyComponentStatusValue::Failed
            } else if applicable {
                PolicyComponentStatusValue::Passed
            } else {
                PolicyComponentStatusValue::NotApplicable
            },
        })
        .collect()
}

fn invalid_policy_result(
    policy: &PresentationPolicy,
    input: &PolicyEvaluationInput,
    message: &str,
) -> PolicyEvaluationResult {
    let error = PolicyEvaluationError {
        code: PolicyErrorCode::InvalidPolicy,
        component: PolicyComponent::Claims,
        message: message.to_string(),
    };
    PolicyEvaluationResult {
        is_satisfied: false,
        component_statuses: component_statuses(policy, input, std::slice::from_ref(&error)),
        errors: vec![error],
        warnings: Vec::new(),
        missing_claims: Vec::new(),
        issuer_violations: Vec::new(),
        freshness_violations: Vec::new(),
        minimum_disclosure_set: Vec::new(),
    }
}
