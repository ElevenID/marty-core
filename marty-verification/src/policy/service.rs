//! Service-level presentation policy evaluation.
//!
//! Protocol verifiers and external services resolve signatures, trust profiles,
//! status records, and authorization policy before calling this deterministic
//! kernel. The kernel owns the final presentation-policy decision.

use chrono::{DateTime, Datelike, NaiveDate};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use thiserror::Error;

const MAX_CREDENTIALS: usize = 128;
const MAX_REQUIREMENTS: usize = 128;
const MAX_CLAIMS_PER_REQUIREMENT: usize = 256;
const MAX_CLAIMS_PER_CREDENTIAL: usize = 1_024;
const MAX_STRING_LENGTH: usize = 4_096;
const MAX_REGEX_LENGTH: usize = 4_096;
const MAX_VALUE_BYTES: usize = 65_536;
const MAX_LIST_ITEMS: usize = 256;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServicePolicyError {
    #[error("invalid service policy request: {0}")]
    InvalidRequest(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyEvaluationRequest {
    pub policy: ServicePresentationPolicy,
    pub credentials: Vec<VerifiedCredentialFacts>,
    pub evaluation_time_epoch_seconds: u64,
    pub holder_binding_verified: bool,
    pub holder_binding_method: Option<String>,
    pub proof_profile: Option<String>,
    pub challenge_verified: bool,
    pub audience_verified: bool,
    pub replay_check_verified: bool,
    pub proof_epoch_seconds: Option<u64>,
    pub external_authorization: Option<ExternalAuthorizationFacts>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePresentationPolicy {
    pub id: String,
    pub name: String,
    pub organization_id: String,
    pub credential_requirements: Vec<ServiceCredentialRequirement>,
    pub alternative_requirements: Vec<ServiceAlternativeRequirement>,
    pub trust_profile_id: Option<String>,
    pub holder_binding: ServiceHolderBinding,
    pub freshness: Option<ServiceFreshnessPolicy>,
    pub issuer_constraints: Option<ServiceIssuerConstraints>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServiceHolderBinding {
    pub required: bool,
    pub binding_methods: Vec<String>,
    pub proof_profiles: Vec<String>,
    pub challenge_required: bool,
    pub audience_binding_required: bool,
    pub replay_detection_required: bool,
    pub max_proof_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceFreshnessPolicy {
    pub max_age_seconds: Option<u64>,
    pub require_not_revoked: bool,
    pub revocation_grace_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceIssuerConstraints {
    pub min_trust_level: Option<u32>,
    pub required_compliance_statuses: Vec<String>,
    pub required_accreditations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCredentialRequirement {
    pub id: String,
    pub credential_template_id: String,
    pub required: bool,
    pub credential_payload_format: Option<String>,
    pub requested_claims: Vec<ServiceRequestedClaim>,
    pub trust_profile_id: Option<String>,
    pub max_age_seconds: Option<u64>,
    pub require_fresh_issuance: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAlternativeRequirement {
    pub id: String,
    pub name: String,
    pub credential_requirements: Vec<ServiceCredentialRequirement>,
    pub min_satisfied: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequestedClaim {
    pub claim_name: String,
    pub required: bool,
    pub selective_disclosure: bool,
    pub accept_derived: bool,
    pub predicate_spec: Option<Value>,
    pub constraints: Vec<ServiceClaimConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceClaimConstraint {
    pub claim_name: String,
    pub constraint_type: ServiceConstraintType,
    pub value: Option<Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceConstraintType {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    GreaterOrEqual,
    LessOrEqual,
    InSet,
    NotInSet,
    Presence,
    Regex,
    AgeOver,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedCredentialFacts {
    pub credential_id: String,
    pub credential_template_ids: Vec<String>,
    pub credential_format: String,
    pub claims: HashMap<String, Value>,
    pub issuer_id: String,
    pub signature_verified: bool,
    pub signature_failure_reason: Option<String>,
    pub trust_profile_verified: bool,
    pub trust_failure_reason: Option<String>,
    pub trust_level: Option<u32>,
    pub compliance_statuses: Vec<String>,
    pub accreditations: Vec<String>,
    pub issued_at_epoch_seconds: Option<u64>,
    pub revocation_checked_at_epoch_seconds: Option<u64>,
    pub not_revoked: Option<bool>,
    pub credential_status: Option<CredentialLifecycleStatus>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialLifecycleStatus {
    Active,
    Revoked,
    Suspended,
    Expired,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuthorizationFacts {
    pub evaluated: bool,
    pub allowed: bool,
    pub reasons: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceEvaluationOutcome {
    Passed,
    Failed,
    Partial,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceDecision {
    Allow,
    Deny,
    ManualReview,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServicePolicyErrorCode {
    CredentialMissing,
    SignatureInvalid,
    CredentialFormatMismatch,
    TrustProfileNotVerified,
    IssuerTrustLevelInsufficient,
    IssuerComplianceStatusMissing,
    IssuerAccreditationMissing,
    CredentialTimestampMissing,
    CredentialTimestampFuture,
    CredentialStale,
    ProofTimestampMissing,
    ProofTimestampFuture,
    ProofStale,
    RevocationCheckRequired,
    RevocationEvidenceStale,
    RevocationStatusUnknown,
    CredentialRevoked,
    ClaimMissing,
    ClaimConstraintFailed,
    AlternativeRequirementFailed,
    HolderBindingRequired,
    HolderBindingMethodNotAllowed,
    ProofProfileNotAllowed,
    ChallengeBindingRequired,
    AudienceBindingRequired,
    ReplayDetectionRequired,
    ExternalAuthorizationDenied,
    ExternalAuthorizationNotEvaluated,
    ConflictingVerifiedClaim,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServicePolicyViolation {
    pub code: ServicePolicyErrorCode,
    pub requirement_id: Option<String>,
    pub credential_id: Option<String>,
    pub claim_name: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConstraintResult {
    pub constraint_type: ServiceConstraintType,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceClaimResult {
    pub claim_name: String,
    pub satisfied: bool,
    pub presented_value: Option<Value>,
    pub constraint_results: Vec<ServiceConstraintResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCredentialResult {
    pub requirement_id: String,
    pub credential_template_id: String,
    pub credential_id: Option<String>,
    pub issuer_id: Option<String>,
    pub satisfied: bool,
    pub claim_results: Vec<ServiceClaimResult>,
    pub errors: Vec<ServicePolicyViolation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAlternativeResult {
    pub alternative_id: String,
    pub name: String,
    pub satisfied: bool,
    pub min_satisfied: usize,
    pub satisfied_count: usize,
    pub credential_results: Vec<ServiceCredentialResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePolicyEvaluationResult {
    pub result: ServiceEvaluationOutcome,
    pub decision: ServiceDecision,
    pub decision_reason: String,
    pub policy_id: String,
    pub policy_name: String,
    pub credential_results: Vec<ServiceCredentialResult>,
    pub alternative_results: Vec<ServiceAlternativeResult>,
    pub total_requirements: usize,
    pub satisfied_requirements: usize,
    pub required_satisfied: usize,
    pub required_total: usize,
    pub verified_claims: BTreeMap<String, Value>,
    pub errors: Vec<ServicePolicyViolation>,
    pub warnings: Vec<String>,
    pub evaluation_time_epoch_seconds: u64,
}

pub fn evaluate_service_policy(
    request: ServicePolicyEvaluationRequest,
) -> Result<ServicePolicyEvaluationResult, ServicePolicyError> {
    validate_request(&request)?;

    let mut credentials = request.credentials;
    credentials.sort_by(|left, right| left.credential_id.cmp(&right.credential_id));
    let mut direct_results = Vec::new();
    let mut alternative_results = Vec::new();
    let mut required_total = 0usize;
    let mut required_satisfied = 0usize;
    let mut verified_claims = BTreeMap::new();
    let mut aggregation_errors = Vec::new();

    for requirement in &request.policy.credential_requirements {
        let result = evaluate_requirement(
            requirement,
            &request.policy,
            &credentials,
            request.evaluation_time_epoch_seconds,
        );
        if requirement.required {
            required_total += 1;
            if result.satisfied {
                required_satisfied += 1;
            }
        }
        collect_verified_claims(&result, &mut verified_claims, &mut aggregation_errors);
        direct_results.push(result);
    }

    for alternative in &request.policy.alternative_requirements {
        let results: Vec<ServiceCredentialResult> = alternative
            .credential_requirements
            .iter()
            .map(|requirement| {
                evaluate_requirement(
                    requirement,
                    &request.policy,
                    &credentials,
                    request.evaluation_time_epoch_seconds,
                )
            })
            .collect();
        let satisfied_count = results.iter().filter(|result| result.satisfied).count();
        let satisfied = satisfied_count >= alternative.min_satisfied;
        required_total += 1;
        if satisfied {
            required_satisfied += 1;
            for result in &results {
                if result.satisfied {
                    collect_verified_claims(result, &mut verified_claims, &mut aggregation_errors);
                }
            }
        }
        alternative_results.push(ServiceAlternativeResult {
            alternative_id: alternative.id.clone(),
            name: alternative.name.clone(),
            satisfied,
            min_satisfied: alternative.min_satisfied,
            satisfied_count,
            credential_results: results,
        });
    }

    let mut errors: Vec<ServicePolicyViolation> = direct_results
        .iter()
        .flat_map(|result| result.errors.clone())
        .collect();
    errors.extend(aggregation_errors);
    for alternative in &alternative_results {
        if !alternative.satisfied {
            errors.extend(
                alternative
                    .credential_results
                    .iter()
                    .flat_map(|result| result.errors.clone()),
            );
            errors.push(ServicePolicyViolation {
                code: ServicePolicyErrorCode::AlternativeRequirementFailed,
                requirement_id: Some(alternative.alternative_id.clone()),
                credential_id: None,
                claim_name: None,
                message: format!(
                    "Alternative requirement needs {} satisfied credentials; received {}",
                    alternative.min_satisfied, alternative.satisfied_count
                ),
            });
        }
    }

    if request.policy.holder_binding.required && !request.holder_binding_verified {
        errors.push(ServicePolicyViolation {
            code: ServicePolicyErrorCode::HolderBindingRequired,
            requirement_id: None,
            credential_id: None,
            claim_name: None,
            message: "Required holder binding was not verified".to_string(),
        });
    }
    if request.policy.holder_binding.required && request.holder_binding_verified {
        if !request.policy.holder_binding.binding_methods.is_empty()
            && request.holder_binding_method.as_ref().is_none_or(|method| {
                !request
                    .policy
                    .holder_binding
                    .binding_methods
                    .contains(method)
            })
        {
            errors.push(global_violation(
                ServicePolicyErrorCode::HolderBindingMethodNotAllowed,
                "Verified holder-binding method is not allowed by the policy",
            ));
        }
        if !request.policy.holder_binding.proof_profiles.is_empty()
            && request.proof_profile.as_ref().is_none_or(|profile| {
                !request
                    .policy
                    .holder_binding
                    .proof_profiles
                    .contains(profile)
            })
        {
            errors.push(global_violation(
                ServicePolicyErrorCode::ProofProfileNotAllowed,
                "Verified proof profile is not allowed by the policy",
            ));
        }
        if request.policy.holder_binding.challenge_required && !request.challenge_verified {
            errors.push(global_violation(
                ServicePolicyErrorCode::ChallengeBindingRequired,
                "Presentation challenge binding was not verified",
            ));
        }
        if request.policy.holder_binding.audience_binding_required && !request.audience_verified {
            errors.push(global_violation(
                ServicePolicyErrorCode::AudienceBindingRequired,
                "Presentation audience binding was not verified",
            ));
        }
        if request.policy.holder_binding.replay_detection_required && !request.replay_check_verified
        {
            errors.push(global_violation(
                ServicePolicyErrorCode::ReplayDetectionRequired,
                "Presentation replay detection was not verified",
            ));
        }
    }

    if request
        .proof_epoch_seconds
        .is_some_and(|proof_time| proof_time > request.evaluation_time_epoch_seconds)
    {
        errors.push(global_violation(
            ServicePolicyErrorCode::ProofTimestampFuture,
            "Proof time is after evaluation time",
        ));
    } else if request.policy.holder_binding.required {
        if let Some(max_age) = request.policy.holder_binding.max_proof_age_seconds {
            match request.proof_epoch_seconds {
                None => errors.push(global_violation(
                    ServicePolicyErrorCode::ProofTimestampMissing,
                    "Proof time is required by the holder-binding policy",
                )),
                Some(proof_time)
                    if request.evaluation_time_epoch_seconds - proof_time > max_age =>
                {
                    errors.push(global_violation(
                        ServicePolicyErrorCode::ProofStale,
                        "Proof is older than the holder-binding policy permits",
                    ));
                }
                Some(_) => {}
            }
        }
    }

    if let Some(external) = &request.external_authorization {
        if !external.evaluated {
            let details = external
                .reasons
                .iter()
                .chain(external.errors.iter())
                .cloned()
                .collect::<Vec<_>>()
                .join("; ");
            errors.push(global_violation(
                ServicePolicyErrorCode::ExternalAuthorizationNotEvaluated,
                &if details.is_empty() {
                    "External authorization was supplied but not evaluated".to_string()
                } else {
                    format!("External authorization was not evaluated: {details}")
                },
            ));
        } else if !external.allowed {
            errors.push(global_violation(
                ServicePolicyErrorCode::ExternalAuthorizationDenied,
                &format!(
                    "External authorization denied: {}",
                    external
                        .reasons
                        .iter()
                        .chain(external.errors.iter())
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
    }

    let required_policy_satisfied = required_satisfied == required_total;
    let all_direct_required_satisfied = request
        .policy
        .credential_requirements
        .iter()
        .zip(direct_results.iter())
        .all(|(requirement, result)| !requirement.required || result.satisfied);
    let global_failure = errors.iter().any(|error| error.requirement_id.is_none());
    let fully_satisfied =
        required_policy_satisfied && all_direct_required_satisfied && !global_failure;
    let (result, decision, decision_reason) = if fully_satisfied {
        (
            ServiceEvaluationOutcome::Passed,
            ServiceDecision::Allow,
            "All required credentials and claims satisfied".to_string(),
        )
    } else if required_satisfied > 0 && !global_failure {
        (
            ServiceEvaluationOutcome::Partial,
            ServiceDecision::ManualReview,
            format!("Partially satisfied: {required_satisfied}/{required_total} required"),
        )
    } else {
        (
            ServiceEvaluationOutcome::Failed,
            ServiceDecision::Deny,
            errors
                .first()
                .map(|error| error.message.clone())
                .unwrap_or_else(|| "Required credentials not satisfied".to_string()),
        )
    };

    if decision != ServiceDecision::Allow {
        verified_claims.clear();
    }
    let warnings = credentials
        .iter()
        .flat_map(|credential| credential.warnings.clone())
        .collect();

    Ok(ServicePolicyEvaluationResult {
        result,
        decision,
        decision_reason,
        policy_id: request.policy.id,
        policy_name: request.policy.name,
        total_requirements: direct_results.len() + alternative_results.len(),
        satisfied_requirements: direct_results
            .iter()
            .filter(|result| result.satisfied)
            .count()
            + alternative_results
                .iter()
                .filter(|result| result.satisfied)
                .count(),
        required_satisfied,
        required_total,
        verified_claims,
        errors,
        warnings,
        credential_results: direct_results,
        alternative_results,
        evaluation_time_epoch_seconds: request.evaluation_time_epoch_seconds,
    })
}

fn evaluate_requirement(
    requirement: &ServiceCredentialRequirement,
    policy: &ServicePresentationPolicy,
    credentials: &[VerifiedCredentialFacts],
    evaluation_time: u64,
) -> ServiceCredentialResult {
    let candidates: Vec<&VerifiedCredentialFacts> = credentials
        .iter()
        .filter(|credential| {
            requirement.credential_template_id.is_empty()
                || credential
                    .credential_template_ids
                    .contains(&requirement.credential_template_id)
        })
        .collect();
    if candidates.is_empty() {
        return ServiceCredentialResult {
            requirement_id: requirement.id.clone(),
            credential_template_id: requirement.credential_template_id.clone(),
            credential_id: None,
            issuer_id: None,
            satisfied: false,
            claim_results: Vec::new(),
            errors: vec![violation(
                ServicePolicyErrorCode::CredentialMissing,
                requirement,
                None,
                None,
                "No credential matched the requirement",
            )],
            warnings: Vec::new(),
        };
    }

    let mut evaluated: Vec<ServiceCredentialResult> = candidates
        .into_iter()
        .map(|credential| evaluate_candidate(requirement, policy, credential, evaluation_time))
        .collect();
    evaluated.sort_by(|left, right| {
        right
            .satisfied
            .cmp(&left.satisfied)
            .then_with(|| left.errors.len().cmp(&right.errors.len()))
            .then_with(|| left.credential_id.cmp(&right.credential_id))
    });
    evaluated.remove(0)
}

fn evaluate_candidate(
    requirement: &ServiceCredentialRequirement,
    policy: &ServicePresentationPolicy,
    credential: &VerifiedCredentialFacts,
    evaluation_time: u64,
) -> ServiceCredentialResult {
    let mut errors = Vec::new();
    let mut claim_results = Vec::new();

    if !credential.signature_verified {
        let message = credential
            .signature_failure_reason
            .as_deref()
            .map(|reason| format!("Credential signature was not verified: {reason}"))
            .unwrap_or_else(|| "Credential signature was not verified".to_string());
        errors.push(violation(
            ServicePolicyErrorCode::SignatureInvalid,
            requirement,
            Some(credential),
            None,
            &message,
        ));
    }
    if let Some(required_format) = &requirement.credential_payload_format {
        if canonical_credential_format(required_format)
            != canonical_credential_format(&credential.credential_format)
        {
            errors.push(violation(
                ServicePolicyErrorCode::CredentialFormatMismatch,
                requirement,
                Some(credential),
                None,
                "Credential format does not match the requirement",
            ));
        }
    }
    if (requirement.trust_profile_id.is_some() || policy.trust_profile_id.is_some())
        && !credential.trust_profile_verified
    {
        let message = credential
            .trust_failure_reason
            .as_deref()
            .map(|reason| format!("Issuer trust verification failed: {reason}"))
            .unwrap_or_else(|| {
                "Issuer was not verified against the required trust profile".to_string()
            });
        errors.push(violation(
            ServicePolicyErrorCode::TrustProfileNotVerified,
            requirement,
            Some(credential),
            None,
            &message,
        ));
    }
    apply_issuer_constraints(requirement, policy, credential, &mut errors);
    apply_freshness(
        requirement,
        policy,
        credential,
        evaluation_time,
        &mut errors,
    );

    for requested in &requirement.requested_claims {
        let value = credential.claims.get(&requested.claim_name);
        let mut constraint_results = Vec::new();
        let mut satisfied = value.is_some() || !requested.required;
        for constraint in &requested.constraints {
            let passed = evaluate_constraint(constraint, value, evaluation_time);
            constraint_results.push(ServiceConstraintResult {
                constraint_type: constraint.constraint_type,
                passed,
            });
            if !passed {
                satisfied = false;
                errors.push(violation(
                    ServicePolicyErrorCode::ClaimConstraintFailed,
                    requirement,
                    Some(credential),
                    Some(&requested.claim_name),
                    "Claim constraint was not satisfied",
                ));
            }
        }
        if requested.required && value.is_none() {
            errors.push(violation(
                ServicePolicyErrorCode::ClaimMissing,
                requirement,
                Some(credential),
                Some(&requested.claim_name),
                "Required claim is missing",
            ));
        }
        claim_results.push(ServiceClaimResult {
            claim_name: requested.claim_name.clone(),
            satisfied,
            presented_value: value.cloned(),
            constraint_results,
        });
    }

    ServiceCredentialResult {
        requirement_id: requirement.id.clone(),
        credential_template_id: requirement.credential_template_id.clone(),
        credential_id: Some(credential.credential_id.clone()),
        issuer_id: Some(credential.issuer_id.clone()),
        satisfied: errors.is_empty(),
        claim_results,
        errors,
        warnings: credential.warnings.clone(),
    }
}

fn apply_issuer_constraints(
    requirement: &ServiceCredentialRequirement,
    policy: &ServicePresentationPolicy,
    credential: &VerifiedCredentialFacts,
    errors: &mut Vec<ServicePolicyViolation>,
) {
    let Some(constraints) = &policy.issuer_constraints else {
        return;
    };
    if let Some(minimum) = constraints.min_trust_level {
        if credential.trust_level.is_none_or(|actual| actual < minimum) {
            errors.push(violation(
                ServicePolicyErrorCode::IssuerTrustLevelInsufficient,
                requirement,
                Some(credential),
                None,
                "Issuer trust level is below the policy minimum",
            ));
        }
    }
    let compliance: BTreeSet<&str> = credential
        .compliance_statuses
        .iter()
        .map(String::as_str)
        .collect();
    for required in &constraints.required_compliance_statuses {
        if !compliance.contains(required.as_str()) {
            errors.push(violation(
                ServicePolicyErrorCode::IssuerComplianceStatusMissing,
                requirement,
                Some(credential),
                None,
                &format!("Issuer compliance status is missing: {required}"),
            ));
        }
    }
    let accreditations: BTreeSet<&str> = credential
        .accreditations
        .iter()
        .map(String::as_str)
        .collect();
    for required in &constraints.required_accreditations {
        if !accreditations.contains(required.as_str()) {
            errors.push(violation(
                ServicePolicyErrorCode::IssuerAccreditationMissing,
                requirement,
                Some(credential),
                None,
                &format!("Issuer accreditation is missing: {required}"),
            ));
        }
    }
}

fn apply_freshness(
    requirement: &ServiceCredentialRequirement,
    policy: &ServicePresentationPolicy,
    credential: &VerifiedCredentialFacts,
    evaluation_time: u64,
    errors: &mut Vec<ServicePolicyViolation>,
) {
    let policy_max_age = policy
        .freshness
        .as_ref()
        .and_then(|freshness| freshness.max_age_seconds);
    let max_age = match (requirement.max_age_seconds, policy_max_age) {
        (Some(requirement_age), Some(policy_age)) => Some(requirement_age.min(policy_age)),
        (requirement_age, policy_age) => requirement_age.or(policy_age),
    };
    if max_age.is_some() || requirement.require_fresh_issuance {
        match credential.issued_at_epoch_seconds {
            None => errors.push(violation(
                ServicePolicyErrorCode::CredentialTimestampMissing,
                requirement,
                Some(credential),
                None,
                "Credential issuance-time evidence is unavailable or invalid",
            )),
            Some(issued_at) if issued_at > evaluation_time => errors.push(violation(
                ServicePolicyErrorCode::CredentialTimestampFuture,
                requirement,
                Some(credential),
                None,
                "Credential issuance time is after evaluation time",
            )),
            Some(issued_at)
                if max_age.is_some_and(|maximum| evaluation_time - issued_at > maximum) =>
            {
                let maximum = max_age.expect("stale guard requires a maximum age");
                errors.push(violation(
                    ServicePolicyErrorCode::CredentialStale,
                    requirement,
                    Some(credential),
                    None,
                    &format!("Credential exceeds maximum age of {maximum} seconds"),
                ));
            }
            Some(_) => {}
        }
    } else if credential
        .issued_at_epoch_seconds
        .is_some_and(|issued_at| issued_at > evaluation_time)
    {
        errors.push(violation(
            ServicePolicyErrorCode::CredentialTimestampFuture,
            requirement,
            Some(credential),
            None,
            "Credential issuance time is after evaluation time",
        ));
    }

    if credential.not_revoked == Some(false) {
        let message = match credential.credential_status {
            Some(CredentialLifecycleStatus::Suspended) => "Credential is suspended",
            Some(CredentialLifecycleStatus::Expired) => "Credential is expired",
            _ => "Credential is revoked",
        };
        errors.push(violation(
            ServicePolicyErrorCode::CredentialRevoked,
            requirement,
            Some(credential),
            None,
            message,
        ));
        return;
    }
    let Some(freshness) = &policy.freshness else {
        return;
    };
    if !freshness.require_not_revoked {
        return;
    }
    match credential.revocation_checked_at_epoch_seconds {
        None => errors.push(violation(
            ServicePolicyErrorCode::RevocationCheckRequired,
            requirement,
            Some(credential),
            None,
            "Revocation status was not checked",
        )),
        Some(checked_at) if checked_at > evaluation_time => errors.push(violation(
            ServicePolicyErrorCode::RevocationEvidenceStale,
            requirement,
            Some(credential),
            None,
            "Revocation check time is after evaluation time",
        )),
        Some(checked_at)
            if freshness
                .revocation_grace_seconds
                .is_some_and(|grace| evaluation_time - checked_at > grace) =>
        {
            errors.push(violation(
                ServicePolicyErrorCode::RevocationEvidenceStale,
                requirement,
                Some(credential),
                None,
                "Revocation evidence is older than the policy permits",
            ));
        }
        Some(_) if credential.not_revoked.is_none() => errors.push(violation(
            ServicePolicyErrorCode::RevocationStatusUnknown,
            requirement,
            Some(credential),
            None,
            "Revocation status is unknown",
        )),
        Some(_) => {}
    }
}

fn evaluate_constraint(
    constraint: &ServiceClaimConstraint,
    actual: Option<&Value>,
    evaluation_time: u64,
) -> bool {
    let expected = constraint.value.as_ref();
    match constraint.constraint_type {
        ServiceConstraintType::Presence => actual.is_some_and(|value| !value.is_null()),
        ServiceConstraintType::Equals => {
            compare_text(actual, expected, |left, right| left == right)
        }
        ServiceConstraintType::NotEquals => {
            compare_text(actual, expected, |left, right| left != right)
        }
        ServiceConstraintType::GreaterThan => {
            compare_number(actual, expected, |left, right| left > right)
        }
        ServiceConstraintType::LessThan => {
            compare_number(actual, expected, |left, right| left < right)
        }
        ServiceConstraintType::GreaterOrEqual => {
            compare_number(actual, expected, |left, right| left >= right)
        }
        ServiceConstraintType::LessOrEqual => {
            compare_number(actual, expected, |left, right| left <= right)
        }
        ServiceConstraintType::InSet | ServiceConstraintType::NotInSet => {
            let Some(actual_text) = actual.and_then(value_text) else {
                return false;
            };
            let values: Vec<&Value> = match expected {
                Some(Value::Array(values)) => values.iter().collect(),
                Some(value) => vec![value],
                None => Vec::new(),
            };
            let contained = values
                .iter()
                .filter_map(|value| value_text(value))
                .any(|value| value == actual_text);
            if constraint.constraint_type == ServiceConstraintType::InSet {
                contained
            } else {
                !contained
            }
        }
        ServiceConstraintType::Regex => {
            let Some((actual, pattern)) = actual
                .and_then(value_text)
                .zip(expected.and_then(value_text))
            else {
                return false;
            };
            if pattern.len() > MAX_REGEX_LENGTH {
                return false;
            }
            Regex::new(&format!(r"\A(?:{pattern})\z")).is_ok_and(|regex| regex.is_match(&actual))
        }
        ServiceConstraintType::AgeOver => {
            let Some(date_text) = actual.and_then(value_text) else {
                return false;
            };
            let Some(required_age) = expected.and_then(value_number).map(|value| value as i32)
            else {
                return false;
            };
            let Some(evaluation_date) = DateTime::from_timestamp(evaluation_time as i64, 0)
                .map(|timestamp| timestamp.date_naive())
            else {
                return false;
            };
            let Ok(birth_date) =
                NaiveDate::parse_from_str(date_text.get(..10).unwrap_or(&date_text), "%Y-%m-%d")
            else {
                return false;
            };
            if birth_date > evaluation_date {
                return false;
            }
            let mut age = evaluation_date.year() - birth_date.year();
            if (evaluation_date.month(), evaluation_date.day())
                < (birth_date.month(), birth_date.day())
            {
                age -= 1;
            }
            age >= required_age
        }
    }
}

fn compare_text(
    actual: Option<&Value>,
    expected: Option<&Value>,
    predicate: impl FnOnce(String, String) -> bool,
) -> bool {
    actual
        .and_then(value_text)
        .zip(expected.and_then(value_text))
        .is_some_and(|(left, right)| predicate(left, right))
}

fn compare_number(
    actual: Option<&Value>,
    expected: Option<&Value>,
    predicate: impl FnOnce(f64, f64) -> bool,
) -> bool {
    actual
        .and_then(value_number)
        .zip(expected.and_then(value_number))
        .is_some_and(|(left, right)| {
            left.is_finite() && right.is_finite() && predicate(left, right)
        })
}

fn value_number(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}

fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::Null => None,
        Value::String(text) => Some(text.clone()),
        Value::Bool(value) => Some(if *value { "True" } else { "False" }.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).ok(),
    }
}

/// Normalize every service-supported credential format alias in one place.
pub fn canonical_credential_format(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "" => "UNKNOWN".to_string(),
        "w3c-vcdm-di" | "w3c-vcdm-v2-di" | "data-integrity" | "json-ld" | "ldp-vc" => {
            "W3C_VCDM_V2_DI".to_string()
        }
        "sd-jwt" | "sd-jwt-vc" | "dc+sd-jwt" | "vc+sd-jwt" | "spruce-vc+sd-jwt" | "ietf-sd-jwt"
        | "w3c-vcdm-v2-sd-jwt" => "SD_JWT_VC".to_string(),
        "w3c-vc" | "w3c-vcdm-v2-jwt-vc" | "jwt-vc" | "vc-jwt" | "jwt-vc-json" => {
            "VC_JWT".to_string()
        }
        "mdoc" | "mso-mdoc" => "MDOC".to_string(),
        "openbadge-v3" | "open-badge-v3" | "openbadge3" => "OPENBADGE_V3".to_string(),
        "openbadge-v2" | "open-badge-v2" | "openbadge2" => "OPENBADGE_V2".to_string(),
        _ => normalized.to_ascii_uppercase().replace('-', "_"),
    }
}

fn collect_verified_claims(
    result: &ServiceCredentialResult,
    output: &mut BTreeMap<String, Value>,
    errors: &mut Vec<ServicePolicyViolation>,
) {
    if !result.satisfied {
        return;
    }
    for claim in &result.claim_results {
        if claim.satisfied {
            if let Some(value) = &claim.presented_value {
                if output
                    .get(&claim.claim_name)
                    .is_some_and(|existing| existing != value)
                {
                    errors.push(ServicePolicyViolation {
                        code: ServicePolicyErrorCode::ConflictingVerifiedClaim,
                        requirement_id: None,
                        credential_id: result.credential_id.clone(),
                        claim_name: Some(claim.claim_name.clone()),
                        message: format!(
                            "Verified credentials contain conflicting values for {}",
                            claim.claim_name
                        ),
                    });
                } else {
                    output.insert(claim.claim_name.clone(), value.clone());
                }
            }
        }
    }
}

fn violation(
    code: ServicePolicyErrorCode,
    requirement: &ServiceCredentialRequirement,
    credential: Option<&VerifiedCredentialFacts>,
    claim_name: Option<&str>,
    message: &str,
) -> ServicePolicyViolation {
    ServicePolicyViolation {
        code,
        requirement_id: Some(requirement.id.clone()),
        credential_id: credential.map(|credential| credential.credential_id.clone()),
        claim_name: claim_name.map(str::to_string),
        message: message.to_string(),
    }
}

fn global_violation(code: ServicePolicyErrorCode, message: &str) -> ServicePolicyViolation {
    ServicePolicyViolation {
        code,
        requirement_id: None,
        credential_id: None,
        claim_name: None,
        message: message.to_string(),
    }
}

fn validate_request(request: &ServicePolicyEvaluationRequest) -> Result<(), ServicePolicyError> {
    if request.evaluation_time_epoch_seconds > i64::MAX as u64 {
        return invalid("evaluation time is outside the supported timestamp range");
    }
    validate_string("policy.id", &request.policy.id)?;
    validate_string("policy.name", &request.policy.name)?;
    validate_string("policy.organization_id", &request.policy.organization_id)?;
    validate_optional_string(
        "policy.trust_profile_id",
        request.policy.trust_profile_id.as_deref(),
    )?;
    validate_bounded_strings(
        "holder_binding.binding_methods",
        &request.policy.holder_binding.binding_methods,
    )?;
    validate_bounded_strings(
        "holder_binding.proof_profiles",
        &request.policy.holder_binding.proof_profiles,
    )?;
    validate_optional_string(
        "holder_binding_method",
        request.holder_binding_method.as_deref(),
    )?;
    validate_optional_string("proof_profile", request.proof_profile.as_deref())?;
    if request.credentials.len() > MAX_CREDENTIALS {
        return invalid("too many credentials");
    }
    let requirement_count = request.policy.credential_requirements.len()
        + request
            .policy
            .alternative_requirements
            .iter()
            .map(|alternative| alternative.credential_requirements.len())
            .sum::<usize>();
    if requirement_count > MAX_REQUIREMENTS {
        return invalid("too many credential requirements");
    }
    let required_units = request
        .policy
        .credential_requirements
        .iter()
        .filter(|requirement| requirement.required)
        .count()
        + request.policy.alternative_requirements.len();
    if required_units == 0 {
        return invalid("policy has no required credential obligations");
    }
    for credential in &request.credentials {
        validate_string("credential_id", &credential.credential_id)?;
        validate_string("issuer_id", &credential.issuer_id)?;
        validate_string("credential_format", &credential.credential_format)?;
        validate_optional_string(
            "signature_failure_reason",
            credential.signature_failure_reason.as_deref(),
        )?;
        validate_optional_string(
            "trust_failure_reason",
            credential.trust_failure_reason.as_deref(),
        )?;
        validate_bounded_strings(
            "credential_template_ids",
            &credential.credential_template_ids,
        )?;
        validate_bounded_strings("compliance_statuses", &credential.compliance_statuses)?;
        validate_bounded_strings("accreditations", &credential.accreditations)?;
        validate_bounded_strings("credential warnings", &credential.warnings)?;
        if credential.claims.len() > MAX_CLAIMS_PER_CREDENTIAL {
            return invalid("credential has too many claims");
        }
        for (claim_name, value) in &credential.claims {
            validate_string("claim_name", claim_name)?;
            validate_value("claim value", value)?;
        }
    }
    for requirement in request.policy.credential_requirements.iter().chain(
        request
            .policy
            .alternative_requirements
            .iter()
            .flat_map(|alternative| alternative.credential_requirements.iter()),
    ) {
        validate_string("requirement.id", &requirement.id)?;
        if !requirement.credential_template_id.is_empty() {
            validate_string(
                "requirement.credential_template_id",
                &requirement.credential_template_id,
            )?;
        }
        validate_optional_string(
            "requirement.credential_payload_format",
            requirement.credential_payload_format.as_deref(),
        )?;
        validate_optional_string(
            "requirement.trust_profile_id",
            requirement.trust_profile_id.as_deref(),
        )?;
        if requirement.requested_claims.len() > MAX_CLAIMS_PER_REQUIREMENT {
            return invalid("requirement has too many requested claims");
        }
        for claim in &requirement.requested_claims {
            validate_string("claim_name", &claim.claim_name)?;
            if let Some(predicate_spec) = &claim.predicate_spec {
                validate_value("predicate_spec", predicate_spec)?;
            }
            for constraint in &claim.constraints {
                if constraint.claim_name != claim.claim_name {
                    return invalid("constraint claim_name does not match requested claim");
                }
                if constraint.constraint_type == ServiceConstraintType::Regex {
                    let pattern_length = constraint
                        .value
                        .as_ref()
                        .and_then(Value::as_str)
                        .map(str::len)
                        .unwrap_or(usize::MAX);
                    if pattern_length > MAX_REGEX_LENGTH {
                        return invalid("regex constraint is missing or too large");
                    }
                }
                if constraint.constraint_type != ServiceConstraintType::Presence
                    && constraint.value.is_none()
                {
                    return invalid("non-presence constraint is missing its comparison value");
                }
                if let Some(value) = &constraint.value {
                    validate_value("constraint value", value)?;
                }
            }
        }
    }
    for alternative in &request.policy.alternative_requirements {
        validate_string("alternative.id", &alternative.id)?;
        validate_string("alternative.name", &alternative.name)?;
        if alternative.min_satisfied == 0
            || alternative.min_satisfied > alternative.credential_requirements.len()
        {
            return invalid("alternative min_satisfied is outside its credential range");
        }
    }
    if let Some(constraints) = &request.policy.issuer_constraints {
        validate_bounded_strings(
            "required_compliance_statuses",
            &constraints.required_compliance_statuses,
        )?;
        validate_bounded_strings(
            "required_accreditations",
            &constraints.required_accreditations,
        )?;
    }
    if let Some(external) = &request.external_authorization {
        for message in external.reasons.iter().chain(external.errors.iter()) {
            validate_string("external authorization message", message)?;
        }
    }
    Ok(())
}

fn validate_string(field: &str, value: &str) -> Result<(), ServicePolicyError> {
    if value.is_empty() || value.len() > MAX_STRING_LENGTH {
        return invalid(&format!("{field} must be non-empty and bounded"));
    }
    Ok(())
}

fn validate_optional_string(field: &str, value: Option<&str>) -> Result<(), ServicePolicyError> {
    if let Some(value) = value {
        validate_string(field, value)?;
    }
    Ok(())
}

fn validate_bounded_strings(field: &str, values: &[String]) -> Result<(), ServicePolicyError> {
    if values.len() > MAX_LIST_ITEMS {
        return invalid(&format!("{field} has too many values"));
    }
    for value in values {
        validate_string(field, value)?;
    }
    Ok(())
}

fn validate_value(field: &str, value: &Value) -> Result<(), ServicePolicyError> {
    if serde_json::to_vec(value)
        .map_err(|error| ServicePolicyError::InvalidRequest(error.to_string()))?
        .len()
        > MAX_VALUE_BYTES
    {
        return invalid(&format!("{field} is too large"));
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, ServicePolicyError> {
    Err(ServicePolicyError::InvalidRequest(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, TimeZone, Utc};
    use serde_json::json;

    fn requirement(id: &str, template: &str, claim: &str) -> ServiceCredentialRequirement {
        ServiceCredentialRequirement {
            id: id.to_string(),
            credential_template_id: template.to_string(),
            required: true,
            credential_payload_format: Some("sd_jwt_vc".to_string()),
            requested_claims: vec![ServiceRequestedClaim {
                claim_name: claim.to_string(),
                required: true,
                selective_disclosure: true,
                accept_derived: false,
                predicate_spec: None,
                constraints: vec![ServiceClaimConstraint {
                    claim_name: claim.to_string(),
                    constraint_type: ServiceConstraintType::Presence,
                    value: None,
                }],
            }],
            trust_profile_id: Some("trust-1".to_string()),
            max_age_seconds: Some(3_600),
            require_fresh_issuance: false,
        }
    }

    fn policy() -> ServicePresentationPolicy {
        ServicePresentationPolicy {
            id: "policy-1".to_string(),
            name: "Login".to_string(),
            organization_id: "org-1".to_string(),
            credential_requirements: vec![requirement("req-1", "member", "email")],
            alternative_requirements: Vec::new(),
            trust_profile_id: None,
            holder_binding: ServiceHolderBinding::default(),
            freshness: Some(ServiceFreshnessPolicy {
                max_age_seconds: None,
                require_not_revoked: true,
                revocation_grace_seconds: Some(300),
            }),
            issuer_constraints: None,
        }
    }

    fn credential() -> VerifiedCredentialFacts {
        VerifiedCredentialFacts {
            credential_id: "credential-1".to_string(),
            credential_template_ids: vec!["member".to_string()],
            credential_format: "sd-jwt".to_string(),
            claims: [("email".to_string(), json!("member@example.com"))]
                .into_iter()
                .collect(),
            issuer_id: "did:example:issuer".to_string(),
            signature_verified: true,
            signature_failure_reason: None,
            trust_profile_verified: true,
            trust_failure_reason: None,
            trust_level: Some(80),
            compliance_statuses: Vec::new(),
            accreditations: Vec::new(),
            issued_at_epoch_seconds: Some(900),
            revocation_checked_at_epoch_seconds: Some(990),
            not_revoked: Some(true),
            credential_status: Some(CredentialLifecycleStatus::Active),
            warnings: Vec::new(),
        }
    }

    fn request() -> ServicePolicyEvaluationRequest {
        ServicePolicyEvaluationRequest {
            policy: policy(),
            credentials: vec![credential()],
            evaluation_time_epoch_seconds: 1_000,
            holder_binding_verified: false,
            holder_binding_method: None,
            proof_profile: None,
            challenge_verified: false,
            audience_verified: false,
            replay_check_verified: false,
            proof_epoch_seconds: None,
            external_authorization: None,
        }
    }

    #[test]
    fn passes_complete_verified_facts() {
        let result = evaluate_service_policy(request()).unwrap();
        assert_eq!(result.result, ServiceEvaluationOutcome::Passed);
        assert_eq!(result.decision, ServiceDecision::Allow);
        assert_eq!(result.verified_claims["email"], "member@example.com");
    }

    #[test]
    fn malformed_or_missing_security_evidence_fails_closed() {
        let mut request = request();
        request.credentials[0].signature_verified = false;
        request.credentials[0].trust_profile_verified = false;
        request.credentials[0].issued_at_epoch_seconds = Some(1_001);
        request.credentials[0].revocation_checked_at_epoch_seconds = None;
        request.credentials[0].not_revoked = None;
        let result = evaluate_service_policy(request).unwrap();
        let codes: Vec<ServicePolicyErrorCode> =
            result.errors.iter().map(|error| error.code).collect();
        assert_eq!(result.decision, ServiceDecision::Deny);
        assert!(codes.contains(&ServicePolicyErrorCode::SignatureInvalid));
        assert!(codes.contains(&ServicePolicyErrorCode::TrustProfileNotVerified));
        assert!(codes.contains(&ServicePolicyErrorCode::CredentialTimestampFuture));
        assert!(codes.contains(&ServicePolicyErrorCode::RevocationCheckRequired));
        assert!(result.verified_claims.is_empty());
    }

    #[test]
    fn preserves_bounded_verifier_trust_and_lifecycle_details() {
        let mut request = request();
        request.credentials[0].signature_verified = false;
        request.credentials[0].signature_failure_reason = Some("DID resolution failed".to_string());
        request.credentials[0].trust_profile_verified = false;
        request.credentials[0].trust_failure_reason =
            Some("issuer relationship is explicitly denied".to_string());
        request.credentials[0].not_revoked = Some(false);
        request.credentials[0].credential_status = Some(CredentialLifecycleStatus::Suspended);

        let result = evaluate_service_policy(request).unwrap();
        let messages = result
            .errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>();
        assert!(messages
            .iter()
            .any(|message| message.contains("DID resolution failed")));
        assert!(messages
            .iter()
            .any(|message| message.contains("explicitly denied")));
        assert!(messages.contains(&"Credential is suspended"));
    }

    #[test]
    fn evaluates_all_constraint_operators_with_explicit_time() {
        let date = NaiveDate::from_ymd_opt(2026, 8, 10).unwrap();
        let evaluation_time = Utc
            .from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap())
            .timestamp() as u64;
        let cases = [
            (ServiceConstraintType::Equals, json!("21"), json!(21), true),
            (
                ServiceConstraintType::NotEquals,
                json!("21"),
                json!(22),
                true,
            ),
            (
                ServiceConstraintType::GreaterThan,
                json!(22),
                json!(21),
                true,
            ),
            (ServiceConstraintType::LessThan, json!(20), json!(21), true),
            (
                ServiceConstraintType::GreaterOrEqual,
                json!(21),
                json!(21),
                true,
            ),
            (
                ServiceConstraintType::LessOrEqual,
                json!(21),
                json!(21),
                true,
            ),
            (
                ServiceConstraintType::InSet,
                json!("US"),
                json!(["US", "CA"]),
                true,
            ),
            (
                ServiceConstraintType::NotInSet,
                json!("MX"),
                json!(["US", "CA"]),
                true,
            ),
            (
                ServiceConstraintType::Presence,
                json!(false),
                Value::Null,
                true,
            ),
            (
                ServiceConstraintType::Regex,
                json!("ABC-12"),
                json!(r"[A-Z]{3}-\d{2}"),
                true,
            ),
            (
                ServiceConstraintType::AgeOver,
                json!("2005-08-10"),
                json!(21),
                true,
            ),
        ];
        for (constraint_type, actual, expected, wanted) in cases {
            let constraint = ServiceClaimConstraint {
                claim_name: "value".to_string(),
                constraint_type,
                value: (!expected.is_null()).then_some(expected),
            };
            assert_eq!(
                evaluate_constraint(&constraint, Some(&actual), evaluation_time),
                wanted,
                "constraint {constraint_type:?}"
            );
        }
    }

    #[test]
    fn alternative_groups_enforce_minimum_satisfied() {
        let mut request = request();
        request.policy.credential_requirements.clear();
        request.policy.alternative_requirements = vec![ServiceAlternativeRequirement {
            id: "alternative-1".to_string(),
            name: "Passport or member card".to_string(),
            credential_requirements: vec![
                requirement("passport", "passport", "document_number"),
                requirement("member", "member", "email"),
            ],
            min_satisfied: 1,
        }];

        let result = evaluate_service_policy(request).unwrap();
        assert_eq!(result.decision, ServiceDecision::Allow);
        assert_eq!(result.alternative_results[0].satisfied_count, 1);
    }

    #[test]
    fn unknown_fields_and_unknown_constraints_are_rejected_during_deserialization() {
        let mut value = serde_json::to_value(request()).unwrap();
        value["unexpected"] = json!(true);
        assert!(serde_json::from_value::<ServicePolicyEvaluationRequest>(value).is_err());

        let mut value = serde_json::to_value(request()).unwrap();
        value["policy"]["credential_requirements"][0]["requested_claims"][0]["constraints"][0]
            ["constraint_type"] = json!("unknown");
        assert!(serde_json::from_value::<ServicePolicyEvaluationRequest>(value).is_err());
    }

    #[test]
    fn policy_without_required_obligations_is_invalid() {
        let mut request = request();
        request.policy.credential_requirements[0].required = false;
        assert_eq!(
            evaluate_service_policy(request).unwrap_err(),
            ServicePolicyError::InvalidRequest(
                "policy has no required credential obligations".to_string()
            )
        );
    }

    #[test]
    fn holder_binding_and_external_authorization_fail_globally() {
        let mut request = request();
        request.policy.holder_binding = ServiceHolderBinding {
            required: true,
            binding_methods: vec!["SESSION_BINDING".to_string()],
            proof_profiles: vec!["OID4VP_VERIFIABLE_PRESENTATION".to_string()],
            challenge_required: true,
            audience_binding_required: true,
            replay_detection_required: true,
            max_proof_age_seconds: Some(60),
        };
        request.holder_binding_verified = false;
        request.proof_epoch_seconds = Some(1_001);
        request.external_authorization = Some(ExternalAuthorizationFacts {
            evaluated: true,
            allowed: false,
            reasons: vec!["policy denied".to_string()],
            errors: Vec::new(),
        });

        let result = evaluate_service_policy(request).unwrap();
        let codes: Vec<ServicePolicyErrorCode> =
            result.errors.iter().map(|error| error.code).collect();
        assert_eq!(result.decision, ServiceDecision::Deny);
        assert!(codes.contains(&ServicePolicyErrorCode::HolderBindingRequired));
        assert!(codes.contains(&ServicePolicyErrorCode::ProofTimestampFuture));
        assert!(codes.contains(&ServicePolicyErrorCode::ExternalAuthorizationDenied));
    }

    #[test]
    fn unevaluated_external_authorization_preserves_failure_details() {
        let mut request = request();
        request.external_authorization = Some(ExternalAuthorizationFacts {
            evaluated: false,
            allowed: false,
            reasons: Vec::new(),
            errors: vec!["Cedar policy engine is unavailable".to_string()],
        });

        let result = evaluate_service_policy(request).unwrap();
        assert_eq!(result.decision, ServiceDecision::Deny);
        assert!(result
            .decision_reason
            .contains("Cedar policy engine is unavailable"));
    }

    #[test]
    fn holder_binding_method_profile_and_proof_facts_are_enforced() {
        let mut request = request();
        request.policy.holder_binding = ServiceHolderBinding {
            required: true,
            binding_methods: vec!["SESSION_BINDING".to_string()],
            proof_profiles: vec!["OID4VP_VERIFIABLE_PRESENTATION".to_string()],
            challenge_required: true,
            audience_binding_required: true,
            replay_detection_required: true,
            max_proof_age_seconds: Some(60),
        };
        request.holder_binding_verified = true;
        request.holder_binding_method = Some("DEVICE_KEY".to_string());
        request.proof_profile = None;
        request.proof_epoch_seconds = Some(990);

        let result = evaluate_service_policy(request).unwrap();
        let codes: Vec<ServicePolicyErrorCode> =
            result.errors.iter().map(|error| error.code).collect();
        assert!(codes.contains(&ServicePolicyErrorCode::HolderBindingMethodNotAllowed));
        assert!(codes.contains(&ServicePolicyErrorCode::ProofProfileNotAllowed));
        assert!(codes.contains(&ServicePolicyErrorCode::ChallengeBindingRequired));
        assert!(codes.contains(&ServicePolicyErrorCode::AudienceBindingRequired));
        assert!(codes.contains(&ServicePolicyErrorCode::ReplayDetectionRequired));
    }

    #[test]
    fn issuer_constraints_and_stale_revocation_evidence_fail() {
        let mut request = request();
        request.policy.issuer_constraints = Some(ServiceIssuerConstraints {
            min_trust_level: Some(90),
            required_compliance_statuses: vec!["approved".to_string()],
            required_accreditations: vec!["government".to_string()],
        });
        request.credentials[0].revocation_checked_at_epoch_seconds = Some(600);

        let result = evaluate_service_policy(request).unwrap();
        let codes: Vec<ServicePolicyErrorCode> =
            result.errors.iter().map(|error| error.code).collect();
        assert!(codes.contains(&ServicePolicyErrorCode::IssuerTrustLevelInsufficient));
        assert!(codes.contains(&ServicePolicyErrorCode::IssuerComplianceStatusMissing));
        assert!(codes.contains(&ServicePolicyErrorCode::IssuerAccreditationMissing));
        assert!(codes.contains(&ServicePolicyErrorCode::RevocationEvidenceStale));
    }

    #[test]
    fn applies_the_stricter_policy_and_requirement_maximum_age() {
        let mut request = request();
        request.policy.freshness.as_mut().unwrap().max_age_seconds = Some(50);
        request.policy.credential_requirements[0].max_age_seconds = Some(500);
        request.credentials[0].issued_at_epoch_seconds = Some(900);

        let result = evaluate_service_policy(request).unwrap();
        assert!(result
            .errors
            .iter()
            .any(|error| error.code == ServicePolicyErrorCode::CredentialStale));
    }

    #[test]
    fn conflicting_verified_claims_deny_ambiguous_aggregation() {
        let mut request = request();
        request
            .policy
            .credential_requirements
            .push(requirement("req-2", "employee", "email"));
        let mut second = credential();
        second.credential_id = "credential-2".to_string();
        second.credential_template_ids = vec!["employee".to_string()];
        second
            .claims
            .insert("email".to_string(), json!("other@example.com"));
        request.credentials.push(second);

        let result = evaluate_service_policy(request).unwrap();
        assert_eq!(result.decision, ServiceDecision::Deny);
        assert!(result
            .errors
            .iter()
            .any(|error| error.code == ServicePolicyErrorCode::ConflictingVerifiedClaim));
        assert!(result.verified_claims.is_empty());
    }

    #[test]
    fn canonical_format_aliases_are_stable() {
        assert_eq!(canonical_credential_format("sd_jwt_vc"), "SD_JWT_VC");
        assert_eq!(
            canonical_credential_format("w3c_vcdm_v2_sd_jwt"),
            "SD_JWT_VC"
        );
        assert_eq!(canonical_credential_format("jwt_vc_json"), "VC_JWT");
        assert_eq!(
            canonical_credential_format("w3c_vcdm_v2_di"),
            "W3C_VCDM_V2_DI"
        );
        assert_eq!(canonical_credential_format("JSON_LD"), "W3C_VCDM_V2_DI");
        assert_eq!(canonical_credential_format("mso_mdoc"), "MDOC");
        assert_eq!(canonical_credential_format("open-badge-v3"), "OPENBADGE_V3");
    }
}
