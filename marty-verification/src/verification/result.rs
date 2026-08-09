//! Canonical verification decision result assembly and validation.

use super::decision::{
    reduce_required_checks, VerificationCategorySummary, VerificationCheckResult,
    VerificationDecision, VerificationDecisionCode, VerificationProcessingStatus,
    VerificationReductionError, REQUIRED_CHECK_REDUCER_ID, REQUIRED_CHECK_REDUCER_VERSION,
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;

pub const VERIFICATION_DECISION_SCHEMA_VERSION: &str = "1.0.0";
pub const MAX_VERIFICATION_COMPONENTS: usize = 32;
pub const MAX_VERIFICATION_CHECKS: usize = 1024;
pub const MAX_CHECK_EVIDENCE_REFS: usize = 16;

/// Authorization mode for the verification decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationContextMode {
    Online,
    Offline,
}

/// Tenant and transaction scope in which verification was authorized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationDecisionContext {
    pub mode: VerificationContextMode,
    pub verifier_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_profile_id: Option<String>,
}

/// Versioned policy or trust profile used by a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationProfileReference {
    pub id: String,
    pub version: String,
    pub content_digest: String,
}

/// Exact software or adapter artifact that produced verification evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationComponentVersion {
    pub component_id: String,
    pub version: String,
    pub artifact_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adapter_version: Option<String>,
}

/// Pure reducer contract recorded in result provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReducerReference {
    pub reducer_id: String,
    pub version: String,
}

/// Caller-supplied facts from which a canonical result is assembled.
///
/// Decision, decision code, legacy validity, reducer identity, and category
/// summaries are intentionally absent because callers cannot set them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationDecisionResultInput {
    pub verification_id: String,
    pub context: VerificationDecisionContext,
    pub processing_status: VerificationProcessingStatus,
    pub evaluated_at: String,
    pub input_digest: String,
    pub evidence_digest: String,
    pub policy: VerificationProfileReference,
    pub trust_profile: VerificationProfileReference,
    pub components: Vec<VerificationComponentVersion>,
    pub checks: Vec<VerificationCheckResult>,
}

/// Canonical, privacy-minimized verification decision and evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct VerificationDecisionResult {
    schema_version: String,
    verification_id: String,
    context: VerificationDecisionContext,
    processing_status: VerificationProcessingStatus,
    decision: VerificationDecision,
    decision_code: VerificationDecisionCode,
    valid: bool,
    evaluated_at: String,
    input_digest: String,
    evidence_digest: String,
    policy: VerificationProfileReference,
    trust_profile: VerificationProfileReference,
    reducer: VerificationReducerReference,
    components: Vec<VerificationComponentVersion>,
    checks: Vec<VerificationCheckResult>,
    category_summaries: Vec<VerificationCategorySummary>,
}

impl VerificationDecisionResult {
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn verification_id(&self) -> &str {
        &self.verification_id
    }

    pub fn context(&self) -> &VerificationDecisionContext {
        &self.context
    }

    pub fn processing_status(&self) -> VerificationProcessingStatus {
        self.processing_status
    }

    pub fn decision(&self) -> VerificationDecision {
        self.decision
    }

    pub fn decision_code(&self) -> VerificationDecisionCode {
        self.decision_code
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn evaluated_at(&self) -> &str {
        &self.evaluated_at
    }

    pub fn input_digest(&self) -> &str {
        &self.input_digest
    }

    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }

    pub fn policy(&self) -> &VerificationProfileReference {
        &self.policy
    }

    pub fn trust_profile(&self) -> &VerificationProfileReference {
        &self.trust_profile
    }

    pub fn reducer(&self) -> &VerificationReducerReference {
        &self.reducer
    }

    pub fn components(&self) -> &[VerificationComponentVersion] {
        &self.components
    }

    pub fn checks(&self) -> &[VerificationCheckResult] {
        &self.checks
    }

    pub fn category_summaries(&self) -> &[VerificationCategorySummary] {
        &self.category_summaries
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerificationDecisionResultError {
    #[error("invalid canonical result field {field}: {reason}")]
    InvalidField { field: String, reason: &'static str },
    #[error("online and offline context fields do not match mode {mode:?}")]
    InvalidContextShape { mode: VerificationContextMode },
    #[error(
        "canonical result must declare between 1 and {MAX_VERIFICATION_COMPONENTS} components"
    )]
    InvalidComponentCount,
    #[error("canonical result supports at most {MAX_VERIFICATION_CHECKS} checks")]
    TooManyChecks,
    #[error("duplicate verification component ID: {component_id}")]
    DuplicateComponentId { component_id: String },
    #[error("component {component_id} must set adapter_id and adapter_version together")]
    IncompleteAdapterReference { component_id: String },
    #[error("check {check_id} references undeclared component {component_id}")]
    UndeclaredCheckComponent {
        check_id: String,
        component_id: String,
    },
    #[error(transparent)]
    Reduction(#[from] VerificationReductionError),
}

/// Validate provenance and assemble a canonical result using the sole reducer.
pub fn build_verification_decision_result(
    mut input: VerificationDecisionResultInput,
) -> Result<VerificationDecisionResult, VerificationDecisionResultError> {
    validate_scoped_id("verification_id", &input.verification_id, 128)?;
    let evaluated_at = validate_datetime("evaluated_at", &input.evaluated_at)?;
    validate_digest("input_digest", &input.input_digest)?;
    validate_digest("evidence_digest", &input.evidence_digest)?;
    validate_context(&input.context)?;
    validate_profile("policy", &input.policy)?;
    validate_profile("trust_profile", &input.trust_profile)?;

    if input.components.is_empty() || input.components.len() > MAX_VERIFICATION_COMPONENTS {
        return Err(VerificationDecisionResultError::InvalidComponentCount);
    }
    if input.checks.len() > MAX_VERIFICATION_CHECKS {
        return Err(VerificationDecisionResultError::TooManyChecks);
    }

    let mut component_ids = BTreeSet::new();
    for (index, component) in input.components.iter().enumerate() {
        validate_component(index, component)?;
        if !component_ids.insert(component.component_id.as_str()) {
            return Err(VerificationDecisionResultError::DuplicateComponentId {
                component_id: component.component_id.clone(),
            });
        }
    }

    for (index, check) in input.checks.iter_mut().enumerate() {
        let check_evaluated_at = validate_check(index, check)?;
        if check_evaluated_at > evaluated_at {
            return invalid(
                &format!("checks[{index}].evaluated_at"),
                "must not be later than the enclosing result",
            );
        }
        check.evaluated_at = canonical_datetime(check_evaluated_at);
        if !component_ids.contains(check.component_id.as_str()) {
            return Err(VerificationDecisionResultError::UndeclaredCheckComponent {
                check_id: check.check_id.clone(),
                component_id: check.component_id.clone(),
            });
        }
    }

    let reduced = reduce_required_checks(input.processing_status, &input.checks)?;

    Ok(VerificationDecisionResult {
        schema_version: VERIFICATION_DECISION_SCHEMA_VERSION.to_owned(),
        verification_id: input.verification_id,
        context: input.context,
        processing_status: reduced.processing_status,
        decision: reduced.decision,
        decision_code: reduced.decision_code,
        valid: reduced.valid,
        evaluated_at: canonical_datetime(evaluated_at),
        input_digest: input.input_digest,
        evidence_digest: input.evidence_digest,
        policy: input.policy,
        trust_profile: input.trust_profile,
        reducer: VerificationReducerReference {
            reducer_id: REQUIRED_CHECK_REDUCER_ID.to_owned(),
            version: REQUIRED_CHECK_REDUCER_VERSION.to_owned(),
        },
        components: input.components,
        checks: input.checks,
        category_summaries: reduced.category_summaries,
    })
}

fn validate_context(
    context: &VerificationDecisionContext,
) -> Result<(), VerificationDecisionResultError> {
    validate_scoped_id("context.verifier_id", &context.verifier_id, 128)?;
    match (
        context.mode,
        context.organization_id.as_deref(),
        context.transaction_id.as_deref(),
        context.audience.as_deref(),
        context.offline_profile_id.as_deref(),
    ) {
        (
            VerificationContextMode::Online,
            Some(organization_id),
            Some(transaction_id),
            Some(audience),
            None,
        ) => {
            let parsed = Uuid::parse_str(organization_id).map_err(|_| {
                VerificationDecisionResultError::InvalidField {
                    field: "context.organization_id".to_owned(),
                    reason: "must be a canonical UUID",
                }
            })?;
            if parsed.to_string() != organization_id {
                return invalid("context.organization_id", "must be a canonical UUID");
            }
            validate_scoped_id("context.transaction_id", transaction_id, 128)?;
            validate_bounded_text("context.audience", audience, 1, 255)
        }
        (VerificationContextMode::Offline, None, None, None, Some(offline_profile_id)) => {
            validate_scoped_id("context.offline_profile_id", offline_profile_id, 128)
        }
        (mode, ..) => Err(VerificationDecisionResultError::InvalidContextShape { mode }),
    }
}

fn validate_profile(
    field: &str,
    profile: &VerificationProfileReference,
) -> Result<(), VerificationDecisionResultError> {
    validate_scoped_id(&format!("{field}.id"), &profile.id, 128)?;
    validate_version(&format!("{field}.version"), &profile.version)?;
    validate_digest(&format!("{field}.content_digest"), &profile.content_digest)
}

fn validate_component(
    index: usize,
    component: &VerificationComponentVersion,
) -> Result<(), VerificationDecisionResultError> {
    let prefix = format!("components[{index}]");
    validate_lower_id(
        &format!("{prefix}.component_id"),
        &component.component_id,
        64,
    )?;
    validate_version(&format!("{prefix}.version"), &component.version)?;
    validate_digest(
        &format!("{prefix}.artifact_digest"),
        &component.artifact_digest,
    )?;
    match (&component.adapter_id, &component.adapter_version) {
        (Some(adapter_id), Some(adapter_version)) => {
            validate_lower_id(&format!("{prefix}.adapter_id"), adapter_id, 64)?;
            validate_version(&format!("{prefix}.adapter_version"), adapter_version)
        }
        (None, None) => Ok(()),
        _ => Err(
            VerificationDecisionResultError::IncompleteAdapterReference {
                component_id: component.component_id.clone(),
            },
        ),
    }
}

fn validate_check(
    index: usize,
    check: &VerificationCheckResult,
) -> Result<DateTime<FixedOffset>, VerificationDecisionResultError> {
    let prefix = format!("checks[{index}]");
    validate_check_id(&format!("{prefix}.check_id"), &check.check_id)?;
    validate_code(&format!("{prefix}.code"), &check.code)?;
    validate_lower_id(&format!("{prefix}.component_id"), &check.component_id, 64)?;
    let evaluated_at = validate_datetime(&format!("{prefix}.evaluated_at"), &check.evaluated_at)?;
    if let Some(message) = &check.safe_message {
        validate_bounded_text(&format!("{prefix}.safe_message"), message, 1, 256)?;
        if message
            .chars()
            .any(|character| character <= '\u{001f}' || character == '\u{007f}')
        {
            return invalid(
                &format!("{prefix}.safe_message"),
                "must not contain control characters",
            );
        }
    }
    if check.evidence_refs.len() > MAX_CHECK_EVIDENCE_REFS {
        return invalid(
            &format!("{prefix}.evidence_refs"),
            "contains more than 16 references",
        );
    }
    for (evidence_index, evidence_ref) in check.evidence_refs.iter().enumerate() {
        validate_evidence_ref(
            &format!("{prefix}.evidence_refs[{evidence_index}]"),
            evidence_ref,
        )?;
    }
    Ok(evaluated_at)
}

fn validate_scoped_id(
    field: &str,
    value: &str,
    max: usize,
) -> Result<(), VerificationDecisionResultError> {
    validate_ascii_pattern(field, value, 1, max, |index, byte| {
        byte.is_ascii_alphanumeric()
            || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
    })
}

fn validate_lower_id(
    field: &str,
    value: &str,
    max: usize,
) -> Result<(), VerificationDecisionResultError> {
    validate_ascii_pattern(field, value, 1, max, |index, byte| {
        if index == 0 {
            byte.is_ascii_lowercase()
        } else {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        }
    })
}

fn validate_version(field: &str, value: &str) -> Result<(), VerificationDecisionResultError> {
    validate_ascii_pattern(field, value, 1, 64, |index, byte| {
        byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'+' | b'-'))
    })
}

fn validate_code(field: &str, value: &str) -> Result<(), VerificationDecisionResultError> {
    validate_ascii_pattern(field, value, 3, 96, |index, byte| {
        if index == 0 {
            byte.is_ascii_uppercase()
        } else {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
        }
    })
}

fn validate_check_id(field: &str, value: &str) -> Result<(), VerificationDecisionResultError> {
    if value.len() < 3 || value.len() > 128 || !value.is_ascii() {
        return invalid(field, "must be a bounded dotted lowercase identifier");
    }
    let segments: Vec<_> = value.split('.').collect();
    if segments.len() < 2
        || segments.iter().any(|segment| {
            segment.is_empty()
                || !segment.as_bytes()[0].is_ascii_lowercase()
                || !segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
    {
        return invalid(field, "must be a bounded dotted lowercase identifier");
    }
    Ok(())
}

fn validate_evidence_ref(field: &str, value: &str) -> Result<(), VerificationDecisionResultError> {
    const PREFIX: &str = "urn:marty:evidence:";
    if value.len() < 20 || value.len() > 224 || !value.is_ascii() {
        return invalid(field, "must be a bounded Marty evidence URN");
    }
    let Some(tail) = value.strip_prefix(PREFIX) else {
        return invalid(field, "must be a bounded Marty evidence URN");
    };
    if tail.len() < 2
        || !tail.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
        })
    {
        return invalid(field, "must be a bounded Marty evidence URN");
    }
    Ok(())
}

fn validate_digest(field: &str, value: &str) -> Result<(), VerificationDecisionResultError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return invalid(field, "must be a lowercase SHA-256 digest");
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid(field, "must be a lowercase SHA-256 digest");
    }
    Ok(())
}

fn validate_datetime(
    field: &str,
    value: &str,
) -> Result<DateTime<FixedOffset>, VerificationDecisionResultError> {
    DateTime::parse_from_rfc3339(value).map_err(|_| VerificationDecisionResultError::InvalidField {
        field: field.to_owned(),
        reason: "must be an RFC 3339 date-time",
    })
}

fn canonical_datetime(value: DateTime<FixedOffset>) -> String {
    value
        .with_timezone(&Utc)
        .to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn validate_bounded_text(
    field: &str,
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), VerificationDecisionResultError> {
    let length = value.chars().count();
    if length < min || length > max {
        return invalid(field, "text length is outside protocol bounds");
    }
    Ok(())
}

fn validate_ascii_pattern(
    field: &str,
    value: &str,
    min: usize,
    max: usize,
    allowed: impl Fn(usize, u8) -> bool,
) -> Result<(), VerificationDecisionResultError> {
    if value.len() < min
        || value.len() > max
        || !value.is_ascii()
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| allowed(index, byte))
    {
        return invalid(field, "does not match the canonical identifier pattern");
    }
    Ok(())
}

fn invalid<T>(field: &str, reason: &'static str) -> Result<T, VerificationDecisionResultError> {
    Err(VerificationDecisionResultError::InvalidField {
        field: field.to_owned(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verification::decision::{VerificationCheckCategory, VerificationCheckOutcome};

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn check(check_id: &str, component_id: &str) -> VerificationCheckResult {
        VerificationCheckResult {
            check_id: check_id.to_owned(),
            category: VerificationCheckCategory::CredentialProof,
            required: true,
            outcome: VerificationCheckOutcome::Passed,
            code: "CREDENTIAL_SIGNATURE_VALID".to_owned(),
            safe_message: None,
            component_id: component_id.to_owned(),
            evaluated_at: "2026-08-08T23:30:00Z".to_owned(),
            evidence_refs: vec![format!("urn:marty:evidence:{check_id}")],
        }
    }

    fn component(component_id: &str) -> VerificationComponentVersion {
        VerificationComponentVersion {
            component_id: component_id.to_owned(),
            version: "0.1.35".to_owned(),
            artifact_digest: DIGEST.to_owned(),
            adapter_id: Some("oid4vp".to_owned()),
            adapter_version: Some("1.0.0".to_owned()),
        }
    }

    fn online_context() -> VerificationDecisionContext {
        VerificationDecisionContext {
            mode: VerificationContextMode::Online,
            verifier_id: "verifier:example".to_owned(),
            organization_id: Some("123e4567-e89b-12d3-a456-426614174000".to_owned()),
            transaction_id: Some("transaction-example-001".to_owned()),
            audience: Some("https://verifier.example".to_owned()),
            offline_profile_id: None,
        }
    }

    fn input() -> VerificationDecisionResultInput {
        VerificationDecisionResultInput {
            verification_id: "verification-example-001".to_owned(),
            context: online_context(),
            processing_status: VerificationProcessingStatus::Completed,
            evaluated_at: "2026-08-08T23:30:00Z".to_owned(),
            input_digest: DIGEST.to_owned(),
            evidence_digest: DIGEST.to_owned(),
            policy: VerificationProfileReference {
                id: "policy:employee-access".to_owned(),
                version: "7".to_owned(),
                content_digest: DIGEST.to_owned(),
            },
            trust_profile: VerificationProfileReference {
                id: "trust:employee-issuers".to_owned(),
                version: "4".to_owned(),
                content_digest: DIGEST.to_owned(),
            },
            components: vec![component("marty-core")],
            checks: vec![check("credential.signature", "marty-core")],
        }
    }

    #[test]
    fn derives_all_caller_forbidden_fields() {
        let result = build_verification_decision_result(input()).expect("canonical input");

        assert_eq!(
            result.schema_version(),
            VERIFICATION_DECISION_SCHEMA_VERSION
        );
        assert_eq!(result.decision(), VerificationDecision::Pass);
        assert_eq!(
            result.decision_code(),
            VerificationDecisionCode::AllRequiredChecksPassed
        );
        assert!(result.is_valid());
        assert_eq!(result.reducer().reducer_id, REQUIRED_CHECK_REDUCER_ID);
        assert_eq!(result.reducer().version, REQUIRED_CHECK_REDUCER_VERSION);
        assert_eq!(result.category_summaries().len(), 1);

        let value = serde_json::to_value(result).expect("serializable result");
        assert_eq!(value["context"]["mode"], "ONLINE");
        assert_eq!(value["decision"], "PASS");
        assert_eq!(value["valid"], true);
    }

    #[test]
    fn accepts_only_one_authorization_context_shape() {
        let mut offline = input();
        offline.context = VerificationDecisionContext {
            mode: VerificationContextMode::Offline,
            verifier_id: "verifier:offline".to_owned(),
            organization_id: None,
            transaction_id: None,
            audience: None,
            offline_profile_id: Some("offline:supervised".to_owned()),
        };
        build_verification_decision_result(offline).expect("exclusive offline context");

        let mut online_with_offline = input();
        online_with_offline.context.offline_profile_id = Some("offline:extra".to_owned());
        assert!(matches!(
            build_verification_decision_result(online_with_offline),
            Err(VerificationDecisionResultError::InvalidContextShape {
                mode: VerificationContextMode::Online
            })
        ));

        let mut offline_with_online = input();
        offline_with_online.context.mode = VerificationContextMode::Offline;
        offline_with_online.context.offline_profile_id = Some("offline:extra".to_owned());
        assert!(matches!(
            build_verification_decision_result(offline_with_online),
            Err(VerificationDecisionResultError::InvalidContextShape {
                mode: VerificationContextMode::Offline
            })
        ));
    }

    #[test]
    fn rejects_duplicate_and_dangling_component_provenance() {
        let mut duplicate = input();
        duplicate.components.push(component("marty-core"));
        assert_eq!(
            build_verification_decision_result(duplicate),
            Err(VerificationDecisionResultError::DuplicateComponentId {
                component_id: "marty-core".to_owned()
            })
        );

        let mut dangling = input();
        dangling.checks[0].component_id = "missing-adapter".to_owned();
        assert_eq!(
            build_verification_decision_result(dangling),
            Err(VerificationDecisionResultError::UndeclaredCheckComponent {
                check_id: "credential.signature".to_owned(),
                component_id: "missing-adapter".to_owned()
            })
        );
    }

    #[test]
    fn permits_multiple_checks_from_one_declared_component() {
        let mut value = input();
        value.checks.push(check("credential.status", "marty-core"));

        let result = build_verification_decision_result(value).expect("shared component is valid");
        assert_eq!(result.components().len(), 1);
        assert_eq!(result.checks().len(), 2);
    }

    #[test]
    fn rejects_partial_adapter_provenance() {
        let mut value = input();
        value.components[0].adapter_version = None;
        assert_eq!(
            build_verification_decision_result(value),
            Err(
                VerificationDecisionResultError::IncompleteAdapterReference {
                    component_id: "marty-core".to_owned()
                }
            )
        );
    }

    #[test]
    fn rejects_protocol_collection_overflow() {
        let mut components = input();
        components.components = (0..=MAX_VERIFICATION_COMPONENTS)
            .map(|index| component(&format!("component-{index}")))
            .collect();
        assert_eq!(
            build_verification_decision_result(components),
            Err(VerificationDecisionResultError::InvalidComponentCount)
        );

        let mut checks = input();
        checks.checks = (0..=MAX_VERIFICATION_CHECKS)
            .map(|index| check(&format!("credential.check_{index}"), "marty-core"))
            .collect();
        assert_eq!(
            build_verification_decision_result(checks),
            Err(VerificationDecisionResultError::TooManyChecks)
        );
    }

    #[test]
    fn rejects_invalid_wire_fields_before_reduction() {
        let mut digest = input();
        digest.input_digest = "sha256:ABC".to_owned();
        assert!(matches!(
            build_verification_decision_result(digest),
            Err(VerificationDecisionResultError::InvalidField { field, .. })
                if field == "input_digest"
        ));

        let mut check_id = input();
        check_id.checks[0].check_id = "credential".to_owned();
        assert!(matches!(
            build_verification_decision_result(check_id),
            Err(VerificationDecisionResultError::InvalidField { field, .. })
                if field == "checks[0].check_id"
        ));

        let mut evidence = input();
        evidence.checks[0].evidence_refs = vec!["https://example.invalid/raw".to_owned()];
        assert!(matches!(
            build_verification_decision_result(evidence),
            Err(VerificationDecisionResultError::InvalidField { field, .. })
                if field == "checks[0].evidence_refs[0]"
        ));

        let mut unsafe_message = input();
        unsafe_message.checks[0].safe_message = Some("operator\tmessage".to_owned());
        assert!(matches!(
            build_verification_decision_result(unsafe_message),
            Err(VerificationDecisionResultError::InvalidField { field, .. })
                if field == "checks[0].safe_message"
        ));
    }

    #[test]
    fn normalizes_timestamps_and_rejects_checks_after_the_result() {
        let mut normalized = input();
        normalized.evaluated_at = "2026-08-09T00:30:00+01:00".to_owned();
        normalized.checks[0].evaluated_at = "2026-08-08T18:30:00-05:00".to_owned();
        let result =
            build_verification_decision_result(normalized).expect("equivalent UTC timestamps");
        assert_eq!(result.evaluated_at(), "2026-08-08T23:30:00Z");
        assert_eq!(result.checks()[0].evaluated_at, "2026-08-08T23:30:00Z");

        let mut future_check = input();
        future_check.checks[0].evaluated_at = "2026-08-08T23:30:01Z".to_owned();
        assert!(matches!(
            build_verification_decision_result(future_check),
            Err(VerificationDecisionResultError::InvalidField { field, .. })
                if field == "checks[0].evaluated_at"
        ));
    }

    #[test]
    fn delegates_vacuous_and_duplicate_check_rejection_to_the_reducer() {
        let mut empty = input();
        empty.checks.clear();
        assert_eq!(
            build_verification_decision_result(empty),
            Err(VerificationDecisionResultError::Reduction(
                VerificationReductionError::MissingRequiredCheck
            ))
        );

        let mut duplicate = input();
        duplicate.checks.push(duplicate.checks[0].clone());
        assert!(matches!(
            build_verification_decision_result(duplicate),
            Err(VerificationDecisionResultError::Reduction(
                VerificationReductionError::DuplicateCheckId { .. }
            ))
        ));
    }
}
