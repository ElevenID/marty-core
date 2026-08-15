//! Server-owned verification governance decisions.
//!
//! This module owns canonical hashing, exact configuration parsing, API-key
//! authorization, purpose checks, and persisted-snapshot revalidation. The
//! JSON functions form a language-neutral boundary for service adapters.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CREDENTIALS_COMPONENT_ID: &str = "marty-credentials";
const VERIFICATION_ADAPTER_ID: &str = "verification-service";
const SESSION_CREATE_PURPOSE: &str = "verification.session.create";
const DIRECT_VERIFY_PURPOSE: &str = "verification.direct";
const VDS_NC_VERIFY_PURPOSE: &str = "verification.vds-nc";

const ALL_PRESENTATION_CHECKS: &[&str] = &[
    "presentation.structure",
    "presentation.proof",
    "credential.proof",
    "issuer.trust",
    "credential.status",
    "holder.binding",
    "transaction.binding",
    "claim.constraints",
];
const VDS_CHECKS: &[&str] = &["credential.proof", "issuer.trust"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileReference {
    pub id: String,
    pub version: String,
    pub content_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentReference {
    pub component_id: String,
    pub version: String,
    pub artifact_digest: String,
    pub adapter_id: String,
    pub adapter_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyContent {
    verifier_id: String,
    presentation_definition_digest: String,
    required_checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustContent {
    trusted_issuers: Vec<String>,
    allow_public_did_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDocument {
    organization_id: String,
    id: String,
    version: String,
    content_digest: String,
    content: PolicyContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustDocument {
    organization_id: String,
    id: String,
    version: String,
    content_digest: String,
    content: TrustContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurposeAuthorization {
    policy_id: String,
    trust_profile_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientAuthorization {
    client_id: String,
    api_key_sha256: String,
    organization_id: String,
    purposes: BTreeMap<String, PurposeAuthorization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernanceDocument {
    component: ComponentReference,
    policies: Vec<PolicyDocument>,
    trust_profiles: Vec<TrustDocument>,
    clients: Vec<ClientAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotPolicy {
    #[serde(flatten)]
    reference: ProfileReference,
    content: PolicyContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotTrustProfile {
    #[serde(flatten)]
    reference: ProfileReference,
    content: TrustContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernanceSnapshot {
    client_id: String,
    purpose: String,
    organization_id: String,
    policy: SnapshotPolicy,
    trust_profile: SnapshotTrustProfile,
    component: ComponentReference,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationRequest {
    governance: Value,
    api_key: String,
    purpose: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeRequest {
    governance: Value,
    snapshot: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRequest {
    snapshot: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PurposeRequest {
    snapshot: PurposeSnapshot,
    purpose: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateRequest {
    snapshot: RequestBindingSnapshot,
    verifier_id: String,
    presentation_definition: Value,
}

#[derive(Debug, Deserialize)]
struct PurposeSnapshot {
    purpose: String,
    policy: PurposePolicy,
}

#[derive(Debug, Deserialize)]
struct PurposePolicy {
    content: PurposePolicyContent,
}

#[derive(Debug, Deserialize)]
struct PurposePolicyContent {
    required_checks: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RequestBindingSnapshot {
    policy: RequestBindingPolicy,
}

#[derive(Debug, Deserialize)]
struct RequestBindingPolicy {
    content: RequestBindingContent,
}

#[derive(Debug, Deserialize)]
struct RequestBindingContent {
    verifier_id: String,
    presentation_definition_digest: String,
}

pub fn canonical_digest_json(value_json: &str) -> Result<String, String> {
    let value: Value =
        serde_json::from_str(value_json).map_err(|_| "value is not canonical JSON".to_string())?;
    canonical_digest(&value)
}

pub fn validate_governance_json(raw: &str) -> Result<(), String> {
    parse_governance(raw).map(|_| ())
}

pub fn authorize_governance_json(request_json: &str) -> Result<String, String> {
    let request: AuthorizationRequest = serde_json::from_str(request_json)
        .map_err(|error| format!("invalid governance authorization request: {error}"))?;
    let raw = serde_json::to_string(&request.governance)
        .map_err(|_| "VERIFICATION_GOVERNANCE_JSON must be valid JSON".to_string())?;
    let governance = parse_governance(&raw)?;
    let snapshot = authorize(&governance, &request.api_key, &request.purpose)?;
    serde_json::to_string(&snapshot).map_err(|error| error.to_string())
}

pub fn governance_from_snapshot_json(request_json: &str) -> Result<String, String> {
    let request: SnapshotRequest = serde_json::from_str(request_json)
        .map_err(|error| format!("invalid governance snapshot request: {error}"))?;
    let snapshot = parse_snapshot(request.snapshot)?;
    serde_json::to_string(&snapshot).map_err(|error| error.to_string())
}

pub fn resume_governance_json(request_json: &str) -> Result<String, String> {
    let request: ResumeRequest = serde_json::from_str(request_json)
        .map_err(|error| format!("invalid governance resume request: {error}"))?;
    let raw = serde_json::to_string(&request.governance)
        .map_err(|_| "VERIFICATION_GOVERNANCE_JSON must be valid JSON".to_string())?;
    let governance = parse_governance(&raw)?;
    let snapshot = parse_snapshot(request.snapshot)?;
    let resumed = resume(&governance, snapshot)?;
    serde_json::to_string(&resumed).map_err(|error| error.to_string())
}

pub fn require_governance_purpose_json(request_json: &str) -> Result<(), String> {
    let request: PurposeRequest = serde_json::from_str(request_json)
        .map_err(|error| format!("invalid governance purpose request: {error}"))?;
    if request.snapshot.purpose != request.purpose {
        return Err("verification governance context is not authorized for this purpose".into());
    }
    require_purpose_checks(
        &request.purpose,
        &request.snapshot.policy.content.required_checks,
    )
    .map_err(|_| "verification policy is missing mandatory purpose checks".to_string())
}

pub fn validate_governance_request_json(request_json: &str) -> Result<(), String> {
    let request: ValidateRequest = serde_json::from_str(request_json)
        .map_err(|error| format!("invalid governed verification request: {error}"))?;
    if request.verifier_id != request.snapshot.policy.content.verifier_id {
        return Err("verifier_id does not match the caller-bound verification policy".into());
    }
    let definition_digest = canonical_digest(&request.presentation_definition)
        .map_err(|_| "presentation_definition is not canonical JSON".to_string())?;
    if definition_digest
        != request
            .snapshot
            .policy
            .content
            .presentation_definition_digest
    {
        return Err(
            "presentation_definition does not match the caller-bound verification policy".into(),
        );
    }
    Ok(())
}

/// Language-neutral conformance vectors used by native and adapter tests.
pub fn behavior_fixture_json() -> &'static str {
    include_str!("../tests/fixtures/governance_behavior.json")
}

fn parse_governance(raw: &str) -> Result<GovernanceDocument, String> {
    let governance: GovernanceDocument = serde_json::from_str(raw)
        .map_err(|error| format!("VERIFICATION_GOVERNANCE_JSON must be valid JSON: {error}"))?;
    validate_component(&governance.component, "component")?;
    if governance.policies.is_empty()
        || governance.trust_profiles.is_empty()
        || governance.clients.is_empty()
    {
        return Err("policies, trust_profiles, and clients must be non-empty lists".into());
    }

    let mut policy_keys = BTreeSet::new();
    for (index, policy) in governance.policies.iter().enumerate() {
        validate_policy(policy, &format!("policies[{index}]"))?;
        if !policy_keys.insert((policy.organization_id.clone(), policy.id.clone())) {
            return Err("duplicate organization policy profile".into());
        }
    }
    let mut trust_keys = BTreeSet::new();
    for (index, trust) in governance.trust_profiles.iter().enumerate() {
        validate_trust(trust, &format!("trust_profiles[{index}]"))?;
        if !trust_keys.insert((trust.organization_id.clone(), trust.id.clone())) {
            return Err("duplicate organization trust profile".into());
        }
    }

    let mut client_ids = BTreeSet::new();
    let mut key_digests = BTreeSet::new();
    for (index, client) in governance.clients.iter().enumerate() {
        let field = format!("clients[{index}]");
        bounded_text(&client.client_id, &format!("{field}.client_id"))?;
        canonical_uuid(&client.organization_id, &format!("{field}.organization_id"))?;
        lowercase_sha256(
            &client.api_key_sha256,
            &format!("{field}.api_key_sha256"),
            false,
        )?;
        if client.purposes.is_empty() {
            return Err(format!("{field}.purposes is invalid"));
        }
        if !client_ids.insert(client.client_id.clone()) {
            return Err("duplicate client id".into());
        }
        if !key_digests.insert(client.api_key_sha256.clone()) {
            return Err("duplicate client API key digest".into());
        }
        for (purpose, authorization) in &client.purposes {
            required_checks(purpose)?;
            bounded_text(
                &authorization.policy_id,
                &format!("{field}.purposes[{purpose}].policy_id"),
            )?;
            bounded_text(
                &authorization.trust_profile_id,
                &format!("{field}.purposes[{purpose}].trust_profile_id"),
            )?;
            let policy = governance.policies.iter().find(|policy| {
                policy.organization_id == client.organization_id
                    && policy.id == authorization.policy_id
            });
            let Some(policy) = policy else {
                return Err(format!(
                    "client {} purpose {purpose} references an unknown organization policy",
                    client.client_id
                ));
            };
            if !governance.trust_profiles.iter().any(|trust| {
                trust.organization_id == client.organization_id
                    && trust.id == authorization.trust_profile_id
            }) {
                return Err(format!(
                    "client {} purpose {purpose} references an unknown organization trust profile",
                    client.client_id
                ));
            }
            require_purpose_checks(purpose, &policy.content.required_checks).map_err(
                |missing| {
                    format!(
                        "client {} policy is missing mandatory checks for {purpose}: {missing:?}",
                        client.client_id
                    )
                },
            )?;
        }
    }
    Ok(governance)
}

fn authorize(
    governance: &GovernanceDocument,
    api_key: &str,
    purpose: &str,
) -> Result<GovernanceSnapshot, String> {
    required_checks(purpose).map_err(|_| "Unsupported verification purpose".to_string())?;
    if api_key.is_empty() || api_key.len() > 4096 {
        return Err("Invalid or unauthorized API key".into());
    }
    let supplied = Sha256::digest(api_key.as_bytes());
    let mut matched = None;
    for client in &governance.clients {
        let expected = decode_hex(&client.api_key_sha256).unwrap_or_default();
        if constant_time_equal(&supplied, &expected) {
            matched = Some(client);
        }
    }
    let client = matched.ok_or_else(|| "Invalid or unauthorized API key".to_string())?;
    let authorization = client
        .purposes
        .get(purpose)
        .ok_or_else(|| "Invalid or unauthorized API key".to_string())?;
    let policy = governance
        .policies
        .iter()
        .find(|policy| {
            policy.organization_id == client.organization_id && policy.id == authorization.policy_id
        })
        .expect("validated governance policy reference");
    let trust = governance
        .trust_profiles
        .iter()
        .find(|trust| {
            trust.organization_id == client.organization_id
                && trust.id == authorization.trust_profile_id
        })
        .expect("validated governance trust reference");
    Ok(snapshot(governance, client, purpose, policy, trust))
}

fn resume(
    governance: &GovernanceDocument,
    frozen: GovernanceSnapshot,
) -> Result<GovernanceSnapshot, String> {
    let client = governance
        .clients
        .iter()
        .find(|client| client.client_id == frozen.client_id)
        .filter(|client| client.organization_id == frozen.organization_id)
        .ok_or_else(|| {
            "governance_snapshot client is not registered for its organization".to_string()
        })?;
    let authorization = client.purposes.get(&frozen.purpose).ok_or_else(|| {
        "governance_snapshot client is not authorized for its purpose".to_string()
    })?;
    if authorization.policy_id != frozen.policy.reference.id
        || authorization.trust_profile_id != frozen.trust_profile.reference.id
    {
        return Err("governance_snapshot profiles are not authorized for its purpose".into());
    }
    let policy = governance
        .policies
        .iter()
        .find(|policy| {
            policy.organization_id == frozen.organization_id && policy.id == authorization.policy_id
        })
        .ok_or_else(|| {
            "governance_snapshot profiles do not match the registered authority".to_string()
        })?;
    let trust = governance
        .trust_profiles
        .iter()
        .find(|trust| {
            trust.organization_id == frozen.organization_id
                && trust.id == authorization.trust_profile_id
        })
        .ok_or_else(|| {
            "governance_snapshot profiles do not match the registered authority".to_string()
        })?;
    let expected = snapshot(governance, client, &frozen.purpose, policy, trust);
    if frozen.policy != expected.policy || frozen.trust_profile != expected.trust_profile {
        return Err("governance_snapshot profiles do not match the registered authority".into());
    }
    Ok(expected)
}

fn snapshot(
    governance: &GovernanceDocument,
    client: &ClientAuthorization,
    purpose: &str,
    policy: &PolicyDocument,
    trust: &TrustDocument,
) -> GovernanceSnapshot {
    GovernanceSnapshot {
        client_id: client.client_id.clone(),
        purpose: purpose.to_string(),
        organization_id: client.organization_id.clone(),
        policy: SnapshotPolicy {
            reference: ProfileReference {
                id: policy.id.clone(),
                version: policy.version.clone(),
                content_digest: policy.content_digest.clone(),
            },
            content: policy.content.clone(),
        },
        trust_profile: SnapshotTrustProfile {
            reference: ProfileReference {
                id: trust.id.clone(),
                version: trust.version.clone(),
                content_digest: trust.content_digest.clone(),
            },
            content: trust.content.clone(),
        },
        component: governance.component.clone(),
    }
}

fn parse_snapshot(value: Value) -> Result<GovernanceSnapshot, String> {
    let snapshot: GovernanceSnapshot = serde_json::from_value(value)
        .map_err(|error| format!("governance_snapshot is invalid: {error}"))?;
    bounded_text(&snapshot.client_id, "governance_snapshot.client_id")?;
    required_checks(&snapshot.purpose)?;
    canonical_uuid(
        &snapshot.organization_id,
        "governance_snapshot.organization_id",
    )?;
    validate_component(&snapshot.component, "governance_snapshot.component")?;
    validate_snapshot_policy(&snapshot.policy, &snapshot.organization_id)?;
    validate_snapshot_trust(&snapshot.trust_profile, &snapshot.organization_id)?;
    require_purpose_checks(&snapshot.purpose, &snapshot.policy.content.required_checks).map_err(
        |missing| {
            format!("governance_snapshot policy is missing mandatory purpose checks: {missing:?}")
        },
    )?;
    Ok(snapshot)
}

fn validate_component(component: &ComponentReference, field: &str) -> Result<(), String> {
    bounded_text(&component.component_id, &format!("{field}.component_id"))?;
    bounded_text(&component.version, &format!("{field}.version"))?;
    lowercase_sha256(
        &component.artifact_digest,
        &format!("{field}.artifact_digest"),
        true,
    )?;
    bounded_text(&component.adapter_id, &format!("{field}.adapter_id"))?;
    bounded_text(
        &component.adapter_version,
        &format!("{field}.adapter_version"),
    )?;
    if component.component_id != CREDENTIALS_COMPONENT_ID {
        return Err(format!(
            "{field}.component_id must be {CREDENTIALS_COMPONENT_ID}"
        ));
    }
    if component.adapter_id != VERIFICATION_ADAPTER_ID {
        return Err(format!(
            "{field}.adapter_id must be {VERIFICATION_ADAPTER_ID}"
        ));
    }
    Ok(())
}

fn validate_policy(policy: &PolicyDocument, field: &str) -> Result<(), String> {
    canonical_uuid(&policy.organization_id, &format!("{field}.organization_id"))?;
    bounded_text(&policy.id, &format!("{field}.id"))?;
    bounded_text(&policy.version, &format!("{field}.version"))?;
    lowercase_sha256(
        &policy.content_digest,
        &format!("{field}.content_digest"),
        true,
    )?;
    validate_policy_content(&policy.content, field)?;
    let content = serde_json::to_value(&policy.content).map_err(|error| error.to_string())?;
    if canonical_digest(&content)? != policy.content_digest {
        return Err(format!("{field}.content_digest does not match content"));
    }
    Ok(())
}

fn validate_snapshot_policy(policy: &SnapshotPolicy, organization_id: &str) -> Result<(), String> {
    let document = PolicyDocument {
        organization_id: organization_id.to_string(),
        id: policy.reference.id.clone(),
        version: policy.reference.version.clone(),
        content_digest: policy.reference.content_digest.clone(),
        content: policy.content.clone(),
    };
    validate_policy(&document, "governance_snapshot.policy")
}

fn validate_policy_content(content: &PolicyContent, field: &str) -> Result<(), String> {
    bounded_text(
        &content.verifier_id,
        &format!("{field}.content.verifier_id"),
    )?;
    lowercase_sha256(
        &content.presentation_definition_digest,
        &format!("{field}.content.presentation_definition_digest"),
        true,
    )?;
    if content.required_checks.is_empty() {
        return Err(format!("{field}.content.required_checks must be non-empty"));
    }
    let supported: BTreeSet<&str> = ALL_PRESENTATION_CHECKS.iter().copied().collect();
    if content
        .required_checks
        .iter()
        .any(|check| !supported.contains(check.as_str()))
    {
        return Err(format!("{field}.content.required_checks is unsupported"));
    }
    let unique: BTreeSet<&str> = content.required_checks.iter().map(String::as_str).collect();
    if unique.len() != content.required_checks.len() {
        return Err(format!(
            "{field}.content.required_checks contains duplicates"
        ));
    }
    Ok(())
}

fn validate_trust(trust: &TrustDocument, field: &str) -> Result<(), String> {
    canonical_uuid(&trust.organization_id, &format!("{field}.organization_id"))?;
    bounded_text(&trust.id, &format!("{field}.id"))?;
    bounded_text(&trust.version, &format!("{field}.version"))?;
    lowercase_sha256(
        &trust.content_digest,
        &format!("{field}.content_digest"),
        true,
    )?;
    validate_trust_content(&trust.content, field)?;
    let content = serde_json::to_value(&trust.content).map_err(|error| error.to_string())?;
    if canonical_digest(&content)? != trust.content_digest {
        return Err(format!("{field}.content_digest does not match content"));
    }
    Ok(())
}

fn validate_snapshot_trust(
    trust: &SnapshotTrustProfile,
    organization_id: &str,
) -> Result<(), String> {
    let document = TrustDocument {
        organization_id: organization_id.to_string(),
        id: trust.reference.id.clone(),
        version: trust.reference.version.clone(),
        content_digest: trust.reference.content_digest.clone(),
        content: trust.content.clone(),
    };
    validate_trust(&document, "governance_snapshot.trust_profile")
}

fn validate_trust_content(content: &TrustContent, field: &str) -> Result<(), String> {
    if content.trusted_issuers.is_empty()
        || content
            .trusted_issuers
            .iter()
            .any(|issuer| !issuer.starts_with("did:") || issuer.len() > 255)
        || !is_sorted_unique(&content.trusted_issuers)
    {
        return Err(format!(
            "{field}.content.trusted_issuers must be a non-empty sorted unique list"
        ));
    }
    if content.allow_public_did_fallback {
        return Err(format!(
            "{field}.content.allow_public_did_fallback must be false"
        ));
    }
    Ok(())
}

fn canonical_digest(value: &Value) -> Result<String, String> {
    let canonical = canonical_json(value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())))
}

fn canonical_json(value: &Value) -> Result<String, String> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_string(value).map_err(|_| "value is not canonical JSON".to_string())
        }
        Value::Array(values) => {
            let parts = values
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("[{}]", parts.join(",")))
        }
        Value::Object(values) => {
            let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let mut parts = Vec::with_capacity(keys.len());
            for key in keys {
                let encoded_key = serde_json::to_string(key)
                    .map_err(|_| "value is not canonical JSON".to_string())?;
                parts.push(format!("{encoded_key}:{}", canonical_json(&values[key])?));
            }
            Ok(format!("{{{}}}", parts.join(",")))
        }
    }
}

fn required_checks(purpose: &str) -> Result<&'static [&'static str], String> {
    match purpose {
        SESSION_CREATE_PURPOSE | DIRECT_VERIFY_PURPOSE => Ok(ALL_PRESENTATION_CHECKS),
        VDS_NC_VERIFY_PURPOSE => Ok(VDS_CHECKS),
        _ => Err("Unsupported verification purpose".into()),
    }
}

fn require_purpose_checks(purpose: &str, checks: &[String]) -> Result<(), Vec<String>> {
    let required = required_checks(purpose).map_err(|error| vec![error])?;
    let actual: BTreeSet<&str> = checks.iter().map(String::as_str).collect();
    let missing: Vec<String> = required
        .iter()
        .filter(|check| !actual.contains(**check))
        .map(|check| (*check).to_string())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

fn bounded_text(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 255 {
        Err(format!("{field} must be non-empty bounded text"))
    } else {
        Ok(())
    }
}

fn lowercase_sha256(value: &str, field: &str, prefixed: bool) -> Result<(), String> {
    let value = if prefixed {
        value
            .strip_prefix("sha256:")
            .ok_or_else(|| format!("{field} must be a lowercase SHA-256 digest"))?
    } else {
        value
    };
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!("{field} must be lowercase SHA-256"))
    }
}

fn canonical_uuid(value: &str, field: &str) -> Result<(), String> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| format!("{field} must be a canonical UUID"))?;
    if parsed.to_string() != value {
        return Err(format!("{field} must be a canonical UUID"));
    }
    Ok(())
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16)?;
            let low = (pair[1] as char).to_digit(16)?;
            Some(((high << 4) | low) as u8)
        })
        .collect()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Deserialize)]
    struct BehaviorFixture {
        governance: Value,
        definition: Value,
        authorization_cases: Vec<AuthorizationCase>,
    }

    #[derive(Deserialize)]
    struct AuthorizationCase {
        name: String,
        api_key: String,
        purpose: String,
        expected_client_id: Option<String>,
        expected_error: Option<String>,
    }

    fn fixture() -> BehaviorFixture {
        serde_json::from_str(include_str!("../tests/fixtures/governance_behavior.json")).unwrap()
    }

    #[test]
    fn fixture_authorization_cases_are_fail_closed() {
        let fixture = fixture();
        let governance = fixture.governance;
        validate_governance_json(&governance.to_string()).unwrap();
        for case in fixture.authorization_cases {
            let result = authorize_governance_json(
                &json!({
                    "governance": governance,
                    "api_key": case.api_key,
                    "purpose": case.purpose,
                })
                .to_string(),
            );
            match (case.expected_client_id, case.expected_error) {
                (Some(client_id), None) => {
                    let snapshot: Value = serde_json::from_str(&result.unwrap()).unwrap();
                    assert_eq!(snapshot["client_id"], client_id, "{}", case.name);
                }
                (None, Some(error)) => {
                    assert!(result.unwrap_err().contains(&error), "{}", case.name);
                }
                _ => panic!("invalid behavior fixture case: {}", case.name),
            }
        }
    }

    #[test]
    fn fixture_snapshot_and_request_contract_is_fail_closed() {
        let fixture = fixture();
        let authorized = authorize_governance_json(
            &json!({
                "governance": fixture.governance,
                "api_key": "purpose-scoped-test-key",
                "purpose": DIRECT_VERIFY_PURPOSE,
            })
            .to_string(),
        )
        .unwrap();
        let snapshot: Value = serde_json::from_str(&authorized).unwrap();

        governance_from_snapshot_json(&json!({"snapshot": snapshot}).to_string()).unwrap();
        require_governance_purpose_json(
            &json!({"snapshot": snapshot, "purpose": DIRECT_VERIFY_PURPOSE}).to_string(),
        )
        .unwrap();
        validate_governance_request_json(
            &json!({
                "snapshot": snapshot,
                "verifier_id": "did:web:verifier.example",
                "presentation_definition": fixture.definition,
            })
            .to_string(),
        )
        .unwrap();

        let mut stale_component = snapshot.clone();
        stale_component["component"]["version"] = json!("0.0.1");
        let resumed = resume_governance_json(
            &json!({"governance": fixture.governance, "snapshot": stale_component}).to_string(),
        )
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&resumed).unwrap()["component"]["version"],
            "0.1.56"
        );

        let wrong_purpose = require_governance_purpose_json(
            &json!({"snapshot": snapshot, "purpose": VDS_NC_VERIFY_PURPOSE}).to_string(),
        )
        .unwrap_err();
        assert!(wrong_purpose.contains("not authorized"));

        let wrong_verifier = validate_governance_request_json(
            &json!({
                "snapshot": snapshot,
                "verifier_id": "did:web:attacker.example",
                "presentation_definition": fixture.definition,
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(wrong_verifier.contains("verifier_id"));

        let mut tampered = snapshot;
        tampered["trust_profile"]["content"]["trusted_issuers"] =
            json!(["did:web:attacker.example"]);
        assert!(governance_from_snapshot_json(&json!({"snapshot": tampered}).to_string()).is_err());
    }
}
