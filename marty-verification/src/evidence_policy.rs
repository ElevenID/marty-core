//! Provider-neutral evidence policy decisions.
//!
//! Python adapters normalize service models into this JSON boundary. Revision
//! selection, requirement matching, context construction, PolicySet checks,
//! and Cedar authorization are owned here so every caller uses one kernel.

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, str::FromStr};

const BUNDLED_APPROVAL_POLICY: &str = r#"
@id("auto-approve-verified-external-evidence")
permit (
    principal is MIP::ServiceAccount,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    principal.service_name == "canvas-evidence-policy" &&
    context has evidence_provider &&
    context has evidence_verification_status &&
    context has evidence_scope_matched &&
    context has all_required_evidence_satisfied &&
    context has satisfied_requirement_count &&
    context has required_evidence_count &&
    context.evidence_verification_status == "VERIFIED" &&
    context.evidence_scope_matched &&
    context.all_required_evidence_satisfied &&
    context.satisfied_requirement_count >= context.required_evidence_count
};

@id("deny-unverified-external-evidence")
forbid (
    principal is MIP::ServiceAccount,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    principal.service_name == "canvas-evidence-policy" &&
    context has evidence_provider &&
    context has evidence_verification_status &&
    context.evidence_verification_status != "VERIFIED"
};

@id("deny-wrong-scope-external-evidence")
forbid (
    principal is MIP::ServiceAccount,
    action == MIP::Action::"applications:approve",
    resource
)
when {
    principal.service_name == "canvas-evidence-policy" &&
    context has evidence_provider &&
    context has evidence_scope_matched &&
    !context.evidence_scope_matched
};
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationRequest {
    app: ApplicationInput,
    #[serde(default)]
    template: Option<TemplateInput>,
    #[serde(default)]
    binding: Option<BindingInput>,
    #[serde(default)]
    requirements: Vec<Value>,
    #[serde(default)]
    facts: Vec<EvidenceFact>,
    #[serde(default)]
    policy_set: Option<ApprovalPolicySetInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplicationInput {
    id: String,
    organization_id: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TemplateInput {
    #[serde(default)]
    approval_policy_set_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingInput {
    #[serde(default)]
    approval_policy_set_id: Option<String>,
    #[serde(default)]
    auto_approve_on_evidence: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceFact {
    id: String,
    #[serde(default)]
    logical_key: String,
    provider: String,
    fact_type: String,
    subject_id: String,
    #[serde(default)]
    requirement_id: String,
    #[serde(default)]
    scope: Map<String, Value>,
    #[serde(default)]
    assertion: Map<String, Value>,
    #[serde(default)]
    verification: Map<String, Value>,
    #[serde(default)]
    source: Map<String, Value>,
    #[serde(default)]
    effective_at: Option<DateTime<Utc>>,
    observed_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalPolicySetInput {
    #[serde(rename = "id")]
    _id: String,
    status: String,
    policy_type: String,
    cedar_policies: Value,
}

#[derive(Debug, Serialize)]
struct EvidencePolicyDecision {
    allowed: bool,
    engine: String,
    policy_source: String,
    policy_set_id: Option<String>,
    reasons: Vec<String>,
    errors: Vec<String>,
    context: Value,
}

pub fn evaluate_application_evidence_policy_json(raw: &str) -> Result<String, String> {
    let request: EvaluationRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid evidence policy request: {error}"))?;
    let decision = evaluate(request)?;
    serde_json::to_string(&decision).map_err(|error| error.to_string())
}

pub fn current_evidence_heads_json(raw: &str) -> Result<String, String> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HeadsRequest {
        facts: Vec<EvidenceFact>,
    }
    let request: HeadsRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid evidence heads request: {error}"))?;
    let ids: Vec<String> = current_heads(request.facts)
        .into_iter()
        .map(|fact| fact.id)
        .collect();
    serde_json::to_string(&ids).map_err(|error| error.to_string())
}

/// Language-neutral conformance vectors used by native and adapter tests.
pub fn behavior_fixture_json() -> &'static str {
    include_str!("../tests/fixtures/evidence_policy_behavior.json")
}

fn evaluate(request: EvaluationRequest) -> Result<EvidencePolicyDecision, String> {
    let facts = current_heads(request.facts);
    let context = build_context(request.binding.as_ref(), &request.requirements, &facts);
    let policy_set_id = request
        .binding
        .as_ref()
        .and_then(|binding| binding.approval_policy_set_id.clone())
        .or_else(|| {
            request
                .template
                .as_ref()
                .and_then(|template| template.approval_policy_set_id.clone())
        });
    let policy_source = if policy_set_id.is_some() {
        "policy_set"
    } else {
        "bundled"
    };

    let policy_text = if let Some(id) = policy_set_id.as_deref() {
        let Some(policy_set) = request.policy_set.as_ref() else {
            return Ok(policy_error(
                "policy_set_unavailable",
                policy_source,
                policy_set_id.clone(),
                format!(
                    "Approval PolicySet {id} was not found for organization {}",
                    request.app.organization_id
                ),
                context,
            ));
        };
        if normalize_policy_value(&policy_set.status) != "ACTIVE" {
            return Ok(policy_error(
                "policy_set_inactive",
                policy_source,
                policy_set_id.clone(),
                format!("Approval PolicySet {id} is not active"),
                context,
            ));
        }
        let policy_type = normalize_policy_value(&policy_set.policy_type);
        if policy_type != "APPROVAL_RULES" && policy_type != "CUSTOM" {
            return Ok(policy_error(
                "policy_set_wrong_type",
                policy_source,
                policy_set_id.clone(),
                format!(
                    "PolicySet {id} has unsupported approval policy_type {:?}",
                    policy_set.policy_type
                ),
                context,
            ));
        }
        let text = normalize_cedar_policy_text(&policy_set.cedar_policies);
        if text.is_empty() {
            return Ok(policy_error(
                "policy_set_empty",
                policy_source,
                policy_set_id.clone(),
                format!("Approval PolicySet {id} has no enabled Cedar policies"),
                context,
            ));
        }
        text
    } else {
        BUNDLED_APPROVAL_POLICY.to_string()
    };

    let (allowed, reasons, errors) = authorize(&request.app, &facts, &context, &policy_text)
        .unwrap_or_else(|error| (false, Vec::new(), vec![error]));
    Ok(EvidencePolicyDecision {
        allowed,
        engine: "cedar".into(),
        policy_source: policy_source.into(),
        policy_set_id,
        reasons,
        errors,
        context,
    })
}

fn policy_error(
    engine: &str,
    policy_source: &str,
    policy_set_id: Option<String>,
    error: String,
    context: Value,
) -> EvidencePolicyDecision {
    EvidencePolicyDecision {
        allowed: false,
        engine: engine.into(),
        policy_source: policy_source.into(),
        policy_set_id,
        reasons: Vec::new(),
        errors: vec![error],
        context,
    }
}

fn authorize(
    app: &ApplicationInput,
    facts: &[EvidenceFact],
    context: &Value,
    policy_text: &str,
) -> Result<(bool, Vec<String>, Vec<String>), String> {
    let policies = PolicySet::from_str(policy_text).map_err(|error| error.to_string())?;
    let entities = Entities::from_json_value(build_entities(app, facts), None)
        .map_err(|error| error.to_string())?;
    let cedar_context =
        Context::from_json_value(context.clone(), None).map_err(|error| error.to_string())?;
    let request = Request::new(
        EntityUid::from_str(r#"MIP::ServiceAccount::"canvas-evidence-policy""#)
            .map_err(|error| error.to_string())?,
        EntityUid::from_str(r#"MIP::Action::"applications:approve""#)
            .map_err(|error| error.to_string())?,
        EntityUid::from_str(&format!(r#"MIP::Application::"{}""#, app.id))
            .map_err(|error| error.to_string())?,
        cedar_context,
        None,
    )
    .map_err(|error| error.to_string())?;
    let response = Authorizer::new().is_authorized(&request, &policies, &entities);
    let mut reasons: Vec<String> = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect();
    let mut errors: Vec<String> = response
        .diagnostics()
        .errors()
        .map(ToString::to_string)
        .collect();
    reasons.sort();
    errors.sort();
    Ok((response.decision() == Decision::Allow, reasons, errors))
}

fn build_entities(app: &ApplicationInput, facts: &[EvidenceFact]) -> Value {
    let app_uid = json!({"type": "MIP::Application", "id": app.id});
    let organization = json!({"type": "MIP::Organization", "id": app.organization_id});
    let mut entities = vec![
        json!({
            "uid": {"type": "MIP::ServiceAccount", "id": "canvas-evidence-policy"},
            "attrs": {"service_name": "canvas-evidence-policy"},
            "parents": [organization]
        }),
        json!({"uid": organization, "attrs": {}, "parents": []}),
        json!({
            "uid": app_uid,
            "attrs": {"risk_score": 0, "status": app.status},
            "parents": [organization]
        }),
    ];
    entities.extend(facts.iter().map(|fact| {
        json!({
            "uid": {"type": "MIP::EvidenceFact", "id": fact.id},
            "attrs": {
                "provider": fact.provider,
                "fact_type": fact.fact_type,
                "subject_id": fact.subject_id,
                "verification_status": string_field(&fact.verification, "status"),
            },
            "parents": [app_uid, organization]
        })
    }));
    Value::Array(entities)
}

fn current_heads(facts: Vec<EvidenceFact>) -> Vec<EvidenceFact> {
    let mut heads: BTreeMap<String, EvidenceFact> = BTreeMap::new();
    for fact in facts {
        let logical_key = if fact.logical_key.is_empty() {
            fact.id.clone()
        } else {
            fact.logical_key.clone()
        };
        let replace = heads
            .get(&logical_key)
            .is_none_or(|current| fact_order(&fact) > fact_order(current));
        if replace {
            heads.insert(logical_key, fact);
        }
    }
    let mut heads: Vec<EvidenceFact> = heads.into_values().collect();
    heads.sort_by_key(|fact| (fact.observed_at, fact.created_at, fact.id.clone()));
    heads
}

fn fact_order(fact: &EvidenceFact) -> (DateTime<Utc>, DateTime<Utc>, DateTime<Utc>, &str) {
    (
        fact.effective_at.unwrap_or(fact.observed_at),
        fact.observed_at,
        fact.created_at,
        &fact.id,
    )
}

fn build_context(
    binding: Option<&BindingInput>,
    requirements: &[Value],
    facts: &[EvidenceFact],
) -> Value {
    let (required, satisfied, all_satisfied, scope_matched) =
        summarize_requirements(requirements, facts);
    let latest = facts.last();
    let verified = facts.iter().filter(|fact| fact_verified(fact)).count();
    let requirement_auto_issue = requirements.iter().any(|requirement| {
        requirement_mapping(requirement)
            .and_then(|value| value.get("auto_issue_on_permit"))
            .is_some_and(truthy)
    });
    json!({
        "risk_score": 0,
        "document_verification_passed": true,
        "biometric_match_score": 100,
        "evidence_count": facts.len(),
        "applicant_country": "US",
        "evidence_provider": latest.map_or("canvas", |fact| fact.provider.as_str()),
        "evidence_fact_type": latest.map_or("", |fact| fact.fact_type.as_str()),
        "evidence_verification_status": latest.map_or_else(
            || "UNVERIFIED".to_string(),
            |fact| {
                let status = string_field(&fact.verification, "status");
                if status.is_empty() { "UNVERIFIED".into() } else { status.to_uppercase() }
            }
        ),
        "evidence_scope_matched": scope_matched,
        "verified_evidence_count": verified,
        "required_evidence_count": required,
        "satisfied_requirement_count": satisfied,
        "all_required_evidence_satisfied": all_satisfied,
        "auto_issue_eligible": all_satisfied && (
            requirement_auto_issue
                || binding.is_some_and(|value| value.auto_approve_on_evidence)
        ),
    })
}

fn summarize_requirements(
    requirements: &[Value],
    facts: &[EvidenceFact],
) -> (usize, usize, bool, bool) {
    let required: Vec<&Value> = requirements
        .iter()
        .filter(|requirement| {
            requirement_mapping(requirement).and_then(|value| value.get("required"))
                != Some(&Value::Bool(false))
        })
        .collect();
    let defaults;
    let effective: Vec<&Value> = if !required.is_empty() {
        required
    } else if !requirements.is_empty() {
        return (0, 0, false, true);
    } else {
        defaults = vec![Value::String("canvas.course_completion".into())];
        defaults.iter().collect()
    };

    let mut satisfied = 0;
    let mut scope_matched = true;
    for requirement in &effective {
        let scope = requirement_scope(requirement);
        let type_matches: Vec<&EvidenceFact> = facts
            .iter()
            .filter(|fact| requirement_identity_matches(fact, requirement, false))
            .collect();
        if !scope.is_empty()
            && !type_matches
                .iter()
                .any(|fact| scope_matches(&fact.scope, scope))
        {
            scope_matched = false;
        }
        if facts
            .iter()
            .any(|fact| fact_satisfies_requirement(fact, requirement))
        {
            satisfied += 1;
        }
    }
    let count = effective.len();
    (count, satisfied, satisfied >= count, scope_matched)
}

fn fact_satisfies_requirement(fact: &EvidenceFact, requirement: &Value) -> bool {
    if let Some(requirement_id) = requirement_string(requirement, "requirement_id") {
        if !requirement_id.is_empty()
            && !fact.requirement_id.is_empty()
            && fact.requirement_id != requirement_id
        {
            return false;
        }
    }
    if !requirement_identity_matches(fact, requirement, true) {
        return false;
    }
    let method = requirement_string(requirement, "verification_method").unwrap_or_default();
    if !method.is_empty() && string_field(&fact.verification, "method") != method {
        return false;
    }
    if !scope_matches(&fact.scope, requirement_scope(requirement)) {
        return false;
    }
    fact_verified(fact) && pass_rule_satisfied(fact, requirement)
}

fn requirement_identity_matches(
    fact: &EvidenceFact,
    requirement: &Value,
    include_scope: bool,
) -> bool {
    let provider = requirement_string(requirement, "provider").unwrap_or_default();
    let source = requirement_string(requirement, "source").unwrap_or_default();
    let fact_type = requirement_type(requirement);
    (provider.is_empty() || fact.provider == provider)
        && (source.is_empty() || string_field(&fact.source, "source") == source)
        && (fact_type.is_empty() || fact.fact_type == fact_type)
        && (!include_scope || scope_matches(&fact.scope, requirement_scope(requirement)))
}

fn scope_matches(actual: &Map<String, Value>, expected: &Map<String, Value>) -> bool {
    expected.iter().all(|(key, value)| {
        value.is_null() || py_string_or_empty(actual.get(key)) == py_string_or_empty(Some(value))
    })
}

fn pass_rule_satisfied(fact: &EvidenceFact, requirement: &Value) -> bool {
    let Some(rule) = requirement_mapping(requirement)
        .and_then(|value| value.get("pass_rule"))
        .and_then(Value::as_object)
    else {
        return true;
    };
    if rule.is_empty() {
        return true;
    }
    if ["all", "any", "not", "path"]
        .iter()
        .any(|key| rule.contains_key(*key))
    {
        return path_condition_satisfied(fact, &Value::Object(rule.clone()));
    }
    let mut evaluated = false;
    for key in ["completed", "submitted", "passed", "eligible"] {
        if let Some(expected) = rule.get(key) {
            evaluated = true;
            if truthy(fact.assertion.get(key).unwrap_or(&Value::Null)) != truthy(expected) {
                return false;
            }
        }
    }
    for (assertion_key, aliases) in [
        ("score", ["score", "min_score"]),
        ("score_percent", ["score_percent", "min_score_percent"]),
    ] {
        for alias in aliases {
            if let Some(expected) = rule.get(alias) {
                evaluated = true;
                if !comparison_satisfied(fact.assertion.get(assertion_key), expected) {
                    return false;
                }
            }
        }
    }
    for (assertion_key, aliases) in [
        ("membership_status", ["membership_status", "status", ""]),
        ("roles", ["roles_include", "role", "role_includes"]),
    ] {
        for alias in aliases.into_iter().filter(|alias| !alias.is_empty()) {
            if let Some(expected) = rule.get(alias) {
                evaluated = true;
                if !string_rule_satisfied(fact.assertion.get(assertion_key), expected) {
                    return false;
                }
            }
        }
    }
    evaluated
}

fn path_condition_satisfied(fact: &EvidenceFact, condition: &Value) -> bool {
    let Some(condition) = condition.as_object() else {
        return truthy(condition);
    };
    if let Some(items) = condition.get("all") {
        return items.as_array().is_some_and(|items| {
            items
                .iter()
                .all(|item| path_condition_satisfied(fact, item))
        });
    }
    if let Some(items) = condition.get("any") {
        return items.as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| path_condition_satisfied(fact, item))
        });
    }
    if let Some(item) = condition.get("not") {
        return !path_condition_satisfied(fact, item);
    }
    let Some(path) = condition.get("path").and_then(Value::as_str) else {
        return false;
    };
    if path.is_empty() {
        return false;
    }
    let actual = fact_path_value(fact, path);
    let operator = condition
        .get("op")
        .or_else(|| condition.get("operator"))
        .and_then(Value::as_str)
        .unwrap_or(if condition.contains_key("value") {
            "eq"
        } else {
            "exists"
        })
        .to_lowercase();
    let expected = condition.get("value").unwrap_or(&Value::Null);
    match operator.as_str() {
        "exists" | "present" => actual.as_ref().is_some_and(|value| !value.is_null()),
        "truthy" | "true" => actual.as_ref().is_some_and(truthy),
        "falsy" | "false" => !actual.as_ref().is_some_and(truthy),
        "eq" | "equals" | "==" => py_equal(actual.as_ref().unwrap_or(&Value::Null), expected),
        "neq" | "not_equals" | "!=" => !py_equal(actual.as_ref().unwrap_or(&Value::Null), expected),
        ">=" | "gt_eq" | "gte" | "min" => compare_numbers(actual.as_ref(), expected, |a, b| a >= b),
        ">" | "gt" => compare_numbers(actual.as_ref(), expected, |a, b| a > b),
        "<=" | "lt_eq" | "lte" | "max" => compare_numbers(actual.as_ref(), expected, |a, b| a <= b),
        "<" | "lt" => compare_numbers(actual.as_ref(), expected, |a, b| a < b),
        "in" => expected.as_array().is_some_and(|values| {
            values
                .iter()
                .any(|value| py_equal(actual.as_ref().unwrap_or(&Value::Null), value))
        }),
        "contains" => actual.as_ref().is_some_and(|actual| match actual {
            Value::Array(values) => values.iter().any(|value| py_equal(value, expected)),
            Value::String(value) => value.contains(&py_string(expected)),
            _ => false,
        }),
        _ => false,
    }
}

fn fact_path_value(fact: &EvidenceFact, path: &str) -> Option<Value> {
    let normalized = path.trim();
    let root = json!({
        "assertion": fact.assertion,
        "scope": fact.scope,
        "verification": fact.verification,
        "source": fact.source,
        "provider": fact.provider,
        "fact_type": fact.fact_type,
        "subject_id": fact.subject_id,
    });
    let uses_root = ["assertion.", "scope.", "verification.", "source.", "$."]
        .iter()
        .any(|prefix| normalized.starts_with(prefix));
    let owned = if uses_root {
        root
    } else {
        Value::Object(fact.assertion.clone())
    };
    path_value_owned(owned, normalized)
}

fn path_value_owned(mut current: Value, path: &str) -> Option<Value> {
    let mut path = path.trim();
    if let Some(stripped) = path.strip_prefix("$.") {
        path = stripped;
    } else if let Some(stripped) = path.strip_prefix('$') {
        path = stripped.trim_start_matches('.');
    }
    if path.is_empty() {
        return None;
    }
    for part in path.split('.').filter(|part| !part.is_empty()) {
        current = match current {
            Value::Object(mut values) => values.remove(part)?,
            Value::Array(mut values) => values.remove(part.parse::<usize>().ok()?),
            _ => return None,
        };
    }
    Some(current)
}

fn comparison_satisfied(actual: Option<&Value>, rule: &Value) -> bool {
    let Some(actual) = actual.and_then(numeric_value) else {
        return false;
    };
    if let Some(rule) = rule.as_object() {
        let mut saw = false;
        for (operator, compare) in [
            (">=", 0),
            ("min", 0),
            (">", 1),
            ("<=", 2),
            ("max", 2),
            ("<", 3),
            ("==", 4),
            ("equals", 4),
        ] {
            let Some(expected) = rule.get(operator) else {
                continue;
            };
            saw = true;
            let Some(expected) = numeric_value(expected) else {
                return false;
            };
            let matched = match compare {
                0 => actual >= expected,
                1 => actual > expected,
                2 => actual <= expected,
                3 => actual < expected,
                _ => actual == expected,
            };
            if !matched {
                return false;
            }
        }
        saw
    } else {
        numeric_value(rule).is_some_and(|expected| actual >= expected)
    }
}

fn compare_numbers(
    actual: Option<&Value>,
    expected: &Value,
    compare: fn(f64, f64) -> bool,
) -> bool {
    actual
        .and_then(numeric_value)
        .zip(numeric_value(expected))
        .is_some_and(|(actual, expected)| compare(actual, expected))
}

fn numeric_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn string_rule_satisfied(actual: Option<&Value>, expected: &Value) -> bool {
    if let Some(expected) = expected.as_array() {
        return expected
            .iter()
            .any(|expected| string_rule_satisfied(actual, expected));
    }
    if let Some(actual) = actual.and_then(Value::as_array) {
        return actual
            .iter()
            .any(|actual| py_string(actual).eq_ignore_ascii_case(&py_string(expected)));
    }
    py_string_or_empty(actual).eq_ignore_ascii_case(&py_string_or_empty(Some(expected)))
}

fn requirement_mapping(requirement: &Value) -> Option<&Map<String, Value>> {
    requirement.as_object()
}

fn requirement_type(requirement: &Value) -> String {
    if let Some(value) = requirement.as_str() {
        return value.to_string();
    }
    ["fact_type", "evidence_type", "type"]
        .iter()
        .find_map(|key| requirement_string(requirement, key).filter(|value| !value.is_empty()))
        .unwrap_or_default()
}

fn requirement_scope(requirement: &Value) -> &Map<String, Value> {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    requirement_mapping(requirement)
        .and_then(|mapping| mapping.get("scope").or_else(|| mapping.get("canvas_scope")))
        .and_then(Value::as_object)
        .unwrap_or(&EMPTY)
}

fn requirement_string(requirement: &Value, key: &str) -> Option<String> {
    requirement_mapping(requirement)
        .and_then(|mapping| mapping.get(key))
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn fact_verified(fact: &EvidenceFact) -> bool {
    string_field(&fact.verification, "status").to_uppercase() == "VERIFIED"
}

fn string_field(values: &Map<String, Value>, key: &str) -> String {
    values
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn normalize_policy_value(value: &str) -> String {
    value.trim().to_uppercase()
}

fn normalize_cedar_policy_text(value: &Value) -> String {
    match value {
        Value::String(value) => {
            let stripped = value.trim();
            if stripped.is_empty() {
                return String::new();
            }
            serde_json::from_str::<Value>(stripped)
                .map(|parsed| normalize_cedar_policy_text(&parsed))
                .unwrap_or_else(|_| stripped.to_string())
        }
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_object)
            .filter(|policy| policy.get("enabled") != Some(&Value::Bool(false)))
            .filter_map(|policy| policy.get("cedar_text").and_then(Value::as_str))
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n"),
        Value::Object(value) => value.get("cedar_policies").map_or_else(
            || {
                if value.get("enabled") == Some(&Value::Bool(false)) {
                    String::new()
                } else {
                    value
                        .get("cedar_text")
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .unwrap_or_default()
                        .to_string()
                }
            },
            normalize_cedar_policy_text,
        ),
        _ => String::new(),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn py_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Bool(left), Value::Number(right)) | (Value::Number(right), Value::Bool(left)) => {
            right.as_f64() == Some(if *left { 1.0 } else { 0.0 })
        }
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        _ => left == right,
    }
}

fn py_string_or_empty(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(value) if !truthy(value) => String::new(),
        Some(value) => py_string(value),
    }
}

fn py_string(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Array(_) | Value::Object(_) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct BehaviorFixture {
        cases: Vec<BehaviorCase>,
        heads: HeadsCase,
    }

    #[derive(Deserialize)]
    struct BehaviorCase {
        name: String,
        request: Value,
        allowed: bool,
        engine: String,
        required_count: usize,
        satisfied_count: usize,
        scope_matched: bool,
    }

    #[derive(Deserialize)]
    struct HeadsCase {
        facts: Vec<EvidenceFact>,
        expected_ids: Vec<String>,
    }

    fn fixture() -> BehaviorFixture {
        serde_json::from_str(include_str!(
            "../tests/fixtures/evidence_policy_behavior.json"
        ))
        .unwrap()
    }

    #[test]
    fn language_neutral_policy_cases_match() {
        for case in fixture().cases {
            let raw = evaluate_application_evidence_policy_json(&case.request.to_string()).unwrap();
            let decision: Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(decision["allowed"], case.allowed, "{}", case.name);
            assert_eq!(decision["engine"], case.engine, "{}", case.name);
            assert_eq!(
                decision["context"]["required_evidence_count"], case.required_count,
                "{}",
                case.name
            );
            assert_eq!(
                decision["context"]["satisfied_requirement_count"], case.satisfied_count,
                "{}",
                case.name
            );
            assert_eq!(
                decision["context"]["evidence_scope_matched"], case.scope_matched,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn language_neutral_revision_heads_match() {
        let case = fixture().heads;
        let raw = current_evidence_heads_json(&json!({"facts": case.facts}).to_string()).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&raw).unwrap(),
            case.expected_ids
        );
    }
}
