//! Deterministic evidence-reconciliation state decisions.
//!
//! Fetching, persistence, audit emission, and issuance remain caller-owned.
//! This module is the sole owner of action selection, metric classification,
//! requirement precedence, Canvas account extraction, and stale-receipt reasons.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationPlanRequest {
    policy: Map<String, Value>,
    policy_freshly_evaluated: bool,
    issuance_transaction: Option<TransactionState>,
    application_issuance_transaction_id: Option<String>,
    issue_on_permit: bool,
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionState {
    id: String,
    status: String,
    is_expired: bool,
}

#[derive(Debug, Serialize)]
struct ReconciliationPlan {
    next: &'static str,
    action: &'static str,
    metric_increments: BTreeMap<&'static str, u64>,
    policy_event: Option<&'static str>,
    issuance_transaction_id: Option<String>,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaleReceiptRequest {
    issuance_response: Value,
    receipt_issuance_transaction_id: Option<String>,
    application: Option<StaleApplication>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StaleApplication {
    policy: Option<Map<String, Value>>,
    issuance_transaction_id: Option<String>,
}

pub fn reconciliation_plan_json(raw: &str) -> Result<String, String> {
    let request: ReconciliationPlanRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid evidence reconciliation plan request: {error}"))?;
    serde_json::to_string(&reconciliation_plan(request)).map_err(|error| error.to_string())
}

pub fn stale_receipt_reasons_json(raw: &str) -> Result<String, String> {
    let request: StaleReceiptRequest = serde_json::from_str(raw)
        .map_err(|error| format!("invalid stale evidence receipt request: {error}"))?;
    serde_json::to_string(&stale_receipt_reasons(&request)).map_err(|error| error.to_string())
}

pub fn behavior_fixture_json() -> &'static str {
    include_str!("../tests/fixtures/evidence_reconciliation_behavior.json")
}

fn reconciliation_plan(request: ReconciliationPlanRequest) -> ReconciliationPlan {
    let app_transaction_id = request.application_issuance_transaction_id.clone();
    let policy = &request.policy;
    let allowed = policy.get("allowed") == Some(&Value::Bool(true));
    let (metrics, policy_event) = if request.policy_freshly_evaluated {
        let mut metrics = metric("evaluated_policies");
        metrics.insert(
            if allowed {
                "policy_permits"
            } else {
                "policy_denies"
            },
            1,
        );
        (metrics, Some(if allowed { "permitted" } else { "denied" }))
    } else {
        (BTreeMap::new(), None)
    };

    if !allowed {
        let errors = policy
            .get("errors")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();
        return complete(
            "policy_denied",
            metrics,
            policy_event,
            app_transaction_id,
            errors,
        );
    }
    if let Some(transaction) = request.issuance_transaction.as_ref() {
        if transaction.status == "pending" && !transaction.is_expired {
            return complete(
                "issuance_transaction_already_pending",
                metrics,
                policy_event,
                Some(transaction.id.clone()),
                Vec::new(),
            );
        }
    }
    if !request.issue_on_permit {
        return complete(
            "policy_permitted_issue_disabled",
            metrics,
            policy_event,
            app_transaction_id,
            Vec::new(),
        );
    }
    if request.dry_run {
        return complete(
            "would_create_or_refresh_issuance_transaction",
            metrics,
            policy_event,
            app_transaction_id,
            Vec::new(),
        );
    }
    ReconciliationPlan {
        next: "approve",
        action: if request.policy_freshly_evaluated {
            "approval_issuance_succeeded"
        } else {
            "approval_issuance_recovered_from_policy_permit"
        },
        metric_increments: metrics,
        policy_event,
        issuance_transaction_id: app_transaction_id,
        errors: Vec::new(),
    }
}

fn complete(
    action: &'static str,
    metric_increments: BTreeMap<&'static str, u64>,
    policy_event: Option<&'static str>,
    issuance_transaction_id: Option<String>,
    errors: Vec<String>,
) -> ReconciliationPlan {
    ReconciliationPlan {
        next: "complete",
        action,
        metric_increments,
        policy_event,
        issuance_transaction_id,
        errors,
    }
}

fn metric(name: &'static str) -> BTreeMap<&'static str, u64> {
    BTreeMap::from([(name, 1)])
}

fn stale_receipt_reasons(request: &StaleReceiptRequest) -> Vec<&'static str> {
    let response = request.issuance_response.as_object();
    let app_id = response
        .and_then(|value| value.get("application_id"))
        .filter(|value| !is_falsy(value));
    if app_id.is_none() {
        return vec!["receipt_missing_application_id"];
    }
    let Some(application) = request.application.as_ref() else {
        return vec!["receipt_application_missing"];
    };

    let mut reasons = Vec::new();
    if response
        .and_then(|value| value.get("evidence_facts"))
        .is_none_or(is_falsy)
    {
        reasons.push("receipt_without_evidence_fact_metadata");
    }
    let response_policy = response
        .and_then(|value| value.get("policy_decision"))
        .and_then(Value::as_object);
    let policy = response_policy.or(application.policy.as_ref());
    if let Some(policy) = policy {
        if policy.get("allowed") == Some(&Value::Bool(true))
            && request.receipt_issuance_transaction_id.is_none()
            && application.issuance_transaction_id.is_none()
        {
            reasons.push("policy_permit_without_issuance_transaction");
        }
    } else {
        reasons.push("receipt_without_policy_decision");
    }
    reasons
}

fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => true,
        Value::Number(value) => value.as_f64() == Some(0.0),
        Value::String(value) => value.is_empty(),
        Value::Array(value) => value.is_empty(),
        Value::Object(value) => value.is_empty(),
        Value::Bool(true) => false,
    }
}
