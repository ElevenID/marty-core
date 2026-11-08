//! Checked raw-value fallback for the protocol's predicate contract.
//!
//! A raw claim can never establish a zero-knowledge proof. Until a verifier
//! supplies a separate authenticated predicate-evidence boundary, proof-only
//! predicates remain unsatisfied, even when the raw comparison would pass.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::cmp::Ordering;

use super::service::ServicePolicyError;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServicePredicateFallback {
    #[default]
    AcceptRaw,
    RequirePredicate,
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PredicateSpec {
    predicate_type: String,
    params: Map<String, Value>,
    supported_circuits: Option<Vec<String>>,
    fallback_policy: Option<ServicePredicateFallback>,
}

pub(super) struct CompiledPredicate {
    fallback: ServicePredicateFallback,
    comparison: Comparison,
}

enum Comparison {
    Equal(Value),
    NotEqual(Value),
    Member(Vec<Value>),
    NonMember(Vec<Value>),
    Range {
        min: Number,
        max: Number,
    },
    Threshold {
        value: Number,
        ordering: Ordering,
        inclusive: bool,
    },
}

impl CompiledPredicate {
    pub(super) fn requires_proof(&self) -> bool {
        self.fallback == ServicePredicateFallback::RequirePredicate
    }

    pub(super) fn accepts_raw(&self, actual: Option<&Value>) -> bool {
        if self.fallback != ServicePredicateFallback::AcceptRaw {
            return false;
        }
        let Some(actual) = actual else { return false };
        match &self.comparison {
            Comparison::Equal(expected) => actual == expected,
            Comparison::NotEqual(expected) => actual != expected,
            Comparison::Member(values) => values.contains(actual),
            Comparison::NonMember(values) => !values.contains(actual),
            Comparison::Range { min, max } => actual.as_number().is_some_and(|number| {
                numeric_order(number, min).is_some_and(|order| order != Ordering::Less)
                    && numeric_order(number, max).is_some_and(|order| order != Ordering::Greater)
            }),
            Comparison::Threshold {
                value,
                ordering,
                inclusive,
            } => actual
                .as_number()
                .and_then(|number| numeric_order(number, value))
                .is_some_and(|actual_order| {
                    actual_order == *ordering || (*inclusive && actual_order == Ordering::Equal)
                }),
        }
    }
}

pub(super) fn compile(
    value: &Value,
    policy_fallback: ServicePredicateFallback,
    policy_circuits: &[String],
) -> Result<CompiledPredicate, ServicePolicyError> {
    let spec: PredicateSpec = serde_json::from_value(value.clone())
        .map_err(|_| invalid("predicate shape or fallback is unsupported"))?;
    let fallback = spec.fallback_policy.unwrap_or(policy_fallback);
    let circuits = spec
        .supported_circuits
        .as_deref()
        .unwrap_or(policy_circuits);
    if circuits.len() > 256
        || circuits
            .iter()
            .any(|id| id.trim().is_empty() || id.len() > 4096)
    {
        return Err(invalid(
            "predicate circuits must be nonempty bounded identifiers",
        ));
    }
    if fallback == ServicePredicateFallback::RequirePredicate && circuits.is_empty() {
        return Err(invalid("REQUIRE_PREDICATE needs an explicit circuit"));
    }
    let params = &spec.params;
    let comparison = match spec.predicate_type.as_str() {
        "EQUALITY" | "INEQUALITY" => {
            exact_keys(params, &["target_value"])?;
            let target = params["target_value"].clone();
            if spec.predicate_type == "EQUALITY" {
                Comparison::Equal(target)
            } else {
                Comparison::NotEqual(target)
            }
        }
        "MEMBERSHIP" | "NON_MEMBERSHIP" => {
            let key = if spec.predicate_type == "MEMBERSHIP" {
                "allowed_values"
            } else {
                "excluded_values"
            };
            exact_keys(params, &[key])?;
            let values = params[key]
                .as_array()
                .filter(|values| !values.is_empty() && values.len() <= 256)
                .ok_or_else(|| invalid("predicate set must contain between 1 and 256 values"))?
                .clone();
            if spec.predicate_type == "MEMBERSHIP" {
                Comparison::Member(values)
            } else {
                Comparison::NonMember(values)
            }
        }
        "RANGE_PROOF" => {
            if params.contains_key("threshold") {
                exact_keys(params, &["threshold", "comparison"])?;
                let value = number(params, "threshold")?;
                let (ordering, inclusive) = match params["comparison"].as_str() {
                    Some("gt") => (Ordering::Greater, false),
                    Some("gte") => (Ordering::Greater, true),
                    Some("lt") => (Ordering::Less, false),
                    Some("lte") => (Ordering::Less, true),
                    _ => return Err(invalid("range comparison must be gt, gte, lt, or lte")),
                };
                Comparison::Threshold {
                    value,
                    ordering,
                    inclusive,
                }
            } else {
                exact_keys(params, &["min", "max"])?;
                let min = number(params, "min")?;
                let max = number(params, "max")?;
                if numeric_order(&min, &max).is_none_or(|order| order == Ordering::Greater) {
                    return Err(invalid(
                        "predicate range is reversed or cannot be compared exactly",
                    ));
                }
                Comparison::Range { min, max }
            }
        }
        _ => return Err(invalid("predicate type is unsupported")),
    };
    Ok(CompiledPredicate {
        fallback,
        comparison,
    })
}

fn exact_keys(params: &Map<String, Value>, keys: &[&str]) -> Result<(), ServicePolicyError> {
    if params.len() != keys.len() || keys.iter().any(|key| !params.contains_key(*key)) {
        return Err(invalid(
            "predicate parameters do not match the selected type",
        ));
    }
    Ok(())
}

fn number(params: &Map<String, Value>, key: &str) -> Result<Number, ServicePolicyError> {
    params[key]
        .as_number()
        .cloned()
        .ok_or_else(|| invalid("range values must be JSON numbers"))
}

// Preserve integer precision instead of rounding a u64 to f64 at a policy boundary.
// Mixed floating/integer comparisons outside f64's exact integer range fail closed.
fn numeric_order(left: &Number, right: &Number) -> Option<Ordering> {
    if let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) {
        return Some(left.cmp(&right));
    }
    if let (Some(left), Some(right)) = (left.as_u64(), right.as_u64()) {
        return Some(left.cmp(&right));
    }
    if left.as_i64().is_some_and(|value| value < 0) && right.as_u64().is_some() {
        return Some(Ordering::Less);
    }
    if right.as_i64().is_some_and(|value| value < 0) && left.as_u64().is_some() {
        return Some(Ordering::Greater);
    }
    const EXACT_INTEGER_LIMIT: u64 = 9_007_199_254_740_992;
    // Check the original integer before conversion: 2^53 + 1 rounds down to
    // 2^53 as an f64 and would otherwise pass a post-conversion magnitude guard.
    for number in [left, right] {
        if number
            .as_i64()
            .is_some_and(|value| value.unsigned_abs() > EXACT_INTEGER_LIMIT)
            || number
                .as_u64()
                .is_some_and(|value| value > EXACT_INTEGER_LIMIT)
        {
            return None;
        }
    }
    let left = left.as_f64()?;
    let right = right.as_f64()?;
    if left.abs() > EXACT_INTEGER_LIMIT as f64 || right.abs() > EXACT_INTEGER_LIMIT as f64 {
        return None;
    }
    left.partial_cmp(&right)
}

fn invalid(message: &str) -> ServicePolicyError {
    ServicePolicyError::InvalidRequest(format!("Invalid predicate: {message}"))
}
