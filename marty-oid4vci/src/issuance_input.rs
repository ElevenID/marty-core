//! Compatibility input normalization shared by Rust language bindings.

use crate::types::ZkPredicateBinding;

/// Normalize legacy claim/predicate lists or JSON-encoded typed bindings.
/// Predicate-only input prefers birth_date, then the lexicographically first claim.
pub fn normalize_zk_predicate_claims(
    claims: &std::collections::HashMap<String, serde_json::Value>,
    raw: Vec<String>,
) -> Vec<ZkPredicateBinding> {
    if raw.is_empty() {
        return vec![];
    }

    let mut json_bindings: Vec<ZkPredicateBinding> = Vec::new();
    let mut all_json_bindings = true;
    for item in &raw {
        match serde_json::from_str::<ZkPredicateBinding>(item) {
            Ok(binding)
                if !binding.claim_name.is_empty() && !binding.supported_predicates.is_empty() =>
            {
                json_bindings.push(binding);
            }
            _ => {
                all_json_bindings = false;
                break;
            }
        }
    }
    if all_json_bindings {
        return json_bindings;
    }

    let mut claim_names: Vec<String> = Vec::new();
    let mut predicates: Vec<String> = Vec::new();
    for item in &raw {
        if claims.contains_key(item) {
            claim_names.push(item.clone());
        } else {
            predicates.push(item.clone());
        }
    }

    if !claim_names.is_empty() {
        let fallback_predicates = if predicates.is_empty() {
            claim_names.clone()
        } else {
            predicates.clone()
        };

        return claim_names
            .into_iter()
            .map(|claim_name| ZkPredicateBinding::multi(claim_name, fallback_predicates.clone()))
            .collect();
    }

    if !predicates.is_empty() {
        if claims.contains_key("birth_date") {
            return vec![ZkPredicateBinding::multi("birth_date", predicates)];
        }
        if let Some(first_claim_name) = claims.keys().min() {
            return vec![ZkPredicateBinding::multi(
                first_claim_name.clone(),
                predicates,
            )];
        }
    }

    raw.into_iter()
        .map(|name| ZkPredicateBinding::single(name.clone(), name))
        .collect()
}
