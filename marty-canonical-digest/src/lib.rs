//! Marty JSON digest compatibility, not an RFC 8785 implementation.
//!
//! This algorithm is shared by verification governance and transport contracts.
//! Its serialization and error semantics are frozen independently of either caller.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn canonical_digest_json(value_json: &str) -> Result<String, String> {
    let value: Value =
        serde_json::from_str(value_json).map_err(|_| "value is not canonical JSON".to_string())?;
    canonical_digest(&value)
}

pub fn canonical_digest(value: &Value) -> Result<String, String> {
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
