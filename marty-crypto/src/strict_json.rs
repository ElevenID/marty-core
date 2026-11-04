//! JSON parsing that rejects duplicate members at every object depth.
//! Callers retain root-shape requirements, size bounds and protocol errors.

use serde::de::{self, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::fmt;

/// Parse a JSON value while rejecting repeated object members recursively.
///
/// This preserves the existing Serde visitor and number handling. Root shape,
/// byte limits and protocol interpretation belong to the calling boundary.
pub fn parse_unique_json(bytes: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice::<UniqueValue>(bytes).map(|value| value.0)
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some((name, value)) = access.next_entry::<String, UniqueValue>()? {
            if object.insert(name, value.0).is_some() {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
        }
        Ok(UniqueValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_unique_json;
    use serde_json::{json, Value};

    #[test]
    fn unique_nested_values_and_sibling_member_names_are_preserved() {
        let raw = br#"{"items":[true,false,null,"text"],"left":{"id":1},"right":{"id":2}}"#;
        assert_eq!(
            parse_unique_json(raw).unwrap(),
            json!({"items": [true, false, null, "text"], "left": {"id": 1}, "right": {"id": 2}})
        );
    }

    #[test]
    fn duplicate_members_are_rejected_at_every_object_depth() {
        for raw in [
            br#"{"id":1,"id":2}"#.as_slice(),
            br#"{"cnf":{"jwk":{"kty":"EC","kty":"oct"}}}"#,
            br#"{"items":[{"id":1,"id":2}]}"#,
            br#"{"a":1,"\u0061":2}"#,
        ] {
            let error = parse_unique_json(raw).unwrap_err();
            assert!(error.to_string().contains("duplicate JSON object member"));
        }
    }

    #[test]
    fn duplicate_diagnostic_keeps_the_input_location() {
        let error = parse_unique_json(b"{\"a\":1,\n \"a\":2}").unwrap_err();
        assert_eq!(error.line(), 2);
        assert_eq!(error.column(), 7);
    }

    #[test]
    fn raw_parser_accepts_scalar_and_array_roots_without_protocol_policy() {
        for raw in [
            "null",
            "true",
            "false",
            "\"text\"",
            "[]",
            "[1,2]",
            "-1",
            "18446744073709551615",
        ] {
            assert_eq!(
                parse_unique_json(raw.as_bytes()).unwrap(),
                serde_json::from_str::<Value>(raw).unwrap()
            );
        }
        // Preserve acceptance across both ordinary and arbitrary-precision
        // Serde feature graphs; the existing visitor owns number handling.
        for raw in ["1.5", "-0.0", "1e2", "-1e-2"] {
            assert!(parse_unique_json(raw.as_bytes()).is_ok());
        }
    }

    #[test]
    fn malformed_duplicate_value_is_parsed_before_duplicate_rejection() {
        let raw = br#"{"id":1,"id":]}"#;
        let error = parse_unique_json(raw).unwrap_err();
        let syntax_error = serde_json::from_slice::<Value>(raw).unwrap_err();
        assert_eq!(error.to_string(), syntax_error.to_string());
    }

    #[test]
    fn trailing_documents_and_excessive_depth_remain_rejected() {
        assert!(parse_unique_json(br#"{} {}"#).is_err());
        assert!(parse_unique_json(b"{\"x\":").is_err());
        let deep = format!("{}null{}", "[".repeat(256), "]".repeat(256));
        assert!(parse_unique_json(deep.as_bytes()).is_err());
        assert!(parse_unique_json(b" \n {} \t ").is_ok());
    }
}
