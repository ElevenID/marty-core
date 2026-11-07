//! JSON parsing that rejects duplicate members at every object depth.
//! Callers retain root-shape requirements, size bounds and protocol errors.

use serde::de::{self, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::fmt;

/// Parse a JSON value while rejecting repeated object members recursively.
///
/// Duplicate diagnostics, syntax precedence and depth limits are checked before
/// constructing values from their raw JSON token shape. Numeric values remain
/// numbers even when a consumer enables serde_json's arbitrary_precision feature;
/// literal objects with Serde's private-looking keys remain objects. Root shape,
/// byte limits and protocol interpretation belong to the calling boundary.
pub fn parse_unique_json(bytes: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice::<UniqueValue>(bytes)?;
    materialize_validated_json(bytes)
}

// This private second pass consumes only the exact input that passed the strict
// recursive visitor. Containers are constructed explicitly from their wire token
// shape; Serde interprets only strings and scalars. No private marker spelling or
// additional serde_json feature is needed for number preservation.
fn materialize_validated_json(bytes: &[u8]) -> serde_json::Result<Value> {
    let mut cursor = ValidatedJsonCursor { remaining: bytes };
    let value = cursor.value()?;
    cursor.whitespace();
    if !cursor.remaining.is_empty() {
        return Err(de::Error::custom(
            "invalid previously validated JSON structure",
        ));
    }
    Ok(value)
}

struct ValidatedJsonCursor<'a> {
    remaining: &'a [u8],
}

impl ValidatedJsonCursor<'_> {
    fn whitespace(&mut self) {
        while matches!(self.remaining.first(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.remaining = &self.remaining[1..];
        }
    }

    fn consume(&mut self, expected: u8) -> serde_json::Result<()> {
        self.whitespace();
        if self.remaining.first() != Some(&expected) {
            return Err(de::Error::custom(
                "invalid previously validated JSON structure",
            ));
        }
        self.remaining = &self.remaining[1..];
        Ok(())
    }

    fn scalar<T: serde::de::DeserializeOwned>(&mut self) -> serde_json::Result<T> {
        let mut stream = serde_json::Deserializer::from_slice(self.remaining).into_iter::<T>();
        let value = stream.next().ok_or_else(|| {
            <serde_json::Error as de::Error>::custom("invalid previously validated JSON structure")
        })??;
        // Advance only after a successful decode. byte_offset includes any JSON
        // whitespace and UTF-8/escaped string bytes consumed by Serde.
        self.remaining = &self.remaining[stream.byte_offset()..];
        Ok(value)
    }

    fn value(&mut self) -> serde_json::Result<Value> {
        self.whitespace();
        match self.remaining.first() {
            Some(b'{') => {
                self.consume(b'{')?;
                self.whitespace();
                let mut values = Map::new();
                if self.remaining.first() == Some(&b'}') {
                    self.consume(b'}')?;
                    return Ok(Value::Object(values));
                }
                loop {
                    let key = self.scalar::<String>()?;
                    self.consume(b':')?;
                    values.insert(key, self.value()?);
                    self.whitespace();
                    if self.remaining.first() == Some(&b'}') {
                        self.consume(b'}')?;
                        return Ok(Value::Object(values));
                    }
                    self.consume(b',')?;
                }
            }
            Some(b'[') => {
                self.consume(b'[')?;
                self.whitespace();
                let mut values = Vec::new();
                if self.remaining.first() == Some(&b']') {
                    self.consume(b']')?;
                    return Ok(Value::Array(values));
                }
                loop {
                    values.push(self.value()?);
                    self.whitespace();
                    if self.remaining.first() == Some(&b']') {
                        self.consume(b']')?;
                        return Ok(Value::Array(values));
                    }
                    self.consume(b',')?;
                }
            }
            _ => self.scalar::<Value>(),
        }
    }
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
        for (raw, expected) in [
            ("1.5", 1.5),
            ("-0.0", -0.0),
            ("1e2", 100.0),
            ("-1e-2", -0.01),
        ] {
            let parsed = parse_unique_json(raw.as_bytes()).unwrap();
            assert!(parsed.is_number(), "number changed JSON type: {parsed}");
            assert_eq!(parsed.as_f64(), Some(expected));
        }
        assert!(parse_unique_json(b"-0.0")
            .unwrap()
            .as_f64()
            .unwrap()
            .is_sign_negative());
    }

    #[test]
    fn nested_fractional_numbers_and_private_token_objects_keep_their_json_types() {
        let value = parse_unique_json(
            br#"{"iat":1794070000.25,"nested":[1.5,{"ratio":-1e-2}],"literal":{"$serde_json::private::Number":"1.5"},"extended":{"$serde_json::private::Number":"1.5","other":true}}"#,
        )
        .unwrap();
        assert_eq!(value["iat"].as_f64(), Some(1794070000.25));
        assert_eq!(value["nested"][0].as_f64(), Some(1.5));
        assert_eq!(value["nested"][1]["ratio"].as_f64(), Some(-0.01));
        assert!(value["literal"].is_object());
        assert_eq!(value["literal"]["$serde_json::private::Number"], "1.5");
        assert!(value["extended"].is_object());
        assert_eq!(value["extended"]["other"], true);
        assert_eq!(
            parse_unique_json(br#"{"$serde_json::private::Number":"1.5"}"#).unwrap(),
            json!({"$serde_json::private::Number":"1.5"}),
        );
        assert_eq!(
            parse_unique_json(br#"{"$serde_json::private::RawValue":"{\"x\":1}"}"#).unwrap(),
            json!({"$serde_json::private::RawValue":r#"{"x":1}"#}),
        );
        assert!(parse_unique_json(
            br#"{"nested":[{"$serde_json::private::Number":"1.5","$serde_json::private::Number":"2.5"}]}"#,
        ).unwrap_err().to_string().contains("duplicate JSON object member"));
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

    #[test]
    fn cursor_preserves_whitespace_escape_and_container_boundaries() {
        let input = " \t\n {\"a\\\"\\\\\": [\"[,]{}:\", {\"\\u0062\":\"\\uD83D\\uDE00\", \"n\": 1.25}, [], {}]} \r\n";
        let value = parse_unique_json(input.as_bytes()).unwrap();
        let items = &value["a\"\\"];
        assert_eq!(items[0], "[,]{}:");
        assert_eq!(items[1]["b"], "😀");
        assert_eq!(items[1]["n"].as_f64(), Some(1.25));
        assert!(items[2].as_array().unwrap().is_empty());
        assert!(items[3].as_object().unwrap().is_empty());
    }
}
