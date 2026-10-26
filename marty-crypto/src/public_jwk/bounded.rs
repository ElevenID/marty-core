//! Shared bounded deserialization for public and verifier JWK representations.

use serde::Deserialize;
use std::{cell::Cell, collections::HashMap, rc::Rc};

pub const RESERVED_JWK_MEMBERS: [&str; 23] = [
    "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "n",
    "e", "d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k",
];
pub const MAX_JWK_MEMBER_BYTES: usize = 16 * 1024;
pub const MAX_JWK_LIST_ITEMS: usize = 128;
pub const MAX_JWK_EXTENSION_MEMBERS: usize = 32;
pub const MAX_JWK_EXTENSION_DEPTH: usize = 8;
/// Largest JSON document accepted by [`super::PublicJwk::from_json`].
pub const MAX_PUBLIC_JWK_JSON_BYTES: usize = 64 * 1024;

pub struct BoundedString(pub String);

impl<'de> Deserialize<'de> for BoundedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = BoundedString;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JWK string no larger than 16384 bytes")
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > MAX_JWK_MEMBER_BYTES {
                    return Err(E::custom("JWK string member exceeds 16384 bytes"));
                }
                Ok(BoundedString(value.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
                if value.len() > MAX_JWK_MEMBER_BYTES {
                    return Err(E::custom("JWK string member exceeds 16384 bytes"));
                }
                Ok(BoundedString(value))
            }
        }
        deserializer.deserialize_string(Visitor)
    }
}

pub struct BoundedOptionStringVecSeed;

impl<'de> serde::de::DeserializeSeed<'de> for BoundedOptionStringVecSeed {
    type Value = Option<Vec<String>>;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct VecVisitor;
        impl<'de> serde::de::Visitor<'de> for VecVisitor {
            type Value = Vec<String>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an array containing at most 128 bounded strings")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values =
                    Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_JWK_LIST_ITEMS));
                while values.len() < MAX_JWK_LIST_ITEMS {
                    match sequence.next_element::<BoundedString>()? {
                        Some(value) => values.push(value.0),
                        None => return Ok(values),
                    }
                }
                if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom(
                        "JWK list member exceeds 128 items",
                    ));
                }
                Ok(values)
            }
        }
        struct OptionVisitor;
        impl<'de> serde::de::Visitor<'de> for OptionVisitor {
            type Value = Option<Vec<String>>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("null or an array of bounded JWK strings")
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_seq(VecVisitor).map(Some)
            }
        }
        deserializer.deserialize_option(OptionVisitor)
    }
}

#[derive(Clone)]
pub struct BoundedValueSeed {
    pub depth: usize,
    pub remaining: Rc<Cell<usize>>,
}

impl BoundedValueSeed {
    pub fn consume<E: serde::de::Error>(&self, amount: usize) -> Result<(), E> {
        let remaining = self.remaining.get();
        if amount > remaining {
            return Err(E::custom("JWK members exceed 65536 bytes"));
        }
        self.remaining.set(remaining - amount);
        Ok(())
    }
}

impl<'de> serde::de::DeserializeSeed<'de> for BoundedValueSeed {
    type Value = serde_json::Value;
    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_JWK_EXTENSION_DEPTH {
            return Err(serde::de::Error::custom(
                "JWK extension nesting exceeds 8 levels",
            ));
        }
        deserializer.deserialize_any(BoundedValueVisitor(self))
    }
}

struct BoundedValueVisitor(BoundedValueSeed);

impl<'de> serde::de::Visitor<'de> for BoundedValueVisitor {
    type Value = serde_json::Value;
    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON extension data")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.0.consume(1)?;
        Ok(serde_json::Value::Null)
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
        self.visit_unit()
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
        self.0.consume(1)?;
        Ok(serde_json::Value::Bool(value))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
        self.0.consume(8)?;
        Ok(value.into())
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
        self.0.consume(8)?;
        Ok(value.into())
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        self.0.consume(8)?;
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("non-finite JWK extension number"))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > MAX_JWK_MEMBER_BYTES {
            return Err(E::custom("JWK extension string exceeds 16384 bytes"));
        }
        self.0.consume(value.len())?;
        Ok(serde_json::Value::String(value.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > MAX_JWK_MEMBER_BYTES {
            return Err(E::custom("JWK extension string exceeds 16384 bytes"));
        }
        self.0.consume(value.len())?;
        Ok(serde_json::Value::String(value))
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while values.len() < MAX_JWK_LIST_ITEMS {
            let seed = BoundedValueSeed {
                depth: self.0.depth + 1,
                remaining: self.0.remaining.clone(),
            };
            match sequence.next_element_seed(seed)? {
                Some(value) => values.push(value),
                None => return Ok(serde_json::Value::Array(values)),
            }
        }
        if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "JWK extension array exceeds 128 items",
            ));
        }
        Ok(serde_json::Value::Array(values))
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = serde_json::Map::new();
        while values.len() < MAX_JWK_EXTENSION_MEMBERS {
            let Some(key) = map.next_key::<BoundedString>()? else {
                return Ok(serde_json::Value::Object(values));
            };
            if values.contains_key(&key.0) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JWK extension member '{}'",
                    key.0
                )));
            }
            self.0.consume(key.0.len())?;
            let seed = BoundedValueSeed {
                depth: self.0.depth + 1,
                remaining: self.0.remaining.clone(),
            };
            values.insert(key.0, map.next_value_seed(seed)?);
        }
        if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom(
                "JWK extension object exceeds 32 members",
            ));
        }
        Ok(serde_json::Value::Object(values))
    }
}

fn bounded_json_value_size(value: &serde_json::Value, depth: usize) -> Result<usize, String> {
    if depth > MAX_JWK_EXTENSION_DEPTH {
        return Err("JWK extension nesting exceeds 8 levels".to_string());
    }
    match value {
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            Ok(8)
        }
        serde_json::Value::String(value) => {
            if value.len() > MAX_JWK_MEMBER_BYTES {
                Err("JWK extension string exceeds 16384 bytes".to_string())
            } else {
                Ok(value.len())
            }
        }
        serde_json::Value::Array(values) => {
            if values.len() > MAX_JWK_LIST_ITEMS {
                return Err("JWK extension array exceeds 128 items".to_string());
            }
            values.iter().try_fold(0usize, |size, value| {
                size.checked_add(bounded_json_value_size(value, depth + 1)?)
                    .ok_or_else(|| "JWK extension size overflow".to_string())
            })
        }
        serde_json::Value::Object(values) => {
            if values.len() > MAX_JWK_EXTENSION_MEMBERS {
                return Err("JWK extension object exceeds 32 members".to_string());
            }
            values.iter().try_fold(0usize, |size, (key, value)| {
                if key.len() > MAX_JWK_MEMBER_BYTES {
                    return Err("JWK extension name exceeds 16384 bytes".to_string());
                }
                let value_size = bounded_json_value_size(value, depth + 1)?;
                size.checked_add(key.len())
                    .and_then(|size| size.checked_add(value_size))
                    .ok_or_else(|| "JWK extension size overflow".to_string())
            })
        }
    }
}

pub fn validate_public_extensions(
    extensions: &HashMap<String, serde_json::Value>,
) -> Result<(), String> {
    if extensions.len() > MAX_JWK_EXTENSION_MEMBERS {
        return Err("JWK extensions exceed 32 members".to_string());
    }
    let size = extensions.iter().try_fold(0usize, |size, (key, value)| {
        if key.len() > MAX_JWK_MEMBER_BYTES {
            return Err("JWK extension name exceeds 16384 bytes".to_string());
        }
        let value_size = bounded_json_value_size(value, 0)?;
        size.checked_add(key.len())
            .and_then(|size| size.checked_add(value_size))
            .ok_or_else(|| "JWK extensions exceed their size limit".to_string())
    })?;
    if size > MAX_PUBLIC_JWK_JSON_BYTES {
        return Err("JWK extensions exceed 65536 bytes".to_string());
    }
    if let Some(member) = RESERVED_JWK_MEMBERS
        .iter()
        .find(|member| extensions.contains_key(**member))
    {
        return Err(format!(
            "JWK member '{member}' must use its typed field and cannot be an extension"
        ));
    }
    Ok(())
}
