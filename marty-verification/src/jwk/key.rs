//! JSON Web Key (JWK) representation.
//!
//! Implements RFC 7517 JWK format for various key types.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::{VerificationError, VerificationResult};

/// Largest JSON document accepted by [`Jwk::from_json`].
pub const MAX_PUBLIC_JWK_JSON_BYTES: usize = 64 * 1024;
/// Largest JSON document accepted by [`JwkSet::from_json`].
pub const MAX_JWK_SET_JSON_BYTES: usize = 1024 * 1024;
/// Largest number of keys accepted in a parsed JWK set.
pub const MAX_JWK_SET_KEYS: usize = 128;
const MAX_JWK_MEMBER_BYTES: usize = 16 * 1024;
const MAX_JWK_LIST_ITEMS: usize = 128;
const MAX_JWK_EXTENSION_MEMBERS: usize = 32;
const MAX_JWK_EXTENSION_DEPTH: usize = 8;

struct BoundedString(String);

impl<'de> Deserialize<'de> for BoundedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringVisitor;
        impl serde::de::Visitor<'_> for StringVisitor {
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
        deserializer.deserialize_string(StringVisitor)
    }
}

fn deserialize_bounded_option_string_vec<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringVecVisitor;
    impl<'de> serde::de::Visitor<'de> for StringVecVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an array containing at most 128 bounded strings")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
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

    struct OptionalStringVecVisitor;
    impl<'de> serde::de::Visitor<'de> for OptionalStringVecVisitor {
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
            deserializer.deserialize_seq(StringVecVisitor).map(Some)
        }
    }
    deserializer.deserialize_option(OptionalStringVecVisitor)
}

struct BoundedOptionStringVecSeed;

impl<'de> serde::de::DeserializeSeed<'de> for BoundedOptionStringVecSeed {
    type Value = Option<Vec<String>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_bounded_option_string_vec(deserializer)
    }
}

fn deserialize_bounded_jwk_vec<'de, D>(deserializer: D) -> Result<Vec<Jwk>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct JwkVecVisitor;

    impl<'de> serde::de::Visitor<'de> for JwkVecVisitor {
        type Value = Vec<Jwk>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an array containing at most 128 public JWKs")
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut keys =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_JWK_SET_KEYS));
            while keys.len() < MAX_JWK_SET_KEYS {
                match sequence.next_element()? {
                    Some(key) => keys.push(key),
                    None => return Ok(keys),
                }
            }
            if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("JWK Set exceeds 128 keys"));
            }
            Ok(keys)
        }
    }

    deserializer.deserialize_seq(JwkVecVisitor)
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
                size.checked_add(key.len())
                    .and_then(|size| {
                        bounded_json_value_size(value, depth + 1)
                            .ok()
                            .and_then(|value_size| size.checked_add(value_size))
                    })
                    .ok_or_else(|| "JWK extension size overflow".to_string())
            })
        }
    }
}

#[derive(Clone)]
struct BoundedValueSeed {
    depth: usize,
    remaining: Rc<Cell<usize>>,
}

impl BoundedValueSeed {
    fn consume<E: serde::de::Error>(&self, amount: usize) -> Result<(), E> {
        let remaining = self.remaining.get();
        if amount > remaining {
            return Err(E::custom("JWK extensions exceed 65536 bytes"));
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

const RESERVED_EXTENSION_MEMBERS: [&str; 23] = [
    "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "n",
    "e", "d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k",
];

fn validate_public_extensions(
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
    if let Some(member) = RESERVED_EXTENSION_MEMBERS
        .iter()
        .find(|member| extensions.contains_key(**member))
    {
        return Err(format!(
            "JWK member '{member}' must use its typed field and cannot be an extension"
        ));
    }
    Ok(())
}

// ============================================================================
// JWK Structure
// ============================================================================

/// JSON Web Key (RFC 7517).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Jwk {
    /// Key type (kty): EC, RSA, OKP, oct
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub kty: String,

    /// Key use: sig (signature) or enc (encryption)
    #[serde(
        default,
        rename = "use",
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub use_: Option<String>,

    /// Key operations: sign, verify, encrypt, decrypt, etc.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_ops: Option<Vec<String>>,

    /// Algorithm intended for use with this key
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub alg: Option<String>,

    /// Key ID
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub kid: Option<String>,

    /// X.509 URL
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5u: Option<String>,

    /// X.509 certificate chain
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5c: Option<Vec<String>>,

    /// X.509 certificate SHA-1 thumbprint
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5t: Option<String>,

    /// X.509 certificate SHA-256 thumbprint
    #[serde(
        default,
        rename = "x5t#S256",
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5t_s256: Option<String>,

    // EC parameters
    /// Curve name (P-256, P-384, P-521, Ed25519, X25519)
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub crv: Option<String>,

    /// X coordinate (EC public key)
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x: Option<String>,

    /// Y coordinate (EC public key)
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub y: Option<String>,

    /// D value (EC/OKP private key)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub d: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) d: Option<String>,

    // RSA parameters
    /// Modulus (RSA)
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub n: Option<String>,

    /// Exponent (RSA)
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub e: Option<String>,

    /// Private exponent (RSA private key)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub rsa_d: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) rsa_d: Option<String>,

    /// First prime factor (RSA private key)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub p: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) p: Option<String>,

    /// Second prime factor (RSA private key)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub q: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) q: Option<String>,

    /// First factor CRT exponent (RSA private key)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub dp: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) dp: Option<String>,

    /// Second factor CRT exponent (RSA private key)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub dq: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) dq: Option<String>,

    /// First CRT coefficient (RSA private key)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub qi: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) qi: Option<String>,

    // Symmetric key
    /// Key value (symmetric key, base64url-encoded)
    #[cfg(test)]
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub k: Option<String>,
    #[cfg(not(test))]
    #[serde(
        default,
        deserialize_with = "reject_private_key_material",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) k: Option<String>,

    /// Additional parameters
    #[serde(flatten, deserialize_with = "deserialize_public_extensions")]
    pub(crate) extra: HashMap<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct JwkVisitor;
        impl<'de> serde::de::Visitor<'de> for JwkVisitor {
            type Value = Jwk;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded public JWK object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Jwk, A::Error> {
                let mut jwk = Jwk::default();
                let mut has_kty = false;
                let mut seen_members = HashSet::new();
                let budget = Rc::new(Cell::new(MAX_PUBLIC_JWK_JSON_BYTES));
                macro_rules! optional_string {
                    ($field:ident) => {{
                        let value = map
                            .next_value::<Option<BoundedString>>()?
                            .map(|value| value.0);
                        if let Some(value) = &value {
                            BoundedValueSeed {
                                depth: 0,
                                remaining: budget.clone(),
                            }
                            .consume::<A::Error>(value.len())?;
                        }
                        jwk.$field = value;
                    }};
                }
                while let Some(key) = map.next_key::<BoundedString>()? {
                    if !seen_members.insert(key.0.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JWK member '{}'",
                            key.0
                        )));
                    }
                    BoundedValueSeed {
                        depth: 0,
                        remaining: budget.clone(),
                    }
                    .consume::<A::Error>(key.0.len())?;
                    match key.0.as_str() {
                        "kty" => {
                            jwk.kty = map.next_value::<BoundedString>()?.0;
                            BoundedValueSeed {
                                depth: 0,
                                remaining: budget.clone(),
                            }
                            .consume::<A::Error>(jwk.kty.len())?;
                            has_kty = true;
                        }
                        "use" => optional_string!(use_),
                        "key_ops" => {
                            jwk.key_ops = map.next_value_seed(BoundedOptionStringVecSeed)?;
                            if let Some(values) = &jwk.key_ops {
                                for value in values {
                                    BoundedValueSeed {
                                        depth: 0,
                                        remaining: budget.clone(),
                                    }
                                    .consume::<A::Error>(value.len())?;
                                }
                            }
                        }
                        "alg" => optional_string!(alg),
                        "kid" => optional_string!(kid),
                        "x5u" => optional_string!(x5u),
                        "x5c" => {
                            jwk.x5c = map.next_value_seed(BoundedOptionStringVecSeed)?;
                            if let Some(values) = &jwk.x5c {
                                for value in values {
                                    BoundedValueSeed {
                                        depth: 0,
                                        remaining: budget.clone(),
                                    }
                                    .consume::<A::Error>(value.len())?;
                                }
                            }
                        }
                        "x5t" => optional_string!(x5t),
                        "x5t#S256" => optional_string!(x5t_s256),
                        "crv" => optional_string!(crv),
                        "x" => optional_string!(x),
                        "y" => optional_string!(y),
                        "n" => optional_string!(n),
                        "e" => optional_string!(e),
                        "d" | "rsa_d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k" => {
                            #[cfg(test)]
                            {
                                let value = map
                                    .next_value::<Option<BoundedString>>()?
                                    .map(|value| value.0);
                                if let Some(value) = &value {
                                    BoundedValueSeed {
                                        depth: 0,
                                        remaining: budget.clone(),
                                    }
                                    .consume::<A::Error>(value.len())?;
                                }
                                match key.0.as_str() {
                                    "d" => jwk.d = value,
                                    "rsa_d" => jwk.rsa_d = value,
                                    "p" => jwk.p = value,
                                    "q" => jwk.q = value,
                                    "dp" => jwk.dp = value,
                                    "dq" => jwk.dq = value,
                                    "qi" => jwk.qi = value,
                                    "k" => jwk.k = value,
                                    "oth" => {
                                        return Err(serde::de::Error::custom(
                                            "unsupported private JWK member oth",
                                        ))
                                    }
                                    _ => unreachable!(),
                                }
                            }
                            #[cfg(not(test))]
                            {
                                map.next_value::<serde::de::IgnoredAny>()?;
                                return Err(serde::de::Error::custom(
                                    "private JWK material is disabled in this build",
                                ));
                            }
                        }
                        _ => {
                            if jwk.extra.len() == MAX_JWK_EXTENSION_MEMBERS {
                                return Err(serde::de::Error::custom(
                                    "JWK extensions exceed 32 members",
                                ));
                            }
                            if RESERVED_EXTENSION_MEMBERS.contains(&key.0.as_str()) {
                                return Err(serde::de::Error::custom(
                                    "reserved JWK extension member",
                                ));
                            }
                            let seed = BoundedValueSeed {
                                depth: 0,
                                remaining: budget.clone(),
                            };
                            jwk.extra.insert(key.0, map.next_value_seed(seed)?);
                        }
                    }
                }
                if !has_kty {
                    return Err(serde::de::Error::missing_field("kty"));
                }
                Ok(jwk)
            }
        }
        deserializer.deserialize_map(JwkVisitor)
    }
}

impl Jwk {
    /// Create a new empty JWK with the specified key type.
    pub fn new(kty: &str) -> Self {
        Self {
            kty: kty.to_string(),
            ..Default::default()
        }
    }

    /// Return validated extension members without permitting unchecked mutation.
    pub fn extensions(&self) -> &HashMap<String, serde_json::Value> {
        &self.extra
    }

    /// Replace extension members after rejecting private and modeled JWK names.
    pub fn set_public_extensions(
        &mut self,
        extensions: HashMap<String, serde_json::Value>,
    ) -> VerificationResult<()> {
        validate_public_extensions(&extensions).map_err(VerificationError::key_error)?;
        self.extra = extensions;
        Ok(())
    }

    /// Add validated public extension members using a builder-style API.
    pub fn with_extensions(
        mut self,
        extensions: HashMap<String, serde_json::Value>,
    ) -> VerificationResult<Self> {
        self.set_public_extensions(extensions)?;
        Ok(self)
    }

    /// Check if this is a private key.
    pub fn is_private(&self) -> bool {
        self.d.is_some()
            || self.rsa_d.is_some()
            || self.p.is_some()
            || self.q.is_some()
            || self.dp.is_some()
            || self.dq.is_some()
            || self.qi.is_some()
            || self.k.is_some()
    }

    /// Check if this is a public key (asymmetric key without private component).
    pub fn is_public(&self) -> bool {
        !self.is_private() && self.kty != "oct"
    }

    /// Check if this is a symmetric key.
    pub fn is_symmetric(&self) -> bool {
        self.kty == "oct"
    }

    /// Get the key type.
    pub fn key_type(&self) -> KeyType {
        match self.kty.as_str() {
            "EC" => match self.crv.as_deref() {
                Some("P-256") => KeyType::EcP256,
                Some("P-384") => KeyType::EcP384,
                Some("P-521") => KeyType::EcP521,
                _ => KeyType::Unknown,
            },
            "OKP" => match self.crv.as_deref() {
                Some("Ed25519") => KeyType::Ed25519,
                Some("Ed448") => KeyType::Ed448,
                Some("X25519") => KeyType::X25519,
                _ => KeyType::Unknown,
            },
            "RSA" => KeyType::Rsa,
            "oct" => KeyType::Symmetric,
            _ => KeyType::Unknown,
        }
    }

    /// Get the public key portion (strips private key data).
    pub fn to_public(&self) -> Self {
        let mut public = self.clone();
        public.d = None;
        public.rsa_d = None;
        public.p = None;
        public.q = None;
        public.dp = None;
        public.dq = None;
        public.qi = None;
        public.k = None;
        public
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> VerificationResult<String> {
        serde_json::to_string(self)
            .map_err(|e| VerificationError::internal(format!("JWK serialization failed: {}", e)))
    }

    /// Serialize to pretty-printed JSON string.
    pub fn to_json_pretty(&self) -> VerificationResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| VerificationError::internal(format!("JWK serialization failed: {}", e)))
    }

    /// Parse from JSON string.
    pub fn from_json(json: &str) -> VerificationResult<Self> {
        if json.len() > MAX_PUBLIC_JWK_JSON_BYTES {
            return Err(VerificationError::internal(format!(
                "JWK JSON exceeds {MAX_PUBLIC_JWK_JSON_BYTES} bytes"
            )));
        }
        serde_json::from_str(json)
            .map_err(|e| VerificationError::internal(format!("JWK parsing failed: {}", e)))
    }

    /// Compute the thumbprint (RFC 7638).
    pub fn thumbprint(&self) -> VerificationResult<String> {
        use sha2::{Digest, Sha256};

        // Build canonical JSON representation (sorted keys, no whitespace)
        let canonical =
            match self.kty.as_str() {
                "EC" => {
                    let crv = self.crv.as_ref().ok_or_else(|| {
                        VerificationError::internal("EC key missing crv".to_string())
                    })?;
                    let x = self.x.as_ref().ok_or_else(|| {
                        VerificationError::internal("EC key missing x".to_string())
                    })?;
                    let y = self.y.as_ref().ok_or_else(|| {
                        VerificationError::internal("EC key missing y".to_string())
                    })?;
                    format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
                }
                "OKP" => {
                    let crv = self.crv.as_ref().ok_or_else(|| {
                        VerificationError::internal("OKP key missing crv".to_string())
                    })?;
                    let x = self.x.as_ref().ok_or_else(|| {
                        VerificationError::internal("OKP key missing x".to_string())
                    })?;
                    format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x)
                }
                "RSA" => {
                    let e = self.e.as_ref().ok_or_else(|| {
                        VerificationError::internal("RSA key missing e".to_string())
                    })?;
                    let n = self.n.as_ref().ok_or_else(|| {
                        VerificationError::internal("RSA key missing n".to_string())
                    })?;
                    format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
                }
                "oct" => {
                    let k = self.k.as_ref().ok_or_else(|| {
                        VerificationError::internal("Symmetric key missing k".to_string())
                    })?;
                    format!(r#"{{"k":"{}","kty":"oct"}}"#, k)
                }
                _ => {
                    return Err(VerificationError::internal(format!(
                        "Unsupported key type for thumbprint: {}",
                        self.kty
                    )))
                }
            };

        let hash = Sha256::digest(canonical.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(hash))
    }
}

// ============================================================================
// Key Types
// ============================================================================

/// Key type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// P-256 elliptic curve
    EcP256,
    /// P-384 elliptic curve
    EcP384,
    /// P-521 elliptic curve
    EcP521,
    /// Ed25519 (EdDSA)
    Ed25519,
    /// Ed448 (EdDSA)
    Ed448,
    /// X25519 (key agreement)
    X25519,
    /// RSA
    Rsa,
    /// Symmetric (oct)
    Symmetric,
    /// Unknown key type
    Unknown,
}

// ============================================================================
// JWK Set
// ============================================================================

/// JSON Web Key Set (RFC 7517).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkSet {
    /// Array of JWK values
    #[serde(deserialize_with = "deserialize_bounded_jwk_vec")]
    pub keys: Vec<Jwk>,
}

impl JwkSet {
    /// Create an empty JWK Set.
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    /// Add a key to the set.
    pub fn add(&mut self, key: Jwk) {
        self.keys.push(key);
    }

    /// Find a key by ID.
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }

    /// Find keys by algorithm.
    pub fn find_by_alg(&self, alg: &str) -> Vec<&Jwk> {
        self.keys
            .iter()
            .filter(|k| k.alg.as_deref() == Some(alg))
            .collect()
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> VerificationResult<String> {
        serde_json::to_string(self).map_err(|e| {
            VerificationError::internal(format!("JWK Set serialization failed: {}", e))
        })
    }

    /// Parse from JSON string.
    pub fn from_json(json: &str) -> VerificationResult<Self> {
        if json.len() > MAX_JWK_SET_JSON_BYTES {
            return Err(VerificationError::internal(format!(
                "JWK Set JSON exceeds {MAX_JWK_SET_JSON_BYTES} bytes"
            )));
        }
        let set: Self = serde_json::from_str(json)
            .map_err(|e| VerificationError::internal(format!("JWK Set parsing failed: {}", e)))?;
        if set.keys.len() > MAX_JWK_SET_KEYS {
            return Err(VerificationError::internal(format!(
                "JWK Set exceeds {MAX_JWK_SET_KEYS} keys"
            )));
        }
        Ok(set)
    }
}

impl Default for JwkSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Key Generation
// ============================================================================

/// Generate a new EC P-256 JWK.
#[cfg(test)]
pub fn generate_ec_p256() -> VerificationResult<Jwk> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p256::SecretKey;
    use rand::rngs::OsRng;

    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(false);

    let x = point
        .x()
        .ok_or_else(|| VerificationError::internal("Failed to get x coordinate".to_string()))?;
    let y = point
        .y()
        .ok_or_else(|| VerificationError::internal("Failed to get y coordinate".to_string()))?;

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(x)),
        y: Some(URL_SAFE_NO_PAD.encode(y)),
        d: Some(URL_SAFE_NO_PAD.encode(secret.to_bytes())),
        ..Default::default()
    })
}

/// Generate a new EC P-384 JWK.
#[cfg(test)]
pub fn generate_ec_p384() -> VerificationResult<Jwk> {
    use elliptic_curve::sec1::ToEncodedPoint;
    use p384::SecretKey;
    use rand::rngs::OsRng;

    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(false);

    let x = point
        .x()
        .ok_or_else(|| VerificationError::internal("Failed to get x coordinate".to_string()))?;
    let y = point
        .y()
        .ok_or_else(|| VerificationError::internal("Failed to get y coordinate".to_string()))?;

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some("P-384".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(x)),
        y: Some(URL_SAFE_NO_PAD.encode(y)),
        d: Some(URL_SAFE_NO_PAD.encode(secret.to_bytes())),
        ..Default::default()
    })
}

/// Generate a new Ed25519 JWK.
#[cfg(test)]
pub fn generate_ed25519() -> VerificationResult<Jwk> {
    use ed25519_dalek::SigningKey;

    let keypair = SigningKey::generate(&mut rand::rngs::OsRng);

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(keypair.verifying_key().to_bytes())),
        d: Some(URL_SAFE_NO_PAD.encode(keypair.to_bytes())),
        ..Default::default()
    })
}

/// Generate a new X25519 JWK.
#[cfg(test)]
pub fn generate_x25519() -> VerificationResult<Jwk> {
    use rand::rngs::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("X25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(public.as_bytes())),
        d: Some(URL_SAFE_NO_PAD.encode(secret.to_bytes())),
        ..Default::default()
    })
}

/// Generate a new symmetric key JWK.
#[cfg(test)]
pub fn generate_symmetric(size: usize) -> VerificationResult<Jwk> {
    use rand::RngCore;

    let mut key = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut key);

    Ok(Jwk {
        kty: "oct".to_string(),
        k: Some(URL_SAFE_NO_PAD.encode(&key)),
        ..Default::default()
    })
}

// ============================================================================
// Key Import/Export
// ============================================================================

/// Import an Ed25519 public key from raw bytes.
pub fn import_ed25519_public(bytes: &[u8]) -> VerificationResult<Jwk> {
    if bytes.len() != 32 {
        return Err(VerificationError::internal(
            "Ed25519 public key must be 32 bytes".to_string(),
        ));
    }

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(bytes)),
        ..Default::default()
    })
}

/// Import an Ed25519 private key from raw bytes.
#[cfg(test)]
pub fn import_ed25519_private(secret: &[u8], public: &[u8]) -> VerificationResult<Jwk> {
    if secret.len() != 32 || public.len() != 32 {
        return Err(VerificationError::internal(
            "Ed25519 keys must be 32 bytes each".to_string(),
        ));
    }

    Ok(Jwk {
        kty: "OKP".to_string(),
        crv: Some("Ed25519".to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(public)),
        d: Some(URL_SAFE_NO_PAD.encode(secret)),
        ..Default::default()
    })
}

/// Export an Ed25519 public key to raw bytes.
pub fn export_ed25519_public(jwk: &Jwk) -> VerificationResult<Vec<u8>> {
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
        return Err(VerificationError::internal(
            "Not an Ed25519 key".to_string(),
        ));
    }

    let x = jwk
        .x
        .as_ref()
        .ok_or_else(|| VerificationError::internal("Ed25519 key missing x".to_string()))?;

    URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| VerificationError::internal(format!("Invalid base64url: {}", e)))
}

/// Export an Ed25519 private key to raw bytes.
#[cfg(test)]
pub fn export_ed25519_private(jwk: &Jwk) -> VerificationResult<Vec<u8>> {
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
        return Err(VerificationError::internal(
            "Not an Ed25519 key".to_string(),
        ));
    }

    let d = jwk.d.as_ref().ok_or_else(|| {
        VerificationError::internal("Ed25519 key missing d (private key)".to_string())
    })?;

    URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|e| VerificationError::internal(format!("Invalid base64url: {}", e)))
}

// ============================================================================
// Base64URL Helpers
// ============================================================================

/// Encode bytes to base64url (no padding).
pub fn base64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url (no padding) to bytes.
pub fn base64url_decode(data: &str) -> VerificationResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| VerificationError::internal(format!("Invalid base64url: {}", e)))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ec_p256() {
        let jwk = generate_ec_p256().unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, Some("P-256".to_string()));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
        assert!(jwk.d.is_some());
        assert!(jwk.is_private());
    }

    #[test]
    fn test_generate_ed25519() {
        let jwk = generate_ed25519().unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, Some("Ed25519".to_string()));
        assert!(jwk.x.is_some());
        assert!(jwk.d.is_some());
        assert!(jwk.is_private());
    }

    #[test]
    fn test_generate_symmetric() {
        let jwk = generate_symmetric(32).unwrap();
        assert_eq!(jwk.kty, "oct");
        assert!(jwk.k.is_some());
        assert!(jwk.is_symmetric());
    }

    #[test]
    fn test_to_public() {
        let private = generate_ec_p256().unwrap();
        let public = private.to_public();

        assert!(private.is_private());
        assert!(public.is_public());
        assert!(public.d.is_none());
        assert_eq!(private.x, public.x);
        assert_eq!(private.y, public.y);
    }

    #[test]
    fn every_modeled_private_member_is_classified_private() {
        for member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "k"] {
            let json = format!(r#"{{"kty":"RSA","{member}":"secret"}}"#);
            let jwk = Jwk::from_json(&json).unwrap();
            assert!(jwk.is_private(), "{member} was not classified private");
            assert!(!jwk.is_public(), "{member} was classified public");
        }
    }

    #[test]
    fn test_json_roundtrip() {
        let original = generate_ec_p256().unwrap();
        let json = original.to_json().unwrap();
        let parsed = Jwk::from_json(&json).unwrap();

        assert_eq!(original.kty, parsed.kty);
        assert_eq!(original.crv, parsed.crv);
        assert_eq!(original.x, parsed.x);
        assert_eq!(original.y, parsed.y);
        assert_eq!(original.d, parsed.d);
    }

    #[test]
    fn test_thumbprint() {
        let jwk = generate_ec_p256().unwrap();
        let thumbprint = jwk.thumbprint().unwrap();

        // Thumbprint should be base64url-encoded SHA-256 (43 chars without padding)
        assert_eq!(thumbprint.len(), 43);

        // Same key should produce same thumbprint
        let thumbprint2 = jwk.thumbprint().unwrap();
        assert_eq!(thumbprint, thumbprint2);
    }

    #[test]
    fn test_jwk_set() {
        let mut set = JwkSet::new();

        let mut key1 = generate_ec_p256().unwrap();
        key1.kid = Some("key-1".to_string());
        key1.alg = Some("ES256".to_string());

        let mut key2 = generate_ed25519().unwrap();
        key2.kid = Some("key-2".to_string());
        key2.alg = Some("EdDSA".to_string());

        set.add(key1);
        set.add(key2);

        assert_eq!(set.keys.len(), 2);
        assert!(set.find_by_kid("key-1").is_some());
        assert!(set.find_by_kid("key-2").is_some());
        assert!(set.find_by_kid("key-3").is_none());
        assert_eq!(set.find_by_alg("ES256").len(), 1);
    }

    #[test]
    fn test_key_type() {
        let ec = generate_ec_p256().unwrap();
        assert_eq!(ec.key_type(), KeyType::EcP256);

        let ed = generate_ed25519().unwrap();
        assert_eq!(ed.key_type(), KeyType::Ed25519);

        let sym = generate_symmetric(32).unwrap();
        assert_eq!(sym.key_type(), KeyType::Symmetric);
    }

    #[test]
    fn test_import_export_ed25519() {
        let original = generate_ed25519().unwrap();

        let public_bytes = export_ed25519_public(&original).unwrap();
        let private_bytes = export_ed25519_private(&original).unwrap();

        assert_eq!(public_bytes.len(), 32);
        assert_eq!(private_bytes.len(), 32);

        let imported = import_ed25519_private(&private_bytes, &public_bytes).unwrap();
        assert_eq!(original.x, imported.x);
        assert_eq!(original.d, imported.d);
    }
}
