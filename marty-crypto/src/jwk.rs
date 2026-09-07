//! Public JSON Web Key conversion primitives.
//!
//! This module owns the format conversion from SPKI public keys and X.509
//! certificates into public RFC 7517 parameters. Protocol crates may add JOSE
//! policy, but must not duplicate key parsing or coordinate extraction.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use der::asn1::UintRef;
use der::{Decode, DecodePem, Sequence};
use serde::{Deserialize, Serialize};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

use crate::{CryptoError, CryptoResult};

const RESERVED_JWK_MEMBERS: [&str; 23] = [
    "kty", "use", "key_ops", "alg", "kid", "x5u", "x5c", "x5t", "x5t#S256", "crv", "x", "y", "n",
    "e", "d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k",
];
const MAX_JWK_MEMBER_BYTES: usize = 16 * 1024;
const MAX_JWK_LIST_ITEMS: usize = 128;
const MAX_JWK_EXTENSION_MEMBERS: usize = 32;
const MAX_JWK_EXTENSION_DEPTH: usize = 8;
/// Largest JSON document accepted by [`PublicJwk::from_json`].
pub const MAX_PUBLIC_JWK_JSON_BYTES: usize = 64 * 1024;

struct BoundedString(String);

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

struct BoundedOptionStringVecSeed;

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
struct BoundedValueSeed {
    depth: usize,
    remaining: Rc<Cell<usize>>,
}

impl BoundedValueSeed {
    fn consume<E: serde::de::Error>(&self, amount: usize) -> Result<(), E> {
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

/// Public-only RFC 7517 JSON Web Key parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PublicJwk {
    /// Key type (`EC`, `RSA`, or `OKP`).
    #[serde(deserialize_with = "deserialize_bounded_string")]
    pub kty: String,
    /// Intended key use.
    #[serde(
        default,
        rename = "use",
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub use_: Option<String>,
    /// Permitted key operations.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub key_ops: Option<Vec<String>>,
    /// Intended algorithm.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub alg: Option<String>,
    /// Key identifier.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub kid: Option<String>,
    /// X.509 URL.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5u: Option<String>,
    /// X.509 certificate chain.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5c: Option<Vec<String>>,
    /// X.509 SHA-1 thumbprint.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5t: Option<String>,
    /// X.509 SHA-256 thumbprint.
    #[serde(
        default,
        rename = "x5t#S256",
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x5t_s256: Option<String>,
    /// EC or OKP curve.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub crv: Option<String>,
    /// EC x coordinate or OKP public bytes.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub x: Option<String>,
    /// EC y coordinate.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub y: Option<String>,
    /// RSA modulus.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub n: Option<String>,
    /// RSA public exponent.
    #[serde(
        default,
        deserialize_with = "deserialize_bounded_option_string",
        skip_serializing_if = "Option::is_none"
    )]
    pub e: Option<String>,
    /// Extension members retained during serialization.
    #[serde(flatten, deserialize_with = "deserialize_public_extensions")]
    extra: HashMap<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for PublicJwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PublicJwk;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded public JWK object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut jwk = PublicJwk::default();
                let mut has_kty = false;
                let mut seen = HashSet::new();
                let budget = Rc::new(Cell::new(MAX_PUBLIC_JWK_JSON_BYTES));
                macro_rules! consume {
                    ($amount:expr) => {
                        BoundedValueSeed {
                            depth: 0,
                            remaining: budget.clone(),
                        }
                        .consume::<A::Error>($amount)?
                    };
                }
                macro_rules! optional_string {
                    ($field:ident) => {{
                        let value = map
                            .next_value::<Option<BoundedString>>()?
                            .map(|value| value.0);
                        if let Some(value) = &value {
                            consume!(value.len());
                        }
                        jwk.$field = value;
                    }};
                }
                macro_rules! optional_string_vec {
                    ($field:ident) => {{
                        jwk.$field = map.next_value_seed(BoundedOptionStringVecSeed)?;
                        if let Some(values) = &jwk.$field {
                            for value in values {
                                consume!(value.len());
                            }
                        }
                    }};
                }

                while let Some(key) = map.next_key::<BoundedString>()? {
                    if !seen.insert(key.0.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JWK member '{}'",
                            key.0
                        )));
                    }
                    consume!(key.0.len());
                    match key.0.as_str() {
                        "kty" => {
                            jwk.kty = map.next_value::<BoundedString>()?.0;
                            consume!(jwk.kty.len());
                            has_kty = true;
                        }
                        "use" => optional_string!(use_),
                        "key_ops" => optional_string_vec!(key_ops),
                        "alg" => optional_string!(alg),
                        "kid" => optional_string!(kid),
                        "x5u" => optional_string!(x5u),
                        "x5c" => optional_string_vec!(x5c),
                        "x5t" => optional_string!(x5t),
                        "x5t#S256" => optional_string!(x5t_s256),
                        "crv" => optional_string!(crv),
                        "x" => optional_string!(x),
                        "y" => optional_string!(y),
                        "n" => optional_string!(n),
                        "e" => optional_string!(e),
                        "d" | "rsa_d" | "p" | "q" | "dp" | "dq" | "qi" | "oth" | "k" => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            return Err(serde::de::Error::custom(
                                "private JWK material is disabled",
                            ));
                        }
                        _ => {
                            if jwk.extra.len() == MAX_JWK_EXTENSION_MEMBERS {
                                return Err(serde::de::Error::custom(
                                    "JWK extensions exceed 32 members",
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
        deserializer.deserialize_map(Visitor)
    }
}

impl PublicJwk {
    /// Parse a public JWK from a size-capped JSON document.
    ///
    /// This constructor adds a total input-size ceiling to the bounded Serde
    /// implementation and should be preferred for untrusted JSON documents.
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        if json.len() > MAX_PUBLIC_JWK_JSON_BYTES {
            return Err(CryptoError::encoding_error(format!(
                "JWK JSON exceeds {MAX_PUBLIC_JWK_JSON_BYTES} bytes"
            )));
        }
        serde_json::from_str(json)
            .map_err(|error| CryptoError::encoding_error(format!("JWK parsing failed: {error}")))
    }

    /// Return the validated, non-key extension members.
    pub fn extensions(&self) -> &HashMap<String, serde_json::Value> {
        &self.extra
    }

    /// Replace extension members after rejecting private and modeled JWK names.
    pub fn set_public_extensions(
        &mut self,
        extensions: HashMap<String, serde_json::Value>,
    ) -> CryptoResult<()> {
        validate_public_extensions(&extensions).map_err(CryptoError::key_error)?;
        self.extra = extensions;
        Ok(())
    }

    /// Add validated public extension members using a builder-style API.
    pub fn with_extensions(
        mut self,
        extensions: HashMap<String, serde_json::Value>,
    ) -> CryptoResult<Self> {
        self.set_public_extensions(extensions)?;
        Ok(self)
    }

    /// Serialize the public JWK as JSON.
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(|error| {
            CryptoError::encoding_error(format!("JWK serialization failed: {error}"))
        })
    }
}

/// Convert a PEM SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_pem_to_jwk(pem: &str) -> CryptoResult<PublicJwk> {
    let info = SubjectPublicKeyInfoOwned::from_pem(pem).map_err(|error| {
        CryptoError::pem_error(format!("Failed to parse public key PEM: {error}"))
    })?;
    public_key_info_to_jwk(&info)
}

/// Convert a DER SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_der_to_jwk(spki: &[u8]) -> CryptoResult<PublicJwk> {
    let info = SubjectPublicKeyInfoOwned::from_der(spki).map_err(|error| {
        CryptoError::der_error(format!("Failed to parse public key DER: {error}"))
    })?;
    public_key_info_to_jwk(&info)
}

fn public_key_info_to_jwk(info: &SubjectPublicKeyInfoOwned) -> CryptoResult<PublicJwk> {
    let raw = info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| CryptoError::key_error("Invalid public key bit string"))?;
    let key_type = detect_public_key_type(info)?;

    match key_type.as_str() {
        "EC_P256" => jwk_from_ec("P-256", raw),
        "EC_P384" => jwk_from_ec("P-384", raw),
        "EC_P521" => jwk_from_ec("P-521", raw),
        "Ed25519" | "Ed448" => Ok(PublicJwk {
            kty: "OKP".to_string(),
            crv: Some(key_type),
            x: Some(URL_SAFE_NO_PAD.encode(raw)),
            ..PublicJwk::default()
        }),
        "RSA" => jwk_from_rsa(raw),
        _ => Err(CryptoError::key_error(format!(
            "Unsupported public key type: {key_type}"
        ))),
    }
}

/// Extract a PEM X.509 certificate public key and convert it to JWK.
pub fn certificate_pem_to_jwk(pem: &str) -> CryptoResult<PublicJwk> {
    let certificate = Certificate::from_pem(pem).map_err(|error| {
        CryptoError::pem_error(format!("Failed to parse certificate PEM: {error}"))
    })?;
    public_key_info_to_jwk(&certificate.tbs_certificate.subject_public_key_info)
}

/// Extract a DER X.509 certificate public key and convert it to JWK.
pub fn certificate_der_to_jwk(der: &[u8]) -> CryptoResult<PublicJwk> {
    let certificate = Certificate::from_der(der).map_err(|error| {
        CryptoError::der_error(format!("Failed to parse certificate DER: {error}"))
    })?;
    public_key_info_to_jwk(&certificate.tbs_certificate.subject_public_key_info)
}

fn detect_public_key_type(info: &SubjectPublicKeyInfoOwned) -> CryptoResult<String> {
    let oid = info.algorithm.oid;
    if oid == const_oid::db::rfc5912::ID_EC_PUBLIC_KEY {
        let curve = info
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<const_oid::ObjectIdentifier>().ok());
        return match curve {
            Some(value) if value == const_oid::db::rfc5912::SECP_256_R_1 => Ok("EC_P256".into()),
            Some(value) if value == const_oid::db::rfc5912::SECP_384_R_1 => Ok("EC_P384".into()),
            Some(value) if value == const_oid::db::rfc5912::SECP_521_R_1 => Ok("EC_P521".into()),
            Some(value) => Err(CryptoError::unsupported_algorithm(format!(
                "Unsupported EC curve OID: {value}"
            ))),
            None => Err(CryptoError::key_error(
                "EC public key is missing curve parameters",
            )),
        };
    }
    if oid == const_oid::db::rfc5912::RSA_ENCRYPTION {
        return Ok("RSA".into());
    }
    if oid == const_oid::db::rfc8410::ID_ED_25519 {
        return Ok("Ed25519".into());
    }
    if oid == const_oid::db::rfc8410::ID_ED_448 {
        return Ok("Ed448".into());
    }
    Err(CryptoError::unsupported_algorithm(format!(
        "Unsupported public key algorithm OID: {oid}"
    )))
}

fn jwk_from_ec(curve: &str, raw: &[u8]) -> CryptoResult<PublicJwk> {
    let (x, y) = match curve {
        "P-256" => point_coordinates::<p256::NistP256>(raw, curve)?,
        "P-384" => point_coordinates::<p384::NistP384>(raw, curve)?,
        "P-521" => point_coordinates::<p521::NistP521>(raw, curve)?,
        _ => {
            return Err(CryptoError::unsupported_algorithm(format!(
                "Unsupported EC curve: {curve}"
            )))
        }
    };

    Ok(PublicJwk {
        kty: "EC".to_string(),
        crv: Some(curve.to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(x)),
        y: Some(URL_SAFE_NO_PAD.encode(y)),
        ..PublicJwk::default()
    })
}

fn point_coordinates<C>(raw: &[u8], curve: &str) -> CryptoResult<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let point = elliptic_curve::sec1::EncodedPoint::<C>::from_bytes(raw)
        .map_err(|error| CryptoError::key_error(format!("Invalid {curve} key: {error}")))?;
    let x = point
        .x()
        .ok_or_else(|| CryptoError::key_error(format!("Missing {curve} x")))?;
    let y = point
        .y()
        .ok_or_else(|| CryptoError::key_error(format!("Missing {curve} y")))?;
    Ok((x.to_vec(), y.to_vec()))
}

fn jwk_from_rsa(raw: &[u8]) -> CryptoResult<PublicJwk> {
    let key = RsaPublicKey::from_der(raw)
        .map_err(|error| CryptoError::key_error(format!("Invalid RSA public key: {error}")))?;

    Ok(PublicJwk {
        kty: "RSA".to_string(),
        n: Some(URL_SAFE_NO_PAD.encode(key.modulus.as_bytes())),
        e: Some(URL_SAFE_NO_PAD.encode(key.public_exponent.as_bytes())),
        ..PublicJwk::default()
    })
}

#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_jwk_parser_enforces_member_and_extension_bounds() {
        let oversized_member = format!(
            r#"{{"kty":"EC","x":"{}"}}"#,
            "A".repeat(MAX_JWK_MEMBER_BYTES + 1)
        );
        assert!(PublicJwk::from_json(&oversized_member).is_err());

        let too_many_extensions = format!(
            r#"{{"kty":"EC",{}}}"#,
            (0..=MAX_JWK_EXTENSION_MEMBERS)
                .map(|index| format!(r#""extension-{index}":true"#))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(PublicJwk::from_json(&too_many_extensions).is_err());
    }
}
