//! Bounded public-only RFC7517 JWK data parsing, independent of key conversion.
//! This module provides no signing, private-key generation or network resolution.

use crate::{CryptoError, CryptoResult};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// Bounded parser primitives shared with protocol representations.
#[doc(hidden)]
pub mod bounded;

pub use bounded::MAX_PUBLIC_JWK_JSON_BYTES;
use bounded::{
    validate_public_extensions, BoundedOptionStringVecSeed, BoundedString, BoundedValueSeed,
    MAX_JWK_EXTENSION_MEMBERS,
};

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
    pub(crate) extra: HashMap<String, serde_json::Value>,
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

#[cfg(test)]
mod tests {
    use super::bounded::MAX_JWK_MEMBER_BYTES;
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
