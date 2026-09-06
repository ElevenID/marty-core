//! OpenBadgeMethod wrapper enum combining SSI's AnyMethod with X509VerificationKey2021.
//!
//! This module provides a wrapper around SSI's verification methods that adds support
//! for X.509 certificate-based verification while maintaining compatibility with
//! standard Open Badge verification methods.

use iref::IriBuf;
use serde_json::Value;
use ssi_verification_methods::{AnyMethod, GenericVerificationMethod, VerificationMethod};

use crate::error::{VerificationError, VerificationResult};

use super::x509_verification_method::X509VerificationKey2021;

const PRIVATE_JWK_MEMBERS: [&str; 9] = ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const PRIVATE_METHOD_MEMBERS: [&str; 5] = [
    "privateKeyJwk",
    "privateKeyPem",
    "privateKeyBase58",
    "privateKeyMultibase",
    "privateKeyHex",
];

pub(super) fn ensure_public_verification_method(value: &Value) -> VerificationResult<()> {
    if let Some(member) = PRIVATE_METHOD_MEMBERS
        .iter()
        .find(|member| value.get(**member).is_some())
    {
        return Err(VerificationError::open_badges(format!(
            "verification method contains private key member '{member}'"
        )));
    }
    let Some(jwk) = value.get("publicKeyJwk").and_then(Value::as_object) else {
        return Ok(());
    };
    if let Some(member) = PRIVATE_JWK_MEMBERS
        .iter()
        .find(|member| jwk.contains_key(**member))
    {
        return Err(VerificationError::open_badges(format!(
            "verification method publicKeyJwk contains private member '{member}'"
        )));
    }
    Ok(())
}

/// Opaque wrapper for validated Open Badge verification methods.
///
/// Combines SSI's standard verification methods (JsonWebKey2020, Ed25519VerificationKey2018/2020)
/// with custom X509VerificationKey2021 for certificate-based verification.
#[derive(Debug, Clone)]
pub struct OpenBadgeMethod {
    inner: OpenBadgeMethodKind,
}

#[derive(Debug, Clone)]
enum OpenBadgeMethodKind {
    Ssi(AnyMethod),
    X509(X509VerificationKey2021),
}

impl OpenBadgeMethod {
    /// Parse from JSON value, attempting X509 first, then falling back to SSI methods.
    pub fn from_json(value: &Value) -> VerificationResult<Self> {
        ensure_public_verification_method(value)?;
        // Check if it's an X509 method
        if let Some(type_str) = value.get("type").and_then(|v| v.as_str()) {
            if type_str == "X509VerificationKey2021" {
                let x509: X509VerificationKey2021 =
                    serde_json::from_value(value.clone()).map_err(|e| {
                        VerificationError::open_badges(format!(
                            "Failed to parse X509VerificationKey2021: {}",
                            e
                        ))
                    })?;
                return Ok(Self {
                    inner: OpenBadgeMethodKind::X509(x509),
                });
            }
        }

        // Try parsing as generic method first, then convert to AnyMethod
        let method = if let Ok(generic) =
            serde_json::from_value::<GenericVerificationMethod>(value.clone())
        {
            AnyMethod::try_from(generic).map_err(|e| {
                VerificationError::open_badges(format!("Invalid verification method: {}", e))
            })?
        } else {
            serde_json::from_value::<AnyMethod>(value.clone()).map_err(|e| {
                VerificationError::open_badges(format!(
                    "Failed to parse verification method: {}",
                    e
                ))
            })?
        };

        Ok(Self {
            inner: OpenBadgeMethodKind::Ssi(method),
        })
    }

    /// Get the verification method ID.
    pub fn id(&self) -> &iref::Iri {
        match &self.inner {
            OpenBadgeMethodKind::Ssi(m) => m.id(),
            OpenBadgeMethodKind::X509(m) => m.id(),
        }
    }

    /// Check if this is an X509 verification method.
    pub fn is_x509(&self) -> bool {
        matches!(&self.inner, OpenBadgeMethodKind::X509(_))
    }

    /// Get X509 method reference, if applicable.
    pub fn as_x509(&self) -> Option<&X509VerificationKey2021> {
        match &self.inner {
            OpenBadgeMethodKind::X509(m) => Some(m),
            _ => None,
        }
    }

    /// Get SSI method reference, if applicable.
    pub fn as_ssi(&self) -> Option<&AnyMethod> {
        match &self.inner {
            OpenBadgeMethodKind::Ssi(m) => Some(m),
            _ => None,
        }
    }
}

impl VerificationMethod for OpenBadgeMethod {
    fn id(&self) -> &iref::Iri {
        match &self.inner {
            OpenBadgeMethodKind::Ssi(m) => m.id(),
            OpenBadgeMethodKind::X509(m) => m.id(),
        }
    }

    fn controller(&self) -> Option<&iref::Iri> {
        match &self.inner {
            OpenBadgeMethodKind::Ssi(m) => m.controller(),
            OpenBadgeMethodKind::X509(m) => m.controller(),
        }
    }
}

/// Parse verification method from JSON, with warnings collection.
pub fn parse_open_badge_method(
    value: &Value,
    warnings: &mut Vec<String>,
    key: &str,
) -> Option<(IriBuf, OpenBadgeMethod)> {
    match OpenBadgeMethod::from_json(value) {
        Ok(method) => match IriBuf::new(method.id().to_string()) {
            Ok(iri) => Some((iri, method)),
            Err(_) => {
                warnings.push(format!(
                    "Invalid verification method id for document {}",
                    key
                ));
                None
            }
        },
        Err(err) => {
            warnings.push(format!(
                "Failed to parse verification method {}: {}",
                key, err
            ));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_x509_method() {
        let json = json!({
            "id": "https://issuer.edu/keys/1",
            "type": "X509VerificationKey2021",
            "controller": "https://issuer.edu",
            "publicKeyPem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
        });

        let method = OpenBadgeMethod::from_json(&json).unwrap();
        assert!(method.is_x509());
        assert_eq!(method.id().as_str(), "https://issuer.edu/keys/1");
    }

    #[test]
    fn test_parse_jwk_method() {
        // Generate a real Ed25519 keypair so parsing passes curve-point validation
        let jwk = ssi_jwk::JWK::generate_ed25519().expect("generate ed25519");
        let pub_jwk = jwk.to_public();
        let json = serde_json::json!({
            "id": "did:example:issuer#key-1",
            "type": "JsonWebKey2020",
            "controller": "did:example:issuer",
            "publicKeyJwk": serde_json::to_value(&pub_jwk).expect("jwk to value")
        });

        let method = OpenBadgeMethod::from_json(&json).unwrap();
        assert!(!method.is_x509());
        assert!(method.as_ssi().is_some());
    }

    #[test]
    fn test_parse_jwk_method_rejects_private_members() {
        for member in PRIVATE_JWK_MEMBERS {
            let mut jwk = serde_json::json!({"kty":"OKP","crv":"Ed25519","x":"public"});
            jwk.as_object_mut()
                .unwrap()
                .insert(member.to_owned(), serde_json::json!("secret"));
            let method = serde_json::json!({
                "id": "did:example:issuer#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:issuer",
                "publicKeyJwk": jwk
            });
            assert!(OpenBadgeMethod::from_json(&method).is_err());
        }
    }

    #[test]
    fn test_parse_method_rejects_private_key_extensions_without_value_echo() {
        for member in PRIVATE_METHOD_MEMBERS {
            let mut method = serde_json::json!({
                "id": "did:example:issuer#key-1",
                "type": "JsonWebKey2020",
                "controller": "did:example:issuer"
            });
            method
                .as_object_mut()
                .unwrap()
                .insert(member.into(), serde_json::json!("secret-sentinel"));
            let error = OpenBadgeMethod::from_json(&method).unwrap_err();
            assert!(error.to_string().contains("private key member"));
            assert!(!error.to_string().contains("secret-sentinel"));
        }
    }

    #[test]
    fn test_parse_with_warnings() {
        let json = json!({
            "id": "https://issuer.edu/keys/1",
            "type": "X509VerificationKey2021",
            "controller": "https://issuer.edu",
            "publicKeyPem": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----"
        });

        let mut warnings = Vec::new();
        let result = parse_open_badge_method(&json, &mut warnings, "test");

        assert!(result.is_some());
        assert!(warnings.is_empty());

        let (iri, method) = result.unwrap();
        assert_eq!(iri.as_str(), "https://issuer.edu/keys/1");
        assert!(method.is_x509());
    }
}
