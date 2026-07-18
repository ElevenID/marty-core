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

/// Wrapper enum for Open Badge verification methods.
///
/// Combines SSI's standard verification methods (JsonWebKey2020, Ed25519VerificationKey2018/2020)
/// with custom X509VerificationKey2021 for certificate-based verification.
#[derive(Debug, Clone)]
pub enum OpenBadgeMethod {
    /// Standard SSI verification method (JsonWebKey2020, Ed25519, etc.).
    Ssi(AnyMethod),

    /// X.509 certificate-based verification method.
    X509(X509VerificationKey2021),
}

impl OpenBadgeMethod {
    /// Parse from JSON value, attempting X509 first, then falling back to SSI methods.
    pub fn from_json(value: &Value) -> VerificationResult<Self> {
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
                return Ok(OpenBadgeMethod::X509(x509));
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

        Ok(OpenBadgeMethod::Ssi(method))
    }

    /// Get the verification method ID.
    pub fn id(&self) -> &iref::Iri {
        match self {
            OpenBadgeMethod::Ssi(m) => m.id(),
            OpenBadgeMethod::X509(m) => m.id(),
        }
    }

    /// Check if this is an X509 verification method.
    pub fn is_x509(&self) -> bool {
        matches!(self, OpenBadgeMethod::X509(_))
    }

    /// Get X509 method reference, if applicable.
    pub fn as_x509(&self) -> Option<&X509VerificationKey2021> {
        match self {
            OpenBadgeMethod::X509(m) => Some(m),
            _ => None,
        }
    }

    /// Get SSI method reference, if applicable.
    pub fn as_ssi(&self) -> Option<&AnyMethod> {
        match self {
            OpenBadgeMethod::Ssi(m) => Some(m),
            _ => None,
        }
    }
}

impl VerificationMethod for OpenBadgeMethod {
    fn id(&self) -> &iref::Iri {
        match self {
            OpenBadgeMethod::Ssi(m) => m.id(),
            OpenBadgeMethod::X509(m) => m.id(),
        }
    }

    fn controller(&self) -> Option<&iref::Iri> {
        match self {
            OpenBadgeMethod::Ssi(m) => m.controller(),
            OpenBadgeMethod::X509(m) => m.controller(),
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
