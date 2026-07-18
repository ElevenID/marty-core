//! X509VerificationKey2021 verification method for Open Badges.
//!
//! This module provides X.509 certificate-based verification for Open Badge v3 credentials,
//! supporting the X509VerificationKey2021 verification method type.

use iref::IriBuf;
use serde::{Deserialize, Serialize};
use ssi_verification_methods::VerificationMethod;

use crate::error::{VerificationError, VerificationResult};

/// X509VerificationKey2021 verification method.
///
/// Represents an X.509 certificate-based verification method for Open Badges,
/// following the W3C DID specification pattern.
///
/// # Example JSON
/// ```json
/// {
///   "id": "https://issuer.edu/credentials/keys/1",
///   "type": "X509VerificationKey2021",
///   "controller": "https://issuer.edu",
///   "publicKeyPem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X509VerificationKey2021 {
    /// Unique identifier for this verification method (e.g., "https://issuer.edu/keys/1").
    pub id: IriBuf,

    /// Controller DID or URL that owns this verification method.
    pub controller: String,

    /// PEM-encoded X.509 certificate.
    #[serde(rename = "publicKeyPem")]
    pub public_key_pem: String,

    /// Optional X.509 certificate chain (base64-encoded DER certificates).
    /// First certificate is the end-entity cert, followed by intermediates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

impl X509VerificationKey2021 {
    /// Create a new X509VerificationKey2021 from a PEM-encoded certificate.
    pub fn new(id: IriBuf, controller: String, public_key_pem: String) -> Self {
        Self {
            id,
            controller,
            public_key_pem,
            x5c: None,
        }
    }

    /// Create with certificate chain.
    pub fn with_chain(
        id: IriBuf,
        controller: String,
        public_key_pem: String,
        x5c: Vec<String>,
    ) -> Self {
        Self {
            id,
            controller,
            public_key_pem,
            x5c: Some(x5c),
        }
    }

    /// Get the certificate as PEM string.
    pub fn certificate_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// Parse the PEM certificate to DER bytes for validation.
    pub fn certificate_der(&self) -> VerificationResult<Vec<u8>> {
        // Parse PEM to DER
        let pem_data = self
            .public_key_pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();

        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&pem_data)
            .map_err(|e| {
                VerificationError::open_badges(format!("Failed to decode certificate PEM: {}", e))
            })
    }
}

impl VerificationMethod for X509VerificationKey2021 {
    fn id(&self) -> &iref::Iri {
        &self.id
    }

    fn controller(&self) -> Option<&iref::Iri> {
        None // X.509 certificates have their own subject/issuer hierarchy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x509_verification_method_json() {
        let json = r#"{
            "id": "https://issuer.edu/keys/1",
            "type": "X509VerificationKey2021",
            "controller": "https://issuer.edu",
            "publicKeyPem": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKHHCgVZU7c4MAoGCCqGSM49BAMCMA0xCzAJBgNVBAYTAlVTMB4X\nDTI0MDEwMTAwMDAwMFoXDTI1MDEwMTAwMDAwMFowDTELMAkGA1UEBhMCVVMwWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAARx3Z9Q7Y8sH5K0Wq7xJ3H9O6d5k0P2jO6w\nKqC8n5k0P2jO6wKqC8n5k0P2jO6wKqC8n5k0P2jO6wKqC8n5k0P2MAoGCCqGSM49\nBAMCA0gAMEUCIQDJ0P2jO6wKqC8n5k0P2jO6wKqC8n5k0P2jO6wKqC8n5wIgJ0P2\njO6wKqC8n5k0P2jO6wKqC8n5k0P2jO6wKqC8n5k=\n-----END CERTIFICATE-----"
        }"#;

        let method: X509VerificationKey2021 = serde_json::from_str(json).unwrap();
        assert_eq!(method.id.as_str(), "https://issuer.edu/keys/1");
        assert_eq!(method.controller, "https://issuer.edu");
        assert!(method.public_key_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_x509_with_chain() {
        let method = X509VerificationKey2021::with_chain(
            IriBuf::new("https://issuer.edu/keys/1".to_string()).unwrap(),
            "https://issuer.edu".to_string(),
            "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----".to_string(),
            vec!["MIIBkT...".to_string()],
        );

        assert!(method.x5c.is_some());
        assert_eq!(method.x5c.unwrap().len(), 1);
    }
}
