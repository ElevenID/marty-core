//! Trust anchor registry trait and common types.
//!
//! Adapted from isomdl::definitions::x509::trust_anchor with extensions
//! for unified verification across document types.

use anyhow::{Context, Error};
use der::{DecodePem, EncodePem};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use crate::error::{VerificationError, VerificationResult};

/// Identifies what purpose the certificate is trusted for.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustPurpose {
    /// Issuing Authority Certificate Authority for mDL (ISO 18013-5).
    Iaca,
    /// Reader Certificate Authority for mDL (ISO 18013-5).
    ReaderCa,
    /// Country Signing Certificate Authority for eMRTD (ICAO 9303).
    Csca,
    /// Document Signer Certificate for eMRTD (ICAO 9303).
    Dsc,
}

/// A root of trust for a specific purpose.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// The X.509 certificate.
    pub certificate: Certificate,
    /// What this certificate is trusted for.
    pub purpose: TrustPurpose,
    /// Optional jurisdiction code (e.g., "US-CA" for California).
    pub jurisdiction: Option<String>,
}

/// PEM representation of a TrustAnchor, used for serialization and deserialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PemTrustAnchor {
    /// PEM-encoded certificate.
    pub certificate_pem: String,
    /// What this certificate is trusted for.
    pub purpose: TrustPurpose,
    /// Optional jurisdiction code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
}

impl TryFrom<PemTrustAnchor> for TrustAnchor {
    type Error = Error;

    fn try_from(value: PemTrustAnchor) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate: Certificate::from_pem(&value.certificate_pem)?,
            purpose: value.purpose,
            jurisdiction: value.jurisdiction,
        })
    }
}

impl<'l> TryFrom<&'l TrustAnchor> for PemTrustAnchor {
    type Error = Error;

    fn try_from(value: &'l TrustAnchor) -> Result<Self, Self::Error> {
        Ok(Self {
            certificate_pem: value.certificate.to_pem(Default::default())?,
            purpose: value.purpose,
            jurisdiction: value.jurisdiction.clone(),
        })
    }
}

impl Serialize for TrustAnchor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;

        PemTrustAnchor::try_from(self)
            .map_err(S::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for TrustAnchor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        PemTrustAnchor::deserialize(deserializer)?
            .try_into()
            .map_err(D::Error::custom)
    }
}

/// Trait for trust anchor registries.
///
/// Implementations provide access to trusted root certificates for different
/// verification scenarios (mDL, eMRTD, etc.).
pub trait TrustRegistry: Send + Sync {
    /// Get all trust anchors in the registry.
    fn get_anchors(&self) -> &[TrustAnchor];

    /// Get trust anchors filtered by purpose.
    fn get_anchors_by_purpose(&self, purpose: TrustPurpose) -> Vec<&TrustAnchor> {
        self.get_anchors()
            .iter()
            .filter(|a| a.purpose == purpose)
            .collect()
    }

    /// Get trust anchors filtered by jurisdiction.
    fn get_anchors_by_jurisdiction(&self, jurisdiction: &str) -> Vec<&TrustAnchor> {
        self.get_anchors()
            .iter()
            .filter(|a| a.jurisdiction.as_deref() == Some(jurisdiction))
            .collect()
    }

    /// Find a trust anchor that could have signed the given certificate.
    fn find_issuer(&self, subject: &Certificate, purpose: TrustPurpose) -> Option<&TrustAnchor> {
        self.get_anchors()
            .iter()
            .filter(|a| a.purpose == purpose)
            .find(|anchor| {
                anchor.certificate.tbs_certificate.subject == subject.tbs_certificate.issuer
            })
    }

    /// Add a trust anchor to the registry.
    fn add_anchor(&mut self, anchor: TrustAnchor) -> VerificationResult<()>;

    /// Remove a trust anchor from the registry by subject name.
    fn remove_anchor(&mut self, subject: &str) -> VerificationResult<bool>;

    /// Refresh the registry from its source (if applicable).
    fn refresh(&mut self) -> VerificationResult<usize> {
        // Default: no-op, returns 0 anchors refreshed
        Ok(0)
    }

    /// Get the number of trust anchors in the registry.
    fn len(&self) -> usize {
        self.get_anchors().len()
    }

    /// Check if the registry is empty.
    fn is_empty(&self) -> bool {
        self.get_anchors().is_empty()
    }
}

/// A basic in-memory trust anchor registry.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct BasicTrustRegistry {
    anchors: Vec<TrustAnchor>,
}

impl BasicTrustRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a trust anchor registry from PEM certificates.
    pub fn from_pem_certificates(certs: Vec<PemTrustAnchor>) -> VerificationResult<Self> {
        let anchors = certs
            .into_iter()
            .enumerate()
            .map(|(index, t)| {
                TrustAnchor::try_from(t)
                    .context(format!("Failed to build trust anchor for cert no. {index}"))
                    .map_err(|e| {
                        VerificationError::trust_anchor_load(format!(
                            "Certificate #{}: {}",
                            index, e
                        ))
                    })
            })
            .collect::<VerificationResult<Vec<_>>>()?;

        Ok(Self { anchors })
    }

    /// Load trust anchors from a directory of PEM files.
    pub fn from_pem_directory(
        path: &std::path::Path,
        purpose: TrustPurpose,
    ) -> VerificationResult<Self> {
        let mut anchors = Vec::new();

        if !path.exists() {
            return Err(VerificationError::io_error(format!(
                "Directory does not exist: {}",
                path.display()
            )));
        }

        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();

            if file_path
                .extension()
                .is_some_and(|ext| ext == "pem" || ext == "crt")
            {
                let pem_data = std::fs::read_to_string(&file_path)?;

                match Certificate::from_pem(&pem_data) {
                    Ok(cert) => {
                        // Extract jurisdiction from filename if present (e.g., "US-CA.pem")
                        let jurisdiction = file_path
                            .file_stem()
                            .and_then(|s| s.to_str())
                            .map(|s| s.to_string());

                        anchors.push(TrustAnchor {
                            certificate: cert,
                            purpose,
                            jurisdiction,
                        });

                        tracing::debug!("Loaded trust anchor from: {}", file_path.display());
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse certificate from {}: {}",
                            file_path.display(),
                            e
                        );
                    }
                }
            }
        }

        if anchors.is_empty() {
            return Err(VerificationError::empty_registry());
        }

        Ok(Self { anchors })
    }
}

impl TrustRegistry for BasicTrustRegistry {
    fn get_anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    fn add_anchor(&mut self, anchor: TrustAnchor) -> VerificationResult<()> {
        self.anchors.push(anchor);
        Ok(())
    }

    fn remove_anchor(&mut self, subject: &str) -> VerificationResult<bool> {
        let initial_len = self.anchors.len();
        self.anchors.retain(|a| {
            // Compare against common name or full subject
            let cn = a.certificate.tbs_certificate.subject.to_string();
            !cn.contains(subject)
        });
        Ok(self.anchors.len() < initial_len)
    }
}

/// Convert from isomdl's TrustAnchorRegistry for interoperability.
impl From<isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry> for BasicTrustRegistry {
    fn from(registry: isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry) -> Self {
        let anchors = registry
            .anchors
            .into_iter()
            .map(|a| TrustAnchor {
                certificate: a.certificate,
                purpose: match a.purpose {
                    isomdl::definitions::x509::trust_anchor::TrustPurpose::Iaca => {
                        TrustPurpose::Iaca
                    }
                    isomdl::definitions::x509::trust_anchor::TrustPurpose::ReaderCa => {
                        TrustPurpose::ReaderCa
                    }
                },
                jurisdiction: None,
            })
            .collect();

        Self { anchors }
    }
}

/// Convert to isomdl's TrustAnchorRegistry for interoperability.
impl From<&BasicTrustRegistry> for isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry {
    fn from(registry: &BasicTrustRegistry) -> Self {
        let anchors = registry
            .anchors
            .iter()
            .filter_map(|a| {
                let purpose = match a.purpose {
                    TrustPurpose::Iaca => {
                        Some(isomdl::definitions::x509::trust_anchor::TrustPurpose::Iaca)
                    }
                    TrustPurpose::ReaderCa => {
                        Some(isomdl::definitions::x509::trust_anchor::TrustPurpose::ReaderCa)
                    }
                    _ => None, // CSCA/DSC don't map to isomdl
                };

                purpose.map(|p| isomdl::definitions::x509::trust_anchor::TrustAnchor {
                    certificate: a.certificate.clone(),
                    purpose: p,
                })
            })
            .collect();

        isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry { anchors }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = BasicTrustRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_purpose_filter() {
        let registry = BasicTrustRegistry::new();
        let iaca_anchors = registry.get_anchors_by_purpose(TrustPurpose::Iaca);
        assert!(iaca_anchors.is_empty());
    }

    #[test]
    fn test_trust_purpose_display() {
        assert_eq!(format!("{:?}", TrustPurpose::Iaca), "Iaca");
        assert_eq!(format!("{:?}", TrustPurpose::Csca), "Csca");
        assert_eq!(format!("{:?}", TrustPurpose::Dsc), "Dsc");
        assert_eq!(format!("{:?}", TrustPurpose::ReaderCa), "ReaderCa");
    }

    #[test]
    fn test_parse_nist_trust_anchor_der() {
        use crate::testdata::NIST_TRUST_ANCHOR_DER;
        use der::Decode;
        use x509_cert::Certificate;

        // Parse the NIST Trust Anchor certificate from DER
        let cert = Certificate::from_der(NIST_TRUST_ANCHOR_DER)
            .expect("Failed to parse NIST Trust Anchor certificate");

        // Verify it's a CA certificate (self-signed root)
        let subject = cert.tbs_certificate.subject.to_string();
        assert!(
            subject.contains("Trust Anchor"),
            "Subject should contain 'Trust Anchor': {}",
            subject
        );
        assert!(
            subject.contains("Test Certificates"),
            "Subject should contain 'Test Certificates': {}",
            subject
        );
    }

    #[test]
    fn test_parse_nist_good_ca_der() {
        use crate::testdata::NIST_GOOD_CA_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(NIST_GOOD_CA_DER)
            .expect("Failed to parse NIST Good CA certificate");

        let subject = cert.tbs_certificate.subject.to_string();
        assert!(
            subject.contains("Good CA"),
            "Subject should contain 'Good CA': {}",
            subject
        );
    }

    #[test]
    fn test_parse_nist_valid_ee_der() {
        use crate::testdata::NIST_VALID_EE_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(NIST_VALID_EE_DER)
            .expect("Failed to parse NIST Valid EE certificate");

        let subject = cert.tbs_certificate.subject.to_string();
        assert!(
            subject.contains("Valid EE Certificate Test1"),
            "Subject should identify test: {}",
            subject
        );
    }

    #[test]
    fn test_add_anchor_from_der() {
        use crate::testdata::NIST_TRUST_ANCHOR_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert =
            Certificate::from_der(NIST_TRUST_ANCHOR_DER).expect("Failed to parse certificate");

        let anchor = TrustAnchor {
            certificate: cert,
            purpose: TrustPurpose::Csca,
            jurisdiction: Some("US".to_string()),
        };

        let mut registry = BasicTrustRegistry::new();
        registry.add_anchor(anchor).expect("Failed to add anchor");

        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());

        let csca_anchors = registry.get_anchors_by_purpose(TrustPurpose::Csca);
        assert_eq!(csca_anchors.len(), 1);

        let iaca_anchors = registry.get_anchors_by_purpose(TrustPurpose::Iaca);
        assert!(iaca_anchors.is_empty());
    }

    #[test]
    fn test_add_multiple_anchors() {
        use crate::testdata::{NIST_DSA_CA_DER, NIST_GOOD_CA_DER, NIST_TRUST_ANCHOR_DER};
        use der::Decode;
        use x509_cert::Certificate;

        let mut registry = BasicTrustRegistry::new();

        // Add Trust Anchor as CSCA
        let cert1 = Certificate::from_der(NIST_TRUST_ANCHOR_DER).unwrap();
        registry
            .add_anchor(TrustAnchor {
                certificate: cert1,
                purpose: TrustPurpose::Csca,
                jurisdiction: Some("US".to_string()),
            })
            .unwrap();

        // Add Good CA as IACA
        let cert2 = Certificate::from_der(NIST_GOOD_CA_DER).unwrap();
        registry
            .add_anchor(TrustAnchor {
                certificate: cert2,
                purpose: TrustPurpose::Iaca,
                jurisdiction: Some("US-CA".to_string()),
            })
            .unwrap();

        // Add DSA CA as another CSCA
        let cert3 = Certificate::from_der(NIST_DSA_CA_DER).unwrap();
        registry
            .add_anchor(TrustAnchor {
                certificate: cert3,
                purpose: TrustPurpose::Csca,
                jurisdiction: Some("DE".to_string()),
            })
            .unwrap();

        assert_eq!(registry.len(), 3);
        assert_eq!(registry.get_anchors_by_purpose(TrustPurpose::Csca).len(), 2);
        assert_eq!(registry.get_anchors_by_purpose(TrustPurpose::Iaca).len(), 1);
    }

    #[test]
    fn test_der_to_pem_roundtrip() {
        use crate::testdata::{nist_trust_anchor_pem, NIST_TRUST_ANCHOR_DER};
        use der::Decode;
        use x509_cert::Certificate;

        // Parse from DER
        let cert_from_der =
            Certificate::from_der(NIST_TRUST_ANCHOR_DER).expect("Failed to parse from DER");

        // Convert to PEM and parse back
        let pem_str = nist_trust_anchor_pem();
        assert!(pem_str.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem_str.ends_with("-----END CERTIFICATE-----"));

        // Parse from PEM
        use der::DecodePem;
        let cert_from_pem = Certificate::from_pem(&pem_str).expect("Failed to parse from PEM");

        // Subjects should match
        assert_eq!(
            cert_from_der.tbs_certificate.subject.to_string(),
            cert_from_pem.tbs_certificate.subject.to_string()
        );
    }

    #[test]
    fn test_find_issuer() {
        use crate::testdata::{NIST_GOOD_CA_DER, NIST_TRUST_ANCHOR_DER};
        use der::Decode;
        use x509_cert::Certificate;

        let mut registry = BasicTrustRegistry::new();

        // Add Trust Anchor
        let trust_anchor = Certificate::from_der(NIST_TRUST_ANCHOR_DER).unwrap();
        registry
            .add_anchor(TrustAnchor {
                certificate: trust_anchor,
                purpose: TrustPurpose::Csca,
                jurisdiction: None,
            })
            .unwrap();

        // Parse Good CA (issued by Trust Anchor)
        let good_ca = Certificate::from_der(NIST_GOOD_CA_DER).unwrap();

        // Find issuer should return the Trust Anchor
        let issuer = registry.find_issuer(&good_ca, TrustPurpose::Csca);
        assert!(issuer.is_some(), "Should find issuer for Good CA");

        let issuer = issuer.unwrap();
        let issuer_subject = issuer.certificate.tbs_certificate.subject.to_string();
        assert!(issuer_subject.contains("Trust Anchor"));
    }
}
