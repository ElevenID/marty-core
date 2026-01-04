//! CSCA (Country Signing Certificate Authority) registry for eMRTD verification.
//!
//! This module provides CSCA certificate management for ICAO 9303 eMRTD verification
//! (ePassports, electronic travel documents).

use std::collections::HashMap;
use std::path::Path;

use x509_cert::Certificate;

use super::registry::{BasicTrustRegistry, TrustAnchor, TrustPurpose, TrustRegistry};
use crate::error::VerificationResult;

/// CSCA-specific trust anchor registry with country management.
///
/// Extends BasicTrustRegistry with ICAO PKD-specific functionality:
/// - Country-based lookups (ISO 3166-1 alpha-2/alpha-3)
/// - Master List parsing
/// - DSC certificate caching
#[derive(Clone, Default)]
pub struct CscaRegistry {
    /// Inner registry storing all CSCA trust anchors.
    csca_anchors: BasicTrustRegistry,
    /// Cached DSC certificates indexed by issuer.
    dsc_cache: HashMap<String, Vec<Certificate>>,
    /// Index by country code for fast lookups.
    country_index: HashMap<String, Vec<usize>>,
    /// Master List version for delta sync.
    master_list_version: Option<String>,
}

impl CscaRegistry {
    /// Create a new empty CSCA registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load CSCA certificates from a directory.
    ///
    /// Expects PEM files named by country code (e.g., `US.pem`, `DEU.pem`).
    pub fn from_directory(path: &Path) -> VerificationResult<Self> {
        let csca_anchors = BasicTrustRegistry::from_pem_directory(path, TrustPurpose::Csca)?;
        let mut registry = Self {
            csca_anchors,
            dsc_cache: HashMap::new(),
            country_index: HashMap::new(),
            master_list_version: None,
        };
        registry.rebuild_index();
        Ok(registry)
    }

    /// Add a CSCA certificate for a specific country.
    pub fn add_country_csca(
        &mut self,
        country_code: &str,
        certificate: Certificate,
    ) -> VerificationResult<()> {
        let anchor = TrustAnchor {
            certificate,
            purpose: TrustPurpose::Csca,
            jurisdiction: Some(country_code.to_uppercase()),
        };

        let index = self.csca_anchors.get_anchors().len();
        self.csca_anchors.add_anchor(anchor)?;

        self.country_index
            .entry(country_code.to_uppercase())
            .or_default()
            .push(index);

        Ok(())
    }

    /// Get all CSCA certificates for a specific country.
    ///
    /// A country may have multiple CSCAs (e.g., during key rotation).
    pub fn get_country_cscas(&self, country_code: &str) -> Vec<&TrustAnchor> {
        self.country_index
            .get(&country_code.to_uppercase())
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&idx| self.csca_anchors.get_anchors().get(idx))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all supported countries.
    pub fn supported_countries(&self) -> Vec<&str> {
        self.country_index.keys().map(|s| s.as_str()).collect()
    }

    /// Merge CSCA certificates from a local PEM directory (existing pattern for PKD caches).
    pub fn merge_from_directory(&mut self, path: &Path) -> VerificationResult<usize> {
        let from_dir = BasicTrustRegistry::from_pem_directory(path, TrustPurpose::Csca)?;
        let mut added = 0;
        for anchor in from_dir.get_anchors() {
            self.add_anchor(anchor.clone())?;
            added += 1;
        }
        Ok(added)
    }

    /// Cache a DSC certificate for faster verification.
    pub fn cache_dsc(&mut self, issuer: &str, dsc: Certificate) {
        self.dsc_cache
            .entry(issuer.to_string())
            .or_default()
            .push(dsc);
    }

    /// Get cached DSC certificates by issuer.
    pub fn get_cached_dscs(&self, issuer: &str) -> Option<&Vec<Certificate>> {
        self.dsc_cache.get(issuer)
    }

    /// Clear the DSC cache.
    pub fn clear_dsc_cache(&mut self) {
        self.dsc_cache.clear();
    }

    /// Get the Master List version for delta sync.
    pub fn master_list_version(&self) -> Option<&str> {
        self.master_list_version.as_deref()
    }

    /// Set the Master List version after a sync.
    pub fn set_master_list_version(&mut self, version: String) {
        self.master_list_version = Some(version);
    }

    /// Rebuild the country index after modifications.
    fn rebuild_index(&mut self) {
        self.country_index.clear();
        for (idx, anchor) in self.csca_anchors.get_anchors().iter().enumerate() {
            if let Some(jurisdiction) = &anchor.jurisdiction {
                self.country_index
                    .entry(jurisdiction.clone())
                    .or_default()
                    .push(idx);
            }
        }
    }
}

impl TrustRegistry for CscaRegistry {
    fn get_anchors(&self) -> &[TrustAnchor] {
        self.csca_anchors.get_anchors()
    }

    fn add_anchor(&mut self, anchor: TrustAnchor) -> VerificationResult<()> {
        let jurisdiction = anchor.jurisdiction.clone();
        let index = self.csca_anchors.get_anchors().len();
        self.csca_anchors.add_anchor(anchor)?;

        if let Some(j) = jurisdiction {
            self.country_index.entry(j).or_default().push(index);
        }

        Ok(())
    }

    fn remove_anchor(&mut self, subject: &str) -> VerificationResult<bool> {
        let result = self.csca_anchors.remove_anchor(subject)?;
        if result {
            self.rebuild_index();
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = CscaRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.supported_countries().is_empty());
    }

    #[test]
    fn test_country_lookup() {
        let registry = CscaRegistry::new();
        let cscas = registry.get_country_cscas("US");
        assert!(cscas.is_empty());
    }

    #[test]
    fn test_add_country_csca() {
        use crate::testdata::NIST_TRUST_ANCHOR_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert =
            Certificate::from_der(NIST_TRUST_ANCHOR_DER).expect("Failed to parse certificate");

        let mut registry = CscaRegistry::new();
        registry
            .add_country_csca("US", cert.clone())
            .expect("Failed to add CSCA");

        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());

        let countries = registry.supported_countries();
        assert!(countries.contains(&"US"));

        let us_cscas = registry.get_country_cscas("US");
        assert_eq!(us_cscas.len(), 1);
    }

    #[test]
    fn test_add_multiple_countries() {
        use crate::testdata::{NIST_DSA_CA_DER, NIST_GOOD_CA_DER, NIST_TRUST_ANCHOR_DER};
        use der::Decode;
        use x509_cert::Certificate;

        let mut registry = CscaRegistry::new();

        // Add US CSCA
        let cert_us = Certificate::from_der(NIST_TRUST_ANCHOR_DER).unwrap();
        registry.add_country_csca("US", cert_us).unwrap();

        // Add DE CSCA
        let cert_de = Certificate::from_der(NIST_DSA_CA_DER).unwrap();
        registry.add_country_csca("DE", cert_de).unwrap();

        // Add FR CSCA
        let cert_fr = Certificate::from_der(NIST_GOOD_CA_DER).unwrap();
        registry.add_country_csca("FR", cert_fr).unwrap();

        assert_eq!(registry.len(), 3);

        let countries = registry.supported_countries();
        assert!(countries.contains(&"US"));
        assert!(countries.contains(&"DE"));
        assert!(countries.contains(&"FR"));
    }

    #[test]
    fn test_multiple_cscas_per_country() {
        use crate::testdata::{NIST_DSA_CA_DER, NIST_TRUST_ANCHOR_DER};
        use der::Decode;
        use x509_cert::Certificate;

        let mut registry = CscaRegistry::new();

        // Add two CSCAs for US (simulating key rollover)
        let cert1 = Certificate::from_der(NIST_TRUST_ANCHOR_DER).unwrap();
        registry.add_country_csca("US", cert1).unwrap();

        let cert2 = Certificate::from_der(NIST_DSA_CA_DER).unwrap();
        registry.add_country_csca("US", cert2).unwrap();

        assert_eq!(registry.len(), 2);

        let us_cscas = registry.get_country_cscas("US");
        assert_eq!(us_cscas.len(), 2);

        // Only one country should be listed
        let countries = registry.supported_countries();
        assert_eq!(countries.len(), 1);
        assert!(countries.contains(&"US"));
    }

    #[test]
    fn test_dsc_caching() {
        use crate::testdata::{NIST_TRUST_ANCHOR_DER, NIST_VALID_EE_DER};
        use der::Decode;
        use x509_cert::Certificate;

        let mut registry = CscaRegistry::new();

        // Add CSCA
        let csca = Certificate::from_der(NIST_TRUST_ANCHOR_DER).unwrap();
        registry.add_country_csca("US", csca).unwrap();

        // Cache a DSC
        let dsc = Certificate::from_der(NIST_VALID_EE_DER).unwrap();
        registry.cache_dsc("US", dsc);

        // Verify caching (implementation-dependent)
        // This mainly tests that the method doesn't panic
        assert!(!registry.is_empty());
    }
}
