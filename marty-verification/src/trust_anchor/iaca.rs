//! IACA (Issuing Authority Certificate Authority) registry for mDL verification.
//!
//! This module provides IACA certificate management for ISO 18013-5 mDL verification,
//! with support for AAMVA jurisdictions (US states/territories, Canadian provinces).

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use super::registry::{BasicTrustRegistry, TrustAnchor, TrustPurpose, TrustRegistry};
use crate::error::VerificationResult;

/// IACA-specific trust anchor registry with jurisdiction management.
///
/// Extends BasicTrustRegistry with AAMVA-specific functionality:
/// - Jurisdiction-based lookups (US-CA, US-NY, CA-ON, etc.)
/// - VICAL (Verifier IACA Certificate Authority List) support
/// - Automatic certificate refresh from AAMVA DTS
#[derive(Clone, Default)]
pub struct IacaRegistry {
    /// Inner registry storing all trust anchors.
    inner: BasicTrustRegistry,
    /// Index by jurisdiction code for fast lookups.
    jurisdiction_index: HashMap<String, usize>,
    /// VICAL version for delta sync.
    vical_version: Option<String>,
}

/// AAMVA jurisdiction codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Jurisdiction {
    // US States
    Alabama,
    Alaska,
    Arizona,
    Arkansas,
    California,
    Colorado,
    Connecticut,
    Delaware,
    DistrictOfColumbia,
    Florida,
    Georgia,
    Hawaii,
    Idaho,
    Illinois,
    Indiana,
    Iowa,
    Kansas,
    Kentucky,
    Louisiana,
    Maine,
    Maryland,
    Massachusetts,
    Michigan,
    Minnesota,
    Mississippi,
    Missouri,
    Montana,
    Nebraska,
    Nevada,
    NewHampshire,
    NewJersey,
    NewMexico,
    NewYork,
    NorthCarolina,
    NorthDakota,
    Ohio,
    Oklahoma,
    Oregon,
    Pennsylvania,
    RhodeIsland,
    SouthCarolina,
    SouthDakota,
    Tennessee,
    Texas,
    Utah,
    Vermont,
    Virginia,
    Washington,
    WestVirginia,
    Wisconsin,
    Wyoming,
    // US Territories
    AmericanSamoa,
    Guam,
    NorthernMarianaIslands,
    PuertoRico,
    VirginIslands,
    // Canadian Provinces
    Alberta,
    BritishColumbia,
    Manitoba,
    NewBrunswick,
    NewfoundlandAndLabrador,
    NovaScotia,
    Ontario,
    PrinceEdwardIsland,
    Quebec,
    Saskatchewan,
    NorthwestTerritories,
    Nunavut,
    Yukon,
}

impl Jurisdiction {
    /// Get the ISO 3166-2 code for this jurisdiction.
    pub fn code(&self) -> &'static str {
        match self {
            // US States
            Jurisdiction::Alabama => "US-AL",
            Jurisdiction::Alaska => "US-AK",
            Jurisdiction::Arizona => "US-AZ",
            Jurisdiction::Arkansas => "US-AR",
            Jurisdiction::California => "US-CA",
            Jurisdiction::Colorado => "US-CO",
            Jurisdiction::Connecticut => "US-CT",
            Jurisdiction::Delaware => "US-DE",
            Jurisdiction::DistrictOfColumbia => "US-DC",
            Jurisdiction::Florida => "US-FL",
            Jurisdiction::Georgia => "US-GA",
            Jurisdiction::Hawaii => "US-HI",
            Jurisdiction::Idaho => "US-ID",
            Jurisdiction::Illinois => "US-IL",
            Jurisdiction::Indiana => "US-IN",
            Jurisdiction::Iowa => "US-IA",
            Jurisdiction::Kansas => "US-KS",
            Jurisdiction::Kentucky => "US-KY",
            Jurisdiction::Louisiana => "US-LA",
            Jurisdiction::Maine => "US-ME",
            Jurisdiction::Maryland => "US-MD",
            Jurisdiction::Massachusetts => "US-MA",
            Jurisdiction::Michigan => "US-MI",
            Jurisdiction::Minnesota => "US-MN",
            Jurisdiction::Mississippi => "US-MS",
            Jurisdiction::Missouri => "US-MO",
            Jurisdiction::Montana => "US-MT",
            Jurisdiction::Nebraska => "US-NE",
            Jurisdiction::Nevada => "US-NV",
            Jurisdiction::NewHampshire => "US-NH",
            Jurisdiction::NewJersey => "US-NJ",
            Jurisdiction::NewMexico => "US-NM",
            Jurisdiction::NewYork => "US-NY",
            Jurisdiction::NorthCarolina => "US-NC",
            Jurisdiction::NorthDakota => "US-ND",
            Jurisdiction::Ohio => "US-OH",
            Jurisdiction::Oklahoma => "US-OK",
            Jurisdiction::Oregon => "US-OR",
            Jurisdiction::Pennsylvania => "US-PA",
            Jurisdiction::RhodeIsland => "US-RI",
            Jurisdiction::SouthCarolina => "US-SC",
            Jurisdiction::SouthDakota => "US-SD",
            Jurisdiction::Tennessee => "US-TN",
            Jurisdiction::Texas => "US-TX",
            Jurisdiction::Utah => "US-UT",
            Jurisdiction::Vermont => "US-VT",
            Jurisdiction::Virginia => "US-VA",
            Jurisdiction::Washington => "US-WA",
            Jurisdiction::WestVirginia => "US-WV",
            Jurisdiction::Wisconsin => "US-WI",
            Jurisdiction::Wyoming => "US-WY",
            // US Territories
            Jurisdiction::AmericanSamoa => "US-AS",
            Jurisdiction::Guam => "US-GU",
            Jurisdiction::NorthernMarianaIslands => "US-MP",
            Jurisdiction::PuertoRico => "US-PR",
            Jurisdiction::VirginIslands => "US-VI",
            // Canadian Provinces
            Jurisdiction::Alberta => "CA-AB",
            Jurisdiction::BritishColumbia => "CA-BC",
            Jurisdiction::Manitoba => "CA-MB",
            Jurisdiction::NewBrunswick => "CA-NB",
            Jurisdiction::NewfoundlandAndLabrador => "CA-NL",
            Jurisdiction::NovaScotia => "CA-NS",
            Jurisdiction::Ontario => "CA-ON",
            Jurisdiction::PrinceEdwardIsland => "CA-PE",
            Jurisdiction::Quebec => "CA-QC",
            Jurisdiction::Saskatchewan => "CA-SK",
            Jurisdiction::NorthwestTerritories => "CA-NT",
            Jurisdiction::Nunavut => "CA-NU",
            Jurisdiction::Yukon => "CA-YT",
        }
    }

    /// Parse a jurisdiction from its code.
    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_uppercase().as_str() {
            "US-AL" => Some(Jurisdiction::Alabama),
            "US-AK" => Some(Jurisdiction::Alaska),
            "US-AZ" => Some(Jurisdiction::Arizona),
            "US-AR" => Some(Jurisdiction::Arkansas),
            "US-CA" => Some(Jurisdiction::California),
            "US-CO" => Some(Jurisdiction::Colorado),
            "US-CT" => Some(Jurisdiction::Connecticut),
            "US-DE" => Some(Jurisdiction::Delaware),
            "US-DC" => Some(Jurisdiction::DistrictOfColumbia),
            "US-FL" => Some(Jurisdiction::Florida),
            "US-GA" => Some(Jurisdiction::Georgia),
            "US-HI" => Some(Jurisdiction::Hawaii),
            "US-ID" => Some(Jurisdiction::Idaho),
            "US-IL" => Some(Jurisdiction::Illinois),
            "US-IN" => Some(Jurisdiction::Indiana),
            "US-IA" => Some(Jurisdiction::Iowa),
            "US-KS" => Some(Jurisdiction::Kansas),
            "US-KY" => Some(Jurisdiction::Kentucky),
            "US-LA" => Some(Jurisdiction::Louisiana),
            "US-ME" => Some(Jurisdiction::Maine),
            "US-MD" => Some(Jurisdiction::Maryland),
            "US-MA" => Some(Jurisdiction::Massachusetts),
            "US-MI" => Some(Jurisdiction::Michigan),
            "US-MN" => Some(Jurisdiction::Minnesota),
            "US-MS" => Some(Jurisdiction::Mississippi),
            "US-MO" => Some(Jurisdiction::Missouri),
            "US-MT" => Some(Jurisdiction::Montana),
            "US-NE" => Some(Jurisdiction::Nebraska),
            "US-NV" => Some(Jurisdiction::Nevada),
            "US-NH" => Some(Jurisdiction::NewHampshire),
            "US-NJ" => Some(Jurisdiction::NewJersey),
            "US-NM" => Some(Jurisdiction::NewMexico),
            "US-NY" => Some(Jurisdiction::NewYork),
            "US-NC" => Some(Jurisdiction::NorthCarolina),
            "US-ND" => Some(Jurisdiction::NorthDakota),
            "US-OH" => Some(Jurisdiction::Ohio),
            "US-OK" => Some(Jurisdiction::Oklahoma),
            "US-OR" => Some(Jurisdiction::Oregon),
            "US-PA" => Some(Jurisdiction::Pennsylvania),
            "US-RI" => Some(Jurisdiction::RhodeIsland),
            "US-SC" => Some(Jurisdiction::SouthCarolina),
            "US-SD" => Some(Jurisdiction::SouthDakota),
            "US-TN" => Some(Jurisdiction::Tennessee),
            "US-TX" => Some(Jurisdiction::Texas),
            "US-UT" => Some(Jurisdiction::Utah),
            "US-VT" => Some(Jurisdiction::Vermont),
            "US-VA" => Some(Jurisdiction::Virginia),
            "US-WA" => Some(Jurisdiction::Washington),
            "US-WV" => Some(Jurisdiction::WestVirginia),
            "US-WI" => Some(Jurisdiction::Wisconsin),
            "US-WY" => Some(Jurisdiction::Wyoming),
            "US-AS" => Some(Jurisdiction::AmericanSamoa),
            "US-GU" => Some(Jurisdiction::Guam),
            "US-MP" => Some(Jurisdiction::NorthernMarianaIslands),
            "US-PR" => Some(Jurisdiction::PuertoRico),
            "US-VI" => Some(Jurisdiction::VirginIslands),
            "CA-AB" => Some(Jurisdiction::Alberta),
            "CA-BC" => Some(Jurisdiction::BritishColumbia),
            "CA-MB" => Some(Jurisdiction::Manitoba),
            "CA-NB" => Some(Jurisdiction::NewBrunswick),
            "CA-NL" => Some(Jurisdiction::NewfoundlandAndLabrador),
            "CA-NS" => Some(Jurisdiction::NovaScotia),
            "CA-ON" => Some(Jurisdiction::Ontario),
            "CA-PE" => Some(Jurisdiction::PrinceEdwardIsland),
            "CA-QC" => Some(Jurisdiction::Quebec),
            "CA-SK" => Some(Jurisdiction::Saskatchewan),
            "CA-NT" => Some(Jurisdiction::NorthwestTerritories),
            "CA-NU" => Some(Jurisdiction::Nunavut),
            "CA-YT" => Some(Jurisdiction::Yukon),
            _ => None,
        }
    }
}

impl IacaRegistry {
    /// Create a new empty IACA registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load IACA certificates from a directory.
    ///
    /// Expects PEM files named by jurisdiction code (e.g., `US-CA.pem`).
    pub fn from_directory(path: &Path) -> VerificationResult<Self> {
        let inner = BasicTrustRegistry::from_pem_directory(path, TrustPurpose::Iaca)?;
        let mut registry = Self {
            inner,
            jurisdiction_index: HashMap::new(),
            vical_version: None,
        };
        registry.rebuild_index();
        Ok(registry)
    }

    /// Add an IACA certificate for a specific jurisdiction.
    pub fn add_jurisdiction_iaca(
        &mut self,
        jurisdiction: Jurisdiction,
        certificate: Certificate,
    ) -> VerificationResult<()> {
        let anchor = TrustAnchor {
            certificate,
            purpose: TrustPurpose::Iaca,
            jurisdiction: Some(jurisdiction.code().to_string()),
        };

        let index = self.inner.get_anchors().len();
        self.inner.add_anchor(anchor)?;
        self.jurisdiction_index
            .insert(jurisdiction.code().to_string(), index);

        Ok(())
    }

    /// Get the IACA certificate for a specific jurisdiction.
    pub fn get_jurisdiction_iaca(&self, jurisdiction: Jurisdiction) -> Option<&TrustAnchor> {
        self.jurisdiction_index
            .get(jurisdiction.code())
            .and_then(|&idx| self.inner.get_anchors().get(idx))
    }

    /// Get all supported jurisdictions.
    pub fn supported_jurisdictions(&self) -> Vec<&str> {
        self.jurisdiction_index.keys().map(|s| s.as_str()).collect()
    }

    /// Get the VICAL version for delta sync.
    pub fn vical_version(&self) -> Option<&str> {
        self.vical_version.as_deref()
    }

    /// Set the VICAL version after a sync.
    pub fn set_vical_version(&mut self, version: String) {
        self.vical_version = Some(version);
    }

    /// Rebuild the jurisdiction index after modifications.
    fn rebuild_index(&mut self) {
        self.jurisdiction_index.clear();
        for (idx, anchor) in self.inner.get_anchors().iter().enumerate() {
            if let Some(jurisdiction) = &anchor.jurisdiction {
                self.jurisdiction_index.insert(jurisdiction.clone(), idx);
            }
        }
    }

    /// Convert to isomdl TrustAnchorRegistry for use with isomdl verification.
    pub fn to_isomdl_registry(
        &self,
    ) -> isomdl::definitions::x509::trust_anchor::TrustAnchorRegistry {
        (&self.inner).into()
    }
}

impl TrustRegistry for IacaRegistry {
    fn get_anchors(&self) -> &[TrustAnchor] {
        self.inner.get_anchors()
    }

    fn add_anchor(&mut self, anchor: TrustAnchor) -> VerificationResult<()> {
        let jurisdiction = anchor.jurisdiction.clone();
        let index = self.inner.get_anchors().len();
        self.inner.add_anchor(anchor)?;

        if let Some(j) = jurisdiction {
            self.jurisdiction_index.insert(j, index);
        }

        Ok(())
    }

    fn remove_anchor(&mut self, subject: &str) -> VerificationResult<bool> {
        let result = self.inner.remove_anchor(subject)?;
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
    fn test_jurisdiction_codes() {
        assert_eq!(Jurisdiction::California.code(), "US-CA");
        assert_eq!(Jurisdiction::Ontario.code(), "CA-ON");
        assert_eq!(
            Jurisdiction::from_code("US-CA"),
            Some(Jurisdiction::California)
        );
        assert_eq!(Jurisdiction::from_code("INVALID"), None);
    }

    #[test]
    fn test_empty_registry() {
        let registry = IacaRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.supported_jurisdictions().is_empty());
    }

    #[test]
    fn test_all_us_states_have_codes() {
        let us_states = [
            Jurisdiction::Alabama,
            Jurisdiction::Alaska,
            Jurisdiction::Arizona,
            Jurisdiction::Arkansas,
            Jurisdiction::California,
            Jurisdiction::Colorado,
            Jurisdiction::Connecticut,
            Jurisdiction::Delaware,
            Jurisdiction::Florida,
            Jurisdiction::Georgia,
            Jurisdiction::Hawaii,
            Jurisdiction::Idaho,
            Jurisdiction::Illinois,
            Jurisdiction::Indiana,
            Jurisdiction::Iowa,
            Jurisdiction::Kansas,
            Jurisdiction::Kentucky,
            Jurisdiction::Louisiana,
            Jurisdiction::Maine,
            Jurisdiction::Maryland,
            Jurisdiction::Massachusetts,
            Jurisdiction::Michigan,
            Jurisdiction::Minnesota,
            Jurisdiction::Mississippi,
            Jurisdiction::Missouri,
            Jurisdiction::Montana,
            Jurisdiction::Nebraska,
            Jurisdiction::Nevada,
            Jurisdiction::NewHampshire,
            Jurisdiction::NewJersey,
            Jurisdiction::NewMexico,
            Jurisdiction::NewYork,
            Jurisdiction::NorthCarolina,
            Jurisdiction::NorthDakota,
            Jurisdiction::Ohio,
            Jurisdiction::Oklahoma,
            Jurisdiction::Oregon,
            Jurisdiction::Pennsylvania,
            Jurisdiction::RhodeIsland,
            Jurisdiction::SouthCarolina,
            Jurisdiction::SouthDakota,
            Jurisdiction::Tennessee,
            Jurisdiction::Texas,
            Jurisdiction::Utah,
            Jurisdiction::Vermont,
            Jurisdiction::Virginia,
            Jurisdiction::Washington,
            Jurisdiction::WestVirginia,
            Jurisdiction::Wisconsin,
            Jurisdiction::Wyoming,
        ];

        for state in us_states {
            let code = state.code();
            assert!(
                code.starts_with("US-"),
                "US state code should start with US-: {}",
                code
            );
            assert_eq!(code.len(), 5, "US state code should be 5 chars: {}", code);

            // Verify roundtrip
            let parsed = Jurisdiction::from_code(code);
            assert_eq!(parsed, Some(state), "Roundtrip failed for {}", code);
        }
    }

    #[test]
    fn test_canadian_provinces_have_codes() {
        let ca_provinces = [
            Jurisdiction::Alberta,
            Jurisdiction::BritishColumbia,
            Jurisdiction::Manitoba,
            Jurisdiction::NewBrunswick,
            Jurisdiction::NewfoundlandAndLabrador,
            Jurisdiction::NovaScotia,
            Jurisdiction::Ontario,
            Jurisdiction::PrinceEdwardIsland,
            Jurisdiction::Quebec,
            Jurisdiction::Saskatchewan,
        ];

        for province in ca_provinces {
            let code = province.code();
            assert!(
                code.starts_with("CA-"),
                "Canadian province code should start with CA-: {}",
                code
            );

            // Verify roundtrip
            let parsed = Jurisdiction::from_code(code);
            assert_eq!(parsed, Some(province), "Roundtrip failed for {}", code);
        }
    }

    #[test]
    fn test_us_territories_have_codes() {
        let territories = [
            Jurisdiction::DistrictOfColumbia,
            Jurisdiction::PuertoRico,
            Jurisdiction::Guam,
            Jurisdiction::VirginIslands,
            Jurisdiction::AmericanSamoa,
            Jurisdiction::NorthernMarianaIslands,
        ];

        for territory in territories {
            let code = territory.code();
            assert!(
                code.starts_with("US-"),
                "Territory code should start with US-: {}",
                code
            );

            // Verify roundtrip
            let parsed = Jurisdiction::from_code(code);
            assert_eq!(parsed, Some(territory), "Roundtrip failed for {}", code);
        }
    }

    #[test]
    fn test_add_jurisdiction_iaca() {
        use crate::testdata::NIST_GOOD_CA_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(NIST_GOOD_CA_DER).expect("Failed to parse certificate");

        let mut registry = IacaRegistry::new();
        registry
            .add_jurisdiction_iaca(Jurisdiction::California, cert.clone())
            .expect("Failed to add IACA");

        assert_eq!(registry.len(), 1);

        let jurisdictions = registry.supported_jurisdictions();
        assert!(jurisdictions.contains(&"US-CA"));

        let iaca = registry.get_jurisdiction_iaca(Jurisdiction::California);
        assert!(iaca.is_some());
    }

    #[test]
    fn test_add_multiple_jurisdictions() {
        use crate::testdata::{NIST_DSA_CA_DER, NIST_GOOD_CA_DER, NIST_TRUST_ANCHOR_DER};
        use der::Decode;
        use x509_cert::Certificate;

        let mut registry = IacaRegistry::new();

        let cert1 = Certificate::from_der(NIST_GOOD_CA_DER).unwrap();
        registry
            .add_jurisdiction_iaca(Jurisdiction::California, cert1)
            .unwrap();

        let cert2 = Certificate::from_der(NIST_DSA_CA_DER).unwrap();
        registry
            .add_jurisdiction_iaca(Jurisdiction::Texas, cert2)
            .unwrap();

        let cert3 = Certificate::from_der(NIST_TRUST_ANCHOR_DER).unwrap();
        registry
            .add_jurisdiction_iaca(Jurisdiction::NewYork, cert3)
            .unwrap();

        assert_eq!(registry.len(), 3);

        let jurisdictions = registry.supported_jurisdictions();
        assert!(jurisdictions.contains(&"US-CA"));
        assert!(jurisdictions.contains(&"US-TX"));
        assert!(jurisdictions.contains(&"US-NY"));
    }

    #[test]
    fn test_vical_version() {
        let mut registry = IacaRegistry::new();
        assert!(registry.vical_version().is_none());

        registry.set_vical_version("1.2.3".to_string());
        assert_eq!(registry.vical_version(), Some("1.2.3"));
    }

    #[test]
    fn test_to_isomdl_registry() {
        use crate::testdata::NIST_GOOD_CA_DER;
        use der::Decode;
        use x509_cert::Certificate;

        let cert = Certificate::from_der(NIST_GOOD_CA_DER).unwrap();

        let mut registry = IacaRegistry::new();
        registry
            .add_jurisdiction_iaca(Jurisdiction::Utah, cert)
            .unwrap();

        // Convert to isomdl TrustAnchorRegistry
        let _isomdl_registry = registry.to_isomdl_registry();

        // The registry should have at least one anchor
        // (conversion should succeed without panic)
        assert!(!registry.is_empty());
    }
}
