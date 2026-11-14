//! EUDI (EU Digital Identity) trust registry.
//!
//! This module provides trust anchor management for EU Digital Identity Wallet
//! verification, with support for:
//! - EU Trusted Lists (ETSI TS 119 612)
//! - List of Trusted Lists (LoTL)
//! - Qualified Trust Service Providers (QTSPs)
//! - 27 EU Member States

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x509_cert::Certificate;

use super::registry::{BasicTrustRegistry, TrustAnchor, TrustPurpose, TrustRegistry};
use crate::error::VerificationResult;

/// EUDI-specific trust anchor registry with member state management.
///
/// Extends BasicTrustRegistry with EUDI-specific functionality:
/// - Member state-based lookups (DE, FR, NL, etc.)
/// - LoTL (List of Trusted Lists) support
/// - QTSP (Qualified Trust Service Provider) management
/// - Trust Service status tracking
#[derive(Clone, Default)]
pub struct EudiRegistry {
    /// Inner registry storing all trust anchors.
    inner: BasicTrustRegistry,
    /// LoTL version for delta sync.
    lotl_version: Option<String>,
    /// QTSP metadata cache.
    qtsp_cache: HashMap<String, TrustServiceProvider>,
}

/// EU Member State codes (ISO 3166-1 alpha-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EuMemberState {
    /// Austria
    AT,
    /// Belgium
    BE,
    /// Bulgaria
    BG,
    /// Croatia
    HR,
    /// Cyprus
    CY,
    /// Czech Republic
    CZ,
    /// Denmark
    DK,
    /// Estonia
    EE,
    /// Finland
    FI,
    /// France
    FR,
    /// Germany
    DE,
    /// Greece
    GR,
    /// Hungary
    HU,
    /// Ireland
    IE,
    /// Italy
    IT,
    /// Latvia
    LV,
    /// Lithuania
    LT,
    /// Luxembourg
    LU,
    /// Malta
    MT,
    /// Netherlands
    NL,
    /// Poland
    PL,
    /// Portugal
    PT,
    /// Romania
    RO,
    /// Slovakia
    SK,
    /// Slovenia
    SI,
    /// Spain
    ES,
    /// Sweden
    SE,
}

impl EuMemberState {
    /// Get the two-letter ISO code.
    pub fn code(&self) -> &'static str {
        match self {
            EuMemberState::AT => "AT",
            EuMemberState::BE => "BE",
            EuMemberState::BG => "BG",
            EuMemberState::HR => "HR",
            EuMemberState::CY => "CY",
            EuMemberState::CZ => "CZ",
            EuMemberState::DK => "DK",
            EuMemberState::EE => "EE",
            EuMemberState::FI => "FI",
            EuMemberState::FR => "FR",
            EuMemberState::DE => "DE",
            EuMemberState::GR => "GR",
            EuMemberState::HU => "HU",
            EuMemberState::IE => "IE",
            EuMemberState::IT => "IT",
            EuMemberState::LV => "LV",
            EuMemberState::LT => "LT",
            EuMemberState::LU => "LU",
            EuMemberState::MT => "MT",
            EuMemberState::NL => "NL",
            EuMemberState::PL => "PL",
            EuMemberState::PT => "PT",
            EuMemberState::RO => "RO",
            EuMemberState::SK => "SK",
            EuMemberState::SI => "SI",
            EuMemberState::ES => "ES",
            EuMemberState::SE => "SE",
        }
    }

    /// Parse from two-letter ISO code.
    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_uppercase().as_str() {
            "AT" => Some(EuMemberState::AT),
            "BE" => Some(EuMemberState::BE),
            "BG" => Some(EuMemberState::BG),
            "HR" => Some(EuMemberState::HR),
            "CY" => Some(EuMemberState::CY),
            "CZ" => Some(EuMemberState::CZ),
            "DK" => Some(EuMemberState::DK),
            "EE" => Some(EuMemberState::EE),
            "FI" => Some(EuMemberState::FI),
            "FR" => Some(EuMemberState::FR),
            "DE" => Some(EuMemberState::DE),
            "GR" => Some(EuMemberState::GR),
            "HU" => Some(EuMemberState::HU),
            "IE" => Some(EuMemberState::IE),
            "IT" => Some(EuMemberState::IT),
            "LV" => Some(EuMemberState::LV),
            "LT" => Some(EuMemberState::LT),
            "LU" => Some(EuMemberState::LU),
            "MT" => Some(EuMemberState::MT),
            "NL" => Some(EuMemberState::NL),
            "PL" => Some(EuMemberState::PL),
            "PT" => Some(EuMemberState::PT),
            "RO" => Some(EuMemberState::RO),
            "SK" => Some(EuMemberState::SK),
            "SI" => Some(EuMemberState::SI),
            "ES" => Some(EuMemberState::ES),
            "SE" => Some(EuMemberState::SE),
            _ => None,
        }
    }

    /// Get all member states.
    pub fn all() -> Vec<Self> {
        vec![
            EuMemberState::AT,
            EuMemberState::BE,
            EuMemberState::BG,
            EuMemberState::HR,
            EuMemberState::CY,
            EuMemberState::CZ,
            EuMemberState::DK,
            EuMemberState::EE,
            EuMemberState::FI,
            EuMemberState::FR,
            EuMemberState::DE,
            EuMemberState::GR,
            EuMemberState::HU,
            EuMemberState::IE,
            EuMemberState::IT,
            EuMemberState::LV,
            EuMemberState::LT,
            EuMemberState::LU,
            EuMemberState::MT,
            EuMemberState::NL,
            EuMemberState::PL,
            EuMemberState::PT,
            EuMemberState::RO,
            EuMemberState::SK,
            EuMemberState::SI,
            EuMemberState::ES,
            EuMemberState::SE,
        ]
    }
}

/// Trust Service Provider status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TspStatus {
    /// Granted - TSP is authorized
    Granted,
    /// Withdrawn - TSP authorization was withdrawn
    Withdrawn,
    /// Suspended - TSP is temporarily suspended
    Suspended,
    /// Unknown status
    Unknown,
}

/// Qualified Trust Service Provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustServiceProvider {
    /// TSP unique identifier.
    pub id: String,
    /// TSP name.
    pub name: String,
    /// Member state where TSP is registered.
    pub member_state: EuMemberState,
    /// TSP status.
    pub status: TspStatus,
    /// List of trust services offered.
    pub trust_services: Vec<TrustService>,
}

/// Trust Service offered by a QTSP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustService {
    /// Service name.
    pub name: String,
    /// Service type (e.g., "QCertESig", "QWAC", "QESValidation").
    pub service_type: String,
    /// Service status.
    pub status: String,
    /// Service digital identity (certificates).
    pub certificates: Vec<String>,
}

impl EudiRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create registry with initial capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: BasicTrustRegistry::with_capacity(capacity),
            lotl_version: None,
            qtsp_cache: HashMap::new(),
        }
    }

    /// Add a trust anchor for a specific member state.
    pub fn add_member_state_anchor(
        &mut self,
        member_state: EuMemberState,
        cert: Certificate,
        purpose: TrustPurpose,
    ) {
        let anchor = TrustAnchor {
            certificate: cert,
            purpose,
            jurisdiction: Some(member_state.code().to_string()),
        };

        self.inner.add_anchor(anchor).ok();
    }

    /// Get all trust anchors for a specific member state.
    pub fn get_member_state_anchors(&self, member_state: EuMemberState) -> Vec<&TrustAnchor> {
        self.inner.get_anchors_by_jurisdiction(member_state.code())
    }

    /// Get supported member states (those with registered anchors).
    pub fn supported_member_states(&self) -> Vec<&str> {
        let mut states: Vec<_> = self
            .inner
            .get_anchors()
            .iter()
            .filter_map(|anchor| anchor.jurisdiction.as_deref())
            .collect();
        states.sort_unstable();
        states.dedup();
        states
    }

    /// Set the LoTL version for delta sync.
    pub fn set_lotl_version(&mut self, version: String) {
        self.lotl_version = Some(version);
    }

    /// Get the current LoTL version.
    pub fn lotl_version(&self) -> Option<&str> {
        self.lotl_version.as_deref()
    }

    /// Add a QTSP to the cache.
    pub fn add_qtsp(&mut self, qtsp: TrustServiceProvider) {
        self.qtsp_cache.insert(qtsp.id.clone(), qtsp);
    }

    /// Get a QTSP by ID.
    pub fn get_qtsp(&self, id: &str) -> Option<&TrustServiceProvider> {
        self.qtsp_cache.get(id)
    }

    /// Get all QTSPs.
    pub fn get_all_qtsps(&self) -> Vec<&TrustServiceProvider> {
        self.qtsp_cache.values().collect()
    }

    /// Get QTSPs for a specific member state.
    pub fn get_qtsps_by_member_state(
        &self,
        member_state: EuMemberState,
    ) -> Vec<&TrustServiceProvider> {
        self.qtsp_cache
            .values()
            .filter(|qtsp| qtsp.member_state == member_state)
            .collect()
    }

    /// Clear all anchors and reset the registry.
    pub fn clear(&mut self) {
        self.inner = BasicTrustRegistry::default();
        self.qtsp_cache.clear();
        self.lotl_version = None;
    }
}

impl TrustRegistry for EudiRegistry {
    fn get_anchors(&self) -> &[TrustAnchor] {
        self.inner.get_anchors()
    }

    fn get_anchors_by_purpose(&self, purpose: TrustPurpose) -> Vec<&TrustAnchor> {
        self.inner.get_anchors_by_purpose(purpose)
    }

    fn get_anchors_by_jurisdiction(&self, jurisdiction: &str) -> Vec<&TrustAnchor> {
        self.inner.get_anchors_by_jurisdiction(jurisdiction)
    }

    fn find_issuer(&self, subject: &Certificate, purpose: TrustPurpose) -> Option<&TrustAnchor> {
        self.inner.find_issuer(subject, purpose)
    }

    fn add_anchor(&mut self, anchor: TrustAnchor) -> VerificationResult<()> {
        self.inner.add_anchor(anchor)
    }

    fn remove_anchor(&mut self, subject: &str) -> VerificationResult<bool> {
        self.inner.remove_anchor(subject)
    }

    fn refresh(&mut self) -> VerificationResult<usize> {
        self.inner.refresh()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::DecodePem;

    fn certificate(name: &str) -> Certificate {
        Certificate::from_pem(match name {
            "first" => include_str!("../../tests/fixtures/trust_lifecycle/first.pem"),
            "other" => include_str!("../../tests/fixtures/trust_lifecycle/other.pem"),
            _ => unreachable!(),
        })
        .unwrap()
    }

    #[test]
    fn removing_an_anchor_preserves_other_member_state_views() {
        let first = certificate("first");
        let other = certificate("other");
        let mut registry = EudiRegistry::new();
        registry.add_member_state_anchor(
            EuMemberState::DE,
            first.clone(),
            TrustPurpose::EudiIssuer,
        );
        registry.add_member_state_anchor(
            EuMemberState::FR,
            other.clone(),
            TrustPurpose::EudiIssuer,
        );
        assert!(registry
            .remove_anchor(&first.tbs_certificate.subject.to_string())
            .unwrap());
        assert!(registry
            .get_member_state_anchors(EuMemberState::DE)
            .is_empty());
        let french = registry.get_member_state_anchors(EuMemberState::FR);
        assert_eq!(french.len(), 1);
        assert_eq!(french[0].certificate, other);
        assert_eq!(registry.supported_member_states(), vec!["FR"]);
    }

    #[test]
    fn generic_additions_and_clear_share_the_same_member_state_view() {
        let mut registry = EudiRegistry::new();
        for purpose in [TrustPurpose::EudiIssuer, TrustPurpose::EudiQtsp] {
            registry
                .add_anchor(TrustAnchor {
                    certificate: certificate("first"),
                    purpose,
                    jurisdiction: Some("DE".into()),
                })
                .unwrap();
        }
        assert_eq!(
            registry.get_member_state_anchors(EuMemberState::DE).len(),
            2
        );
        assert_eq!(registry.supported_member_states(), vec!["DE"]);
        registry.clear();
        assert!(registry
            .get_member_state_anchors(EuMemberState::DE)
            .is_empty());
        assert!(registry.supported_member_states().is_empty());
    }

    #[test]
    fn test_member_state_codes() {
        assert_eq!(EuMemberState::DE.code(), "DE");
        assert_eq!(EuMemberState::FR.code(), "FR");
        assert_eq!(EuMemberState::from_code("DE"), Some(EuMemberState::DE));
        assert_eq!(EuMemberState::from_code("de"), Some(EuMemberState::DE));
        assert_eq!(EuMemberState::from_code("XX"), None);
    }

    #[test]
    fn test_all_member_states() {
        let states = EuMemberState::all();
        assert_eq!(states.len(), 27);
    }
}
