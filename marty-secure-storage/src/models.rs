//! Data models for storage

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Verification event record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvent {
    pub id: String,
    pub credential_type: String,
    pub status: String,
    pub issuer_jurisdiction: Option<String>,
    pub trust_chain_type: Option<String>,
    pub offline_verified: bool,
    pub verified_at: DateTime<Utc>,
    pub synced: bool,
    pub synced_at: Option<DateTime<Utc>>,
}

/// Trust anchor record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchor {
    pub id: String,
    pub anchor_type: TrustAnchorType,
    pub jurisdiction: String,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub serial_number: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub certificate_der: Vec<u8>,
    pub certificate_hash: String,
    pub source: TrustAnchorSource,
    pub synced_at: DateTime<Utc>,
}

pub use marty_types::open_badges::{OpenBadgeKeySource, OpenBadgeVerificationMethod};

/// Authenticated provenance for a complete mixed trust package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPackageProvenance {
    /// Stable trust domain whose active anchor and key sets this package replaces.
    pub trust_domain: String,
    /// Strictly increasing sequence signed into the package.
    pub sequence: u64,
    /// Human-readable signed package version.
    pub package_version: String,
    /// Signed package creation time.
    pub created_at: DateTime<Utc>,
    /// Signed package expiry after which derived trust records fail closed.
    pub expires_at: DateTime<Utc>,
    /// Identifier of the pinned key that authenticated the package.
    pub signer_key_id: String,
    /// Lowercase hexadecimal BLAKE3 digest of the canonical signed package.
    pub package_digest: String,
    /// Local time at which the authenticated package was committed.
    pub imported_at: DateTime<Utc>,
}

/// Backward-compatible name for callers that only consume Open Badge records.
pub type OpenBadgeTrustPackageProvenance = TrustPackageProvenance;

/// Trust anchor plus optional authenticated package provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnchorRecord {
    pub anchor: TrustAnchor,
    pub provenance: Option<TrustPackageProvenance>,
}

/// Open Badge method plus optional authenticated package provenance.
///
/// Legacy and manual records intentionally have `provenance: None` so
/// production callers can distinguish them from governed package records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBadgeTrustRecord {
    pub method: OpenBadgeVerificationMethod,
    pub provenance: Option<TrustPackageProvenance>,
}

/// Counts committed by one atomic mixed trust-package transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustPackageApplyResult {
    pub trust_anchors: usize,
    pub open_badge_methods: usize,
}

/// Trust anchor type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustAnchorType {
    Iaca,
    Csca,
    Dsc,
}

impl std::fmt::Display for TrustAnchorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustAnchorType::Iaca => write!(f, "iaca"),
            TrustAnchorType::Csca => write!(f, "csca"),
            TrustAnchorType::Dsc => write!(f, "dsc"),
        }
    }
}

/// Trust anchor source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchorSource {
    AamvaDts,
    IcaoPkd,
    UsbImport,
    Manual,
}

impl std::fmt::Display for TrustAnchorSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustAnchorSource::AamvaDts => write!(f, "aamva_dts"),
            TrustAnchorSource::IcaoPkd => write!(f, "icao_pkd"),
            TrustAnchorSource::UsbImport => write!(f, "usb_import"),
            TrustAnchorSource::Manual => write!(f, "manual"),
        }
    }
}

/// Offline queue entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineQueueEntry {
    pub id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub retry_count: i32,
    pub last_retry_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub event_type: String,
    pub actor: Option<String>,
    pub target: Option<String>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// License state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseState {
    pub license_jwt: Option<String>,
    pub validated_at: Option<DateTime<Utc>>,
    pub hardware_fingerprint: Option<String>,
    pub verifications_today: i32,
    pub verifications_date: Option<String>,
    pub verifications_total: i64,
    pub grace_period_started: Option<DateTime<Utc>>,
}

/// Sync state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncState {
    pub last_iaca_sync: Option<DateTime<Utc>>,
    pub last_csca_sync: Option<DateTime<Utc>>,
    pub last_crl_sync: Option<DateTime<Utc>>,
    pub iaca_version: Option<String>,
    pub csca_version: Option<String>,
    pub sync_in_progress: bool,
    pub last_error: Option<String>,
}
