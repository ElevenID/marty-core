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

/// Open Badge verification method record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenBadgeVerificationMethod {
    pub id: String,
    pub document: serde_json::Value,
    pub controller: Option<String>,
    pub issuer: Option<String>,
    pub kid: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub status: Option<String>,
    pub source: OpenBadgeKeySource,
    pub synced_at: DateTime<Utc>,
}

/// Open Badge key source
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenBadgeKeySource {
    Sync,
    UsbImport,
    Manual,
}

impl std::fmt::Display for OpenBadgeKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenBadgeKeySource::Sync => write!(f, "sync"),
            OpenBadgeKeySource::UsbImport => write!(f, "usb_import"),
            OpenBadgeKeySource::Manual => write!(f, "manual"),
        }
    }
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
