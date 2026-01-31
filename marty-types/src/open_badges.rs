use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

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
