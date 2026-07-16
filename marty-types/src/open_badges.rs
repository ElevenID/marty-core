use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_badge_key_source_display() {
        assert_eq!(OpenBadgeKeySource::Sync.to_string(), "sync");
        assert_eq!(OpenBadgeKeySource::UsbImport.to_string(), "usb_import");
        assert_eq!(OpenBadgeKeySource::Manual.to_string(), "manual");
    }

    #[test]
    fn test_open_badge_key_source_equality() {
        assert_eq!(OpenBadgeKeySource::Sync, OpenBadgeKeySource::Sync);
        assert_ne!(OpenBadgeKeySource::Sync, OpenBadgeKeySource::Manual);
    }

    #[test]
    fn test_open_badge_key_source_serialization() {
        let json = serde_json::to_string(&OpenBadgeKeySource::UsbImport).unwrap();
        assert_eq!(json, "\"usb_import\"");
        let back: OpenBadgeKeySource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, OpenBadgeKeySource::UsbImport);
    }

    #[test]
    fn test_verification_method_serialization_roundtrip() {
        let method = OpenBadgeVerificationMethod {
            id: "key-1".to_string(),
            document: serde_json::json!({"type": "Ed25519VerificationKey2020"}),
            controller: Some("did:example:issuer".to_string()),
            issuer: Some("Example University".to_string()),
            kid: Some("key-1".to_string()),
            not_before: None,
            not_after: None,
            status: Some("active".to_string()),
            source: OpenBadgeKeySource::Sync,
            synced_at: Utc::now(),
        };

        let json = serde_json::to_string(&method).unwrap();
        let deserialized: OpenBadgeVerificationMethod = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "key-1");
        assert_eq!(
            deserialized.controller,
            Some("did:example:issuer".to_string())
        );
        assert_eq!(deserialized.source, OpenBadgeKeySource::Sync);
    }

    #[test]
    fn test_verification_method_optional_fields() {
        let method = OpenBadgeVerificationMethod {
            id: "minimal".to_string(),
            document: serde_json::Value::Null,
            controller: None,
            issuer: None,
            kid: None,
            not_before: None,
            not_after: None,
            status: None,
            source: OpenBadgeKeySource::Manual,
            synced_at: Utc::now(),
        };

        let json = serde_json::to_string(&method).unwrap();
        let back: OpenBadgeVerificationMethod = serde_json::from_str(&json).unwrap();
        assert!(back.controller.is_none());
        assert!(back.kid.is_none());
        assert!(back.status.is_none());
    }
}
