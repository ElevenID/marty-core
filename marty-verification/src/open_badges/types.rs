use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type DocumentStore = BTreeMap<String, Value>;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpenBadgesVersion {
    V2,
    V3,
    Unknown,
}

impl OpenBadgesVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V2 => "2.0",
            Self::V3 => "3.0",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct OpenBadgesVerificationResult {
    pub valid: bool,
    pub version: String,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub error_codes: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct OpenBadgesIssueResult {
    pub issued: bool,
    pub version: String,
    pub credential: Value,
    pub warnings: Vec<String>,
}
