use chrono::{DateTime, Utc};
use iref::IriBuf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub type DocumentStore = BTreeMap<String, Value>;

const MAX_PROVENANCE_VALUE_LEN: usize = 256;
const MAX_STATUS_AUTHORITY_DOCUMENTS: usize = 64;

/// Immutable identity for an authenticated configuration or software artifact.
///
/// This type is intentionally not deserializable from an Open Badge verification
/// request. The trusted orchestrator must construct it from governed local state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactProvenance {
    id: String,
    version: String,
    digest: String,
}

impl ArtifactProvenance {
    pub fn new(
        id: impl Into<String>,
        version: impl Into<String>,
        digest: impl Into<String>,
    ) -> Result<Self, String> {
        let provenance = Self {
            id: id.into(),
            version: version.into(),
            digest: digest.into(),
        };
        validate_provenance_value("artifact id", &provenance.id)?;
        validate_provenance_value("artifact version", &provenance.version)?;
        validate_digest(&provenance.digest)?;
        Ok(provenance)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Provenance for the trust profile, resolver, and verifier that authenticated a
/// status-list issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StatusAuthorityProvenance {
    trust_profile: ArtifactProvenance,
    resolver: ArtifactProvenance,
    software: ArtifactProvenance,
}

impl StatusAuthorityProvenance {
    pub fn new(
        trust_profile: ArtifactProvenance,
        resolver: ArtifactProvenance,
        software: ArtifactProvenance,
    ) -> Self {
        Self {
            trust_profile,
            resolver,
            software,
        }
    }

    pub fn trust_profile(&self) -> &ArtifactProvenance {
        &self.trust_profile
    }

    pub fn resolver(&self) -> &ArtifactProvenance {
        &self.resolver
    }

    pub fn software(&self) -> &ArtifactProvenance {
        &self.software
    }
}

/// A stapled or cached status-list credential admitted by a trusted orchestrator.
///
/// The credential and resolver-owned authority documents remain subject to proof,
/// issuer, URL, data-model, validity, freshness, and bitstring validation inside
/// `marty-verification`. Caller-provided request documents are not used to resolve
/// the status-list proof.
#[derive(Debug, Clone)]
pub struct AuthenticatedStatusList {
    url: String,
    credential: Value,
    trusted_issuer: String,
    authority_documents: DocumentStore,
    retrieved_at: DateTime<Utc>,
    fresh_until: DateTime<Utc>,
    provenance: StatusAuthorityProvenance,
}

impl AuthenticatedStatusList {
    pub fn new(
        url: impl Into<String>,
        credential: Value,
        trusted_issuer: impl Into<String>,
        authority_documents: DocumentStore,
        retrieved_at: DateTime<Utc>,
        fresh_until: DateTime<Utc>,
        provenance: StatusAuthorityProvenance,
    ) -> Result<Self, String> {
        let status_list = Self {
            url: url.into(),
            credential,
            trusted_issuer: trusted_issuer.into(),
            authority_documents,
            retrieved_at,
            fresh_until,
            provenance,
        };
        IriBuf::new(status_list.url.clone())
            .map_err(|_| "status-list URL must be an absolute IRI".to_string())?;
        IriBuf::new(status_list.trusted_issuer.clone())
            .map_err(|_| "trusted status issuer must be an absolute IRI".to_string())?;
        if !status_list.credential.is_object() {
            return Err("status-list credential must be a JSON object".to_string());
        }
        if status_list.authority_documents.is_empty()
            || status_list.authority_documents.len() > MAX_STATUS_AUTHORITY_DOCUMENTS
        {
            return Err(
                "status authority must contain between 1 and 64 resolver-owned documents"
                    .to_string(),
            );
        }
        if status_list.fresh_until <= status_list.retrieved_at {
            return Err("status-list fresh_until must be later than retrieved_at".to_string());
        }
        Ok(status_list)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn credential(&self) -> &Value {
        &self.credential
    }

    pub fn trusted_issuer(&self) -> &str {
        &self.trusted_issuer
    }

    pub fn authority_documents(&self) -> &DocumentStore {
        &self.authority_documents
    }

    pub fn retrieved_at(&self) -> DateTime<Utc> {
        self.retrieved_at
    }

    pub fn fresh_until(&self) -> DateTime<Utc> {
        self.fresh_until
    }

    pub fn provenance(&self) -> &StatusAuthorityProvenance {
        &self.provenance
    }
}

fn validate_provenance_value(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > MAX_PROVENANCE_VALUE_LEN
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{name} must be a bounded, non-empty value without surrounding whitespace"
        ));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), String> {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return Err("artifact digest must include an algorithm prefix".to_string());
    };
    if !matches!(algorithm, "sha256" | "blake3")
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "artifact digest must be sha256:<64 lowercase hex> or blake3:<64 lowercase hex>"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod status_authority_tests {
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    fn provenance() -> StatusAuthorityProvenance {
        let artifact = |id: &str, byte: char| {
            ArtifactProvenance::new(id, "1", format!("sha256:{}", byte.to_string().repeat(64)))
                .expect("valid provenance")
        };
        StatusAuthorityProvenance::new(
            artifact("trust-profile", 'a'),
            artifact("resolver", 'b'),
            artifact("software", 'c'),
        )
    }

    #[test]
    fn authenticated_status_input_requires_resolver_owned_authority_documents() {
        let now = Utc::now();
        let result = AuthenticatedStatusList::new(
            "https://status.example/list",
            json!({}),
            "did:example:status-issuer",
            DocumentStore::new(),
            now,
            now + Duration::minutes(1),
            provenance(),
        );
        assert_eq!(
            result.expect_err("empty authority documents must be rejected"),
            "status authority must contain between 1 and 64 resolver-owned documents"
        );
    }

    #[test]
    fn provenance_digest_is_canonical_and_bounded() {
        assert!(
            ArtifactProvenance::new("profile", "1", format!("sha256:{}", "a".repeat(64))).is_ok()
        );
        assert!(
            ArtifactProvenance::new("profile", "1", format!("sha256:{}", "A".repeat(64))).is_err()
        );
        assert!(ArtifactProvenance::new("profile", "1", "sha256:abc").is_err());
    }
}

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
