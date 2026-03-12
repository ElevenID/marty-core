//! OID4VCI Credential Issuer Metadata (§11.2).
//!
//! Generates the `.well-known/openid-credential-issuer` metadata document
//! per OID4VCI v1 §12.2.2, including format-aware
//! `credential_configurations_supported` for jwt_vc_json, dc+sd-jwt (OID4VCI 1.0), and
//! mso_mdoc.
//!
//! Replaces both:
//! - `generate_issuer_metadata()` in marty-rs/lib.rs  (Rust/PyO3)
//! - The inline metadata construction in main.py       (Python)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::{CredentialFormat, CredentialTypeConfig, SigningAlgorithm};

// ── Public types ─────────────────────────────────────────────────────

/// OID4VCI Credential Issuer Metadata (§11.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    pub credential_issuer: String,
    pub credential_endpoint: String,
    pub token_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_endpoint: Option<String>,
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayEntry>>,
}

/// A single credential configuration entry in the metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub cryptographic_binding_methods_supported: Vec<String>,
    pub credential_signing_alg_values_supported: Vec<String>,
    pub proof_types_supported: HashMap<String, ProofTypeMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<CredentialDefinitionMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<HashMap<String, ClaimMetadata>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<Vec<String>>,
    /// For ZK mDoc: supported zero-knowledge predicates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk_predicates: Option<Vec<ZkPredicateMetadata>>,
}

/// Metadata entry describing a supported ZK predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPredicateMetadata {
    /// The claim this predicate operates on (e.g., "birth_date").
    pub claim: String,
    /// The predicate name (e.g., "age_over_18").
    pub predicate: String,
    /// The ZK proof protocol (e.g., "longfellow-zk-ligero").
    pub proof_type: String,
}

/// Proof type supported (e.g., JWT proof).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// W3C VC credential definition (used for jwt_vc_json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDefinitionMeta {
    #[serde(rename = "type")]
    pub types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Option<HashMap<String, ClaimMetadata>>,
}

/// Claim metadata for advertised claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayEntry>>,
}

/// Human-readable display information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayEntry {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<LogoEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Logo metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoEntry {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

// ── Builder ──────────────────────────────────────────────────────────

/// Builder for generating OID4VCI issuer metadata.
///
/// # Example
/// ```rust,ignore
/// let metadata = MetadataBuilder::new("https://issuer.example.com", "Example Issuer")
///     .nonce_endpoint("/nonce")
///     .add_credential_type(&cred_config)
///     .build();
/// ```
pub struct MetadataBuilder {
    issuer_url: String,
    issuer_name: String,
    nonce_endpoint: Option<String>,
    deferred_credential_endpoint: Option<String>,
    notification_endpoint: Option<String>,
    authorization_endpoint: Option<String>,
    credential_types: Vec<CredentialTypeConfig>,
    binding_methods: Vec<String>,
    signing_algorithms: Vec<SigningAlgorithm>,
}

impl MetadataBuilder {
    pub fn new(issuer_url: impl Into<String>, issuer_name: impl Into<String>) -> Self {
        MetadataBuilder {
            issuer_url: issuer_url.into(),
            issuer_name: issuer_name.into(),
            nonce_endpoint: None,
            deferred_credential_endpoint: None,
            notification_endpoint: None,
            authorization_endpoint: None,
            credential_types: Vec::new(),
            binding_methods: vec!["did:key".into(), "did:jwk".into(), "jwk".into()],
            signing_algorithms: vec![SigningAlgorithm::ES256, SigningAlgorithm::EdDSA],
        }
    }

    pub fn nonce_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.nonce_endpoint = Some(endpoint.into());
        self
    }

    pub fn deferred_credential_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.deferred_credential_endpoint = Some(endpoint.into());
        self
    }

    pub fn notification_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.notification_endpoint = Some(endpoint.into());
        self
    }

    pub fn authorization_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.authorization_endpoint = Some(endpoint.into());
        self
    }

    pub fn binding_methods(mut self, methods: Vec<String>) -> Self {
        self.binding_methods = methods;
        self
    }

    pub fn signing_algorithms(mut self, algs: Vec<SigningAlgorithm>) -> Self {
        self.signing_algorithms = algs;
        self
    }

    pub fn add_credential_type(mut self, config: CredentialTypeConfig) -> Self {
        self.credential_types.push(config);
        self
    }

    pub fn add_credential_types(mut self, configs: Vec<CredentialTypeConfig>) -> Self {
        self.credential_types.extend(configs);
        self
    }

    /// Build the complete issuer metadata document.
    pub fn build(&self) -> IssuerMetadata {
        let issuer = &self.issuer_url;
        let alg_strs: Vec<String> = self
            .signing_algorithms
            .iter()
            .map(|a| a.as_str().to_string())
            .collect();

        let proof_types = {
            let mut map = HashMap::new();
            map.insert(
                "jwt".into(),
                ProofTypeMetadata {
                    proof_signing_alg_values_supported: alg_strs.clone(),
                },
            );
            map
        };

        let mut configurations = HashMap::new();

        for ctype in &self.credential_types {
            // Generate a configuration entry per supported format
            for format in &ctype.formats {
                let config_id = format_config_id(&ctype.id, format);

                let config = build_config_for_format(
                    format,
                    ctype,
                    &self.binding_methods,
                    &alg_strs,
                    &proof_types,
                );

                configurations.insert(config_id, config);
            }
        }

        // Ensure at least a default entry exists
        if configurations.is_empty() {
            configurations.insert(
                "default".into(),
                build_default_config(&self.binding_methods, &alg_strs, &proof_types),
            );
        }

        IssuerMetadata {
            credential_issuer: issuer.clone(),
            credential_endpoint: format!("{}/credential", issuer),
            token_endpoint: format!("{}/token", issuer),
            nonce_endpoint: self.nonce_endpoint.as_ref().map(|e| {
                if e.starts_with("http") { e.clone() } else { format!("{}{}", issuer, e) }
            }),
            deferred_credential_endpoint: self.deferred_credential_endpoint.as_ref().map(|e| {
                if e.starts_with("http") { e.clone() } else { format!("{}{}", issuer, e) }
            }),
            notification_endpoint: self.notification_endpoint.as_ref().map(|e| {
                if e.starts_with("http") { e.clone() } else { format!("{}{}", issuer, e) }
            }),
            authorization_endpoint: self.authorization_endpoint.as_ref().map(|e| {
                if e.starts_with("http") {
                    e.clone()
                } else {
                    format!("{}{}", issuer, e)
                }
            }),
            credential_configurations_supported: configurations,
            display: Some(vec![DisplayEntry {
                name: self.issuer_name.clone(),
                locale: Some("en-US".into()),
                logo: None,
                description: None,
                background_color: None,
                text_color: None,
            }]),
        }
    }
}

// ── Convenience function (backward-compat with existing Rust/PyO3 API) ──

/// Generate issuer metadata as a JSON string.
///
/// This is the direct replacement for `generate_issuer_metadata` in
/// `marty-rs/src/lib.rs`.
pub fn generate_issuer_metadata(
    issuer_url: &str,
    issuer_name: &str,
    credential_types: &[CredentialTypeConfig],
) -> crate::error::Oid4vciResult<String> {
    let builder = MetadataBuilder::new(issuer_url, issuer_name)
        .nonce_endpoint("/nonce")
        .add_credential_types(credential_types.to_vec());

    let metadata = builder.build();

    serde_json::to_string(&metadata)
        .map_err(|e| crate::error::Oid4vciError::SerializationError(e.to_string()))
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Generate a configuration ID from a type ID and format.
///
/// Examples:
///   - ("IdentityCredential", JwtVcJson) → "IdentityCredential"
///   - ("IdentityCredential", SdJwt)     → "IdentityCredential_sd_jwt"
///   - ("mDL", MsoMdoc)                  → "mDL_mso_mdoc"
fn format_config_id(type_id: &str, format: &CredentialFormat) -> String {
    match format {
        CredentialFormat::JwtVcJson => type_id.to_string(),
        CredentialFormat::SdJwt => format!("{}_sd_jwt", type_id),
        CredentialFormat::MsoMdoc => format!("{}_mso_mdoc", type_id),
        CredentialFormat::ZkMdoc => format!("{}_zk_mdoc", type_id),
    }
}

/// Build a CredentialConfiguration for a specific format.
fn build_config_for_format(
    format: &CredentialFormat,
    ctype: &CredentialTypeConfig,
    binding_methods: &[String],
    signing_algs: &[String],
    proof_types: &HashMap<String, ProofTypeMetadata>,
) -> CredentialConfiguration {
    let display_name = ctype
        .display
        .as_ref()
        .and_then(|d| d.first())
        .map(|d| d.name.as_str())
        .unwrap_or(&ctype.name)
        .to_string();

    match format {
        CredentialFormat::JwtVcJson => CredentialConfiguration {
            format: "jwt_vc_json".into(),
            scope: Some(ctype.id.clone()),
            cryptographic_binding_methods_supported: binding_methods.to_vec(),
            credential_signing_alg_values_supported: signing_algs.to_vec(),
            proof_types_supported: proof_types.clone(),
            credential_definition: Some(CredentialDefinitionMeta {
                types: vec!["VerifiableCredential".into(), display_name.clone()],
                credential_subject: None,
            }),
            doctype: None,
            claims: None,
            display: Some(vec![DisplayEntry {
                name: display_name,
                locale: Some("en-US".into()),
                logo: None,
                description: None,
                background_color: None,
                text_color: None,
            }]),
            vct: None,
            order: None,
            zk_predicates: None,
        },
        CredentialFormat::SdJwt => CredentialConfiguration {
            // OID4VCI 1.0 Final Appendix A: SD-JWT VC format identifier is "dc+sd-jwt"
            format: "dc+sd-jwt".into(),
            scope: Some(ctype.id.clone()),
            cryptographic_binding_methods_supported: binding_methods.to_vec(),
            credential_signing_alg_values_supported: signing_algs.to_vec(),
            proof_types_supported: proof_types.clone(),
            credential_definition: None,
            doctype: None,
            claims: build_claims_metadata(ctype),
            display: Some(vec![DisplayEntry {
                name: display_name.clone(),
                locale: Some("en-US".into()),
                logo: None,
                description: None,
                background_color: None,
                text_color: None,
            }]),
            vct: ctype.vct.clone().or_else(|| Some(ctype.id.clone())),
            order: Some(ctype.claims.keys().cloned().collect()),
            zk_predicates: None,
        },
        CredentialFormat::MsoMdoc => CredentialConfiguration {
            format: "mso_mdoc".into(),
            scope: Some(ctype.id.clone()),
            cryptographic_binding_methods_supported: binding_methods.to_vec(),
            credential_signing_alg_values_supported: {
                // mDoc only supports EC algorithms (COSE)
                signing_algs
                    .iter()
                    .filter(|a| *a != "RS256")
                    .cloned()
                    .collect()
            },
            proof_types_supported: proof_types.clone(),
            credential_definition: None,
            doctype: ctype.doctype.clone(),
            claims: build_mdoc_claims_metadata(ctype),
            display: Some(vec![DisplayEntry {
                name: display_name,
                locale: Some("en-US".into()),
                logo: None,
                description: None,
                background_color: None,
                text_color: None,
            }]),
            vct: None,
            order: None,
            zk_predicates: None,
        },

        CredentialFormat::ZkMdoc => {
            // ZK mDoc has the same shape as mso_mdoc but signals ZK capability.
            // Specific predicate types are not enumerated here — they are
            // negotiated at presentation time between the wallet and verifier
            // based on the Longfellow/Ligero protocol.
            CredentialConfiguration {
                format: "zk_mdoc".into(),
                scope: Some(ctype.id.clone()),
                cryptographic_binding_methods_supported: binding_methods.to_vec(),
                credential_signing_alg_values_supported: {
                    signing_algs
                        .iter()
                        .filter(|a| *a != "RS256")
                        .cloned()
                        .collect()
                },
                proof_types_supported: proof_types.clone(),
                credential_definition: None,
                doctype: ctype.doctype.clone(),
                claims: build_mdoc_claims_metadata(ctype),
                display: Some(vec![DisplayEntry {
                    name: display_name,
                    locale: Some("en-US".into()),
                    logo: None,
                    description: None,
                    background_color: None,
                    text_color: None,
                }]),
                vct: None,
                order: None,
                zk_predicates: None,
            }
        }
    }
}

/// Build a default credential configuration for fallback.
fn build_default_config(
    binding_methods: &[String],
    signing_algs: &[String],
    proof_types: &HashMap<String, ProofTypeMetadata>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: "jwt_vc_json".into(),
        scope: Some("default".into()),
        cryptographic_binding_methods_supported: binding_methods.to_vec(),
        credential_signing_alg_values_supported: signing_algs.to_vec(),
        proof_types_supported: proof_types.clone(),
        credential_definition: Some(CredentialDefinitionMeta {
            types: vec!["VerifiableCredential".into()],
            credential_subject: None,
        }),
        doctype: None,
        claims: None,
        display: Some(vec![DisplayEntry {
            name: "Verifiable Credential".into(),
            locale: Some("en-US".into()),
            logo: None,
            description: None,
            background_color: None,
            text_color: None,
        }]),
        vct: None,
        order: None,
        zk_predicates: None,
    }
}

/// Build claims metadata from a credential type config (for SD-JWT).
fn build_claims_metadata(ctype: &CredentialTypeConfig) -> Option<HashMap<String, ClaimMetadata>> {
    if ctype.claims.is_empty() {
        return None;
    }
    Some(
        ctype
            .claims
            .iter()
            .map(|(name, def)| {
                (
                    name.clone(),
                    ClaimMetadata {
                        mandatory: if def.mandatory { Some(true) } else { None },
                        value_type: def.value_type.clone().or_else(|| Some("string".into())),
                        display: Some(vec![DisplayEntry {
                            name: name.replace('_', " ").to_string(),
                            locale: Some("en-US".into()),
                            logo: None,
                            description: None,
                            background_color: None,
                            text_color: None,
                        }]),
                    },
                )
            })
            .collect(),
    )
}

/// Build claims metadata with namespace for mDoc.
fn build_mdoc_claims_metadata(
    ctype: &CredentialTypeConfig,
) -> Option<HashMap<String, ClaimMetadata>> {
    if ctype.claims.is_empty() {
        return None;
    }
    // For mDoc, top-level key is the namespace, containing element identifiers
    // Use doctype-derived namespace or default
    let namespace = ctype
        .doctype
        .as_deref()
        .and_then(|dt| dt.rfind('.').map(|i| &dt[..i]))
        .unwrap_or("org.iso.18013.5.1");

    let mut outer = HashMap::new();
    for (name, def) in &ctype.claims {
        outer.insert(
            format!("{}.{}", namespace, name),
            ClaimMetadata {
                mandatory: if def.mandatory { Some(true) } else { None },
                value_type: def.value_type.clone().or_else(|| Some("string".into())),
                display: Some(vec![DisplayEntry {
                    name: name.replace('_', " ").to_string(),
                    locale: Some("en-US".into()),
                    logo: None,
                    description: None,
                    background_color: None,
                    text_color: None,
                }]),
            },
        );
    }
    Some(outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_minimal() {
        let metadata = MetadataBuilder::new("https://issuer.example.com", "Test Issuer").build();

        assert_eq!(metadata.credential_issuer, "https://issuer.example.com");
        assert_eq!(
            metadata.credential_endpoint,
            "https://issuer.example.com/credential"
        );
        // Should have at least 1 default configuration
        assert!(!metadata.credential_configurations_supported.is_empty());
        assert!(metadata
            .credential_configurations_supported
            .contains_key("default"));
    }

    #[test]
    fn test_builder_multi_format() {
        use crate::types::ClaimDefinition;
        let ctype = CredentialTypeConfig {
            id: "IdentityCredential".into(),
            name: "Identity Credential".into(),
            formats: vec![
                CredentialFormat::JwtVcJson,
                CredentialFormat::SdJwt,
                CredentialFormat::MsoMdoc,
            ],
            vc_types: vec!["VerifiableCredential".into()],
            vct: None,
            doctype: Some("org.iso.18013.5.1.mDL".into()),
            claims: [
                ("name".into(), ClaimDefinition { mandatory: false, value_type: Some("string".into()), display: None }),
                ("email".into(), ClaimDefinition { mandatory: false, value_type: Some("string".into()), display: None }),
            ].into(),
            display: None,
        };

        let metadata = MetadataBuilder::new("https://issuer.example.com", "Test Issuer")
            .nonce_endpoint("/nonce")
            .add_credential_type(ctype)
            .build();

        let configs = &metadata.credential_configurations_supported;

        // Should have 3 entries
        assert_eq!(configs.len(), 3);
        assert!(configs.contains_key("IdentityCredential"));
        assert!(configs.contains_key("IdentityCredential_sd_jwt"));
        assert!(configs.contains_key("IdentityCredential_mso_mdoc"));

        // Check formats — OID4VCI 1.0 Final format identifiers
        assert_eq!(configs["IdentityCredential"].format, "jwt_vc_json");
        // OID4VCI 1.0 Final Appendix A: SD-JWT VC format identifier MUST be "dc+sd-jwt"
        assert_eq!(configs["IdentityCredential_sd_jwt"].format, "dc+sd-jwt");
        assert_eq!(configs["IdentityCredential_mso_mdoc"].format, "mso_mdoc");

        // SD-JWT should have vct
        assert_eq!(
            configs["IdentityCredential_sd_jwt"].vct,
            Some("IdentityCredential".into())
        );

        // mDoc should have doctype
        assert_eq!(
            configs["IdentityCredential_mso_mdoc"].doctype,
            Some("org.iso.18013.5.1.mDL".into())
        );
    }

    #[test]
    fn test_metadata_json_serialization() {
        let ctype = CredentialTypeConfig {
            id: "TestCred".into(),
            name: "TestCred".into(),
            formats: vec![CredentialFormat::JwtVcJson],
            vc_types: vec![],
            vct: None,
            doctype: None,
            claims: HashMap::new(),
            display: None,
        };

        let metadata = MetadataBuilder::new("https://issuer.example.com", "Issuer")
            .add_credential_type(ctype)
            .build();

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        assert!(json.contains("credential_issuer"));
        assert!(json.contains("credential_configurations_supported"));
        assert!(json.contains("jwt_vc_json"));
    }

    #[test]
    fn test_generate_issuer_metadata_compat() {
        let types = vec![CredentialTypeConfig {
            id: "EmployeeBadge".into(),
            name: "Employee Badge".into(),
            formats: vec![CredentialFormat::JwtVcJson],
            vc_types: vec![],
            vct: None,
            doctype: None,
            claims: HashMap::new(),
            display: None,
        }];

        let json_str = generate_issuer_metadata(
            "https://issuer.example.com",
            "Acme Corp",
            &types,
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["credential_issuer"], "https://issuer.example.com");
        assert!(parsed["credential_configurations_supported"]["EmployeeBadge"].is_object());
    }

    /// OID4VCI 1.0 Final Appendix A conformance: SD-JWT VC format MUST use "dc+sd-jwt",
    /// not the draft identifier "vc+sd-jwt" or the SpruceID alias "spruce-vc+sd-jwt".
    #[test]
    fn test_sd_jwt_format_id_is_final_spec() {
        use crate::types::ClaimDefinition;
        let ctype = CredentialTypeConfig {
            id: "ConformanceCred".into(),
            name: "Conformance Credential".into(),
            formats: vec![CredentialFormat::SdJwt],
            vc_types: vec![],
            vct: Some("https://example.com/credentials/conformance".into()),
            doctype: None,
            claims: [
                ("name".into(), ClaimDefinition { mandatory: true, value_type: Some("string".into()), display: None }),
            ].into(),
            display: None,
        };

        let metadata = MetadataBuilder::new("https://issuer.example.com", "Test Issuer")
            .add_credential_type(ctype)
            .build();

        let sd_jwt_config = &metadata.credential_configurations_supported["ConformanceCred_sd_jwt"];

        // MUST be "dc+sd-jwt" per OID4VCI 1.0 Final
        assert_eq!(
            sd_jwt_config.format, "dc+sd-jwt",
            "SD-JWT VC format identifier MUST be 'dc+sd-jwt' per OID4VCI 1.0 Final Appendix A"
        );
        // MUST NOT be the old draft identifier
        assert_ne!(sd_jwt_config.format, "vc+sd-jwt", "Draft identifier 'vc+sd-jwt' is not allowed in Final");
        assert_ne!(sd_jwt_config.format, "spruce-vc+sd-jwt", "SpruceID alias must not appear in conformant metadata");

        // vct MUST be preserved
        assert_eq!(
            sd_jwt_config.vct.as_deref(),
            Some("https://example.com/credentials/conformance")
        );

        // proof_types_supported MUST include jwt
        assert!(sd_jwt_config.proof_types_supported.contains_key("jwt"));
    }

    #[test]
    fn test_deferred_credential_endpoint_in_metadata() {
        // OID4VCI-1FINAL §9: deferred_credential_endpoint MUST appear in metadata when set.
        let meta = MetadataBuilder::new("https://issuer.example.com", "Test Issuer")
            .deferred_credential_endpoint("/v1/issuance/deferred-credential")
            .build();

        let deferred = meta.deferred_credential_endpoint.as_deref().expect(
            "deferred_credential_endpoint MUST be present when configured",
        );
        assert_eq!(
            deferred,
            "https://issuer.example.com/v1/issuance/deferred-credential"
        );

        // Confirm serialization includes the field
        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            json.contains("deferred_credential_endpoint"),
            "JSON metadata MUST contain deferred_credential_endpoint"
        );
    }

    #[test]
    fn test_notification_endpoint_in_metadata() {
        // OID4VCI-1FINAL §11: notification_endpoint MUST appear in metadata when set.
        let meta = MetadataBuilder::new("https://issuer.example.com", "Test Issuer")
            .notification_endpoint("/v1/issuance/notification")
            .build();

        let notif = meta.notification_endpoint.as_deref().expect(
            "notification_endpoint MUST be present when configured",
        );
        assert_eq!(notif, "https://issuer.example.com/v1/issuance/notification");

        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            json.contains("notification_endpoint"),
            "JSON metadata MUST contain notification_endpoint"
        );
    }

    #[test]
    fn test_deferred_and_notification_absent_by_default() {
        // When not configured, fields MUST be omitted (skip_serializing_if = None).
        let meta = MetadataBuilder::new("https://issuer.example.com", "Test Issuer").build();

        assert!(meta.deferred_credential_endpoint.is_none());
        assert!(meta.notification_endpoint.is_none());

        let json = serde_json::to_string(&meta).unwrap();
        assert!(
            !json.contains("deferred_credential_endpoint"),
            "deferred_credential_endpoint MUST be omitted when not set"
        );
        assert!(
            !json.contains("notification_endpoint"),
            "notification_endpoint MUST be omitted when not set"
        );
    }

    #[test]
    fn test_deferred_absolute_url_not_prefixed() {
        // When an absolute URL is provided it MUST be used as-is.
        let meta = MetadataBuilder::new("https://issuer.example.com", "Test Issuer")
            .deferred_credential_endpoint("https://other.example.com/deferred")
            .notification_endpoint("https://other.example.com/notification")
            .build();

        assert_eq!(
            meta.deferred_credential_endpoint.as_deref(),
            Some("https://other.example.com/deferred")
        );
        assert_eq!(
            meta.notification_endpoint.as_deref(),
            Some("https://other.example.com/notification")
        );
    }
}
