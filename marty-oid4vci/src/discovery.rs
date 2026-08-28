//! Typed OID4VCI and OAuth discovery documents.
//!
//! These types model the current OID4VCI Final wire contract, including
//! authorization-server indirection, Final credential metadata, wallet key
//! attestation requirements, and both JOSE and COSE algorithm identifiers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const VCDM_V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";

/// A human-readable discovery entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayEntry {
    pub name: String,
    pub locale: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<LogoEntry>,
}

impl DisplayEntry {
    #[must_use]
    pub fn english(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            locale: "en-US".to_owned(),
            description: None,
            background_color: None,
            text_color: None,
            logo: None,
        }
    }
}

/// A logo attached to a display entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogoEntry {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

/// A JOSE name or COSE integer algorithm identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AlgorithmIdentifier {
    Jose(String),
    Cose(i64),
}

impl From<&str> for AlgorithmIdentifier {
    fn from(value: &str) -> Self {
        Self::Jose(value.to_owned())
    }
}

impl From<i64> for AlgorithmIdentifier {
    fn from(value: i64) -> Self {
        Self::Cose(value)
    }
}

/// Wallet-key constraints advertised for an OID4VCI JWT proof.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyAttestationRequirements {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_storage: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_authentication: Vec<String>,
}

/// Metadata for one supported proof type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    pub proof_signing_alg_values_supported: Vec<String>,
    pub key_attestations_required: KeyAttestationRequirements,
}

/// A Final-spec credential claim descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimDescriptor {
    pub path: Vec<String>,
    pub display: Vec<DisplayEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
}

/// A VCDM credential definition advertised by OID4VCI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialDefinition {
    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,
    #[serde(rename = "type")]
    pub types: Vec<String>,
}

/// Final-spec display and claim metadata for a credential configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialMetadata {
    pub display: Vec<DisplayEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimDescriptor>>,
}

/// A format-specific OID4VCI credential configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    pub format: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    pub cryptographic_binding_methods_supported: Vec<String>,
    pub credential_signing_alg_values_supported: Vec<AlgorithmIdentifier>,
    pub proof_types_supported: BTreeMap<String, ProofTypeMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<CredentialDefinition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_metadata: Option<CredentialMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Vec<ClaimDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayEntry>>,
}

/// OID4VCI Credential Issuer Metadata (Final, section 11.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    pub credential_issuer: String,
    pub authorization_servers: Vec<String>,
    pub display: Vec<DisplayEntry>,
    pub credential_endpoint: String,
    pub nonce_endpoint: String,
    pub deferred_credential_endpoint: String,
    pub notification_endpoint: String,
    pub credential_configurations_supported: BTreeMap<String, CredentialConfiguration>,
}

/// OAuth 2.0 Authorization Server Metadata used by an OID4VCI issuer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub pushed_authorization_request_endpoint: String,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,
    pub grant_types_supported: Vec<String>,
    pub response_types_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(rename = "pre-authorized_grant_anonymous_access_supported")]
    pub pre_authorized_grant_anonymous_access_supported: bool,
}

/// SD-JWT VC type metadata published at the configuration's `vct` URI.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialTypeMetadata {
    pub vct: String,
    pub name: String,
    pub display: Vec<DisplayEntry>,
}

/// Organization-scoped issuer variants supported by wallet-specific metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum IssuerVariant {
    #[default]
    Default,
    CredentialManager,
    AppleWallet,
}

impl IssuerVariant {
    fn path_suffix(self) -> &'static str {
        match self {
            Self::Default => "",
            Self::CredentialManager => "/credential-manager",
            Self::AppleWallet => "/apple-wallet",
        }
    }
}

/// DRY builder for discovery documents whose content does not require tenant data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticDiscoveryDocuments {
    issuer_base_url: String,
    issuer_display_name: String,
}

impl StaticDiscoveryDocuments {
    #[must_use]
    pub fn new(issuer_base_url: impl Into<String>, issuer_display_name: impl Into<String>) -> Self {
        Self {
            issuer_base_url: issuer_base_url.into(),
            issuer_display_name: issuer_display_name.into(),
        }
    }

    /// Build the unscoped OID4VCI issuer document and all selectable formats.
    #[must_use]
    pub fn root_issuer_metadata(&self) -> CredentialIssuerMetadata {
        let base = &self.issuer_base_url;
        let proof_types = default_proof_types();
        let binding_methods = default_binding_methods();
        let jose_algorithms = default_jose_algorithms();
        let mut configurations = BTreeMap::new();

        configurations.insert(
            "default".to_owned(),
            CredentialConfiguration {
                format: "jwt_vc_json".to_owned(),
                scope: "default".to_owned(),
                vct: None,
                doctype: None,
                cryptographic_binding_methods_supported: binding_methods.clone(),
                credential_signing_alg_values_supported: jose_algorithms.clone(),
                proof_types_supported: proof_types.clone(),
                credential_definition: Some(CredentialDefinition {
                    context: None,
                    types: vec!["VerifiableCredential".to_owned()],
                }),
                credential_metadata: Some(display_metadata("Verifiable Credential")),
                claims: None,
                display: None,
            },
        );
        configurations.insert(
            "default#credential-manager".to_owned(),
            CredentialConfiguration {
                format: "dc+sd-jwt".to_owned(),
                scope: "default".to_owned(),
                vct: Some(format!("{base}/credentials/default")),
                doctype: None,
                cryptographic_binding_methods_supported: binding_methods.clone(),
                credential_signing_alg_values_supported: jose_algorithms,
                proof_types_supported: proof_types.clone(),
                credential_definition: None,
                credential_metadata: Some(display_metadata("Verifiable Credential (SD-JWT)")),
                claims: None,
                display: None,
            },
        );
        configurations.insert(
            "default#ldp-vc".to_owned(),
            CredentialConfiguration {
                format: "ldp_vc".to_owned(),
                scope: "default".to_owned(),
                vct: None,
                doctype: None,
                cryptographic_binding_methods_supported: binding_methods.clone(),
                credential_signing_alg_values_supported: vec!["eddsa-rdfc-2022".into()],
                proof_types_supported: proof_types.clone(),
                credential_definition: Some(CredentialDefinition {
                    context: Some(vec![VCDM_V2_CONTEXT.to_owned()]),
                    types: vec!["VerifiableCredential".to_owned()],
                }),
                credential_metadata: Some(display_metadata(
                    "Verifiable Credential (Data Integrity)",
                )),
                claims: None,
                display: None,
            },
        );
        configurations.insert(
            "default#mdoc".to_owned(),
            CredentialConfiguration {
                format: "mso_mdoc".to_owned(),
                scope: "default".to_owned(),
                vct: None,
                doctype: Some("org.iso.18013.5.1.mDL".to_owned()),
                cryptographic_binding_methods_supported: binding_methods,
                credential_signing_alg_values_supported: vec![(-7).into(), (-8).into()],
                proof_types_supported: proof_types,
                credential_definition: None,
                credential_metadata: Some(display_metadata("Mobile Document (mDL)")),
                claims: None,
                display: None,
            },
        );

        CredentialIssuerMetadata {
            credential_issuer: base.clone(),
            authorization_servers: vec![base.clone()],
            display: vec![DisplayEntry::english(&self.issuer_display_name)],
            credential_endpoint: format!("{base}/v1/issuance/credential"),
            nonce_endpoint: format!("{base}/v1/issuance/nonce"),
            deferred_credential_endpoint: format!("{base}/v1/issuance/deferred-credential"),
            notification_endpoint: format!("{base}/v1/issuance/notification"),
            credential_configurations_supported: configurations,
        }
    }

    /// Build unscoped RFC 8414 metadata.
    #[must_use]
    pub fn root_authorization_server_metadata(&self) -> AuthorizationServerMetadata {
        self.authorization_server_metadata(None, IssuerVariant::Default)
    }

    /// Build organization-scoped RFC 8414 metadata for a wallet variant.
    #[must_use]
    pub fn organization_authorization_server_metadata(
        &self,
        organization_id: &str,
        variant: IssuerVariant,
    ) -> AuthorizationServerMetadata {
        self.authorization_server_metadata(Some(organization_id), variant)
    }

    /// Build metadata served by the stable SD-JWT `vct` URI.
    #[must_use]
    pub fn credential_type_metadata(&self, credential_type: &str) -> CredentialTypeMetadata {
        let normalized = credential_type.trim_matches('/');
        let display_name = python_style_title(normalized);
        CredentialTypeMetadata {
            vct: format!("{}/credentials/{normalized}", self.issuer_base_url),
            name: display_name.clone(),
            display: vec![DisplayEntry::english(display_name)],
        }
    }

    fn authorization_server_metadata(
        &self,
        organization_id: Option<&str>,
        variant: IssuerVariant,
    ) -> AuthorizationServerMetadata {
        let base = &self.issuer_base_url;
        let scope = organization_id
            .map(|organization_id| format!("/org/{organization_id}{}", variant.path_suffix()));
        let query = organization_id
            .map(|organization_id| format!("?issuer_org={organization_id}"))
            .unwrap_or_default();
        let tenant_scoped = organization_id.is_some();

        AuthorizationServerMetadata {
            issuer: scope
                .as_ref()
                .map_or_else(|| base.clone(), |scope| format!("{base}{scope}")),
            authorization_endpoint: format!("{base}/v1/issuance/authorize{query}"),
            token_endpoint: format!("{base}/v1/issuance/token"),
            pushed_authorization_request_endpoint: format!("{base}/v1/issuance/par{query}"),
            token_endpoint_auth_methods_supported: if tenant_scoped {
                vec!["none".to_owned(), "private_key_jwt".to_owned()]
            } else {
                vec!["none".to_owned()]
            },
            token_endpoint_auth_signing_alg_values_supported: tenant_scoped
                .then(|| vec!["ES256".to_owned()]),
            grant_types_supported: vec![
                PRE_AUTHORIZED_CODE_GRANT.to_owned(),
                "authorization_code".to_owned(),
            ],
            response_types_supported: vec!["code".to_owned()],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            pre_authorized_grant_anonymous_access_supported: true,
        }
    }
}

fn default_proof_types() -> BTreeMap<String, ProofTypeMetadata> {
    BTreeMap::from([(
        "jwt".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_owned(), "EdDSA".to_owned()],
            key_attestations_required: KeyAttestationRequirements::default(),
        },
    )])
}

fn default_binding_methods() -> Vec<String> {
    vec!["did:key".to_owned(), "jwk".to_owned()]
}

fn default_jose_algorithms() -> Vec<AlgorithmIdentifier> {
    vec!["ES256".into(), "EdDSA".into()]
}

fn display_metadata(name: &str) -> CredentialMetadata {
    CredentialMetadata {
        display: vec![DisplayEntry::english(name)],
        claims: None,
    }
}

fn python_style_title(value: &str) -> String {
    let mut title = String::with_capacity(value.len());
    let mut start_of_word = true;
    for character in value.replace(['_', '-'], " ").chars() {
        if character.is_alphabetic() {
            if start_of_word {
                title.extend(character.to_uppercase());
            } else {
                title.extend(character.to_lowercase());
            }
            start_of_word = false;
        } else {
            title.push(character);
            start_of_word = true;
        }
    }
    title
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{IssuerVariant, StaticDiscoveryDocuments};

    fn documents() -> StaticDiscoveryDocuments {
        StaticDiscoveryDocuments::new("https://issuer.example", "Example Issuer")
    }

    #[test]
    fn root_issuer_metadata_preserves_final_spec_shape_and_all_formats() {
        let value = serde_json::to_value(documents().root_issuer_metadata()).expect("serialize");
        assert_eq!(value["credential_issuer"], "https://issuer.example");
        assert_eq!(
            value["authorization_servers"],
            json!(["https://issuer.example"])
        );
        assert_eq!(value["display"][0]["name"], "Example Issuer");
        let configurations = &value["credential_configurations_supported"];
        assert_eq!(configurations["default"]["format"], "jwt_vc_json");
        assert_eq!(
            configurations["default#credential-manager"]["format"],
            "dc+sd-jwt"
        );
        assert_eq!(configurations["default#ldp-vc"]["format"], "ldp_vc");
        assert_eq!(
            configurations["default#mdoc"]["credential_signing_alg_values_supported"],
            json!([-7, -8])
        );
        for identifier in [
            "default",
            "default#credential-manager",
            "default#ldp-vc",
            "default#mdoc",
        ] {
            assert_eq!(
                configurations[identifier]["proof_types_supported"]["jwt"]
                    ["key_attestations_required"],
                json!({})
            );
        }
    }

    #[test]
    fn authorization_server_metadata_scopes_private_key_jwt_to_tenants() {
        let root = documents().root_authorization_server_metadata();
        assert_eq!(root.issuer, "https://issuer.example");
        assert_eq!(root.token_endpoint_auth_methods_supported, ["none"]);
        assert!(root
            .token_endpoint_auth_signing_alg_values_supported
            .is_none());

        let tenant = documents()
            .organization_authorization_server_metadata("org-a", IssuerVariant::CredentialManager);
        assert_eq!(
            tenant.issuer,
            "https://issuer.example/org/org-a/credential-manager"
        );
        assert_eq!(
            tenant.authorization_endpoint,
            "https://issuer.example/v1/issuance/authorize?issuer_org=org-a"
        );
        assert_eq!(
            tenant.token_endpoint_auth_methods_supported,
            ["none", "private_key_jwt"]
        );
        assert_eq!(
            tenant.token_endpoint_auth_signing_alg_values_supported,
            Some(vec!["ES256".to_owned()])
        );
    }

    #[test]
    fn wallet_variants_and_type_metadata_match_public_paths() {
        let apple = documents()
            .organization_authorization_server_metadata("org-a", IssuerVariant::AppleWallet);
        assert_eq!(
            apple.issuer,
            "https://issuer.example/org/org-a/apple-wallet"
        );
        let generic =
            documents().organization_authorization_server_metadata("org-a", IssuerVariant::Default);
        assert_eq!(generic.issuer, "https://issuer.example/org/org-a");

        let credential_type = documents().credential_type_metadata("/access_badge/");
        assert_eq!(
            credential_type.vct,
            "https://issuer.example/credentials/access_badge"
        );
        assert_eq!(credential_type.name, "Access Badge");
        assert_eq!(credential_type.display[0].name, "Access Badge");
    }

    #[test]
    fn discovery_documents_round_trip_without_losing_optional_fields() {
        let issuer = documents().root_issuer_metadata();
        let issuer_json = serde_json::to_string(&issuer).expect("serialize issuer");
        assert_eq!(
            serde_json::from_str::<super::CredentialIssuerMetadata>(&issuer_json)
                .expect("deserialize issuer"),
            issuer
        );

        let authorization_server =
            documents().organization_authorization_server_metadata("org-a", IssuerVariant::Default);
        let authorization_server_json =
            serde_json::to_string(&authorization_server).expect("serialize AS");
        assert_eq!(
            serde_json::from_str::<super::AuthorizationServerMetadata>(&authorization_server_json)
                .expect("deserialize AS"),
            authorization_server
        );
    }
}
