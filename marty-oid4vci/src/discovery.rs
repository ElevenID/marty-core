//! Typed OID4VCI and OAuth discovery documents.
//!
//! These types model the current OID4VCI Final wire contract, including
//! authorization-server indirection, Final credential metadata, wallet key
//! attestation requirements, and both JOSE and COSE algorithm identifiers.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

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

/// Raw claim metadata stored with a tenant credential template.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantClaimMetadata {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<TenantClaimDisplay>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// Nested claim label accepted by the Python template contract.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantClaimDisplay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Optional colors and logo stored with a tenant credential template.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantDisplayStyle {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
}

/// Display, claims, and issuer selection data for one tenant credential type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantCredentialMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<TenantClaimMetadata>,
    #[serde(default)]
    pub display_style: TenantDisplayStyle,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
}

/// Repository projection needed to publish one tenant credential type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantCredentialTemplate {
    pub credential_type: String,
    #[serde(default)]
    pub supported_formats: Vec<String>,
    #[serde(default)]
    pub metadata: TenantCredentialMetadata,
}

/// An external issuer-policy lookup required by tenant discovery.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProofPolicyRequest {
    pub organization_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    pub credential_format: String,
    pub key_purpose: String,
}

impl ProofPolicyRequest {
    fn new(organization_id: &str, issuer_did: Option<String>, credential_format: &str) -> Self {
        Self {
            organization_id: organization_id.to_owned(),
            issuer_did,
            credential_format: credential_format.to_owned(),
            key_purpose: if credential_format == "mso_mdoc" {
                "mdoc_dsc"
            } else {
                "vc_jwt_issuer"
            }
            .to_owned(),
        }
    }
}

/// A tenant discovery plan whose external policy reads have not yet been supplied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantDiscoveryPlan {
    documents: StaticDiscoveryDocuments,
    organization_id: String,
    variant: IssuerVariant,
    templates: Vec<TenantCredentialTemplate>,
    proof_policy_requests: Vec<ProofPolicyRequest>,
}

impl TenantDiscoveryPlan {
    /// Unique policy reads required before the metadata document can be built.
    #[must_use]
    pub fn proof_policy_requests(&self) -> &[ProofPolicyRequest] {
        &self.proof_policy_requests
    }

    /// Build the tenant document from an explicit result for every planned read.
    ///
    /// A resolver response without a required policy is represented by an empty
    /// [`KeyAttestationRequirements`]. A missing map entry means the I/O phase
    /// did not complete and fails closed rather than weakening advertised policy.
    pub fn build(
        &self,
        resolved_policies: &BTreeMap<ProofPolicyRequest, KeyAttestationRequirements>,
    ) -> Result<CredentialIssuerMetadata, TenantDiscoveryError> {
        for request in &self.proof_policy_requests {
            if !resolved_policies.contains_key(request) {
                return Err(TenantDiscoveryError::MissingProofPolicy(request.clone()));
            }
        }

        let configurations = match self.variant {
            IssuerVariant::Default => self.default_configurations(resolved_policies),
            IssuerVariant::CredentialManager => {
                self.credential_manager_configurations(resolved_policies)
            }
            IssuerVariant::AppleWallet => self.apple_wallet_configurations(resolved_policies),
        }?;
        let base = &self.documents.issuer_base_url;
        let issuer = format!(
            "{base}/org/{}{}",
            self.organization_id,
            self.variant.path_suffix()
        );
        Ok(CredentialIssuerMetadata {
            credential_issuer: issuer.clone(),
            authorization_servers: vec![issuer],
            display: vec![DisplayEntry::english(&self.documents.issuer_display_name)],
            credential_endpoint: format!("{base}/v1/issuance/credential"),
            nonce_endpoint: format!("{base}/v1/issuance/nonce"),
            deferred_credential_endpoint: format!("{base}/v1/issuance/deferred-credential"),
            notification_endpoint: format!("{base}/v1/issuance/notification"),
            credential_configurations_supported: configurations,
        })
    }

    fn proof_types(
        &self,
        template: Option<&TenantCredentialTemplate>,
        credential_format: &str,
        resolved: &BTreeMap<ProofPolicyRequest, KeyAttestationRequirements>,
    ) -> Result<BTreeMap<String, ProofTypeMetadata>, TenantDiscoveryError> {
        let issuer_did = match self.variant {
            IssuerVariant::Default => template
                .and_then(|value| trimmed(&value.metadata.issuer_did))
                .map(str::to_owned),
            IssuerVariant::CredentialManager | IssuerVariant::AppleWallet => None,
        };
        if self.variant == IssuerVariant::Default && issuer_did.is_none() {
            return Ok(default_proof_types());
        }
        let request = ProofPolicyRequest::new(&self.organization_id, issuer_did, credential_format);
        let requirements = resolved
            .get(&request)
            .cloned()
            .ok_or(TenantDiscoveryError::MissingProofPolicy(request))?;
        Ok(proof_types_with_requirements(requirements))
    }

    fn default_configurations(
        &self,
        resolved: &BTreeMap<ProofPolicyRequest, KeyAttestationRequirements>,
    ) -> Result<BTreeMap<String, CredentialConfiguration>, TenantDiscoveryError> {
        let mut configurations = BTreeMap::new();
        for template in &self.templates {
            let formats = SupportedFormats::new(&template.supported_formats);
            let credential_type = &template.credential_type;
            let metadata = credential_metadata(credential_type, &template.metadata);
            if formats.jwt_vc {
                configurations.insert(
                    credential_type.clone(),
                    tenant_configuration(
                        "jwt_vc_json",
                        credential_type,
                        self.proof_types(Some(template), "jwt_vc_json", resolved)?,
                        Some(CredentialDefinition {
                            context: None,
                            types: vec!["VerifiableCredential".to_owned(), credential_type.clone()],
                        }),
                        Some(metadata.clone()),
                    ),
                );
            }
            if formats.mdoc || credential_type.starts_with("org.iso.18013") {
                let mut configuration = tenant_configuration(
                    "mso_mdoc",
                    credential_type,
                    self.proof_types(Some(template), "mso_mdoc", resolved)?,
                    None,
                    Some(metadata.clone()),
                );
                configuration.doctype = Some(credential_type.clone());
                configuration.credential_signing_alg_values_supported = mdoc_algorithms();
                configurations.insert(format!("{credential_type}#mdoc"), configuration);
            }
            if formats.data_integrity {
                let mut types = vec!["VerifiableCredential".to_owned()];
                if credential_type != "VerifiableCredential" {
                    types.push(credential_type.clone());
                }
                let mut configuration = tenant_configuration(
                    "ldp_vc",
                    credential_type,
                    self.proof_types(Some(template), "ldp_vc", resolved)?,
                    Some(CredentialDefinition {
                        context: Some(vec![VCDM_V2_CONTEXT.to_owned()]),
                        types,
                    }),
                    Some(metadata.clone()),
                );
                configuration.credential_signing_alg_values_supported =
                    vec!["eddsa-rdfc-2022".into()];
                configurations.insert(format!("{credential_type}#ldp-vc"), configuration);
            }
            if formats.sd_jwt && !credential_type.starts_with("org.iso.18013") {
                let mut configuration = tenant_configuration(
                    "dc+sd-jwt",
                    credential_type,
                    self.proof_types(Some(template), "dc+sd-jwt", resolved)?,
                    None,
                    Some(metadata),
                );
                configuration.vct = Some(resolve_vct(
                    &template.metadata.vct,
                    credential_type,
                    &self.documents.issuer_base_url,
                ));
                configurations.insert(format!("{credential_type}#sd-jwt"), configuration);
            }
        }
        Ok(configurations)
    }

    fn credential_manager_configurations(
        &self,
        resolved: &BTreeMap<ProofPolicyRequest, KeyAttestationRequirements>,
    ) -> Result<BTreeMap<String, CredentialConfiguration>, TenantDiscoveryError> {
        let proof_types = self.proof_types(None, "dc+sd-jwt", resolved)?;
        Ok(self
            .templates
            .iter()
            .filter(|template| !template.credential_type.starts_with("org.iso.18013"))
            .map(|template| {
                let mut configuration = tenant_configuration(
                    "dc+sd-jwt",
                    &template.credential_type,
                    proof_types.clone(),
                    None,
                    None,
                );
                configuration.vct = Some(resolve_vct(
                    &template.metadata.vct,
                    &template.credential_type,
                    &self.documents.issuer_base_url,
                ));
                configuration.display = Some(credential_display_entries(
                    &template.credential_type,
                    &template.metadata,
                ));
                let claims = claim_descriptors(&template.metadata);
                configuration.claims = (!claims.is_empty()).then_some(claims);
                (
                    format!("{}#credential-manager", template.credential_type),
                    configuration,
                )
            })
            .collect())
    }

    fn apple_wallet_configurations(
        &self,
        resolved: &BTreeMap<ProofPolicyRequest, KeyAttestationRequirements>,
    ) -> Result<BTreeMap<String, CredentialConfiguration>, TenantDiscoveryError> {
        let proof_types = self.proof_types(None, "mso_mdoc", resolved)?;
        Ok(self
            .templates
            .iter()
            .map(|template| {
                let mut configuration = tenant_configuration(
                    "mso_mdoc",
                    &template.credential_type,
                    proof_types.clone(),
                    None,
                    None,
                );
                configuration.doctype = Some(template.credential_type.clone());
                configuration.credential_signing_alg_values_supported = mdoc_algorithms();
                configuration.display = Some(credential_display_entries(
                    &template.credential_type,
                    &template.metadata,
                ));
                (
                    format!("{}#apple-wallet", template.credential_type),
                    configuration,
                )
            })
            .collect())
    }
}

/// Failure to supply an external result required by a tenant discovery plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TenantDiscoveryError {
    MissingProofPolicy(ProofPolicyRequest),
}

impl fmt::Display for TenantDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingProofPolicy(request) => write!(
                formatter,
                "missing proof policy for {} / {}",
                request.organization_id, request.credential_format
            ),
        }
    }
}

impl Error for TenantDiscoveryError {}

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

    /// Plan organization-scoped issuer metadata without performing external I/O.
    ///
    /// This implements the language-neutral
    /// `marty.issuance-tenant-discovery/v1` behavior contract maintained by
    /// `marty-credentials/contracts/issuance-tenant-discovery.json`.
    ///
    /// The caller reads [`TenantDiscoveryPlan::proof_policy_requests`], resolves
    /// those requests through its signing-context adapter, and then supplies all
    /// results to [`TenantDiscoveryPlan::build`].
    #[must_use]
    pub fn plan_organization_issuer_metadata(
        &self,
        organization_id: impl Into<String>,
        variant: IssuerVariant,
        templates: Vec<TenantCredentialTemplate>,
    ) -> TenantDiscoveryPlan {
        let organization_id = organization_id.into();
        let mut requests = Vec::new();
        let mut seen_requests = BTreeSet::new();
        let mut push_request = |request: ProofPolicyRequest| {
            if seen_requests.insert(request.clone()) {
                requests.push(request);
            }
        };
        match variant {
            IssuerVariant::CredentialManager => {
                push_request(ProofPolicyRequest::new(&organization_id, None, "dc+sd-jwt"));
            }
            IssuerVariant::AppleWallet => {
                push_request(ProofPolicyRequest::new(&organization_id, None, "mso_mdoc"));
            }
            IssuerVariant::Default => {
                for template in &templates {
                    let Some(issuer_did) = trimmed(&template.metadata.issuer_did) else {
                        continue;
                    };
                    let formats = SupportedFormats::new(&template.supported_formats);
                    for credential_format in [
                        formats.jwt_vc.then_some("jwt_vc_json"),
                        formats.sd_jwt.then_some("dc+sd-jwt"),
                        (formats.mdoc || template.credential_type.starts_with("org.iso.18013"))
                            .then_some("mso_mdoc"),
                        formats.data_integrity.then_some("ldp_vc"),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        push_request(ProofPolicyRequest::new(
                            &organization_id,
                            Some(issuer_did.to_owned()),
                            credential_format,
                        ));
                    }
                }
            }
        }
        TenantDiscoveryPlan {
            documents: self.clone(),
            organization_id,
            variant,
            templates,
            proof_policy_requests: requests,
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SupportedFormats {
    jwt_vc: bool,
    sd_jwt: bool,
    data_integrity: bool,
    mdoc: bool,
}

impl SupportedFormats {
    fn new(values: &[String]) -> Self {
        let values: BTreeSet<String> = values
            .iter()
            .map(|value| value.trim().to_lowercase().replace('-', "_"))
            .collect();
        Self {
            jwt_vc: [
                "jwt_vc",
                "jwt_vc_json",
                "w3c_vcdm_v2_jwt",
                "w3c_vcdm_v2_jwt_vc",
            ]
            .iter()
            .any(|value| values.contains(*value)),
            sd_jwt: ["sd_jwt_vc", "dc+sd_jwt", "vc+sd_jwt", "w3c_vcdm_v2_sd_jwt"]
                .iter()
                .any(|value| values.contains(*value)),
            data_integrity: ["json_ld", "ldp_vc", "w3c_vcdm_v2_di"]
                .iter()
                .any(|value| values.contains(*value)),
            mdoc: ["mdoc", "mso_mdoc"]
                .iter()
                .any(|value| values.contains(*value)),
        }
    }
}

fn tenant_configuration(
    format: &str,
    credential_type: &str,
    proof_types_supported: BTreeMap<String, ProofTypeMetadata>,
    credential_definition: Option<CredentialDefinition>,
    credential_metadata: Option<CredentialMetadata>,
) -> CredentialConfiguration {
    CredentialConfiguration {
        format: format.to_owned(),
        scope: credential_type.to_owned(),
        vct: None,
        doctype: None,
        cryptographic_binding_methods_supported: default_binding_methods(),
        credential_signing_alg_values_supported: default_jose_algorithms(),
        proof_types_supported,
        credential_definition,
        credential_metadata,
        claims: None,
        display: None,
    }
}

fn proof_types_with_requirements(
    requirements: KeyAttestationRequirements,
) -> BTreeMap<String, ProofTypeMetadata> {
    BTreeMap::from([(
        "jwt".to_owned(),
        ProofTypeMetadata {
            proof_signing_alg_values_supported: vec!["ES256".to_owned(), "EdDSA".to_owned()],
            key_attestations_required: requirements,
        },
    )])
}

fn mdoc_algorithms() -> Vec<AlgorithmIdentifier> {
    vec![(-7).into(), (-8).into()]
}

fn credential_metadata(
    credential_type: &str,
    metadata: &TenantCredentialMetadata,
) -> CredentialMetadata {
    let claims = claim_descriptors(metadata);
    CredentialMetadata {
        display: credential_display_entries(credential_type, metadata),
        claims: (!claims.is_empty()).then_some(claims),
    }
}

fn credential_display_entries(
    credential_type: &str,
    metadata: &TenantCredentialMetadata,
) -> Vec<DisplayEntry> {
    let name = trimmed(&metadata.name).map_or_else(
        || friendly_credential_type_name(credential_type),
        str::to_owned,
    );
    let style = &metadata.display_style;
    vec![DisplayEntry {
        logo: trimmed(&style.logo_url).map(|uri| LogoEntry {
            uri: uri.to_owned(),
            alt_text: Some(name.clone()),
        }),
        name,
        locale: "en-US".to_owned(),
        description: trimmed(&metadata.description).map(str::to_owned),
        background_color: trimmed(&style.background_color).map(str::to_owned),
        text_color: trimmed(&style.text_color).map(str::to_owned),
    }]
}

fn claim_descriptors(metadata: &TenantCredentialMetadata) -> Vec<ClaimDescriptor> {
    metadata
        .claims
        .iter()
        .filter_map(|claim| {
            if claim.name.is_empty() {
                return None;
            }
            let name = &claim.name;
            let display_name = claim
                .display
                .as_ref()
                .and_then(|display| trimmed(&display.label).or_else(|| trimmed(&display.name)))
                .or_else(|| trimmed(&claim.display_name))
                .map_or_else(|| title_words(&name.replace('_', " ")), str::to_owned);
            Some(ClaimDescriptor {
                path: vec![name.clone()],
                display: vec![DisplayEntry::english(display_name)],
                mandatory: claim.required.then_some(true),
            })
        })
        .collect()
}

fn friendly_credential_type_name(value: &str) -> String {
    if value.contains('.') {
        return value.to_owned();
    }
    let mut words = String::with_capacity(value.len());
    let mut previous_lowercase = false;
    for character in value.replace('_', " ").chars() {
        if previous_lowercase && character.is_uppercase() {
            words.push(' ');
        }
        previous_lowercase = character.is_lowercase();
        words.push(character);
    }
    title_words(&words)
}

fn title_words(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut start_of_word = true;
    for character in value.chars() {
        if character.is_alphabetic() {
            if start_of_word {
                result.extend(character.to_uppercase());
            } else {
                result.extend(character.to_lowercase());
            }
            start_of_word = false;
        } else {
            result.push(character);
            start_of_word = true;
        }
    }
    result
}

fn resolve_vct(raw_vct: &Option<String>, credential_type: &str, issuer_base_url: &str) -> String {
    if let Some(value) = trimmed(raw_vct) {
        if has_uri_scheme(value) {
            return value.to_owned();
        }
    }
    format!(
        "{}/credentials/{credential_type}",
        issuer_base_url.trim_end_matches('/')
    )
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
}

fn trimmed(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn default_proof_types() -> BTreeMap<String, ProofTypeMetadata> {
    proof_types_with_requirements(KeyAttestationRequirements::default())
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
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::{
        IssuerVariant, KeyAttestationRequirements, ProofPolicyRequest, StaticDiscoveryDocuments,
        TenantClaimDisplay, TenantClaimMetadata, TenantCredentialMetadata,
        TenantCredentialTemplate, TenantDiscoveryError, TenantDisplayStyle,
    };

    fn documents() -> StaticDiscoveryDocuments {
        StaticDiscoveryDocuments::new("https://issuer.example", "Example Issuer")
    }

    fn tenant_templates() -> Vec<TenantCredentialTemplate> {
        vec![
            TenantCredentialTemplate {
                credential_type: "EmployeeBadge".to_owned(),
                supported_formats: vec![
                    "jwt_vc_json".to_owned(),
                    "sd_jwt_vc".to_owned(),
                    "w3c_vcdm_v2_di".to_owned(),
                ],
                metadata: TenantCredentialMetadata {
                    name: Some(" Employee Badge ".to_owned()),
                    description: Some(" Company access credential ".to_owned()),
                    claims: vec![
                        TenantClaimMetadata {
                            name: "employee_id".to_owned(),
                            display: Some(TenantClaimDisplay {
                                label: Some(" Employee ID ".to_owned()),
                                name: None,
                            }),
                            display_name: None,
                            required: true,
                        },
                        TenantClaimMetadata {
                            name: "department".to_owned(),
                            display: None,
                            display_name: Some("Department".to_owned()),
                            required: false,
                        },
                    ],
                    display_style: TenantDisplayStyle {
                        background_color: Some(" #112233 ".to_owned()),
                        text_color: Some("#ffffff".to_owned()),
                        logo_url: Some("https://issuer.example/logo.png".to_owned()),
                    },
                    vct: Some("https://types.example/employee-badge".to_owned()),
                    issuer_did: Some(" did:web:issuer.example:employee ".to_owned()),
                },
            },
            TenantCredentialTemplate {
                credential_type: "org.iso.18013.5.1.mDL".to_owned(),
                supported_formats: vec!["mso_mdoc".to_owned()],
                metadata: TenantCredentialMetadata {
                    name: Some("Mobile Driving Licence".to_owned()),
                    issuer_did: Some("did:web:issuer.example:mdl".to_owned()),
                    ..TenantCredentialMetadata::default()
                },
            },
        ]
    }

    fn resolved_policies(
        requests: &[ProofPolicyRequest],
    ) -> BTreeMap<ProofPolicyRequest, KeyAttestationRequirements> {
        requests
            .iter()
            .cloned()
            .map(|request| {
                let requirements = match request.credential_format.as_str() {
                    "dc+sd-jwt" => KeyAttestationRequirements {
                        key_storage: vec!["iso_18045_high".to_owned()],
                        user_authentication: vec!["biometric".to_owned()],
                    },
                    "ldp_vc" => KeyAttestationRequirements {
                        user_authentication: vec!["biometric".to_owned()],
                        ..KeyAttestationRequirements::default()
                    },
                    "mso_mdoc" => KeyAttestationRequirements {
                        key_storage: vec!["iso_18045_high".to_owned()],
                        ..KeyAttestationRequirements::default()
                    },
                    _ => KeyAttestationRequirements::default(),
                };
                (request, requirements)
            })
            .collect()
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

    #[test]
    fn tenant_default_plan_preserves_policy_selection_and_all_formats() {
        let plan = documents().plan_organization_issuer_metadata(
            "org-a",
            IssuerVariant::Default,
            tenant_templates(),
        );
        assert_eq!(
            plan.proof_policy_requests(),
            [
                ProofPolicyRequest::new(
                    "org-a",
                    Some("did:web:issuer.example:employee".to_owned()),
                    "jwt_vc_json",
                ),
                ProofPolicyRequest::new(
                    "org-a",
                    Some("did:web:issuer.example:employee".to_owned()),
                    "dc+sd-jwt",
                ),
                ProofPolicyRequest::new(
                    "org-a",
                    Some("did:web:issuer.example:employee".to_owned()),
                    "ldp_vc",
                ),
                ProofPolicyRequest::new(
                    "org-a",
                    Some("did:web:issuer.example:mdl".to_owned()),
                    "mso_mdoc",
                ),
            ]
        );

        let value = serde_json::to_value(
            plan.build(&resolved_policies(plan.proof_policy_requests()))
                .expect("all policies supplied"),
        )
        .expect("serialize");
        assert_eq!(
            value["credential_issuer"],
            "https://issuer.example/org/org-a"
        );
        assert_eq!(
            value["authorization_servers"],
            json!(["https://issuer.example/org/org-a"])
        );
        assert_eq!(
            value["display"],
            json!([{"name": "Example Issuer", "locale": "en-US"}])
        );
        assert_eq!(
            value["credential_endpoint"],
            "https://issuer.example/v1/issuance/credential"
        );
        assert_eq!(
            value["nonce_endpoint"],
            "https://issuer.example/v1/issuance/nonce"
        );
        assert_eq!(
            value["deferred_credential_endpoint"],
            "https://issuer.example/v1/issuance/deferred-credential"
        );
        assert_eq!(
            value["notification_endpoint"],
            "https://issuer.example/v1/issuance/notification"
        );

        let configurations = &value["credential_configurations_supported"];
        assert_eq!(configurations.as_object().expect("map").len(), 4);
        let display = json!([{
            "name": "Employee Badge",
            "locale": "en-US",
            "description": "Company access credential",
            "background_color": "#112233",
            "text_color": "#ffffff",
            "logo": {
                "uri": "https://issuer.example/logo.png",
                "alt_text": "Employee Badge"
            }
        }]);
        let claims = json!([
            {
                "path": ["employee_id"],
                "display": [{"name": "Employee ID", "locale": "en-US"}],
                "mandatory": true
            },
            {
                "path": ["department"],
                "display": [{"name": "Department", "locale": "en-US"}]
            }
        ]);
        let employee = &configurations["EmployeeBadge"];
        assert_eq!(employee["format"], "jwt_vc_json");
        assert_eq!(
            employee["credential_definition"],
            json!({"type": ["VerifiableCredential", "EmployeeBadge"]})
        );
        assert_eq!(employee["credential_metadata"]["display"], display);
        assert_eq!(employee["credential_metadata"]["claims"], claims);
        assert_eq!(
            employee["proof_types_supported"]["jwt"]["key_attestations_required"],
            json!({})
        );

        let sd_jwt = &configurations["EmployeeBadge#sd-jwt"];
        assert_eq!(sd_jwt["format"], "dc+sd-jwt");
        assert_eq!(sd_jwt["vct"], "https://types.example/employee-badge");
        assert_eq!(sd_jwt["credential_metadata"]["display"], display);
        assert_eq!(sd_jwt["credential_metadata"]["claims"], claims);
        assert_eq!(
            sd_jwt["proof_types_supported"]["jwt"]["key_attestations_required"],
            json!({
                "key_storage": ["iso_18045_high"],
                "user_authentication": ["biometric"]
            })
        );

        let data_integrity = &configurations["EmployeeBadge#ldp-vc"];
        assert_eq!(data_integrity["format"], "ldp_vc");
        assert_eq!(
            data_integrity["credential_signing_alg_values_supported"],
            json!(["eddsa-rdfc-2022"])
        );
        assert_eq!(
            data_integrity["credential_definition"],
            json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "EmployeeBadge"]
            })
        );
        assert_eq!(
            data_integrity["proof_types_supported"]["jwt"]["key_attestations_required"],
            json!({"user_authentication": ["biometric"]})
        );

        let mdoc = &configurations["org.iso.18013.5.1.mDL#mdoc"];
        assert_eq!(mdoc["format"], "mso_mdoc");
        assert_eq!(mdoc["doctype"], "org.iso.18013.5.1.mDL");
        assert_eq!(
            mdoc["credential_signing_alg_values_supported"],
            json!([-7, -8])
        );
        assert_eq!(
            mdoc["credential_metadata"]["display"],
            json!([{"name": "Mobile Driving Licence", "locale": "en-US"}])
        );
    }

    #[test]
    fn tenant_wallet_variants_preserve_format_filtering_and_metadata_placement() {
        let manager = documents().plan_organization_issuer_metadata(
            "org-a",
            IssuerVariant::CredentialManager,
            tenant_templates(),
        );
        assert_eq!(
            manager.proof_policy_requests(),
            [ProofPolicyRequest::new("org-a", None, "dc+sd-jwt")]
        );
        let manager_value = serde_json::to_value(
            manager
                .build(&resolved_policies(manager.proof_policy_requests()))
                .expect("manager policy supplied"),
        )
        .expect("serialize manager");
        let manager_configs = &manager_value["credential_configurations_supported"];
        assert_eq!(manager_configs.as_object().expect("map").len(), 1);
        let employee = &manager_configs["EmployeeBadge#credential-manager"];
        assert_eq!(employee["format"], "dc+sd-jwt");
        assert!(employee.get("credential_metadata").is_none());
        assert_eq!(employee["display"][0]["name"], "Employee Badge");
        assert_eq!(employee["claims"][0]["mandatory"], true);
        assert_eq!(
            employee["proof_types_supported"]["jwt"]["key_attestations_required"],
            json!({
                "key_storage": ["iso_18045_high"],
                "user_authentication": ["biometric"]
            })
        );

        let apple = documents().plan_organization_issuer_metadata(
            "org-a",
            IssuerVariant::AppleWallet,
            tenant_templates(),
        );
        assert_eq!(
            apple.proof_policy_requests(),
            [ProofPolicyRequest::new("org-a", None, "mso_mdoc")]
        );
        let apple_value = serde_json::to_value(
            apple
                .build(&resolved_policies(apple.proof_policy_requests()))
                .expect("apple policy supplied"),
        )
        .expect("serialize apple");
        let apple_configs = &apple_value["credential_configurations_supported"];
        assert_eq!(apple_configs.as_object().expect("map").len(), 2);
        for credential_type in ["EmployeeBadge", "org.iso.18013.5.1.mDL"] {
            let configuration = &apple_configs[format!("{credential_type}#apple-wallet")];
            assert_eq!(configuration["format"], "mso_mdoc");
            assert_eq!(configuration["doctype"], credential_type);
            assert_eq!(
                configuration["credential_signing_alg_values_supported"],
                json!([-7, -8])
            );
            assert!(configuration.get("claims").is_none());
            assert!(configuration.get("credential_metadata").is_none());
        }
    }

    #[test]
    fn tenant_discovery_fails_closed_when_a_planned_policy_is_missing() {
        let plan = documents().plan_organization_issuer_metadata(
            "org-a",
            IssuerVariant::CredentialManager,
            tenant_templates(),
        );
        assert_eq!(
            plan.build(&BTreeMap::new()),
            Err(TenantDiscoveryError::MissingProofPolicy(
                ProofPolicyRequest::new("org-a", None, "dc+sd-jwt")
            ))
        );
    }
}
