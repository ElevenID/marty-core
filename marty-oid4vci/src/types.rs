//! OID4VCI protocol data types.
//!
//! Implements the core data structures from OID4VCI v1 specification:
//! - Credential Offers (§4)
//! - Token Request/Response (§6)
//! - Credential Request/Response (§8)
//! - Issuer Metadata (§12.2.2)
//! - OAuth Authorization Server Metadata (§12.2.4)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Credential Formats (§8.1)
// =============================================================================

/// Supported credential formats per OID4VCI v1 §8.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CredentialFormat {
    /// W3C Verifiable Credentials JWT format.
    #[serde(rename = "jwt_vc_json")]
    JwtVcJson,
    /// IETF SD-JWT Verifiable Credential format (OID4VCI 1.0).
    #[serde(rename = "dc+sd-jwt", alias = "spruce-vc+sd-jwt")]
    SdJwt,
    /// ISO 18013-5 mobile document format.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc,
    /// mDoc with ZK proof capability (Longfellow/Ligero).
    #[serde(rename = "zk_mdoc")]
    ZkMdoc,
    /// ICAO 9303 Visible Digital Seal - Non-Constrained.
    #[serde(rename = "vds_nc", alias = "vds-nc", alias = "VDS-NC")]
    VdsNc,
}

impl CredentialFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::JwtVcJson => "jwt_vc_json",
            Self::SdJwt => "dc+sd-jwt",
            Self::MsoMdoc => "mso_mdoc",
            Self::ZkMdoc => "zk_mdoc",
            Self::VdsNc => "vds_nc",
        }
    }

    /// Parse a format string into a CredentialFormat.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "jwt_vc_json" | "jwt_vc" => Some(Self::JwtVcJson),
            "dc+sd-jwt" | "spruce-vc+sd-jwt" | "vc+sd-jwt" | "sd_jwt" | "sd-jwt" => Some(Self::SdJwt),
            "mso_mdoc" | "mdoc" => Some(Self::MsoMdoc),
            "zk_mdoc" | "zk-mdoc" | "zkp_mdoc" => Some(Self::ZkMdoc),
            "vds_nc" | "vds-nc" | "VDS-NC" => Some(Self::VdsNc),
            _ => None,
        }
    }
}

impl std::fmt::Display for CredentialFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Credential Offer (§4)
// =============================================================================

/// Configuration for creating a credential offer.
#[derive(Debug, Clone)]
pub struct OfferConfig {
    /// Credential configuration IDs to include in the offer.
    pub credential_configuration_ids: Vec<String>,
    /// Pre-authorized code for the pre-authorized code flow (§4.1).
    pub pre_authorized_code: Option<String>,
    /// Whether a user PIN/transaction code is required.
    pub user_pin_required: bool,
    /// Authorization code issuer state (for authorization code flow, §4.2).
    pub issuer_state: Option<String>,
}

/// OID4VCI Credential Offer (§4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The Credential Issuer URL.
    pub credential_issuer: String,
    /// Array of credential configuration IDs offered.
    pub credential_configuration_ids: Vec<String>,
    /// Grant types available for this offer.
    pub grants: CredentialOfferGrants,
}

/// Grant types in a credential offer.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CredentialOfferGrants {
    /// Pre-authorized code grant (§4.1.1).
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    /// Authorization code grant (§4.1.2).
    #[serde(rename = "authorization_code", skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,
}

/// Pre-authorized code grant parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    /// The pre-authorized code.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    /// Transaction code configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TransactionCode>,
}

/// Transaction code (PIN) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionCode {
    /// Input mode: "numeric" or "text".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,
    /// Length of the code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// Description for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Authorization code grant parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeGrant {
    /// Issuer state for correlating the offer with an authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
    /// Authorization server URL (if different from credential issuer).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_server: Option<String>,
}

// =============================================================================
// Authorization Endpoint (§5)
// =============================================================================

/// OAuth 2.0 grant types supported by OID4VCI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantType {
    /// Pre-authorized code grant (OID4VCI §4.1.1).
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode,
    /// Authorization code grant (RFC 6749 §4.1).
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
}

impl GrantType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreAuthorizedCode => "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            Self::AuthorizationCode => "authorization_code",
        }
    }

    /// Parse a grant type string.
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code" => Some(Self::PreAuthorizedCode),
            "authorization_code" => Some(Self::AuthorizationCode),
            _ => None,
        }
    }
}

impl std::fmt::Display for GrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// PKCE code challenge methods (RFC 7636).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    /// SHA-256 based challenge.
    S256,
    /// Plain text challenge (NOT recommended).
    #[serde(rename = "plain")]
    Plain,
}

impl CodeChallengeMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S256 => "S256",
            Self::Plain => "plain",
        }
    }
}

impl std::fmt::Display for CodeChallengeMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Authorization request parameters (OID4VCI §5.1).
///
/// Sent by the wallet to the authorization endpoint when using the
/// authorization code flow. Extends RFC 6749 §4.1.1 with OID4VCI
/// parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Must be "code".
    pub response_type: String,
    /// Client identifier (wallet DID or registered client_id).
    pub client_id: String,
    /// Redirect URI for the authorization response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Requested scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Opaque state value for CSRF protection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    /// OID4VCI: issuer state from the credential offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
    /// PKCE code challenge (RFC 7636).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (RFC 7636).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// Authorization details (RFC 9396) — contains credential configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
}

/// Authorization Details entry (RFC 9396, OID4VCI §5.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDetail {
    /// Must be "openid_credential".
    #[serde(rename = "type")]
    pub detail_type: String,
    /// Credential configuration ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    /// Credential format (alternative to credential_configuration_id).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Authorization response parameters (RFC 6749 §4.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The authorization code.
    pub code: String,
    /// Echoed state value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Stored authorization session for the code grant flow.
///
/// The calling service is responsible for persisting and retrieving
/// these sessions — the engine is stateless.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationSession {
    /// The generated authorization code.
    pub code: String,
    /// The client that initiated the request.
    pub client_id: String,
    /// Redirect URI the code is bound to.
    pub redirect_uri: Option<String>,
    /// PKCE code challenge for verification at token exchange.
    pub code_challenge: Option<String>,
    /// PKCE code challenge method.
    pub code_challenge_method: Option<CodeChallengeMethod>,
    /// Issuer state from the credential offer.
    pub issuer_state: Option<String>,
    /// Credential configuration IDs authorized.
    pub credential_configuration_ids: Vec<String>,
    /// When this authorization session was created (Unix timestamp).
    pub created_at: u64,
    /// Lifetime in seconds.
    pub expires_in: u64,
}

impl AuthorizationSession {
    /// Check whether this session has expired.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix > self.created_at + self.expires_in
    }
}

// =============================================================================
// Token Request/Response (§6)
// =============================================================================

/// Token request for the pre-authorized code flow (§6.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// Must be "urn:ietf:params:oauth:grant-type:pre-authorized_code".
    pub grant_type: String,
    /// The pre-authorized code from the credential offer.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,
    /// Transaction code (PIN) if required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<String>,
}

/// Token request for the authorization code flow (RFC 6749 §4.1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeTokenRequest {
    /// Must be "authorization_code".
    pub grant_type: String,
    /// The authorization code received from the authorization endpoint.
    pub code: String,
    /// The redirect_uri used in the authorization request (required if
    /// one was included in the authorization request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Client identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// PKCE code verifier (RFC 7636).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_verifier: Option<String>,
}

/// Token response (§6.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: u64,
    /// Scope granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Response from the OID4VCI 1.0 Nonce Endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NonceResponse {
    /// Fresh proof nonce. The response must be delivered with `Cache-Control: no-store`.
    pub c_nonce: String,
}

// =============================================================================
// Credential Request/Response (§8)
// =============================================================================

/// Credential request (§8.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The credential format requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Credential configuration selected from issuer metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_configuration_id: Option<String>,
    /// Credential configuration ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,
    /// Proof of possession (§8.2) — v1 format with `proofs` object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proofs: Option<ProofsObject>,
    /// Credential definition (for jwt_vc_json).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_definition: Option<serde_json::Value>,
    /// vct value (for sd-jwt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    /// doctype (for mso_mdoc).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    /// Claims to include (for selective formats).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

/// OID4VCI v1 proof container (§8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofsObject {
    /// JWT proofs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<Vec<String>>,
}

/// Credential response (§8.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The issued credential (format-dependent encoding).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<serde_json::Value>,
    /// Multiple credentials (v1 batch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<Vec<serde_json::Value>>,
    /// Transaction ID for deferred issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

// =============================================================================
// Credential Configuration (for metadata)
// =============================================================================

/// Configuration for a credential type that the issuer supports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialTypeConfig {
    /// Unique identifier for this credential type.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Supported formats for this credential type.
    pub formats: Vec<CredentialFormat>,
    /// W3C VC types (for jwt_vc_json).
    #[serde(default)]
    pub vc_types: Vec<String>,
    /// SD-JWT Verifiable Credential Type value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    /// mDoc document type (e.g., "org.iso.18013.5.1.mDL").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    /// Claim definitions for this credential type.
    #[serde(default)]
    pub claims: HashMap<String, ClaimDefinition>,
    /// Display information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayEntry>>,
}

/// Definition of a single claim within a credential type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimDefinition {
    /// Whether this claim is mandatory.
    #[serde(default)]
    pub mandatory: bool,
    /// Value type (e.g., "string", "number", "boolean").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    /// Display information for this claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayEntry>>,
}

/// Localized display information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayEntry {
    /// Human-readable name.
    pub name: String,
    /// Locale (e.g., "en-US").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    /// Logo information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<LogoEntry>,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Background color (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    /// Text color (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Logo display information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoEntry {
    /// Logo URI.
    pub uri: String,
    /// Alt text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

// =============================================================================
// Signing Key Material
// =============================================================================

/// Issuer key material for credential signing.
#[derive(Debug, Clone)]
pub struct IssuerKey {
    /// The DID or key identifier for the issuer.
    pub issuer_id: String,
    /// JWK JSON string (contains private key for signing).
    pub jwk_json: String,
    /// Key algorithm hint.
    pub algorithm: SigningAlgorithm,
}

impl IssuerKey {
    /// Returns the `kid` value to use in JWT/SD-JWT headers.
    ///
    /// For `did:key:` DIDs the kid is the full DID URL with verification-method
    /// fragment, e.g. `did:key:z6Mk…#z6Mk…`.  The fragment equals the
    /// multibase-encoded key identifier per the did:key specification (§2.2).
    ///
    /// For all other DID methods the issuer ID is returned unchanged.
    pub fn kid_url(&self) -> String {
        if let Some(key_part) = self.issuer_id.strip_prefix("did:key:") {
            format!("{}#{}", self.issuer_id, key_part)
        } else {
            self.issuer_id.clone()
        }
    }
}

/// Supported signing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    /// ECDSA with P-256 and SHA-256.
    ES256,
    /// Edwards-curve Digital Signature Algorithm (Ed25519).
    EdDSA,
    /// ECDSA with secp256k1 and SHA-256.
    ES256K,
    /// ECDSA with P-384 and SHA-384.
    ES384,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RS256,
}

impl SigningAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ES256 => "ES256",
            Self::EdDSA => "EdDSA",
            Self::ES256K => "ES256K",
            Self::ES384 => "ES384",
            Self::RS256 => "RS256",
        }
    }
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// Credential Payload Format
// =============================================================================

/// Payload structure for signed credentials.
///
/// For SD-JWT: controls whether the body is a flat IETF SD-JWT VC or a W3C VCDM v2 envelope.
/// For JWT-VC: controls whether the `vc` claim follows VCDM v1 or VCDM v2 property names.
///
/// The *wire format* (OID4VCI metadata identifier: `spruce-vc+sd-jwt`, `jwt_vc_json`, etc.)
/// is a separate concern expressed via `CredentialFormat`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CredentialPayloadFormat {
    /// Flat IETF SD-JWT VC: `vct` + flat claims at top level.
    ///
    /// SD-JWT only. Selective disclosure JSONPath: `$.claim_name`
    #[serde(rename = "ietf_sd_jwt")]
    IetfSdJwt,

    /// W3C VCDM v2 envelope inside an SD-JWT.
    ///
    /// Claims nested under `credentialSubject`.
    /// Selective disclosure JSONPath: `$.credentialSubject.claim_name`
    ///
    /// Required by wallets that parse the revealed payload as a VCDM v2
    /// `JsonCredential` (e.g. SpruceID).
    #[default]
    #[serde(rename = "w3c_vcdm_v2_sd_jwt")]
    W3cVcdmV2SdJwt,

    /// W3C VCDM v2 inside a plain JWT-VC (`jwt_vc_json`).
    ///
    /// Uses `https://www.w3.org/ns/credentials/v2` context,
    /// `validFrom` / `validUntil` instead of `issuanceDate` / `expirationDate`,
    /// and respects `w3c_context` / `w3c_types` extension fields.
    #[serde(rename = "w3c_vcdm_v2_jwt_vc")]
    W3cVcdmV2JwtVc,
}

impl CredentialPayloadFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IetfSdJwt => "ietf_sd_jwt",
            Self::W3cVcdmV2SdJwt => "w3c_vcdm_v2_sd_jwt",
            Self::W3cVcdmV2JwtVc => "w3c_vcdm_v2_jwt_vc",
        }
    }

    pub fn from_str_loose(s: &str) -> Self {
        match s {
            "ietf_sd_jwt" | "ietf" | "flat" => Self::IetfSdJwt,
            "w3c_vcdm_v2_jwt_vc" => Self::W3cVcdmV2JwtVc,
            _ => Self::W3cVcdmV2SdJwt,
        }
    }
}

// =============================================================================
// ZK Predicate Binding
// =============================================================================

/// Declares that a specific mDoc claim supports one or more ZK predicates.
///
/// For example, a `birth_date` claim might support both `"age_over_18"` and
/// `"age_over_21"` predicates.  This metadata is embedded in issued
/// `ZkMdoc` credentials so wallets know which proofs they can generate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ZkPredicateBinding {
    /// The mDoc claim name (e.g. `"birth_date"`).
    pub claim_name: String,
    /// Predicate identifiers supported for this claim
    /// (e.g. `["age_over_18", "age_over_21"]`).
    pub supported_predicates: Vec<String>,
}

impl ZkPredicateBinding {
    /// Create a binding for a claim with a single supported predicate.
    pub fn single(claim_name: impl Into<String>, predicate: impl Into<String>) -> Self {
        Self {
            claim_name: claim_name.into(),
            supported_predicates: vec![predicate.into()],
        }
    }

    /// Create a binding for a claim with multiple supported predicates.
    pub fn multi(claim_name: impl Into<String>, predicates: Vec<String>) -> Self {
        Self {
            claim_name: claim_name.into(),
            supported_predicates: predicates,
        }
    }
}

// =============================================================================
// Credential Claims
// =============================================================================

/// Claims to be included in a credential, format-agnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialClaims {
    /// Subject identifier (DID, URI, or other identifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Credential type identifier.
    pub credential_type: String,
    /// The actual claims as key-value pairs.
    pub claims: HashMap<String, serde_json::Value>,
    /// Expiration duration in seconds from issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_seconds: Option<i64>,
    /// For SD-JWT: which claims should be selectively disclosable.
    #[serde(default)]
    pub selective_disclosure_claims: Vec<String>,
    /// For mDoc: namespace for the claims (e.g., "org.iso.18013.5.1").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdoc_namespace: Option<String>,
    /// For mDoc: document type (e.g., "org.iso.18013.5.1.mDL").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdoc_doctype: Option<String>,
    /// For ZK mDoc: per-claim ZK predicate bindings.
    ///
    /// Each entry declares a claim name and the predicates it supports.
    /// Example: `[{ claim_name: "birth_date", supported_predicates: ["age_over_18", "age_over_21"] }]`
    #[serde(default)]
    pub zk_predicate_claims: Vec<ZkPredicateBinding>,
    /// SD-JWT payload structure: IETF flat or W3C VCDM v2 envelope.
    /// Defaults to W3C VCDM v2 for backward compatibility.
    #[serde(default)]
    pub credential_payload_format: CredentialPayloadFormat,
    /// W3C VCDM v2 only: additional `@context` entries beyond the base.
    #[serde(default)]
    pub w3c_context: Vec<String>,
    /// W3C VCDM v2 only: additional `type` values beyond "VerifiableCredential".
    #[serde(default)]
    pub w3c_types: Vec<String>,
}

// =============================================================================
// Signed Credential Output
// =============================================================================

/// The result of credential signing, format-specific.
#[derive(Debug, Clone)]
pub enum SignedCredential {
    /// A JWT-encoded verifiable credential.
    JwtVcJson {
        /// The signed JWT string.
        jwt: String,
        /// The credential ID (urn:uuid:...).
        credential_id: String,
    },
    /// An SD-JWT encoded verifiable credential.
    SdJwt {
        /// The combined SD-JWT string (jwt~disclosure1~disclosure2~).
        compact: String,
        /// The credential ID.
        credential_id: String,
    },
    /// An mDoc credential (CBOR-encoded IssuerSigned).
    MsoMdoc {
        /// Base64url-encoded CBOR IssuerSigned document.
        issuer_signed_b64: String,
        /// The credential ID.
        credential_id: String,
    },
    /// An mDoc credential with ZK proof capability metadata.
    ZkMdoc {
        /// Base64url-encoded CBOR IssuerSigned document.
        issuer_signed_b64: String,
        /// Per-claim ZK predicate bindings — which claims support which predicates.
        zk_predicate_bindings: Vec<ZkPredicateBinding>,
        /// ZK proof type identifier (e.g., "longfellow-zk-ligero").
        zk_proof_type: String,
        /// The credential ID.
        credential_id: String,
    },
    /// A VDS-NC credential represented as barcode payload text.
    VdsNc {
        /// Header + payload + signature string (tilde-separated).
        barcode_data: String,
        /// The credential ID.
        credential_id: String,
    },
}

impl SignedCredential {
    /// Get the format of this signed credential.
    pub fn format(&self) -> CredentialFormat {
        match self {
            Self::JwtVcJson { .. } => CredentialFormat::JwtVcJson,
            Self::SdJwt { .. } => CredentialFormat::SdJwt,
            Self::MsoMdoc { .. } => CredentialFormat::MsoMdoc,
            Self::ZkMdoc { .. } => CredentialFormat::ZkMdoc,
            Self::VdsNc { .. } => CredentialFormat::VdsNc,
        }
    }

    /// Get the credential ID.
    pub fn credential_id(&self) -> &str {
        match self {
            Self::JwtVcJson { credential_id, .. } => credential_id,
            Self::SdJwt { credential_id, .. } => credential_id,
            Self::MsoMdoc { credential_id, .. } => credential_id,
            Self::ZkMdoc { credential_id, .. } => credential_id,
            Self::VdsNc { credential_id, .. } => credential_id,
        }
    }

    /// Get the serialized credential value for inclusion in the OID4VCI response.
    pub fn to_response_value(&self) -> serde_json::Value {
        match self {
            Self::JwtVcJson { jwt, .. } => serde_json::Value::String(jwt.clone()),
            Self::SdJwt { compact, .. } => serde_json::Value::String(compact.clone()),
            Self::MsoMdoc {
                issuer_signed_b64, ..
            } => serde_json::Value::String(issuer_signed_b64.clone()),
            Self::ZkMdoc {
                issuer_signed_b64,
                zk_predicate_bindings,
                zk_proof_type,
                ..
            } => serde_json::json!({
                "credential": issuer_signed_b64,
                "zk_metadata": {
                    "proof_type": zk_proof_type,
                    "predicate_bindings": zk_predicate_bindings,
                }
            }),
            Self::VdsNc { barcode_data, .. } => serde_json::Value::String(barcode_data.clone()),
        }
    }
}

// =============================================================================
// Issuer Configuration (multi-tenant)
// =============================================================================

/// Configuration for a specific issuer/organization.
#[derive(Debug, Clone)]
pub struct IssuerConfig {
    /// The base URL for this issuer (e.g., "https://issuer.example.com/org/123").
    pub credential_issuer_url: String,
    /// Human-readable name.
    pub issuer_name: String,
    /// Credential types this issuer supports.
    pub credential_types: Vec<CredentialTypeConfig>,
    /// The issuer's signing key.
    pub issuer_key: IssuerKey,
    /// Token endpoint URL (if different from default).
    pub token_endpoint: Option<String>,
    /// Credential endpoint URL (if different from default).
    pub credential_endpoint: Option<String>,
    /// Authorization endpoint URL (for authorization code flow).
    pub authorization_endpoint: Option<String>,
    /// Deferred credential endpoint URL.
    pub deferred_credential_endpoint: Option<String>,
    /// Supported cryptographic binding methods.
    pub binding_methods: Vec<String>,
    /// Supported proof signing algorithms.
    pub proof_signing_alg_values: Vec<String>,
}

impl IssuerConfig {
    /// Get the token endpoint, defaulting to `{credential_issuer_url}/token`.
    pub fn token_endpoint(&self) -> String {
        self.token_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/token", self.credential_issuer_url))
    }

    /// Get the credential endpoint, defaulting to `{credential_issuer_url}/credential`.
    pub fn credential_endpoint(&self) -> String {
        self.credential_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/credential", self.credential_issuer_url))
    }
}
