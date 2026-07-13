//! OID4VCI/OID4VP wallet (holder) engine.
//!
//! Implements the wallet/holder side of the OID4VCI v1 and OID4VP v1
//! specifications.  For the server (issuer/verifier) side see [`crate::issuer`]
//! and [`crate::verifier`].
//!
//! # Feature flag
//!
//! This module is gated behind the `wallet` feature.  Enable it in consuming
//! crates with:
//!
//! ```toml
//! marty-oid4vci = { path = "…", features = ["wallet", "jwt_vc_json", "sd_jwt", "mso_mdoc", "zk_mdoc"] }
//! ```
//!
//! # Supported flows
//!
//! | Flow | Method |
//! |------|--------|
//! | Pre-authorized code (§4.1) | [`WalletEngine::exchange_pre_auth_code`] |
//! | Authorization code + PKCE (§4.2) | [`WalletEngine::build_authorization_request`] / [`WalletEngine::exchange_auth_code`] |
//! | Credential request (§8) | [`WalletEngine::request_credential`] |
//! | OID4VP presentation (§5) | [`WalletEngine::build_presentation_submission`] / [`WalletEngine::submit_presentation`] |
//! | ZK predicate presentation | [`WalletEngine::build_zk_presentation`] |

use std::collections::HashMap;

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::issuer::generate_pkce_challenge_s256;
use crate::types::{
    AuthorizationDetail, AuthorizationRequest,
    CodeChallengeMethod, CredentialFormat, CredentialOffer, CredentialRequest, CredentialResponse,
    GrantType, ProofsObject, TokenResponse,
};
use crate::verifier::{
    DescriptorMapEntry, PresentationDefinition, PresentationSubmission,
};

// ═══════════════════════════════════════════════════════════════════════════
// Issuer metadata (wallet-parsed)
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed `.well-known/openid-credential-issuer` response (OID4VCI §12.2.2).
///
/// Only the fields the wallet needs to drive a credential issuance flow are
/// modelled here.  Unknown fields are captured in `extra`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerMetadata {
    /// The Credential Issuer identifier URL.
    pub credential_issuer: String,
    /// Token endpoint (may live on a separate AS).
    pub token_endpoint: Option<String>,
    /// Credential endpoint.
    pub credential_endpoint: String,
    /// Authorization endpoint (for auth-code flow).
    pub authorization_endpoint: Option<String>,
    /// Supported grant types.
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// Credential configurations offered by this issuer.
    #[serde(default)]
    pub credential_configurations_supported: HashMap<String, serde_json::Value>,
    /// Raw extra fields preserved for forward-compatibility.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl IssuerMetadata {
    /// Resolve the token endpoint, falling back to `{credential_issuer}/token`.
    pub fn token_endpoint(&self) -> String {
        self.token_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/token", self.credential_issuer))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// OID4VP wallet types
// ═══════════════════════════════════════════════════════════════════════════

/// A ZK proof for one input descriptor in a presentation.
///
/// `predicate_id` follows the wire format (e.g. `"age_over_18"`, `"age_over_21"`).
/// Generation is the caller's responsibility (via `marty-zkp::Prover::prove_by_id`).
#[derive(Debug, Clone)]
pub struct ZkProofEntry {
    /// The `InputDescriptor.id` this proof satisfies.
    pub descriptor_id: String,
    /// Wire-format predicate identifier (e.g. `"age_over_18"`).
    pub predicate_id: String,
    /// ZK proof bytes from `marty-zkp::Prover`.
    pub proof_bytes: Vec<u8>,
}

/// The credential query shape used in an OpenID4VP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresentationRequestQueryType {
    PresentationDefinition,
    DcqlQuery,
}

/// A requested DCQL claim path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcqlClaimQuery {
    pub id: String,
    pub path: Vec<String>,
}

/// One credential entry in a DCQL query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcqlCredentialQuery {
    pub id: String,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<DcqlClaimQuery>,
}

/// DCQL query object carried in an OpenID4VP request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DcqlQuery {
    pub credentials: Vec<DcqlCredentialQuery>,
}

/// Parsed OpenID4VP request object retained in its original query shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPresentationRequest {
    pub client_id: String,
    pub nonce: String,
    pub response_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    pub query_type: PresentationRequestQueryType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<PresentationDefinition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dcql_query: Option<DcqlQuery>,
}

/// The verifier's response after receiving a VP token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationResponse {
    /// Whether the verifier accepted the presentation.
    pub ok: bool,
    /// Optional redirect URI returned by the verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,
    /// Optional error code (OID4VP §6.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Holder key material for wallet-controlled proof and presentation signing.
#[derive(Debug, Clone)]
pub struct HolderKeyMaterial {
    /// Self-contained P-256 did:key identifier.
    pub holder_id: String,
    /// Private P-256 JWK. Callers must store this as sensitive key material.
    pub private_jwk: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// WalletEngine
// ═══════════════════════════════════════════════════════════════════════════

/// OID4VCI/OID4VP wallet engine.
///
/// Stateless — all session state is returned to the caller rather than stored
/// internally, consistent with the pattern used by [`crate::issuer::IssuanceEngine`].
pub struct WalletEngine {
    client: reqwest::Client,
}

impl WalletEngine {
    /// Create a new wallet engine with default HTTP client settings.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("marty-wallet/0.1")
                .build()
                .expect("reqwest client init failed"),
        }
    }

    /// Generate a P-256 holder key represented as a self-contained `did:key`.
    pub fn generate_holder_key(&self) -> HolderKeyMaterial {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let encoded_point = signing_key.verifying_key().to_encoded_point(false);
        let x = encoded_point.x().expect("uncompressed P-256 point has x");
        let y = encoded_point.y().expect("uncompressed P-256 point has y");
        let mut multicodec_key = vec![0x80, 0x24];
        multicodec_key.extend_from_slice(
            signing_key.verifying_key().to_encoded_point(true).as_bytes(),
        );
        let holder_id = format!("did:key:z{}", base58btc_encode(&multicodec_key));
        let private_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y),
            "d": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
        })
        .to_string();

        HolderKeyMaterial {
            holder_id,
            private_jwk,
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Credential Offer parsing (§4)
    // ──────────────────────────────────────────────────────────────────────

    /// Parse a `openid-credential-offer://` URI or a plain
    /// `https://…?credential_offer=…` URL into a [`CredentialOffer`].
    ///
    /// Handles both inline `credential_offer` parameter (base64url-encoded JSON)
    /// and the `credential_offer_uri` redirect pattern (fetches the URI).
    pub async fn parse_credential_offer(&self, input: &str) -> Oid4vciResult<CredentialOffer> {
        // Normalise the scheme so `url::Url` can parse it.
        let url_str = if input.starts_with("openid-credential-offer://") {
            input.replacen("openid-credential-offer://", "https://offer.invalid/", 1)
        } else {
            input.to_string()
        };

        let parsed = url::Url::parse(&url_str).map_err(|e| {
            Oid4vciError::InvalidRequest(format!("Invalid credential offer URI: {}", e))
        })?;

        let params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();

        if let Some(offer_json) = params.get("credential_offer") {
            // Inline JSON (may be URL-encoded but reqwest handles that for us)
            let offer: CredentialOffer = serde_json::from_str(offer_json).map_err(|e| {
                Oid4vciError::InvalidRequest(format!("Invalid credential_offer JSON: {}", e))
            })?;
            return Ok(offer);
        }

        if let Some(offer_uri) = params.get("credential_offer_uri") {
            // Redirect pattern — fetch the offer
            let resp = self
                .client
                .get(offer_uri)
                .send()
                .await
                .map_err(|e| Oid4vciError::InvalidRequest(format!("credential_offer_uri fetch failed: {}", e)))?;

            let offer: CredentialOffer = resp.json().await.map_err(|e| {
                Oid4vciError::InvalidRequest(format!(
                    "credential_offer_uri response is not valid JSON: {}",
                    e
                ))
            })?;
            return Ok(offer);
        }

        Err(Oid4vciError::InvalidRequest(
            "No credential_offer or credential_offer_uri parameter found".into(),
        ))
    }

    // ──────────────────────────────────────────────────────────────────────
    // Issuer metadata (§12.2.2)
    // ──────────────────────────────────────────────────────────────────────

    /// Fetch and parse `.well-known/openid-credential-issuer` for `issuer_url`.
    pub async fn fetch_issuer_metadata(&self, issuer_url: &str) -> Oid4vciResult<IssuerMetadata> {
        let well_known = format!(
            "{}/.well-known/openid-credential-issuer",
            issuer_url.trim_end_matches('/')
        );

        let resp = self
            .client
            .get(&well_known)
            .send()
            .await
            .map_err(|e| Oid4vciError::InvalidRequest(format!("Metadata fetch failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(Oid4vciError::InvalidRequest(format!(
                "Metadata endpoint returned HTTP {}",
                resp.status()
            )));
        }

        resp.json::<IssuerMetadata>().await.map_err(|e| {
            Oid4vciError::InvalidRequest(format!("Metadata response parse error: {}", e))
        })
    }

    // ──────────────────────────────────────────────────────────────────────
    // Token endpoint — pre-authorized code flow (§6.1)
    // ──────────────────────────────────────────────────────────────────────

    /// Exchange a pre-authorized code for an access token.
    ///
    /// `tx_code` — the transaction PIN, if the offer requires one.
    pub async fn exchange_pre_auth_code(
        &self,
        token_endpoint: &str,
        pre_auth_code: &str,
        tx_code: Option<&str>,
    ) -> Oid4vciResult<TokenResponse> {
        let mut params = vec![
            (
                "grant_type",
                GrantType::PreAuthorizedCode.as_str().to_string(),
            ),
            ("pre-authorized_code", pre_auth_code.to_string()),
        ];
        if let Some(pin) = tx_code {
            params.push(("tx_code", pin.to_string()));
        }

        let resp = self
            .client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| Oid4vciError::InvalidRequest(format!("Token request failed: {}", e)))?;

        Self::parse_token_response(resp).await
    }

    // ──────────────────────────────────────────────────────────────────────
    // Token endpoint — authorization code + PKCE flow (§6.2 / RFC 7636)
    // ──────────────────────────────────────────────────────────────────────

    /// Build an authorization request for the authorization code + PKCE flow.
    ///
    /// Returns the request struct (for constructing the redirect URL) and the
    /// raw PKCE code verifier the caller must keep secret until token exchange.
    pub fn build_authorization_request(
        &self,
        _issuer_metadata: &IssuerMetadata,
        credential_configuration_id: &str,
        client_id: &str,
        redirect_uri: &str,
        issuer_state: Option<String>,
    ) -> Oid4vciResult<(AuthorizationRequest, String)> {
        // Generate PKCE challenge — reuse existing helper from the issuer module.
        let code_verifier = generate_random_verifier();
        let code_challenge = generate_pkce_challenge_s256(&code_verifier);

        let req = AuthorizationRequest {
            response_type: "code".into(),
            client_id: client_id.to_string(),
            redirect_uri: Some(redirect_uri.to_string()),
            scope: None,
            state: Some(generate_random_state()),
            issuer_state,
            code_challenge: Some(code_challenge),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            authorization_details: Some(vec![AuthorizationDetail {
                detail_type: "openid_credential".into(),
                credential_configuration_id: Some(credential_configuration_id.to_string()),
                format: None,
            }]),
        };

        Ok((req, code_verifier))
    }

    /// Build the authorization redirect URL from an [`AuthorizationRequest`].
    pub fn authorization_redirect_url(
        &self,
        authorization_endpoint: &str,
        req: &AuthorizationRequest,
    ) -> Oid4vciResult<String> {
        let mut url = url::Url::parse(authorization_endpoint).map_err(|e| {
            Oid4vciError::InvalidRequest(format!("Invalid authorization_endpoint: {}", e))
        })?;

        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("response_type", &req.response_type);
            pairs.append_pair("client_id", &req.client_id);
            if let Some(ref uri) = req.redirect_uri {
                pairs.append_pair("redirect_uri", uri);
            }
            if let Some(ref state) = req.state {
                pairs.append_pair("state", state);
            }
            if let Some(ref challenge) = req.code_challenge {
                pairs.append_pair("code_challenge", challenge);
                pairs.append_pair(
                    "code_challenge_method",
                    req.code_challenge_method
                        .as_ref()
                        .map(|m| m.as_str())
                        .unwrap_or("S256"),
                );
            }
            if let Some(ref issuer_state) = req.issuer_state {
                pairs.append_pair("issuer_state", issuer_state);
            }
            if let Some(ref details) = req.authorization_details {
                let details_json = serde_json::to_string(details).map_err(|e| {
                    Oid4vciError::InvalidRequest(format!(
                        "authorization_details serialization error: {}",
                        e
                    ))
                })?;
                pairs.append_pair("authorization_details", &details_json);
            }
        }

        Ok(url.to_string())
    }

    /// Exchange an authorization code (+ PKCE verifier) for an access token.
    pub async fn exchange_auth_code(
        &self,
        token_endpoint: &str,
        code: &str,
        code_verifier: &str,
        redirect_uri: Option<&str>,
        client_id: Option<&str>,
    ) -> Oid4vciResult<TokenResponse> {
        let mut params = vec![
            (
                "grant_type",
                GrantType::AuthorizationCode.as_str().to_string(),
            ),
            ("code", code.to_string()),
            ("code_verifier", code_verifier.to_string()),
        ];
        if let Some(uri) = redirect_uri {
            params.push(("redirect_uri", uri.to_string()));
        }
        if let Some(id) = client_id {
            params.push(("client_id", id.to_string()));
        }

        let resp = self
            .client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| Oid4vciError::InvalidRequest(format!("Token request failed: {}", e)))?;

        Self::parse_token_response(resp).await
    }

    // ──────────────────────────────────────────────────────────────────────
    // Proof-of-possession JWT (§8.2)
    // ──────────────────────────────────────────────────────────────────────

    /// Create an `openid4vci-proof+jwt` proof-of-possession JWT.
    ///
    /// Signs with the holder's P-256 private key (JWK JSON).  Other algorithms
    /// can be added by extending `SigningAlgorithm` in types.rs.
    ///
    /// # Arguments
    /// * `holder_kid`   — the holder DID or key URL to use as the proof issuer
    /// * `c_nonce`      — the nonce from the token response (OID4VCI §8.2)
    /// * `issuer_url`   — the credential issuer URL (goes in `aud`)
    /// * `jwk_json`     — holder's P-256 JWK (private key, JSON string)
    pub fn create_proof_jwt(
        &self,
        holder_kid: &str,
        c_nonce: &str,
        issuer_url: &str,
        jwk_json: &str,
    ) -> Oid4vciResult<String> {
        use jsonwebtoken::{encode, jwk::Jwk, Algorithm, Header};

        let encoding_key = p256_encoding_key(jwk_json)?;
        let mut public_jwk: serde_json::Value = serde_json::from_str(jwk_json)
            .map_err(|e| Oid4vciError::KeyError(format!("Invalid holder JWK: {e}")))?;
        let public_jwk_object = public_jwk.as_object_mut().ok_or_else(|| {
            Oid4vciError::KeyError("Holder JWK must be a JSON object".to_string())
        })?;
        public_jwk_object.remove("d");
        let header_jwk: Jwk = serde_json::from_value(public_jwk)
            .map_err(|e| Oid4vciError::KeyError(format!("Invalid public holder JWK: {e}")))?;

        let now = chrono::Utc::now().timestamp() as u64;
        let holder_id = holder_kid.split('#').next().unwrap_or(holder_kid);

        let claims = ProofJwtClaims {
            iss: Some(holder_id.to_string()),
            aud: issuer_url.to_string(),
            iat: now,
            nonce: c_nonce.to_string(),
        };

        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("openid4vci-proof+jwt".into());
        header.jwk = Some(header_jwk);

        encode(&header, &claims, &encoding_key)
            .map_err(|e| Oid4vciError::SigningError(format!("JWT signing failed: {}", e)))
    }

    /// Create a selectively disclosed SD-JWT VC presentation with a KB-JWT.
    ///
    /// The key-binding JWT binds the presentation to the verifier's audience
    /// and nonce. The private JWK must correspond to the public key in the
    /// credential's `cnf` claim.
    pub fn create_sd_jwt_presentation(
        &self,
        credential: &str,
        claims_to_disclose: &[String],
        nonce: &str,
        audience: &str,
        holder_jwk_json: &str,
    ) -> Oid4vciResult<String> {
        use sd_jwt_rs::{SDJWTHolder, SDJWTSerializationFormat};

        let disclosures = claims_to_disclose
            .iter()
            .map(|claim| (claim.clone(), serde_json::Value::Bool(true)))
            .collect();
        let encoding_key = p256_encoding_key(holder_jwk_json)?;
        let mut holder = SDJWTHolder::new(
            credential.to_string(),
            SDJWTSerializationFormat::Compact,
        )
        .map_err(|error| {
            Oid4vciError::InvalidRequest(format!("Invalid SD-JWT credential: {error:?}"))
        })?;

        holder
            .create_presentation(
                disclosures,
                Some(nonce.to_string()),
                Some(audience.to_string()),
                Some(encoding_key),
                Some("ES256".to_string()),
            )
            .map_err(|error| {
                Oid4vciError::SigningError(format!(
                    "SD-JWT presentation creation failed: {error:?}"
                ))
            })
    }

    // ──────────────────────────────────────────────────────────────────────
    // Credential request (§8)
    // ──────────────────────────────────────────────────────────────────────

    /// Post a credential request to the issuer's credential endpoint.
    ///
    /// `proof_jwt` — the PoP JWT from [`WalletEngine::create_proof_jwt`].
    pub async fn request_credential(
        &self,
        credential_endpoint: &str,
        access_token: &str,
        format: &CredentialFormat,
        credential_configuration_id: Option<&str>,
        proof_jwt: &str,
    ) -> Oid4vciResult<CredentialResponse> {
        let req = CredentialRequest {
            format: Some(format.as_str().to_string()),
            credential_configuration_id: credential_configuration_id.map(|s| s.to_string()),
            credential_identifier: None,
            proofs: Some(ProofsObject {
                jwt: Some(vec![proof_jwt.to_string()]),
            }),
            credential_definition: None,
            vct: None,
            doctype: None,
            claims: None,
        };

        let resp = self
            .client
            .post(credential_endpoint)
            .bearer_auth(access_token)
            .json(&req)
            .send()
            .await
            .map_err(|e| {
                Oid4vciError::InvalidRequest(format!("Credential request failed: {}", e))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(Oid4vciError::InvalidRequest(format!(
                "Credential endpoint returned HTTP {}: {}",
                status, body
            )));
        }

        resp.json::<CredentialResponse>().await.map_err(|e| {
            Oid4vciError::InvalidRequest(format!("Credential response parse error: {}", e))
        })
    }

    // ──────────────────────────────────────────────────────────────────────
    // OID4VP — parse incoming presentation request (§5)
    // ──────────────────────────────────────────────────────────────────────

    /// Parse an `openid4vp://` request URI into a full request object.
    ///
    /// Handles inline JSON, `request_uri`, `presentation_definition_uri`, and
    /// request objects returned as signed JWT payloads.
    pub async fn parse_presentation_request(
        &self,
        input: &str,
    ) -> Oid4vciResult<ParsedPresentationRequest> {
        let url_str = if input.starts_with("openid4vp://") {
            input.replacen("openid4vp://", "https://vp.invalid/", 1)
        } else {
            input.to_string()
        };

        let parsed = url::Url::parse(&url_str).map_err(|e| {
            Oid4vciError::InvalidRequest(format!("Invalid presentation request URI: {}", e))
        })?;

        let params: HashMap<String, String> = parsed.query_pairs().into_owned().collect();

        let inline_request = Self::request_object_from_params(&params)?;

        if let Some(request_uri) = params.get("request_uri") {
            let fetched = self.fetch_request_object_value(request_uri).await?;
            return Self::parsed_request_from_value(
                Self::merge_request_objects(fetched, serde_json::Value::Object(inline_request)),
            );
        }

        if let Some(presentation_definition_uri) = params.get("presentation_definition_uri") {
            let fetched = self.fetch_request_object_value(presentation_definition_uri).await?;
            let pd_value = fetched
                .get("presentation_definition")
                .cloned()
                .unwrap_or(fetched);
            let mut inline_with_pd = inline_request;
            inline_with_pd.insert("presentation_definition".into(), pd_value);
            return Self::parsed_request_from_value(serde_json::Value::Object(inline_with_pd));
        }

        if !inline_request.is_empty() {
            return Self::parsed_request_from_value(serde_json::Value::Object(inline_request));
        }

        if input.starts_with("http://") || input.starts_with("https://") {
            let fetched = self.fetch_request_object_value(input).await?;
            return Self::parsed_request_from_value(fetched);
        }

        Err(Oid4vciError::InvalidRequest(
            "No presentation_definition, dcql_query, request_uri or presentation_definition_uri found".into(),
        ))
    }

    // ──────────────────────────────────────────────────────────────────────
    // OID4VP — build and submit presentations (§6)
    // ──────────────────────────────────────────────────────────────────────

    /// Build a standard (non-ZK) presentation submission.
    ///
    /// `credentials` — map of descriptor ID → VP token/credential bytes (format-encoded).
    /// Returns a [`PresentationSubmission`] and a serialized `vp_token`.
    pub fn build_presentation_submission(
        &self,
        definition: &PresentationDefinition,
        credentials: HashMap<String, String>,
    ) -> Oid4vciResult<(String, PresentationSubmission)> {
        let vp_id = uuid::Uuid::new_v4().to_string();

        let descriptor_map: Vec<DescriptorMapEntry> = definition
            .input_descriptors
            .iter()
            .map(|desc| {
                let format = credentials
                    .get(&desc.id)
                    .and_then(|cred| infer_format(cred))
                    .unwrap_or("jwt_vc_json");

                DescriptorMapEntry {
                    id: desc.id.clone(),
                    format: format.to_string(),
                    path: "$".to_string(),
                    path_nested: None,
                }
            })
            .collect();

        // Build a minimal VP envelope
        let vp_claims: Vec<serde_json::Value> = definition
            .input_descriptors
            .iter()
            .filter_map(|desc| credentials.get(&desc.id))
            .map(|cred| serde_json::Value::String(cred.clone()))
            .collect();

        let vp_token = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": vp_claims
        })
        .to_string();

        let submission = PresentationSubmission {
            id: vp_id,
            definition_id: definition.id.clone(),
            descriptor_map,
        };

        Ok((vp_token, submission))
    }

    /// Build a VP for either a Presentation Exchange or a DCQL request.
    pub fn build_presentation_for_request(
        &self,
        request: &ParsedPresentationRequest,
        credentials: HashMap<String, String>,
    ) -> Oid4vciResult<(String, Option<PresentationSubmission>)> {
        if request.query_type == PresentationRequestQueryType::DcqlQuery {
            let dcql_query = request.dcql_query.as_ref().ok_or_else(|| {
                Oid4vciError::InvalidRequest(
                    "DCQL request is missing dcql_query payload".into(),
                )
            })?;
            return self.build_dcql_presentation(dcql_query, credentials);
        }

        let definition = request.presentation_definition.as_ref().ok_or_else(|| {
            Oid4vciError::InvalidRequest(
                "Presentation definition request is missing presentation_definition payload".into(),
            )
        })?;
        let (vp_token, submission) = self.build_presentation_submission(definition, credentials)?;
        Ok((vp_token, Some(submission)))
    }

    fn build_dcql_presentation(
        &self,
        dcql_query: &DcqlQuery,
        credentials: HashMap<String, String>,
    ) -> Oid4vciResult<(String, Option<PresentationSubmission>)> {
        let mut vp_tokens = serde_json::Map::new();
        for query in &dcql_query.credentials {
            if let Some(credential) = credentials.get(&query.id) {
                vp_tokens.insert(
                    query.id.clone(),
                    serde_json::Value::Array(vec![serde_json::Value::String(
                        credential.clone(),
                    )]),
                );
            }
        }

        if vp_tokens.is_empty() {
            return Err(Oid4vciError::InvalidRequest(
                "No credentials satisfy the DCQL query".into(),
            ));
        }

        let vp_token = serde_json::Value::Object(vp_tokens).to_string();

        Ok((vp_token, None))
    }

    /// Build a ZK presentation submission.
    ///
    /// For each ZK-requested field in the definition, one [`ZkProofEntry`]
    /// must be provided.  Standard (non-ZK) descriptors use `credentials`.
    ///
    /// ZK proof generation is intentionally kept outside this method so that
    /// the caller controls key material and `marty-zkp` invocation.
    pub fn build_zk_presentation(
        &self,
        definition: &PresentationDefinition,
        credentials: HashMap<String, String>,
        zk_proofs: Vec<ZkProofEntry>,
    ) -> Oid4vciResult<(String, PresentationSubmission)> {
        let vp_id = uuid::Uuid::new_v4().to_string();
        let zk_proofs_by_id: HashMap<_, _> =
            zk_proofs.iter().map(|e| (e.descriptor_id.as_str(), e)).collect();

        let mut descriptor_map = vec![];
        let mut vp_credentials = vec![];
        let mut zk_proof_map: HashMap<String, serde_json::Value> = HashMap::new();

        for desc in &definition.input_descriptors {
            let has_zk = desc.constraints.fields.iter().any(|f| f.zk_predicate.is_some());

            if has_zk {
                // ZK path — embed the proof, not the raw credential
                let entry = zk_proofs_by_id.get(desc.id.as_str()).ok_or_else(|| {
                    Oid4vciError::InvalidRequest(format!(
                        "Missing ZK proof for descriptor '{}'",
                        desc.id
                    ))
                })?;

                let proof_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&entry.proof_bytes);

                zk_proof_map.insert(
                    desc.id.clone(),
                    serde_json::json!({
                        "predicate": entry.predicate_id,
                        "proof": proof_b64,
                        "proof_type": crate::formats::zk_mdoc::ZK_PROOF_TYPE_LIGERO,
                    }),
                );

                descriptor_map.push(DescriptorMapEntry {
                    id: desc.id.clone(),
                    format: "zk_mdoc".to_string(),
                    path: format!("$.zk_proofs.{}", desc.id),
                    path_nested: None,
                });
            } else {
                // Standard path
                if let Some(cred) = credentials.get(&desc.id) {
                    let format = infer_format(cred).unwrap_or("jwt_vc_json");
                    vp_credentials.push(serde_json::Value::String(cred.clone()));
                    descriptor_map.push(DescriptorMapEntry {
                        id: desc.id.clone(),
                        format: format.to_string(),
                        path: format!("$.verifiableCredential[{}]", vp_credentials.len() - 1),
                        path_nested: None,
                    });
                }
            }
        }

        let vp_token = serde_json::json!({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": vp_credentials,
            "zk_proofs": zk_proof_map,
        })
        .to_string();

        let submission = PresentationSubmission {
            id: vp_id,
            definition_id: definition.id.clone(),
            descriptor_map,
        };

        Ok((vp_token, submission))
    }

    /// POST a VP token + submission to the verifier's `response_uri`.
    pub async fn submit_presentation(
        &self,
        response_uri: &str,
        vp_token: &str,
        presentation_submission: &PresentationSubmission,
    ) -> Oid4vciResult<PresentationResponse> {
        self.submit_presentation_optional(response_uri, vp_token, Some(presentation_submission))
            .await
    }

    /// POST a VP token and an optional presentation submission to the verifier.
    pub async fn submit_presentation_optional(
        &self,
        response_uri: &str,
        vp_token: &str,
        presentation_submission: Option<&PresentationSubmission>,
    ) -> Oid4vciResult<PresentationResponse> {
        self.submit_presentation_form(
            response_uri,
            vp_token,
            presentation_submission,
            None,
        )
        .await
    }

    /// Submit a response for a parsed request, including its state value.
    pub async fn submit_presentation_for_request(
        &self,
        request: &ParsedPresentationRequest,
        vp_token: &str,
        presentation_submission: Option<&PresentationSubmission>,
    ) -> Oid4vciResult<PresentationResponse> {
        self.submit_presentation_form(
            &request.response_uri,
            vp_token,
            presentation_submission,
            request.state.as_deref(),
        )
        .await
    }

    async fn submit_presentation_form(
        &self,
        response_uri: &str,
        vp_token: &str,
        presentation_submission: Option<&PresentationSubmission>,
        state: Option<&str>,
    ) -> Oid4vciResult<PresentationResponse> {
        let mut params: Vec<(String, String)> = vec![("vp_token".to_string(), vp_token.to_string())];
        if let Some(submission) = presentation_submission {
            let submission_json = serde_json::to_string(submission).map_err(|e| {
                Oid4vciError::InvalidRequest(format!(
                    "Presentation submission serialization error: {}",
                    e
                ))
            })?;
            params.push(("presentation_submission".to_string(), submission_json));
        }
        if let Some(state) = state {
            params.push(("state".to_string(), state.to_string()));
        }

        let resp = self
            .client
            .post(response_uri)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                Oid4vciError::InvalidRequest(format!("Presentation submission failed: {}", e))
            })?;

        let status = resp.status();
        let body: serde_json::Value =
            resp.json().await.unwrap_or(serde_json::Value::Object(Default::default()));

        if status.is_success() {
            Ok(PresentationResponse {
                ok: true,
                redirect_uri: body
                    .get("redirect_uri")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                error: None,
                error_description: None,
            })
        } else {
            Ok(PresentationResponse {
                ok: false,
                redirect_uri: None,
                error: body
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                error_description: body
                    .get("error_description")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            })
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // Internal helpers
    // ──────────────────────────────────────────────────────────────────────

    async fn parse_token_response(resp: reqwest::Response) -> Oid4vciResult<TokenResponse> {
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Oid4vciError::InvalidRequest(format!(
                "Token endpoint returned HTTP {}: {}",
                status, body
            )));
        }
        resp.json::<TokenResponse>().await.map_err(|e| {
            Oid4vciError::InvalidRequest(format!("Token response parse error: {}", e))
        })
    }

    fn request_object_from_params(
        params: &HashMap<String, String>,
    ) -> Oid4vciResult<serde_json::Map<String, serde_json::Value>> {
        let mut request = serde_json::Map::new();

        for key in [
            "response_type",
            "client_id",
            "client_id_scheme",
            "nonce",
            "response_mode",
            "response_uri",
            "redirect_uri",
            "state",
        ] {
            if let Some(value) = params.get(key) {
                request.insert(key.to_string(), serde_json::Value::String(value.clone()));
            }
        }

        if let Some(pd_json) = params.get("presentation_definition") {
            let pd_value = serde_json::from_str(pd_json).map_err(|e| {
                Oid4vciError::InvalidRequest(format!(
                    "Invalid presentation_definition JSON: {}",
                    e
                ))
            })?;
            request.insert("presentation_definition".into(), pd_value);
        }

        if let Some(dcql_json) = params.get("dcql_query") {
            let dcql_value = serde_json::from_str(dcql_json).map_err(|e| {
                Oid4vciError::InvalidRequest(format!(
                    "Invalid dcql_query JSON: {}",
                    e
                ))
            })?;
            request.insert("dcql_query".into(), dcql_value);
        }

        Ok(request)
    }

    fn merge_request_objects(
        primary: serde_json::Value,
        fallback: serde_json::Value,
    ) -> serde_json::Value {
        let mut merged = match primary {
            serde_json::Value::Object(object) => object,
            other => return other,
        };

        if let serde_json::Value::Object(fallback_object) = fallback {
            for (key, value) in fallback_object {
                merged.entry(key).or_insert(value);
            }
        }

        serde_json::Value::Object(merged)
    }

    async fn fetch_request_object_value(
        &self,
        uri: &str,
    ) -> Oid4vciResult<serde_json::Value> {
        let resp = self
            .client
            .get(uri)
            .send()
            .await
            .map_err(|e| {
                Oid4vciError::InvalidRequest(format!("Request object fetch failed: {}", e))
            })?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Oid4vciError::InvalidRequest(format!(
                "Request object endpoint returned HTTP {}: {}",
                status, body
            )));
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp.text().await.map_err(|e| {
            Oid4vciError::InvalidRequest(format!("Request object read failed: {}", e))
        })?;

        Self::decode_request_object_body(&body, Some(content_type.as_str()))
    }

    fn decode_request_object_body(
        body: &str,
        content_type: Option<&str>,
    ) -> Oid4vciResult<serde_json::Value> {
        let trimmed = body.trim();
        let is_jwt = content_type.map(|value| value.contains("jwt")).unwrap_or(false)
            || Self::looks_like_compact_jwt(trimmed);

        if is_jwt {
            return Self::decode_jwt_payload(trimmed);
        }

        serde_json::from_str(trimmed).map_err(|e| {
            Oid4vciError::InvalidRequest(format!(
                "Request object response parse error: {}",
                e
            ))
        })
    }

    fn looks_like_compact_jwt(body: &str) -> bool {
        let trimmed = body.trim();
        trimmed.split('.').count() == 3 && !trimmed.starts_with('{')
    }

    fn decode_jwt_payload(jwt: &str) -> Oid4vciResult<serde_json::Value> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(Oid4vciError::InvalidRequest(
                "Request object JWT must use compact serialization".into(),
            ));
        }

        let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(parts[1]))
            .map_err(|e| {
                Oid4vciError::InvalidRequest(format!(
                    "Request object JWT payload decode error: {}",
                    e
                ))
            })?;

        serde_json::from_slice(&payload_bytes).map_err(|e| {
            Oid4vciError::InvalidRequest(format!(
                "Request object JWT payload parse error: {}",
                e
            ))
        })
    }

    fn parsed_request_from_value(value: serde_json::Value) -> Oid4vciResult<ParsedPresentationRequest> {
        let Some(request) = value.as_object() else {
            return Err(Oid4vciError::InvalidRequest(
                "Presentation request object must be a JSON object".into(),
            ));
        };

        let presentation_definition = match request.get("presentation_definition") {
            Some(pd_value) => Some(serde_json::from_value(pd_value.clone()).map_err(|e| {
                Oid4vciError::InvalidRequest(format!(
                    "presentation_definition parse error: {}",
                    e
                ))
            })?),
            None => None,
        };

        let dcql_query = match request.get("dcql_query") {
            Some(dcql_value) => Some(serde_json::from_value(dcql_value.clone()).map_err(|e| {
                Oid4vciError::InvalidRequest(format!(
                    "dcql_query parse error: {}",
                    e
                ))
            })?),
            None => None,
        };

        let query_type = if dcql_query.is_some() {
            PresentationRequestQueryType::DcqlQuery
        } else if presentation_definition.is_some() {
            PresentationRequestQueryType::PresentationDefinition
        } else {
            return Err(Oid4vciError::InvalidRequest(
                "Presentation request must include presentation_definition or dcql_query".into(),
            ));
        };

        Ok(ParsedPresentationRequest {
            client_id: request
                .get("client_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            nonce: request
                .get("nonce")
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            response_uri: request
                .get("response_uri")
                .or_else(|| request.get("redirect_uri"))
                .and_then(|value| value.as_str())
                .unwrap_or_default()
                .to_string(),
            response_mode: request
                .get("response_mode")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            state: request
                .get("state")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
            query_type,
            presentation_definition,
            dcql_query,
        })
    }
}

impl Default for WalletEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// PoP JWT claims
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize)]
struct ProofJwtClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    aud: String,
    iat: u64,
    nonce: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// PKCE helpers
// ═══════════════════════════════════════════════════════════════════════════

fn generate_random_verifier() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_random_state() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base58btc_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let leading_zeroes = data.iter().take_while(|&&byte| byte == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for digit in &mut digits {
            carry += (*digit as u32) * 256;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    digits.extend(std::iter::repeat(0).take(leading_zeroes));
    digits.reverse();
    digits
        .iter()
        .map(|&digit| ALPHABET[digit as usize] as char)
        .collect()
}

fn p256_encoding_key(jwk_json: &str) -> Oid4vciResult<jsonwebtoken::EncodingKey> {
    use p256::pkcs8::EncodePrivateKey as _;

    let jwk: serde_json::Value = serde_json::from_str(jwk_json)
        .map_err(|e| Oid4vciError::InvalidRequest(format!("Invalid JWK JSON: {e}")))?;
    if jwk.get("kty").and_then(|value| value.as_str()) != Some("EC")
        || jwk.get("crv").and_then(|value| value.as_str()) != Some("P-256")
    {
        return Err(Oid4vciError::InvalidRequest(
            "Holder JWK must be an EC P-256 key".into(),
        ));
    }
    let d_b64 = jwk
        .get("d")
        .and_then(|value| value.as_str())
        .ok_or_else(|| Oid4vciError::InvalidRequest("JWK missing 'd' (private key)".into()))?;
    let d_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(d_b64)
        .map_err(|e| Oid4vciError::InvalidRequest(format!("JWK 'd' decode error: {e}")))?;
    let secret_key = p256::SecretKey::from_slice(&d_bytes)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 private key: {e}")))?;
    let der = secret_key
        .to_pkcs8_der()
        .map_err(|e| Oid4vciError::KeyError(format!("PKCS#8 DER encoding failed: {e}")))?;

    Ok(jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes()))
}

// ═══════════════════════════════════════════════════════════════════════════
// Format detection heuristic
// ═══════════════════════════════════════════════════════════════════════════

/// Infer a credential format string from the raw credential value.
fn infer_format(cred: &str) -> Option<&'static str> {
    if cred.contains('~') {
        Some("dc+sd-jwt")
    } else if cred.starts_with('{') {
        Some("mso_mdoc")
    } else {
        // Treat as JWT
        Some("jwt_vc_json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_query_json(value: &str) -> String {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
    }

    #[tokio::test]
    async fn parse_presentation_request_by_value_dcql() {
        let engine = WalletEngine::new();
        let dcql_query = r#"{"credentials":[{"id":"member_credential","format":"dc+sd-jwt","claims":[{"id":"claim_email","path":["email"]}]}]}"#;
        let request_uri = format!(
            "openid4vp://authorize?client_id={}&nonce=nonce-123&response_uri={}&dcql_query={}",
            encode_query_json("https://verifier.example"),
            encode_query_json("https://verifier.example/submit"),
            encode_query_json(dcql_query),
        );

        let parsed = engine.parse_presentation_request(&request_uri).await.unwrap();

        assert_eq!(parsed.client_id, "https://verifier.example");
        assert_eq!(parsed.nonce, "nonce-123");
        assert_eq!(parsed.response_uri, "https://verifier.example/submit");
        assert_eq!(parsed.query_type, PresentationRequestQueryType::DcqlQuery);
        assert!(parsed.presentation_definition.is_none());
        let dcql_query = parsed.dcql_query.expect("dcql_query should be present");
        assert_eq!(dcql_query.credentials.len(), 1);
        assert_eq!(dcql_query.credentials[0].id, "member_credential");
        assert_eq!(dcql_query.credentials[0].format, "dc+sd-jwt");
    }

    #[test]
    fn generated_holder_key_creates_verifiable_proof() {
        let engine = WalletEngine::new();
        let holder = engine.generate_holder_key();
        let proof = engine
            .create_proof_jwt(
                &format!("{}#{}", holder.holder_id, holder.holder_id),
                "nonce-123",
                "https://issuer.example",
                &holder.private_jwk,
            )
            .unwrap();

        let verified = crate::proof::verify_jwt_proof(
            &proof,
            "https://issuer.example",
            Some("nonce-123"),
            300,
        )
        .unwrap();
        assert_eq!(verified.holder_id, holder.holder_id);
        let holder_jwk = verified.holder_jwk.expect("proof must expose the holder public JWK");
        let holder_jwk_json = serde_json::to_value(holder_jwk).unwrap();
        assert_eq!(holder_jwk_json["kty"], "EC");
        assert_eq!(holder_jwk_json["crv"], "P-256");
        assert!(holder_jwk_json.get("d").is_none());
    }

    #[test]
    fn decode_request_object_body_supports_signed_request_jwt() {
        let body = format!(
            "eyJhbGciOiJFUzI1NiJ9.{}.signature",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                r#"{"client_id":"https://verifier.example","nonce":"nonce-123","response_uri":"https://verifier.example/submit","dcql_query":{"credentials":[{"id":"member_credential","format":"dc+sd-jwt"}]}}"#
            )
        );

        let decoded = WalletEngine::decode_request_object_body(
            &body,
            Some("application/oauth-authz-req+jwt"),
        )
        .unwrap();

        assert_eq!(decoded["client_id"], "https://verifier.example");
        assert!(decoded.get("dcql_query").is_some());
    }

    #[test]
    fn build_presentation_for_dcql_omits_presentation_submission() {
        let engine = WalletEngine::new();
        let request = ParsedPresentationRequest {
            client_id: "https://verifier.example".into(),
            nonce: "nonce-123".into(),
            response_uri: "https://verifier.example/submit".into(),
            response_mode: Some("direct_post".into()),
            state: None,
            query_type: PresentationRequestQueryType::DcqlQuery,
            presentation_definition: None,
            dcql_query: Some(DcqlQuery {
                credentials: vec![DcqlCredentialQuery {
                    id: "member_credential".into(),
                    format: "dc+sd-jwt".into(),
                    meta: None,
                    claims: vec![DcqlClaimQuery {
                        id: "claim_email".into(),
                        path: vec!["email".into()],
                    }],
                }],
            }),
        };
        let credentials = HashMap::from([(
            "member_credential".to_string(),
            "credential.jwt".to_string(),
        )]);

        let (vp_token, submission) = engine
            .build_presentation_for_request(&request, credentials)
            .unwrap();

        assert!(submission.is_none());
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&vp_token).unwrap(),
            serde_json::json!({"member_credential": ["credential.jwt"]})
        );
    }

    #[test]
    fn create_sd_jwt_presentation_adds_nonce_audience_and_dcql_shape() {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;
        use p256::pkcs8::EncodePrivateKey as _;
        use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
        use sd_jwt_rs::{SDJWTIssuer, SDJWTSerializationFormat};

        let issuer_key = SigningKey::random(&mut OsRng);
        let issuer_der = issuer_key.to_pkcs8_der().unwrap();
        let holder_key = SigningKey::random(&mut OsRng);
        let holder_point = holder_key.verifying_key().to_encoded_point(false);
        let private_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(holder_point.x().unwrap()),
            "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(holder_point.y().unwrap()),
            "d": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(holder_key.to_bytes()),
        });
        let public_jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": private_jwk["x"],
            "y": private_jwk["y"],
        }))
        .unwrap();
        let credential = SDJWTIssuer::new(
            jsonwebtoken::EncodingKey::from_ec_der(issuer_der.as_bytes()),
            Some("ES256".to_string()),
        )
        .issue_sd_jwt(
            serde_json::json!({"email": "member@example.com", "role": "member"}),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            Some(public_jwk),
            false,
            SDJWTSerializationFormat::Compact,
        )
        .unwrap();

        let presentation = WalletEngine::new()
            .create_sd_jwt_presentation(
                &credential,
                &["email".to_string()],
                "nonce-123",
                "https://verifier.example",
                &private_jwk.to_string(),
            )
            .unwrap();
        let kb_jwt = presentation
            .split('~')
            .filter(|part| !part.is_empty())
            .next_back()
            .unwrap();
        let payload = WalletEngine::decode_jwt_payload(kb_jwt).unwrap();

        assert_eq!(payload["nonce"], "nonce-123");
        assert_eq!(payload["aud"], "https://verifier.example");
        assert!(payload["sd_hash"].as_str().is_some());
        assert!(presentation.contains('~'));
    }
}
