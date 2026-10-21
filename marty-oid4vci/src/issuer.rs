//! OID4VCI Issuance Engine.
//!
//! Implements the core protocol state machine for OID4VCI v1 issuance:
//!
//! ```text
//!   [Issuer] ──offer──> [Wallet]
//!   [Wallet] ──token──> [Issuer]  (pre-authorized code exchange)
//!   [Issuer] ──token──> [Wallet]  (access_token)
//!   [Wallet] ──nonce──> [Issuer]  (empty, unauthenticated POST)
//!   [Issuer] ──nonce──> [Wallet]  (c_nonce, no-store)
//!   [Wallet] ──cred───> [Issuer]  (credential request with PoP proof)
//!   [Issuer] ──cred───> [Wallet]  (credential signed by remote KMS)
//! ```
//!
//! This engine is *stateless* — it does not persist offers, tokens, or nonces.
//! State management (Redis, DB, etc.) is the responsibility of the calling
//! service layer. The engine performs stateless protocol logic; credential
//! preparation and remote signing use the format-specific issuer APIs.

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::metadata::{IssuerMetadata, MetadataBuilder};
use crate::types::*;

#[cfg(test)]
use std::collections::HashMap;

// =============================================================================
// IssuanceEngine
// =============================================================================

/// The main OID4VCI issuance engine.
///
/// Performs protocol operations (offer creation and token exchange) without
/// managing state. The caller is responsible for persisting
/// and retrieving offers, tokens, and nonces.
///
/// # Example
/// ```rust,ignore
/// let engine = IssuanceEngine::new(issuer_config);
///
/// // 1. Create an offer
/// let offer = engine.create_offer(&OfferConfig { ... })?;
///
/// // 2. Exchange pre-authorized code for token (caller validates code)
/// let token_resp = engine.create_token_response("code123", 300)?;
///
/// // 3. Verify the holder proof and prepare the credential for remote signing.
/// ```
pub struct IssuanceEngine {
    config: IssuerConfig,
}

impl IssuanceEngine {
    /// Create a new issuance engine with the given configuration.
    pub fn new(config: IssuerConfig) -> Self {
        IssuanceEngine { config }
    }

    /// Get the issuer configuration.
    pub fn config(&self) -> &IssuerConfig {
        &self.config
    }

    // ── Offer Creation (§4) ──────────────────────────────────────────

    /// Create a credential offer.
    ///
    /// Returns the serialized offer as a JSON string and the raw struct.
    pub fn create_offer(&self, offer_config: &OfferConfig) -> Oid4vciResult<CredentialOffer> {
        if offer_config.credential_configuration_ids.is_empty() {
            return Err(Oid4vciError::InvalidOffer(
                "At least one credential_configuration_id is required".into(),
            ));
        }

        let grants = if let Some(ref code) = offer_config.pre_authorized_code {
            CredentialOfferGrants {
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: code.clone(),
                    tx_code: if offer_config.user_pin_required {
                        Some(TransactionCode {
                            input_mode: Some("numeric".into()),
                            length: Some(6),
                            description: Some("Please enter the transaction code".into()),
                        })
                    } else {
                        None
                    },
                }),
                authorization_code: None,
            }
        } else {
            CredentialOfferGrants {
                pre_authorized_code: None,
                authorization_code: Some(AuthorizationCodeGrant {
                    issuer_state: offer_config
                        .issuer_state
                        .clone()
                        .or_else(|| Some(uuid::Uuid::new_v4().to_string())),
                    authorization_server: None,
                }),
            }
        };

        Ok(CredentialOffer {
            credential_issuer: self.config.credential_issuer_url.clone(),
            credential_configuration_ids: offer_config.credential_configuration_ids.clone(),
            grants,
        })
    }

    /// Serialize a credential offer to JSON.
    pub fn offer_to_json(&self, offer: &CredentialOffer) -> Oid4vciResult<String> {
        serde_json::to_string(offer).map_err(|e| Oid4vciError::SerializationError(e.to_string()))
    }

    /// Generate a credential offer URI for QR code display.
    ///
    /// Supports two URI schemes:
    /// - `"oid4vci"` (default): `openid-credential-offer://?credential_offer_uri=...`
    /// - `"microsoft"`: `openid-vc://?request_uri=...`
    pub fn generate_offer_uri(
        &self,
        offer_id: &str,
        scheme: Option<&str>,
    ) -> Oid4vciResult<String> {
        Ok(generate_offer_uri(
            &self.config.credential_issuer_url,
            offer_id,
            scheme.unwrap_or("oid4vci"),
        ))
    }

    // ── Authorization Endpoint (§5) ─────────────────────────────────

    /// Process an authorization request and create an authorization
    /// response containing an authorization code.
    ///
    /// The caller is responsible for:
    /// 1. Authenticating the user (e.g. via Keycloak, login form, etc.)
    /// 2. Persisting the returned [`AuthorizationSession`] for later
    ///    validation at the token endpoint
    ///
    /// Returns `(AuthorizationResponse, AuthorizationSession)`.
    pub fn create_authorization_response(
        &self,
        request: &AuthorizationRequest,
        session_lifetime_secs: u64,
    ) -> Oid4vciResult<(AuthorizationResponse, AuthorizationSession)> {
        if request.response_type != "code" {
            return Err(Oid4vciError::InvalidOffer(
                "response_type must be 'code'".into(),
            ));
        }

        // Validate PKCE if provided
        if let Some(ref method) = request.code_challenge_method {
            if *method != CodeChallengeMethod::S256 && *method != CodeChallengeMethod::Plain {
                return Err(Oid4vciError::InvalidOffer(
                    "Unsupported code_challenge_method".into(),
                ));
            }
            if request.code_challenge.is_none() {
                return Err(Oid4vciError::InvalidOffer(
                    "code_challenge required when code_challenge_method is present".into(),
                ));
            }
        }

        let code = format!("ac_{}", uuid::Uuid::new_v4());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let credential_config_ids: Vec<String> = request
            .authorization_details
            .as_ref()
            .map(|details| {
                details
                    .iter()
                    .filter_map(|d| d.credential_configuration_id.clone())
                    .collect()
            })
            .unwrap_or_default();

        let session = AuthorizationSession {
            code: code.clone(),
            client_id: request.client_id.clone(),
            redirect_uri: request.redirect_uri.clone(),
            code_challenge: request.code_challenge.clone(),
            code_challenge_method: request.code_challenge_method.clone(),
            issuer_state: request.issuer_state.clone(),
            credential_configuration_ids: credential_config_ids,
            created_at: now,
            expires_in: session_lifetime_secs,
        };

        let response = AuthorizationResponse {
            code,
            state: request.state.clone(),
        };

        Ok((response, session))
    }

    // ── Token Exchange (§6) ──────────────────────────────────────────

    /// Create a token response for a pre-authorized code exchange.
    ///
    /// The caller is responsible for:
    /// 1. Validating the pre-authorized code is genuine and not expired
    /// 2. Verifying the tx_code (PIN) if required
    /// 3. Persisting the access token for later validation
    ///
    /// This function generates an OID4VCI 1.0 Final token response. Proof
    /// nonces are obtained separately from the Nonce Endpoint.
    pub fn create_token_response(
        &self,
        _pre_authorized_code: &str,
        token_lifetime_secs: u64,
    ) -> Oid4vciResult<TokenResponse> {
        let access_token = format!("at_{}", uuid::Uuid::new_v4());
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: token_lifetime_secs,
            scope: None,
        })
    }

    /// Create a response for the unauthenticated OID4VCI Nonce Endpoint.
    pub fn create_nonce_response(&self) -> NonceResponse {
        NonceResponse {
            c_nonce: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Create a token response for an authorization code exchange.
    ///
    /// The caller is responsible for:
    /// 1. Looking up the [`AuthorizationSession`] by the provided code
    /// 2. Verifying the session is not expired
    /// 3. Invalidating the session after use (one-time use)
    /// 4. Persisting the access token for later validation
    ///
    /// This method validates:
    /// - The grant_type is `authorization_code`
    /// - redirect_uri matches the original authorization request
    /// - PKCE code_verifier matches the stored code_challenge
    pub fn create_token_response_for_auth_code(
        &self,
        request: &AuthorizationCodeTokenRequest,
        session: &AuthorizationSession,
        token_lifetime_secs: u64,
    ) -> Oid4vciResult<TokenResponse> {
        // Validate grant_type
        if request.grant_type != "authorization_code" {
            return Err(Oid4vciError::InvalidPreAuthCode(
                "grant_type must be 'authorization_code'".into(),
            ));
        }

        // Validate redirect_uri matches
        if session.redirect_uri.is_some() && request.redirect_uri != session.redirect_uri {
            return Err(Oid4vciError::InvalidPreAuthCode(
                "redirect_uri mismatch".into(),
            ));
        }

        // Validate PKCE code_verifier
        if let Some(ref stored_challenge) = session.code_challenge {
            let verifier = request.code_verifier.as_deref().ok_or_else(|| {
                Oid4vciError::InvalidPreAuthCode("code_verifier required (PKCE)".into())
            })?;

            let method = session
                .code_challenge_method
                .as_ref()
                .unwrap_or(&CodeChallengeMethod::Plain);

            let valid = match method {
                CodeChallengeMethod::S256 => verify_pkce_s256(verifier, stored_challenge),
                CodeChallengeMethod::Plain => verifier == stored_challenge.as_str(),
            };

            if !valid {
                return Err(Oid4vciError::InvalidPreAuthCode(
                    "PKCE code_verifier does not match code_challenge".into(),
                ));
            }
        }

        // Generate token response (same shape as pre-auth flow)
        let access_token = format!("at_{}", uuid::Uuid::new_v4());
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".into(),
            expires_in: token_lifetime_secs,
            scope: None,
        })
    }

    // Metadata

    /// Generate the complete issuer metadata document.
    pub fn generate_metadata(&self) -> IssuerMetadata {
        let mut builder =
            MetadataBuilder::new(&self.config.credential_issuer_url, &self.config.issuer_name);

        // Nonce endpoint
        builder = builder.nonce_endpoint(format!("{}/nonce", self.config.credential_issuer_url));

        // Authorization endpoint (if authorization code flow is supported)
        if let Some(ref auth_ep) = self.config.authorization_endpoint {
            builder = builder.authorization_endpoint(auth_ep.clone());
        }

        // Add credential types
        for ctype in &self.config.credential_types {
            builder = builder.add_credential_type(ctype.clone());
        }

        builder.build()
    }

    /// Generate issuer metadata as a JSON string.
    pub fn generate_metadata_json(&self) -> Oid4vciResult<String> {
        let metadata = self.generate_metadata();
        serde_json::to_string(&metadata)
            .map_err(|e| Oid4vciError::SerializationError(e.to_string()))
    }
}

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// Verify a PKCE S256 code_verifier against a stored code_challenge.
///
/// Per RFC 7636 §4.6:
///   code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
pub fn verify_pkce_s256(code_verifier: &str, code_challenge: &str) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let computed = URL_SAFE_NO_PAD.encode(hash);
    computed == code_challenge
}

/// Generate a PKCE code challenge from a code verifier using S256.
pub fn generate_pkce_challenge_s256(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

// =============================================================================
// Convenience functions (for simpler use cases & PyO3 bindings)
// =============================================================================

/// Create a credential offer as a JSON string (standalone function).
///
/// This is the direct replacement for `create_credential_offer` in marty-rs.
pub fn create_credential_offer(
    issuer_url: &str,
    credential_types: &[String],
    pre_authorized_code: Option<&str>,
    user_pin_required: bool,
) -> Oid4vciResult<String> {
    let _offer_config = OfferConfig {
        credential_configuration_ids: credential_types.to_vec(),
        pre_authorized_code: pre_authorized_code.map(String::from),
        user_pin_required,
        issuer_state: None,
    };

    let grants = if let Some(code) = pre_authorized_code {
        CredentialOfferGrants {
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: code.to_string(),
                tx_code: if user_pin_required {
                    Some(TransactionCode {
                        input_mode: Some("numeric".into()),
                        length: Some(6),
                        description: None,
                    })
                } else {
                    None
                },
            }),
            authorization_code: None,
        }
    } else {
        CredentialOfferGrants {
            pre_authorized_code: None,
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some(uuid::Uuid::new_v4().to_string()),
                authorization_server: None,
            }),
        }
    };

    let offer = CredentialOffer {
        credential_issuer: issuer_url.to_string(),
        credential_configuration_ids: credential_types.to_vec(),
        grants,
    };

    serde_json::to_string(&offer).map_err(|e| Oid4vciError::SerializationError(e.to_string()))
}

/// Generate a credential offer URI (standalone function).
///
/// This is the direct replacement for `generate_offer_uri` in marty-rs.
pub use crate::offer_uri::generate_offer_uri;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> IssuanceEngine {
        let mut config = IssuerConfig::stateless();
        config.credential_issuer_url = "https://issuer.example.com".into();
        config.issuer_name = "Test Issuer".into();
        config.credential_types = vec![CredentialTypeConfig {
            id: "TestCredential".into(),
            name: "Test Credential".into(),
            formats: vec![CredentialFormat::JwtVcJson, CredentialFormat::SdJwt],
            vc_types: vec!["VerifiableCredential".into()],
            vct: None,
            doctype: None,
            claims: HashMap::new(),
            display: None,
        }];
        config.authorization_endpoint = Some("https://issuer.example.com/authorize".into());
        config.binding_methods = vec!["did:key".into(), "jwk".into()];
        config.proof_signing_alg_values = vec!["ES256".into(), "EdDSA".into()];
        IssuanceEngine::new(config)
    }

    #[test]
    fn test_create_offer_pre_auth() {
        let engine = test_engine();
        let offer = engine
            .create_offer(&OfferConfig {
                credential_configuration_ids: vec!["TestCredential".into()],
                pre_authorized_code: Some("code123".into()),
                user_pin_required: false,
                issuer_state: None,
            })
            .unwrap();

        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert!(offer.grants.pre_authorized_code.is_some());
        assert!(offer.grants.authorization_code.is_none());

        let json = serde_json::to_string(&offer).unwrap();
        assert!(json.contains("pre-authorized_code"));
    }

    #[test]
    fn test_create_offer_auth_code() {
        let engine = test_engine();
        let offer = engine
            .create_offer(&OfferConfig {
                credential_configuration_ids: vec!["TestCredential".into()],
                pre_authorized_code: None,
                user_pin_required: false,
                issuer_state: Some("state_abc".into()),
            })
            .unwrap();

        assert!(offer.grants.pre_authorized_code.is_none());
        assert!(offer.grants.authorization_code.is_some());
        assert_eq!(
            offer
                .grants
                .authorization_code
                .unwrap()
                .issuer_state
                .unwrap(),
            "state_abc"
        );
    }

    #[test]
    fn test_create_token_response() {
        let engine = test_engine();
        let resp = engine.create_token_response("code123", 300).unwrap();

        assert!(resp.access_token.starts_with("at_"));
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 300);
        assert!(serde_json::to_value(&resp)
            .unwrap()
            .get("c_nonce")
            .is_none());

        let nonce = engine.create_nonce_response();
        assert!(!nonce.c_nonce.is_empty());
    }

    #[test]
    fn test_generate_metadata() {
        let engine = test_engine();
        let metadata = engine.generate_metadata();

        assert_eq!(metadata.credential_issuer, "https://issuer.example.com");
        assert!(metadata
            .credential_configurations_supported
            .contains_key("TestCredential"));
    }

    #[test]
    fn metadata_constrains_mdoc_holder_proof_to_es256() {
        let mut engine = test_engine();
        engine.config.credential_types[0].formats = vec![CredentialFormat::MsoMdoc];
        let metadata = engine.generate_metadata();
        let configuration =
            &metadata.credential_configurations_supported["TestCredential_mso_mdoc"];
        assert_eq!(
            configuration.proof_types_supported["jwt"].proof_signing_alg_values_supported,
            ["ES256"],
        );
    }

    #[test]
    fn test_generate_offer_uri() {
        let engine = test_engine();

        let uri = engine.generate_offer_uri("offer123", None).unwrap();
        assert!(uri.starts_with("openid-credential-offer://"));
        assert!(uri.contains("offer123"));

        let ms_uri = engine
            .generate_offer_uri("offer456", Some("microsoft"))
            .unwrap();
        assert!(ms_uri.starts_with("openid-vc://"));
    }

    #[test]
    fn test_create_credential_offer_compat() {
        let json = create_credential_offer(
            "https://issuer.example.com",
            &["TestCred".to_string()],
            Some("code789"),
            false,
        )
        .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["credential_issuer"], "https://issuer.example.com");
        assert!(
            parsed["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"].is_object()
        );
    }

    #[test]
    fn test_create_authorization_response() {
        let engine = test_engine();
        let request = AuthorizationRequest {
            response_type: "code".into(),
            client_id: "did:key:z6Mk_wallet".into(),
            redirect_uri: Some("https://wallet.example/callback".into()),
            scope: Some("openid".into()),
            state: Some("csrf_token_123".into()),
            issuer_state: Some("offer_state_abc".into()),
            code_challenge: None,
            code_challenge_method: None,
            authorization_details: Some(vec![AuthorizationDetail {
                detail_type: "openid_credential".into(),
                credential_configuration_id: Some("TestCredential".into()),
                format: None,
            }]),
        };

        let (response, session) = engine.create_authorization_response(&request, 600).unwrap();

        assert!(response.code.starts_with("ac_"));
        assert_eq!(response.state, Some("csrf_token_123".into()));
        assert_eq!(session.client_id, "did:key:z6Mk_wallet");
        assert_eq!(
            session.redirect_uri,
            Some("https://wallet.example/callback".into())
        );
        assert_eq!(session.issuer_state, Some("offer_state_abc".into()));
        assert_eq!(session.credential_configuration_ids, vec!["TestCredential"]);
        assert_eq!(session.expires_in, 600);
        assert!(!session.is_expired(session.created_at));
        assert!(session.is_expired(session.created_at + 601));
    }

    #[test]
    fn test_auth_code_token_exchange() {
        let engine = test_engine();

        // Create a session (simulating what create_authorization_response would produce)
        let session = AuthorizationSession {
            code: "ac_test123".into(),
            client_id: "did:key:z6Mk_wallet".into(),
            redirect_uri: Some("https://wallet.example/callback".into()),
            code_challenge: None,
            code_challenge_method: None,
            issuer_state: None,
            credential_configuration_ids: vec!["TestCredential".into()],
            created_at: 1000,
            expires_in: 600,
        };

        let request = AuthorizationCodeTokenRequest {
            grant_type: "authorization_code".into(),
            code: "ac_test123".into(),
            redirect_uri: Some("https://wallet.example/callback".into()),
            client_id: Some("did:key:z6Mk_wallet".into()),
            code_verifier: None,
        };

        let resp = engine
            .create_token_response_for_auth_code(&request, &session, 1800)
            .unwrap();

        assert!(resp.access_token.starts_with("at_"));
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 1800);
        assert!(serde_json::to_value(&resp)
            .unwrap()
            .get("c_nonce")
            .is_none());
    }

    #[test]
    fn test_auth_code_token_exchange_pkce() {
        let engine = test_engine();
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code_challenge = generate_pkce_challenge_s256(code_verifier);

        let session = AuthorizationSession {
            code: "ac_pkce_test".into(),
            client_id: "did:key:z6Mk_wallet".into(),
            redirect_uri: None,
            code_challenge: Some(code_challenge.clone()),
            code_challenge_method: Some(CodeChallengeMethod::S256),
            issuer_state: None,
            credential_configuration_ids: vec![],
            created_at: 1000,
            expires_in: 600,
        };

        // Valid verifier
        let request = AuthorizationCodeTokenRequest {
            grant_type: "authorization_code".into(),
            code: "ac_pkce_test".into(),
            redirect_uri: None,
            client_id: None,
            code_verifier: Some(code_verifier.into()),
        };

        let resp = engine
            .create_token_response_for_auth_code(&request, &session, 1800)
            .unwrap();
        assert!(resp.access_token.starts_with("at_"));

        // Invalid verifier should fail
        let bad_request = AuthorizationCodeTokenRequest {
            grant_type: "authorization_code".into(),
            code: "ac_pkce_test".into(),
            redirect_uri: None,
            client_id: None,
            code_verifier: Some("wrong_verifier".into()),
        };

        let err = engine.create_token_response_for_auth_code(&bad_request, &session, 1800);
        assert!(err.is_err());
    }

    #[test]
    fn test_auth_code_redirect_uri_mismatch() {
        let engine = test_engine();

        let session = AuthorizationSession {
            code: "ac_redirect_test".into(),
            client_id: "client1".into(),
            redirect_uri: Some("https://wallet.example/callback".into()),
            code_challenge: None,
            code_challenge_method: None,
            issuer_state: None,
            credential_configuration_ids: vec![],
            created_at: 1000,
            expires_in: 600,
        };

        let request = AuthorizationCodeTokenRequest {
            grant_type: "authorization_code".into(),
            code: "ac_redirect_test".into(),
            redirect_uri: Some("https://evil.example/steal".into()),
            client_id: None,
            code_verifier: None,
        };

        let err = engine.create_token_response_for_auth_code(&request, &session, 1800);
        assert!(err.is_err());
    }

    #[test]
    fn test_metadata_includes_authorization_endpoint() {
        let engine = test_engine();
        let metadata = engine.generate_metadata();
        assert_eq!(
            metadata.authorization_endpoint,
            Some("https://issuer.example.com/authorize".into())
        );
    }

    #[test]
    fn test_pkce_s256() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_pkce_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(verify_pkce_s256(verifier, &challenge));
        assert!(!verify_pkce_s256("wrong_verifier", &challenge));
    }
}
