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
//!   [Issuer] ──cred───> [Wallet]  (signed credential)
//! ```
//!
//! This engine is *stateless* — it does not persist offers, tokens, or nonces.
//! State management (Redis, DB, etc.) is the responsibility of the calling
//! service layer. The engine only performs protocol logic and credential signing.

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::formats;
use crate::metadata::{IssuerMetadata, MetadataBuilder};
use crate::proof;
use crate::signing_batch::{
    Es256SignerScope, Es256SigningBatchInput, MdocSigningBatchInput, SigningBatchError,
};
use crate::types::*;

use std::collections::HashMap;

// =============================================================================
// IssuanceEngine
// =============================================================================

/// The main OID4VCI issuance engine.
///
/// Performs protocol operations (offer creation, token exchange, credential
/// issuance) without managing state. The caller is responsible for persisting
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
/// // 3. Validate credential request and issue credential
/// let resp = engine.issue_credential(&cred_request, &claims, "expected_nonce")?;
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
        let issuer = &self.config.credential_issuer_url;
        match scheme.unwrap_or("oid4vci") {
            "microsoft" => Ok(format!(
                "openid-vc://?request_uri={}/issuance-requests/{}",
                issuer, offer_id
            )),
            _ => Ok(format!(
                "openid-credential-offer://?credential_offer_uri={}/offers/{}",
                issuer, offer_id
            )),
        }
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

    // ── Credential Issuance (§8) ─────────────────────────────────────

    /// Process a credential request and issue a signed credential.
    ///
    /// This performs:
    /// 1. Format negotiation (from request.format or credential_identifier)
    /// 2. Proof of possession verification (PoP JWT signature + c_nonce)
    /// 3. Credential signing in the negotiated format
    /// 4. Response construction; a later proof nonce is obtained from the
    ///    Nonce Endpoint rather than embedded in this response
    ///
    /// # Arguments
    /// - `request` — The credential request from the wallet
    /// - `claims` — The claims to include in the credential (from the issuer's DB)
    /// - `expected_nonce` — The c_nonce the wallet should have used
    /// - `issuer_audience` — The expected audience in the PoP JWT (usually the issuer URL)
    pub fn issue_credential(
        &self,
        request: &CredentialRequest,
        claims: &CredentialClaims,
        expected_nonce: &str,
        issuer_audience: Option<&str>,
    ) -> Oid4vciResult<CredentialResponse> {
        let audience = issuer_audience.unwrap_or(&self.config.credential_issuer_url);

        // 1. Verify proof of possession
        self.verify_request_proof(request, expected_nonce, audience)?;

        // 2. Negotiate format
        let supported_formats: Vec<CredentialFormat> = self
            .config
            .credential_types
            .iter()
            .flat_map(|ct| ct.formats.iter().cloned())
            .collect();

        let format = formats::negotiate_format(request.format.as_deref(), &supported_formats)?;

        // 3. Sign the credential
        let signed = formats::sign_credential(&format, &self.config.issuer_key, claims)?;

        // 4. Build the credential response. Nonces come from the Nonce Endpoint.
        Ok(CredentialResponse {
            credential: Some(signed.to_response_value()),
            credentials: None,
            transaction_id: None,
        })
    }

    /// Issue a credential in a specific format (bypassing negotiation).
    pub fn issue_credential_in_format(
        &self,
        format: &CredentialFormat,
        claims: &CredentialClaims,
    ) -> Oid4vciResult<SignedCredential> {
        formats::sign_credential(format, &self.config.issuer_key, claims)
    }

    /// Issue a caller-ordered batch of local ES256 mdoc credentials.
    ///
    /// This is a narrow integration and staging boundary for the existing
    /// serial signing batch. No workspace production consumer is wired to it
    /// yet; consumer wiring is a separate follow-up slice. It does not process
    /// credential requests, proofs, remote signers, persistence, or protocol
    /// events. Every input is prepared before the first signing call, and any
    /// failure returns no credential outputs under [`SigningBatchError`]'s
    /// existing redacted precedence contract.
    pub fn issue_mdoc_batch(
        &self,
        inputs: Vec<MdocSigningBatchInput>,
    ) -> Result<Vec<SignedCredential>, SigningBatchError> {
        let scope = Es256SignerScope::new(&self.config.issuer_key)?;
        scope.sign_batch(
            inputs
                .into_iter()
                .map(Es256SigningBatchInput::from)
                .collect(),
        )
    }

    // ── Metadata (§11.2) ─────────────────────────────────────────────

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

    // ── Internal helpers ─────────────────────────────────────────────

    /// Verify the proof of possession from a credential request.
    fn verify_request_proof(
        &self,
        request: &CredentialRequest,
        expected_nonce: &str,
        audience: &str,
    ) -> Oid4vciResult<()> {
        let jwt = request
            .proofs
            .as_ref()
            .and_then(|proofs| proofs.jwt.as_ref())
            .and_then(|jwts| jwts.first())
            .ok_or_else(|| {
                Oid4vciError::ProofVerificationFailed("No JWT in proofs object".into())
            })?;

        // Verify the PoP JWT
        proof::verify_jwt_proof(jwt, audience, Some(expected_nonce), 300)?;
        Ok(())
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
pub fn generate_offer_uri(issuer_url: &str, offer_id: &str, format: &str) -> String {
    match format {
        "microsoft" => format!(
            "openid-vc://?request_uri={}/issuance-requests/{}",
            issuer_url, offer_id
        ),
        _ => format!(
            "openid-credential-offer://?credential_offer_uri={}/offers/{}",
            issuer_url, offer_id
        ),
    }
}

/// Sign a verifiable credential (standalone function).
///
/// This is the direct replacement for `create_verifiable_credential` in marty-rs.
#[allow(clippy::too_many_arguments)]
pub fn create_verifiable_credential(
    issuer_id: &str,
    jwk_json: &str,
    subject_id: Option<&str>,
    credential_type: &str,
    claims: HashMap<String, serde_json::Value>,
    expiration_seconds: Option<i64>,
    format: &str,
    zk_predicate_claims: Vec<crate::types::ZkPredicateBinding>,
) -> Oid4vciResult<(String, String)> {
    let algorithm = detect_algorithm(jwk_json)?;

    let issuer_key = IssuerKey {
        issuer_id: issuer_id.to_string(),
        jwk_json: jwk_json.to_string(),
        algorithm,
    };

    let cred_claims = CredentialClaims {
        subject_id: subject_id.map(String::from),
        credential_type: credential_type.to_string(),
        claims,
        expiration_seconds,
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims,
        credential_payload_format: crate::types::CredentialPayloadFormat::W3cVcdmV2SdJwt,
        w3c_context: vec![],
        w3c_types: vec![],
    };

    let cred_format =
        CredentialFormat::from_str_loose(format).unwrap_or(CredentialFormat::JwtVcJson);

    let signed = formats::sign_credential(&cred_format, &issuer_key, &cred_claims)?;

    let credential_str = match &signed {
        SignedCredential::JwtVcJson { jwt, .. } => jwt.clone(),
        SignedCredential::SdJwt { compact, .. } => compact.clone(),
        SignedCredential::MsoMdoc {
            issuer_signed_b64, ..
        } => issuer_signed_b64.clone(),
        SignedCredential::ZkMdoc {
            issuer_signed_b64, ..
        } => issuer_signed_b64.clone(),
        SignedCredential::VdsNc { barcode_data, .. } => barcode_data.clone(),
    };

    Ok((credential_str, signed.credential_id().to_string()))
}

/// Detect the signing algorithm from a JWK JSON string.
pub fn detect_algorithm(jwk_json: &str) -> Oid4vciResult<SigningAlgorithm> {
    let jwk: serde_json::Value = serde_json::from_str(jwk_json)
        .map_err(|e| Oid4vciError::KeyError(format!("Invalid JWK JSON: {}", e)))?;

    // Check explicit alg field first
    if let Some(alg) = jwk.get("alg").and_then(|v| v.as_str()) {
        return match alg {
            "ES256" => Ok(SigningAlgorithm::ES256),
            "EdDSA" => Ok(SigningAlgorithm::EdDSA),
            "ES256K" => Ok(SigningAlgorithm::ES256K),
            "ES384" => Ok(SigningAlgorithm::ES384),
            "RS256" => Ok(SigningAlgorithm::RS256),
            _ => Err(Oid4vciError::KeyError(format!(
                "Unsupported algorithm: {}",
                alg
            ))),
        };
    }

    // Infer from key type and curve
    match jwk.get("kty").and_then(|v| v.as_str()) {
        Some("OKP") => match jwk.get("crv").and_then(|v| v.as_str()) {
            Some("Ed25519") => Ok(SigningAlgorithm::EdDSA),
            Some(crv) => Err(Oid4vciError::KeyError(format!(
                "Unsupported OKP curve: {}",
                crv
            ))),
            None => Err(Oid4vciError::KeyError("Missing curve for OKP key".into())),
        },
        Some("EC") => match jwk.get("crv").and_then(|v| v.as_str()) {
            Some("P-256") => Ok(SigningAlgorithm::ES256),
            Some("P-384") => Ok(SigningAlgorithm::ES384),
            Some("secp256k1") => Ok(SigningAlgorithm::ES256K),
            Some(crv) => Err(Oid4vciError::KeyError(format!(
                "Unsupported EC curve: {}",
                crv
            ))),
            None => Err(Oid4vciError::KeyError("Missing curve for EC key".into())),
        },
        Some("RSA") => Ok(SigningAlgorithm::RS256),
        Some(kty) => Err(Oid4vciError::KeyError(format!(
            "Unsupported key type: {}",
            kty
        ))),
        None => Err(Oid4vciError::KeyError("Missing kty in JWK".into())),
    }
}

/// Generate a P-256 signing JWK and its public-only counterpart.
///
/// Key generation and public-key derivation stay in Rust so Python callers do
/// not need to interpret or transform private key material.
pub fn generate_p256_jwk_pair() -> Oid4vciResult<(String, String)> {
    let material = crate::holder_key::generate_p256_did_jwk_holder_key()?;
    Ok((material.private_jwk, material.public_jwk))
}

/// Generate a did:jwk issuer identifier and its P-256 private signing JWK.
pub fn generate_p256_did_jwk() -> Oid4vciResult<(String, String)> {
    let material = crate::holder_key::generate_p256_did_jwk_holder_key()?;
    Ok((material.kid, material.private_jwk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_batch::{MdocSigningBatchInput, SigningBatchErrorKind, SigningRouteId};

    fn test_engine() -> IssuanceEngine {
        let jwk = ssi_jwk::JWK::generate_p256();
        let jwk_json = serde_json::to_string(&jwk).unwrap();

        let config = IssuerConfig {
            credential_issuer_url: "https://issuer.example.com".into(),
            issuer_name: "Test Issuer".into(),
            credential_types: vec![CredentialTypeConfig {
                id: "TestCredential".into(),
                name: "Test Credential".into(),
                formats: vec![CredentialFormat::JwtVcJson, CredentialFormat::SdJwt],
                vc_types: vec!["VerifiableCredential".into()],
                vct: None,
                doctype: None,
                claims: HashMap::new(),
                display: None,
            }],
            issuer_key: IssuerKey {
                issuer_id: "did:example:issuer".into(),
                jwk_json,
                algorithm: SigningAlgorithm::ES256,
            },
            token_endpoint: None,
            credential_endpoint: None,
            authorization_endpoint: Some("https://issuer.example.com/authorize".into()),
            deferred_credential_endpoint: None,
            binding_methods: vec!["did:key".into(), "jwk".into()],
            proof_signing_alg_values: vec!["ES256".into(), "EdDSA".into()],
        };

        IssuanceEngine::new(config)
    }

    fn mdoc_claims(name: &str) -> CredentialClaims {
        CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: [("given_name".into(), serde_json::json!(name))].into(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        }
    }

    fn mdoc_input(route: u64, name: &str) -> MdocSigningBatchInput {
        MdocSigningBatchInput::new(SigningRouteId::new(route), mdoc_claims(name))
    }

    #[test]
    fn issuance_engine_mdoc_batch_is_empty_and_caller_ordered() {
        let engine = test_engine();
        assert!(engine.issue_mdoc_batch(Vec::new()).unwrap().is_empty());

        let signed = engine
            .issue_mdoc_batch(vec![mdoc_input(91, "Alice"), mdoc_input(7, "Bob")])
            .unwrap();
        assert_eq!(signed.len(), 2);
        for credential in &signed {
            assert!(matches!(credential, SignedCredential::MsoMdoc { .. }));
        }
        let contains = |credential: &SignedCredential, expected: &[u8]| {
            let SignedCredential::MsoMdoc {
                issuer_signed_b64, ..
            } = credential
            else {
                return false;
            };
            URL_SAFE_NO_PAD
                .decode(issuer_signed_b64)
                .unwrap()
                .windows(expected.len())
                .any(|window| window == expected)
        };
        assert!(contains(&signed[0], b"Alice"));
        assert!(contains(&signed[1], b"Bob"));
        assert_ne!(signed[0].credential_id(), signed[1].credential_id());
    }

    #[test]
    fn issuance_engine_mdoc_batch_preserves_kernel_error_precedence_and_redaction() {
        let engine = test_engine();
        let mut invalid_duplicate = mdoc_claims("Sensitive Duplicate");
        invalid_duplicate
            .claims
            .insert("_mdoc_x5c".into(), serde_json::json!("Sensitive Duplicate"));
        let duplicate = engine
            .issue_mdoc_batch(vec![
                MdocSigningBatchInput::new(SigningRouteId::new(9), invalid_duplicate),
                mdoc_input(9, "Bob"),
            ])
            .unwrap_err();
        assert_eq!(duplicate.kind(), SigningBatchErrorKind::DuplicateRoute);
        assert_eq!(duplicate.item_ordinal(), Some(0));

        let mut invalid = mdoc_claims("Sensitive Name");
        invalid
            .claims
            .insert("_mdoc_x5c".into(), serde_json::json!("Sensitive Name"));
        let preparation = engine
            .issue_mdoc_batch(vec![
                mdoc_input(1, "Valid"),
                MdocSigningBatchInput::new(SigningRouteId::new(2), invalid),
            ])
            .unwrap_err();
        assert_eq!(preparation.kind(), SigningBatchErrorKind::PreparationFailed);
        assert_eq!(preparation.item_ordinal(), Some(1));
        for rendered in [format!("{preparation}"), format!("{preparation:?}")] {
            assert!(!rendered.contains("Sensitive Name"));
            assert!(!rendered.contains("did:example"));
        }
    }

    #[test]
    fn issuance_engine_mdoc_batch_rejects_scope_and_signing_failures_without_outputs() {
        let mut wrong_algorithm = test_engine();
        wrong_algorithm.config.issuer_key.algorithm = SigningAlgorithm::ES384;
        let scope = wrong_algorithm
            .issue_mdoc_batch(vec![mdoc_input(1, "Alice")])
            .unwrap_err();
        assert_eq!(scope.kind(), SigningBatchErrorKind::InvalidScope);
        assert_eq!(scope.item_ordinal(), None);

        let mut broken_signer = test_engine();
        broken_signer.config.issuer_key.jwk_json = "{}".into();
        let signing = broken_signer
            .issue_mdoc_batch(vec![mdoc_input(1, "Alice"), mdoc_input(2, "Bob")])
            .unwrap_err();
        assert_eq!(signing.kind(), SigningBatchErrorKind::ExecutorFailed);
        assert_eq!(signing.item_ordinal(), Some(0));
    }

    #[test]
    fn issuance_engine_mdoc_batch_does_not_change_scalar_issuance() {
        let engine = test_engine();
        let scalar = engine
            .issue_credential_in_format(&CredentialFormat::MsoMdoc, &mdoc_claims("Alice"))
            .unwrap();
        let batch = engine
            .issue_mdoc_batch(vec![mdoc_input(1, "Alice")])
            .unwrap();
        assert!(matches!(scalar, SignedCredential::MsoMdoc { .. }));
        assert!(matches!(
            batch.as_slice(),
            [SignedCredential::MsoMdoc { .. }]
        ));
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
    fn test_issue_credential_in_format() {
        let engine = test_engine();
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "TestCredential".into(),
            claims: [("name".into(), serde_json::json!("Alice"))].into(),
            expiration_seconds: Some(3600),
            selective_disclosure_claims: vec![],
            mdoc_namespace: None,
            mdoc_doctype: None,
            zk_predicate_claims: vec![],
            credential_payload_format: Default::default(),
            w3c_context: vec![],
            w3c_types: vec![],
        };

        let signed = engine
            .issue_credential_in_format(&CredentialFormat::JwtVcJson, &claims)
            .unwrap();

        assert!(matches!(signed, SignedCredential::JwtVcJson { .. }));
        assert!(signed.credential_id().starts_with("urn:uuid:"));
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
    fn test_detect_algorithm() {
        let p256 = ssi_jwk::JWK::generate_p256();
        let p256_json = serde_json::to_string(&p256).unwrap();
        assert_eq!(
            detect_algorithm(&p256_json).unwrap(),
            SigningAlgorithm::ES256
        );

        let ed25519 = ssi_jwk::JWK::generate_ed25519().unwrap();
        let ed_json = serde_json::to_string(&ed25519).unwrap();
        assert_eq!(detect_algorithm(&ed_json).unwrap(), SigningAlgorithm::EdDSA);
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
