//! OID4VP (OpenID for Verifiable Presentations) verifier engine.
//!
//! Implements the server/verifier side of the OID4VP v1.0 specification,
//! including:
//!
//! - **Presentation definitions** — Build presentation requests with input
//!   descriptors specifying which credentials to present
//! - **Presentation verification** — Validate VP tokens against definitions
//! - **ZK predicate proofs** — Request and verify zero-knowledge predicate
//!   proofs (e.g., `age_over_18`) via Longfellow/Ligero (behind `zk_mdoc` feature)
//!
//! # Protocol Flow
//!
//! ```text
//! Verifier                              Wallet
//!    |                                     |
//!    |  1. POST /authorize                 |
//!    |  (presentation_definition)          |
//!    | ----------------------------------> |
//!    |                                     |
//!    |  2. POST response_uri               |
//!    |  (vp_token, presentation_submission) |
//!    | <---------------------------------- |
//!    |                                     |
//!    |  3. Verify VP token                 |
//!    |     + ZK proofs if requested        |
//!    |                                     |
//! ```
//!
//! # ZK Predicate Verification
//!
//! When a presentation definition includes a ZK predicate constraint
//! (e.g., prove age >= 18 without revealing birth date), the verifier:
//!
//! 1. Generates a challenge nonce via [`VerificationEngine::create_zk_challenge`]
//! 2. Includes the nonce + predicate in the presentation definition
//! 3. Receives a ZK proof from the wallet
//! 4. Verifies the proof via `marty-zkp::Verifier` without seeing the value

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::{Oid4vciError, Oid4vciResult};

// ── OID4VP Types ─────────────────────────────────────────────────────

/// Presentation definition (OID4VP §5.1).
///
/// Describes what credentials and claims the verifier is requesting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    pub id: String,
    /// Human-readable name for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable purpose for this request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Input descriptors — one per credential type requested.
    pub input_descriptors: Vec<InputDescriptor>,
}

/// A single credential request within a presentation definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    pub id: String,
    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Acceptable credential formats and their params.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<HashMap<String, FormatRequirement>>,
    /// Constraints on which claims/fields to present.
    pub constraints: Constraints,
}

/// Format-specific requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatRequirement {
    /// Acceptable proof/signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Vec<String>>,
}

/// Constraints define which fields the verifier is requesting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Fields the verifier wants to see.
    /// Per DIF PE v2 §5, `fields` is optional; defaults to empty array.
    #[serde(default)]
    pub fields: Vec<FieldConstraint>,
    /// Whether selective disclosure is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_disclosure: Option<String>,
}

/// A single field constraint within a presentation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldConstraint {
    /// JSONPath expressions pointing to the claim.
    pub path: Vec<String>,
    /// Optional filter on the value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Value>,
    /// Whether this field is optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    /// ZK predicate request (extension for Longfellow).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zk_predicate: Option<ZkPredicateRequest>,
}

/// A request for a zero-knowledge predicate proof on a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkPredicateRequest {
    /// The predicate to prove (e.g., "age_over_18").
    pub predicate: String,
    /// The ZK proof protocol (e.g., "longfellow-zk-ligero").
    pub proof_type: String,
    /// Challenge nonce for this ZK proof (base64url-encoded).
    pub nonce: String,
}

// ── Presentation Submission ──────────────────────────────────────────

/// Wallet's response mapping VP tokens to input descriptors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    pub id: String,
    pub definition_id: String,
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// Maps a VP token to an input descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMapEntry {
    pub id: String,
    pub format: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_nested: Option<Box<DescriptorMapEntry>>,
}

// ── ZK Types ─────────────────────────────────────────────────────────

/// A ZK challenge session, analogous to `ZkChallengeSession` in Python.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkChallenge {
    /// Unique session identifier.
    pub session_id: String,
    /// The challenge nonce (base64url-encoded).
    pub nonce: String,
    /// The raw nonce bytes (not serialized — for internal use).
    #[serde(skip)]
    pub nonce_bytes: Vec<u8>,
    /// The predicate being proved.
    pub predicate: String,
    /// Timestamp when the challenge was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Expiration duration in seconds.
    pub expires_in_seconds: i64,
}

/// Result of verifying a ZK predicate proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVerificationResult {
    pub valid: bool,
    pub predicate: String,
    pub proof_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Result of a scoped, low-level presentation verification check.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationResult {
    /// Whether this result is sufficient for a final credential decision.
    ///
    /// Low-level presentation-proof, structural, and constraint checks never
    /// set this field to `true`: none of those checks authenticates every
    /// embedded credential, establishes issuer trust/status, and proves holder
    /// binding. Callers that need the low-level result must inspect
    /// `check_valid`, `scope`, and `evidence` explicitly.
    pub valid: bool,
    /// Whether the check identified by `scope` passed.
    pub check_valid: bool,
    /// Whether all evidence required for a final credential decision exists.
    pub decision_ready: bool,
    /// The exact operation performed by this result.
    pub scope: VerificationScope,
    /// Proof and binding facts established (or not established) by the check.
    pub evidence: VerificationEvidence,
    /// Per-descriptor results.
    pub descriptor_results: Vec<DescriptorVerificationResult>,
    /// ZK predicate verification results (if any).
    pub zk_results: Vec<ZkVerificationResult>,
    /// Errors encountered during verification.
    pub errors: Vec<String>,
}

/// Scope of a low-level verification operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationScope {
    PresentationProof,
    PresentationStructure,
    PresentationExchange,
}

/// Four-state status for a required proof or binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationCheckStatus {
    Passed,
    Failed,
    NotChecked,
    Unsupported,
}

/// Evidence established by a low-level verification operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub presentation_proof: VerificationCheckStatus,
    pub transaction_binding: VerificationCheckStatus,
    pub credential_issuer_proofs: VerificationCheckStatus,
    pub holder_binding: VerificationCheckStatus,
    pub presentation_structure: VerificationCheckStatus,
    pub presentation_constraints: VerificationCheckStatus,
}

impl VerificationEvidence {
    fn not_checked() -> Self {
        Self {
            presentation_proof: VerificationCheckStatus::NotChecked,
            transaction_binding: VerificationCheckStatus::NotChecked,
            credential_issuer_proofs: VerificationCheckStatus::NotChecked,
            holder_binding: VerificationCheckStatus::NotChecked,
            presentation_structure: VerificationCheckStatus::NotChecked,
            presentation_constraints: VerificationCheckStatus::NotChecked,
        }
    }
}

impl VerificationResult {
    fn low_level(
        scope: VerificationScope,
        check_valid: bool,
        evidence: VerificationEvidence,
        descriptor_results: Vec<DescriptorVerificationResult>,
        zk_results: Vec<ZkVerificationResult>,
        errors: Vec<String>,
    ) -> Self {
        Self {
            valid: false,
            check_valid,
            decision_ready: false,
            scope,
            evidence,
            descriptor_results,
            zk_results,
            errors,
        }
    }
}

/// Result for a single input descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorVerificationResult {
    pub descriptor_id: String,
    pub valid: bool,
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ── Verification Engine ──────────────────────────────────────────────

/// OID4VP verification engine.
///
/// Handles construction of presentation requests and verification of
/// VP tokens, including ZK predicate proofs.
pub struct VerificationEngine {
    /// Verifier identifier (typically a DID or URL).
    pub verifier_id: String,
    /// URL the wallet should send the response to.
    pub response_uri: String,
    /// Maximum age for nonces in seconds.
    pub nonce_max_age: i64,
}

impl VerificationEngine {
    pub fn new(verifier_id: impl Into<String>, response_uri: impl Into<String>) -> Self {
        Self {
            verifier_id: verifier_id.into(),
            response_uri: response_uri.into(),
            nonce_max_age: 600, // 10 minutes
        }
    }

    /// Set the maximum nonce age in seconds.
    pub fn nonce_max_age(mut self, seconds: i64) -> Self {
        self.nonce_max_age = seconds;
        self
    }

    /// Create a presentation definition requesting specific credentials.
    ///
    /// # Arguments
    /// * `id` — unique identifier for this presentation request
    /// * `descriptors` — input descriptors for requested credentials
    pub fn create_presentation_definition(
        &self,
        id: impl Into<String>,
        descriptors: Vec<InputDescriptor>,
    ) -> Oid4vciResult<PresentationDefinition> {
        if descriptors.is_empty() {
            return Err(Oid4vciError::ConfigError(
                "Presentation definition requires at least one input descriptor".into(),
            ));
        }

        Ok(PresentationDefinition {
            id: id.into(),
            name: None,
            purpose: None,
            input_descriptors: descriptors,
        })
    }

    /// Build an input descriptor for an mDL credential.
    pub fn mdl_descriptor(
        &self,
        id: impl Into<String>,
        requested_fields: &[&str],
    ) -> InputDescriptor {
        let fields: Vec<FieldConstraint> = requested_fields
            .iter()
            .map(|f| FieldConstraint {
                path: vec![format!("$.org\\.iso\\.18013\\.5\\.1.{}", f)],
                filter: None,
                optional: None,
                zk_predicate: None,
            })
            .collect();

        let mut format = HashMap::new();
        format.insert(
            "mso_mdoc".into(),
            FormatRequirement {
                alg: Some(vec!["ES256".into()]),
            },
        );

        InputDescriptor {
            id: id.into(),
            name: Some("Mobile Driving License".into()),
            purpose: Some("Verify identity claims from mDL".into()),
            format: Some(format),
            constraints: Constraints {
                fields,
                limit_disclosure: Some("required".into()),
            },
        }
    }

    /// Build an input descriptor requesting a ZK predicate proof.
    ///
    /// This creates a field constraint with a ZK predicate request,
    /// telling the wallet to generate a zero-knowledge proof instead of
    /// revealing the actual claim value.
    ///
    /// # Arguments
    /// * `id` — descriptor identifier
    /// * `claim_path` — JSONPath to the claim (e.g., `$.org\.iso\.18013\.5\.1.birth_date`)
    /// * `predicate` — the predicate name (e.g., `"age_over_18"`)
    /// * `nonce` — challenge nonce (base64url-encoded)
    pub fn zk_predicate_descriptor(
        &self,
        id: impl Into<String>,
        claim_path: &str,
        predicate: &str,
        nonce: &str,
    ) -> InputDescriptor {
        let mut format = HashMap::new();
        format.insert(
            "zk_mdoc".into(),
            FormatRequirement {
                alg: Some(vec!["ES256".into()]),
            },
        );

        InputDescriptor {
            id: id.into(),
            name: Some(format!("ZK Predicate: {}", predicate)),
            purpose: Some(format!(
                "Prove {} without revealing the underlying value",
                predicate
            )),
            format: Some(format),
            constraints: Constraints {
                fields: vec![FieldConstraint {
                    path: vec![claim_path.to_string()],
                    filter: None,
                    optional: Some(false),
                    zk_predicate: Some(ZkPredicateRequest {
                        predicate: predicate.to_string(),
                        proof_type: crate::formats::zk_mdoc::ZK_PROOF_TYPE_LIGERO.to_string(),
                        nonce: nonce.to_string(),
                    }),
                }],
                limit_disclosure: Some("required".into()),
            },
        }
    }

    /// Create a ZK challenge for use in a presentation request.
    ///
    /// Generates a random 32-byte nonce to be used as a challenge in a
    /// ZK predicate proof request.
    pub fn create_zk_challenge(&self, predicate: &str) -> Oid4vciResult<ZkChallenge> {
        use base64::Engine;
        use rand::RngCore;

        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);

        let session_id = uuid::Uuid::new_v4().to_string();

        Ok(ZkChallenge {
            session_id,
            nonce: nonce_b64,
            nonce_bytes: nonce_bytes.to_vec(),
            predicate: predicate.to_string(),
            created_at: chrono::Utc::now(),
            expires_in_seconds: self.nonce_max_age,
        })
    }

    /// Verify a ZK predicate proof using the Longfellow/Ligero verifier.
    ///
    /// Dispatches to the appropriate ZK circuit based on the predicate
    /// identifier carried in `challenge.predicate` (e.g. `"age_over_18"`,
    /// `"age_over_21"`).  New predicates are supported automatically as long
    /// as `marty-zkp` implements the corresponding circuit — no changes are
    /// needed here.
    ///
    /// # Arguments
    /// * `challenge` — the original ZK challenge that was sent to the wallet
    /// * `circuit`   — pre-generated circuit for the attribute count
    /// * `input`     — the mDoc prove input (mdoc bytes, issuer key, attributes, etc.)
    /// * `proof`     — the ZK proof bytes from the wallet
    #[cfg(feature = "zk_mdoc")]
    pub fn verify_zk_predicate(
        &self,
        challenge: &ZkChallenge,
        circuit: &marty_zkp::Circuit,
        input: &marty_zkp::MdocProveInput,
        proof: &[u8],
    ) -> ZkVerificationResult {
        use chrono::Utc;

        // Check challenge expiration
        let elapsed = Utc::now()
            .signed_duration_since(challenge.created_at)
            .num_seconds();
        if elapsed > challenge.expires_in_seconds {
            return ZkVerificationResult {
                valid: false,
                predicate: challenge.predicate.clone(),
                proof_type: crate::formats::zk_mdoc::ZK_PROOF_TYPE_LIGERO.to_string(),
                error: Some("ZK challenge has expired".into()),
            };
        }

        match marty_zkp::Verifier::verify(circuit, input, proof) {
            Ok(true) => ZkVerificationResult {
                valid: true,
                predicate: challenge.predicate.clone(),
                proof_type: crate::formats::zk_mdoc::ZK_PROOF_TYPE_LIGERO.to_string(),
                error: None,
            },
            Ok(false) => ZkVerificationResult {
                valid: false,
                predicate: challenge.predicate.clone(),
                proof_type: crate::formats::zk_mdoc::ZK_PROOF_TYPE_LIGERO.to_string(),
                error: Some("ZK proof verification returned false".into()),
            },
            Err(e) => ZkVerificationResult {
                valid: false,
                predicate: challenge.predicate.clone(),
                proof_type: crate::formats::zk_mdoc::ZK_PROOF_TYPE_LIGERO.to_string(),
                error: Some(format!("ZK verification error: {}", e)),
            },
        }
    }

    /// Verify a JWT Verifiable Presentation token cryptographically.
    ///
    /// Validates:
    /// 1. JWT structure (compact serialization, 3 parts)
    /// 2. `nonce` claim matches `expected_nonce`
    /// 3. `aud` claim contains this verifier's `verifier_id`
    /// 4. Token is not expired (60-second clock skew grace)
    /// 5. JWT signature using the presentation's embedded public key, sourced from
    ///    (in priority order): JWT header `jwk`, payload `cnf.jwk`, payload `sub_jwk`
    ///
    /// This establishes presentation proof and transaction binding only. A key
    /// supplied by the presentation is self-declared: this method does not
    /// authenticate embedded issuer credentials or bind the presentation key
    /// to a credential confirmation key. Therefore `valid` and
    /// `decision_ready` remain false even when `check_valid` is true.
    ///
    /// This handles the `jwt_vp_json` format. For mDoc VP verification use the
    /// ISO 18013-7 `DeviceResponse` path instead.
    ///
    /// # Arguments
    /// * `vp_token`         — compact JWT VP token from the wallet
    /// * `expected_nonce`   — nonce from the original authorization request
    pub fn verify_vp_token(&self, vp_token: &str, expected_nonce: &str) -> VerificationResult {
        use base64::Engine;
        use jsonwebtoken::{decode_header, Algorithm, DecodingKey, Validation};

        let failed = |message: String,
                      presentation_proof: VerificationCheckStatus,
                      transaction_binding: VerificationCheckStatus| {
            let mut evidence = VerificationEvidence::not_checked();
            evidence.presentation_proof = presentation_proof;
            evidence.transaction_binding = transaction_binding;
            VerificationResult::low_level(
                VerificationScope::PresentationProof,
                false,
                evidence,
                vec![],
                vec![],
                vec![message],
            )
        };

        if expected_nonce.is_empty()
            || !expected_nonce.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '.' | '_' | '~')
            })
        {
            return failed(
                "Expected transaction nonce must be non-empty and ASCII URL-safe".into(),
                VerificationCheckStatus::NotChecked,
                VerificationCheckStatus::Failed,
            );
        }
        if self.verifier_id.is_empty() {
            return failed(
                "Expected verifier audience must be non-empty".into(),
                VerificationCheckStatus::NotChecked,
                VerificationCheckStatus::Failed,
            );
        }

        // ── Step 1: Parse JWT header ──────────────────────────────────
        let header = match decode_header(vp_token) {
            Ok(h) => h,
            Err(e) => {
                return failed(
                    format!("VP token header parse error: {e}"),
                    VerificationCheckStatus::Failed,
                    VerificationCheckStatus::NotChecked,
                )
            }
        };

        let format_label = match header.alg {
            Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::EdDSA => "jwt_vp_json",
            unsupported => {
                return failed(
                    format!("Unsupported VP token signature algorithm: {unsupported:?}"),
                    VerificationCheckStatus::Unsupported,
                    VerificationCheckStatus::NotChecked,
                )
            }
        };

        // ── Step 2: Base64-decode payload to extract claims ───────────
        let parts: Vec<&str> = vp_token.split('.').collect();
        if parts.len() != 3 {
            return failed(
                "VP token is not a valid compact JWT (expected 3 parts)".into(),
                VerificationCheckStatus::Failed,
                VerificationCheckStatus::NotChecked,
            );
        }

        let payload_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(parts[1])
        {
            Ok(b) => b,
            Err(e) => {
                return failed(
                    format!("VP token payload base64 decode error: {e}"),
                    VerificationCheckStatus::Failed,
                    VerificationCheckStatus::NotChecked,
                )
            }
        };

        let payload: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
            Ok(v) => v,
            Err(e) => {
                return failed(
                    format!("VP token payload JSON parse error: {e}"),
                    VerificationCheckStatus::Failed,
                    VerificationCheckStatus::NotChecked,
                )
            }
        };

        // ── Step 3: Validate nonce ────────────────────────────────────
        let Some(token_nonce) = payload
            .get("nonce")
            .and_then(|v| v.as_str())
            .filter(|nonce| !nonce.is_empty())
        else {
            return failed(
                "VP token nonce claim is missing or empty".into(),
                VerificationCheckStatus::NotChecked,
                VerificationCheckStatus::Failed,
            );
        };
        if token_nonce != expected_nonce {
            return failed(
                "VP token nonce does not match the transaction".into(),
                VerificationCheckStatus::NotChecked,
                VerificationCheckStatus::Failed,
            );
        }

        // ── Step 4: Validate audience ─────────────────────────────────
        let aud_ok = match payload.get("aud") {
            Some(serde_json::Value::String(a)) => a == &self.verifier_id,
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().any(|a| a.as_str() == Some(&self.verifier_id))
            }
            _ => false,
        };
        if !aud_ok {
            return failed(
                "VP token audience does not match the verifier".into(),
                VerificationCheckStatus::NotChecked,
                VerificationCheckStatus::Failed,
            );
        }

        // ── Step 5: Validate expiration ───────────────────────────────
        let Some(exp) = payload.get("exp").and_then(|v| v.as_i64()) else {
            return failed(
                "VP token expiration claim is missing or invalid".into(),
                VerificationCheckStatus::NotChecked,
                VerificationCheckStatus::Failed,
            );
        };
        let now = chrono::Utc::now().timestamp();
        if now > exp.saturating_add(60) {
            return failed(
                "VP token has expired".into(),
                VerificationCheckStatus::NotChecked,
                VerificationCheckStatus::Failed,
            );
        }

        // ── Step 6: Locate presentation public key ───────────────────
        //   Priority:
        //   a) Header `jwk` (RFC 7517 §4.7) — set by spec-compliant wallets
        //   b) Payload `cnf.jwk`            — key confirmation claim (RFC 7800)
        //   c) Payload `sub_jwk`            — older/draft wallets
        let jwk: Option<jsonwebtoken::jwk::Jwk> = header
            .jwk
            .clone()
            .or_else(|| {
                payload
                    .get("cnf")
                    .and_then(|c| c.get("jwk"))
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
            })
            .or_else(|| {
                payload
                    .get("sub_jwk")
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
            });

        let jwk = match jwk {
            Some(j) => j,
            None => {
                return failed(
                    "No presentation public key found in VP token".into(),
                    VerificationCheckStatus::Failed,
                    VerificationCheckStatus::NotChecked,
                )
            }
        };

        // ── Step 7: Build decoding key from JWK ──────────────────────
        let decoding_key = match DecodingKey::from_jwk(&jwk) {
            Ok(k) => k,
            Err(e) => {
                return failed(
                    format!("Cannot build decoding key from JWK: {e}"),
                    VerificationCheckStatus::Failed,
                    VerificationCheckStatus::NotChecked,
                )
            }
        };

        // ── Step 8: Verify JWT signature ──────────────────────────────
        // Claims (nonce, aud, exp) were already validated manually.
        // jsonwebtoken is used here only for the cryptographic signature check.
        let mut validation = Validation::new(header.alg);
        validation.validate_aud = false; // validated manually above
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = 60; // 60s clock skew tolerance

        match jsonwebtoken::decode::<serde_json::Value>(vp_token, &decoding_key, &validation) {
            Ok(_) => {
                let mut evidence = VerificationEvidence::not_checked();
                evidence.presentation_proof = VerificationCheckStatus::Passed;
                evidence.transaction_binding = VerificationCheckStatus::Passed;
                VerificationResult::low_level(
                    VerificationScope::PresentationProof,
                    true,
                    evidence,
                    vec![DescriptorVerificationResult {
                        descriptor_id: "vp_token".into(),
                        valid: true,
                        format: format_label.into(),
                        error: None,
                    }],
                    vec![],
                    vec![],
                )
            }
            Err(e) => {
                let mut evidence = VerificationEvidence::not_checked();
                evidence.presentation_proof = VerificationCheckStatus::Failed;
                VerificationResult::low_level(
                    VerificationScope::PresentationProof,
                    false,
                    evidence,
                    vec![DescriptorVerificationResult {
                        descriptor_id: "vp_token".into(),
                        valid: false,
                        format: format_label.into(),
                        error: Some(format!("JWT signature verification failed: {e}")),
                    }],
                    vec![],
                    vec![format!("VP token signature verification failed: {e}")],
                )
            }
        }
    }

    /// Verify a presentation submission against a presentation definition.
    ///
    /// Performs structural validation (descriptor mapping, format checks).
    /// Cryptographic verification of individual VP tokens is delegated to
    /// format-specific verifiers.
    pub fn verify_presentation_structure(
        &self,
        definition: &PresentationDefinition,
        submission: &PresentationSubmission,
    ) -> VerificationResult {
        let mut descriptor_results = Vec::new();
        let mut errors = Vec::new();

        if definition.input_descriptors.is_empty() {
            errors.push("Presentation definition contains no input descriptors".into());
        }
        if submission.descriptor_map.is_empty() {
            errors.push("Presentation submission contains no descriptor mappings".into());
        }

        let mut definition_ids = HashSet::new();
        for descriptor in &definition.input_descriptors {
            if !definition_ids.insert(descriptor.id.as_str()) {
                errors.push(format!(
                    "Presentation definition contains duplicate descriptor id '{}'",
                    descriptor.id
                ));
            }
        }

        let mut mapped_ids = HashSet::new();
        for entry in &submission.descriptor_map {
            if !definition_ids.contains(entry.id.as_str()) {
                errors.push(format!(
                    "Submission maps unknown descriptor id '{}'",
                    entry.id
                ));
            }
            if !mapped_ids.insert(entry.id.as_str()) {
                errors.push(format!(
                    "Submission contains duplicate mapping for descriptor '{}'",
                    entry.id
                ));
            }
        }

        // Verify definition_id matches
        if submission.definition_id != definition.id {
            errors.push(format!(
                "Submission definition_id '{}' does not match definition id '{}'",
                submission.definition_id, definition.id
            ));
        }

        // Check that every required input descriptor has a mapping
        for descriptor in &definition.input_descriptors {
            let mapped = submission
                .descriptor_map
                .iter()
                .find(|m| m.id == descriptor.id);

            match mapped {
                Some(entry) => {
                    let leaf = match Self::validate_descriptor_map_chain(entry, &descriptor.id) {
                        Ok(leaf) => leaf,
                        Err(error) => {
                            errors.push(error.clone());
                            descriptor_results.push(DescriptorVerificationResult {
                                descriptor_id: descriptor.id.clone(),
                                valid: false,
                                format: entry.format.clone(),
                                error: Some(error),
                            });
                            continue;
                        }
                    };
                    let format_error = descriptor.format.as_ref().and_then(|required_formats| {
                        (!required_formats.contains_key(&leaf.format)).then(|| {
                            format!(
                                "Format '{}' not in accepted formats: {:?}",
                                leaf.format,
                                required_formats.keys().collect::<Vec<_>>()
                            )
                        })
                    });
                    let format_ok = format_error.is_none();

                    descriptor_results.push(DescriptorVerificationResult {
                        descriptor_id: descriptor.id.clone(),
                        valid: format_ok,
                        format: leaf.format.clone(),
                        error: format_error,
                    });
                }
                None => {
                    descriptor_results.push(DescriptorVerificationResult {
                        descriptor_id: descriptor.id.clone(),
                        valid: false,
                        format: "missing".into(),
                        error: Some("No descriptor mapping found in submission".into()),
                    });
                }
            }
        }

        let all_valid = errors.is_empty() && descriptor_results.iter().all(|r| r.valid);
        let mut evidence = VerificationEvidence::not_checked();
        evidence.presentation_structure = if all_valid {
            VerificationCheckStatus::Passed
        } else {
            VerificationCheckStatus::Failed
        };

        VerificationResult::low_level(
            VerificationScope::PresentationStructure,
            all_valid,
            evidence,
            descriptor_results,
            vec![],
            errors,
        )
    }

    /// Full Presentation Exchange (DIF PE v2) evaluation.
    ///
    /// Performs structural validation (descriptor mapping, format checks) AND
    /// field constraint evaluation against the decoded VP token payload JSON.
    ///
    /// `vp_payload` is the JWT body (the `serde_json::Value` decoded from the
    /// VP token's second segment). When `None`, the full check fails closed.
    /// Call [`verify_presentation_structure`] explicitly for structure only.
    ///
    /// For each `InputDescriptor`, the matching `descriptor_map` entry's `path`
    /// (and `path_nested.path` when present) navigates from the VP token payload
    /// to the relevant credential document.  `FieldConstraint.path` JSONPath
    /// expressions are evaluated against that document and `FieldConstraint.filter`
    /// (JSON Schema draft-07 subset) restricts accepted values.
    pub fn verify_presentation(
        &self,
        definition: &PresentationDefinition,
        submission: &PresentationSubmission,
        vp_payload: Option<&serde_json::Value>,
    ) -> VerificationResult {
        // ── 1. Structural check ──────────────────────────────────────────────
        let structural = self.verify_presentation_structure(definition, submission);
        if !structural.check_valid {
            return structural;
        }

        let payload = match vp_payload {
            Some(p) => p,
            None => {
                let mut evidence = VerificationEvidence::not_checked();
                evidence.presentation_structure = VerificationCheckStatus::Passed;
                evidence.presentation_constraints = VerificationCheckStatus::Failed;
                return VerificationResult::low_level(
                    VerificationScope::PresentationExchange,
                    false,
                    evidence,
                    structural.descriptor_results,
                    vec![],
                    vec![
                        "Decoded presentation payload is required for constraint evaluation".into(),
                    ],
                );
            }
        };

        // ── 2. Field constraint evaluation per descriptor ────────────────────
        let mut descriptor_results: Vec<DescriptorVerificationResult> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for descriptor in &definition.input_descriptors {
            // Structural check already verified this entry exists.
            let map_entry = match submission
                .descriptor_map
                .iter()
                .find(|e| e.id == descriptor.id)
            {
                Some(e) => e,
                None => continue,
            };

            let leaf_map = match Self::validate_descriptor_map_chain(map_entry, &descriptor.id) {
                Ok(leaf) => leaf,
                Err(error) => {
                    errors.push(error.clone());
                    descriptor_results.push(DescriptorVerificationResult {
                        descriptor_id: descriptor.id.clone(),
                        valid: false,
                        format: map_entry.format.clone(),
                        error: Some(error),
                    });
                    continue;
                }
            };
            if descriptor
                .format
                .as_ref()
                .and_then(|formats| formats.get(&leaf_map.format))
                .and_then(|requirement| requirement.alg.as_ref())
                .is_some_and(|algorithms| !algorithms.is_empty())
            {
                let err = format!(
                    "Descriptor '{}': format algorithm requirement has no authenticated algorithm evidence",
                    descriptor.id
                );
                errors.push(err.clone());
                descriptor_results.push(DescriptorVerificationResult {
                    descriptor_id: descriptor.id.clone(),
                    valid: false,
                    format: leaf_map.format.clone(),
                    error: Some(err),
                });
                continue;
            }

            // Navigate the complete descriptor chain. A bad mapping must never
            // widen evaluation to an enclosing object or ignore deeper nesting.
            let Some(credential_doc) = Self::descriptor_map_get(payload, map_entry) else {
                let err = format!(
                    "Descriptor '{}': mapping path chain did not resolve",
                    descriptor.id
                );
                errors.push(err.clone());
                descriptor_results.push(DescriptorVerificationResult {
                    descriptor_id: descriptor.id.clone(),
                    valid: false,
                    format: leaf_map.format.clone(),
                    error: Some(err),
                });
                continue;
            };

            // A selective-disclosure designation must be an exact known value.
            // Substring matching would let attacker-chosen format names such as
            // `not_sd_jwt` masquerade as selective-disclosure credentials.
            if descriptor.constraints.limit_disclosure.as_deref() == Some("required") {
                let fmt = leaf_map.format.as_str();
                if !Self::is_selective_disclosure_format(fmt) {
                    let err = format!(
                        "Descriptor '{}': limit_disclosure:required but format '{}' is not SD-JWT",
                        descriptor.id, fmt
                    );
                    errors.push(err.clone());
                    descriptor_results.push(DescriptorVerificationResult {
                        descriptor_id: descriptor.id.clone(),
                        valid: false,
                        format: leaf_map.format.clone(),
                        error: Some(err),
                    });
                    continue;
                }
            } else if let Some(value) = descriptor.constraints.limit_disclosure.as_deref() {
                if value != "preferred" {
                    let err = format!(
                        "Descriptor '{}': unsupported limit_disclosure value '{}'",
                        descriptor.id, value
                    );
                    errors.push(err.clone());
                    descriptor_results.push(DescriptorVerificationResult {
                        descriptor_id: descriptor.id.clone(),
                        valid: false,
                        format: leaf_map.format.clone(),
                        error: Some(err),
                    });
                    continue;
                }
            }

            // Evaluate field constraints against the credential document.
            let mut field_errors: Vec<String> = Vec::new();
            let mut selected_values: Vec<&serde_json::Value> = Vec::new();
            for field in &descriptor.constraints.fields {
                if field.zk_predicate.is_some() {
                    field_errors.push(format!(
                        "Descriptor '{}': required ZK predicate has no bound proof result",
                        descriptor.id
                    ));
                    continue;
                }

                if field.path.is_empty() {
                    field_errors.push(format!(
                        "Descriptor '{}': field path array must not be empty",
                        descriptor.id
                    ));
                    continue;
                }
                if let Some(unsupported) = field
                    .path
                    .iter()
                    .find(|path| !Self::is_supported_json_path(path))
                {
                    field_errors.push(format!(
                        "Descriptor '{}': unsupported JSONPath expression '{}'",
                        descriptor.id, unsupported
                    ));
                    continue;
                }

                let matched = field
                    .path
                    .iter()
                    .find_map(|path| Self::json_path_get(credential_doc, path));

                match matched {
                    None if field.optional.unwrap_or(false) => {} // absent but optional — ok
                    None => {
                        field_errors.push(format!(
                            "Descriptor '{}': required claim not found at paths {:?}",
                            descriptor.id, field.path
                        ));
                    }
                    Some(val) => {
                        selected_values.push(val);
                        if let Some(ref filter) = field.filter {
                            if let Err(e) = Self::apply_json_schema_filter(val, filter) {
                                field_errors.push(format!(
                                    "Descriptor '{}': field filter not satisfied — {}",
                                    descriptor.id, e
                                ));
                            }
                        }
                    }
                }
            }

            if descriptor.constraints.limit_disclosure.as_deref() == Some("required")
                && field_errors.is_empty()
                && !Self::contains_only_selected_values(credential_doc, &selected_values)
            {
                field_errors.push(format!(
                    "Descriptor '{}': limit_disclosure:required but unrequested values were disclosed",
                    descriptor.id
                ));
            }

            let valid = field_errors.is_empty();
            let error = if valid {
                None
            } else {
                Some(field_errors.join("; "))
            };
            errors.extend(field_errors);

            // Reuse the format label from the structural result.
            let format = structural
                .descriptor_results
                .iter()
                .find(|r| r.descriptor_id == descriptor.id)
                .map(|r| r.format.clone())
                .unwrap_or_else(|| leaf_map.format.clone());

            descriptor_results.push(DescriptorVerificationResult {
                descriptor_id: descriptor.id.clone(),
                valid,
                format,
                error,
            });
        }

        let all_valid = errors.is_empty() && descriptor_results.iter().all(|r| r.valid);
        let mut evidence = VerificationEvidence::not_checked();
        evidence.presentation_structure = VerificationCheckStatus::Passed;
        evidence.presentation_constraints = if all_valid {
            VerificationCheckStatus::Passed
        } else {
            VerificationCheckStatus::Failed
        };
        VerificationResult::low_level(
            VerificationScope::PresentationExchange,
            all_valid,
            evidence,
            descriptor_results,
            structural.zk_results,
            errors,
        )
    }

    fn validate_descriptor_map_chain<'a>(
        entry: &'a DescriptorMapEntry,
        expected_id: &str,
    ) -> Result<&'a DescriptorMapEntry, String> {
        let mut current = entry;
        loop {
            if current.id != expected_id {
                return Err(format!(
                    "Descriptor '{expected_id}': nested mapping id '{}' does not match",
                    current.id
                ));
            }
            if current.format.trim().is_empty() {
                return Err(format!(
                    "Descriptor '{expected_id}': mapping format must be non-empty"
                ));
            }
            if !Self::is_supported_json_path(&current.path) {
                return Err(format!(
                    "Descriptor '{expected_id}': unsupported mapping JSONPath '{}'",
                    current.path
                ));
            }

            match current.path_nested.as_deref() {
                Some(nested) => current = nested,
                None => return Ok(current),
            }
        }
    }

    fn descriptor_map_get<'a>(
        root: &'a serde_json::Value,
        entry: &DescriptorMapEntry,
    ) -> Option<&'a serde_json::Value> {
        let mut current_value = root;
        let mut current_entry = entry;
        loop {
            current_value = Self::json_path_get(current_value, &current_entry.path)?;
            match current_entry.path_nested.as_deref() {
                Some(nested) => current_entry = nested,
                None => return Some(current_value),
            }
        }
    }

    fn is_selective_disclosure_format(format: &str) -> bool {
        matches!(
            format,
            "dc+sd-jwt" | "vc+sd-jwt" | "spruce-vc+sd-jwt" | "sd_jwt" | "sd-jwt"
        )
    }

    fn contains_only_selected_values(
        root: &serde_json::Value,
        selected: &[&serde_json::Value],
    ) -> bool {
        let mut allowed = HashSet::new();
        for value in selected {
            Self::collect_value_addresses(value, &mut allowed, false);
        }

        let mut disclosed = HashSet::new();
        Self::collect_value_addresses(root, &mut disclosed, true);
        disclosed.is_subset(&allowed)
    }

    fn collect_value_addresses(
        value: &serde_json::Value,
        addresses: &mut HashSet<usize>,
        terminals_only: bool,
    ) {
        let terminal = match value {
            serde_json::Value::Array(values) => values.is_empty(),
            serde_json::Value::Object(values) => values.is_empty(),
            _ => true,
        };
        if !terminals_only || terminal {
            addresses.insert(value as *const serde_json::Value as usize);
        }

        match value {
            serde_json::Value::Array(values) => {
                for child in values {
                    Self::collect_value_addresses(child, addresses, terminals_only);
                }
            }
            serde_json::Value::Object(values) => {
                for child in values.values() {
                    Self::collect_value_addresses(child, addresses, terminals_only);
                }
            }
            _ => {}
        }
    }

    fn is_supported_json_path(path: &str) -> bool {
        if path == "$" {
            return true;
        }
        let Some(rest) = path.strip_prefix("$.") else {
            return false;
        };
        if rest.is_empty() {
            return false;
        }

        let segments = Self::split_path_segments(rest);
        if segments.is_empty() || segments.iter().any(|segment| segment.is_empty()) {
            return false;
        }

        segments.iter().all(|segment| {
            if segment.chars().any(|character| {
                matches!(
                    character,
                    '*' | '?' | '@' | '(' | ')' | ',' | ':' | '\'' | '"'
                )
            }) {
                return false;
            }

            let open_count = segment.matches('[').count();
            let close_count = segment.matches(']').count();
            match (open_count, close_count) {
                (0, 0) => true,
                (1, 1) => {
                    let Some(open) = segment.find('[') else {
                        return false;
                    };
                    segment.ends_with(']')
                        && open > 0
                        && segment[open + 1..segment.len() - 1]
                            .chars()
                            .all(|character| character.is_ascii_digit())
                        && open + 1 < segment.len() - 1
                }
                _ => false,
            }
        })
    }

    /// Extract a value from a JSON document using a simple JSONPath expression.
    ///
    /// Supported subset:
    ///   - `$`            — root document
    ///   - `$.field`      — top-level field
    ///   - `$.a.b.c`      — nested path
    ///   - `$.a\.b.c`     — escaped dots (mDoc namespace separators)
    ///   - `$.arr[0]`     — zero-based array index
    ///
    /// Recursive descent (`..`), wildcards (`*`), and filter expressions
    /// (`?(...)`) are not supported — they are not used in Marty PDs.
    pub(crate) fn json_path_get<'a>(
        root: &'a serde_json::Value,
        path: &str,
    ) -> Option<&'a serde_json::Value> {
        if !Self::is_supported_json_path(path) {
            return None;
        }
        let rest = path.strip_prefix('$')?;
        if rest.is_empty() {
            return Some(root);
        }
        let rest = rest.strip_prefix('.').unwrap_or(rest);
        let segments = Self::split_path_segments(rest);
        let mut current = root;
        for seg in &segments {
            if let Some(bracket) = seg.find('[') {
                let field = &seg[..bracket];
                let end = seg.rfind(']').unwrap_or(seg.len());
                let idx: usize = seg[bracket + 1..end].parse().ok()?;
                current = current.get(field)?;
                current = current.get(idx)?;
            } else {
                let field = seg.replace("\\.", ".");
                current = current.get(field.as_str())?;
            }
        }
        Some(current)
    }

    /// Split a JSONPath tail on unescaped dots.
    fn split_path_segments(path: &str) -> Vec<String> {
        let mut segments: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut chars = path.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    current.push('\\');
                    if chars.peek() == Some(&'.') {
                        current.push(chars.next().unwrap());
                    }
                }
                '.' => {
                    segments.push(std::mem::take(&mut current));
                }
                _ => current.push(c),
            }
        }
        if !current.is_empty() {
            segments.push(current);
        }
        segments
    }

    /// Apply a JSON Schema draft-07 subset filter to a value.
    ///
    /// Supported keywords:
    /// - `type`     — `"string"`, `"number"`, `"array"`, `"object"`, `"boolean"`, `"null"`
    /// - `const`    — exact equality
    /// - `enum`     — membership in array
    /// - `minimum`  — numeric lower bound (inclusive)
    /// - `maximum`  — numeric upper bound (inclusive)
    /// - `pattern`  — ECMA 262 regular expression (JSON Schema §6.3.3)
    /// - `contains` — at least one array element satisfies a sub-schema
    /// - `format`   — `date`, `date-time`, or `uri`
    ///
    /// Unsupported assertion keywords, malformed schemas, and invalid regular
    /// expressions fail closed. Annotation-only keywords are ignored.
    fn apply_json_schema_filter(
        value: &serde_json::Value,
        filter: &serde_json::Value,
    ) -> Result<(), String> {
        let obj = filter
            .as_object()
            .ok_or_else(|| "JSON Schema filter must be an object".to_string())?;

        const SUPPORTED_ASSERTIONS: &[&str] = &[
            "type", "const", "enum", "minimum", "maximum", "pattern", "contains", "format",
        ];
        const ANNOTATIONS: &[&str] = &[
            "$schema",
            "$id",
            "$comment",
            "title",
            "description",
            "default",
            "examples",
            "readOnly",
            "writeOnly",
        ];
        for keyword in obj.keys() {
            if !SUPPORTED_ASSERTIONS.contains(&keyword.as_str())
                && !ANNOTATIONS.contains(&keyword.as_str())
            {
                return Err(format!(
                    "unsupported JSON Schema assertion keyword '{keyword}'"
                ));
            }
        }

        if let Some(type_value) = obj.get("type") {
            let expected_type = type_value
                .as_str()
                .ok_or_else(|| "JSON Schema 'type' must be a string".to_string())?;
            let matches = match expected_type {
                "string" => value.is_string(),
                "number" => value.is_number(),
                "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
                "array" => value.is_array(),
                "object" => value.is_object(),
                "boolean" => value.is_boolean(),
                "null" => value.is_null(),
                unsupported => return Err(format!("unsupported JSON Schema type '{unsupported}'")),
            };
            if !matches {
                return Err(format!(
                    "type mismatch: expected '{expected_type}', got {value}"
                ));
            }
        }

        if let Some(expected) = obj.get("const") {
            if value != expected {
                return Err(format!("const mismatch: expected {expected}, got {value}"));
            }
        }

        if let Some(enum_value) = obj.get("enum") {
            let variants = enum_value
                .as_array()
                .filter(|variants| !variants.is_empty())
                .ok_or_else(|| "JSON Schema 'enum' must be a non-empty array".to_string())?;
            if !variants.contains(value) {
                return Err(format!("enum: {value} is not one of {variants:?}"));
            }
        }

        if let Some(minimum_value) = obj.get("minimum") {
            let min = minimum_value
                .as_f64()
                .ok_or_else(|| "JSON Schema 'minimum' must be a number".to_string())?;
            match value.as_f64() {
                Some(n) if n >= min => {}
                Some(n) => return Err(format!("minimum {min}: {n} is below minimum")),
                None => return Err(format!("minimum {min}: value is not a number")),
            }
        }

        if let Some(maximum_value) = obj.get("maximum") {
            let max = maximum_value
                .as_f64()
                .ok_or_else(|| "JSON Schema 'maximum' must be a number".to_string())?;
            match value.as_f64() {
                Some(n) if n <= max => {}
                Some(n) => return Err(format!("maximum {max}: {n} exceeds maximum")),
                None => return Err(format!("maximum {max}: value is not a number")),
            }
        }

        if let Some(pattern_value) = obj.get("pattern") {
            let pattern = pattern_value
                .as_str()
                .ok_or_else(|| "JSON Schema 'pattern' must be a string".to_string())?;
            let s = value
                .as_str()
                .ok_or_else(|| "JSON Schema 'pattern' requires a string value".to_string())?;
            // JSON Schema §6.3.3: pattern uses ECMA 262 regular expressions.
            // The `regex` crate is compatible for all patterns used in DIF PEX spec examples.
            match regex::Regex::new(pattern) {
                Ok(re) => {
                    if !re.is_match(s) {
                        return Err(format!("pattern '{pattern}' not matched by '{s}'"));
                    }
                }
                Err(error) => return Err(format!("invalid pattern '{pattern}': {error}")),
            }
        }

        if let Some(format_value) = obj.get("format") {
            let format = format_value
                .as_str()
                .ok_or_else(|| "JSON Schema 'format' must be a string".to_string())?;
            let text = value
                .as_str()
                .ok_or_else(|| format!("JSON Schema format '{format}' requires a string value"))?;
            let valid = match format {
                "date" => chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").is_ok(),
                "date-time" => chrono::DateTime::parse_from_rfc3339(text).is_ok(),
                "uri" => url::Url::parse(text).is_ok(),
                unsupported => {
                    return Err(format!(
                        "unsupported JSON Schema format assertion '{unsupported}'"
                    ))
                }
            };
            if !valid {
                return Err(format!(
                    "value does not satisfy JSON Schema format '{format}'"
                ));
            }
        }

        if let Some(contains_schema) = obj.get("contains") {
            match value.as_array() {
                None => {
                    return Err(format!("`contains` applied to non-array: {value}"));
                }
                Some(arr) => {
                    let satisfied = arr
                        .iter()
                        .any(|elem| Self::apply_json_schema_filter(elem, contains_schema).is_ok());
                    if !satisfied {
                        return Err(format!(
                            "array does not contain element satisfying: {contains_schema}"
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

// ── Builder helpers ──────────────────────────────────────────────────

/// Build a presentation definition for age verification using ZK proofs.
///
/// This is a convenience function for the most common ZK use case:
/// verifying that a holder is 18+ without learning their birth date.
pub fn age_verification_definition(
    verifier: &VerificationEngine,
    nonce: &str,
) -> Oid4vciResult<PresentationDefinition> {
    let descriptor = verifier.zk_predicate_descriptor(
        "age_verification",
        "$.org\\.iso\\.18013\\.5\\.1.birth_date",
        "age_over_18",
        nonce,
    );

    verifier.create_presentation_definition("age_verification_request", vec![descriptor])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> VerificationEngine {
        VerificationEngine::new(
            "did:example:verifier",
            "https://verifier.example.com/response",
        )
    }

    #[test]
    fn test_create_presentation_definition() {
        let engine = test_engine();
        let desc = engine.mdl_descriptor("mdl_request", &["family_name", "birth_date"]);

        let pd = engine
            .create_presentation_definition("test_pd", vec![desc])
            .unwrap();

        assert_eq!(pd.id, "test_pd");
        assert_eq!(pd.input_descriptors.len(), 1);
        assert_eq!(pd.input_descriptors[0].constraints.fields.len(), 2);
    }

    #[test]
    fn test_empty_descriptors_error() {
        let engine = test_engine();
        let err = engine
            .create_presentation_definition("empty", vec![])
            .unwrap_err();
        assert!(err.to_string().contains("at least one input descriptor"));
    }

    #[test]
    fn test_zk_predicate_descriptor() {
        let engine = test_engine();
        let desc = engine.zk_predicate_descriptor(
            "age_check",
            "$.org\\.iso\\.18013\\.5\\.1.birth_date",
            "age_over_18",
            "dGVzdG5vbmNl",
        );

        assert_eq!(desc.id, "age_check");
        let zk = desc.constraints.fields[0].zk_predicate.as_ref().unwrap();
        assert_eq!(zk.predicate, "age_over_18");
        assert_eq!(zk.proof_type, "longfellow-zk-ligero");
        assert_eq!(zk.nonce, "dGVzdG5vbmNl");
    }

    #[test]
    fn test_create_zk_challenge() {
        let engine = test_engine();
        let challenge = engine.create_zk_challenge("age_over_18").unwrap();

        assert_eq!(challenge.predicate, "age_over_18");
        assert!(!challenge.nonce.is_empty());
        assert_eq!(challenge.nonce_bytes.len(), 32);
        assert_eq!(challenge.expires_in_seconds, 600);
    }

    #[test]
    fn test_verify_presentation_structure_valid() {
        let engine = test_engine();
        let desc = engine.mdl_descriptor("mdl_request", &["family_name"]);
        let pd = engine
            .create_presentation_definition("test_pd", vec![desc])
            .unwrap();

        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "test_pd".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "mdl_request".into(),
                format: "mso_mdoc".into(),
                path: "$".into(),
                path_nested: None,
            }],
        };

        let result = engine.verify_presentation_structure(&pd, &submission);
        assert!(result.check_valid);
        assert!(result.errors.is_empty());
        assert_eq!(
            result.evidence.presentation_structure,
            VerificationCheckStatus::Passed
        );
        assert_eq!(
            result.evidence.presentation_constraints,
            VerificationCheckStatus::NotChecked
        );
        assert_eq!(result.descriptor_results.len(), 1);
        assert!(result.descriptor_results[0].valid);
    }

    #[test]
    fn test_verify_presentation_structure_wrong_definition_id() {
        let engine = test_engine();
        let desc = engine.mdl_descriptor("mdl_request", &["family_name"]);
        let pd = engine
            .create_presentation_definition("test_pd", vec![desc])
            .unwrap();

        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "wrong_id".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "mdl_request".into(),
                format: "mso_mdoc".into(),
                path: "$".into(),
                path_nested: None,
            }],
        };

        let result = engine.verify_presentation_structure(&pd, &submission);
        assert!(!result.check_valid);
        assert!(result.errors[0].contains("does not match"));
    }

    #[test]
    fn test_verify_presentation_structure_missing_descriptor() {
        let engine = test_engine();
        let desc = engine.mdl_descriptor("mdl_request", &["family_name"]);
        let pd = engine
            .create_presentation_definition("test_pd", vec![desc])
            .unwrap();

        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "test_pd".into(),
            descriptor_map: vec![], // no mappings
        };

        let result = engine.verify_presentation_structure(&pd, &submission);
        assert!(!result.check_valid);
        assert!(result.descriptor_results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("No descriptor mapping"));
    }

    #[test]
    fn test_verify_presentation_structure_wrong_format() {
        let engine = test_engine();
        let desc = engine.mdl_descriptor("mdl_request", &["family_name"]);
        let pd = engine
            .create_presentation_definition("test_pd", vec![desc])
            .unwrap();

        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "test_pd".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "mdl_request".into(),
                format: "jwt_vc_json".into(), // wrong format
                path: "$".into(),
                path_nested: None,
            }],
        };

        let result = engine.verify_presentation_structure(&pd, &submission);
        assert!(!result.check_valid);
        assert!(result.descriptor_results[0]
            .error
            .as_ref()
            .unwrap()
            .contains("not in accepted formats"));
    }

    #[test]
    fn test_verify_presentation_structure_rejects_invalid_nested_mapping() {
        let engine = test_engine();
        let desc = engine.mdl_descriptor("mdl_request", &["family_name"]);
        let pd = engine
            .create_presentation_definition("test_pd", vec![desc])
            .unwrap();

        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "test_pd".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "mdl_request".into(),
                format: "jwt_vp".into(),
                path: "$".into(),
                path_nested: Some(Box::new(DescriptorMapEntry {
                    id: "different_descriptor".into(),
                    format: "mso_mdoc".into(),
                    path: "$.credential".into(),
                    path_nested: None,
                })),
            }],
        };

        let result = engine.verify_presentation_structure(&pd, &submission);
        assert!(!result.check_valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("nested mapping id")));
    }

    #[test]
    fn test_verify_presentation_structure_rejects_unsupported_mapping_path() {
        let engine = test_engine();
        let desc = engine.mdl_descriptor("mdl_request", &["family_name"]);
        let pd = engine
            .create_presentation_definition("test_pd", vec![desc])
            .unwrap();

        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "test_pd".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "mdl_request".into(),
                format: "mso_mdoc".into(),
                path: "$..credential".into(),
                path_nested: None,
            }],
        };

        let result = engine.verify_presentation_structure(&pd, &submission);
        assert!(!result.check_valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("unsupported mapping JSONPath")));
    }

    #[test]
    fn test_limit_disclosure_rejects_spoofed_format_name() {
        let engine = test_engine();
        let pd = PresentationDefinition {
            id: "test_pd".into(),
            name: None,
            purpose: None,
            input_descriptors: vec![InputDescriptor {
                id: "credential".into(),
                name: None,
                purpose: None,
                format: None,
                constraints: Constraints {
                    fields: vec![],
                    limit_disclosure: Some("required".into()),
                },
            }],
        };
        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "test_pd".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "credential".into(),
                format: "attacker_sd_jwt_wrapper".into(),
                path: "$".into(),
                path_nested: None,
            }],
        };

        let result = engine.verify_presentation(&pd, &submission, Some(&serde_json::json!({})));
        assert!(!result.check_valid);
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("not SD-JWT")));
    }

    #[test]
    fn test_limit_disclosure_rejects_unrequested_values() {
        let engine = test_engine();
        let pd = PresentationDefinition {
            id: "test_pd".into(),
            name: None,
            purpose: None,
            input_descriptors: vec![InputDescriptor {
                id: "credential".into(),
                name: None,
                purpose: None,
                format: None,
                constraints: Constraints {
                    fields: vec![FieldConstraint {
                        path: vec!["$.role".into()],
                        filter: None,
                        optional: None,
                        zk_predicate: None,
                    }],
                    limit_disclosure: Some("required".into()),
                },
            }],
        };
        let submission = PresentationSubmission {
            id: "sub_1".into(),
            definition_id: "test_pd".into(),
            descriptor_map: vec![DescriptorMapEntry {
                id: "credential".into(),
                format: "dc+sd-jwt".into(),
                path: "$".into(),
                path_nested: None,
            }],
        };

        let pass = engine.verify_presentation(
            &pd,
            &submission,
            Some(&serde_json::json!({"role": "admin"})),
        );
        let fail = engine.verify_presentation(
            &pd,
            &submission,
            Some(&serde_json::json!({"role": "admin", "secret": "extra"})),
        );

        assert!(pass.check_valid, "requested-only values should pass");
        assert!(!fail.check_valid);
        assert!(fail
            .errors
            .iter()
            .any(|error| error.contains("unrequested values")));
    }

    #[test]
    fn test_verify_vp_token_rejects_non_url_safe_expected_nonce() {
        let result = test_engine().verify_vp_token("not.a.jwt", "nonce with spaces");
        assert!(!result.check_valid);
        assert!(result.errors[0].contains("ASCII URL-safe"));
    }

    #[test]
    fn test_age_verification_definition() {
        let engine = test_engine();
        let pd = age_verification_definition(&engine, "testnonce123").unwrap();

        assert_eq!(pd.id, "age_verification_request");
        assert_eq!(pd.input_descriptors.len(), 1);
        let zk = pd.input_descriptors[0].constraints.fields[0]
            .zk_predicate
            .as_ref()
            .unwrap();
        assert_eq!(zk.predicate, "age_over_18");
    }

    #[test]
    fn test_verify_vp_token_malformed() {
        let engine = test_engine();
        let result = engine.verify_vp_token("not.a.jwt.at.all", "nonce");
        assert!(!result.check_valid);
        assert!(
            result.errors[0].contains("header parse error") || result.errors[0].contains("3 parts")
        );
    }

    #[test]
    fn test_verify_vp_token_nonce_mismatch() {
        let engine = test_engine();
        // Craft a minimal payload with wrong nonce (no signature check yet — key missing)
        use base64::Engine;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ES256","typ":"JWT"}"#);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"iss":"did:example:holder","aud":"did:example:verifier","nonce":"wrong","iat":1000000000}"#,
        );
        let fake_token = format!("{}.{}.fake_sig", header_b64, payload_b64);
        let result = engine.verify_vp_token(&fake_token, "correct_nonce");
        assert!(!result.check_valid);
        assert!(result.errors[0].contains("nonce does not match"));
    }

    #[test]
    fn test_verify_vp_token_audience_mismatch() {
        let engine = test_engine(); // verifier_id = "did:example:verifier"
        use base64::Engine;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ES256","typ":"JWT"}"#);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"iss":"did:example:holder","aud":"did:example:wrong_verifier","nonce":"abc","iat":1000000000}"#,
        );
        let fake_token = format!("{}.{}.fake_sig", header_b64, payload_b64);
        let result = engine.verify_vp_token(&fake_token, "abc");
        assert!(!result.check_valid);
        assert!(result.errors[0].contains("audience does not match"));
    }

    #[test]
    fn test_verify_vp_token_no_key() {
        let engine = test_engine();
        use base64::Engine;
        let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"alg":"ES256","typ":"JWT"}"#);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            r#"{"iss":"did:example:holder","aud":"did:example:verifier","nonce":"testnonce","iat":1000000000,"exp":9999999999}"#,
        );
        let fake_token = format!("{}.{}.fake_sig", header_b64, payload_b64);
        let result = engine.verify_vp_token(&fake_token, "testnonce");
        assert!(!result.check_valid);
        assert!(result.errors[0].contains("No presentation public key"));
    }

    #[test]
    fn test_presentation_definition_serialization() {
        let engine = test_engine();
        let desc =
            engine.zk_predicate_descriptor("age_check", "$.birth_date", "age_over_18", "nonce123");
        let pd = engine
            .create_presentation_definition("pd_1", vec![desc])
            .unwrap();

        let json = serde_json::to_string_pretty(&pd).unwrap();
        assert!(json.contains("age_over_18"));
        assert!(json.contains("longfellow-zk-ligero"));
        assert!(json.contains("nonce123"));

        // Round-trip
        let parsed: PresentationDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "pd_1");
    }
}
