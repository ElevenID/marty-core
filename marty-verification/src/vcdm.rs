//! W3C Verifiable Credentials Data Model v2 Data Integrity verification.
//!
//! This module deliberately starts with the standards-track
//! `eddsa-rdfc-2022` cryptosuite and offline `did:key` resolution. It verifies
//! presentation proofs, binds their challenge and domain, and independently
//! verifies every embedded credential rather than trusting a valid outer proof.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use iref::IriBuf;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::data_integrity::{
    AnyProtocol, AnySignatureAlgorithm, AnySuite, CryptographicSuite, DataIntegrity, ProofOptions,
};
use ssi_claims::vc::syntax::{AnyJsonCredential, AnyJsonPresentation};
use ssi_claims::{
    MessageSignatureError, SignatureEnvironment, SignatureError, ValidateProof, VerifiableClaims,
    VerificationParameters,
};
use ssi_dids::{DIDKey, DIDResolver, VerificationMethodDIDResolver};
use ssi_jwk::Params as JwkParams;
use ssi_jwk::{Algorithm, JWKResolver, JWK};
use ssi_verification_methods::{
    AnyMethod, MessageSigner, Multikey, ProofPurpose, ReferenceOrOwned, ReferenceOrOwnedRef,
    ResolutionOptions, SignatureProtocol, Signer, VerificationMethod,
    VerificationMethodResolutionError, VerificationMethodResolver,
};
use std::{
    borrow::Cow,
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::open_badges::open_badges_context_loader;

type AnyCredential = DataIntegrity<AnyJsonCredential, AnySuite>;
type AnyPresentation = DataIntegrity<AnyJsonPresentation, AnySuite>;

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    document: Value,
    #[serde(default)]
    expected_challenge: Option<String>,
    #[serde(default)]
    expected_domain: Option<String>,
    /// Public verification methods obtained from the product DID resolver.
    ///
    /// This is an internal verifier input, not a caller-selectable key or KMS
    /// coordinate. Private JWK parameters and controller mismatches are
    /// rejected before the methods can enter the resolver.
    #[serde(default)]
    resolved_verification_methods: Vec<ResolvedVerificationMethod>,
}

#[derive(Debug, Deserialize)]
struct ResolvedVerificationMethod {
    id: String,
    controller: String,
    public_jwk: Value,
}

#[derive(Debug, Serialize)]
struct VerifyResult {
    valid: bool,
    kind: &'static str,
    verified_proofs: usize,
    verified_credentials: usize,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyJwtRequest {
    token: String,
    /// Public verification material resolved from the issuer profile's DID.
    /// Private JWK parameters are rejected at this boundary.
    #[serde(default)]
    issuer_public_jwk: Option<Value>,
}

#[derive(Debug, Serialize)]
struct VerifyJwtResult {
    valid: bool,
    algorithm: Option<String>,
    issuer: Option<String>,
    claims: Option<Value>,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PrepareDataIntegrityCredentialRequest {
    credential: Value,
    issuer_did: String,
    verification_method_id: String,
    public_jwk: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct PreparedDataIntegrityCredential {
    credential: Value,
    issuer_did: String,
    verification_method_id: String,
    public_jwk: Value,
    algorithm: String,
    signing_input_b64: String,
}

#[derive(Debug, Deserialize)]
struct CompleteDataIntegrityCredentialRequest {
    prepared: PreparedDataIntegrityCredential,
    signature_b64: String,
}

#[derive(Debug, Clone)]
struct CapturedSigningInput {
    algorithm: String,
    message: Vec<u8>,
}

#[derive(Clone)]
struct CaptureSigner {
    expected_method: IriBuf,
    captured: Arc<Mutex<Option<CapturedSigningInput>>>,
}

#[derive(Clone)]
struct CaptureMessageSigner {
    captured: Arc<Mutex<Option<CapturedSigningInput>>>,
}

struct ResolvedDidResolver {
    methods: HashMap<IriBuf, AnyMethod>,
    did_key: VerificationMethodDIDResolver<DIDKey, AnyMethod>,
}

impl VerificationMethodResolver for ResolvedDidResolver {
    type Method = AnyMethod;

    async fn resolve_verification_method_with(
        &'_ self,
        issuer: Option<&iref::Iri>,
        method: Option<ReferenceOrOwnedRef<'_, Self::Method>>,
        options: ResolutionOptions,
    ) -> Result<Cow<'_, Self::Method>, VerificationMethodResolutionError> {
        if let Some(ReferenceOrOwnedRef::Reference(id)) = method {
            if let Some(resolved) = self.methods.get(id) {
                return Ok(Cow::Borrowed(resolved));
            }
        }
        self.did_key
            .resolve_verification_method_with(issuer, method, options)
            .await
    }
}

impl Signer<AnyMethod> for CaptureSigner {
    type MessageSigner = CaptureMessageSigner;

    async fn for_method(
        &self,
        method: Cow<'_, AnyMethod>,
    ) -> Result<Option<Self::MessageSigner>, SignatureError> {
        if method.id() != self.expected_method.as_iri() {
            return Ok(None);
        }
        Ok(Some(CaptureMessageSigner {
            captured: Arc::clone(&self.captured),
        }))
    }
}

impl MessageSigner<AnySignatureAlgorithm> for CaptureMessageSigner {
    async fn sign(
        self,
        ssi_verification_methods::protocol::WithProtocol(algorithm, protocol):
            <AnySignatureAlgorithm as ssi_crypto::algorithm::SignatureAlgorithmType>::Instance,
        message: &[u8],
    ) -> Result<Vec<u8>, MessageSignatureError> {
        let prepared_message = protocol.prepare_message(message).into_owned();
        let algorithm_name = algorithm.algorithm().to_string();
        if algorithm_name != "EdDSA" || protocol != AnyProtocol::None {
            return Err(MessageSignatureError::UnsupportedAlgorithm(format!(
                "{algorithm_name} with protocol {protocol:?}"
            )));
        }

        let mut captured = self
            .captured
            .lock()
            .map_err(|_| MessageSignatureError::InvalidResponse)?;
        if captured.is_some() {
            return Err(MessageSignatureError::InvalidResponse);
        }
        *captured = Some(CapturedSigningInput {
            algorithm: algorithm_name,
            message: prepared_message,
        });

        // The SSI library must build the exact proof configuration before a
        // remote signer can receive the canonical bytes. A fixed-size
        // placeholder lets it serialize that proof without handling private
        // key material. Completion always replaces it and verifies the final
        // proof against the issuer profile's public key.
        Ok(vec![0_u8; 64])
    }
}

/// Prepare a W3C VCDM v2 `eddsa-rdfc-2022` credential for remote signing.
///
/// The returned signing input is the exact byte sequence produced by the SSI
/// canonicalization implementation. Private JWK parameters are rejected.
pub async fn prepare_vcdm_data_integrity_credential_json_async(
    request_json: &str,
) -> Result<String, String> {
    let request: PrepareDataIntegrityCredentialRequest = serde_json::from_str(request_json)
        .map_err(|error| format!("Invalid Data Integrity prepare request: {error}"))?;
    validate_data_integrity_identity(
        &request.credential,
        &request.issuer_did,
        &request.verification_method_id,
    )?;
    validate_data_integrity_issuance_dates(&request.credential)?;
    if request.credential.get("proof").is_some() {
        return Err("Credential already contains a proof".to_string());
    }

    let public_jwk = parse_public_jwk(request.public_jwk.clone())?;
    let method = ed25519_multikey(
        &public_jwk,
        &request.issuer_did,
        &request.verification_method_id,
    )?;
    let method_id = method.id.clone();
    let mut resolver = HashMap::new();
    resolver.insert(method_id.clone(), AnyMethod::Multikey(method));

    let credential: AnyJsonCredential = serde_json::from_value(request.credential)
        .map_err(|error| format!("Invalid VCDM v2 credential: {error}"))?;
    let suite = AnySuite::EdDsaRdfc2022;
    let mut proof_options =
        ProofOptions::from_method(ReferenceOrOwned::Reference(method_id.clone()));
    proof_options.proof_purpose = ProofPurpose::Assertion;

    let captured = Arc::new(Mutex::new(None));
    let signer = CaptureSigner {
        expected_method: method_id,
        captured: Arc::clone(&captured),
    };
    let environment = SignatureEnvironment {
        json_ld_loader: open_badges_context_loader().map_err(|error| error.to_string())?,
        eip712_loader: (),
    };
    let prepared_credential = suite
        .sign_with(
            environment,
            credential,
            &resolver,
            &signer,
            proof_options,
            Default::default(),
        )
        .await
        .map_err(|error| format!("Data Integrity preparation failed: {error}"))?;
    let captured = captured
        .lock()
        .map_err(|_| "Data Integrity signing input lock was poisoned".to_string())?
        .take()
        .ok_or_else(|| "Data Integrity suite produced no signing input".to_string())?;

    serde_json::to_string(&PreparedDataIntegrityCredential {
        credential: serde_json::to_value(prepared_credential)
            .map_err(|error| format!("Failed to serialize prepared credential: {error}"))?,
        issuer_did: request.issuer_did,
        verification_method_id: request.verification_method_id,
        public_jwk: serde_json::to_value(public_jwk)
            .map_err(|error| format!("Failed to serialize public JWK: {error}"))?,
        algorithm: captured.algorithm,
        signing_input_b64: URL_SAFE_NO_PAD.encode(captured.message),
    })
    .map_err(|error| format!("Failed to serialize Data Integrity signing request: {error}"))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn prepare_vcdm_data_integrity_credential_json(request_json: &str) -> Result<String, String> {
    futures::executor::block_on(prepare_vcdm_data_integrity_credential_json_async(
        request_json,
    ))
}

/// Complete and verify a remotely signed W3C VCDM v2 credential.
///
/// Completion fails if the credential, DID, verification method, public key,
/// or signature changed incompatibly after preparation.
pub async fn complete_vcdm_data_integrity_credential_json_async(
    request_json: &str,
) -> Result<String, String> {
    let request: CompleteDataIntegrityCredentialRequest = serde_json::from_str(request_json)
        .map_err(|error| format!("Invalid Data Integrity completion request: {error}"))?;
    let mut prepared = request.prepared;
    validate_data_integrity_identity(
        &prepared.credential,
        &prepared.issuer_did,
        &prepared.verification_method_id,
    )?;
    validate_data_integrity_issuance_dates(&prepared.credential)?;
    if prepared.algorithm != "EdDSA" {
        return Err(format!(
            "Unsupported Data Integrity signing algorithm: {}",
            prepared.algorithm
        ));
    }
    URL_SAFE_NO_PAD
        .decode(&prepared.signing_input_b64)
        .map_err(|error| format!("Invalid prepared signing input: {error}"))?;

    let public_jwk = parse_public_jwk(prepared.public_jwk.clone())?;
    let method = ed25519_multikey(
        &public_jwk,
        &prepared.issuer_did,
        &prepared.verification_method_id,
    )?;
    let method_id = method.id.clone();
    let signature = URL_SAFE_NO_PAD
        .decode(&request.signature_b64)
        .map_err(|error| format!("Invalid Data Integrity signature encoding: {error}"))?;
    if signature.len() != 64 {
        return Err(format!(
            "EdDSA Data Integrity signature must be 64 bytes, got {}",
            signature.len()
        ));
    }

    let proof = prepared
        .credential
        .get_mut("proof")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "Prepared credential must contain one proof object".to_string())?;
    if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof")
        || proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-rdfc-2022")
        || proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod")
        || proof.get("verificationMethod").and_then(Value::as_str)
            != Some(prepared.verification_method_id.as_str())
    {
        return Err("Prepared credential proof configuration changed".to_string());
    }
    proof.insert(
        "proofValue".to_string(),
        Value::String(format!("z{}", bs58::encode(signature).into_string())),
    );

    let credential: AnyCredential = serde_json::from_value(prepared.credential.clone())
        .map_err(|error| format!("Invalid completed VCDM credential: {error}"))?;
    let mut resolver = HashMap::new();
    resolver.insert(method_id, AnyMethod::Multikey(method));
    let parameters = VerificationParameters::from_resolver(resolver)
        .with_json_ld_loader(open_badges_context_loader().map_err(|error| error.to_string())?);
    // Completion verifies the exact proof produced by the remote custody
    // service, but it must not impose a "valid right now" policy on issuance.
    // VCDM v2 explicitly permits validFrom in the future and validUntil in the
    // past. The public verifier still uses `VerifiableClaims::verify`, which
    // validates current-time claims as well as the proof.
    match credential
        .proof()
        .validate_proof(&parameters, credential.claims())
        .await
    {
        Ok(Ok(())) => serde_json::to_string(&prepared.credential)
            .map_err(|error| format!("Failed to serialize completed credential: {error}")),
        Ok(Err(invalid)) => Err(format!(
            "Completed Data Integrity credential proof is invalid: {invalid}"
        )),
        Err(error) => Err(format!(
            "Completed Data Integrity credential proof verification failed: {error}"
        )),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn complete_vcdm_data_integrity_credential_json(request_json: &str) -> Result<String, String> {
    futures::executor::block_on(complete_vcdm_data_integrity_credential_json_async(
        request_json,
    ))
}

fn validate_data_integrity_identity(
    credential: &Value,
    issuer_did: &str,
    verification_method_id: &str,
) -> Result<(), String> {
    if !issuer_did.starts_with("did:") {
        return Err("issuer_did must be a DID".to_string());
    }
    if identifier(credential, "issuer") != Some(issuer_did) {
        return Err("Credential issuer must exactly match issuer_did".to_string());
    }
    if verification_method_id.split_once('#').map(|(did, _)| did) != Some(issuer_did) {
        return Err("Verification method controller must exactly match issuer_did".to_string());
    }
    if !has_type(credential, "VerifiableCredential") {
        return Err("Document must be a VerifiableCredential".to_string());
    }
    if !matches!(
        credential.get("@context"),
        Some(Value::String(context)) if context == "https://www.w3.org/ns/credentials/v2"
    ) && !credential
        .get("@context")
        .and_then(Value::as_array)
        .is_some_and(|contexts| {
            contexts
                .iter()
                .any(|context| context.as_str() == Some("https://www.w3.org/ns/credentials/v2"))
        })
    {
        return Err("Credential must use the W3C VCDM v2 context".to_string());
    }
    Ok(())
}

fn validate_data_integrity_issuance_dates(credential: &Value) -> Result<(), String> {
    let parse = |name: &str| -> Result<Option<chrono::DateTime<chrono::FixedOffset>>, String> {
        let Some(value) = credential.get(name) else {
            return Ok(None);
        };
        let value = value
            .as_str()
            .ok_or_else(|| format!("Credential `{name}` must be an RFC 3339 date-time"))?;
        chrono::DateTime::parse_from_rfc3339(value)
            .map(Some)
            .map_err(|_| format!("Credential `{name}` must be an RFC 3339 date-time"))
    };
    let valid_from = parse("validFrom")?;
    let valid_until = parse("validUntil")?;
    if let (Some(valid_from), Some(valid_until)) = (valid_from, valid_until) {
        if valid_until < valid_from {
            return Err("Credential validUntil must not precede validFrom".to_string());
        }
    }
    Ok(())
}

fn ed25519_multikey(
    public_jwk: &JWK,
    issuer_did: &str,
    verification_method_id: &str,
) -> Result<Multikey, String> {
    let public_key = match &public_jwk.params {
        JwkParams::OKP(parameters) if parameters.curve == "Ed25519" => {
            parameters.public_key.0.as_slice()
        }
        _ => {
            return Err(
                "eddsa-rdfc-2022 requires an Ed25519 public JWK from the issuer profile"
                    .to_string(),
            )
        }
    };
    let verifying_key = ed25519_dalek::VerifyingKey::try_from(public_key)
        .map_err(|error| format!("Invalid Ed25519 public JWK: {error}"))?;
    let method_id = IriBuf::new(verification_method_id.to_string())
        .map_err(|error| format!("Invalid verification method IRI: {error}"))?;
    let controller = iref::UriBuf::new(issuer_did.as_bytes().to_vec())
        .map_err(|error| format!("Invalid issuer DID URI: {error:?}"))?;
    Ok(Multikey::from_public_key(
        method_id,
        controller,
        &verifying_key,
    ))
}

/// Verify a VCDM v2 credential or presentation and return a JSON result.
///
/// Invalid input is represented as `valid: false`, including parse and proof
/// errors, so callers cannot accidentally treat an exception as an acceptance.
pub async fn verify_vcdm_data_integrity_json_async(request_json: &str) -> String {
    let request = match serde_json::from_str::<VerifyRequest>(request_json) {
        Ok(request) => request,
        Err(error) => {
            return serialize_result(VerifyResult {
                valid: false,
                kind: "unknown",
                verified_proofs: 0,
                verified_credentials: 0,
                errors: vec![format!("Invalid VCDM verification request: {error}")],
            });
        }
    };

    let is_presentation = has_type(&request.document, "VerifiablePresentation");
    let is_credential = has_type(&request.document, "VerifiableCredential");
    if is_presentation == is_credential {
        return serialize_result(VerifyResult {
            valid: false,
            kind: "unknown",
            verified_proofs: 0,
            verified_credentials: 0,
            errors: vec![
                "Document must identify exactly one VCDM credential or presentation type"
                    .to_string(),
            ],
        });
    }

    if is_presentation {
        verify_presentation(request).await
    } else {
        verify_credential_document(&request.document, &request.resolved_verification_methods).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_vcdm_data_integrity_json(request_json: &str) -> String {
    futures::executor::block_on(verify_vcdm_data_integrity_json_async(request_json))
}

/// Verify a compact VCDM v2 VC-JWT using public issuer-profile DID material.
///
/// Callers either supply a public JWK already resolved through the issuer
/// profile, or use a `did:key` verification-method URL in `kid` for offline
/// resolution. This function deliberately has no KMS coordinate or private-key
/// input: key custody and signing remain behind the issuer profile.
pub async fn verify_vcdm_jwt_json_async(request_json: &str) -> String {
    let request = match serde_json::from_str::<VerifyJwtRequest>(request_json) {
        Ok(request) => request,
        Err(error) => {
            return serialize_jwt_result(VerifyJwtResult {
                valid: false,
                algorithm: None,
                issuer: None,
                claims: None,
                errors: vec![format!("Invalid VCDM JWT verification request: {error}")],
            });
        }
    };

    let (unverified_header, unverified_payload) = match ssi_jws::decode_unverified(&request.token) {
        Ok(decoded) => decoded,
        Err(error) => {
            return serialize_jwt_result(VerifyJwtResult {
                valid: false,
                algorithm: None,
                issuer: None,
                claims: None,
                errors: vec![format!("Invalid compact JWS: {error}")],
            });
        }
    };
    let algorithm = unverified_header.algorithm.as_str().to_string();
    if !matches!(
        unverified_header.algorithm,
        Algorithm::EdDSA | Algorithm::ES256
    ) {
        return serialize_jwt_result(VerifyJwtResult {
            valid: false,
            algorithm: Some(algorithm),
            issuer: None,
            claims: None,
            errors: vec!["Unsupported VC-JWT algorithm; expected EdDSA or ES256".to_string()],
        });
    }

    let unverified_claims = match serde_json::from_slice::<Value>(&unverified_payload) {
        Ok(Value::Object(claims)) => Value::Object(claims),
        Ok(_) => {
            return serialize_jwt_result(VerifyJwtResult {
                valid: false,
                algorithm: Some(algorithm),
                issuer: None,
                claims: None,
                errors: vec!["VC-JWT payload must be a JSON object".to_string()],
            });
        }
        Err(error) => {
            return serialize_jwt_result(VerifyJwtResult {
                valid: false,
                algorithm: Some(algorithm),
                issuer: None,
                claims: None,
                errors: vec![format!("Invalid VC-JWT payload: {error}")],
            });
        }
    };
    let unverified_issuer = unverified_claims
        .get("iss")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let verification_jwk = match request.issuer_public_jwk {
        Some(jwk_value) => match parse_public_jwk(jwk_value) {
            Ok(jwk) => jwk,
            Err(error) => {
                return serialize_jwt_result(VerifyJwtResult {
                    valid: false,
                    algorithm: Some(algorithm),
                    issuer: unverified_issuer,
                    claims: None,
                    errors: vec![error],
                });
            }
        },
        None => {
            let Some(key_id) = unverified_header.key_id.as_deref() else {
                return serialize_jwt_result(VerifyJwtResult {
                    valid: false,
                    algorithm: Some(algorithm),
                    issuer: unverified_issuer,
                    claims: None,
                    errors: vec![
                        "VC-JWT requires issuer-profile public JWK material or a did:key kid"
                            .to_string(),
                    ],
                });
            };
            if !key_id.starts_with("did:key:") || !key_id.contains('#') {
                return serialize_jwt_result(VerifyJwtResult {
                    valid: false,
                    algorithm: Some(algorithm),
                    issuer: unverified_issuer,
                    claims: None,
                    errors: vec![
                        "Automatic VC-JWT key resolution is restricted to did:key URLs".to_string(),
                    ],
                });
            }
            let resolver: VerificationMethodDIDResolver<DIDKey, AnyMethod> =
                VerificationMethodDIDResolver::new(DIDKey);
            match resolver.fetch_public_jwk(Some(key_id)).await {
                Ok(jwk) => jwk.into_owned(),
                Err(error) => {
                    return serialize_jwt_result(VerifyJwtResult {
                        valid: false,
                        algorithm: Some(algorithm),
                        issuer: unverified_issuer,
                        claims: None,
                        errors: vec![format!("Unable to resolve VC-JWT did:key: {error}")],
                    });
                }
            }
        }
    };

    let (verified_header, verified_payload) =
        match ssi_jws::decode_verify(&request.token, &verification_jwk) {
            Ok(decoded) => decoded,
            Err(error) => {
                return serialize_jwt_result(VerifyJwtResult {
                    valid: false,
                    algorithm: Some(algorithm),
                    issuer: unverified_issuer,
                    claims: None,
                    errors: vec![format!("VC-JWT signature is invalid: {error}")],
                });
            }
        };
    let claims: Value = match serde_json::from_slice(&verified_payload) {
        Ok(claims) => claims,
        Err(error) => {
            return serialize_jwt_result(VerifyJwtResult {
                valid: false,
                algorithm: Some(algorithm),
                issuer: unverified_issuer,
                claims: None,
                errors: vec![format!("Verified VC-JWT payload is invalid JSON: {error}")],
            });
        }
    };
    let issuer = claims.get("iss").and_then(Value::as_str).map(str::to_owned);
    let mut errors = validate_vcdm_jwt_claims(&claims, verified_header.key_id.as_deref());
    if verified_header.algorithm != unverified_header.algorithm {
        errors.push("VC-JWT protected algorithm changed during verification".to_string());
    }

    serialize_jwt_result(VerifyJwtResult {
        valid: errors.is_empty(),
        algorithm: Some(algorithm),
        issuer,
        claims: Some(claims),
        errors,
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_vcdm_jwt_json(request_json: &str) -> String {
    futures::executor::block_on(verify_vcdm_jwt_json_async(request_json))
}

fn parse_public_jwk(value: Value) -> Result<JWK, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "issuer_public_jwk must be a JSON object".to_string())?;
    const PRIVATE_PARAMETERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if let Some(parameter) = PRIVATE_PARAMETERS
        .iter()
        .find(|parameter| object.contains_key(**parameter))
    {
        return Err(format!(
            "issuer_public_jwk contains prohibited private key parameter `{parameter}`"
        ));
    }
    serde_json::from_value(value).map_err(|error| format!("Invalid issuer public JWK: {error}"))
}

fn validate_vcdm_jwt_claims(claims: &Value, key_id: Option<&str>) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(vc) = claims.get("vc").and_then(Value::as_object) else {
        return vec!["VC-JWT payload must contain a `vc` object".to_string()];
    };
    let vc = Value::Object(vc.clone());

    if !has_v2_context(&vc) {
        errors.push("VC-JWT credential must use the VCDM v2 base context".to_string());
    }
    if !has_type(&vc, "VerifiableCredential") {
        errors.push("VC-JWT credential type must include VerifiableCredential".to_string());
    }
    let vc_issuer = identifier(&vc, "issuer");
    let jwt_issuer = claims.get("iss").and_then(Value::as_str);
    if vc_issuer.is_none() || jwt_issuer.is_none() {
        errors.push("VC-JWT requires absolute `iss` and credential issuer identifiers".to_string());
    } else if vc_issuer != jwt_issuer {
        errors.push("VC-JWT `iss` does not match credential issuer".to_string());
    }
    if let (Some(issuer), Some(kid)) = (jwt_issuer, key_id) {
        if issuer.starts_with("did:") && kid.split_once('#').map(|(did, _)| did) != Some(issuer) {
            errors.push("VC-JWT kid controller does not match issuer DID".to_string());
        }
    }

    validate_credential_subject(&vc, &mut errors);
    validate_identifier_mapping(claims, &vc, "jti", "id", &mut errors);
    if let Some(subject) = claims.get("sub").and_then(Value::as_str) {
        let subject_matches = vc
            .get("credentialSubject")
            .map(|value| match value {
                Value::Object(item) => item.get("id").and_then(Value::as_str) == Some(subject),
                Value::Array(items) => items
                    .iter()
                    .any(|item| item.get("id").and_then(Value::as_str) == Some(subject)),
                _ => false,
            })
            .unwrap_or(false);
        if !subject_matches {
            errors.push("VC-JWT `sub` does not identify a credential subject".to_string());
        }
    }
    validate_numeric_dates(claims, &mut errors);
    validate_credential_dates(&vc, &mut errors);
    errors
}

fn has_v2_context(document: &Value) -> bool {
    const V2_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
    match document.get("@context") {
        Some(Value::String(value)) => value == V2_CONTEXT,
        Some(Value::Array(values)) => values.first().and_then(Value::as_str) == Some(V2_CONTEXT),
        _ => false,
    }
}

fn validate_credential_subject(document: &Value, errors: &mut Vec<String>) {
    let valid = match document.get("credentialSubject") {
        Some(Value::Object(subject)) => !subject.is_empty(),
        Some(Value::Array(subjects)) => {
            !subjects.is_empty()
                && subjects
                    .iter()
                    .all(|subject| subject.as_object().is_some_and(|value| !value.is_empty()))
        }
        _ => false,
    };
    if !valid {
        errors.push("credentialSubject must contain one or more non-empty objects".to_string());
    }
}

fn validate_identifier_mapping(
    claims: &Value,
    credential: &Value,
    claim_name: &str,
    property_name: &str,
    errors: &mut Vec<String>,
) {
    if let (Some(claim), Some(property)) = (
        claims.get(claim_name).and_then(Value::as_str),
        credential.get(property_name).and_then(Value::as_str),
    ) {
        if claim != property {
            errors.push(format!(
                "VC-JWT `{claim_name}` does not match credential `{property_name}`"
            ));
        }
    }
}

fn validate_numeric_dates(claims: &Value, errors: &mut Vec<String>) {
    let now = chrono::Utc::now().timestamp() as f64;
    if let Some(not_before) = claims.get("nbf") {
        match not_before.as_f64() {
            Some(value) if value <= now => {}
            Some(_) => errors.push("VC-JWT is not yet valid".to_string()),
            None => errors.push("VC-JWT `nbf` must be a NumericDate".to_string()),
        }
    }
    if let Some(expires) = claims.get("exp") {
        match expires.as_f64() {
            Some(value) if value > now => {}
            Some(_) => errors.push("VC-JWT has expired".to_string()),
            None => errors.push("VC-JWT `exp` must be a NumericDate".to_string()),
        }
    }
}

fn validate_credential_dates(credential: &Value, errors: &mut Vec<String>) {
    let parse = |name: &str| {
        credential
            .get(name)
            .and_then(Value::as_str)
            .map(chrono::DateTime::parse_from_rfc3339)
    };
    let valid_from = parse("validFrom");
    let valid_until = parse("validUntil");
    for (name, parsed) in [("validFrom", &valid_from), ("validUntil", &valid_until)] {
        if parsed.as_ref().is_some_and(Result::is_err) {
            errors.push(format!("Credential `{name}` must be an RFC 3339 date-time"));
        }
    }
    let now = chrono::Utc::now();
    if let Some(Ok(valid_from)) = valid_from.as_ref() {
        if *valid_from > now {
            errors.push("Credential is not yet valid".to_string());
        }
    }
    if let Some(Ok(valid_until)) = valid_until.as_ref() {
        if *valid_until <= now {
            errors.push("Credential has expired".to_string());
        }
    }
    if let (Some(Ok(valid_from)), Some(Ok(valid_until))) =
        (valid_from.as_ref(), valid_until.as_ref())
    {
        if valid_until <= valid_from {
            errors.push("Credential validUntil must be later than validFrom".to_string());
        }
    }
}

async fn verify_presentation(request: VerifyRequest) -> String {
    let holder = identifier(&request.document, "holder");
    let mut errors = validate_proofs(
        &request.document,
        "authentication",
        request.expected_challenge.as_deref(),
        request.expected_domain.as_deref(),
        holder,
    );
    if request
        .expected_challenge
        .as_deref()
        .is_none_or(str::is_empty)
    {
        errors.push("Presentation verification requires an expected challenge".to_string());
    }
    if request.expected_domain.as_deref().is_none_or(str::is_empty) {
        errors.push("Presentation verification requires an expected domain".to_string());
    }

    let mut verified_proofs = 0;
    match serde_json::from_value::<AnyPresentation>(request.document.clone()) {
        Ok(presentation) => match verification_parameters(&request.resolved_verification_methods) {
            Ok(parameters) => match presentation.verify(parameters).await {
                Ok(Ok(())) => verified_proofs += 1,
                Ok(Err(invalid)) => {
                    errors.push(format!("Presentation proof is invalid: {invalid}"))
                }
                Err(error) => errors.push(format!("Presentation verification failed: {error}")),
            },
            Err(error) => errors.push(error),
        },
        Err(error) => errors.push(format!("Invalid VCDM presentation: {error}")),
    }

    let mut verified_credentials = 0;
    if let Some(credentials) = request.document.get("verifiableCredential") {
        let credentials = credentials.as_array().cloned().unwrap_or_else(|| {
            errors.push("verifiableCredential must be an array".to_string());
            Vec::new()
        });
        for (index, credential) in credentials.iter().enumerate() {
            let credential_errors = validate_proofs(
                credential,
                "assertionMethod",
                None,
                None,
                identifier(credential, "issuer"),
            );
            errors.extend(
                credential_errors
                    .into_iter()
                    .map(|error| format!("Credential {index}: {error}")),
            );
            match verify_credential(credential, &request.resolved_verification_methods).await {
                Ok(()) => verified_credentials += 1,
                Err(error) => errors.push(format!("Credential {index}: {error}")),
            }
        }
    }

    serialize_result(VerifyResult {
        valid: errors.is_empty(),
        kind: "presentation",
        verified_proofs,
        verified_credentials,
        errors,
    })
}

async fn verify_credential_document(
    document: &Value,
    resolved_methods: &[ResolvedVerificationMethod],
) -> String {
    let issuer = identifier(document, "issuer");
    let mut errors = validate_proofs(document, "assertionMethod", None, None, issuer);
    if issuer.is_none() {
        errors.push("Credential issuer must be an absolute identifier".to_string());
    }
    let mut verified_proofs = 0;
    match verify_credential(document, resolved_methods).await {
        Ok(()) => verified_proofs = 1,
        Err(error) => errors.push(error),
    }
    serialize_result(VerifyResult {
        valid: errors.is_empty(),
        kind: "credential",
        verified_proofs,
        verified_credentials: usize::from(verified_proofs == 1),
        errors,
    })
}

async fn verify_credential(
    document: &Value,
    resolved_methods: &[ResolvedVerificationMethod],
) -> Result<(), String> {
    let credential: AnyCredential = serde_json::from_value(document.clone())
        .map_err(|error| format!("Invalid VCDM credential: {error}"))?;
    let parameters = verification_parameters(resolved_methods)?;
    match credential.verify(parameters).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(invalid)) => Err(format!("Credential proof is invalid: {invalid}")),
        Err(error) => Err(format!("Credential verification failed: {error}")),
    }
}

fn verification_parameters(
    resolved_methods: &[ResolvedVerificationMethod],
) -> Result<VerificationParameters<ResolvedDidResolver, ssi_json_ld::ContextLoader>, String> {
    let loader = open_badges_context_loader().map_err(|error| error.to_string())?;
    let mut methods = HashMap::new();
    for resolved in resolved_methods {
        if !resolved.controller.starts_with("did:") {
            return Err("Resolved verification method controller must be a DID".to_string());
        }
        let Some((controller, fragment)) = resolved.id.split_once('#') else {
            return Err("Resolved verification method id must be a DID URL".to_string());
        };
        if fragment.is_empty() || controller != resolved.controller {
            return Err(
                "Resolved verification method controller must exactly match its DID URL"
                    .to_string(),
            );
        }
        let public_jwk = parse_public_jwk(resolved.public_jwk.clone())?;
        let method = ed25519_multikey(&public_jwk, &resolved.controller, &resolved.id)?;
        if methods
            .insert(method.id.clone(), AnyMethod::Multikey(method))
            .is_some()
        {
            return Err("Resolved verification method ids must be unique".to_string());
        }
    }
    let resolver = ResolvedDidResolver {
        methods,
        did_key: DIDKey.into_vm_resolver::<AnyMethod>(),
    };
    Ok(VerificationParameters::from_resolver(resolver).with_json_ld_loader(loader))
}

fn has_type(document: &Value, expected: &str) -> bool {
    match document.get("type") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn identifier<'a>(document: &'a Value, name: &str) -> Option<&'a str> {
    match document.get(name) {
        Some(Value::String(value)) if value.contains(':') => Some(value),
        Some(Value::Object(value)) => value
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| value.contains(':')),
        _ => None,
    }
}

fn validate_proofs(
    document: &Value,
    expected_purpose: &str,
    expected_challenge: Option<&str>,
    expected_domain: Option<&str>,
    expected_controller: Option<&str>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(proof) = document.get("proof") else {
        return vec!["Missing Data Integrity proof".to_string()];
    };
    let proofs: Vec<&Value> = match proof {
        Value::Array(values) if !values.is_empty() => values.iter().collect(),
        Value::Object(_) => vec![proof],
        _ => return vec!["Proof must be a non-empty object or array".to_string()],
    };

    for proof in proofs {
        if proof.get("type").and_then(Value::as_str) != Some("DataIntegrityProof") {
            errors.push("Unsupported proof type".to_string());
        }
        if proof.get("cryptosuite").and_then(Value::as_str) != Some("eddsa-rdfc-2022") {
            errors.push("Unsupported Data Integrity cryptosuite".to_string());
        }
        if proof.get("proofPurpose").and_then(Value::as_str) != Some(expected_purpose) {
            errors.push(format!("Proof purpose must be {expected_purpose}"));
        }
        let verification_method = proof.get("verificationMethod").and_then(Value::as_str);
        if !verification_method.is_some_and(|value| {
            value.starts_with("did:")
                && value
                    .split_once('#')
                    .is_some_and(|(did, fragment)| !did.is_empty() && !fragment.is_empty())
        }) {
            errors.push("Verification method must be an absolute DID URL".to_string());
        }
        if let (Some(method), Some(controller)) = (verification_method, expected_controller) {
            if method.split_once('#').map(|(did, _)| did) != Some(controller) {
                errors.push(
                    "Proof verification method controller does not match document signer"
                        .to_string(),
                );
            }
        }
        if !proof
            .get("proofValue")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with('z') && value.len() > 1)
        {
            errors.push("Proof value must be non-empty base58btc multibase".to_string());
        }
        if let Some(expected) = expected_challenge {
            if proof.get("challenge").and_then(Value::as_str) != Some(expected) {
                errors.push("Presentation proof challenge does not match".to_string());
            }
        }
        if let Some(expected) = expected_domain {
            if proof.get("domain").and_then(Value::as_str) != Some(expected) {
                errors.push("Presentation proof domain does not match".to_string());
            }
        }
    }
    errors
}

fn serialize_result(result: VerifyResult) -> String {
    serde_json::to_string(&result).expect("serializing a VCDM verification result cannot fail")
}

fn serialize_jwt_result(result: VerifyJwtResult) -> String {
    serde_json::to_string(&result).expect("serializing a VCDM JWT verification result cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi_jws::encode_sign;

    const OFFICIAL_SUITE_PRESENTATION: &str =
        include_str!("../tests/fixtures/w3c_vcdm_v2_official_suite_presentation.json");

    const OFFICIAL_SUITE_PRESENTATION_WITHOUT_HOLDER: &str = r#"{
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiablePresentation"],
      "proof": {
        "type": "DataIntegrityProof",
        "created": "2026-07-22T09:59:37Z",
        "verificationMethod": "did:key:z6MkpJySvETLnxhQG9DzEdmKJtysBDjuuTeDfUj1uNNCUqcj#z6MkpJySvETLnxhQG9DzEdmKJtysBDjuuTeDfUj1uNNCUqcj",
        "cryptosuite": "eddsa-rdfc-2022",
        "proofPurpose": "authentication",
        "challenge": "challenge-123",
        "domain": "verifier.example",
        "proofValue": "z21YwBZrwiRK3mGfxEBNWxnbJrD4oYDpVSJeSdQyECW4NsL4YMuuZ6yugdiuWyf5ZD9nXkyKixD6C5691eLwwf7Sv"
      }
    }"#;

    fn remote_data_integrity_prepare_request(key: &JWK) -> Value {
        let verification_method_id = DIDKey::generate_url(key).unwrap().to_string();
        let issuer_did = verification_method_id
            .split_once('#')
            .map(|(did, _)| did)
            .unwrap()
            .to_string();
        json!({
            "credential": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "urn:uuid:2f2e1a96-3f33-4be7-90d9-fca583d23a8b",
                "type": ["VerifiableCredential"],
                "issuer": issuer_did,
                "validFrom": "2026-07-28T00:00:00Z",
                "credentialSubject": {
                    "id": "did:example:holder"
                }
            },
            "issuer_did": issuer_did,
            "verification_method_id": verification_method_id,
            "public_jwk": serde_json::to_value(key.to_public()).unwrap()
        })
    }

    fn remote_data_integrity_prepare_request_for_did_web(key: &JWK) -> Value {
        let issuer_did = "did:web:issuer.example";
        let verification_method_id = format!("{issuer_did}#key-1");
        json!({
            "credential": {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": "urn:uuid:2f2e1a96-3f33-4be7-90d9-fca583d23a8b",
                "type": ["VerifiableCredential"],
                "issuer": issuer_did,
                "validFrom": "2026-07-28T00:00:00Z",
                "credentialSubject": {
                    "id": "did:example:holder"
                }
            },
            "issuer_did": issuer_did,
            "verification_method_id": verification_method_id,
            "public_jwk": serde_json::to_value(key.to_public()).unwrap()
        })
    }

    fn remotely_sign_prepared_credential(
        private_key: &JWK,
        prepared: &Value,
    ) -> Result<String, String> {
        let signing_input = URL_SAFE_NO_PAD
            .decode(prepared["signing_input_b64"].as_str().unwrap())
            .unwrap();
        let signature = ssi_jws::sign_bytes(Algorithm::EdDSA, &signing_input, private_key).unwrap();
        complete_vcdm_data_integrity_credential_json(
            &json!({
                "prepared": prepared,
                "signature_b64": URL_SAFE_NO_PAD.encode(signature)
            })
            .to_string(),
        )
    }

    #[test]
    fn prepares_completes_and_verifies_remote_eddsa_rdfc_credential() {
        let key = JWK::generate_ed25519().unwrap();
        let prepared_json = prepare_vcdm_data_integrity_credential_json(
            &remote_data_integrity_prepare_request(&key).to_string(),
        )
        .unwrap();
        let prepared: Value = serde_json::from_str(&prepared_json).unwrap();

        assert_eq!(prepared["algorithm"], "EdDSA");
        assert_eq!(
            prepared["credential"]["proof"]["cryptosuite"],
            "eddsa-rdfc-2022"
        );
        assert_eq!(
            prepared["credential"]["proof"]["verificationMethod"],
            prepared["verification_method_id"]
        );

        let completed = remotely_sign_prepared_credential(&key, &prepared).unwrap();
        let credential: Value = serde_json::from_str(&completed).unwrap();
        assert!(credential["proof"]["proofValue"]
            .as_str()
            .is_some_and(|value| value.starts_with('z')));

        let verification: Value = serde_json::from_str(&verify_vcdm_data_integrity_json(
            &json!({"document": credential}).to_string(),
        ))
        .unwrap();
        assert_eq!(verification["valid"], true, "{verification}");
        assert_eq!(verification["verified_credentials"], 1);
    }

    #[test]
    fn prepares_vcdm_v2_credential_with_standard_related_resource() {
        let key = JWK::generate_ed25519().unwrap();
        let mut request = remote_data_integrity_prepare_request(&key);
        request["credential"]["relatedResource"] = json!({
            "id": "https://www.w3.org/ns/credentials/v2",
            "digestSRI": "sha384-l/HrjlBCNWyAX91hr6LFV2Y3heB5Tcr6IeE4/Tje8YyzYBM8IhqjHWiWpr8+ZbYU"
        });

        let prepared_json =
            prepare_vcdm_data_integrity_credential_json(&request.to_string()).unwrap();
        let prepared: Value = serde_json::from_str(&prepared_json).unwrap();

        assert_eq!(
            prepared["credential"]["relatedResource"]["id"],
            "https://www.w3.org/ns/credentials/v2"
        );
        assert_eq!(
            prepared["credential"]["relatedResource"]["digestSRI"],
            "sha384-l/HrjlBCNWyAX91hr6LFV2Y3heB5Tcr6IeE4/Tje8YyzYBM8IhqjHWiWpr8+ZbYU"
        );
    }

    #[test]
    fn verifies_did_web_credential_with_resolver_owned_public_method() {
        let key = JWK::generate_ed25519().unwrap();
        let request = remote_data_integrity_prepare_request_for_did_web(&key);
        let prepared_json =
            prepare_vcdm_data_integrity_credential_json(&request.to_string()).unwrap();
        let prepared: Value = serde_json::from_str(&prepared_json).unwrap();
        let completed = remotely_sign_prepared_credential(&key, &prepared).unwrap();
        let credential: Value = serde_json::from_str(&completed).unwrap();
        let issuer_did = request["issuer_did"].as_str().unwrap();
        let method_id = request["verification_method_id"].as_str().unwrap();

        let without_resolved_method: Value = serde_json::from_str(
            &verify_vcdm_data_integrity_json(&json!({"document": credential}).to_string()),
        )
        .unwrap();
        assert_eq!(without_resolved_method["valid"], false);

        let verification: Value = serde_json::from_str(&verify_vcdm_data_integrity_json(
            &json!({
                "document": credential,
                "resolved_verification_methods": [{
                    "id": method_id,
                    "controller": issuer_did,
                    "public_jwk": serde_json::to_value(key.to_public()).unwrap()
                }]
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(verification["valid"], true, "{verification}");
        assert_eq!(verification["verified_credentials"], 1);
    }

    #[test]
    fn resolved_did_method_fails_closed_on_controller_private_key_and_wrong_key() {
        let key = JWK::generate_ed25519().unwrap();
        let wrong_key = JWK::generate_ed25519().unwrap();
        let request = remote_data_integrity_prepare_request_for_did_web(&key);
        let prepared_json =
            prepare_vcdm_data_integrity_credential_json(&request.to_string()).unwrap();
        let prepared: Value = serde_json::from_str(&prepared_json).unwrap();
        let completed = remotely_sign_prepared_credential(&key, &prepared).unwrap();
        let credential: Value = serde_json::from_str(&completed).unwrap();
        let issuer_did = request["issuer_did"].as_str().unwrap();
        let method_id = request["verification_method_id"].as_str().unwrap();

        let cases = [
            json!({
                "id": method_id,
                "controller": "did:web:other.example",
                "public_jwk": serde_json::to_value(key.to_public()).unwrap()
            }),
            json!({
                "id": method_id,
                "controller": issuer_did,
                "public_jwk": serde_json::to_value(key.clone()).unwrap()
            }),
            json!({
                "id": method_id,
                "controller": issuer_did,
                "public_jwk": serde_json::to_value(wrong_key.to_public()).unwrap()
            }),
        ];

        for resolved_method in cases {
            let verification: Value = serde_json::from_str(&verify_vcdm_data_integrity_json(
                &json!({
                    "document": credential,
                    "resolved_verification_methods": [resolved_method]
                })
                .to_string(),
            ))
            .unwrap();
            assert_eq!(verification["valid"], false, "{verification}");
        }
    }

    #[test]
    fn remote_data_integrity_signing_accepts_noncurrent_validity_but_verification_denies_it() {
        let cases = [
            ("2023-02-26T01:19:19Z", "2023-02-26T01:19:20Z", "expired"),
            ("2099-02-26T01:19:19Z", "2100-02-26T01:19:20Z", "premature"),
        ];

        for (valid_from, valid_until, expected_error) in cases {
            let key = JWK::generate_ed25519().unwrap();
            let mut request = remote_data_integrity_prepare_request(&key);
            request["credential"]["validFrom"] = json!(valid_from);
            request["credential"]["validUntil"] = json!(valid_until);

            let prepared_json =
                prepare_vcdm_data_integrity_credential_json(&request.to_string()).unwrap();
            let prepared: Value = serde_json::from_str(&prepared_json).unwrap();
            let completed = remotely_sign_prepared_credential(&key, &prepared).unwrap();
            let credential: Value = serde_json::from_str(&completed).unwrap();

            let verification: Value = serde_json::from_str(&verify_vcdm_data_integrity_json(
                &json!({"document": credential}).to_string(),
            ))
            .unwrap();
            assert_eq!(verification["valid"], false, "{verification}");
            assert!(
                verification["errors"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|error| error.contains(expected_error)),
                "{verification}"
            );
        }
    }

    #[test]
    fn remote_data_integrity_signing_rejects_invalid_or_reversed_validity() {
        let key = JWK::generate_ed25519().unwrap();
        let mut malformed = remote_data_integrity_prepare_request(&key);
        malformed["credential"]["validUntil"] = json!("not-a-date");
        let error =
            prepare_vcdm_data_integrity_credential_json(&malformed.to_string()).unwrap_err();
        assert!(
            error.contains("validUntil") && error.contains("RFC 3339"),
            "{error}"
        );

        let mut reversed = remote_data_integrity_prepare_request(&key);
        reversed["credential"]["validFrom"] = json!("2099-02-26T01:19:20Z");
        reversed["credential"]["validUntil"] = json!("2023-02-26T01:19:19Z");
        let error = prepare_vcdm_data_integrity_credential_json(&reversed.to_string()).unwrap_err();
        assert!(error.contains("must not precede validFrom"), "{error}");
    }

    #[test]
    fn remote_data_integrity_rejects_private_jwk_at_prepare_boundary() {
        let key = JWK::generate_ed25519().unwrap();
        let mut request = remote_data_integrity_prepare_request(&key);
        request["public_jwk"] = serde_json::to_value(key).unwrap();

        let error = prepare_vcdm_data_integrity_credential_json(&request.to_string()).unwrap_err();
        assert!(
            error.contains("prohibited private key parameter"),
            "{error}"
        );
    }

    #[test]
    fn remote_data_integrity_completion_rejects_tampered_credential() {
        let key = JWK::generate_ed25519().unwrap();
        let prepared_json = prepare_vcdm_data_integrity_credential_json(
            &remote_data_integrity_prepare_request(&key).to_string(),
        )
        .unwrap();
        let mut prepared: Value = serde_json::from_str(&prepared_json).unwrap();
        prepared["credential"]["credentialSubject"]["id"] = json!("did:example:attacker");

        let error = remotely_sign_prepared_credential(&key, &prepared).unwrap_err();
        assert!(
            error.contains("credential proof is invalid")
                || error.contains("credential proof verification failed"),
            "{error}"
        );
    }

    #[test]
    fn remote_data_integrity_completion_rejects_invalid_signature() {
        let key = JWK::generate_ed25519().unwrap();
        let prepared_json = prepare_vcdm_data_integrity_credential_json(
            &remote_data_integrity_prepare_request(&key).to_string(),
        )
        .unwrap();
        let prepared: Value = serde_json::from_str(&prepared_json).unwrap();
        let error = complete_vcdm_data_integrity_credential_json(
            &json!({
                "prepared": prepared,
                "signature_b64": URL_SAFE_NO_PAD.encode([0x5a_u8; 64])
            })
            .to_string(),
        )
        .unwrap_err();
        assert!(error.contains("credential proof is invalid"), "{error}");
    }

    #[test]
    fn verifies_official_suite_eddsa_rdfc_presentation_and_nested_credential() {
        let request = json!({
            "document": serde_json::from_str::<Value>(OFFICIAL_SUITE_PRESENTATION).unwrap(),
            "expected_challenge": "challenge-123",
            "expected_domain": "verifier.example"
        });
        let result: Value =
            serde_json::from_str(&verify_vcdm_data_integrity_json(&request.to_string())).unwrap();
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["verified_proofs"], 1);
        assert_eq!(result["verified_credentials"], 1);
    }

    #[test]
    fn verifies_official_suite_presentation_without_optional_holder() {
        let request = json!({
            "document": serde_json::from_str::<Value>(
                OFFICIAL_SUITE_PRESENTATION_WITHOUT_HOLDER
            )
            .unwrap(),
            "expected_challenge": "challenge-123",
            "expected_domain": "verifier.example"
        });
        let result: Value =
            serde_json::from_str(&verify_vcdm_data_integrity_json(&request.to_string())).unwrap();
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["verified_proofs"], 1);
        assert_eq!(result["verified_credentials"], 0);
    }

    #[test]
    fn rejects_tampering_and_challenge_mismatch() {
        let mut document: Value = serde_json::from_str(OFFICIAL_SUITE_PRESENTATION).unwrap();
        document["holder"] = json!("did:example:tampered");
        let request = json!({
            "document": document,
            "expected_challenge": "wrong-challenge",
            "expected_domain": "verifier.example"
        });
        let result: Value =
            serde_json::from_str(&verify_vcdm_data_integrity_json(&request.to_string())).unwrap();
        assert_eq!(result["valid"], false);
        assert!(result["errors"].as_array().unwrap().len() >= 2);
    }

    fn jwt_claims(issuer: &str) -> Value {
        json!({
            "iss": issuer,
            "sub": "did:example:alice",
            "jti": "https://issuer.example/credentials/123",
            "vc": {
                "@context": [
                    "https://www.w3.org/ns/credentials/v2",
                    "https://www.w3.org/ns/credentials/examples/v2"
                ],
                "id": "https://issuer.example/credentials/123",
                "type": ["VerifiableCredential", "ExampleCredential"],
                "issuer": issuer,
                "validFrom": "2025-01-01T00:00:00Z",
                "validUntil": "2099-01-01T00:00:00Z",
                "credentialSubject": {
                    "id": "did:example:alice",
                    "name": "Alice"
                }
            }
        })
    }

    #[test]
    fn verifies_eddsa_vc_jwt_using_offline_did_key_resolution() {
        let mut key = JWK::generate_ed25519().unwrap();
        let kid = DIDKey::generate_url(&key).unwrap().to_string();
        let issuer = kid.split_once('#').unwrap().0.to_string();
        key.key_id = Some(kid);
        let token = encode_sign(Algorithm::EdDSA, &jwt_claims(&issuer).to_string(), &key).unwrap();

        let result: Value =
            serde_json::from_str(&verify_vcdm_jwt_json(&json!({"token": token}).to_string()))
                .unwrap();
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["algorithm"], "EdDSA");
        assert_eq!(result["issuer"], issuer);
    }

    #[test]
    fn verifies_es256_vc_jwt_with_public_profile_did_material() {
        let mut key = JWK::generate_p256();
        let issuer = "did:web:issuer.example";
        key.key_id = Some(format!("{issuer}#key-1"));
        let token = encode_sign(Algorithm::ES256, &jwt_claims(issuer).to_string(), &key).unwrap();
        let public_jwk = serde_json::to_value(key.to_public()).unwrap();

        let result: Value = serde_json::from_str(&verify_vcdm_jwt_json(
            &json!({
                "token": token,
                "issuer_public_jwk": public_jwk
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["algorithm"], "ES256");
        assert_eq!(result["issuer"], issuer);
    }

    #[test]
    fn rejects_tampered_vc_jwt_and_private_profile_material() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let mut key = JWK::generate_p256();
        let issuer = "did:web:issuer.example";
        key.key_id = Some(format!("{issuer}#key-1"));
        let token = encode_sign(Algorithm::ES256, &jwt_claims(issuer).to_string(), &key).unwrap();
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3);
        let mut signature = URL_SAFE_NO_PAD.decode(segments[2]).unwrap();
        signature[0] ^= 1;
        let tampered = format!(
            "{}.{}.{}",
            segments[0],
            segments[1],
            URL_SAFE_NO_PAD.encode(signature)
        );
        let public_jwk = serde_json::to_value(key.to_public()).unwrap();

        let invalid: Value = serde_json::from_str(&verify_vcdm_jwt_json(
            &json!({
                "token": tampered,
                "issuer_public_jwk": public_jwk
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(invalid["valid"], false);
        assert!(invalid["errors"][0]
            .as_str()
            .unwrap()
            .contains("signature is invalid"));

        let private_material: Value = serde_json::from_str(&verify_vcdm_jwt_json(
            &json!({
                "token": token,
                "issuer_public_jwk": serde_json::to_value(key).unwrap()
            })
            .to_string(),
        ))
        .unwrap();
        assert_eq!(private_material["valid"], false);
        assert!(private_material["errors"][0]
            .as_str()
            .unwrap()
            .contains("prohibited private key parameter"));
    }
}
