use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use iref::{IriBuf, UriBuf};
use ssi_claims::data_integrity::CryptographicSuite;
use ssi_claims::data_integrity::{AnySuite, DataIntegrity, ProofOptions};
use ssi_claims::vc::syntax::AnyJsonCredential;
use ssi_claims::SignatureEnvironment;
use ssi_claims::VerificationParameters;
use ssi_json_ld::syntax::{Context, ContextEntry};
use ssi_jwk::Params as JwkParams;
use ssi_jwk::JWK;
use ssi_verification_methods::VerificationMethod;
use ssi_verification_methods::{
    AnyMethod, Ed25519VerificationKey2018, Ed25519VerificationKey2020, GenericVerificationMethod,
    JsonWebKey2020, ProofPurpose, ReferenceOrOwned, SingleSecretSigner,
};

use crate::error::{codes as error_codes, VerificationError, VerificationResult};

use super::contexts::{ob3_context_uri, open_badges_context_loader, security_v2_context_uri};
use super::status::check_credential_status;
use super::types::{
    AuthenticatedStatusList, DocumentStore, OpenBadgesIssueResult, OpenBadgesVerificationResult,
};
use super::x509_verification_method::X509VerificationKey2021;

#[derive(Debug, Deserialize)]
struct IssueOb3Request {
    credential: Value,
    signing: Ob3SigningOptions,
}

#[derive(Debug, Deserialize)]
struct VerifyOb3Request {
    credential: Value,
    #[serde(default)]
    document_store: Option<DocumentStore>,
}

#[derive(Debug, Deserialize)]
struct Ob3SigningOptions {
    jwk: Value,
    verification_method: String,
    #[serde(default)]
    verification_method_type: Option<String>,
    #[serde(default)]
    controller: Option<String>,
    #[serde(default)]
    proof_purpose: Option<String>,
}

pub(super) type AnyCredential = DataIntegrity<AnyJsonCredential, AnySuite>;

pub async fn issue_ob3_json_async(request_json: &str) -> VerificationResult<String> {
    let req: IssueOb3Request = serde_json::from_str(request_json)
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB3 issue request: {}", e)))?;

    let credential: AnyJsonCredential = serde_json::from_value(req.credential.clone())
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB3 credential: {}", e)))?;

    let jwk: JWK = serde_json::from_value(req.signing.jwk.clone())
        .map_err(|e| VerificationError::open_badges(format!("Invalid JWK: {}", e)))?;

    let verification_method_iri =
        IriBuf::new(req.signing.verification_method.clone()).map_err(|e| {
            VerificationError::open_badges(format!("Invalid verification_method: {}", e))
        })?;

    let controller = req
        .signing
        .controller
        .clone()
        .or_else(|| credential_issuer(&req.credential))
        .ok_or_else(|| {
            VerificationError::open_badges("Missing controller for verification method".to_string())
        })?;

    let controller_bytes = controller.clone().into_bytes();
    let controller_uri = UriBuf::new(controller_bytes).map_err(|e| {
        VerificationError::open_badges(format!("Invalid controller URI {}: {:?}", controller, e))
    })?;

    let method_type = req
        .signing
        .verification_method_type
        .clone()
        .unwrap_or_else(|| "JsonWebKey2020".to_string());
    let (method, suite) =
        build_verification_method(&jwk, &verification_method_iri, controller_uri, &method_type)?;

    let mut resolver: HashMap<IriBuf, AnyMethod> = HashMap::new();
    resolver.insert(verification_method_iri.clone(), method);

    let signer = SingleSecretSigner::new(jwk.clone()).into_local();

    let proof_purpose = req
        .signing
        .proof_purpose
        .as_deref()
        .unwrap_or("assertionMethod");
    if proof_purpose != "assertionMethod" {
        return Err(VerificationError::open_badges_unsupported(format!(
            "Open Badge credentials must use assertionMethod proof purpose, not {proof_purpose}"
        )));
    }

    let mut proof_options =
        ProofOptions::from_method(ReferenceOrOwned::Reference(verification_method_iri));
    proof_options.proof_purpose = ProofPurpose::Assertion;
    if method_type == "Ed25519VerificationKey2018" {
        let context_iri = IriBuf::new(security_v2_context_uri().to_string()).map_err(|e| {
            VerificationError::open_badges(format!("Invalid proof context URI: {}", e))
        })?;
        proof_options.context = Some(Context::One(ContextEntry::from(context_iri)));
    }
    let loader = open_badges_context_loader()?;
    let env = SignatureEnvironment {
        json_ld_loader: loader,
        eip712_loader: (),
    };

    let signed = suite
        .sign_with(
            env,
            credential,
            &resolver,
            &signer,
            proof_options,
            Default::default(),
        )
        .await
        .map_err(|e| VerificationError::open_badges(format!("OB3 signing failed: {}", e)))?;

    let result = OpenBadgesIssueResult {
        issued: true,
        version: "3.0".to_string(),
        credential: serde_json::to_value(&signed).map_err(|e| {
            VerificationError::open_badges(format!("Failed to serialize OB3 credential: {}", e))
        })?,
        warnings: Vec::new(),
    };

    serde_json::to_string(&result).map_err(|e| {
        VerificationError::open_badges(format!("Failed to serialize OB3 issue result: {}", e))
    })
}

pub async fn verify_ob3_json_async(request_json: &str) -> VerificationResult<String> {
    verify_ob3_json_with_status_lists_async(request_json, &[]).await
}

/// Verify an Open Badge v3 credential using status lists admitted by a trusted
/// orchestrator. Untyped documents in `document_store` never establish status
/// authority on their own.
pub async fn verify_ob3_json_with_status_lists_async(
    request_json: &str,
    authenticated_status_lists: &[AuthenticatedStatusList],
) -> VerificationResult<String> {
    let req: VerifyOb3Request = serde_json::from_str(request_json).map_err(|e| {
        VerificationError::open_badges(format!("Invalid OB3 verify request: {}", e))
    })?;

    let credential: AnyCredential = serde_json::from_value(req.credential.clone())
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB3 credential: {}", e)))?;

    let mut errors = Vec::new();
    let mut error_codes_out = Vec::new();
    let mut warnings = Vec::new();

    if !has_context(&req.credential, ob3_context_uri())
        && !has_context(&req.credential, "https://w3id.org/openbadges/v3")
        && !has_context(
            &req.credential,
            "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
        )
    {
        push_error(
            &mut errors,
            &mut error_codes_out,
            error_codes::OPEN_BADGES_CONTEXT_MISSING,
            "Missing Open Badges v3 context",
        );
    }

    let store = req.document_store.unwrap_or_default();
    let collected = collect_verification_methods(&store, &mut warnings);
    validate_issuer_proof_authorization(
        &req.credential,
        &collected,
        &mut errors,
        &mut error_codes_out,
    );

    let loader = open_badges_context_loader()?;
    let params =
        VerificationParameters::from_resolver(collected.resolver).with_json_ld_loader(loader);

    match credential.verify(params).await {
        Ok(Ok(())) => {}
        Ok(Err(invalid)) => push_error(
            &mut errors,
            &mut error_codes_out,
            error_codes::OPEN_BADGES_PROOF_INVALID,
            format!("Credential invalid: {}", invalid),
        ),
        Err(err) => push_error(
            &mut errors,
            &mut error_codes_out,
            error_codes::OPEN_BADGES_PROOF_INVALID,
            format!("Credential verification error: {}", err),
        ),
    }

    let status_checks = check_credential_status(
        &req.credential,
        authenticated_status_lists,
        &mut errors,
        &mut error_codes_out,
        &mut warnings,
    )
    .await;

    let normalized = normalize_ob3(&req.credential);

    let result = OpenBadgesVerificationResult {
        valid: errors.is_empty(),
        version: "3.0".to_string(),
        errors,
        error_codes: error_codes_out,
        warnings,
        status_checks,
        normalized: Some(normalized),
    };

    serde_json::to_string(&result).map_err(|e| {
        VerificationError::open_badges(format!("Failed to serialize OB3 verify result: {}", e))
    })
}

#[cfg(not(target_arch = "wasm32"))]
pub fn issue_ob3_json(request_json: &str) -> VerificationResult<String> {
    futures::executor::block_on(issue_ob3_json_async(request_json))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_ob3_json(request_json: &str) -> VerificationResult<String> {
    futures::executor::block_on(verify_ob3_json_async(request_json))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_ob3_json_with_status_lists(
    request_json: &str,
    authenticated_status_lists: &[AuthenticatedStatusList],
) -> VerificationResult<String> {
    futures::executor::block_on(verify_ob3_json_with_status_lists_async(
        request_json,
        authenticated_status_lists,
    ))
}

fn build_verification_method(
    jwk: &JWK,
    verification_method: &IriBuf,
    controller: UriBuf,
    method_type: &str,
) -> VerificationResult<(AnyMethod, AnySuite)> {
    match method_type {
        "JsonWebKey2020" => {
            let public_jwk = jwk.to_public();
            let method = JsonWebKey2020 {
                id: verification_method.clone(),
                controller,
                public_key: Box::new(public_jwk),
            };
            Ok((
                AnyMethod::JsonWebKey2020(method),
                AnySuite::JsonWebSignature2020,
            ))
        }
        "Ed25519VerificationKey2018" => {
            let public_key = ed25519_public_key_bytes(jwk)?;
            let public_key_base58 = bs58::encode(public_key).into_string();
            let method_value = json!({
                "id": verification_method.to_string(),
                "type": "Ed25519VerificationKey2018",
                "controller": controller.to_string(),
                "publicKeyBase58": public_key_base58
            });
            let method: Ed25519VerificationKey2018 =
                serde_json::from_value(method_value).map_err(|e| {
                    VerificationError::open_badges(format!(
                        "Invalid Ed25519VerificationKey2018 method: {}",
                        e
                    ))
                })?;
            Ok((
                AnyMethod::Ed25519VerificationKey2018(method),
                AnySuite::Ed25519Signature2018,
            ))
        }
        "Ed25519VerificationKey2020" => {
            let verifying_key = ed25519_verifying_key(jwk)?;
            let method = Ed25519VerificationKey2020::from_public_key(
                verification_method.clone(),
                controller,
                verifying_key,
            );
            Ok((
                AnyMethod::Ed25519VerificationKey2020(method),
                AnySuite::Ed25519Signature2020,
            ))
        }
        _ => Err(VerificationError::open_badges_unsupported(format!(
            "Unsupported verification method type: {}",
            method_type
        ))),
    }
}

// For X509 verification methods, this function extracts PEM from the credential's verificationMethod
#[allow(dead_code)]
fn build_x509_verification_method(
    pem: &str,
    verification_method: &IriBuf,
    controller: UriBuf,
) -> VerificationResult<X509VerificationKey2021> {
    Ok(X509VerificationKey2021::new(
        verification_method.clone(),
        controller.to_string(),
        pem.to_string(),
    ))
}

fn ed25519_public_key_bytes(jwk: &JWK) -> VerificationResult<Vec<u8>> {
    match &jwk.params {
        JwkParams::OKP(params) if params.curve == "Ed25519" => Ok(params.public_key.0.clone()),
        _ => Err(VerificationError::open_badges_unsupported(
            "Ed25519 verification methods require an Ed25519 OKP JWK".to_string(),
        )),
    }
}

fn ed25519_verifying_key(jwk: &JWK) -> VerificationResult<ed25519_dalek::VerifyingKey> {
    let public_key = ed25519_public_key_bytes(jwk)?;
    ed25519_dalek::VerifyingKey::try_from(public_key.as_slice())
        .map_err(|e| VerificationError::open_badges(format!("Invalid Ed25519 public key: {}", e)))
}

pub(super) fn push_error(
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
    code: &'static str,
    message: impl Into<String>,
) {
    errors.push(message.into());
    error_codes_out.push(code.to_string());
}

fn has_context(value: &Value, context_uri: &str) -> bool {
    match value.get("@context") {
        Some(Value::String(ctx)) => ctx == context_uri,
        Some(Value::Array(contexts)) => contexts
            .iter()
            .any(|ctx| ctx.as_str().map(|s| s == context_uri).unwrap_or(false)),
        _ => false,
    }
}

#[derive(Default)]
pub(super) struct CollectedVerificationMethods {
    pub(super) resolver: HashMap<IriBuf, AnyMethod>,
    assertion_authorizations: HashSet<(String, String)>,
    ambiguous: HashSet<IriBuf>,
}

pub(super) fn collect_verification_methods(
    store: &DocumentStore,
    warnings: &mut Vec<String>,
) -> CollectedVerificationMethods {
    let mut collected = CollectedVerificationMethods::default();

    for (key, value) in store {
        let controller_document_id = value.get("id").and_then(Value::as_str);
        let assertion_entries = relationship_entries(value.get("assertionMethod"));

        if let Some(controller) = controller_document_id {
            for entry in &assertion_entries {
                if let Some(method_id) = relationship_method_id(entry) {
                    collected
                        .assertion_authorizations
                        .insert((controller.to_string(), method_id.to_string()));
                }
            }
        }

        if let Some(entries) = extract_method_entries(value) {
            for entry in entries {
                if let Some((iri, method)) = parse_verification_method(&entry, warnings, key) {
                    insert_verification_method(&mut collected, iri, method, warnings);
                }
            }
        } else if let Some((iri, method)) = parse_verification_method(value, warnings, key) {
            if let Some(controller) = method.controller() {
                collected
                    .assertion_authorizations
                    .insert((controller.to_string(), iri.to_string()));
            }
            insert_verification_method(&mut collected, iri, method, warnings);
        }

        // DID/controller documents may embed a method directly in the
        // assertion relationship instead of referencing verificationMethod.
        for entry in assertion_entries {
            if entry.is_object() {
                if let Some((iri, method)) = parse_verification_method(entry, warnings, key) {
                    insert_verification_method(&mut collected, iri, method, warnings);
                }
            }
        }
    }

    collected
}

fn insert_verification_method(
    collected: &mut CollectedVerificationMethods,
    iri: IriBuf,
    method: AnyMethod,
    warnings: &mut Vec<String>,
) {
    if collected.ambiguous.contains(&iri) {
        return;
    }

    if collected.resolver.remove(&iri).is_some() {
        warnings.push(format!(
            "Ambiguous duplicate verification method id {}",
            iri
        ));
        collected.ambiguous.insert(iri);
    } else {
        collected.resolver.insert(iri, method);
    }
}

fn relationship_entries(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Array(entries)) => entries.iter().collect(),
        Some(entry @ (Value::String(_) | Value::Object(_))) => vec![entry],
        _ => Vec::new(),
    }
}

fn relationship_method_id(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("id").and_then(Value::as_str))
}

pub(super) fn validate_issuer_proof_authorization(
    credential: &Value,
    collected: &CollectedVerificationMethods,
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
) {
    let Some(issuer) = credential_issuer(credential) else {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
            "Open Badge credential is missing an issuer identifier",
        );
        return;
    };

    let proofs = proof_entries(credential.get("proof"));
    if proofs.is_empty() {
        push_error(
            errors,
            error_codes_out,
            error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
            "Open Badge credential is missing an issuer proof",
        );
        return;
    }

    for proof in proofs {
        if proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod") {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                "Open Badge issuer proof must use assertionMethod",
            );
            continue;
        }

        let Some(method_id) = proof.get("verificationMethod").and_then(Value::as_str) else {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                "Open Badge issuer proof is missing a verificationMethod identifier",
            );
            continue;
        };
        let Ok(method_iri) = IriBuf::new(method_id.to_string()) else {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                "Open Badge issuer proof has an invalid verificationMethod identifier",
            );
            continue;
        };

        if collected.ambiguous.contains(&method_iri) {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                format!("Open Badge verification method {method_id} is ambiguous"),
            );
            continue;
        }

        let Some(method) = collected.resolver.get(&method_iri) else {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                format!("Open Badge verification method {method_id} is not trusted"),
            );
            continue;
        };
        let Some(controller) = method.controller().map(ToString::to_string) else {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                format!("Open Badge verification method {method_id} has no controller"),
            );
            continue;
        };

        if !issuer_controller_matches(&issuer, &controller, method_id) {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                format!(
                    "Open Badge verification method {method_id} is not controlled by issuer {issuer}"
                ),
            );
            continue;
        }

        if !collected
            .assertion_authorizations
            .contains(&(controller, method_id.to_string()))
        {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED,
                format!(
                    "Open Badge verification method {method_id} is not authorized for issuer assertions"
                ),
            );
        }
    }
}

fn proof_entries(value: Option<&Value>) -> Vec<&Value> {
    match value {
        Some(Value::Array(proofs)) => proofs.iter().collect(),
        Some(proof @ Value::Object(_)) => vec![proof],
        _ => Vec::new(),
    }
}

fn issuer_controller_matches(issuer: &str, controller: &str, method_id: &str) -> bool {
    if issuer == controller {
        return true;
    }

    issuer.starts_with("did:")
        && issuer == method_id
        && issuer
            .split_once('#')
            .is_some_and(|(did, fragment)| !fragment.is_empty() && did == controller)
}

fn parse_verification_method(
    value: &Value,
    warnings: &mut Vec<String>,
    key: &str,
) -> Option<(IriBuf, AnyMethod)> {
    let method =
        if let Ok(generic) = serde_json::from_value::<GenericVerificationMethod>(value.clone()) {
            AnyMethod::try_from(generic).map_err(|e| e.to_string())
        } else {
            serde_json::from_value::<AnyMethod>(value.clone()).map_err(|e| e.to_string())
        };

    match method {
        Ok(method) => match IriBuf::new(method.id().to_string()) {
            Ok(iri) => Some((iri, method)),
            Err(_) => {
                warnings.push(format!(
                    "Invalid verification method id for document {}",
                    key
                ));
                None
            }
        },
        Err(err) => {
            warnings.push(format!(
                "Failed to parse verification method {}: {}",
                key, err
            ));
            None
        }
    }
}

fn extract_method_entries(value: &Value) -> Option<Vec<Value>> {
    let methods = value.get("verificationMethod")?;
    Some(match methods {
        Value::Array(entries) => entries.clone(),
        Value::Object(_) => vec![methods.clone()],
        _ => Vec::new(),
    })
}

pub(super) fn credential_issuer(value: &Value) -> Option<String> {
    match value.get("issuer") {
        Some(Value::String(issuer)) => Some(issuer.clone()),
        Some(Value::Object(obj)) => obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn normalize_ob3(value: &Value) -> Value {
    json!({
        "credential_id": value.get("id").cloned().unwrap_or(Value::Null),
        "issuer": value.get("issuer").cloned().unwrap_or(Value::Null),
        "credential_subject": value.get("credentialSubject").cloned().unwrap_or(Value::Null),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authorization_method(method_id: &str, controller: &str) -> Value {
        let jwk = JWK::generate_ed25519().expect("generate test key");
        json!({
            "id": method_id,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": serde_json::to_value(jwk.to_public()).expect("serialize public key")
        })
    }

    fn authorization_codes(credential: &Value, store: &DocumentStore) -> Vec<String> {
        let mut warnings = Vec::new();
        let collected = collect_verification_methods(store, &mut warnings);
        let mut errors = Vec::new();
        let mut codes = Vec::new();
        validate_issuer_proof_authorization(credential, &collected, &mut errors, &mut codes);
        codes
    }

    fn issuer_credential(issuer: &str, method_id: &str, purpose: &str) -> Value {
        json!({
            "issuer": issuer,
            "proof": {
                "proofPurpose": purpose,
                "verificationMethod": method_id
            }
        })
    }

    #[test]
    fn issuer_proof_requires_issuer_control_and_assertion_purpose() {
        let method_id = "did:example:issuer#key-1";
        let credential = issuer_credential("did:example:issuer", method_id, "assertionMethod");
        let mut store = DocumentStore::new();
        store.insert(
            method_id.to_string(),
            authorization_method(method_id, "did:example:other"),
        );
        assert_eq!(
            authorization_codes(&credential, &store),
            vec![error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED]
        );

        store.insert(
            method_id.to_string(),
            authorization_method(method_id, "did:example:issuer"),
        );
        let wrong_purpose = issuer_credential("did:example:issuer", method_id, "authentication");
        assert_eq!(
            authorization_codes(&wrong_purpose, &store),
            vec![error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED]
        );
    }

    #[test]
    fn controller_document_requires_assertion_relationship() {
        let issuer = "did:example:issuer";
        let method_id = "did:example:issuer#key-1";
        let method = authorization_method(method_id, issuer);
        let credential = issuer_credential(issuer, method_id, "assertionMethod");
        let mut store = DocumentStore::new();
        store.insert(
            issuer.to_string(),
            json!({
                "id": issuer,
                "verificationMethod": [method]
            }),
        );

        assert_eq!(
            authorization_codes(&credential, &store),
            vec![error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED]
        );

        store.get_mut(issuer).expect("controller document")["assertionMethod"] = json!([method_id]);
        assert!(authorization_codes(&credential, &store).is_empty());

        store.insert(
            issuer.to_string(),
            json!({
                "id": issuer,
                "assertionMethod": [authorization_method(method_id, issuer)]
            }),
        );
        assert!(authorization_codes(&credential, &store).is_empty());
    }

    #[test]
    fn duplicate_verification_method_ids_are_ambiguous() {
        let issuer = "did:example:issuer";
        let method_id = "did:example:issuer#key-1";
        let method = authorization_method(method_id, issuer);
        let credential = issuer_credential(issuer, method_id, "assertionMethod");
        let mut store = DocumentStore::new();
        store.insert("record-a".to_string(), method.clone());
        store.insert("record-b".to_string(), method);

        assert_eq!(
            authorization_codes(&credential, &store),
            vec![error_codes::OPEN_BADGES_ISSUER_UNAUTHORIZED]
        );
    }

    #[test]
    fn did_url_issuer_can_use_its_fragmentless_did_controller() {
        let method_id = "did:example:issuer#key-1";
        let credential = issuer_credential(method_id, method_id, "assertionMethod");
        let mut store = DocumentStore::new();
        store.insert(
            method_id.to_string(),
            authorization_method(method_id, "did:example:issuer"),
        );

        assert!(authorization_codes(&credential, &store).is_empty());
    }
}
