use serde::Deserialize;
use serde_json::json;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

use iref::IriBuf;
use ssi_claims::data_integrity::{AnySuite, DataIntegrity};
use ssi_claims::vc::syntax::AnyJsonCredential;
use ssi_claims::VerificationParameters;
use ssi_verification_methods::VerificationMethod;
use ssi_verification_methods::{AnyMethod, GenericVerificationMethod};

use crate::error::{codes as error_codes, VerificationError, VerificationResult};

use super::contexts::{ob3_context_uri, open_badges_context_loader};
use super::method_wrapper::ensure_public_verification_method;
use super::status::check_credential_status;
use super::types::{AuthenticatedStatusList, DocumentStore, OpenBadgesVerificationResult};

#[derive(Debug, Deserialize)]
pub struct VerifyOb3Request {
    pub credential: Value,
    #[serde(default)]
    pub document_store: Option<DocumentStore>,
}

pub(super) type AnyCredential = DataIntegrity<AnyJsonCredential, AnySuite>;

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

    let result = verify_ob3_with_status_lists_async(req, authenticated_status_lists).await?;
    serde_json::to_string(&result).map_err(|e| {
        VerificationError::open_badges(format!("Failed to serialize OB3 verify result: {}", e))
    })
}

/// Verify an OB3 credential without an intermediate JSON request or response.
pub async fn verify_ob3_async(
    req: VerifyOb3Request,
) -> VerificationResult<OpenBadgesVerificationResult> {
    verify_ob3_with_status_lists_async(req, &[]).await
}

/// Verify an OB3 credential with separately authenticated status-list inputs.
/// Documents in the request's store never establish status authority themselves.
pub async fn verify_ob3_with_status_lists_async(
    req: VerifyOb3Request,
    authenticated_status_lists: &[AuthenticatedStatusList],
) -> VerificationResult<OpenBadgesVerificationResult> {
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

    Ok(result)
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
    if let Err(error) = ensure_public_verification_method(value) {
        warnings.push(format!(
            "Failed to parse verification method {key}: {error}"
        ));
        return None;
    }
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
        json!({
            "id": method_id,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": marty_crypto_test_support::ED25519_PUBLIC_JWK_X
            }
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
    fn document_store_rejects_private_verification_method_extensions() {
        for member in [
            "privateKeyJwk",
            "privateKeyPem",
            "privateKeyBase58",
            "privateKeyMultibase",
            "privateKeyHex",
        ] {
            let method_id = "did:example:issuer#key-1";
            let mut method = authorization_method(method_id, "did:example:issuer");
            method
                .as_object_mut()
                .unwrap()
                .insert(member.into(), json!("secret-sentinel"));
            let mut store = DocumentStore::new();
            store.insert(method_id.into(), method);
            let mut warnings = Vec::new();
            let collected = collect_verification_methods(&store, &mut warnings);
            assert!(collected.resolver.is_empty());
            assert!(warnings
                .iter()
                .any(|warning| warning.contains("private key member")));
            assert!(!warnings
                .iter()
                .any(|warning| warning.contains("secret-sentinel")));
        }
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
    fn private_jwk_verification_methods_are_not_collected() {
        let method_id = "did:example:issuer#key-1";
        let mut method = authorization_method(method_id, "did:example:issuer");
        method["publicKeyJwk"]["d"] = json!("secret");
        let mut store = DocumentStore::new();
        store.insert(method_id.to_string(), method);
        let mut warnings = Vec::new();
        let collected = collect_verification_methods(&store, &mut warnings);
        assert!(collected.resolver.is_empty());
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("private member")));
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
