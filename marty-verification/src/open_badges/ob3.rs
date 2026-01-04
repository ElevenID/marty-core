use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

use iref::{IriBuf, UriBuf};
use ssi::claims::data_integrity::{AnySuite, DataIntegrity, ProofOptions};
use ssi::claims::vc::syntax::AnyJsonCredential;
use ssi::claims::SignatureEnvironment;
use ssi::claims::VerificationParameters;
use ssi::prelude::CryptographicSuite;
use ssi::verification_methods::{
    AnyMethod, Ed25519VerificationKey2018, Ed25519VerificationKey2020, GenericVerificationMethod,
    JsonWebKey2020, ProofPurpose, ReferenceOrOwned, SingleSecretSigner,
};
use ssi::verification_methods::VerificationMethod;
use ssi::jwk::Params as JwkParams;
use ssi::JWK;
use ssi::json_ld::syntax::{Context, ContextEntry};

use crate::error::{codes as error_codes, VerificationError, VerificationResult};

use super::contexts::{ob3_context_uri, open_badges_context_loader, security_v2_context_uri};
use super::types::{DocumentStore, OpenBadgesIssueResult, OpenBadgesVerificationResult};

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

type AnyCredential = DataIntegrity<AnyJsonCredential, AnySuite>;

pub async fn issue_ob3_json_async(request_json: &str) -> VerificationResult<String> {
    let req: IssueOb3Request = serde_json::from_str(request_json)
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB3 issue request: {}", e)))?;

    let credential: AnyJsonCredential = serde_json::from_value(req.credential.clone())
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB3 credential: {}", e)))?;

    let jwk: JWK = serde_json::from_value(req.signing.jwk.clone())
        .map_err(|e| VerificationError::open_badges(format!("Invalid JWK: {}", e)))?;

    let verification_method_iri = IriBuf::new(req.signing.verification_method.clone())
        .map_err(|e| VerificationError::open_badges(format!("Invalid verification_method: {}", e)))?;

    let controller = req
        .signing
        .controller
        .clone()
        .or_else(|| credential_issuer(&req.credential))
        .ok_or_else(|| VerificationError::open_badges("Missing controller for verification method".to_string()))?;

    let controller_bytes = controller.clone().into_bytes();
    let controller_uri = UriBuf::new(controller_bytes).map_err(|e| {
        VerificationError::open_badges(format!("Invalid controller URI {}: {:?}", controller, e))
    })?;

    let method_type = req
        .signing
        .verification_method_type
        .clone()
        .unwrap_or_else(|| "JsonWebKey2020".to_string());
    let (method, suite) = build_verification_method(
        &jwk,
        &verification_method_iri,
        controller_uri,
        &method_type,
    )?;

    let mut resolver: HashMap<IriBuf, AnyMethod> = HashMap::new();
    resolver.insert(verification_method_iri.clone(), method);

    let signer = SingleSecretSigner::new(jwk.clone()).into_local();

    let mut proof_options = ProofOptions::from_method(ReferenceOrOwned::Reference(verification_method_iri));
    if method_type == "Ed25519VerificationKey2018" {
        let context_iri = IriBuf::new(security_v2_context_uri().to_string()).map_err(|e| {
            VerificationError::open_badges(format!("Invalid proof context URI: {}", e))
        })?;
        proof_options.context = Some(Context::One(ContextEntry::from(context_iri)));
    }
    if let Some(purpose) = req.signing.proof_purpose {
        proof_options.proof_purpose = parse_proof_purpose(&purpose)?;
    }

    let loader = open_badges_context_loader()?;
    let env = SignatureEnvironment {
        json_ld_loader: loader,
        eip712_loader: (),
    };

    let signed = suite
        .sign_with(env, credential, &resolver, &signer, proof_options, Default::default())
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

    serde_json::to_string(&result)
        .map_err(|e| VerificationError::open_badges(format!("Failed to serialize OB3 issue result: {}", e)))
}

pub async fn verify_ob3_json_async(request_json: &str) -> VerificationResult<String> {
    let req: VerifyOb3Request = serde_json::from_str(request_json)
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB3 verify request: {}", e)))?;

    let credential: AnyCredential = serde_json::from_value(req.credential.clone())
        .map_err(|e| VerificationError::open_badges(format!("Invalid OB3 credential: {}", e)))?;

    let mut errors = Vec::new();
    let mut error_codes_out = Vec::new();
    let mut warnings = Vec::new();

    if !has_context(&req.credential, ob3_context_uri())
        && !has_context(&req.credential, "https://w3id.org/openbadges/v3")
    {
        push_error(
            &mut errors,
            &mut error_codes_out,
            error_codes::OPEN_BADGES_CONTEXT_MISSING,
            "Missing Open Badges v3 context",
        );
    }

    let store = req.document_store.unwrap_or_default();
    let resolver = collect_verification_methods(&store, &mut warnings);

    let loader = open_badges_context_loader()?;
    let params = VerificationParameters::from_resolver(resolver).with_json_ld_loader(loader);

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

    // Credential status check (revocation)
    check_credential_status(&req.credential, &store, &mut errors, &mut error_codes_out, &mut warnings);

    let normalized = normalize_ob3(&req.credential);

    let result = OpenBadgesVerificationResult {
        valid: errors.is_empty(),
        version: "3.0".to_string(),
        errors,
        error_codes: error_codes_out,
        warnings,
        normalized: Some(normalized),
    };

    serde_json::to_string(&result)
        .map_err(|e| VerificationError::open_badges(format!("Failed to serialize OB3 verify result: {}", e)))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn issue_ob3_json(request_json: &str) -> VerificationResult<String> {
    futures::executor::block_on(issue_ob3_json_async(request_json))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_ob3_json(request_json: &str) -> VerificationResult<String> {
    futures::executor::block_on(verify_ob3_json_async(request_json))
}

fn parse_proof_purpose(value: &str) -> VerificationResult<ProofPurpose> {
    match value {
        "assertionMethod" => Ok(ProofPurpose::Assertion),
        "authentication" => Ok(ProofPurpose::Authentication),
        "capabilityInvocation" => Ok(ProofPurpose::CapabilityInvocation),
        "capabilityDelegation" => Ok(ProofPurpose::CapabilityDelegation),
        "keyAgreement" => Ok(ProofPurpose::KeyAgreement),
        _ => Err(VerificationError::open_badges_unsupported(format!(
            "Unsupported proof purpose: {}",
            value
        ))),
    }
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
            Ok((AnyMethod::JsonWebKey2020(method), AnySuite::JsonWebSignature2020))
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
            let method: Ed25519VerificationKey2018 = serde_json::from_value(method_value).map_err(|e| {
                VerificationError::open_badges(format!(
                    "Invalid Ed25519VerificationKey2018 method: {}",
                    e
                ))
            })?;
            Ok((AnyMethod::Ed25519VerificationKey2018(method), AnySuite::Ed25519Signature2018))
        }
        "Ed25519VerificationKey2020" => {
            let verifying_key = ed25519_verifying_key(jwk)?;
            let method =
                Ed25519VerificationKey2020::from_public_key(verification_method.clone(), controller, verifying_key);
            Ok((AnyMethod::Ed25519VerificationKey2020(method), AnySuite::Ed25519Signature2020))
        }
        _ => Err(VerificationError::open_badges_unsupported(format!(
            "Unsupported verification method type: {}",
            method_type
        ))),
    }
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
    ed25519_dalek::VerifyingKey::try_from(public_key.as_slice()).map_err(|e| {
        VerificationError::open_badges(format!("Invalid Ed25519 public key: {}", e))
    })
}

fn push_error(
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

fn collect_verification_methods(
    store: &DocumentStore,
    warnings: &mut Vec<String>,
) -> HashMap<IriBuf, AnyMethod> {
    let mut methods = HashMap::new();

    for (key, value) in store {
        if let Some(entries) = extract_method_entries(value) {
            for entry in entries {
                if let Some((iri, method)) = parse_verification_method(&entry, warnings, key) {
                    methods.insert(iri, method);
                }
            }
        } else if let Some((iri, method)) = parse_verification_method(value, warnings, key) {
            methods.insert(iri, method);
        }
    }

    methods
}

fn parse_verification_method(
    value: &Value,
    warnings: &mut Vec<String>,
    key: &str,
) -> Option<(IriBuf, AnyMethod)> {
    let method = if let Ok(generic) = serde_json::from_value::<GenericVerificationMethod>(value.clone()) {
        AnyMethod::try_from(generic).map_err(|e| e.to_string())
    } else {
        serde_json::from_value::<AnyMethod>(value.clone()).map_err(|e| e.to_string())
    };

    match method {
        Ok(method) => match IriBuf::new(method.id().to_string()) {
            Ok(iri) => Some((iri, method)),
            Err(_) => {
                warnings.push(format!("Invalid verification method id for document {}", key));
                None
            }
        },
        Err(err) => {
            warnings.push(format!("Failed to parse verification method {}: {}", key, err));
            None
        }
    }
}

fn extract_method_entries(value: &Value) -> Option<Vec<Value>> {
    if let Some(methods) = value.get("verificationMethod") {
        return methods.as_array().cloned();
    }
    None
}

fn credential_issuer(value: &Value) -> Option<String> {
    match value.get("issuer") {
        Some(Value::String(issuer)) => Some(issuer.clone()),
        Some(Value::Object(obj)) => obj.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()),
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

/// Check credential status (revocation) for OB3 credentials.
/// Supports StatusList2021, BitstringStatusListEntry, and RevocationList2020.
fn check_credential_status(
    credential: &Value,
    document_store: &super::types::DocumentStore,
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(status) = credential.get("credentialStatus") else {
        // No credentialStatus field - nothing to check
        return;
    };

    // Handle single status or array of statuses
    let statuses: Vec<&Value> = match status {
        Value::Array(arr) => arr.iter().collect(),
        _ => vec![status],
    };

    for status_entry in statuses {
        let status_type = status_entry
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match status_type {
            "StatusList2021Entry" | "BitstringStatusListEntry" => {
                check_status_list_entry(status_entry, document_store, errors, error_codes_out, warnings);
            }
            "RevocationList2020Status" => {
                check_revocation_list_2020(status_entry, document_store, errors, error_codes_out, warnings);
            }
            _ if !status_type.is_empty() => {
                warnings.push(format!(
                    "Unsupported credential status type '{}', skipping revocation check",
                    status_type
                ));
            }
            _ => {
                warnings.push("Credential status entry missing 'type' field".to_string());
            }
        }
    }
}

/// Check StatusList2021Entry or BitstringStatusListEntry status.
fn check_status_list_entry(
    status_entry: &Value,
    document_store: &super::types::DocumentStore,
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let status_list_credential = status_entry
        .get("statusListCredential")
        .and_then(|v| v.as_str());
    let status_list_index = status_entry
        .get("statusListIndex")
        .and_then(|v| v.as_str().or_else(|| v.as_u64().map(|_| "")))
        .and_then(|s| if s.is_empty() {
            status_entry.get("statusListIndex").and_then(|v| v.as_u64())
        } else {
            s.parse::<u64>().ok()
        });
    let status_purpose = status_entry
        .get("statusPurpose")
        .and_then(|v| v.as_str())
        .unwrap_or("revocation");

    let Some(list_url) = status_list_credential else {
        warnings.push("StatusList entry missing 'statusListCredential' URL".to_string());
        return;
    };

    let Some(index) = status_list_index else {
        warnings.push("StatusList entry missing or invalid 'statusListIndex'".to_string());
        return;
    };

    // Look up the status list credential in the document store
    let Some(status_list_doc) = document_store.get(list_url) else {
        warnings.push(format!(
            "StatusList credential '{}' not found in document store, unable to verify revocation status",
            list_url
        ));
        return;
    };

    // Extract the encoded list from the status list credential
    let encoded_list = status_list_doc
        .get("credentialSubject")
        .and_then(|cs| cs.get("encodedList"))
        .and_then(|v| v.as_str());

    let Some(encoded) = encoded_list else {
        warnings.push("StatusList credential missing 'credentialSubject.encodedList'".to_string());
        return;
    };

    // Decode and check the bit at the specified index
    match decode_and_check_status_bit(encoded, index) {
        Ok(is_set) => {
            if is_set {
                push_error(
                    errors,
                    error_codes_out,
                    error_codes::OPEN_BADGES_REVOKED,
                    format!("Credential has been {} (statusListIndex: {})", status_purpose, index),
                );
            }
        }
        Err(e) => {
            warnings.push(format!("Failed to decode status list: {}", e));
        }
    }
}

/// Decode a base64+gzip compressed bitstring and check if the bit at `index` is set.
fn decode_and_check_status_bit(encoded: &str, index: u64) -> Result<bool, String> {
    use base64::{engine::general_purpose, Engine as _};
    use flate2::read::GzDecoder;
    use std::io::Read;

    // Decode base64
    let compressed = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("Base64 decode error: {}", e))?;

    // Decompress gzip
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut bitstring = Vec::new();
    decoder
        .read_to_end(&mut bitstring)
        .map_err(|e| format!("Gzip decompress error: {}", e))?;

    // Check the bit at the specified index
    let byte_index = (index / 8) as usize;
    let bit_index = (index % 8) as u8;

    if byte_index >= bitstring.len() {
        return Err(format!(
            "Status index {} out of bounds (list size: {} bytes)",
            index,
            bitstring.len()
        ));
    }

    // Bits are numbered from most significant to least significant
    let bit_mask = 0x80 >> bit_index;
    Ok((bitstring[byte_index] & bit_mask) != 0)
}

/// Check RevocationList2020Status (legacy format).
fn check_revocation_list_2020(
    status_entry: &Value,
    document_store: &super::types::DocumentStore,
    errors: &mut Vec<String>,
    error_codes_out: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let revocation_list_credential = status_entry
        .get("revocationListCredential")
        .and_then(|v| v.as_str());
    let revocation_list_index = status_entry
        .get("revocationListIndex")
        .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()).or_else(|| v.as_u64()));

    let Some(list_url) = revocation_list_credential else {
        warnings.push("RevocationList2020 entry missing 'revocationListCredential' URL".to_string());
        return;
    };

    let Some(index) = revocation_list_index else {
        warnings.push("RevocationList2020 entry missing or invalid 'revocationListIndex'".to_string());
        return;
    };

    // Look up in document store
    let Some(revocation_list_doc) = document_store.get(list_url) else {
        warnings.push(format!(
            "RevocationList credential '{}' not found in document store, unable to verify revocation status",
            list_url
        ));
        return;
    };

    // Check if the index is in the revokedCredentials array
    let revoked_credentials = revocation_list_doc
        .get("credentialSubject")
        .and_then(|cs| cs.get("revokedCredentials"))
        .and_then(|v| v.as_array());

    if let Some(revoked) = revoked_credentials {
        let is_revoked = revoked.iter().any(|v| {
            v.as_u64() == Some(index) || v.as_str().and_then(|s| s.parse::<u64>().ok()) == Some(index)
        });

        if is_revoked {
            push_error(
                errors,
                error_codes_out,
                error_codes::OPEN_BADGES_REVOKED,
                format!("Credential has been revoked (revocationListIndex: {})", index),
            );
        }
    } else {
        warnings.push("RevocationList credential missing 'credentialSubject.revokedCredentials'".to_string());
    }
}
