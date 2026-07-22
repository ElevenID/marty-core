//! W3C Verifiable Credentials Data Model v2 Data Integrity verification.
//!
//! This module deliberately starts with the standards-track
//! `eddsa-rdfc-2022` cryptosuite and offline `did:key` resolution. It verifies
//! presentation proofs, binds their challenge and domain, and independently
//! verifies every embedded credential rather than trusting a valid outer proof.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_claims::data_integrity::{AnySuite, DataIntegrity};
use ssi_claims::vc::syntax::{AnyJsonCredential, AnyJsonPresentation};
use ssi_claims::VerificationParameters;
use ssi_dids::{DIDKey, DIDResolver, VerificationMethodDIDResolver};
use ssi_verification_methods::AnyMethod;

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
}

#[derive(Debug, Serialize)]
struct VerifyResult {
    valid: bool,
    kind: &'static str,
    verified_proofs: usize,
    verified_credentials: usize,
    errors: Vec<String>,
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
        verify_credential_document(&request.document).await
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn verify_vcdm_data_integrity_json(request_json: &str) -> String {
    futures::executor::block_on(verify_vcdm_data_integrity_json_async(request_json))
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
    if holder.is_none() {
        errors.push("Presentation holder must be an absolute identifier".to_string());
    }
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
        Ok(presentation) => match verification_parameters() {
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
            match verify_credential(credential).await {
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

async fn verify_credential_document(document: &Value) -> String {
    let issuer = identifier(document, "issuer");
    let mut errors = validate_proofs(document, "assertionMethod", None, None, issuer);
    if issuer.is_none() {
        errors.push("Credential issuer must be an absolute identifier".to_string());
    }
    let mut verified_proofs = 0;
    match verify_credential(document).await {
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

async fn verify_credential(document: &Value) -> Result<(), String> {
    let credential: AnyCredential = serde_json::from_value(document.clone())
        .map_err(|error| format!("Invalid VCDM credential: {error}"))?;
    let parameters = verification_parameters()?;
    match credential.verify(parameters).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(invalid)) => Err(format!("Credential proof is invalid: {invalid}")),
        Err(error) => Err(format!("Credential verification failed: {error}")),
    }
}

fn verification_parameters() -> Result<
    VerificationParameters<
        VerificationMethodDIDResolver<DIDKey, AnyMethod>,
        ssi_json_ld::ContextLoader,
    >,
    String,
> {
    let loader = open_badges_context_loader().map_err(|error| error.to_string())?;
    let resolver = DIDKey.into_vm_resolver::<AnyMethod>();
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
        if !verification_method
            .is_some_and(|value| value.starts_with("did:key:") && value.contains('#'))
        {
            errors.push("Verification method must be a did:key URL".to_string());
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OFFICIAL_SUITE_PRESENTATION: &str =
        include_str!("../tests/fixtures/w3c_vcdm_v2_official_suite_presentation.json");

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
}
