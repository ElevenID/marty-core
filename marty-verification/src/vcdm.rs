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
use ssi_jwk::{Algorithm, JWKResolver, JWK};
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
        let mut key = JWK::generate_p256();
        let issuer = "did:web:issuer.example";
        key.key_id = Some(format!("{issuer}#key-1"));
        let token = encode_sign(Algorithm::ES256, &jwt_claims(issuer).to_string(), &key).unwrap();
        let mut tampered = token.clone().into_bytes();
        let last = tampered.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).unwrap();
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
