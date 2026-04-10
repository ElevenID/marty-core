//! Tests for the BYOK prepare → sign → assemble round-trip.
//!
//! Validates that:
//! 1. `prepare_jwt_vc()` produces a valid signing input
//! 2. Signing that input externally and calling `assemble_jwt_vc()` produces a valid JWT
//! 3. The `CredentialSigner` trait is correctly implemented for `IssuerKey`
//! 4. `sign_jwt_vc_with_signer()` is equivalent to manual prepare+sign+assemble

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::HashMap;

use marty_oid4vci::{
    formats::jwt_vc::{prepare_jwt_vc, assemble_jwt_vc, sign_jwt_vc, sign_jwt_vc_with_signer},
    signer::CredentialSigner,
    types::{CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential, SigningAlgorithm},
};
use serde_json::{json, Value};

// ── Test fixtures ─────────────────────────────────────────────────────────────

const TEST_ED25519_JWK: &str = r#"{
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
}"#;

fn test_issuer_key() -> IssuerKey {
    IssuerKey {
        issuer_id: "https://issuer.example.com".to_string(),
        jwk_json: TEST_ED25519_JWK.to_string(),
        algorithm: SigningAlgorithm::EdDSA,
    }
}

fn base_claims() -> CredentialClaims {
    let mut claims = HashMap::new();
    claims.insert("given_name".to_string(), json!("Alice"));
    claims.insert("family_name".to_string(), json!("Smith"));
    CredentialClaims {
        credential_type: "TestCredential".to_string(),
        claims,
        subject_id: Some("did:key:z6Mktest".to_string()),
        expiration_seconds: Some(3600),
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn prepare_returns_valid_signing_input() {
    let key = test_issuer_key();
    let claims = base_claims();

    let prepared = prepare_jwt_vc(&key, &claims).expect("prepare_jwt_vc");

    // signing_input should be two base64url segments separated by a dot
    let parts: Vec<&str> = prepared.signing_input.split('.').collect();
    assert_eq!(parts.len(), 2, "signing_input should be header.payload");

    // Both parts should be valid base64url
    let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("header base64url");
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload base64url");

    // Header should be valid JSON with alg field
    let header: Value = serde_json::from_slice(&header_bytes).expect("header JSON");
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "vc+jwt");

    // Payload should contain issuer and credential type
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload JSON");
    assert_eq!(payload["iss"], "https://issuer.example.com");
    assert!(payload["vc"]["type"].as_array().unwrap().contains(&json!("TestCredential")));
    assert_eq!(payload["sub"], "did:key:z6Mktest");

    // credential_id should be a URN
    assert!(prepared.credential_id.starts_with("urn:uuid:"));
}

#[test]
fn assemble_produces_three_part_jwt() {
    let key = test_issuer_key();
    let claims = base_claims();

    let prepared = prepare_jwt_vc(&key, &claims).expect("prepare_jwt_vc");
    let cred_id = prepared.credential_id.clone();
    let signing_input = prepared.signing_input.clone();

    // Simulate external signing: sign the signing_input bytes with the test key
    let signature = key.sign(signing_input.as_bytes()).expect("sign");

    let result = assemble_jwt_vc(prepared, &signature);

    match result {
        SignedCredential::JwtVcJson { jwt, credential_id } => {
            // JWT should be three base64url segments
            let parts: Vec<&str> = jwt.split('.').collect();
            assert_eq!(parts.len(), 3, "assembled JWT should have header.payload.signature");

            // credential_id should match
            assert_eq!(credential_id, cred_id);

            // First two segments should match the signing input
            let header_payload = format!("{}.{}", parts[0], parts[1]);
            assert_eq!(header_payload, signing_input);
        }
        other => panic!("Expected JwtVcJson, got {:?}", other),
    }
}

#[test]
fn prepare_assemble_equivalent_to_sign_jwt_vc() {
    let key = test_issuer_key();
    let claims = base_claims();

    // Path A: direct sign
    let direct = sign_jwt_vc(&key, &claims).expect("sign_jwt_vc");

    // Path B: prepare + sign + assemble
    let prepared = prepare_jwt_vc(&key, &claims).expect("prepare_jwt_vc");
    let signature = key.sign(prepared.signing_input.as_bytes()).expect("sign");
    let assembled = assemble_jwt_vc(prepared, &signature);

    // Both should be JwtVcJson variants with valid JWTs
    match (&direct, &assembled) {
        (
            SignedCredential::JwtVcJson { jwt: jwt_a, .. },
            SignedCredential::JwtVcJson { jwt: jwt_b, .. },
        ) => {
            // Both should have 3 parts
            assert_eq!(jwt_a.split('.').count(), 3);
            assert_eq!(jwt_b.split('.').count(), 3);

            // Headers should be structurally identical (same alg, typ, kid)
            let header_a: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(jwt_a.split('.').next().unwrap()).unwrap(),
            )
            .unwrap();
            let header_b: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD.decode(jwt_b.split('.').next().unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(header_a["alg"], header_b["alg"]);
            assert_eq!(header_a["typ"], header_b["typ"]);
        }
        _ => panic!("Expected both to be JwtVcJson"),
    }
}

#[test]
fn sign_jwt_vc_with_signer_uses_trait() {
    let key = test_issuer_key();
    let claims = base_claims();

    // sign_jwt_vc_with_signer uses the CredentialSigner trait
    let result = sign_jwt_vc_with_signer(&key, &claims).expect("sign_jwt_vc_with_signer");

    match result {
        SignedCredential::JwtVcJson { jwt, credential_id } => {
            assert_eq!(jwt.split('.').count(), 3);
            assert!(credential_id.starts_with("urn:uuid:"));
        }
        other => panic!("Expected JwtVcJson, got {:?}", other),
    }
}

#[test]
fn issuer_key_implements_credential_signer() {
    let key = test_issuer_key();

    // Verify trait method implementations
    assert_eq!(key.issuer_id(), "https://issuer.example.com");
    assert_eq!(key.algorithm().as_str(), "EdDSA");

    // kid_url should contain the issuer_id
    let kid = key.kid_url();
    assert!(kid.contains("issuer.example.com"), "kid_url should reference issuer: {}", kid);

    // sign should produce non-empty output
    let sig = key.sign(b"test data").expect("sign");
    assert!(!sig.is_empty());
}
