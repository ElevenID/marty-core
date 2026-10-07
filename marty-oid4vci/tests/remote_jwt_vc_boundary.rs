//! Public-key-only JWT-VC preparation and signature acceptance boundaries.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::jwt_vc::assemble_jwt_vc,
    remote_credential::{prepare_remote_jwt_vc, RemoteJwtVcRequest},
    Oid4vciError,
};
use serde_json::{json, Value};

const CREDENTIAL_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000456";

fn request() -> RemoteJwtVcRequest {
    RemoteJwtVcRequest {
        issuer_id: "did:web:issuer.example".into(),
        verification_method_id: "did:web:issuer.example#key-1".into(),
        algorithm: "ES256".into(),
        issuer_public_jwk: json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
        })
        .to_string(),
        subject_id: Some("did:example:holder".into()),
        credential_type: "EmployeeCredential".into(),
        claims: HashMap::from([
            ("given_name".into(), json!("Alice")),
            ("family_name".into(), json!("Smith")),
        ]),
        expiration_seconds: Some(3_600),
        credential_id: Some(CREDENTIAL_ID.into()),
        credential_subject: None,
        credential_profile: None,
        achievement_id: None,
    }
}

fn segment(signing_input: &str, index: usize) -> Value {
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(signing_input.split('.').nth(index).unwrap())
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn remote_preparation_exposes_exact_public_jwt_signing_input() {
    let prepared = prepare_remote_jwt_vc(request()).unwrap();
    let signing_input = prepared.signing_input();
    assert_eq!(signing_input.split('.').count(), 2);
    assert_eq!(prepared.signing_payload(), signing_input.as_bytes());
    assert_eq!(prepared.credential_id(), CREDENTIAL_ID);

    let header = segment(signing_input, 0);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["kid"], "did:web:issuer.example#key-1");

    let payload = segment(signing_input, 1);
    assert_eq!(payload["iss"], "did:web:issuer.example");
    assert_eq!(payload["sub"], "did:example:holder");
    assert_eq!(payload["jti"], CREDENTIAL_ID);
    assert_eq!(payload["vc"]["credentialSubject"]["given_name"], "Alice");
    assert!(payload["vc"]["type"]
        .as_array()
        .unwrap()
        .contains(&json!("EmployeeCredential")));
}

#[test]
fn remote_assembly_rejects_unverified_signature() {
    let prepared = prepare_remote_jwt_vc(request()).unwrap();
    let error = assemble_jwt_vc(prepared, &[0_u8; 64]).unwrap_err();
    assert!(matches!(error, Oid4vciError::SigningError(_)));
    assert!(!error.to_string().contains("Alice"));
}

#[test]
fn eddsa_remote_preparation_requires_only_public_key_material() {
    let mut request = request();
    request.algorithm = "EdDSA".into();
    request.issuer_public_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    })
    .to_string();

    let prepared = prepare_remote_jwt_vc(request).unwrap();
    let header = segment(prepared.signing_input(), 0);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["kid"], "did:web:issuer.example#key-1");
    assert_eq!(segment(prepared.signing_input(), 1)["jti"], CREDENTIAL_ID);
}
