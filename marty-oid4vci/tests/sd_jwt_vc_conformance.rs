//! SD-JWT VC format assertions over public-only remote-signer preparation.
//! Signed issuance and verifier acceptance run against disposable OpenBao in
//! `remote_issuer_live_kms`; this suite never creates an issuer private key.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::sd_jwt::{prepare_sd_jwt, sign_sd_jwt_with_signer, PreparedSdJwt},
    remote_credential::RemoteSignerMetadata,
    types::{CredentialClaims, CredentialPayloadFormat},
    Oid4vciError,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ISSUER_DID: &str = "did:web:issuer.example";
const PUBLIC_ED25519_JWK: &str =
    r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;

fn signer() -> RemoteSignerMetadata {
    RemoteSignerMetadata::new(
        ISSUER_DID,
        "did:web:issuer.example#key-1",
        "EdDSA",
        PUBLIC_ED25519_JWK.into(),
    )
    .unwrap()
}

fn claims(format: CredentialPayloadFormat) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some("did:example:holder".into()),
        credential_type: "IdentityCredential".into(),
        claims: HashMap::from([
            ("given_name".into(), json!("Alice")),
            ("family_name".into(), json!("Smith")),
            ("birth_date".into(), json!("1990-01-15")),
        ]),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: format,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn payload(prepared: &PreparedSdJwt) -> Value {
    let encoded = prepared.signing_input().split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap()
}

fn disclosures(prepared: &PreparedSdJwt) -> Vec<(&str, Value)> {
    prepared
        .disclosures_suffix()
        .split('~')
        .filter(|entry| !entry.is_empty())
        .map(|encoded| {
            let decoded =
                serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).unwrap()).unwrap();
            (encoded, decoded)
        })
        .collect()
}

#[test]
fn ietf_preparation_preserves_compact_shape_identity_and_plaintext_claims() {
    let prepared = prepare_sd_jwt(&signer(), &claims(CredentialPayloadFormat::IetfSdJwt)).unwrap();
    assert_eq!(prepared.signing_input().split('.').count(), 2);
    assert_eq!(
        prepared.signing_payload(),
        prepared.signing_input().as_bytes()
    );
    assert_eq!(prepared.disclosures_suffix(), "~");
    assert!(disclosures(&prepared).is_empty());

    let credential_id = prepared.credential_id();
    assert!(credential_id.starts_with("urn:uuid:"));
    uuid::Uuid::parse_str(credential_id.trim_start_matches("urn:uuid:")).unwrap();

    let body = payload(&prepared);
    assert_eq!(body["iss"], ISSUER_DID);
    assert_eq!(body["vct"], "IdentityCredential");
    assert_eq!(body["sub"], "did:example:holder");
    assert_eq!(body["jti"], credential_id);
    assert!(body["iat"].is_number());
    assert!(body["exp"].is_number());
    assert_eq!(body["given_name"], "Alice");
    assert_eq!(body["family_name"], "Smith");
    assert!(body.get("credentialSubject").is_none());
}

#[test]
fn w3c_preparation_preserves_context_type_issuer_and_subject() {
    let mut submitted = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
    submitted.credential_type = "UniversityDegreeCredential".into();
    submitted.w3c_context = vec!["https://example.com/credentials/v1".into()];
    submitted.w3c_types = vec!["UniversityDegreeCredential".into()];
    let prepared = prepare_sd_jwt(&signer(), &submitted).unwrap();
    let body = payload(&prepared);
    let contexts = body["@context"].as_array().unwrap();
    assert!(contexts.contains(&json!("https://www.w3.org/ns/credentials/v2")));
    assert!(contexts.contains(&json!("https://example.com/credentials/v1")));
    let types = body["type"].as_array().unwrap();
    assert!(types.contains(&json!("VerifiableCredential")));
    assert!(types.contains(&json!("UniversityDegreeCredential")));
    assert_eq!(body["issuer"], ISSUER_DID);
    assert!(body["validFrom"].is_string());
    assert_eq!(body["credentialSubject"]["id"], "did:example:holder");
    assert_eq!(body["credentialSubject"]["given_name"], "Alice");
    assert!(body.get("given_name").is_none());
}

#[test]
fn ietf_selective_disclosure_hides_claims_and_binds_each_hash() {
    let mut submitted = claims(CredentialPayloadFormat::IetfSdJwt);
    submitted.selective_disclosure_claims = vec![
        "given_name".into(),
        "family_name".into(),
        "birth_date".into(),
    ];
    let prepared = prepare_sd_jwt(&signer(), &submitted).unwrap();
    let body = payload(&prepared);
    for name in ["given_name", "family_name", "birth_date"] {
        assert!(body.get(name).is_none(), "{name} leaked into plaintext");
    }
    assert_eq!(body["_sd_alg"], "sha-256");
    let hashes = body["_sd"].as_array().unwrap();
    assert_eq!(hashes.len(), 3);
    let entries = disclosures(&prepared);
    assert_eq!(entries.len(), 3);
    let mut names = Vec::new();
    for (encoded, decoded) in entries {
        let parts = decoded.as_array().unwrap();
        assert_eq!(parts.len(), 3);
        assert!(parts[0].as_str().unwrap().len() >= 16);
        let name = parts[1].as_str().unwrap();
        names.push(name.to_owned());
        assert_eq!(parts[2], submitted.claims[name]);
        let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
        assert!(hashes.contains(&json!(digest)));
    }
    names.sort_unstable();
    assert_eq!(names, ["birth_date", "family_name", "given_name"]);
}

#[test]
fn w3c_selective_disclosure_hides_only_selected_subject_claims() {
    let mut submitted = claims(CredentialPayloadFormat::W3cVcdmV2SdJwt);
    submitted.selective_disclosure_claims = vec!["given_name".into()];
    let prepared = prepare_sd_jwt(&signer(), &submitted).unwrap();
    let body = payload(&prepared);
    let subject = &body["credentialSubject"];
    assert!(subject.get("given_name").is_none());
    assert_eq!(subject["family_name"], "Smith");
    assert_eq!(subject["_sd"].as_array().unwrap().len(), 1);
    let entries = disclosures(&prepared);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].1[1], "given_name");
    assert_eq!(entries[0].1[2], "Alice");
}

#[test]
fn jwt_vc_payload_format_is_rejected_before_signing() {
    let submitted = claims(CredentialPayloadFormat::W3cVcdmV2JwtVc);
    assert!(prepare_sd_jwt(&signer(), &submitted).is_err());
    assert!(sign_sd_jwt_with_signer(&signer(), &submitted).is_err());
}

#[test]
fn metadata_only_signer_cannot_issue_a_credential() {
    let submitted = claims(CredentialPayloadFormat::IetfSdJwt);
    let error = match sign_sd_jwt_with_signer(&signer(), &submitted) {
        Ok(_) => panic!("metadata-only signer issued a credential"),
        Err(error) => error,
    };
    assert!(matches!(error, Oid4vciError::SigningError(_)));
}
