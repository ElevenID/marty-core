//! Prepared credential payloads borrow the exact bytes passed to a remote signer.
//! Positive signature assembly is covered by `remote_issuer_live_kms`.

use marty_oid4vci::{
    formats::{jwt_vc::prepare_jwt_vc, mdoc::prepare_mdoc},
    remote_credential::RemoteSignerMetadata,
    types::{CredentialClaims, CredentialPayloadFormat},
};

fn signer() -> RemoteSignerMetadata {
    RemoteSignerMetadata::new(
        "did:web:issuer.example",
        "did:web:issuer.example#key-1",
        "ES256",
        serde_json::json!({
            "alg": "ES256",
            "crv": "P-256",
            "kty": "EC",
            "x": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            "y": "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
        })
        .to_string(),
    )
    .unwrap()
}

fn jwt_vc_claims() -> CredentialClaims {
    CredentialClaims {
        credential_type: "EmployeeCredential".into(),
        claims: [
            ("employee_id".into(), serde_json::json!("employee-123")),
            ("given_name".into(), serde_json::json!("Alice")),
        ]
        .into(),
        subject_id: Some("did:example:holder".into()),
        expiration_seconds: Some(3_600),
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn mdoc_claims() -> CredentialClaims {
    CredentialClaims {
        credential_type: "org.iso.18013.5.1.mDL".into(),
        claims: [
            ("birth_date".into(), serde_json::json!("1990-01-15")),
            ("family_name".into(), serde_json::json!("Mustermann")),
            ("given_name".into(), serde_json::json!("Erika")),
        ]
        .into(),
        subject_id: Some("did:example:holder".into()),
        expiration_seconds: Some(86_400),
        credential_payload_format: CredentialPayloadFormat::default(),
        selective_disclosure_claims: vec![],
        mdoc_namespace: Some("org.iso.18013.5.1".into()),
        mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
        zk_predicate_claims: vec![],
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

#[test]
fn prepared_jwt_vc_borrows_the_existing_complete_signing_input() {
    let prepared = prepare_jwt_vc(&signer(), &jwt_vc_claims()).unwrap();

    assert_eq!(
        prepared.signing_payload(),
        prepared.signing_input().as_bytes()
    );
    assert_eq!(
        prepared.signing_payload().as_ptr(),
        prepared.signing_input().as_ptr(),
        "the accessor must borrow the existing signing input without copying"
    );
}

#[test]
fn prepared_mdoc_borrows_the_existing_complete_signing_input() {
    let prepared = prepare_mdoc(&signer(), &mdoc_claims()).unwrap();

    let first_pointer = prepared.signing_payload().as_ptr();
    let first_length = prepared.signing_payload().len();
    assert_ne!(first_length, 0);
    assert_eq!(
        (
            prepared.signing_payload().as_ptr(),
            prepared.signing_payload().len()
        ),
        (first_pointer, first_length),
        "the accessor must borrow the existing signing input without copying"
    );
}
