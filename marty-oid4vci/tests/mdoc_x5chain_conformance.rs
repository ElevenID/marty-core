use base64::Engine;
use ciborium::Value as CborValue;
use marty_oid4vci::{
    formats::mdoc::{assemble_mdoc, prepare_mdoc, sign_mdoc},
    signer::CredentialSigner,
    types::{CredentialClaims, IssuerKey, SignedCredential, SigningAlgorithm},
};

const COSE_HEADER_ALG: i64 = 1;
const COSE_HEADER_X5CHAIN: i64 = 33;
const MDOC_X5C_CLAIM_KEY: &str = "_mdoc_x5c";

fn issuer_key() -> IssuerKey {
    let jwk = ssi_jwk::JWK::generate_p256();
    IssuerKey {
        issuer_id: "did:example:issuer".into(),
        jwk_json: serde_json::to_string(&jwk).unwrap(),
        algorithm: SigningAlgorithm::ES256,
    }
}

fn claims(certificates: &[Vec<u8>]) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some("did:example:holder".into()),
        credential_type: "org.iso.18013.5.1.mDL".into(),
        claims: [
            ("family_name".into(), serde_json::json!("Mustermann")),
            (
                MDOC_X5C_CLAIM_KEY.into(),
                serde_json::Value::Array(
                    certificates
                        .iter()
                        .map(|certificate| {
                            serde_json::Value::String(
                                base64::engine::general_purpose::STANDARD.encode(certificate),
                            )
                        })
                        .collect(),
                ),
            ),
        ]
        .into(),
        expiration_seconds: Some(86400),
        selective_disclosure_claims: vec![],
        mdoc_namespace: Some("org.iso.18013.5.1".into()),
        mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
        zk_predicate_claims: vec![],
        credential_payload_format: Default::default(),
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn issuer_signed_bytes(credential: SignedCredential) -> Vec<u8> {
    let SignedCredential::MsoMdoc {
        issuer_signed_b64, ..
    } = credential
    else {
        panic!("expected mso_mdoc credential");
    };
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(issuer_signed_b64)
        .unwrap()
}

fn assert_iso_18013_x5chain_location(credential: SignedCredential, certificates: &[Vec<u8>]) {
    let bytes = issuer_signed_bytes(credential);
    let issuer_signed: CborValue = ciborium::from_reader(&bytes[..]).unwrap();
    let issuer_auth = match issuer_signed {
        CborValue::Map(entries) => entries
            .into_iter()
            .find_map(|(key, value)| (key == CborValue::Text("issuerAuth".into())).then_some(value))
            .expect("issuerAuth"),
        _ => panic!("IssuerSigned must be a map"),
    };
    let parts = match issuer_auth {
        CborValue::Array(parts) => parts,
        _ => panic!("issuerAuth must be a COSE_Sign1 array"),
    };

    let protected_bytes = match parts.first() {
        Some(CborValue::Bytes(bytes)) => bytes,
        _ => panic!("protected header must be a byte string"),
    };
    let protected: CborValue = ciborium::from_reader(&protected_bytes[..]).unwrap();
    let CborValue::Map(protected) = protected else {
        panic!("protected header must decode to a map");
    };
    assert!(protected.iter().any(|(key, value)| {
        key == &CborValue::Integer(COSE_HEADER_ALG.into())
            && value == &CborValue::Integer((-7).into())
    }));
    assert!(!protected
        .iter()
        .any(|(key, _)| key == &CborValue::Integer(COSE_HEADER_X5CHAIN.into())));

    let unprotected = match parts.get(1) {
        Some(CborValue::Map(headers)) => headers,
        _ => panic!("unprotected header must be a map"),
    };
    let x5chain = unprotected
        .iter()
        .find_map(|(key, value)| {
            (key == &CborValue::Integer(COSE_HEADER_X5CHAIN.into())).then_some(value)
        })
        .expect("x5chain must be unprotected");
    assert_eq!(
        x5chain,
        &CborValue::Array(
            certificates
                .iter()
                .map(|certificate| CborValue::Bytes(certificate.clone()))
                .collect()
        )
    );
}

#[test]
fn local_and_remote_signing_emit_iso_18013_x5chain() {
    let key = issuer_key();
    let certificates = vec![vec![0x30, 0x82, 0x01, 0x0a], vec![0x30, 0x82, 0x01, 0x0b]];
    let claims = claims(&certificates);

    assert_iso_18013_x5chain_location(sign_mdoc(&key, &claims).unwrap(), &certificates);

    let prepared = prepare_mdoc(&key, &claims).unwrap();
    let signature = key.sign(&prepared.tbs_data).unwrap();
    assert_iso_18013_x5chain_location(assemble_mdoc(prepared, &signature).unwrap(), &certificates);
}
