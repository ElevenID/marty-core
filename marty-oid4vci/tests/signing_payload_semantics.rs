//! Regression tests for the scalar credential-signing boundary.
//!
//! These fixtures use a deterministic test-only key in a recording signer.
//! That lets the tests lock the exact bytes crossing the signer boundary while
//! exercising the production rule that every returned signature must verify.

use std::sync::Mutex;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::{
        jwt_vc::{prepare_jwt_vc, sign_jwt_vc_with_signer},
        mdoc::{prepare_mdoc, sign_mdoc_with_signer},
    },
    signer::CredentialSigner,
    types::{CredentialClaims, CredentialPayloadFormat, SignedCredential, SigningAlgorithm},
    Oid4vciResult,
};

const REDACTED_SIGNER_DIAGNOSTIC: &str = "RecordingEs256Signer([redacted])";

struct RecordingEs256Signer {
    signing_payloads: Mutex<Vec<Vec<u8>>>,
    signatures: Mutex<Vec<Vec<u8>>>,
    signing_key: p256::ecdsa::SigningKey,
}

impl Default for RecordingEs256Signer {
    fn default() -> Self {
        let mut scalar = [0u8; 32];
        scalar[31] = 1;
        Self {
            signing_payloads: Mutex::new(Vec::new()),
            signatures: Mutex::new(Vec::new()),
            signing_key: p256::ecdsa::SigningKey::from_slice(&scalar).unwrap(),
        }
    }
}

impl std::fmt::Debug for RecordingEs256Signer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(REDACTED_SIGNER_DIAGNOSTIC)
    }
}

impl RecordingEs256Signer {
    fn only_signing_payload(&self) -> Vec<u8> {
        let signing_payloads = self.signing_payloads.lock().unwrap();
        assert_eq!(
            signing_payloads.len(),
            1,
            "the scalar credential route must invoke its signer exactly once"
        );
        signing_payloads[0].clone()
    }

    fn only_signature(&self) -> Vec<u8> {
        let signatures = self.signatures.lock().unwrap();
        assert_eq!(signatures.len(), 1);
        signatures[0].clone()
    }
}

impl CredentialSigner for RecordingEs256Signer {
    fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        use p256::ecdsa::signature::Signer as _;

        self.signing_payloads.lock().unwrap().push(message.to_vec());
        let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
        let signature = signature.to_bytes().to_vec();
        self.signatures.lock().unwrap().push(signature.clone());
        Ok(signature)
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }

    fn issuer_id(&self) -> &str {
        "did:example:scalar-signing-issuer"
    }

    fn kid_url(&self) -> String {
        "did:example:scalar-signing-issuer#key-1".into()
    }

    fn public_jwk(&self) -> Oid4vciResult<String> {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        Ok(serde_json::json!({
            "alg": "ES256",
            "crv": "P-256",
            "kty": "EC",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
        .to_string())
    }
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
fn scalar_es256_jwt_vc_signs_one_complete_payload_and_forwards_raw_signature() {
    let signer = RecordingEs256Signer::default();

    let credential = sign_jwt_vc_with_signer(&signer, &jwt_vc_claims()).unwrap();
    let signing_payload = signer.only_signing_payload();
    let signature = signer.only_signature();
    let signing_input = String::from_utf8(signing_payload.clone()).unwrap();

    let SignedCredential::JwtVcJson { jwt, credential_id } = credential else {
        panic!("expected a JWT-VC credential")
    };
    let segments: Vec<_> = jwt.split('.').collect();
    assert_eq!(
        segments.len(),
        3,
        "JWT compact serialization must have three parts"
    );
    assert_eq!(
        signing_input,
        format!("{}.{}", segments[0], segments[1]),
        "the signer must receive the complete compact header.payload"
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(segments[2]).unwrap(),
        signature,
        "JWT assembly must preserve the raw 64-byte ES256 signature"
    );

    assert!(credential_id.starts_with("urn:uuid:"));

    let diagnostic = format!("{signer:#?}");
    assert_eq!(diagnostic, REDACTED_SIGNER_DIAGNOSTIC);
    assert!(!diagnostic.contains(&String::from_utf8(signing_payload).unwrap()));
}

#[test]
fn scalar_es256_mdoc_signs_one_complete_payload_and_forwards_raw_signature() {
    let signer = RecordingEs256Signer::default();

    let credential = sign_mdoc_with_signer(&signer, &mdoc_claims()).unwrap();
    let signing_payload = signer.only_signing_payload();
    let signature = signer.only_signature();

    let SignedCredential::MsoMdoc {
        issuer_signed_b64,
        credential_id,
    } = credential
    else {
        panic!("expected an mdoc credential")
    };
    assert!(credential_id.starts_with("urn:uuid:"));
    let issuer_signed_bytes = URL_SAFE_NO_PAD.decode(issuer_signed_b64).unwrap();
    let issuer_signed: isomdl::definitions::IssuerSigned =
        isomdl::cbor::from_slice(&issuer_signed_bytes).unwrap();

    assert_eq!(
        issuer_signed.issuer_auth.tbs_data(&[]),
        signing_payload,
        "the signer must receive the complete COSE Sig_structure"
    );
    assert_eq!(
        issuer_signed.issuer_auth.signature, signature,
        "mdoc assembly must preserve the raw 64-byte ES256 signature"
    );

    let diagnostic = format!("{signer:#?}");
    assert_eq!(diagnostic, REDACTED_SIGNER_DIAGNOSTIC);
    assert!(!diagnostic.contains("Mustermann"));
}

#[test]
fn prepared_jwt_vc_borrows_the_existing_complete_signing_input() {
    let signer = RecordingEs256Signer::default();
    let prepared = prepare_jwt_vc(&signer, &jwt_vc_claims()).unwrap();

    assert_eq!(
        prepared.signing_payload(),
        prepared.signing_input().as_bytes()
    );
    assert_eq!(
        prepared.signing_payload().as_ptr(),
        prepared.signing_input().as_ptr(),
        "the accessor must borrow the existing signing input without copying"
    );
    assert!(signer.signing_payloads.lock().unwrap().is_empty());
}

#[test]
fn prepared_mdoc_borrows_the_existing_complete_signing_input() {
    let signer = RecordingEs256Signer::default();
    let prepared = prepare_mdoc(&signer, &mdoc_claims()).unwrap();

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
    assert!(signer.signing_payloads.lock().unwrap().is_empty());
}
