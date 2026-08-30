//! Regression tests for the scalar credential-signing boundary.
//!
//! These fixtures deliberately use a recording signer instead of key material.
//! That lets the tests lock the exact bytes crossing the signer boundary and
//! the raw-signature assembly contract independently of a crypto backend.

use std::sync::Mutex;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::{
        jwt_vc::{assemble_jwt_vc, sign_jwt_vc_with_signer, PreparedJwtVc},
        mdoc::sign_mdoc_with_signer,
    },
    signer::CredentialSigner,
    types::{CredentialClaims, CredentialPayloadFormat, SignedCredential, SigningAlgorithm},
    Oid4vciResult,
};

const REDACTED_SIGNER_DIAGNOSTIC: &str = "RecordingEs256Signer([redacted])";

// Patterned r || s bytes, including a leading zero, catch accidental DER
// conversion, normalization, truncation, or reordering during assembly.
const RAW_ES256_SIGNATURE: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

#[derive(Default)]
struct RecordingEs256Signer {
    signing_payloads: Mutex<Vec<Vec<u8>>>,
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
}

impl CredentialSigner for RecordingEs256Signer {
    fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        self.signing_payloads.lock().unwrap().push(message.to_vec());
        Ok(RAW_ES256_SIGNATURE.to_vec())
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
        RAW_ES256_SIGNATURE,
        "JWT assembly must preserve the raw 64-byte ES256 signature"
    );

    let expected = assemble_jwt_vc(
        PreparedJwtVc {
            signing_input,
            credential_id: credential_id.clone(),
        },
        &RAW_ES256_SIGNATURE,
    );
    let SignedCredential::JwtVcJson {
        jwt: expected_jwt,
        credential_id: expected_credential_id,
    } = expected
    else {
        unreachable!("assemble_jwt_vc always returns JWT-VC")
    };
    assert_eq!(jwt, expected_jwt);
    assert_eq!(credential_id, expected_credential_id);

    let diagnostic = format!("{signer:#?}");
    assert_eq!(diagnostic, REDACTED_SIGNER_DIAGNOSTIC);
    assert!(!diagnostic.contains(&String::from_utf8(signing_payload).unwrap()));
}

#[test]
fn scalar_es256_mdoc_signs_one_complete_payload_and_forwards_raw_signature() {
    let signer = RecordingEs256Signer::default();

    let credential = sign_mdoc_with_signer(&signer, &mdoc_claims()).unwrap();
    let signing_payload = signer.only_signing_payload();

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
        issuer_signed.issuer_auth.signature, RAW_ES256_SIGNATURE,
        "mdoc assembly must preserve the raw 64-byte ES256 signature"
    );

    let diagnostic = format!("{signer:#?}");
    assert_eq!(diagnostic, REDACTED_SIGNER_DIAGNOSTIC);
    assert!(!diagnostic.contains("Mustermann"));
}
