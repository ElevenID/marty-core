//! Marty-owned regressions for caller-authored SD-JWT structural markers.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::sd_jwt::{
        prepare_sd_jwt, prepare_sd_jwt_with_options, sign_sd_jwt, sign_sd_jwt_with_signer,
        PreparedSdJwt, SdJwtPreparationOptions,
    },
    remote_credential::{prepare_remote_sd_jwt, RemoteSdJwtRequest},
    signer::CredentialSigner,
    types::{CredentialClaims, CredentialPayloadFormat, IssuerKey, SigningAlgorithm},
    Oid4vciError, Oid4vciResult,
};
use ssi_jwk::JWK;

const RESERVED_STRUCTURE: &str = "SD-JWT claims contain reserved structural markers";
const STRUCTURAL_MARKERS: &[&str] = &["_sd", "_sd_alg", "..."];

#[derive(Default)]
struct SignerSpy {
    calls: AtomicUsize,
}

impl std::fmt::Debug for SignerSpy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StructuralSignerSpy([redacted])")
    }
}

impl CredentialSigner for SignerSpy {
    fn sign(&self, _message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(vec![0x3c; 64])
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::ES256
    }

    fn issuer_id(&self) -> &str {
        "did:example:structural-test-issuer"
    }

    fn kid_url(&self) -> String {
        "did:example:structural-test-issuer#key-1".into()
    }
}

fn test_key() -> IssuerKey {
    let jwk = JWK::generate_p256();
    let jwk_json = serde_json::to_string(&jwk).unwrap();
    IssuerKey {
        issuer_id: format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(jwk_json.as_bytes())),
        jwk_json,
        algorithm: SigningAlgorithm::ES256,
    }
}

fn claims(format: CredentialPayloadFormat) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some("did:example:canonical-holder".into()),
        credential_type: "https://credentials.example/StructuralBoundary".into(),
        claims: HashMap::from([(
            "name".into(),
            serde_json::json!("Sensitive structural sentinel"),
        )]),
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

fn payload(prepared: &PreparedSdJwt) -> serde_json::Value {
    let segment = prepared.signing_input.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).unwrap()).unwrap()
}

fn assert_structural_error<T>(result: Oid4vciResult<T>) {
    let error = match result {
        Ok(_) => panic!("caller-authored SD-JWT structure must be rejected"),
        Err(error) => error,
    };
    let Oid4vciError::SdJwtError(message) = error else {
        panic!("structural failures must use the SD-JWT error boundary")
    };
    assert_eq!(message, RESERVED_STRUCTURE);
    assert!(!message.contains("Sensitive structural sentinel"));
    assert!(!message.contains("Sensitive forged structure"));
    assert!(!message.contains("Sensitive private key sentinel"));
}

fn assert_direct_rejection(key: &IssuerKey, spy: &SignerSpy, submitted: &CredentialClaims) {
    assert_structural_error(sign_sd_jwt(key, submitted));
    assert_structural_error(prepare_sd_jwt(spy, submitted));
    assert_structural_error(sign_sd_jwt_with_signer(spy, submitted));
}

fn remote_request() -> RemoteSdJwtRequest {
    RemoteSdJwtRequest {
        issuer_id: "did:web:issuer.example".into(),
        verification_method_id: "did:web:issuer.example#key-1".into(),
        algorithm: "ES256".into(),
        subject_id: Some("did:example:canonical-holder".into()),
        credential_type: "https://credentials.example/StructuralBoundary".into(),
        claims: HashMap::from([(
            "name".into(),
            serde_json::json!("Sensitive structural sentinel"),
        )]),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec![],
        credential_format: Some("dc+sd-jwt".into()),
        credential_id: Some("urn:uuid:00000000-0000-0000-0000-000000000321".into()),
        holder_jwk: Some(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "public-x",
            "y": "public-y",
            "d": "Sensitive private key sentinel"
        })),
        issuer_certificate_chain: vec![],
    }
}

#[test]
fn direct_boundaries_reject_each_marker_as_a_raw_or_nested_object_key_before_signing() {
    let key = test_key();
    let spy = SignerSpy::default();

    for format in [
        CredentialPayloadFormat::IetfSdJwt,
        CredentialPayloadFormat::W3cVcdmV2SdJwt,
    ] {
        for marker in STRUCTURAL_MARKERS {
            let mut top_level = claims(format.clone());
            top_level.claims.insert(
                (*marker).into(),
                serde_json::json!("Sensitive forged structure"),
            );
            assert_direct_rejection(&key, &spy, &top_level);

            let mut member = serde_json::Map::new();
            member.insert(
                (*marker).into(),
                serde_json::json!("Sensitive forged structure"),
            );
            let mut nested = claims(format.clone());
            nested.claims.insert(
                "profile".into(),
                serde_json::json!({
                    "extensions": [
                        {"ordinary": true},
                        [serde_json::Value::Object(member)]
                    ]
                }),
            );
            assert_direct_rejection(&key, &spy, &nested);
        }
    }

    assert_eq!(
        spy.calls.load(Ordering::Relaxed),
        0,
        "structural validation must precede every external signer call"
    );
}

#[test]
fn selectors_and_confirmation_reject_each_structural_marker_in_both_payload_modes() {
    let key = test_key();
    let spy = SignerSpy::default();

    for format in [
        CredentialPayloadFormat::IetfSdJwt,
        CredentialPayloadFormat::W3cVcdmV2SdJwt,
    ] {
        for marker in STRUCTURAL_MARKERS {
            let mut selected = claims(format.clone());
            selected.selective_disclosure_claims = vec![(*marker).into()];
            assert_direct_rejection(&key, &spy, &selected);

            let mut member = serde_json::Map::new();
            member.insert(
                (*marker).into(),
                serde_json::json!("Sensitive forged structure"),
            );
            let confirmation = serde_json::json!({
                "jwk": {
                    "extensions": [[serde_json::Value::Object(member)]]
                }
            });
            assert_structural_error(prepare_sd_jwt_with_options(
                &spy,
                &claims(format.clone()),
                SdJwtPreparationOptions {
                    confirmation: Some(confirmation),
                    ..SdJwtPreparationOptions::default()
                },
            ));
        }
    }

    assert_eq!(spy.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn matching_is_exact_and_marker_strings_are_ordinary_values() {
    for format in [
        CredentialPayloadFormat::IetfSdJwt,
        CredentialPayloadFormat::W3cVcdmV2SdJwt,
    ] {
        let mut submitted = claims(format);
        submitted.claims = HashMap::from([
            (
                "_SD".into(),
                serde_json::json!({"_sd_": ["_sd", "_sd_alg", "..."]}),
            ),
            (
                "_sd_alg_extra".into(),
                serde_json::json!({"ordinary": "..."}),
            ),
            ("....".into(), serde_json::json!("_sd")),
        ]);
        submitted.selective_disclosure_claims = vec!["_SD".into()];

        let prepared = prepare_sd_jwt_with_options(
            &SignerSpy::default(),
            &submitted,
            SdJwtPreparationOptions {
                confirmation: Some(serde_json::json!({
                    "display": {
                        "_SD": "_sd",
                        "_sd_alg_extra": "_sd_alg",
                        "....": "..."
                    }
                })),
                ..SdJwtPreparationOptions::default()
            },
        )
        .unwrap();
        assert_ne!(prepared.disclosures_suffix, "~");
    }
}

#[test]
fn issuer_generated_digest_markers_remain_available_after_input_validation() {
    for format in [
        CredentialPayloadFormat::IetfSdJwt,
        CredentialPayloadFormat::W3cVcdmV2SdJwt,
    ] {
        let mut submitted = claims(format.clone());
        submitted.selective_disclosure_claims = vec!["name".into()];
        let prepared = prepare_sd_jwt(&SignerSpy::default(), &submitted).unwrap();
        let payload = payload(&prepared);
        assert_eq!(payload["_sd_alg"], "sha-256");
        match format {
            CredentialPayloadFormat::IetfSdJwt => assert!(payload["_sd"].is_array()),
            CredentialPayloadFormat::W3cVcdmV2SdJwt => {
                assert!(payload["credentialSubject"]["_sd"].is_array())
            }
            CredentialPayloadFormat::W3cVcdmV2JwtVc => unreachable!(),
        }
    }
}

#[test]
fn remote_preparation_rejects_markers_in_claims_selectors_and_holder_confirmation() {
    for marker in STRUCTURAL_MARKERS {
        let mut member = serde_json::Map::new();
        member.insert(
            (*marker).into(),
            serde_json::json!("Sensitive forged structure"),
        );

        let mut nested_claim = remote_request();
        nested_claim.claims.insert(
            "profile".into(),
            serde_json::json!({"extensions": [serde_json::Value::Object(member.clone())]}),
        );
        assert_structural_error(prepare_remote_sd_jwt(nested_claim));

        let mut selected = remote_request();
        selected.selective_disclosure_claims = vec![(*marker).into()];
        assert_structural_error(prepare_remote_sd_jwt(selected));

        let mut holder = remote_request();
        holder.holder_jwk = Some(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "public-x",
            "y": "public-y",
            "d": "Sensitive private key sentinel",
            "extensions": [[serde_json::Value::Object(member)]]
        }));
        assert_structural_error(prepare_remote_sd_jwt(holder));
    }
}

#[test]
fn unsupported_plain_jwt_format_keeps_its_existing_error_precedence() {
    let mut submitted = claims(CredentialPayloadFormat::W3cVcdmV2JwtVc);
    submitted.claims.insert(
        "_sd".into(),
        serde_json::json!("Sensitive forged structure"),
    );

    let prepared_error = match prepare_sd_jwt(&SignerSpy::default(), &submitted) {
        Ok(_) => panic!("plain JWT payload format must not pass SD-JWT preparation"),
        Err(error) => error,
    };
    for error in [
        sign_sd_jwt(&test_key(), &submitted).unwrap_err(),
        prepared_error,
    ] {
        let Oid4vciError::UnsupportedFormat(message) = error else {
            panic!("the payload-format boundary must remain authoritative")
        };
        assert!(message.contains("w3c_vcdm_v2_jwt_vc"));
        assert!(!message.contains("Sensitive forged structure"));
    }
}
