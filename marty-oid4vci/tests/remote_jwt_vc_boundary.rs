//! Public-key-only JWT-VC preparation and signature acceptance boundaries.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::{jwt_vc::assemble_jwt_vc, sign_credential_with_signer},
    remote_credential::{prepare_remote_jwt_vc, RemoteJwtVcRequest, RemoteSignerMetadata},
    signing_batch::{
        Es256SignerScope, JwtVcSigningBatchInput, SigningBatchErrorKind, SigningRouteId,
    },
    types::{CredentialClaims, CredentialFormat, CredentialPayloadFormat},
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

fn open_badge_request() -> RemoteJwtVcRequest {
    let mut request = request();
    request.credential_type = "OpenBadgeCredential".into();
    request.credential_profile = Some("open_badge_v3".into());
    request.achievement_id = Some("https://issuer.example/achievements/course".into());
    request.claims = HashMap::from([
        (
            "achievement_name".into(),
            json!("Workplace Safety Foundations"),
        ),
        (
            "achievement_description".into(),
            json!("Completed the workplace safety workshop"),
        ),
        (
            "achievement_criteria".into(),
            json!({"narrative": "Complete the workshop and score at least 80%"}),
        ),
    ]);
    request
}

#[test]
fn remote_open_badge_preserves_required_id_and_criteria_in_signed_credential() {
    let prepared = prepare_remote_jwt_vc(open_badge_request()).unwrap();
    let payload = segment(prepared.signing_input(), 1);
    assert_eq!(payload["vc"]["id"], CREDENTIAL_ID);
    assert_eq!(payload["vc"]["id"], payload["jti"]);
    assert_eq!(
        payload["vc"]["credentialSubject"]["achievement"]["criteria"],
        json!({"narrative": "Complete the workshop and score at least 80%"})
    );
    marty_oid4vci::formats::jwt_vc::validate_open_badge_v3_profile(&payload["vc"]).unwrap();

    // The OB3 profile owns this requirement; generic remote JWT-VC callers
    // retain their existing representation contract.
    let generic = prepare_remote_jwt_vc(request()).unwrap();
    assert!(segment(generic.signing_input(), 1)["vc"]
        .get("id")
        .is_none());
}

#[test]
fn direct_profile_preparation_preserves_complete_content_and_independent_times() {
    use marty_oid4vci::{JwtVcPreparationProfile, JwtVcProfileTiming, JwtVcSecuringProfile};
    let from = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00.125Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let until = chrono::DateTime::parse_from_rfc3339("2040-01-01T00:00:00.125Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let timing = JwtVcProfileTiming::new(1_700_000_000, 1_700_003_600, from, Some(until)).unwrap();
    let mut request = open_badge_request();
    request.expiration_seconds = None;
    let prepared = marty_oid4vci::remote_credential::prepare_remote_jwt_vc_with_profile(
        request,
        JwtVcPreparationProfile::DirectVc2Jose(timing),
    )
    .unwrap();
    assert_eq!(
        prepared.binding().securing_profile(),
        JwtVcSecuringProfile::W3cVc2Jose2026V1
    );
    assert_eq!(prepared.binding().credential_format(), "application/vc+jwt");
    let header = segment(prepared.signing_input(), 0);
    let payload = segment(prepared.signing_input(), 1);
    assert_eq!(header["typ"], "vc+jwt");
    assert_eq!(header["cty"], "vc");
    for absent in ["vc", "vp", "nbf", "issuanceDate", "expirationDate"] {
        assert!(payload.get(absent).is_none(), "{absent}");
    }
    assert_eq!(payload["id"], CREDENTIAL_ID);
    assert_eq!(payload["jti"], payload["id"]);
    assert_eq!(payload["iss"], payload["issuer"]);
    assert_eq!(payload["sub"], payload["credentialSubject"]["id"]);
    assert_eq!(payload["iat"], timing.signature_issued_at());
    assert_eq!(payload["exp"], timing.signature_expires_at());
    assert_eq!(payload["validFrom"], "2020-01-01T00:00:00.125Z");
    assert_eq!(payload["validUntil"], "2040-01-01T00:00:00.125Z");
    marty_oid4vci::formats::jwt_vc::validate_open_badge_v3_profile(&payload).unwrap();
    assert!(!format!("{prepared:?}").contains("Workplace Safety"));
    assert!(prepared.complete(&[0; 64]).is_err());
}

#[test]
fn direct_profile_refuses_ambiguous_time_options_and_invalid_content_before_signing() {
    use marty_oid4vci::{JwtVcPreparationProfile, JwtVcProfileTiming};
    let from = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let profile = JwtVcPreparationProfile::DirectVc2Jose(
        JwtVcProfileTiming::new(1_700_000_000, 1_700_003_600, from, None).unwrap(),
    );
    // Existing expiration_seconds must not silently mean two different things.
    assert!(
        marty_oid4vci::remote_credential::prepare_remote_jwt_vc_with_profile(
            open_badge_request(),
            profile
        )
        .is_err()
    );
    let mut invalid = open_badge_request();
    invalid.expiration_seconds = None;
    invalid.claims.remove("achievement_criteria");
    assert!(
        marty_oid4vci::remote_credential::prepare_remote_jwt_vc_with_profile(invalid, profile)
            .is_err()
    );
    for subject in [
        "not-an-absolute-identifier",
        "did:exam\nple:holder",
        "https://issuer.example/a\tb",
        "urn:credential:has space",
        "https://issuer.example/a\\b",
        "https://issuer.example/a\"b",
        "urn:credential:<bad>",
        "urn:credential:%zz",
        "urn:credential:trailing%",
        "urn:credential:short%2",
        "urn:credential:[bad]",
        "urn:credential:caf\u{e9}",
    ] {
        let mut invalid = request();
        invalid.expiration_seconds = None;
        invalid.subject_id = Some(subject.into());
        assert!(
            marty_oid4vci::remote_credential::prepare_remote_jwt_vc_with_profile(invalid, profile)
                .is_err()
        );
    }
    for subject in [
        "did:example:Holder",
        "https://Issuer.Example/CaseSensitive",
        "https://issuer.example/a%20b",
        "urn:credential:escaped%3Cvalue%3E",
    ] {
        let mut valid = request();
        valid.expiration_seconds = None;
        valid.subject_id = Some(subject.into());
        let prepared =
            marty_oid4vci::remote_credential::prepare_remote_jwt_vc_with_profile(valid, profile)
                .unwrap();
        let payload = segment(prepared.signing_input(), 1);
        assert_eq!(payload["sub"], subject);
        assert_eq!(payload["credentialSubject"]["id"], subject);
    }
}

#[test]
fn direct_formatter_rejects_conflicting_subject_alias_before_signing() {
    use marty_oid4vci::formats::jwt_vc::{prepare_jwt_vc_with_profile, JwtVcPreparationOptions};
    use marty_oid4vci::{JwtVcPreparationProfile, JwtVcProfileTiming};
    let request = request();
    let signer = RemoteSignerMetadata::new(
        &request.issuer_id,
        &request.verification_method_id,
        &request.algorithm,
        request.issuer_public_jwk,
    )
    .unwrap();
    let claims = CredentialClaims {
        subject_id: request.subject_id,
        credential_type: request.credential_type,
        claims: HashMap::new(),
        expiration_seconds: None,
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
        w3c_context: vec![],
        w3c_types: vec![],
    };
    // A future credential start is valid preparation input; admission checks
    // its aliases without conflating issuance with verifier evaluation time.
    let timing = JwtVcProfileTiming::new(
        1_700_000_000,
        1_700_003_600,
        chrono::DateTime::from_timestamp(1_700_000_100, 0).unwrap(),
        None,
    )
    .unwrap();
    let profile = JwtVcPreparationProfile::DirectVc2Jose(timing);
    let options = JwtVcPreparationOptions {
        credential_subject: Some(json!({"id":"did:example:other"})),
        ..Default::default()
    };
    let error = prepare_jwt_vc_with_profile(&signer, &claims, options, profile).unwrap_err();
    assert!(error.to_string().contains("subject conflicts"));

    let options = JwtVcPreparationOptions {
        credential_subject: Some(json!({"id":"did:example:holder"})),
        ..Default::default()
    };
    let prepared = prepare_jwt_vc_with_profile(&signer, &claims, options, profile).unwrap();
    let payload = segment(prepared.signing_input(), 1);
    assert_eq!(payload["sub"], payload["credentialSubject"]["id"]);
}

#[test]
fn explicit_historical_profile_retains_nested_remote_wire_contract() {
    use marty_oid4vci::{JwtVcPreparationProfile, JwtVcSecuringProfile};
    let prepared = marty_oid4vci::remote_credential::prepare_remote_jwt_vc_with_profile(
        request(),
        JwtVcPreparationProfile::HistoricalNested,
    )
    .unwrap();
    let payload = segment(prepared.signing_input(), 1);
    assert_eq!(
        prepared.binding().securing_profile(),
        JwtVcSecuringProfile::MartyNestedVc2JwtV1
    );
    assert_eq!(prepared.binding().credential_format(), "jwt_vc_json");
    assert!(payload["vc"].is_object());
    assert!(payload["vc"].get("id").is_none());
    assert!(payload.get("@context").is_none());
    assert_eq!(
        payload["exp"].as_i64().unwrap() - payload["iat"].as_i64().unwrap(),
        3600
    );
    assert!(payload["nbf"].is_number());
    assert!(segment(prepared.signing_input(), 0).get("cty").is_none());
}

#[test]
fn remote_open_badge_rejects_missing_or_non_object_criteria_before_signing() {
    for criteria in [
        None,
        Some(json!(null)),
        Some(json!("Complete the course")),
        Some(json!([])),
        Some(json!(42)),
    ] {
        for explicit_subject in [false, true] {
            let mut request = open_badge_request();
            request.claims.remove("achievement_criteria");
            if explicit_subject {
                request.claims.clear();
                let mut achievement = json!({
                    "name": "Workplace Safety Foundations",
                    "description": "Completed the workplace safety workshop"
                });
                if let Some(criteria) = criteria.as_ref() {
                    achievement["criteria"] = criteria.clone();
                }
                request.credential_subject = Some(json!({"achievement": achievement}));
            } else if let Some(criteria) = criteria.as_ref() {
                request
                    .claims
                    .insert("achievement_criteria".into(), criteria.clone());
            }
            let error = prepare_remote_jwt_vc(request)
                .err()
                .expect("invalid criteria must not produce signing input");
            assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
            assert!(
                error.to_string().contains("achievement criteria"),
                "{error}"
            );
        }
    }
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

#[test]
fn remote_preparation_rejects_private_or_mismatched_issuer_key_metadata() {
    let baseline = request();
    let public_key: Value = serde_json::from_str(&baseline.issuer_public_jwk).unwrap();
    let cases = [
        ("algorithm", "EdDSA", public_key.clone()),
        (
            "declared algorithm",
            "ES256",
            json!({"kty":"EC","crv":"P-256","alg":"EdDSA",
                "x":public_key["x"],"y":public_key["y"]}),
        ),
        (
            "curve",
            "ES256",
            json!({"kty":"EC","crv":"P-384","alg":"ES256",
                "x":public_key["x"],"y":public_key["y"]}),
        ),
        (
            "private member",
            "ES256",
            json!({"kty":"EC","crv":"P-256","alg":"ES256",
                "x":public_key["x"],"y":public_key["y"],"d":"private-sentinel"}),
        ),
        (
            "key ID",
            "ES256",
            json!({"kty":"EC","crv":"P-256","alg":"ES256",
                "x":public_key["x"],"y":public_key["y"],"kid":"did:web:other.example#key-1"}),
        ),
    ];
    for (case, algorithm, jwk) in cases {
        let mut submitted = baseline.clone();
        submitted.algorithm = algorithm.into();
        submitted.issuer_public_jwk = jwk.to_string();
        let error = match prepare_remote_jwt_vc(submitted) {
            Ok(_) => panic!("{case}: unsafe issuer key metadata was accepted"),
            Err(error) => error,
        };
        assert!(
            matches!(error, Oid4vciError::KeyError(_)),
            "{case}: {error}"
        );
        assert!(!error.to_string().contains("private-sentinel"));
    }
}

#[test]
fn remote_format_routes_reject_mismatched_public_key_without_signing() {
    let signer = RemoteSignerMetadata::new(
        "did:web:issuer.example",
        "did:web:issuer.example#key-1",
        "EdDSA",
        request().issuer_public_jwk,
    )
    .unwrap();
    for (format, payload_format) in [
        (
            CredentialFormat::JwtVcJson,
            CredentialPayloadFormat::W3cVcdmV2JwtVc,
        ),
        (CredentialFormat::SdJwt, CredentialPayloadFormat::IetfSdJwt),
        (
            CredentialFormat::MsoMdoc,
            CredentialPayloadFormat::default(),
        ),
    ] {
        let claims = CredentialClaims {
            subject_id: Some("did:example:holder".into()),
            credential_type: "org.iso.18013.5.1.mDL".into(),
            claims: HashMap::from([("given_name".into(), json!("Alice"))]),
            expiration_seconds: Some(3_600),
            selective_disclosure_claims: vec![],
            mdoc_namespace: Some("org.iso.18013.5.1".into()),
            mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
            zk_predicate_claims: vec![],
            credential_payload_format: payload_format,
            w3c_context: vec![],
            w3c_types: vec![],
        };
        let error = match sign_credential_with_signer(&format, &signer, &claims) {
            Ok(_) => panic!("{format:?}: mismatched public key was accepted"),
            Err(error) => error,
        };
        assert!(
            matches!(error, Oid4vciError::KeyError(_)),
            "{format:?}: {error}"
        );
    }
}

#[test]
fn remote_batch_rejects_first_mismatched_key_without_partial_credentials() {
    let mut public_jwk: Value = serde_json::from_str(&request().issuer_public_jwk).unwrap();
    public_jwk["alg"] = json!("EdDSA");
    let signer = RemoteSignerMetadata::new(
        "did:web:issuer.example",
        "did:web:issuer.example#key-1",
        "ES256",
        public_jwk.to_string(),
    )
    .unwrap();
    let scope = Es256SignerScope::new(&signer).unwrap();
    let claims = CredentialClaims {
        subject_id: Some("did:example:holder".into()),
        credential_type: "EmployeeCredential".into(),
        claims: HashMap::from([("given_name".into(), json!("Alice"))]),
        expiration_seconds: Some(3_600),
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::W3cVcdmV2JwtVc,
        w3c_context: vec![],
        w3c_types: vec![],
    };
    let inputs = vec![
        JwtVcSigningBatchInput::new(SigningRouteId::new(1), claims.clone()).into(),
        JwtVcSigningBatchInput::new(SigningRouteId::new(2), claims).into(),
    ];
    let error = scope.sign_batch(inputs).unwrap_err();
    assert_eq!(error.kind(), SigningBatchErrorKind::PreparationFailed);
    assert_eq!(error.item_ordinal(), Some(0));
}
