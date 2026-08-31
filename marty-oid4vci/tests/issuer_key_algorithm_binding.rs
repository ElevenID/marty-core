//! Marty-owned regressions for binding local issuer-key metadata to JWK structure.

use std::collections::HashMap;

#[cfg(feature = "zk_mdoc")]
use marty_oid4vci::types::ZkPredicateBinding;
use marty_oid4vci::{
    formats::{self, jwt_vc::sign_jwt_vc},
    issuer::detect_algorithm,
    signer::CredentialSigner,
    signing_batch::{
        Es256SignerScope, JwtVcSigningBatchInput, SigningBatchErrorKind, SigningRouteId,
    },
    types::{
        CredentialClaims, CredentialFormat, CredentialPayloadFormat, IssuerKey, SigningAlgorithm,
    },
    Oid4vciError, Oid4vciResult,
};
use serde_json::{json, Value};
use ssi_jwk::{Algorithm, JWK};

const MESSAGE: &[u8] = b"issuer-key-algorithm-binding-regression";

fn issuer_key(jwk: &JWK, algorithm: SigningAlgorithm) -> IssuerKey {
    IssuerKey {
        issuer_id: "did:example:issuer-key-binding".into(),
        jwk_json: serde_json::to_string(jwk).unwrap(),
        algorithm,
    }
}

fn issuer_key_from_value(jwk: Value, algorithm: SigningAlgorithm) -> IssuerKey {
    IssuerKey {
        issuer_id: "did:example:issuer-key-binding".into(),
        jwk_json: serde_json::to_string(&jwk).unwrap(),
        algorithm,
    }
}

fn assert_key_error_without_private_material<T>(
    result: Oid4vciResult<T>,
    jwk_json: &str,
) -> Oid4vciError {
    let error = match result {
        Ok(_) => panic!("a contradictory issuer key must not produce output"),
        Err(error) => error,
    };
    assert!(matches!(error, Oid4vciError::KeyError(_)), "{error}");
    let diagnostic = error.to_string();
    assert!(!diagnostic.contains(jwk_json));
    let value: Value = serde_json::from_str(jwk_json).unwrap();
    for member in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        if let Some(secret) = value.get(member).and_then(Value::as_str) {
            assert!(!diagnostic.contains(secret), "error exposed JWK {member}");
        }
    }
    error
}

fn base_claims(payload_format: CredentialPayloadFormat) -> CredentialClaims {
    CredentialClaims {
        subject_id: Some("did:example:holder".into()),
        credential_type: "TestCredential".into(),
        claims: [("given_name".into(), json!("Alice"))].into(),
        expiration_seconds: Some(3600),
        selective_disclosure_claims: vec![],
        mdoc_namespace: Some("org.iso.18013.5.1".into()),
        mdoc_doctype: Some("org.iso.18013.5.1.mDL".into()),
        zk_predicate_claims: vec![],
        credential_payload_format: payload_format,
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

fn jwt_claims(label: &str) -> CredentialClaims {
    let mut claims = base_claims(CredentialPayloadFormat::W3cVcdmV2JwtVc);
    claims.claims.insert("label".into(), json!(label));
    claims
}

fn vds_claims() -> CredentialClaims {
    let claims: HashMap<String, Value> = serde_json::from_value(json!({
        "docType": "CMC", "issuingCountry": "AUS", "documentNumber": "X123456",
        "surname": "EXAMPLE", "givenNames": "ADA", "dateOfBirth": "19900102",
        "nationality": "AUS", "gender": "F", "dateOfIssue": "20260101",
        "dateOfExpiry": "20300101"
    }))
    .unwrap();
    CredentialClaims {
        subject_id: None,
        credential_type: "CMC".into(),
        claims,
        expiration_seconds: None,
        selective_disclosure_claims: vec![],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: vec![],
        credential_payload_format: CredentialPayloadFormat::default(),
        w3c_context: vec![],
        w3c_types: vec![],
    }
}

#[test]
fn raw_issuer_signer_accepts_only_three_structurally_matching_hints() {
    let families = [
        ("P-256", JWK::generate_p256(), SigningAlgorithm::ES256),
        (
            "Ed25519",
            JWK::generate_ed25519().unwrap(),
            SigningAlgorithm::EdDSA,
        ),
        (
            "secp256k1",
            JWK::generate_secp256k1(),
            SigningAlgorithm::ES256K,
        ),
    ];
    let hints = [
        SigningAlgorithm::ES256,
        SigningAlgorithm::EdDSA,
        SigningAlgorithm::ES256K,
        SigningAlgorithm::ES384,
        SigningAlgorithm::RS256,
    ];
    let (mut successes, mut rejections) = (0, 0);
    for (family, jwk, expected) in families {
        for hint in hints {
            let key = issuer_key(&jwk, hint);
            let result = key.sign(MESSAGE);
            if hint == expected {
                let signature = result.unwrap_or_else(|error| {
                    panic!("{family}/{hint} must sign successfully: {error}")
                });
                assert!(!signature.is_empty());
                successes += 1;
            } else {
                assert_key_error_without_private_material(result, &key.jwk_json);
                rejections += 1;
            }
        }
    }
    assert_eq!((successes, rejections), (3, 12));
}

#[test]
fn raw_issuer_signer_requires_embedded_alg_and_exact_okp_curve() {
    for (mut jwk, embedded, configured) in [
        (
            JWK::generate_p256(),
            Algorithm::ES256,
            SigningAlgorithm::ES256,
        ),
        (
            JWK::generate_ed25519().unwrap(),
            Algorithm::EdDSA,
            SigningAlgorithm::EdDSA,
        ),
        (
            JWK::generate_secp256k1(),
            Algorithm::ES256K,
            SigningAlgorithm::ES256K,
        ),
    ] {
        jwk.algorithm = Some(embedded);
        assert!(!issuer_key(&jwk, configured)
            .sign(MESSAGE)
            .unwrap()
            .is_empty());
    }

    for (mut jwk, embedded, configured) in [
        (
            JWK::generate_p256(),
            Algorithm::EdDSA,
            SigningAlgorithm::ES256,
        ),
        (
            JWK::generate_ed25519().unwrap(),
            Algorithm::ES256,
            SigningAlgorithm::EdDSA,
        ),
        (
            JWK::generate_secp256k1(),
            Algorithm::ES256,
            SigningAlgorithm::ES256K,
        ),
    ] {
        jwk.algorithm = Some(embedded);
        let key = issuer_key(&jwk, configured);
        assert_key_error_without_private_material(key.sign(MESSAGE), &key.jwk_json);
    }

    for curve in ["X25519", "Ed448"] {
        let mut value = serde_json::to_value(JWK::generate_ed25519().unwrap()).unwrap();
        value["crv"] = json!(curve);
        value["alg"] = json!("EdDSA");
        let key = issuer_key_from_value(value, SigningAlgorithm::EdDSA);
        assert_key_error_without_private_material(key.sign(MESSAGE), &key.jwk_json);
    }
}

#[test]
fn detector_derives_structure_before_treating_alg_as_an_assertion() {
    for (mut jwk, embedded, expected) in [
        (
            JWK::generate_p256(),
            Algorithm::ES256,
            SigningAlgorithm::ES256,
        ),
        (
            JWK::generate_ed25519().unwrap(),
            Algorithm::EdDSA,
            SigningAlgorithm::EdDSA,
        ),
        (
            JWK::generate_secp256k1(),
            Algorithm::ES256K,
            SigningAlgorithm::ES256K,
        ),
        (
            JWK::generate_p384(),
            Algorithm::ES384,
            SigningAlgorithm::ES384,
        ),
    ] {
        assert_eq!(
            detect_algorithm(&serde_json::to_string(&jwk).unwrap()).unwrap(),
            expected
        );
        jwk.algorithm = Some(embedded);
        assert_eq!(
            detect_algorithm(&serde_json::to_string(&jwk).unwrap()).unwrap(),
            expected
        );
    }

    for rsa in [
        json!({"kty": "RSA", "n": "AQ", "e": "AQAB"}),
        json!({"kty": "RSA", "n": "AQ", "e": "AQAB", "alg": "RS256"}),
    ] {
        assert_eq!(
            detect_algorithm(&rsa.to_string()).unwrap(),
            SigningAlgorithm::RS256
        );
    }

    for (mut jwk, contradictory) in [
        (JWK::generate_p256(), Algorithm::EdDSA),
        (JWK::generate_ed25519().unwrap(), Algorithm::ES256),
        (JWK::generate_secp256k1(), Algorithm::ES256),
        (JWK::generate_p384(), Algorithm::ES256),
    ] {
        jwk.algorithm = Some(contradictory);
        assert!(matches!(
            detect_algorithm(&serde_json::to_string(&jwk).unwrap()),
            Err(Oid4vciError::KeyError(_))
        ));
    }
    assert!(matches!(
        detect_algorithm(
            &json!({"kty": "RSA", "n": "AQ", "e": "AQAB", "alg": "ES256"}).to_string()
        ),
        Err(Oid4vciError::KeyError(_))
    ));
    assert!(matches!(
        detect_algorithm(
            &json!({
                "kty": "OKP", "crv": "X25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", "alg": "EdDSA"
            })
            .to_string()
        ),
        Err(Oid4vciError::KeyError(_))
    ));
}

#[test]
fn detected_p384_and_rsa_retain_their_existing_later_signing_rejections() {
    let mut p384 = JWK::generate_p384();
    p384.algorithm = Some(Algorithm::ES384);
    let p384_key = issuer_key(&p384, SigningAlgorithm::ES384);
    let p384_error =
        assert_key_error_without_private_material(p384_key.sign(MESSAGE), &p384_key.jwk_json);
    assert!(p384_error.to_string().contains("Unsupported EC curve"));

    let rsa_key = issuer_key_from_value(
        json!({
            "kty": "RSA", "n": "AQ", "e": "AQAB", "d": "Ag",
            "alg": "RS256"
        }),
        SigningAlgorithm::RS256,
    );
    let rsa_error =
        assert_key_error_without_private_material(rsa_key.sign(MESSAGE), &rsa_key.jwk_json);
    assert!(rsa_error
        .to_string()
        .contains("Unsupported key type for signing"));
}

#[test]
fn direct_jwt_vc_rejects_mismatch_but_preserves_claim_error_precedence() {
    let key = issuer_key(&JWK::generate_p256(), SigningAlgorithm::EdDSA);
    let claims = jwt_claims("direct");
    assert_key_error_without_private_material(sign_jwt_vc(&key, &claims), &key.jwk_json);

    let mut labeled_jwk = JWK::generate_p256();
    labeled_jwk.algorithm = Some(Algorithm::EdDSA);
    let labeled_key = issuer_key(&labeled_jwk, SigningAlgorithm::ES256);
    assert_key_error_without_private_material(
        sign_jwt_vc(&labeled_key, &claims),
        &labeled_key.jwk_json,
    );

    let mut invalid_claims = claims;
    invalid_claims.expiration_seconds = Some(i64::MAX);
    assert!(matches!(
        sign_jwt_vc(&key, &invalid_claims),
        Err(Oid4vciError::SigningError(_))
    ));
}

#[test]
fn combined_signer_routes_reject_mismatch_without_credentials() {
    let key = issuer_key(&JWK::generate_p256(), SigningAlgorithm::EdDSA);
    let routes = [
        (CredentialFormat::JwtVcJson, jwt_claims("combined-jwt")),
        (
            CredentialFormat::SdJwt,
            base_claims(CredentialPayloadFormat::W3cVcdmV2SdJwt),
        ),
        (
            CredentialFormat::MsoMdoc,
            base_claims(CredentialPayloadFormat::default()),
        ),
        (CredentialFormat::VdsNc, vds_claims()),
    ];
    for (format, claims) in routes {
        assert_key_error_without_private_material(
            formats::sign_credential_with_signer(&format, &key, &claims),
            &key.jwk_json,
        );
    }
}

#[cfg(feature = "zk_mdoc")]
#[test]
fn combined_zk_mdoc_route_rejects_mismatch_without_credentials() {
    let key = issuer_key(&JWK::generate_p256(), SigningAlgorithm::EdDSA);
    let mut claims = base_claims(CredentialPayloadFormat::default());
    claims.zk_predicate_claims = vec![ZkPredicateBinding::multi(
        "given_name",
        vec!["non_empty".into()],
    )];
    assert_key_error_without_private_material(
        formats::sign_credential_with_signer(&CredentialFormat::ZkMdoc, &key, &claims),
        &key.jwk_json,
    );
}

#[test]
fn format_specific_rejections_still_precede_local_key_validation() {
    let key = issuer_key(&JWK::generate_p256(), SigningAlgorithm::ES256K);
    assert!(matches!(
        formats::sign_credential_with_signer(
            &CredentialFormat::MsoMdoc,
            &key,
            &base_claims(CredentialPayloadFormat::default())
        ),
        Err(Oid4vciError::MdocError(_))
    ));
    assert!(matches!(
        formats::sign_credential_with_signer(&CredentialFormat::VdsNc, &key, &vds_claims()),
        Err(Oid4vciError::ConfigError(_))
    ));
    let mut invalid_sd_jwt = base_claims(CredentialPayloadFormat::IetfSdJwt);
    invalid_sd_jwt.claims.insert("_sd".into(), json!([]));
    assert!(matches!(
        formats::sign_credential_with_signer(&CredentialFormat::SdJwt, &key, &invalid_sd_jwt),
        Err(Oid4vciError::SdJwtError(_))
    ));
}

#[cfg(feature = "zk_mdoc")]
#[test]
fn zk_mdoc_configuration_rejection_still_precedes_local_key_validation() {
    let key = issuer_key(&JWK::generate_p256(), SigningAlgorithm::EdDSA);
    assert!(matches!(
        formats::sign_credential_with_signer(
            &CredentialFormat::ZkMdoc,
            &key,
            &base_claims(CredentialPayloadFormat::default())
        ),
        Err(Oid4vciError::ConfigError(_))
    ));
}

#[test]
fn serial_es256_batch_returns_no_credentials_for_contradictory_embedded_alg() {
    let mut jwk = JWK::generate_p256();
    jwk.algorithm = Some(Algorithm::EdDSA);
    let key = issuer_key(&jwk, SigningAlgorithm::ES256);
    let scope = Es256SignerScope::new(&key).unwrap();
    let inputs = vec![
        JwtVcSigningBatchInput::new(SigningRouteId::new(1), jwt_claims("first")).into(),
        JwtVcSigningBatchInput::new(SigningRouteId::new(2), jwt_claims("second")).into(),
    ];
    let error = scope
        .sign_batch(inputs)
        .expect_err("a rejected signer must not return a partial credential vector");
    assert_eq!(error.kind(), SigningBatchErrorKind::ExecutorFailed);
    assert_eq!(error.item_ordinal(), Some(0));
}
