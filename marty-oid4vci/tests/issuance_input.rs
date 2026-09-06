use marty_oid4vci::{issuance_input::normalize_zk_predicate_claims, types::SignedCredential};
use serde_json::json;

#[test]
fn typed_key_admission_preserves_supported_curves_and_metadata_checks() {
    use marty_oid4vci::{signer::derive_typed_jwk_algorithm, types::SigningAlgorithm};
    for (curve, expected) in [
        ("P-256", SigningAlgorithm::ES256),
        ("P-384", SigningAlgorithm::ES384),
        ("secp256k1", SigningAlgorithm::ES256K),
    ] {
        let key: ssi_jwk::JWK = serde_json::from_value(json!({"kty":"EC", "crv":curve})).unwrap();
        assert_eq!(derive_typed_jwk_algorithm(&key).unwrap(), expected);
    }
    let mut key = ssi_jwk::JWK::generate_ed25519().unwrap();
    assert_eq!(
        derive_typed_jwk_algorithm(&key).unwrap(),
        SigningAlgorithm::EdDSA
    );
    key.algorithm = Some(ssi_jwk::Algorithm::ES256);
    assert!(derive_typed_jwk_algorithm(&key).is_err());
    for value in [json!({"kty":"EC"}), json!({"kty":"EC", "crv":"unknown"})] {
        let key = serde_json::from_value(value).unwrap();
        assert!(derive_typed_jwk_algorithm(&key).is_err());
    }
}
use std::collections::HashMap;

#[test]
fn predicate_normalization_preserves_typed_and_legacy_forms() {
    let claims = HashMap::from([("birth_date".into(), json!("2000-01-01"))]);
    assert!(normalize_zk_predicate_claims(&claims, vec![]).is_empty());
    let typed = r#"{"claim_name":"birth_date","supported_predicates":["age_over_18"]}"#;
    for raw in [
        vec![typed.into()],
        vec!["birth_date".into(), "age_over_18".into()],
        vec!["age_over_18".into()],
    ] {
        let bindings = normalize_zk_predicate_claims(&claims, raw);
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].claim_name, "birth_date");
        assert_eq!(bindings[0].supported_predicates, ["age_over_18"]);
    }
    let bindings = normalize_zk_predicate_claims(&claims, vec!["birth_date".into()]);
    assert_eq!(bindings[0].supported_predicates, ["birth_date"]);
    let bindings = normalize_zk_predicate_claims(&HashMap::new(), vec!["unknown".into()]);
    assert_eq!(bindings[0].claim_name, "unknown");
    assert_eq!(bindings[0].supported_predicates, ["unknown"]);
}

#[test]
fn predicate_fallback_is_deterministic_across_map_insertion_orders() {
    for names in [["zeta", "alpha"], ["alpha", "zeta"]] {
        let claims = names
            .into_iter()
            .map(|name| (name.into(), json!(1)))
            .collect();
        let bindings = normalize_zk_predicate_claims(&claims, vec!["predicate".into()]);
        assert_eq!(bindings[0].claim_name, "alpha");
    }
}

#[test]
fn encoded_credentials_preserve_every_format_and_zk_response_metadata() {
    let cases = [
        SignedCredential::JwtVcJson {
            jwt: "jwt".into(),
            credential_id: "id".into(),
        },
        SignedCredential::SdJwt {
            compact: "sd~".into(),
            credential_id: "id".into(),
        },
        SignedCredential::MsoMdoc {
            issuer_signed_b64: "mdoc".into(),
            credential_id: "id".into(),
        },
        SignedCredential::ZkMdoc {
            issuer_signed_b64: "zk".into(),
            credential_id: "id".into(),
            zk_predicate_bindings: vec![],
            zk_proof_type: "proof".into(),
        },
        SignedCredential::VdsNc {
            barcode_data: "barcode".into(),
            credential_id: "id".into(),
        },
    ];
    for (credential, expected) in cases
        .into_iter()
        .zip(["jwt", "sd~", "mdoc", "zk", "barcode"])
    {
        assert_eq!(credential.encoded_credential(), expected);
        assert_eq!(credential.credential_id(), "id");
        let response = credential.to_response_value();
        if expected == "zk" {
            assert_eq!(response["credential"], "zk");
            assert_eq!(response["zk_metadata"]["proof_type"], "proof");
        } else {
            assert_eq!(response, expected);
        }
    }
}

#[test]
fn compact_signing_preserves_payload_and_binds_header_to_key() {
    use base64::Engine;
    use marty_oid4vci::jose::{sign_compact_jwt, verify_compact_jwt_with_public_jwk};
    let jwk = ssi_jwk::JWK::generate_ed25519().unwrap();
    let payload =
        json!({"iss":"did:example:issuer", "vc":{"credentialSubject":{"claims":{"name":"test"}}}});
    let jwt = sign_compact_jwt(&jwk, &json!({"alg":"EdDSA", "typ":"JWT"}), &payload).unwrap();
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jwt.split('.').nth(1).unwrap())
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&decoded).unwrap(),
        payload
    );
    // Public verification checks the signature independently of the signing helper.
    let public = serde_json::to_string(&jwk.to_public()).unwrap();
    let verified = verify_compact_jwt_with_public_jwk(&jwt, &public, "EdDSA").unwrap();
    assert_eq!(verified.claims, payload);
    for header in [json!({}), json!({"alg":7}), json!({"alg":"ES256"})] {
        assert!(sign_compact_jwt(&jwk, &header, &payload).is_err());
    }
}
