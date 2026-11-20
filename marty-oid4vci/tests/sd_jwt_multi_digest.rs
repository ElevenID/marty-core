//! Public-only vectors minted through disposable non-exportable OpenBao keys.
//! The same assertions run natively and in the WASM runtime.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::sd_jwt::{
        create_sd_jwt_presentation, create_sd_jwt_presentation_with_digest_algorithms,
        verify_sd_jwt, verify_sd_jwt_with_policy, verify_sd_jwt_with_policy_and_digest_algorithms,
        SdJwtDigestAlgorithm, SdJwtVerificationPolicy,
    },
    types::SigningAlgorithm,
};
use serde_json::Value;
#[cfg(target_family = "wasm")]
use wasm_bindgen_test::wasm_bindgen_test;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/sd_jwt_multi_digest_public.json")).unwrap()
}

fn policy(fixture: &Value) -> SdJwtVerificationPolicy {
    SdJwtVerificationPolicy {
        expected_issuer: fixture["issuer"].as_str().unwrap().into(),
        issuer_algorithm: SigningAlgorithm::ES256,
        holder_algorithms: vec![SigningAlgorithm::ES256],
    }
}

const ALGORITHMS: [SdJwtDigestAlgorithm; 3] = [
    SdJwtDigestAlgorithm::Sha256,
    SdJwtDigestAlgorithm::Sha384,
    SdJwtDigestAlgorithm::Sha512,
];

#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn signed_digest_selection_requires_explicit_admission() {
    let fixture = fixture();
    let key = fixture["issuer_public_jwk"].to_string();
    let policy = policy(&fixture);
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), ALGORITHMS.len());
    for (vector, selected) in vectors.iter().zip(ALGORITHMS) {
        assert_eq!(vector["digest_algorithm"], selected.name());
        let credential = vector["credential"].as_str().unwrap();
        for admitted in ALGORITHMS {
            let result = verify_sd_jwt_with_policy_and_digest_algorithms(
                credential,
                &key,
                &policy,
                None,
                None,
                &[admitted],
            );
            assert_eq!(result.is_ok(), selected == admitted);
            if let Ok(verified) = result {
                assert_eq!(verified.issuer(), policy.expected_issuer);
                assert_eq!(verified.claims()["given_name"], "Alice");
            }
        }
        assert_eq!(
            verify_sd_jwt(credential, &key, None, None).is_ok(),
            selected == SdJwtDigestAlgorithm::Sha256
        );
        assert_eq!(
            verify_sd_jwt_with_policy(credential, &key, &policy, None, None).is_ok(),
            selected == SdJwtDigestAlgorithm::Sha256
        );
        assert!(verify_sd_jwt_with_policy_and_digest_algorithms(
            credential,
            &key,
            &policy,
            None,
            None,
            &[]
        )
        .is_err());
        let mut wrong_issuer = policy.clone();
        wrong_issuer.expected_issuer.push_str("/other");
        assert!(verify_sd_jwt_with_policy_and_digest_algorithms(
            credential,
            &key,
            &wrong_issuer,
            None,
            None,
            &ALGORITHMS
        )
        .is_err());
        let mut wrong_signature = policy.clone();
        wrong_signature.issuer_algorithm = SigningAlgorithm::ES384;
        assert!(verify_sd_jwt_with_policy_and_digest_algorithms(
            credential,
            &key,
            &wrong_signature,
            None,
            None,
            &ALGORITHMS
        )
        .is_err());
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn selected_disclosures_keep_the_original_encoded_commitments() {
    let fixture = fixture();
    let key = fixture["issuer_public_jwk"].to_string();
    let policy = policy(&fixture);
    for (vector, selected) in fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .zip(ALGORITHMS)
    {
        let credential = vector["credential"].as_str().unwrap();
        let named = vec!["given_name".into()];
        let presentation =
            create_sd_jwt_presentation_with_digest_algorithms(credential, &named, &[selected])
                .unwrap();
        assert_eq!(presentation, credential);
        assert_eq!(
            create_sd_jwt_presentation(credential, &named).is_ok(),
            selected == SdJwtDigestAlgorithm::Sha256
        );
        let undisclosed =
            create_sd_jwt_presentation_with_digest_algorithms(credential, &[], &[selected])
                .unwrap();
        let verified = verify_sd_jwt_with_policy_and_digest_algorithms(
            &undisclosed,
            &key,
            &policy,
            None,
            None,
            &[selected],
        )
        .unwrap();
        assert!(verified.claims().get("given_name").is_none());
        assert_eq!(verified.claims()["family_name"], "Smith");
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen_test)]
#[cfg_attr(not(target_family = "wasm"), test)]
fn selection_rejects_duplicate_and_malformed_digest_selectors() {
    let fixture = fixture();
    let credential = fixture["vectors"][0]["credential"].as_str().unwrap();
    let (jws, disclosures) = credential.split_once('~').unwrap();
    let segments = jws.split('.').collect::<Vec<_>>();
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
    for replacement in [
        "\"_sd_alg\":\"sha-256\",\"_sd_alg\":\"sha-384\"",
        "\"_sd_alg\":null",
        "\"_sd_alg\":\"SHA-256\"",
        "\"_sd_alg\":\"private-selector-canary\"",
    ] {
        assert!(payload.contains("\"_sd_alg\":\"sha-256\""));
        let payload = payload.replace("\"_sd_alg\":\"sha-256\"", replacement);
        let changed = format!(
            "{}.{}.{}~{disclosures}",
            segments[0],
            URL_SAFE_NO_PAD.encode(payload),
            segments[2]
        );
        let error = create_sd_jwt_presentation_with_digest_algorithms(
            &changed,
            &["given_name".into()],
            &ALGORITHMS,
        )
        .unwrap_err();
        assert!(!error.to_string().contains("private-selector-canary"));
    }
}
