//! Legacy signed assertions are retained as rejection and migration evidence.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_verification::credential_format::{detect_credential_format, DetectedCredentialFormat};
use marty_verification::open_badges::{
    detect_version, is_retired_ob2, ob3_context_uri, verify_ob3_json_async, OpenBadgesVersion,
};
use serde_json::{json, Value};

fn legacy_assertion() -> Value {
    let request: Value =
        serde_json::from_str(include_str!("fixtures/open_badges/ob2_verify_request.json")).unwrap();
    request["assertion"].clone()
}

fn jwt(kind: &str, payload: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(json!({"alg": "EdDSA", "typ": kind}).to_string());
    let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    // A well-formed placeholder reaches the pre-proof rejection boundary.
    let signature = URL_SAFE_NO_PAD.encode([0_u8; 64]);
    format!("{header}.{payload}.{signature}")
}

#[test]
fn retained_ob2_assertion_is_not_a_supported_profile() {
    let assertion = legacy_assertion();
    assert!(assertion["signature"].is_string());
    assert!(is_retired_ob2(&assertion));
    assert_eq!(detect_version(&assertion), OpenBadgesVersion::Unknown);
    assert_eq!(
        detect_credential_format(&assertion.to_string()),
        DetectedCredentialFormat::Unknown
    );
    assert!(serde_json::from_str::<OpenBadgesVersion>(r#""V2""#).is_err());
    assert!(serde_json::from_str::<DetectedCredentialFormat>(r#""openbadge-v2""#).is_err());
}

#[test]
fn retired_markers_cannot_be_relabelled_as_ob3_or_data_integrity() {
    let mut mixed = legacy_assertion();
    mixed["@context"] = json!(["https://w3id.org/openbadges/v2", ob3_context_uri()]);
    mixed["type"] = json!(["VerifiableCredential", "OpenBadgeCredential"]);
    mixed["proof"] = json!({"type": "DataIntegrityProof"});
    let assertion_type_only = json!({"type": "Assertion", "@context": ob3_context_uri()});
    let conflicting_alias = json!({
        "@context": ob3_context_uri(),
        "context": ["https://w3id.org/openbadges/v2"],
        "type": ["VerifiableCredential", "OpenBadgeCredential"]
    });
    for credential in [
        legacy_assertion(),
        mixed,
        assertion_type_only,
        conflicting_alias,
    ] {
        assert!(is_retired_ob2(&credential));
        assert_eq!(detect_version(&credential), OpenBadgesVersion::Unknown);
        assert_eq!(
            detect_credential_format(&credential.to_string()),
            DetectedCredentialFormat::Unknown
        );
        let request = json!({"credential": credential});
        let error =
            futures::executor::block_on(verify_ob3_json_async(&request.to_string())).unwrap_err();
        assert!(
            error.to_string().contains("Open Badges 2 is retired"),
            "{error}"
        );
    }
}

#[test]
fn retired_assertions_do_not_gain_a_route_through_envelopes_or_jwts() {
    let assertion = legacy_assertion();
    let wrappers = [
        json!({"credential": assertion}),
        json!({"assertion": assertion}),
        json!({"vc": assertion}),
        json!({"vp": {"verifiableCredential": [assertion]}}),
    ];
    for wrapper in wrappers {
        assert!(is_retired_ob2(&wrapper));
        assert_eq!(
            detect_credential_format(&wrapper.to_string()),
            DetectedCredentialFormat::Unknown
        );
        for kind in ["vc+jwt", "openBadgeCredential"] {
            let token = jwt(kind, &wrapper);
            for token in [token.clone(), format!("{token}~disclosure~")] {
                assert!(is_retired_ob2(&json!(token)));
                assert_eq!(
                    detect_credential_format(&token),
                    DetectedCredentialFormat::Unknown
                );
            }
        }
    }
}

#[test]
fn supported_ob3_contexts_keep_their_route() {
    for context in [
        ob3_context_uri(),
        "https://w3id.org/openbadges/v3",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    ] {
        let credential = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2", context],
            "type": ["VerifiableCredential", "OpenBadgeCredential"]
        });
        assert!(!is_retired_ob2(&credential));
        assert_eq!(detect_version(&credential), OpenBadgesVersion::V3);
        assert_eq!(
            detect_credential_format(&credential.to_string()),
            DetectedCredentialFormat::OpenbadgeV3
        );
        assert_eq!(
            detect_credential_format(&jwt("vc+jwt", &json!({"vc": credential}))),
            DetectedCredentialFormat::OpenbadgeV3
        );
    }
}

#[test]
fn maintenance_ob3_issuance_rejects_a_retired_assertion() {
    let request = json!({
        "credential": legacy_assertion(),
        "signing": {"jwk": {}, "verification_method": "did:example:issuer#key"}
    });
    let error = futures::executor::block_on(marty_verification::open_badges::issue_ob3_json_async(
        &request.to_string(),
    ))
    .unwrap_err();
    assert!(
        error.to_string().contains("Open Badges 2 is retired"),
        "{error}"
    );
}

#[test]
fn direct_vcdm_boundaries_reject_mixed_legacy_profiles_before_proof_processing() {
    use marty_verification::vcdm::{
        validate_vcdm_issuance_document_json, verify_open_badge_v3_jwt_json_async,
        verify_vcdm_data_integrity_json_async, verify_vcdm_jwt_json_async,
    };
    let mut mixed = legacy_assertion();
    mixed["@context"] = json!([
        "https://www.w3.org/ns/credentials/v2",
        ob3_context_uri(),
        "https://w3id.org/openbadges/v2"
    ]);
    mixed["type"] = json!(["VerifiableCredential", "OpenBadgeCredential"]);
    let mut alias = mixed.clone();
    alias["@context"] = json!(["https://www.w3.org/ns/credentials/v2", ob3_context_uri()]);
    alias["context"] = json!("https://w3id.org/openbadges/v2");
    let type_alias = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", ob3_context_uri()],
        "type": ["VerifiableCredential", "OpenBadgeCredential", "OpenBadgeV2"]
    });
    for credential in [legacy_assertion(), mixed, alias, type_alias] {
        assert_eq!(
            validate_vcdm_issuance_document_json(&json!({"credential": credential}).to_string()),
            Err("open_badges_2_retired".to_string())
        );
        for document in [
            credential.clone(),
            json!({
                "type": ["VerifiablePresentation"], "verifiableCredential": [credential]
            }),
        ] {
            let raw = futures::executor::block_on(verify_vcdm_data_integrity_json_async(
                &json!({"document": document}).to_string(),
            ));
            let result: Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(result["valid"], false, "{result}");
            assert_eq!(result["verified_proofs"], 0);
            assert_eq!(result["verified_credentials"], 0);
            assert!(result["errors"][0]
                .as_str()
                .unwrap()
                .contains("Open Badges 2 is retired"));
        }
        let request =
            json!({"token": jwt("openBadgeCredential", &json!({"vc": credential}))}).to_string();
        for raw in [
            futures::executor::block_on(verify_vcdm_jwt_json_async(&request)),
            futures::executor::block_on(verify_open_badge_v3_jwt_json_async(&request)),
        ] {
            let result: Value = serde_json::from_str(&raw).unwrap();
            assert_eq!(result["valid"], false, "{result}");
            assert!(result["claims"].is_null());
            assert!(result["issuer"].is_null());
            assert!(result["errors"][0]
                .as_str()
                .unwrap()
                .contains("Open Badges 2 is retired"));
        }
    }
}

#[test]
fn existing_public_ob3_jwt_remains_valid() {
    use marty_verification::vcdm::{
        verify_open_badge_v3_jwt_json_async, verify_vcdm_jwt_json_async,
    };
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/open_badges/ob3_jwt_verify_request.json"
    ))
    .unwrap();
    let request =
        json!({"token": fixture["token"], "issuer_public_jwk": fixture["public_jwk"]}).to_string();
    for raw in [
        futures::executor::block_on(verify_vcdm_jwt_json_async(&request)),
        futures::executor::block_on(verify_open_badge_v3_jwt_json_async(&request)),
    ] {
        let result: Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["issuer"], fixture["issuer"]);
        assert!(result["claims"].is_object());
    }
}
