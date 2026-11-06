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
    format!("{header}.{payload}.signature")
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
    for credential in [legacy_assertion(), mixed, assertion_type_only] {
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
