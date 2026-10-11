use marty_verification::open_badges::{
    verify_ob2, verify_ob2_json, verify_ob3_async, verify_ob3_json_async,
    verify_ob3_with_status_lists_async, VerifyOb2Request, VerifyOb3Request,
};
use serde_json::{json, Value};

const OB2: &str = include_str!("fixtures/open_badges/ob2_verify_request.json");
const OB3: &str = include_str!("fixtures/open_badges/ob3_verify_request.json");

#[test]
fn typed_ob2_preserves_signed_fixture_and_rejects_missing_context() {
    for valid in [true, false] {
        let mut request: Value = serde_json::from_str(OB2).unwrap();
        if !valid {
            request["assertion"]
                .as_object_mut()
                .unwrap()
                .remove("@context");
        }
        let typed = verify_ob2(serde_json::from_value(request.clone()).unwrap()).unwrap();
        assert_eq!(typed.valid, valid);
        assert_eq!(typed.version, "2.0");
        assert!(typed.normalized.is_some());
        assert!(typed.warnings.is_empty());
        if !valid {
            assert!(typed.errors.iter().any(|error| error.contains("context")));
        }
        let wire: Value =
            serde_json::from_str(&verify_ob2_json(&request.to_string()).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), wire);
    }
}

#[test]
fn ob2_rejects_assertion_id_changed_outside_signed_payload() {
    let mut request: Value = serde_json::from_str(OB2).unwrap();
    request["assertion"]["id"] = json!("urn:uuid:assertion-replaced");

    let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
    assert!(!result.valid);
    assert!(result.error_codes.iter().any(|code| code == "E703"));
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Signed payload does not match assertion body")));
}

#[test]
fn ob2_legacy_unsigned_verification_metadata_is_limited_to_key_selection() {
    let mut request: Value = serde_json::from_str(OB2).unwrap();
    request["assertion"]["verification"]["startsWith"] = json!("urn:uuid:attacker-");

    let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
    assert!(!result.valid);
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Unsigned verification instructions are not supported")));
}

#[test]
fn ob2_rejects_attacker_owned_key_for_victim_issuer() {
    let mut request: Value = serde_json::from_str(OB2).unwrap();
    request["document_store"]["urn:uuid:badge-1"]["issuer"] = json!("did:example:victim");
    request["document_store"]["did:example:victim"] =
        json!({"id": "did:example:victim", "name": "Victim Issuer"});
    request["document_store"]["did:example:issuer#key-1"]["id"] = json!("did:example:issuer#key-1");
    request["document_store"]["did:example:issuer#key-1"]["owner"] = json!("did:example:attacker");

    let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
    assert!(!result.valid, "{result:?}");
    assert!(result.error_codes.iter().any(|code| code == "E703"));
    assert_eq!(
        result.normalized.unwrap()["issuer_id"],
        "did:example:victim"
    );
}

#[test]
fn ob2_rejects_key_not_listed_by_issuer_profile() {
    for public_key in [
        Value::Null,
        json!({}),
        json!("did:example:issuer#different-key"),
        json!([{"id": "did:example:issuer#different-key"}]),
    ] {
        let mut request: Value = serde_json::from_str(OB2).unwrap();
        request["document_store"]["did:example:issuer"]["publicKey"] = public_key;

        let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
        assert!(!result.valid, "{result:?}");
        assert!(result
            .errors
            .iter()
            .any(|error| error.contains("Signing key is not listed by the badge issuer")));
    }
}

#[test]
fn ob2_rejects_key_without_issuer_controller_or_owner() {
    let mut request: Value = serde_json::from_str(OB2).unwrap();
    request["document_store"]["did:example:issuer#key-1"]
        .as_object_mut()
        .unwrap()
        .remove("owner");

    let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
    assert!(!result.valid, "{result:?}");
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Signing key is not controlled by the badge issuer")));
}

#[test]
fn ob2_accepts_governed_controller_key_for_issuer() {
    let mut request: Value = serde_json::from_str(OB2).unwrap();
    request["document_store"]["did:example:issuer"]
        .as_object_mut()
        .unwrap()
        .remove("publicKey");
    let key = request["document_store"]["did:example:issuer#key-1"]
        .as_object_mut()
        .unwrap();
    key.remove("owner");
    key.insert("controller".to_string(), json!("did:example:issuer"));

    let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
    assert!(result.valid, "{result:?}");
}

#[test]
fn ob2_rejects_missing_or_wrong_key_id() {
    for key_id in [None, Some("did:example:attacker#key-1")] {
        let mut request: Value = serde_json::from_str(OB2).unwrap();
        let key = request["document_store"]["did:example:issuer#key-1"]
            .as_object_mut()
            .unwrap();
        match key_id {
            Some(value) => {
                key.insert("id".to_string(), json!(value));
            }
            None => {
                key.remove("id");
            }
        }

        let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
        assert!(!result.valid, "{result:?}");
        assert!(result.error_codes.iter().any(|code| code == "E703"));
    }
}

#[test]
fn ob2_rejects_either_conflicting_issuer_link_on_key() {
    for (owner, controller) in [
        ("did:example:attacker", "did:example:issuer"),
        ("did:example:issuer", "did:example:attacker"),
    ] {
        let mut request: Value = serde_json::from_str(OB2).unwrap();
        let key = request["document_store"]["did:example:issuer#key-1"]
            .as_object_mut()
            .unwrap();
        key.insert("owner".to_string(), json!(owner));
        key.insert("controller".to_string(), json!(controller));

        let result = verify_ob2(serde_json::from_value(request).unwrap()).unwrap();
        assert!(!result.valid, "{result:?}");
        assert!(result.error_codes.iter().any(|code| code == "E703"));
    }
}

#[test]
fn typed_ob3_preserves_signed_fixture_and_missing_authority_failure() {
    futures::executor::block_on(async {
        for valid in [true, false] {
            let mut request: Value = serde_json::from_str(OB3).unwrap();
            if !valid {
                request["document_store"] = json!({});
            }
            let typed = verify_ob3_async(serde_json::from_value(request.clone()).unwrap())
                .await
                .unwrap();
            assert_eq!(typed.valid, valid, "{:?}", typed.errors);
            assert_eq!(typed.version, "3.0");
            if !valid {
                assert!(!typed.errors.is_empty());
            }
            let explicit = verify_ob3_with_status_lists_async(
                serde_json::from_value(request.clone()).unwrap(),
                &[],
            )
            .await
            .unwrap();
            let wire: Value =
                serde_json::from_str(&verify_ob3_json_async(&request.to_string()).await.unwrap())
                    .unwrap();
            assert_eq!(serde_json::to_value(typed).unwrap(), wire);
            assert_eq!(serde_json::to_value(explicit).unwrap(), wire);
        }
    });
}

#[test]
fn request_decoding_and_json_error_context_are_preserved() {
    assert!(serde_json::from_value::<VerifyOb2Request>(json!({})).is_err());
    assert!(serde_json::from_value::<VerifyOb3Request>(json!({})).is_err());
    assert!(verify_ob2_json("{}")
        .unwrap_err()
        .to_string()
        .contains("Invalid OB2 verify request:"));
    let error = futures::executor::block_on(verify_ob3_json_async("{}")).unwrap_err();
    assert!(error.to_string().contains("Invalid OB3 verify request:"));
    let error = futures::executor::block_on(verify_ob3_async(VerifyOb3Request {
        credential: json!({}),
        document_store: None,
    }))
    .unwrap_err();
    assert!(error.to_string().contains("Invalid OB3 credential:"));
}
