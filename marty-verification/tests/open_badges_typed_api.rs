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
        if !valid {
            assert!(typed.errors.iter().any(|error| error.contains("context")));
        }
        let wire: Value =
            serde_json::from_str(&verify_ob2_json(&request.to_string()).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), wire);
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
