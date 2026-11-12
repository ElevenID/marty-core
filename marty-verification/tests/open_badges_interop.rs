use std::env;
use std::fs;

use serde_json::Value;

use marty_verification::open_badges::verify_ob3_json;

const OB3_VERIFY_REQUEST_ENV: &str = "OPEN_BADGES_OB3_VERIFY_REQUEST";
const OB3_FIXTURE_PATH: &str = "tests/fixtures/open_badges/ob3_verify_request.json";
const OTHER_ED25519_PUBLIC_KEY: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fn load_request(var: &str, fallback: &str) -> Option<String> {
    let path = match env::var(var) {
        Ok(value) => value,
        Err(_) => format!("{}/{}", env!("CARGO_MANIFEST_DIR"), fallback),
    };
    match fs::read_to_string(&path) {
        Ok(contents) => Some(contents),
        Err(err) => {
            if env::var("CI").is_ok() {
                panic!("failed to read {} fixture {}: {}", var, path, err);
            }
            None
        }
    }
}

fn assert_valid(label: &str, result_json: &str) {
    let value: Value = serde_json::from_str(result_json)
        .unwrap_or_else(|e| panic!("{} output is not JSON: {}", label, e));
    assert!(
        value
            .get("valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "{} verification failed: {:?}",
        label,
        value
    );
}

fn assert_invalid(label: &str, result_json: &str) {
    let value: Value = serde_json::from_str(result_json)
        .unwrap_or_else(|e| panic!("{} output is not JSON: {}", label, e));
    assert_eq!(value.get("valid").and_then(Value::as_bool), Some(false));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn ob3_verify_external_fixture() {
    // Fixture must be a JSON request accepted by verify_ob3_json:
    // {"credential": {...}, "document_store": {...}}
    let request = match load_request(OB3_VERIFY_REQUEST_ENV, OB3_FIXTURE_PATH) {
        Some(value) => value,
        None => return,
    };

    let result = verify_ob3_json(&request).expect("OB3 fixture verification failed");
    assert_valid("OB3 fixture", &result);

    let mut tampered: Value = serde_json::from_str(&request).unwrap();
    tampered["credential"]["credentialSubject"]["achievement"]["name"] = Value::from("Tampered");
    let result = verify_ob3_json(&tampered.to_string()).expect("OB3 tampered request failed");
    assert_invalid("OB3 tampered fixture", &result);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn bundled_fixtures_reject_mismatched_issuer_key() {
    let mut ob3: Value =
        serde_json::from_str(include_str!("fixtures/open_badges/ob3_verify_request.json")).unwrap();
    for method in ob3["document_store"].as_object_mut().unwrap().values_mut() {
        method["publicKeyJwk"]["x"] = Value::from(OTHER_ED25519_PUBLIC_KEY);
    }
    let result = verify_ob3_json(&ob3.to_string()).expect("OB3 wrong-key request failed");
    assert_invalid("OB3 wrong-key fixture", &result);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn signed_badge_missing_criteria_is_rejected_after_proof_verification() {
    let request = include_str!("fixtures/open_badges/ob3_missing_criteria_verify_request.json");
    let result: Value = serde_json::from_str(&verify_ob3_json(request).unwrap()).unwrap();
    assert_eq!(result["valid"], false, "{result}");
    // A proof/key failure would add another code. This exact signed historical
    // fixture is rejected solely for the missing required OB3 property.
    assert_eq!(result["error_codes"], serde_json::json!(["E701"]));
    assert!(result["errors"][0]
        .as_str()
        .unwrap()
        .contains("achievement criteria"));
}
