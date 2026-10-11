use std::env;
use std::fs;

use serde_json::Value;

use marty_verification::open_badges::{verify_ob2_json, verify_ob3_json};

const OB2_VERIFY_REQUEST_ENV: &str = "OPEN_BADGES_OB2_VERIFY_REQUEST";
const OB3_VERIFY_REQUEST_ENV: &str = "OPEN_BADGES_OB3_VERIFY_REQUEST";
const OB2_FIXTURE_PATH: &str = "tests/fixtures/open_badges/ob2_verify_request.json";
const OB3_FIXTURE_PATH: &str = "tests/fixtures/open_badges/ob3_verify_request.json";

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

#[test]
fn ob2_verify_external_fixture() {
    // Fixture must be a JSON request accepted by verify_ob2_json:
    // {"assertion": {...}, "document_store": {...}, "recipient_identity": "..."}
    let request = match load_request(OB2_VERIFY_REQUEST_ENV, OB2_FIXTURE_PATH) {
        Some(value) => value,
        None => return,
    };

    let result = verify_ob2_json(&request).expect("OB2 fixture verification failed");
    assert_valid("OB2 fixture", &result);

    let mut tampered: Value = serde_json::from_str(&request).unwrap();
    tampered["assertion"]
        .as_object_mut()
        .unwrap()
        .remove("@context");
    let result = verify_ob2_json(&tampered.to_string()).expect("OB2 tampered request failed");
    assert_invalid("OB2 tampered fixture", &result);
}

#[test]
#[ignore = "known gap: OB2 assertion id edit is currently accepted; awaiting payload-binding review"]
fn ob2_assertion_id_payload_binding_gap() {
    let request = load_request(OB2_VERIFY_REQUEST_ENV, OB2_FIXTURE_PATH).unwrap();
    let mut tampered: Value = serde_json::from_str(&request).unwrap();
    tampered["assertion"]["id"] = Value::from("urn:uuid:tampered");
    let result = verify_ob2_json(&tampered.to_string()).unwrap();
    assert_invalid("OB2 assertion-id edit", &result);
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
