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
        value.get("valid").and_then(|v| v.as_bool()).unwrap_or(false),
        "{} verification failed: {:?}",
        label,
        value
    );
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
}
