use serde_json::{json, Value};

use marty_verification::trust_sync;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/trust_registry_sync_behavior.json"))
        .expect("trust-registry behavior fixture must be valid JSON")
}

#[test]
fn catalog_and_import_vectors_are_canonical() {
    let fixture = fixture();
    for case in fixture["catalog_cases"].as_array().unwrap() {
        let output: Value = serde_json::from_str(
            &trust_sync::registry_catalog_json(case["framework"].as_str()).unwrap(),
        )
        .unwrap();
        let types: Vec<&str> = output
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["registry_type"].as_str().unwrap())
            .collect();
        let expected: Vec<&str> = case["expected_types"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(types, expected);
    }

    for case in fixture["import_cases"].as_array().unwrap() {
        let formats = serde_json::to_string(&case["formats"]).unwrap();
        let result = trust_sync::import_decision_json(
            case["registry_type"].as_str().unwrap(),
            Some(&formats),
            case["interval"].as_u64().map(|value| value as u16),
            fixture["now"].as_str().unwrap(),
        );
        if let Some(error) = case["error_contains"].as_str() {
            assert!(result.unwrap_err().to_string().contains(error));
        } else {
            let output: Value = serde_json::from_str(&result.unwrap()).unwrap();
            assert_eq!(output["formats"], case["expected_formats"]);
            assert_eq!(output["next_sync_at"], case["expected_next_sync_at"]);
        }
    }
}

#[test]
fn public_token_and_schedule_vectors_are_canonical() {
    let fixture = fixture();
    for case in fixture["public_sync_query_cases"].as_array().unwrap() {
        let result = trust_sync::public_sync_query_json(case["since"].as_str());
        if let Some(error) = case["error_contains"].as_str() {
            assert!(result.unwrap_err().to_string().contains(error));
        } else {
            let output: Value = serde_json::from_str(&result.unwrap()).unwrap();
            assert_eq!(output["since_sequence"], case["expected_since_sequence"]);
            assert_eq!(output["current_only"], case["expected_current_only"]);
        }
    }

    for case in fixture["schedule_cases"].as_array().unwrap() {
        let output: bool = serde_json::from_str(
            &trust_sync::sync_is_due_json(
                case["last_synchronized_at"].as_str(),
                case["interval"].as_u64().unwrap() as u16,
                fixture["now"].as_str().unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(output, case["expected_due"]);
    }

    let metadata: Value = serde_json::from_str(
        &trust_sync::public_sync_metadata_json(42, fixture["now"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["sync_token"], "42");
    assert_eq!(metadata["sequence"], 42);
    assert_eq!(metadata["has_more"], false);
}

#[test]
fn url_destination_and_request_vectors_are_canonical() {
    let fixture = fixture();
    for case in fixture["url_cases"].as_array().unwrap() {
        let result = trust_sync::validate_registry_url(case["url"].as_str().unwrap());
        if case["valid"].as_bool().unwrap() {
            assert!(result.is_ok());
        } else {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains(case["error_contains"].as_str().unwrap()));
        }
    }

    for case in fixture["destination_cases"].as_array().unwrap() {
        let addresses = serde_json::to_string(&case["addresses"]).unwrap();
        let result = trust_sync::destination_decision_json(
            case["url"].as_str().unwrap(),
            &addresses,
            case["allowlist"].as_str().unwrap(),
        );
        if let Some(error) = case["error_contains"].as_str() {
            assert!(result.unwrap_err().to_string().contains(error));
        } else {
            let output: Value = serde_json::from_str(&result.unwrap()).unwrap();
            assert_eq!(output["address"], case["expected_address"]);
        }
    }

    for case in fixture["allowlist_cases"].as_array().unwrap() {
        let result = trust_sync::private_host_allowlist_json(case["configured"].as_str().unwrap());
        if let Some(error) = case["error_contains"].as_str() {
            assert!(result.unwrap_err().to_string().contains(error));
        } else {
            let output: Value = serde_json::from_str(&result.unwrap()).unwrap();
            assert_eq!(output, case["expected"]);
        }
    }

    for case in fixture["request_cases"].as_array().unwrap() {
        let output: Value = serde_json::from_str(
            &trust_sync::request_plan_json(
                case["url"].as_str().unwrap(),
                case["token"].as_str(),
                case["address"].as_str(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(output["request_url"], case["expected_request_url"]);
        assert_eq!(output["host_header"], case["expected_host_header"]);
        assert_eq!(output["sni_hostname"], case["expected_sni_hostname"]);
    }
}

#[test]
fn page_state_machine_vectors_are_atomic_and_fail_closed() {
    let fixture = fixture();
    for case in fixture["evaluation_cases"].as_array().unwrap() {
        let result = trust_sync::evaluate_pages_json(
            &case["previous"].to_string(),
            &case["pages"].to_string(),
            fixture["now"].as_str().unwrap(),
        );
        if let Some(error) = case["error_contains"].as_str() {
            assert!(result.unwrap_err().to_string().contains(error));
            continue;
        }
        let output: Value = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(output["complete"], case["expected_complete"]);
        assert_eq!(output["pages"], case["expected_pages"]);
        assert_eq!(output["next_token"], case["expected_token"]);
        assert_eq!(output["state"]["sequence"], case["expected_sequence"]);
        assert_eq!(output["state"]["sync_token"], case["expected_token"]);
        assert_eq!(output["state"]["entries"], json!({}));
    }
}
