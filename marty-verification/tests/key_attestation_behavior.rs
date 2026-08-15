use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/key_attestation_behavior.json"))
        .expect("valid language-neutral key-attestation fixture")
}

fn assert_json_case(
    case: &Value,
    operation: impl FnOnce(&str) -> Result<String, String>,
    request: Value,
) {
    let raw = serde_json::to_string(&request).expect("serializable fixture request");
    match case.get("error").and_then(Value::as_str) {
        Some(expected) => assert_eq!(operation(&raw).unwrap_err(), expected, "{}", case["name"]),
        None => {
            let actual: Value = serde_json::from_str(&operation(&raw).expect("successful case"))
                .expect("JSON result");
            assert_eq!(actual, case["expected"], "{}", case["name"]);
        }
    }
}

#[test]
fn tenant_policy_behavior_matches_fixture() {
    for case in fixture()["policy_cases"].as_array().expect("policy cases") {
        assert_json_case(
            case,
            marty_verification::key_attestation::policy_from_issuer_context_json,
            case["request"].clone(),
        );
    }
}

#[test]
fn proof_routing_behavior_matches_fixture() {
    for case in fixture()["route_cases"].as_array().expect("route cases") {
        assert_json_case(
            case,
            marty_verification::key_attestation::route_proof_json,
            case["request"].clone(),
        );
    }
}

#[test]
fn status_reference_behavior_matches_fixture() {
    for case in fixture()["status_reference_cases"]
        .as_array()
        .expect("status reference cases")
    {
        let policy = json!({
            "mode": "required",
            "trusted_root_certificates_pem": ["ROOT"],
            "allowed_algorithms": ["ES256"],
            "required_key_storage": [],
            "required_user_authentication": [],
            "max_age_seconds": 300,
            "require_nonce": true,
            "status_validation": "required",
            "status_list_allowed_origins": case["allowed_origins"],
            "status_list_trusted_root_certificates_pem": ["ROOT"],
            "status_list_allowed_algorithms": ["ES256"],
            "status_list_max_age_seconds": 86400,
            "status_list_allow_private_hosts": case["allow_private_hosts"],
            "status_list_tls_ca_certificates_pem": []
        });
        assert_json_case(
            case,
            marty_verification::key_attestation::validate_status_reference_json,
            json!({"status": case["status"], "policy": policy}),
        );
    }
}
