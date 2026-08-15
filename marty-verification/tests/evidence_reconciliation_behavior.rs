use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "fixtures/evidence_reconciliation_behavior.json"
    ))
    .expect("valid language-neutral reconciliation fixture")
}

fn call(operation: fn(&str) -> Result<String, String>, request: &Value) -> Value {
    serde_json::from_str(&operation(&request.to_string()).expect("successful vector"))
        .expect("JSON result")
}

#[test]
fn reconciliation_plans_match_shared_vectors() {
    let fixture = fixture();
    for case in fixture["plan_cases"].as_array().unwrap() {
        let mut request = fixture["plan_base"].clone();
        request
            .as_object_mut()
            .unwrap()
            .extend(case["patch"].as_object().unwrap().clone());
        assert_eq!(
            call(
                marty_verification::evidence_reconciliation::reconciliation_plan_json,
                &request,
            ),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}

#[test]
fn stale_receipt_reasons_match_shared_vectors() {
    for case in fixture()["stale_cases"].as_array().unwrap() {
        assert_eq!(
            call(
                marty_verification::evidence_reconciliation::stale_receipt_reasons_json,
                &case["request"],
            ),
            case["expected"],
            "{}",
            case["name"]
        );
    }
}
