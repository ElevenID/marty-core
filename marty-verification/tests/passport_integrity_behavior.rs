use marty_verification::passport_integrity::{compare, IntegrityRequest};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    request: IntegrityRequest,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    is_passport_valid: bool,
    successful_verifications: usize,
    failed_verifications: usize,
    critical_errors: usize,
    warnings: usize,
    overall_status: String,
    results: Vec<String>,
    risk_level: Option<String>,
}

#[test]
fn shared_passport_integrity_vectors() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("fixtures/passport_integrity_behavior.json")).unwrap();
    for case in fixture.cases {
        let report = compare(&case.request)
            .unwrap_or_else(|error| panic!("fixture {} unexpectedly failed: {error}", case.name));
        assert_eq!(
            report.is_passport_valid, case.expected.is_passport_valid,
            "{}",
            case.name
        );
        assert_eq!(
            report.successful_verifications, case.expected.successful_verifications,
            "{}",
            case.name
        );
        assert_eq!(
            report.failed_verifications, case.expected.failed_verifications,
            "{}",
            case.name
        );
        assert_eq!(
            report.critical_errors, case.expected.critical_errors,
            "{}",
            case.name
        );
        assert_eq!(report.warnings, case.expected.warnings, "{}", case.name);
        assert_eq!(
            report.overall_status, case.expected.overall_status,
            "{}",
            case.name
        );
        assert_eq!(
            report
                .comparison_entries
                .iter()
                .map(|entry| entry.result.clone())
                .collect::<Vec<_>>(),
            case.expected.results,
            "{}",
            case.name
        );
        assert_eq!(
            report
                .mismatch_analysis
                .security_implications
                .as_ref()
                .map(|value| value.risk_level.clone()),
            case.expected.risk_level,
            "{}",
            case.name
        );
    }
}
