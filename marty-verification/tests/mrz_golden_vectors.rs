use marty_verification::mrz::{parse_mrz, MrzFormat};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureSet {
    schema_version: u32,
    cases: Vec<MrzCase>,
}

#[derive(Deserialize)]
struct MrzCase {
    id: String,
    lines: Vec<String>,
    #[serde(default)]
    valid_check_digits: bool,
    #[serde(default)]
    expect_parse_error: bool,
    expected: Option<ExpectedMrz>,
}

#[derive(Deserialize)]
struct ExpectedMrz {
    format: String,
    document_type: String,
    issuing_country: String,
    document_number: String,
    surname: String,
    given_names: String,
    nationality: String,
    date_of_birth: String,
    sex: String,
    date_of_expiry: String,
}

fn format_name(format: MrzFormat) -> &'static str {
    match format {
        MrzFormat::TD1 => "TD1",
        MrzFormat::TD2 => "TD2",
        MrzFormat::TD3 => "TD3",
    }
}

#[test]
fn rust_matches_shared_mrz_golden_vectors() {
    let fixture: FixtureSet = serde_json::from_str(include_str!("fixtures/emrtd_mrz_vectors.json"))
        .expect("parse shared MRZ fixture");
    assert_eq!(fixture.schema_version, 1);

    for case in fixture.cases {
        let lines: Vec<&str> = case.lines.iter().map(String::as_str).collect();
        let parsed = parse_mrz(&lines);
        if case.expect_parse_error {
            assert!(parsed.is_err(), "{} must fail closed", case.id);
            continue;
        }

        let parsed = parsed.unwrap_or_else(|error| panic!("{} failed: {error}", case.id));
        let expected = case
            .expected
            .expect("successful vector needs expected data");
        assert_eq!(format_name(parsed.format), expected.format, "{}", case.id);
        assert_eq!(parsed.document_type, expected.document_type, "{}", case.id);
        assert_eq!(
            parsed.issuing_country, expected.issuing_country,
            "{}",
            case.id
        );
        assert_eq!(
            parsed.document_number, expected.document_number,
            "{}",
            case.id
        );
        assert_eq!(parsed.surname, expected.surname, "{}", case.id);
        assert_eq!(parsed.given_names, expected.given_names, "{}", case.id);
        assert_eq!(parsed.nationality, expected.nationality, "{}", case.id);
        assert_eq!(parsed.date_of_birth, expected.date_of_birth, "{}", case.id);
        assert_eq!(parsed.sex.to_string(), expected.sex, "{}", case.id);
        assert_eq!(
            parsed.date_of_expiry, expected.date_of_expiry,
            "{}",
            case.id
        );
        assert_eq!(
            parsed.validate_check_digits(),
            case.valid_check_digits,
            "{}",
            case.id
        );
    }
}
