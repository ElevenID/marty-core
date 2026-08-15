use marty_verification::emrtd_data::{
    inspect_rsa_public_key, parse_biometric_template, parse_dg15, parse_ef_com, parse_ef_dg1,
    parse_ef_dg2, parse_tlv, rsa_public_key_spki, validate_template_quality, BiometricTemplate,
    BiometricType, EmrtdDataError, MAX_EMRTD_DATA_BYTES,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u8,
    ef_com: Value,
    dg1: Vec<Value>,
    dg2: Value,
    biometric_templates: Vec<Value>,
    dg15: Value,
    invalid: Vec<Value>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/emrtd_data_vectors.json"))
        .expect("valid language-neutral eMRTD data vectors")
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("hex string")).expect("valid fixture hex")
}

#[test]
fn elementary_files_match_language_neutral_vectors() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);

    let parsed = parse_ef_com(&bytes(&fixture.ef_com["hex"])).unwrap();
    assert_eq!(
        parsed.lds_version.as_deref(),
        fixture.ef_com["lds_version"].as_str()
    );
    assert_eq!(
        parsed.unicode_version.as_deref(),
        fixture.ef_com["unicode_version"].as_str()
    );
    assert_eq!(
        serde_json::to_value(parsed.data_groups).unwrap(),
        fixture.ef_com["data_groups"]
    );

    for vector in fixture.dg1 {
        let mrz = vector["mrz"].as_str().unwrap();
        let inner = encode_tlv(&[0x5f, 0x1f], mrz.as_bytes());
        let dg1 = encode_tlv(&[0x61], &inner);
        let parsed =
            parse_ef_dg1(&dg1).unwrap_or_else(|error| panic!("{}: {error}", vector["name"]));
        assert_eq!(serde_json::to_value(parsed).unwrap(), vector["expected"]);
    }

    let parsed = parse_ef_dg2(&bytes(&fixture.dg2["hex"])).unwrap();
    assert_eq!(
        parsed.biometric_type,
        fixture.dg2["expected"]["biometric_type"]
    );
    assert_eq!(
        parsed.biometric_subtype,
        fixture.dg2["expected"]["biometric_subtype"]
    );
    assert_eq!(parsed.format_owner, fixture.dg2["expected"]["format_owner"]);
    assert_eq!(parsed.format_type, fixture.dg2["expected"]["format_type"]);
    assert_eq!(
        hex::encode_upper(parsed.data),
        fixture.dg2["expected"]["data_hex"]
    );
}

#[test]
fn biometric_templates_and_quality_match_language_neutral_vectors() {
    for vector in fixture().biometric_templates {
        let kind = match vector["type"].as_str().unwrap() {
            "facial_image" => BiometricType::FacialImage,
            "fingerprint" => BiometricType::Fingerprint,
            "iris" => BiometricType::Iris,
            other => panic!("unknown fixture type {other}"),
        };
        let parsed = parse_biometric_template(&bytes(&vector["hex"]), kind).unwrap();
        let expected = &vector["expected"];
        match &parsed {
            BiometricTemplate::Facial(value) => {
                assert_eq!(value.image_width, expected["width"]);
                assert_eq!(value.image_height, expected["height"]);
                assert_eq!(value.quality, expected["quality"]);
                assert_eq!(
                    serde_json::to_value(value.image_format).unwrap(),
                    expected["image_format"]
                );
                assert_eq!(hex::encode_upper(&value.image_data), expected["image_hex"]);
            }
            BiometricTemplate::Fingerprint(value) => {
                assert_eq!(value.image_width, expected["width"]);
                assert_eq!(value.image_height, expected["height"]);
                assert_eq!(value.finger_quality, expected["quality"]);
                assert_eq!(
                    hex::encode_upper(value.image_data.as_deref().unwrap()),
                    expected["image_hex"]
                );
            }
            BiometricTemplate::Iris(value) => {
                assert_eq!(value.image_width, expected["width"]);
                assert_eq!(value.image_height, expected["height"]);
                assert_eq!(value.iris_radius, expected["iris_radius"]);
                assert_eq!(
                    serde_json::to_value(value.image_format).unwrap(),
                    expected["image_format"]
                );
                assert_eq!(hex::encode_upper(&value.image_data), expected["image_hex"]);
            }
        }
        let quality = validate_template_quality(&parsed);
        let expected_quality = expected["overall_quality"].as_f64().unwrap();
        assert!((quality.overall_quality - expected_quality).abs() < f64::EPSILON);
        assert_eq!(
            quality.issues.len() as u64,
            expected["issue_count"].as_u64().unwrap()
        );
    }
}

#[test]
fn dg15_matches_language_neutral_vector() {
    let vector = fixture().dg15;
    let parsed = parse_dg15(&bytes(&vector["hex"])).unwrap();
    assert_eq!(parsed.algorithm, "RSA");
    assert_eq!(parsed.algorithm_oid, vector["algorithm_oid"]);
    assert_eq!(parsed.key_size, vector["key_size"]);
    assert_eq!(parsed.public_exponent, vector["public_exponent"]);
    assert_eq!(parsed.modulus, vector["modulus"]);
    assert_eq!(parsed.fingerprint_sha256, vector["fingerprint_sha256"]);
    assert!(parsed.valid_for_active_authentication);
    assert_eq!(
        rsa_public_key_spki(&parsed.modulus, parsed.public_exponent).unwrap(),
        parsed.spki_der
    );
    assert_eq!(inspect_rsa_public_key(&parsed.spki_der).unwrap(), parsed);
}

#[test]
fn malformed_and_oversized_inputs_fail_closed() {
    for vector in fixture().invalid {
        let data = bytes(&vector["hex"]);
        let result = match vector["operation"].as_str().unwrap() {
            "tlv" => parse_tlv(&data, 0).map(|_| ()),
            "dg1" => parse_ef_dg1(&data).map(|_| ()),
            "dg2" => parse_ef_dg2(&data).map(|_| ()),
            "facial_image" => {
                parse_biometric_template(&data, BiometricType::FacialImage).map(|_| ())
            }
            "dg15" => parse_dg15(&data).map(|_| ()),
            other => panic!("unknown invalid operation {other}"),
        };
        let error = result.expect_err("invalid vector must fail closed");
        assert!(
            error
                .to_string()
                .starts_with(vector["code"].as_str().unwrap()),
            "unexpected error: {error}"
        );
    }

    let oversized = vec![0u8; MAX_EMRTD_DATA_BYTES + 1];
    assert!(matches!(
        parse_tlv(&oversized, 0),
        Err(EmrtdDataError::Oversized(_))
    ));
}

fn encode_tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut output = tag.to_vec();
    if value.len() < 128 {
        output.push(value.len() as u8);
    } else {
        output.extend_from_slice(&[0x81, value.len() as u8]);
    }
    output.extend_from_slice(value);
    output
}
