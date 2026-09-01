#[path = "../benches/es256_signing_matrix/mod.rs"]
mod es256_signing_matrix;

use std::{
    ffi::OsString,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, MutexGuard},
};

use es256_signing_matrix::{
    expected_claim_names, expected_payload_value, matrix_claims, matrix_enabled, MatrixFormat,
    MatrixSelection, PayloadClass, ITEM_COUNTS, MATRIX_BATCH_SIZES,
};
use sha2::{Digest as _, Sha256};

const SELECTORS: [&str; 5] = [
    "MARTY_ES256_MATRIX",
    "MARTY_ES256_MATRIX_FORMATS",
    "MARTY_ES256_MATRIX_CLASSES",
    "MARTY_ES256_MATRIX_ITEM_COUNTS",
    "MARTY_ES256_MATRIX_BATCH_SIZES",
];
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn clean_environment() -> MutexGuard<'static, ()> {
    let guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for name in SELECTORS {
        unsafe { std::env::remove_var(name) };
    }
    guard
}

fn selection_panics(name: &str, value: impl Into<OsString>) {
    let _guard = clean_environment();
    unsafe { std::env::set_var(name, value.into()) };
    let result = catch_unwind(AssertUnwindSafe(MatrixSelection::from_env));
    unsafe { std::env::remove_var(name) };
    assert!(result.is_err(), "{name} malformed value must fail closed");
}

#[test]
fn selectors_accept_unset_all_canonical_and_trimmed_values() {
    let _guard = clean_environment();
    assert!(!matrix_enabled());
    let selection = MatrixSelection::from_env();
    assert_eq!(selection.formats, MatrixFormat::ALL);
    assert_eq!(selection.classes, PayloadClass::ALL);
    assert_eq!(selection.item_counts, ITEM_COUNTS);
    assert_eq!(selection.batch_sizes, MATRIX_BATCH_SIZES);

    unsafe {
        std::env::set_var("MARTY_ES256_MATRIX_FORMATS", " jwt_vc , mdoc ");
        std::env::set_var("MARTY_ES256_MATRIX_CLASSES", "small_primitive, mixed_size");
        std::env::set_var("MARTY_ES256_MATRIX_ITEM_COUNTS", "1, 512");
        std::env::set_var("MARTY_ES256_MATRIX_BATCH_SIZES", " 1 , 256 ");
    }
    let selection = MatrixSelection::from_env();
    assert_eq!(selection.formats, [MatrixFormat::JwtVc, MatrixFormat::Mdoc]);
    assert_eq!(
        selection.classes,
        [PayloadClass::SmallPrimitive, PayloadClass::MixedSize]
    );
    assert_eq!(selection.item_counts, [1, 512]);
    assert_eq!(selection.batch_sizes, [1, 256]);
}

#[test]
fn selectors_reject_malformed_unknown_duplicate_and_all_combinations() {
    for value in ["", ",jwt_vc", "jwt_vc,", "jwt_vc,,mdoc", "jwt_vc, ,mdoc"] {
        selection_panics("MARTY_ES256_MATRIX_FORMATS", value);
    }
    for value in ["unknown", "jwt_vc,jwt_vc", "all,jwt_vc", "jwt_vc,all"] {
        selection_panics("MARTY_ES256_MATRIX_FORMATS", value);
    }
    for value in [
        "unknown",
        "small_primitive,small_primitive",
        "all,mixed_size",
    ] {
        selection_panics("MARTY_ES256_MATRIX_CLASSES", value);
    }
    for value in ["01", "+1", "0", "1,1", "all,1", "1,,8"] {
        selection_panics("MARTY_ES256_MATRIX_ITEM_COUNTS", value);
    }
    for value in ["08", "0", "1,1", "all,1", "1,"] {
        selection_panics("MARTY_ES256_MATRIX_BATCH_SIZES", value);
    }
}

#[test]
fn selectors_reject_non_unicode_values() {
    #[cfg(windows)]
    let invalid = {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0xd800])
    };
    #[cfg(unix)]
    let invalid = {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(vec![0xff])
    };
    selection_panics("MARTY_ES256_MATRIX_FORMATS", invalid);
}

fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn fixture_generators_match_independent_literal_anchors() {
    assert_eq!(
        expected_payload_value(PayloadClass::SmallPrimitive, 0),
        serde_json::json!(0)
    );
    assert_eq!(
        expected_payload_value(PayloadClass::SmallPrimitive, 1),
        serde_json::json!(false)
    );
    assert_eq!(
        expected_payload_value(PayloadClass::SmallPrimitive, 2),
        serde_json::json!("value-0002")
    );
    assert_eq!(
        expected_payload_value(PayloadClass::SmallPrimitive, 4),
        serde_json::json!(true)
    );

    assert_eq!(
        expected_payload_value(PayloadClass::MediumNested, 3),
        serde_json::json!({
            "group": 3,
            "metadata": {"enabled": false, "sequence": 3, "label": "nested-0003"},
            "values": [3, 4, 5, 6]
        })
    );
    assert_eq!(
        expected_payload_value(PayloadClass::MediumNested, 4)["metadata"]["enabled"],
        true
    );

    let large = expected_payload_value(PayloadClass::LargePortrait, 0);
    let large = large.as_str().unwrap();
    assert!(large.starts_with("data:application/octet-stream;base64,"));
    assert_eq!(
        large.len(),
        "data:application/octet-stream;base64,".len() + 256 * 1024
    );
    assert_eq!(
        sha256_hex(large),
        "27a2d428a085f830c36ef99322662c4c0292ef9cfc72a1eea85e9d49199ec0ec"
    );
    assert_eq!(
        expected_payload_value(PayloadClass::LargePortrait, 1),
        serde_json::json!("value-0001")
    );

    let mixed_large = expected_payload_value(PayloadClass::MixedSize, 0);
    let mixed_large = mixed_large.as_str().unwrap();
    assert_eq!(mixed_large.len(), 64 * 1024);
    assert_eq!(
        sha256_hex(mixed_large),
        "156c38442089c1323d3e3ba549a6ac24341c47e8b6367bec4740c9b8c865826e"
    );
    assert_eq!(
        expected_payload_value(PayloadClass::MixedSize, 1),
        serde_json::json!({"sequence": 1, "flags": [true, false, false]})
    );
    assert_eq!(
        expected_payload_value(PayloadClass::MixedSize, 2),
        serde_json::json!(2)
    );
    assert_eq!(
        expected_payload_value(PayloadClass::MixedSize, 3),
        serde_json::json!("mixed-0003")
    );
    let mixed_medium = expected_payload_value(PayloadClass::MixedSize, 4);
    let mixed_medium = mixed_medium.as_str().unwrap();
    assert_eq!(mixed_medium.len(), 1024);
    assert_eq!(
        sha256_hex(mixed_medium),
        "7027515fbf2ca8d0dd931cbef2b7dda1716827cb4a0ef8adad10eaeb2c33860c"
    );
}

#[test]
fn fixtures_match_exact_values_and_bounded_shapes() {
    for class in PayloadClass::ALL {
        for item_count in [1, 512] {
            for format in MatrixFormat::ALL {
                let fixture = matrix_claims(format, class, item_count, 7);
                assert_eq!(fixture.claims.len(), item_count);
                assert_eq!(expected_claim_names(item_count).len(), item_count);
                assert_eq!(
                    fixture.subject_id.as_deref(),
                    Some("urn:example:benchmark-holder:7")
                );
                for index in 0..item_count {
                    let name = format!("benchmark_claim_{index:04}");
                    assert_eq!(
                        fixture.claims.get(&name),
                        Some(&expected_payload_value(class, index))
                    );
                }
                assert_eq!(
                    fixture.selective_disclosure_claims.len(),
                    if format.is_sd_jwt() { item_count } else { 0 }
                );
            }

            let serialized_lengths = (0..item_count)
                .map(|index| expected_payload_value(class, index).to_string().len())
                .collect::<Vec<_>>();
            match class {
                PayloadClass::SmallPrimitive => {
                    assert!(expected_payload_value(class, 0).is_number());
                    if item_count == 512 {
                        assert!(expected_payload_value(class, 1).is_boolean());
                        assert!(expected_payload_value(class, 2).is_string());
                        for index in 0..item_count {
                            let value = expected_payload_value(class, index);
                            assert!(match index % 3 {
                                0 => value.is_number(),
                                1 => value.is_boolean(),
                                _ => value.is_string(),
                            });
                        }
                    }
                    assert!(serialized_lengths.iter().all(|&length| length < 1024));
                }
                PayloadClass::MediumNested => {
                    for index in 0..item_count {
                        let value = expected_payload_value(class, index);
                        let object = value.as_object().unwrap();
                        assert_eq!(object.len(), 3);
                        assert!(object["group"].is_number());
                        let metadata = object["metadata"].as_object().unwrap();
                        assert_eq!(metadata.len(), 3);
                        assert!(metadata["enabled"].is_boolean());
                        assert!(metadata["sequence"].is_number());
                        assert!(metadata["label"].is_string());
                        let values = object["values"].as_array().unwrap();
                        assert_eq!(values.len(), 4);
                        assert!(values.iter().all(serde_json::Value::is_number));
                    }
                    assert!(serialized_lengths.iter().all(|&length| length < 1024));
                }
                PayloadClass::LargePortrait => {
                    assert_eq!(
                        expected_payload_value(class, 0).as_str().unwrap().len(),
                        "data:application/octet-stream;base64,".len() + 256 * 1024
                    );
                    assert_eq!(
                        serialized_lengths
                            .iter()
                            .filter(|&&length| length > 1024)
                            .count(),
                        1
                    );
                    for index in 1..item_count {
                        let value = expected_payload_value(class, index);
                        assert!(value.as_str().unwrap().starts_with("value-"));
                    }
                }
                PayloadClass::MixedSize => {
                    assert_eq!(
                        expected_payload_value(class, 0).as_str().unwrap().len(),
                        64 * 1024
                    );
                    assert!(serialized_lengths
                        .iter()
                        .all(|&length| length <= 64 * 1024 + 2));
                    if item_count == 512 {
                        for index in 1..item_count {
                            let value = expected_payload_value(class, index);
                            match index % 4 {
                                0 => assert_eq!(value.as_str().unwrap().len(), 1024),
                                1 => {
                                    let object = value.as_object().unwrap();
                                    assert!(object["sequence"].is_number());
                                    let flags = object["flags"].as_array().unwrap();
                                    assert_eq!(flags.len(), 3);
                                    assert!(flags.iter().all(serde_json::Value::is_boolean));
                                }
                                2 => assert!(value.is_number()),
                                _ => assert!(value.as_str().unwrap().starts_with("mixed-")),
                            }
                        }
                    }
                }
            }
        }
    }
}
