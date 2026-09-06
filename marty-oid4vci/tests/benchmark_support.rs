#[path = "../src/benchmark_support/mdoc_payload.rs"]
mod payload;
#[path = "../src/benchmark_support/selectors.rs"]
mod selectors;

#[test]
fn payload_profiles_keep_labels_sizes_and_independent_cbor_expectations() {
    use payload::*;
    for (ordinal, class) in PayloadClass::ALL.into_iter().enumerate() {
        assert_eq!(class.code(), ordinal as u64 + 1);
        assert_eq!(PayloadClass::parse(class.label()), Some(class));
        for index in [0, 1, 2, 3, 4, 25, 26, 127, 511] {
            let json = json_value(class, index);
            let expected = expected_cbor_value(class, index);
            // Compare semantic values: serde_json's arbitrary_precision feature
            // uses a private number representation when serialized into CBOR.
            let actual = serde_json::to_value(expected).unwrap();
            assert_eq!(actual, json, "{} at {index}", class.label());
        }
    }
    assert_eq!(PayloadClass::parse("unknown"), None);
    assert_eq!(
        json_value(PayloadClass::LargePortrait, 0)
            .as_str()
            .unwrap()
            .len(),
        256 * 1024
    );
    assert_eq!(
        json_value(PayloadClass::MixedSize, 0)
            .as_str()
            .unwrap()
            .len(),
        64 * 1024
    );
    assert_eq!(
        json_value(PayloadClass::MixedSize, 4)
            .as_str()
            .unwrap()
            .len(),
        1024
    );
    assert_eq!(
        json_value(PayloadClass::SmallPrimitive, 3),
        serde_json::Value::Null
    );
    assert_eq!(repeated_ascii(3, 26), "AAA");
}
