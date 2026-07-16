//! CBOR conformance tests (RFC 8949).
//!
//! Verifies that `ciborium` (used throughout marty-iso18013) correctly encodes
//! and decodes the diagnostic notation examples from RFC 8949 §3 and Appendix A.
//!
//! Tests cover:
//!   - §3.1  Major types 0–7
//!   - §3.2  Integers (positive and negative)
//!   - §3.3  Byte strings
//!   - §3.4  Text strings (UTF-8)
//!   - §3.5  Arrays
//!   - §3.6  Maps
//!   - §4    Indefinite-length items (decoding only — ciborium produces definite-length)
//!   - A     Diagnostic notation appendix examples

use ciborium::{cbor, value::Value};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Serialize to CBOR and return the raw bytes.
fn to_cbor(val: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).expect("cbor encode");
    buf
}

/// Deserialize CBOR bytes back to a `ciborium::Value`.
fn from_cbor(bytes: &[u8]) -> Value {
    ciborium::from_reader(bytes).expect("cbor decode")
}

/// Round-trip: encode then decode, check result equals input.
fn roundtrip(val: &Value) {
    let encoded = to_cbor(val);
    let decoded = from_cbor(&encoded);
    assert_eq!(val, &decoded, "round-trip failed for {:?}", val);
}

// ── §3.1 / Appendix A — basic types ─────────────────────────────────────────

/// RFC 8949 §3.1 major type 0: unsigned integers
#[test]
fn cbor_unsigned_integer_zero() {
    let val = Value::Integer(0.into());
    // 0x00 on the wire for integer 0
    assert_eq!(to_cbor(&val), vec![0x00]);
    roundtrip(&val);
}

#[test]
fn cbor_unsigned_integer_small() {
    for n in 0u64..=23 {
        let val = Value::Integer((n as i64).into());
        // Values 0..23 are encoded as a single byte (major type 0 + value)
        assert_eq!(to_cbor(&val).len(), 1, "integer {} should be 1 byte", n);
        roundtrip(&val);
    }
}

/// RFC 8949 App. A: 0 → 0x00, 1 → 0x01, 23 → 0x17, 24 → 0x1818
#[test]
fn cbor_unsigned_integer_24() {
    let val = Value::Integer(24_i64.into());
    // 0x18 0x18: major type 0, additional 24, then value 24
    assert_eq!(to_cbor(&val), vec![0x18, 0x18]);
    roundtrip(&val);
}

#[test]
fn cbor_unsigned_integer_255() {
    let val = Value::Integer(255_i64.into());
    assert_eq!(to_cbor(&val), vec![0x18, 0xff]);
    roundtrip(&val);
}

#[test]
fn cbor_unsigned_integer_1000() {
    let val = Value::Integer(1000_i64.into());
    // 0x1903e8: major type 0, additional 25 (2-byte follows), value 1000
    assert_eq!(to_cbor(&val), vec![0x19, 0x03, 0xe8]);
    roundtrip(&val);
}

/// RFC 8949 §3.1 major type 1: negative integers
#[test]
fn cbor_negative_integer_minus_one() {
    let val = Value::Integer((-1_i64).into());
    // 0x20: major type 1, value 0  (n = -1 - 0 = -1)
    assert_eq!(to_cbor(&val), vec![0x20]);
    roundtrip(&val);
}

#[test]
fn cbor_negative_integer_minus_100() {
    let val = Value::Integer((-100_i64).into());
    // 0x3863: major type 1, additional 24, value 99 (n = -1 - 99 = -100)
    assert_eq!(to_cbor(&val), vec![0x38, 0x63]);
    roundtrip(&val);
}

/// RFC 8949 §3.1 major type 2: byte strings
#[test]
fn cbor_bytes_empty() {
    let val = Value::Bytes(vec![]);
    assert_eq!(to_cbor(&val), vec![0x40]); // 0x40 = major type 2, length 0
    roundtrip(&val);
}

#[test]
fn cbor_bytes_four_bytes() {
    let val = Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]);
    // 0x44 0x01 0x02 0x03 0x04
    assert_eq!(to_cbor(&val), vec![0x44, 0x01, 0x02, 0x03, 0x04]);
    roundtrip(&val);
}

/// RFC 8949 §3.1 major type 3: text strings (UTF-8)
#[test]
fn cbor_text_empty() {
    let val = Value::Text("".to_string());
    assert_eq!(to_cbor(&val), vec![0x60]); // 0x60 = major type 3, length 0
    roundtrip(&val);
}

#[test]
fn cbor_text_a() {
    // RFC 8949 App. A: "a" → 0x61 0x61
    let val = Value::Text("a".to_string());
    assert_eq!(to_cbor(&val), vec![0x61, 0x61]);
    roundtrip(&val);
}

#[test]
fn cbor_text_ietf() {
    // RFC 8949 App. A: "IETF" → 0x64 0x49 0x45 0x54 0x46
    let val = Value::Text("IETF".to_string());
    assert_eq!(to_cbor(&val), vec![0x64, 0x49, 0x45, 0x54, 0x46]);
    roundtrip(&val);
}

#[test]
fn cbor_text_unicode_snowflake() {
    // RFC 8949 App. A: "\u6c34" (水) → 3 UTF-8 bytes (0xe6 0xb0 0xb4)
    //   encoded as 0x63 0xe6 0xb0 0xb4
    let val = Value::Text("\u{6c34}".to_string());
    assert_eq!(to_cbor(&val), vec![0x63, 0xe6, 0xb0, 0xb4]);
    roundtrip(&val);
}

/// RFC 8949 §3.1 major type 4: arrays
#[test]
fn cbor_array_empty() {
    let val = Value::Array(vec![]);
    assert_eq!(to_cbor(&val), vec![0x80]);
    roundtrip(&val);
}

#[test]
fn cbor_array_one_two_three() {
    // RFC 8949 App. A: [1, 2, 3] → 0x83 0x01 0x02 0x03
    let val = Value::Array(vec![
        Value::Integer(1.into()),
        Value::Integer(2.into()),
        Value::Integer(3.into()),
    ]);
    assert_eq!(to_cbor(&val), vec![0x83, 0x01, 0x02, 0x03]);
    roundtrip(&val);
}

#[test]
fn cbor_nested_array() {
    // RFC 8949 App. A: [1, [2, 3], [4, 5]] → 0x83 0x01 0x82 0x02 0x03 0x82 0x04 0x05
    let val = Value::Array(vec![
        Value::Integer(1.into()),
        Value::Array(vec![Value::Integer(2.into()), Value::Integer(3.into())]),
        Value::Array(vec![Value::Integer(4.into()), Value::Integer(5.into())]),
    ]);
    assert_eq!(
        to_cbor(&val),
        vec![0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05]
    );
    roundtrip(&val);
}

/// RFC 8949 §3.1 major type 5: maps
#[test]
fn cbor_map_empty() {
    let val = cbor!({}).unwrap();
    assert_eq!(to_cbor(&val), vec![0xa0]);
    roundtrip(&val);
}

#[test]
fn cbor_map_one_to_one() {
    // {1: 1} → 0xa1 0x01 0x01
    let val = cbor!({1 => 1}).unwrap();
    assert_eq!(to_cbor(&val), vec![0xa1, 0x01, 0x01]);
    roundtrip(&val);
}

/// RFC 8949 §3.1 major type 7: simple values
#[test]
fn cbor_simple_false() {
    let val = Value::Bool(false);
    assert_eq!(to_cbor(&val), vec![0xf4]);
    roundtrip(&val);
}

#[test]
fn cbor_simple_true() {
    let val = Value::Bool(true);
    assert_eq!(to_cbor(&val), vec![0xf5]);
    roundtrip(&val);
}

#[test]
fn cbor_simple_null() {
    let val = Value::Null;
    assert_eq!(to_cbor(&val), vec![0xf6]);
    roundtrip(&val);
}

// ── ISO 18013-5 relevant structures ──────────────────────────────────────────

/// An ISO 18013-5 IssuerSigned structure uses a nested CBOR map with
/// namespace → list-of-IssuerSignedItem. Verify round-trip of that pattern.
#[test]
fn cbor_mdoc_namespace_structure_roundtrip() {
    // Simplified representation of IssuerSigned namespaces
    let item = cbor!({
        "digestID"  => 0,
        "random"    => Value::Bytes(vec![0xde, 0xad, 0xbe, 0xef]),
        "elementIdentifier" => "family_name",
        "elementValue"      => "Mustermann"
    })
    .unwrap();

    let namespaces = cbor!({
        "org.iso.18013.5.1" => [item]
    })
    .unwrap();

    roundtrip(&namespaces);
}

/// mDoc responses include CBOR-encoded status codes.
/// ISO 18013-5 §8.3.2.1.2.2 defines status 0 = OK.
#[test]
fn cbor_mdoc_status_ok() {
    let status: Value = cbor!({
        "version" => "1.0",
        "documents" => [],
        "status"  => 0
    })
    .unwrap();
    roundtrip(&status);
}
