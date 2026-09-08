#![cfg(not(zk_mock))]

use marty_zkp::{AttributeRequest, Circuit, MdocProveInput, Verifier, ZkError};

const ONE_ATTRIBUTE_V7: &[u8] = include_bytes!(
    "../vendor/longfellow-zk/lib/circuits/mdoc/circuits/8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"
);

#[test]
fn accepts_the_registered_circuit_archive() {
    Circuit::from_bytes(ONE_ATTRIBUTE_V7.to_vec(), 1).expect("registered circuit must load");
}

#[test]
fn rejects_a_registered_archive_for_another_attribute_count() {
    assert!(matches!(
        Circuit::from_bytes(ONE_ATTRIBUTE_V7.to_vec(), 2),
        Err(ZkError::InvalidInput)
    ));
}

#[test]
fn rejects_a_tampered_circuit_archive() {
    let mut bytes = ONE_ATTRIBUTE_V7.to_vec();
    let last = bytes.last_mut().expect("non-empty fixture");
    *last ^= 1;
    assert!(matches!(
        Circuit::from_bytes(bytes, 1),
        Err(ZkError::InvalidInput)
    ));
}

fn verify_with_attribute_cbor(cbor_value: Vec<u8>) -> Result<bool, ZkError> {
    let circuit =
        Circuit::from_bytes(ONE_ATTRIBUTE_V7.to_vec(), 1).expect("registered circuit must load");
    let input = MdocProveInput {
        mdoc: Vec::new(),
        issuer_pkx: "0x2c80c10bf70f63bddcc41ea20d76a22ecba2a97fa8811bf19d572433b12c0c1f"
            .to_string(),
        issuer_pky: "0x3f994c043be7e17dd08387281bac0c37a529361b3cb36a0fac38d41ac066f903"
            .to_string(),
        transcript: vec![0xf6],
        attributes: vec![AttributeRequest::new(
            "org.iso.18013.5.1",
            "age_over_18",
            cbor_value,
        )],
        now: "2026-09-08T00:00:00Z".to_string(),
        doc_type: "org.iso.18013.5.1.mDL".to_string(),
    };

    // The one-byte proof is intentionally too short. A valid CBOR value reaches
    // that later check; malformed or unsupported CBOR is rejected first.
    Verifier::verify(&circuit, &input, &[1])
}

#[test]
fn cbor_validation_preserves_supported_mdoc_value_types() {
    let mut full_date = vec![0xd9, 0x03, 0xec, 0x6a];
    full_date.extend_from_slice(b"1971-09-01");
    let mut date_time = vec![0xc0, 0x74];
    date_time.extend_from_slice(b"2023-11-02T09:00:00Z");

    for value in [
        vec![0x00],
        vec![0x20],
        vec![0xf4],
        vec![0xf5],
        vec![0x60],
        vec![0x61, b'a'],
        vec![0x40],
        vec![0x41, 0x01],
        full_date,
        date_time,
    ] {
        assert!(
            matches!(
                verify_with_attribute_cbor(value.clone()),
                Err(ZkError::VerifierError(8))
            ),
            "supported CBOR value must pass CBOR validation: {value:02x?}"
        );
    }
}

#[test]
fn cbor_validation_rejects_unsupported_or_malformed_values() {
    let mut short_full_date = vec![0xd9, 0x03, 0xec, 0x69];
    short_full_date.extend_from_slice(b"1971-09-0");
    let mut short_date_time = vec![0xc0, 0x73];
    short_date_time.extend_from_slice(b"2023-11-02T09:00:00");

    for value in [
        vec![],
        vec![0xf6],
        vec![0x80],
        vec![0xa0],
        vec![0x61],
        vec![0xf5, 0xf5],
        vec![0xc2, 0x40],
        vec![0xd9, 0x03, 0xec, 0x00],
        vec![0xc0, 0x00],
        short_full_date,
        short_date_time,
    ] {
        assert!(
            matches!(verify_with_attribute_cbor(value.clone()), Ok(false)),
            "unsupported or malformed CBOR must be rejected: {value:02x?}"
        );
    }
}
