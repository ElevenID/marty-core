#![cfg(not(zk_mock))]

use marty_zkp::{Circuit, ZkError};

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
