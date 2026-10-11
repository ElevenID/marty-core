use chrono::{TimeZone, Utc};
use marty_offline_chain_consumer::verify_chain_offline;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

fn fixtures() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let start = time::OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap(); // 2026-01-01
    let end = time::OffsetDateTime::from_unix_timestamp(1_798_761_600).unwrap(); // 2027-01-01

    let mut root_params = CertificateParams::default();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Approved Test Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.not_before = start;
    root_params.not_after = end + time::Duration::days(365);
    let root_key = KeyPair::generate().unwrap();
    let root = root_params.self_signed(&root_key).unwrap();

    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Offline Test Leaf");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.not_before = start;
    leaf_params.not_after = end;
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = leaf_params
        .signed_by(&leaf_key, &Issuer::from_params(&root_params, &root_key))
        .unwrap();

    let mut other_params = CertificateParams::default();
    other_params
        .distinguished_name
        .push(DnType::CommonName, "Unapproved Test Root");
    other_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    other_params.not_before = start;
    other_params.not_after = end + time::Duration::days(365);
    let other = other_params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap();

    (
        leaf.der().to_vec(),
        root.der().to_vec(),
        other.der().to_vec(),
    )
}

fn moment(year: i32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, 7, 1, 0, 0, 0).unwrap()
}

#[test]
fn accepts_valid_local_chain() {
    let (leaf, root, _) = fixtures();
    let result = verify_chain_offline(&[leaf, root.clone()], &root, moment(2026)).unwrap();
    assert!(result.valid, "{:?}", result.errors);
}

#[test]
fn rejects_tampered_signature() {
    let (mut leaf, root, _) = fixtures();
    *leaf.last_mut().unwrap() ^= 1; // DER remains parseable; signature changes.
    let result = verify_chain_offline(&[leaf, root.clone()], &root, moment(2026)).unwrap();
    assert!(!result.valid);
    assert!(result
        .errors
        .iter()
        .any(|error| error.contains("Signature")));
}

#[test]
fn rejects_wrong_trust_anchor() {
    let (leaf, root, other) = fixtures();
    let result = verify_chain_offline(&[leaf, root], &other, moment(2026)).unwrap();
    assert!(!result.valid);
    assert!(result.errors.iter().any(|error| error.contains("trust")));
}

#[test]
fn rejects_expired_leaf_at_caller_supplied_time() {
    let (leaf, root, _) = fixtures();
    let result = verify_chain_offline(&[leaf, root.clone()], &root, moment(2027)).unwrap();
    assert!(!result.valid);
    assert!(result.errors.iter().any(|error| error.contains("expired")));
}
