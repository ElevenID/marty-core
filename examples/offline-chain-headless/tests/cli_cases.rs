use std::io::Write;
use std::process::{Command, Stdio};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::{json, Value};

fn fixtures() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let start = time::OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap();
    let end = time::OffsetDateTime::from_unix_timestamp(1_798_761_600).unwrap();
    let mut root_params = CertificateParams::default();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params.not_before = start;
    root_params.not_after = end + time::Duration::days(365);
    let root_key = KeyPair::generate().unwrap();
    let root = root_params.self_signed(&root_key).unwrap();

    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Leaf");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.not_before = start;
    leaf_params.not_after = end;
    let leaf = leaf_params
        .signed_by(
            &KeyPair::generate().unwrap(),
            &Issuer::from_params(&root_params, &root_key),
        )
        .unwrap();

    // A different key with the SAME subject name must not become trusted.
    let other = root_params
        .self_signed(&KeyPair::generate().unwrap())
        .unwrap();
    (
        leaf.der().to_vec(),
        root.der().to_vec(),
        other.der().to_vec(),
    )
}

fn request(chain: Vec<Vec<u8>>, anchor: Vec<u8>, time: &str) -> Value {
    json!({
        "chain_der_base64": chain.iter().map(|der| STANDARD.encode(der)).collect::<Vec<_>>(),
        "trust_anchor_der_base64": STANDARD.encode(anchor),
        "validation_time": time,
    })
}

fn run(input: &[u8]) -> (i32, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_marty-offline-chain-headless"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
    let response = serde_json::from_slice(&output.stdout).unwrap();
    (output.status.code().unwrap(), response)
}

#[test]
fn valid_chain() {
    let (leaf, root, _) = fixtures();
    let (exit, response) = run(
        request(vec![leaf, root.clone()], root, "2026-07-01T00:00:00Z")
            .to_string()
            .as_bytes(),
    );
    assert_eq!(exit, 0);
    assert_eq!(response["code"], "valid");
    assert_eq!(response["valid"], true);
}

#[test]
fn tampered_signature() {
    let (mut leaf, root, _) = fixtures();
    *leaf.last_mut().unwrap() ^= 1;
    let (exit, response) = run(
        request(vec![leaf, root.clone()], root, "2026-07-01T00:00:00Z")
            .to_string()
            .as_bytes(),
    );
    assert_eq!(exit, 1);
    assert_eq!(response["code"], "invalid_chain");
    assert_eq!(response["valid"], false);
}

#[test]
fn wrong_anchor() {
    let (leaf, root, other) = fixtures();
    let (exit, response) = run(request(vec![leaf, root], other, "2026-07-01T00:00:00Z")
        .to_string()
        .as_bytes());
    assert_eq!(exit, 1);
    assert!(response["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str().unwrap().contains("trust")));
}

#[test]
fn expiry_uses_supplied_time() {
    let (leaf, root, _) = fixtures();
    let (exit, response) = run(
        request(vec![leaf, root.clone()], root, "2027-07-01T00:00:00Z")
            .to_string()
            .as_bytes(),
    );
    assert_eq!(exit, 1);
    assert!(response["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str().unwrap().contains("expired")));
}

#[test]
fn malformed_input_is_distinct_from_invalid_chain() {
    let (exit, response) = run(b"not-json");
    assert_eq!(exit, 2);
    assert_eq!(response["code"], "invalid_request");
    let (leaf, root, _) = fixtures();
    let mut value = request(vec![leaf, root.clone()], root, "2026-07-01T00:00:00Z");
    value["chain_der_base64"][0] = json!(STANDARD.encode([1, 2, 3]));
    let (exit, response) = run(value.to_string().as_bytes());
    assert_eq!(exit, 2);
    assert_eq!(response["code"], "invalid_request");
}

#[test]
fn oversized_request_is_rejected() {
    let input = vec![b' '; marty_offline_chain_headless::MAX_REQUEST_BYTES + 1];
    let (exit, response) = run(&input);
    assert_eq!(exit, 2);
    assert_eq!(response["errors"][0], "request exceeds byte limit");
}

#[test]
fn valid_leaf_only_chain_uses_the_separate_anchor_and_explicit_offset() {
    let (leaf, root, _) = fixtures();
    let (exit, response) = run(request(vec![leaf], root, "2026-07-01T03:00:00+03:00")
        .to_string()
        .as_bytes());
    assert_eq!(exit, 0);
    assert_eq!(response["code"], "valid");
    assert_eq!(response["valid"], true);
}
