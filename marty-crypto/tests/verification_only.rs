//! Fixed-vector characterization for the verifier-only feature surface.

use marty_crypto::{ecdsa, ed25519};

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(pair, 16).expect("valid hex")
        })
        .collect()
}

#[test]
fn verifies_rfc6979_p256_sha256_vector() {
    let public_key = hex(concat!(
        "04",
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    ));
    let signature = hex(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    ));

    assert!(ecdsa::verify_p256_sha256(&public_key, b"sample", &signature).unwrap());
    assert!(!ecdsa::verify_p256_sha256(&public_key, b"tampered", &signature).unwrap());
}

#[test]
fn verifies_rfc8032_ed25519_vector() {
    let public_key = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let signature = hex(concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));

    assert!(ed25519::verify(&public_key, b"", &signature).is_ok());
    assert!(ed25519::verify(&public_key, b"tampered", &signature).is_err());
}
