//! Fixed-vector characterization for the verifier-only feature surface.

use marty_crypto::{ecdsa, ed25519};
use signature::Signer;

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

    let mut tampered_signature = signature;
    *tampered_signature
        .last_mut()
        .expect("non-empty P-256 signature") ^= 1;
    assert!(
        !ecdsa::verify_p256_sha256(&public_key, b"sample", &tampered_signature).unwrap_or(false)
    );
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

#[test]
fn rejects_rfc6979_signature_with_wrong_p256_key() {
    let signature = hex(concat!(
        "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
    ));
    let wrong_key = p256::ecdsa::SigningKey::from_slice(&[1; 32]).expect("valid test scalar");
    let wrong_public = wrong_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    assert!(!ecdsa::verify_p256_sha256(&wrong_public, b"sample", &signature).unwrap());
}

#[test]
fn p384_verifier_accepts_valid_and_rejects_tampered_inputs() {
    let signing_key =
        p384::ecdsa::SigningKey::from_slice(&[2; 48]).expect("valid P-384 test scalar");
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let message = b"P-384 verifier-only boundary";
    let signature: p384::ecdsa::Signature = signing_key.sign(message);
    let signature = signature.to_der().as_bytes().to_vec();

    assert!(ecdsa::verify_p384_sha384(&public_key, message, &signature).unwrap());
    assert!(!ecdsa::verify_p384_sha384(&public_key, b"wrong message", &signature).unwrap());

    let mut tampered = signature;
    *tampered.last_mut().expect("non-empty DER signature") ^= 1;
    assert!(!ecdsa::verify_p384_sha384(&public_key, message, &tampered).unwrap_or(false));
}

#[test]
fn p521_verifier_accepts_valid_and_rejects_wrong_key() {
    let mut scalar = [0; 66];
    scalar[65] = 3;
    let signing_key =
        p521::ecdsa::SigningKey::from_slice(&scalar).expect("valid P-521 test scalar");
    scalar[65] = 4;
    let wrong_key = p521::ecdsa::SigningKey::from_slice(&scalar).expect("valid P-521 test scalar");
    let public_key = p521::ecdsa::VerifyingKey::from(&signing_key)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let wrong_public = p521::ecdsa::VerifyingKey::from(&wrong_key)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let message = b"P-521 verifier-only boundary";
    let signature: p521::ecdsa::Signature = signing_key.sign(message);
    let signature = signature.to_der().as_bytes().to_vec();

    assert!(ecdsa::verify_p521_sha512(&public_key, message, &signature).unwrap());
    assert!(!ecdsa::verify_p521_sha512(&wrong_public, message, &signature).unwrap());
}

#[test]
fn verifier_rejects_cross_curve_signature_confusion() {
    let p256_key = p256::ecdsa::SigningKey::from_slice(&[5; 32]).expect("valid P-256 scalar");
    let p384_key = p384::ecdsa::SigningKey::from_slice(&[6; 48]).expect("valid P-384 scalar");
    let p384_public = p384_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let message = b"cross-curve verifier boundary";
    let p256_signature: p256::ecdsa::Signature = p256_key.sign(message);
    let p256_signature = p256_signature.to_der();

    assert!(
        !ecdsa::verify_p384_sha384(&p384_public, message, p256_signature.as_bytes())
            .unwrap_or(false)
    );
}
