//! RSA public verification vectors for PKCS#1 v1.5 and PSS.
//!
//! The synthetic 2048-bit public keys and signed messages are checked in as
//! public data. No private key, key generation, or local signing is used here.

use marty_crypto::rsa::{
    get_rsa_key_size, verify_pkcs1_sha256, verify_pkcs1_sha384, verify_pkcs1_sha512,
    verify_pss_sha256, verify_pss_sha384, verify_pss_sha512,
};
use marty_crypto::CryptoResult;
use serde_json::Value;

type Verifier = fn(&[u8], &[u8], &[u8]) -> CryptoResult<bool>;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/rsa_verification_public.json")).unwrap()
}

fn public_bytes(vectors: &Value, field: &str) -> Vec<u8> {
    hex::decode(vectors[field].as_str().unwrap()).unwrap()
}

#[test]
fn rsa_public_key_has_expected_size() {
    let vectors = vectors();
    let public_key = public_bytes(&vectors, "public_key_spki_der_hex");
    assert_eq!(get_rsa_key_size(&public_key).unwrap(), 2048);
}

#[test]
fn pkcs1_vectors_verify_all_supported_hashes() {
    let vectors = vectors();
    let public_key = public_bytes(&vectors, "public_key_spki_der_hex");
    let message = vectors["message"].as_str().unwrap().as_bytes();
    for (field, verify) in [
        ("rs256_signature_hex", verify_pkcs1_sha256 as Verifier),
        ("rs384_signature_hex", verify_pkcs1_sha384 as Verifier),
        ("rs512_signature_hex", verify_pkcs1_sha512 as Verifier),
    ] {
        let signature = public_bytes(&vectors, field);
        assert_eq!(signature.len(), 256, "{field}");
        assert!(verify(&public_key, message, &signature).unwrap(), "{field}");
        assert!(
            !verify(&public_key, b"wrong message", &signature).unwrap(),
            "{field}"
        );
    }
}

#[test]
fn pss_vectors_verify_all_supported_hashes() {
    let vectors = vectors();
    let public_key = public_bytes(&vectors, "public_key_spki_der_hex");
    let message = vectors["message"].as_str().unwrap().as_bytes();
    for (field, verify) in [
        ("ps256_signature_hex", verify_pss_sha256 as Verifier),
        ("ps384_signature_hex", verify_pss_sha384 as Verifier),
        ("ps512_signature_hex", verify_pss_sha512 as Verifier),
    ] {
        let signature = public_bytes(&vectors, field);
        assert_eq!(signature.len(), 256, "{field}");
        assert!(verify(&public_key, message, &signature).unwrap(), "{field}");
        assert!(
            !verify(&public_key, b"wrong message", &signature).unwrap(),
            "{field}"
        );
    }
}

#[test]
fn tampered_signatures_and_wrong_key_are_rejected() {
    let vectors = vectors();
    let public_key = public_bytes(&vectors, "public_key_spki_der_hex");
    let other_public_key = public_bytes(&vectors, "other_public_key_spki_der_hex");
    let message = vectors["message"].as_str().unwrap().as_bytes();
    for (field, verify) in [
        ("rs256_signature_hex", verify_pkcs1_sha256 as Verifier),
        ("ps256_signature_hex", verify_pss_sha256 as Verifier),
    ] {
        let mut signature = public_bytes(&vectors, field);
        assert!(
            !verify(&other_public_key, message, &signature).unwrap(),
            "{field}"
        );
        signature[100] ^= 0x01;
        assert!(
            !verify(&public_key, message, &signature).unwrap(),
            "{field}"
        );
    }
}

#[test]
fn signatures_do_not_cross_verification_schemes() {
    let vectors = vectors();
    let public_key = public_bytes(&vectors, "public_key_spki_der_hex");
    let message = vectors["message"].as_str().unwrap().as_bytes();
    let pkcs1 = public_bytes(&vectors, "rs256_signature_hex");
    let pss = public_bytes(&vectors, "ps256_signature_hex");
    assert!(!verify_pss_sha256(&public_key, message, &pkcs1).unwrap());
    assert!(!verify_pkcs1_sha256(&public_key, message, &pss).unwrap());
}

#[test]
fn distinct_pss_signatures_for_one_message_both_verify() {
    let vectors = vectors();
    let public_key = public_bytes(&vectors, "public_key_spki_der_hex");
    let message = vectors["message"].as_str().unwrap().as_bytes();
    let first = public_bytes(&vectors, "ps256_signature_hex");
    let second = public_bytes(&vectors, "ps256_alternate_signature_hex");
    assert_ne!(first, second);
    assert!(verify_pss_sha256(&public_key, message, &first).unwrap());
    assert!(verify_pss_sha256(&public_key, message, &second).unwrap());
}
