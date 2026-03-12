//! RSA conformance tests (FIPS 186-4 / PKCS#1 v2.2).
//!
//! Tests cover:
//!   - PKCS#1 v1.5 sign/verify round-trips (RS256, RS384, RS512) — FIPS 186-4 §5
//!   - RSA-PSS sign/verify round-trips (PS256, PS384, PS512) — FIPS 186-4 §5.5
//!   - Signature rejection on tampered data or wrong key
//!   - Rejection of PKCS#1 signature under PSS verifier and vice-versa
//!   - Key-size enforcement: reject < 2048-bit keys
//!
//! NOTE: RSA signing is randomised; we verify sign→verify round-trip rather
//!       than testing against a fixed known signature byte-string.

use marty_crypto::rsa::{
    generate_rsa_keypair, sign_pkcs1_sha256, sign_pkcs1_sha384, sign_pkcs1_sha512,
    sign_pss_sha256, sign_pss_sha384, sign_pss_sha512, verify_pkcs1_sha256,
    verify_pkcs1_sha384, verify_pkcs1_sha512, verify_pss_sha256, verify_pss_sha384,
    verify_pss_sha512,
};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Returns (private_key_der, public_key_der) for a 2048-bit RSA key.
fn rsa2048_keypair() -> (Vec<u8>, Vec<u8>) {
    generate_rsa_keypair(2048).expect("2048-bit key generation failed")
}

// ── key generation ───────────────────────────────────────────────────────────

/// FIPS 186-4: a 2048-bit key is the minimum allowed for new keys.
#[test]
fn rsa_keygen_2048_produces_valid_keys() {
    let (priv_der, pub_der) = rsa2048_keypair();
    // PKCS#8 DER has a minimum overhead (~26 bytes).  2048-bit key is 256 bytes
    // of modulus → private key DER > 600 bytes; public SPKI DER > 250 bytes.
    assert!(priv_der.len() > 600, "private key too short: {} bytes", priv_der.len());
    assert!(pub_der.len() > 250, "public key too short: {} bytes", pub_der.len());
}

/// Key-size guard: reject < 2048-bit keys.
#[test]
fn rsa_keygen_rejects_1024_bit_keys() {
    let result = generate_rsa_keypair(1024);
    assert!(result.is_err(), "1024-bit key should be rejected");
}

// ── PKCS#1 v1.5 round-trips (RS256 / RS384 / RS512) ──────────────────────────

/// RS256 — sign/verify round-trip; correct signature verifies.
#[test]
fn rsa_pkcs1_rs256_sign_verify_roundtrip() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"FIPS 186-4 RS256 test message";

    let sig = sign_pkcs1_sha256(&priv_der, message).expect("RS256 sign");
    assert_eq!(sig.len(), 256, "2048-bit RS256 signature should be 256 bytes");

    let valid = verify_pkcs1_sha256(&pub_der, message, &sig)
        .expect("RS256 verify should not error");
    assert!(valid, "RS256 signature should verify successfully");
}

/// RS384 — sign/verify round-trip.
#[test]
fn rsa_pkcs1_rs384_sign_verify_roundtrip() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"FIPS 186-4 RS384 test message";

    let sig = sign_pkcs1_sha384(&priv_der, message).expect("RS384 sign");
    assert_eq!(sig.len(), 256);

    let valid = verify_pkcs1_sha384(&pub_der, message, &sig)
        .expect("RS384 verify");
    assert!(valid);
}

/// RS512 — sign/verify round-trip.
#[test]
fn rsa_pkcs1_rs512_sign_verify_roundtrip() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"FIPS 186-4 RS512 test message";

    let sig = sign_pkcs1_sha512(&priv_der, message).expect("RS512 sign");
    assert_eq!(sig.len(), 256);

    let valid = verify_pkcs1_sha512(&pub_der, message, &sig)
        .expect("RS512 verify");
    assert!(valid);
}

// ── PSS round-trips (PS256 / PS384 / PS512) ───────────────────────────────────

/// PS256 — RSA-PSS sign/verify round-trip.
#[test]
fn rsa_pss_ps256_sign_verify_roundtrip() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"FIPS 186-4 PS256 test message";

    let sig = sign_pss_sha256(&priv_der, message).expect("PS256 sign");
    assert_eq!(sig.len(), 256);

    let valid = verify_pss_sha256(&pub_der, message, &sig)
        .expect("PS256 verify");
    assert!(valid, "PS256 signature should verify");
}

/// PS384 — RSA-PSS sign/verify round-trip.
#[test]
fn rsa_pss_ps384_sign_verify_roundtrip() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"FIPS 186-4 PS384 test message";

    let sig = sign_pss_sha384(&priv_der, message).expect("PS384 sign");
    assert_eq!(sig.len(), 256);

    let valid = verify_pss_sha384(&pub_der, message, &sig)
        .expect("PS384 verify");
    assert!(valid);
}

/// PS512 — RSA-PSS sign/verify round-trip.
#[test]
fn rsa_pss_ps512_sign_verify_roundtrip() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"FIPS 186-4 PS512 test message";

    let sig = sign_pss_sha512(&priv_der, message).expect("PS512 sign");
    assert_eq!(sig.len(), 256);

    let valid = verify_pss_sha512(&pub_der, message, &sig)
        .expect("PS512 verify");
    assert!(valid);
}

// ── tamper-detection ─────────────────────────────────────────────────────────

/// RS256: flipping one bit in the signature must cause verification failure.
#[test]
fn rsa_pkcs1_rs256_rejects_tampered_signature() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"tamper detection test";

    let mut sig = sign_pkcs1_sha256(&priv_der, message).expect("RS256 sign");
    sig[128] ^= 0x01; // flip a bit in the middle of the signature

    let valid = verify_pkcs1_sha256(&pub_der, message, &sig)
        .unwrap_or(false);
    assert!(!valid, "tampered RS256 signature must not verify");
}

/// PS256: flipping one bit in the signature must cause verification failure.
#[test]
fn rsa_pss_ps256_rejects_tampered_signature() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"tamper detection test PSS";

    let mut sig = sign_pss_sha256(&priv_der, message).expect("PS256 sign");
    sig[100] ^= 0x80;

    let valid = verify_pss_sha256(&pub_der, message, &sig)
        .unwrap_or(false);
    assert!(!valid, "tampered PS256 signature must not verify");
}

/// RS256: verification with the wrong message must fail.
#[test]
fn rsa_pkcs1_rs256_rejects_wrong_message() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"correct message";
    let wrong   = b"different message";

    let sig = sign_pkcs1_sha256(&priv_der, message).expect("RS256 sign");

    let valid = verify_pkcs1_sha256(&pub_der, wrong, &sig)
        .unwrap_or(false);
    assert!(!valid, "RS256 signature should not verify under wrong message");
}

/// RS256: verification with the wrong key must fail.
#[test]
fn rsa_pkcs1_rs256_rejects_wrong_key() {
    let (priv_der1, _) = rsa2048_keypair();
    let (_, pub_der2)  = rsa2048_keypair();
    let message = b"wrong key test";

    let sig = sign_pkcs1_sha256(&priv_der1, message).expect("RS256 sign");

    let valid = verify_pkcs1_sha256(&pub_der2, message, &sig)
        .unwrap_or(false);
    assert!(!valid, "RS256 signature should not verify under a different public key");
}

// ── cross-scheme rejection ────────────────────────────────────────────────────

/// A PKCS#1 v1.5 signature must not pass PSS verification.
#[test]
fn rsa_pkcs1_signature_fails_pss_verifier() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"cross-scheme rejection test";

    let pkcs1_sig = sign_pkcs1_sha256(&priv_der, message).expect("RS256 sign");

    let result = verify_pss_sha256(&pub_der, message, &pkcs1_sig);
    let valid = result.unwrap_or(false);
    assert!(!valid, "PKCS#1 signature must not verify under PSS verifier");
}

/// A PSS signature must not pass PKCS#1 v1.5 verification.
#[test]
fn rsa_pss_signature_fails_pkcs1_verifier() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"cross-scheme rejection test 2";

    let pss_sig = sign_pss_sha256(&priv_der, message).expect("PS256 sign");

    let result = verify_pkcs1_sha256(&pub_der, message, &pss_sig);
    let valid = result.unwrap_or(false);
    assert!(!valid, "PSS signature must not verify under PKCS#1 verifier");
}

// ── PSS is randomised (non-deterministic) ────────────────────────────────────

/// PSS produces a DIFFERENT signature each time (randomised salt).
/// Both signatures must verify, but they must not be identical.
#[test]
fn rsa_pss_ps256_is_randomised() {
    let (priv_der, pub_der) = rsa2048_keypair();
    let message = b"PSS randomisation test";

    let sig1 = sign_pss_sha256(&priv_der, message).expect("sig1");
    let sig2 = sign_pss_sha256(&priv_der, message).expect("sig2");

    // Both must verify
    assert!(verify_pss_sha256(&pub_der, message, &sig1).unwrap_or(false));
    assert!(verify_pss_sha256(&pub_der, message, &sig2).unwrap_or(false));

    // They should differ (randomised salt)
    assert_ne!(sig1, sig2, "Two PSS signatures of the same message should differ");
}
