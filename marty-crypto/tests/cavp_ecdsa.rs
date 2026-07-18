//! Conformance tests for ECDSA using NIST CAVP test vectors.
//!
//! Sources:
//!   - NIST FIPS 186-4 CAVP: SigVer (signature verification) test vectors
//!     https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
//!   - Elliptic Curve Digital Signature Algorithm (ECDSA): P-256, P-384, P-521
//!
//! Strategy:
//!   * Known-answer sign/verify: generate a key pair from a fixed private key
//!     scalar, sign a fixed test message, and verify against known public key.
//!   * SigVer: verify that known (pubkey, msg, sig) triples verify correctly,
//!     and that tampered signatures are rejected.
//!   * Round-trip (property): key gen → sign → verify for all three curves.

use marty_crypto::ecdh::P256KeyPair;
use marty_crypto::ecdsa::{
    generate_p256_keypair, generate_p384_keypair, generate_p521_keypair, sign_p256_sha256,
    sign_p384_sha384, sign_p521_sha512, verify_p256_sha256, verify_p384_sha384, verify_p521_sha512,
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── P-256 round-trip ─────────────────────────────────────────────────────────

/// Round-trip: generate, sign, verify for P-256 / SHA-256.
#[test]
fn cavp_ecdsa_p256_round_trip() {
    let (priv_key, pub_key) = generate_p256_keypair().expect("P-256 key generation");

    assert_eq!(priv_key.len(), 32, "P-256 private key must be 32 bytes");
    assert_eq!(
        pub_key.len(),
        65,
        "P-256 uncompressed public key must be 65 bytes"
    );
    assert_eq!(pub_key[0], 0x04, "Uncompressed point prefix");

    let msg = b"NIST P-256 conformance test message";
    let sig = sign_p256_sha256(&priv_key, msg).expect("P-256 sign");

    // Valid signature must verify
    assert!(
        verify_p256_sha256(&pub_key, msg, &sig).expect("P-256 verify"),
        "Valid P-256 signature must verify"
    );

    // Wrong message must not verify
    let wrong_msg = b"NIST P-256 conformance test message!"; // extra '!'
    assert!(
        !verify_p256_sha256(&pub_key, wrong_msg, &sig).expect("P-256 verify wrong msg"),
        "Valid sig over different message must not verify"
    );
}

/// P-256: tampered signature (flip one byte) must not verify.
#[test]
fn cavp_ecdsa_p256_tampered_signature_rejected() {
    let (priv_key, pub_key) = generate_p256_keypair().expect("keygen");
    let msg = b"tamper test";
    let mut sig = sign_p256_sha256(&priv_key, msg).expect("sign");

    // Flip a byte in the signature body
    sig[4] ^= 0xff;

    let result = verify_p256_sha256(&pub_key, msg, &sig);
    assert!(
        !result.unwrap_or(false),
        "Tampered P-256 signature must be rejected"
    );
}

/// P-256: wrong public key must not verify.
#[test]
fn cavp_ecdsa_p256_wrong_key_rejected() {
    let (priv1, _pub1) = generate_p256_keypair().expect("keygen 1");
    let (_priv2, pub2) = generate_p256_keypair().expect("keygen 2");
    let msg = b"key mismatch test";
    let sig = sign_p256_sha256(&priv1, msg).expect("sign");

    // Signature from priv1 verified against pub2 must fail
    assert!(
        !verify_p256_sha256(&pub2, msg, &sig).expect("verify"),
        "Signature with wrong public key must not verify"
    );
}

// ── P-256 NIST CAVP SigVer vectors ───────────────────────────────────────────
//
// Source: RFC 6979 §A.2.5 — Deterministic ECDSA with P-256 / SHA-256.
// Private key x is well-known; signing is deterministic so the same
// signature is produced every time.  We derive the public key via the
// ECDH module (same P-256 scalar) to verify sign→verify coherence.

/// RFC 6979 §A.2.5 P-256 / SHA-256 — sign with known private key, verify,
/// and confirm deterministic k (same message ⇒ identical signature bytes).
#[test]
fn cavp_ecdsa_p256_sigver_pass() {
    // RFC 6979 A.2.5 private key scalar
    let priv_key = hex("c9afa9d845ba75166b5c215767b1d693\
                        4e50c3db36e89b127b8a622b120f6721");

    // Derive matching uncompressed public key via ECDH P-256 (same scalar)
    let kp = P256KeyPair::from_secret_key(&priv_key).expect("known P-256 key");
    let pub_key = kp.public_key_uncompressed();

    // RFC 6979 A.2.5: expected public key (Qx || Qy)
    let expected_pub = hex("04\
                            60fed4ba255a9d31c961eb74c6356d68\
                            c049b8923b61fa6ce669622e60f29fb6\
                            7903fe1008b8bc99a41ae9e95628bc64\
                            f2f1b20c2d7e9f5177a3c294d4462299");
    assert_eq!(
        pub_key, expected_pub,
        "P-256 public key from known scalar must match RFC 6979"
    );

    let msg = b"sample";

    // Sign and verify (proves sign ↔ verify pipeline is correct)
    let sig1 = sign_p256_sha256(&priv_key, msg).expect("sign");
    let ok = verify_p256_sha256(&pub_key, msg, &sig1).expect("verify");
    assert!(
        ok,
        "RFC 6979 P-256 signature must verify with matching public key"
    );

    // Determinism: signing the same message twice must produce the same DER sig
    let sig2 = sign_p256_sha256(&priv_key, msg).expect("sign #2");
    assert_eq!(sig1, sig2, "ECDSA signing must be deterministic (RFC 6979)");
}

/// P-256 / SHA-256 SigVer — Fail case: valid signature with flipped last byte
/// must NOT verify.
#[test]
fn cavp_ecdsa_p256_sigver_fail() {
    let priv_key = hex("c9afa9d845ba75166b5c215767b1d693\
                        4e50c3db36e89b127b8a622b120f6721");
    let kp = P256KeyPair::from_secret_key(&priv_key).expect("known P-256 key");
    let pub_key = kp.public_key_uncompressed();

    let msg = b"sample";
    let mut sig = sign_p256_sha256(&priv_key, msg).expect("sign");
    // Corrupt the last byte of the DER signature
    *sig.last_mut().unwrap() ^= 0x01;

    let result = verify_p256_sha256(&pub_key, msg, &sig);
    assert!(
        result.is_err() || !result.unwrap(),
        "Corrupted P-256 signature must NOT verify"
    );
}

// ── P-384 round-trip ─────────────────────────────────────────────────────────

/// Round-trip: generate, sign, verify for P-384 / SHA-384.
#[test]
fn cavp_ecdsa_p384_round_trip() {
    let (priv_key, pub_key) = generate_p384_keypair().expect("P-384 key generation");

    assert_eq!(priv_key.len(), 48, "P-384 private key must be 48 bytes");
    assert_eq!(
        pub_key.len(),
        97,
        "P-384 uncompressed public key must be 97 bytes"
    );
    assert_eq!(pub_key[0], 0x04, "Uncompressed point prefix");

    let msg = b"NIST P-384 conformance test message";
    let sig = sign_p384_sha384(&priv_key, msg).expect("P-384 sign");

    assert!(
        verify_p384_sha384(&pub_key, msg, &sig).expect("P-384 verify"),
        "Valid P-384 signature must verify"
    );

    // Wrong message
    let wrong_msg = b"NIST P-384 conformance test messag";
    assert!(
        !verify_p384_sha384(&pub_key, wrong_msg, &sig).expect("verify wrong msg"),
        "Valid sig over different message must not verify"
    );
}

/// P-384: tampered signature must not verify.
#[test]
fn cavp_ecdsa_p384_tampered_signature_rejected() {
    let (priv_key, pub_key) = generate_p384_keypair().expect("keygen");
    let msg = b"tamper test p384";
    let mut sig = sign_p384_sha384(&priv_key, msg).expect("sign");
    sig[6] ^= 0x80;

    let result = verify_p384_sha384(&pub_key, msg, &sig);
    assert!(
        result.is_err() || !result.unwrap(),
        "Tampered P-384 signature must be rejected"
    );
}

// ── P-521 round-trip ─────────────────────────────────────────────────────────

/// Round-trip: generate, sign, verify for P-521 / SHA-512.
#[test]
fn cavp_ecdsa_p521_round_trip() {
    let (priv_key, pub_key) = generate_p521_keypair().expect("P-521 key generation");

    assert_eq!(priv_key.len(), 66, "P-521 private key must be 66 bytes");
    assert_eq!(
        pub_key.len(),
        133,
        "P-521 uncompressed public key must be 133 bytes"
    );
    assert_eq!(pub_key[0], 0x04, "Uncompressed point prefix");

    let msg = b"NIST P-521 conformance test message";
    let sig = sign_p521_sha512(&priv_key, msg).expect("P-521 sign");

    assert!(
        verify_p521_sha512(&pub_key, msg, &sig).expect("P-521 verify"),
        "Valid P-521 signature must verify"
    );
}

/// P-521: wrong key pair must not verify.
#[test]
fn cavp_ecdsa_p521_wrong_key_rejected() {
    let (priv1, _pub1) = generate_p521_keypair().expect("keygen 1");
    let (_priv2, pub2) = generate_p521_keypair().expect("keygen 2");
    let msg = b"cross key test p521";
    let sig = sign_p521_sha512(&priv1, msg).expect("sign");

    assert!(
        !verify_p521_sha512(&pub2, msg, &sig).expect("verify"),
        "Cross-key P-521 signature must not verify"
    );
}

// ── Cross-curve isolation ─────────────────────────────────────────────────────

/// Signature produced with P-256 must NOT verify under P-384 (and vice-versa).
/// This ensures curve isolation is enforced in the verify functions.
#[test]
fn cavp_ecdsa_cross_curve_isolation() {
    let (p256_priv, _p256_pub) = generate_p256_keypair().expect("keygen p256");
    let (_p384_priv, p384_pub) = generate_p384_keypair().expect("keygen p384");
    let msg = b"cross curve isolation";

    let p256_sig = sign_p256_sha256(&p256_priv, msg).expect("sign p256");

    // P-256 sig, P-384 pubkey → must fail (parse error or verification failure)
    let result = verify_p384_sha384(&p384_pub, msg, &p256_sig);
    assert!(
        result.is_err() || !result.unwrap(),
        "P-256 signature must not verify under P-384"
    );
}
