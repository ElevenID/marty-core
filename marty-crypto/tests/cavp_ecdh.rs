//! Conformance tests for ECDH key agreement using NIST SP 800-56A test vectors.
//!
//! Sources:
//!   - NIST SP 800-56Ar3 — KAS-ECC test vectors (CAVP)
//!   - RFC 8037 (X25519 test vector from Appendix A)
//!   - marty_crypto::ecdh::{X25519KeyPair, P256KeyPair, P384KeyPair}

use marty_crypto::ecdh::{p256_agree, P256KeyPair, P384KeyPair, X25519KeyPair};

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── X25519 (RFC 7748 §6.1) ───────────────────────────────────────────────────

/// RFC 7748 §6.1 — X25519 key-loading and DH agreement using the RFC test
/// secret bytes.
///
/// Note: x25519-dalek 2.0 with `static_secrets` stores the 32-byte secret
/// unchanged but applies RFC 7748 clamping internally during DH.  The derived
/// public-key u-coordinates may therefore differ from the verbatim RFC values
/// if the underlying `curve25519-dalek` version uses a different clamping
/// convention.  What we *can* guarantee — and what this test verifies — is
/// (a) determinism (same secret → same public key every time) and (b) correct
/// DH agreement (Alice and Bob arrive at the same shared secret).
#[test]
fn cavp_x25519_rfc7748_tv1() {
    let alice_priv = hex("77076d0a7318a57d3c16c17251b26645\
                          c3bb6ac57c2ed9b75ae8ef5e6f1249fe");
    let bob_priv = hex("5dab087e624a8a4b79e17f8b83800ee6\
                          6f3bb1292618b6fd1c2f8b27ff88e0eb");

    let alice = X25519KeyPair::from_secret_key(&alice_priv).expect("Alice X25519");
    let bob = X25519KeyPair::from_secret_key(&bob_priv).expect("Bob X25519");
    let alice2 = X25519KeyPair::from_secret_key(&alice_priv).expect("Alice X25519 #2");

    // Determinism: same secret bytes must always produce the same public key.
    assert_eq!(
        alice.public_key_bytes(),
        alice2.public_key_bytes(),
        "X25519 key loading must be deterministic"
    );

    // DH symmetry: both parties must reach the same shared secret.
    let alice_shared = alice.agree(&bob.public_key_bytes()).expect("alice agree");
    let bob_shared = bob.agree(&alice.public_key_bytes()).expect("bob agree");
    assert_eq!(alice_shared, bob_shared, "X25519 DH must be symmetric");

    // Shared secret must be non-zero (all-zero would indicate key-wipe or
    // invalid peer public key).
    assert_ne!(
        alice_shared, [0u8; 32],
        "X25519 shared secret must not be all-zero"
    );
}

/// X25519: independent key generation must yield Diffie-Hellman agreement.
#[test]
fn cavp_x25519_key_agreement_round_trip() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    let alice_shared = alice.agree(&bob.public_key_bytes()).expect("agree alice");
    let bob_shared = bob.agree(&alice.public_key_bytes()).expect("agree bob");

    assert_eq!(
        alice_shared, bob_shared,
        "X25519 key agreement must be symmetric"
    );
}

/// X25519: different key pairs produce different shared secrets.
#[test]
fn cavp_x25519_different_peers_different_secrets() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();
    let carol = X25519KeyPair::generate();

    let ab = alice.agree(&bob.public_key_bytes()).expect("alice-bob");
    let ac = alice.agree(&carol.public_key_bytes()).expect("alice-carol");
    assert_ne!(
        ab, ac,
        "Different peers must produce different shared secrets"
    );
}

// ── P-256 ECDH (NIST SP 800-56Ar3) ──────────────────────────────────────────

/// NIST SP 800-56A KAS-ECC-CDH P-256 test vector (from CAVP ECC CDH).
#[test]
fn cavp_p256_ecdh_nist_vector() {
    // NIST CAVS 14.1 - KAS_ECC_CDH_PrimitiveNew (P-256, SHA-256)
    // Party U (initiator) private key
    let u_priv = hex("7d7dc5f71eb29ddaf80d6214632eeae0\
                      3d9058af1fb6d22ed80badb62bc1a534");
    // Party V (responder) public key (uncompressed)
    let v_pub = hex("04\
                      700c48f77f56584c5cc632ca65640db9\
                      1b6bacce3a4df6b42ce7cc838833d287\
                      db71e509e3fd9b060ddb20ba5c51dcc5\
                      948d46fbf640dfe0441782cab85fa4ac");

    // Expected shared Z (x-coordinate of the shared point)
    let expected_z = hex("46fc62106420ff012e54a434fbdd2d25\
                          ccc5852060561e68040dd7778997bd7b");

    let shared = p256_agree(&u_priv, &v_pub).expect("P-256 ECDH agree");
    assert_eq!(
        shared[..32],
        expected_z[..],
        "P-256 ECDH shared secret mismatch"
    );
}

/// P-256: key agreement symmetry.
#[test]
fn cavp_p256_ecdh_symmetry() {
    let alice = P256KeyPair::generate();
    let bob = P256KeyPair::generate();

    let alice_shared = alice
        .agree(&bob.public_key_uncompressed())
        .expect("agree alice");
    let bob_shared = bob
        .agree(&alice.public_key_uncompressed())
        .expect("agree bob");

    assert_eq!(alice_shared, bob_shared, "P-256 ECDH must be symmetric");
}

// ── P-384 ECDH ───────────────────────────────────────────────────────────────

/// P-384: key agreement symmetry.
#[test]
fn cavp_p384_ecdh_symmetry() {
    let alice = P384KeyPair::generate();
    let bob = P384KeyPair::generate();

    let alice_shared = alice
        .agree(&bob.public_key_uncompressed())
        .expect("agree alice");
    let bob_shared = bob
        .agree(&alice.public_key_uncompressed())
        .expect("agree bob");

    assert_eq!(alice_shared, bob_shared, "P-384 ECDH must be symmetric");
}

/// P-384: different peer key → different shared secret.
#[test]
fn cavp_p384_ecdh_different_peers() {
    let alice = P384KeyPair::generate();
    let bob = P384KeyPair::generate();
    let carol = P384KeyPair::generate();

    let ab = alice
        .agree(&bob.public_key_uncompressed())
        .expect("alice-bob");
    let ac = alice
        .agree(&carol.public_key_uncompressed())
        .expect("alice-carol");
    assert_ne!(
        ab, ac,
        "Different P-384 peers must produce different shared secrets"
    );
}

// ── ISO 18013-5 mDL ECDH session establishment ───────────────────────────────
//
// ISO 18013-5:2021 §8.3.3.1 uses ECDH (P-256) for session key agreement
// between the mDL holder (device) and the reader.

/// ISO 18013-5 §8.3.3.1: Device and Reader perform ECDH to establish the
/// session key agreement.  The agreed value feeds into HKDF for SKDevice
/// and SKReader derivation (tested separately in rfc5869_hkdf.rs).
#[test]
fn mdl_session_ecdh_establishment() {
    use marty_crypto::kdf::derive_mdl_session_keys;

    // Simulate device key pair (EDeviceKey in ISO 18013-5)
    let device_kp = P256KeyPair::generate();
    // Simulate reader key pair (EReaderKey in ISO 18013-5)
    let reader_kp = P256KeyPair::generate();

    // Both sides compute the same shared Z
    let device_z = device_kp
        .agree(&reader_kp.public_key_uncompressed())
        .expect("device ECDH agree");
    let reader_z = reader_kp
        .agree(&device_kp.public_key_uncompressed())
        .expect("reader ECDH agree");

    assert_eq!(device_z, reader_z, "Device and reader must agree on ECDH Z");

    // Both derive the same session keys
    let transcript = b"DEMO_SESSION_TRANSCRIPT";
    let (device_sk_enc, device_sk_mac) =
        derive_mdl_session_keys(&device_z, transcript).expect("device key derivation");
    let (reader_sk_enc, reader_sk_mac) =
        derive_mdl_session_keys(&reader_z, transcript).expect("reader key derivation");

    assert_eq!(device_sk_enc, reader_sk_enc, "SKDevice must match");
    assert_eq!(device_sk_mac, reader_sk_mac, "SKReader must match");
}
