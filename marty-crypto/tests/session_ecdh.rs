//! Ephemeral ECDH and mDL session agreement tests.

use marty_crypto::ecdh::{P256KeyPair, P384KeyPair, X25519KeyPair};

// X25519 session agreement

/// X25519: independent key generation must yield Diffie-Hellman agreement.
#[test]
fn session_x25519_key_agreement_round_trip() {
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
fn session_x25519_different_peers_different_secrets() {
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

// P-256 session agreement

/// P-256: key agreement symmetry.
#[test]
fn session_p256_ecdh_symmetry() {
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

// P-384 session agreement

/// P-384: key agreement symmetry.
#[test]
fn session_p384_ecdh_symmetry() {
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
fn session_p384_ecdh_different_peers() {
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

// ISO 18013-5 mDL ECDH session establishment
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
