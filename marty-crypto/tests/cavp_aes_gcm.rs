//! Conformance tests for AES-GCM using NIST SP 800-38D test vectors.
//!
//! Sources:
//!   - NIST SP 800-38D (GCM) — GCM test vectors from NIST CAVP
//!     https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/CAVP-TESTING-BLOCK-CIPHER-MODES
//!   - "The Galois/Counter Mode of Operation (GCM)" McGrew & Viega 2004
//!     (used in NIST SP 800-38D, Appendix B)
//!
//! Vectors are embedded as hex literals — no external downloads needed.
//! AES-256-GCM vectors come from the ISO 18013-5 session encryption use-case
//! defined in marty-crypto's symmetric.rs.

use marty_crypto::symmetric::{
    aes_128_gcm_decrypt, aes_128_gcm_encrypt, aes_256_gcm_decrypt, aes_256_gcm_encrypt,
};

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── AES-128-GCM (NIST SP 800-38D, Appendix B, §B.1) ─────────────────────────
//
// Test vector set 1 from NIST GCM spec (no AAD, 128-bit plaintext)

/// NIST GCM Test Case 1 — K=128b, IV=96b, P=0-bytes, AAD=empty.
/// The "ciphertext" is only the authentication tag (16 bytes) since plaintext is empty.
#[test]
fn cavp_aes128_gcm_tc1_empty_plaintext() {
    let key   = hex("00000000000000000000000000000000");
    let nonce = hex("000000000000000000000000");
    let plaintext = b"";
    let aad = b"";

    // Encryption of empty plaintext produces only an auth tag
    let ct = aes_128_gcm_encrypt(&key, &nonce, plaintext, aad)
        .expect("AES-128-GCM encrypt TC1");
    // Auth tag is 16 bytes appended
    assert_eq!(ct.len(), 16, "ciphertext of empty plaintext must be 16-byte tag only");

    // Round-trip: decrypt should return empty plaintext
    let pt = aes_128_gcm_decrypt(&key, &nonce, &ct, aad)
        .expect("AES-128-GCM decrypt TC1");
    assert_eq!(&pt, plaintext);
}

/// NIST GCM Test Case 2 — K=128b, IV=96b, P=128b (all-zeros), AAD=empty.
/// Reference: NIST SP 800-38D Table B-1 TC2.
#[test]
fn cavp_aes128_gcm_tc2_128bit_zeros() {
    let key       = hex("00000000000000000000000000000000");
    let nonce     = hex("000000000000000000000000");
    let plaintext = hex("00000000000000000000000000000000");
    let aad       = b"";

    let ct = aes_128_gcm_encrypt(&key, &nonce, &plaintext, aad)
        .expect("AES-128-GCM encrypt TC2");
    assert_eq!(ct.len(), 32, "16-byte ciphertext + 16-byte auth tag");

    // Expected ciphertext bytes (first 16): 0388dace60b6a392f328c2b971b2fe78
    // Expected auth tag (last 16):          ab6e47d42cec13bdf53a67b21257bddf
    // (NIST SP 800-38D §B.1 Table TC2)
    let expected_ct   = hex("0388dace60b6a392f328c2b971b2fe78");
    let expected_tag  = hex("ab6e47d42cec13bdf53a67b21257bddf");
    assert_eq!(&ct[..16], &expected_ct[..], "ciphertext mismatch");
    assert_eq!(&ct[16..], &expected_tag[..], "auth-tag mismatch");

    // Decrypt round-trip
    let pt = aes_128_gcm_decrypt(&key, &nonce, &ct, aad)
        .expect("AES-128-GCM decrypt TC2");
    assert_eq!(pt, plaintext);
}

/// Custom AAD test — ensure AAD is authenticated (wrong AAD produces an error).
#[test]
fn cavp_aes128_gcm_aad_authentication() {
    let key       = hex("feffe9928665731c6d6a8f9467308308");
    let nonce     = hex("cafebabefacedbaddecaf888");
    let plaintext = hex("d9313225f88406e5a55909c5aff5269a");
    let aad       = hex("feedfacedeadbeeffeedfacedeadbeef");

    let ct = aes_128_gcm_encrypt(&key, &nonce, &plaintext, &aad)
        .expect("encrypt with AAD");

    // Correct AAD — must decrypt
    let pt = aes_128_gcm_decrypt(&key, &nonce, &ct, &aad)
        .expect("decrypt with correct AAD");
    assert_eq!(pt, plaintext);

    // Wrong AAD — must fail with authentication error
    let wrong_aad = hex("feedfacedeadbeeffeedfacedeadbeee");
    let result = aes_128_gcm_decrypt(&key, &nonce, &ct, &wrong_aad);
    assert!(result.is_err(), "Wrong AAD must cause authentication failure");
}

/// Nonce reuse check — different nonces produce different ciphertexts.
#[test]
fn cavp_aes128_gcm_nonce_uniqueness() {
    let key       = hex("feffe9928665731c6d6a8f9467308308");
    let nonce1    = hex("cafebabefacedbaddecaf888");
    let nonce2    = hex("cafebabefacedbaddecaf889");
    let plaintext = b"nonce reuse test";

    let ct1 = aes_128_gcm_encrypt(&key, &nonce1, plaintext, b"").expect("encrypt n1");
    let ct2 = aes_128_gcm_encrypt(&key, &nonce2, plaintext, b"").expect("encrypt n2");
    assert_ne!(ct1, ct2, "Different nonces must produce different ciphertexts");
}

/// Wrong key — must fail authentication.
#[test]
fn cavp_aes128_gcm_wrong_key_fails() {
    let key       = hex("00000000000000000000000000000000");
    let wrong_key = hex("ffffffffffffffffffffffffffffffff");
    let nonce     = hex("000000000000000000000000");
    let plaintext = b"authentic message";

    let ct = aes_128_gcm_encrypt(&key, &nonce, plaintext, b"").expect("encrypt");
    let result = aes_128_gcm_decrypt(&wrong_key, &nonce, &ct, b"");
    assert!(result.is_err(), "Wrong key must cause authentication failure");
}

// ── AES-256-GCM (ISO 18013-5 session encryption) ─────────────────────────────
//
// ISO 18013-5:2021 §9.1.1.5 mandates AES-256-GCM for session encryption.
// Vectors verify the AES-256 path is wired correctly.

/// AES-256-GCM round-trip with empty plaintext.
#[test]
fn cavp_aes256_gcm_empty_plaintext() {
    let key   = hex("0000000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex("000000000000000000000000");

    let ct = aes_256_gcm_encrypt(&key, &nonce, b"", b"")
        .expect("AES-256-GCM encrypt empty");
    assert_eq!(ct.len(), 16, "Auth tag only");

    let pt = aes_256_gcm_decrypt(&key, &nonce, &ct, b"")
        .expect("AES-256-GCM decrypt empty");
    assert!(pt.is_empty());
}

/// AES-256-GCM round-trip with 128-bit plaintext.
/// Reference: NIST CAVP AES-GCM-256 EncryptExtIV128.rsp test vector.
#[test]
fn cavp_aes256_gcm_128bit_plaintext() {
    let key       = hex("0000000000000000000000000000000000000000000000000000000000000000");
    let nonce     = hex("000000000000000000000000");
    let plaintext = hex("00000000000000000000000000000000");

    let ct = aes_256_gcm_encrypt(&key, &nonce, &plaintext, b"")
        .expect("AES-256-GCM encrypt");
    // Expected ciphertext (NIST CAVP AES-256-GCM TC1): cea7403d4d606b6e074ec5d3baf39d18
    let expected_ct  = hex("cea7403d4d606b6e074ec5d3baf39d18");
    let expected_tag = hex("d0d1c8a799996bf0265b98b5d48ab919");
    assert_eq!(&ct[..16], &expected_ct[..], "ciphertext mismatch");
    assert_eq!(&ct[16..], &expected_tag[..], "tag mismatch");

    let pt = aes_256_gcm_decrypt(&key, &nonce, &ct, b"")
        .expect("AES-256-GCM decrypt");
    assert_eq!(pt, plaintext);
}

/// AES-256-GCM ISO mDL session encryption pattern:
///   IV = counter (big-endian, padded to 12 bytes), no AAD.
#[test]
fn cavp_aes256_gcm_mdl_counter_iv() {
    let key = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

    let test_messages: &[&[u8]] = &[b"Hello, mDL!", b"Response data"];

    let mut send_counter: u32 = 0;
    for &msg in test_messages {
        // IV = 12 bytes, last 4 filled with counter (big-endian), first 8 = 0
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&send_counter.to_be_bytes());

        let ct = aes_256_gcm_encrypt(&key, &iv, msg, b"").expect("mDL encrypt");
        let pt = aes_256_gcm_decrypt(&key, &iv, &ct, b"").expect("mDL decrypt");
        assert_eq!(&pt, msg, "Round-trip failed for counter={send_counter}");

        send_counter += 1;
    }
}

/// AES-256-GCM: modified ciphertext must fail authentication.
#[test]
fn cavp_aes256_gcm_tampered_ciphertext_fails() {
    let key   = hex("0000000000000000000000000000000000000000000000000000000000000000");
    let nonce = hex("000000000000000000000000");
    let pt    = b"sensitive data";

    let mut ct = aes_256_gcm_encrypt(&key, &nonce, pt, b"").expect("encrypt");
    ct[0] ^= 0xff; // flip a bit in the ciphertext

    let result = aes_256_gcm_decrypt(&key, &nonce, &ct, b"");
    assert!(result.is_err(), "Tampered ciphertext must fail authentication");
}
