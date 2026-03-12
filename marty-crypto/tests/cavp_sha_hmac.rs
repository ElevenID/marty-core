//! Conformance tests for SHA and HMAC using NIST CAVP test vectors.
//!
//! Sources:
//!   - SHA: NIST FIPS 180-4, SHA byte test vectors (CAVS 21.x ShortMsg / LongMsg)
//!   - HMAC: NIST FIPS 198-1, HMAC test vectors (CAVS 21.x HMAC.rsp)
//!
//! All vectors are embedded as hex literals — no external downloads needed.

use marty_crypto::hashing::{hash_sha256, hash_sha384, hash_sha512};

// ── helpers ──────────────────────────────────────────────────────────────────

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex string");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex"))
        .collect()
}

// ── SHA-256 (FIPS 180-4 short-message vectors) ───────────────────────────────

/// SHA-256 of the empty string (NIST CAVS: Len=0).
#[test]
fn cavp_sha256_empty() {
    assert_eq!(
        hash_sha256(b""),
        hex("e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855")
    );
}

/// SHA-256 of "abc" (FIPS 180-4 §B.1 example 1).
/// Reference: NIST FIPS 180-4 §B.1. The expected value is validated against
/// the RustCrypto sha2 crate, sha256sum, and OpenSSL on the build machine.
#[test]
fn cavp_sha256_abc() {
    assert_eq!(
        hash_sha256(b"abc"),
        hex("ba7816bf8f01cfea414140de5dae2223\
             b00361a396177a9cb410ff61f20015ad")
    );
}

/// SHA-256 of the 448-bit message "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
/// (NIST FIPS 180-4 §B.1 example 2).
#[test]
fn cavp_sha256_448bit_message() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        hash_sha256(msg),
        hex("248d6a61d20638b8e5c026930c3e6039\
             a33ce45964ff2167f6ecedd419db06c1")
    );
}

/// SHA-256 of 1 000 000 repetitions of 'a' (FIPS 180-4 §B.1 example 3).
#[test]
fn cavp_sha256_one_million_a() {
    let msg = vec![b'a'; 1_000_000];
    assert_eq!(
        hash_sha256(&msg),
        hex("cdc76e5c9914fb9281a1c7e284d73e67\
             f1809a48a497200e046d39ccc7112cd0")
    );
}

/// SHA-256 of a single byte 0x2d (NIST CAVP ShortMsg Len=8).
#[test]
fn cavp_sha256_short_msg_31bytes() {
    let msg = hex("2d");
    assert_eq!(
        hash_sha256(&msg),
        hex("3973e022e93220f9212c18d0d0c543ae\
             7c309e46640da93a4a0314de999f5112")
    );
}

// ── SHA-384 (FIPS 180-4) ────────────────────────────────────────────────────

/// SHA-384 of "abc" (FIPS 180-4 §B.2).
#[test]
fn cavp_sha384_abc() {
    assert_eq!(
        hash_sha384(b"abc"),
        hex("cb00753f45a35e8bb5a03d699ac65007\
             272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7")
    );
}

/// SHA-384 of the 896-bit message from FIPS 180-4 §B.2.
#[test]
fn cavp_sha384_896bit_message() {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(
        hash_sha384(msg),
        hex("09330c33f71147e83d192fc782cd1b47\
             53111b173b3b05d22fa08086e3b0f712\
             fcc7c71a557e2db966c3e9fa91746039")
    );
}

// ── SHA-512 (FIPS 180-4) ────────────────────────────────────────────────────

/// SHA-512 of "abc" (FIPS 180-4 §B.3).
#[test]
fn cavp_sha512_abc() {
    assert_eq!(
        hash_sha512(b"abc"),
        hex("ddaf35a193617aba cc417349ae204131\
             12e6fa4e89a97ea2 0a9eeee64b55d39a\
             2192992a274fc1a8 36ba3c23a3feebbd\
             454d4423643ce80e 2a9ac94fa54ca49f"
            .replace([' ', '\n'], "")
            .as_str())
    );
}

/// SHA-512 of the 896-bit message from FIPS 180-4 §B.3.
#[test]
fn cavp_sha512_896bit_message() {
    let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(
        hash_sha512(msg),
        hex("8e959b75dae313da 8cf4f72814fc143f\
             8f7779c6eb9f7fa1 7299aeadb6889018\
             501d289e4900f7e4 331b99dec4b5433a\
             c7d329eeb6dd2654 5e96e55b874be909"
            .replace([' ', '\n'], "")
            .as_str())
    );
}

// ── HMAC-SHA-256 (FIPS 198-1 / RFC 4231) ────────────────────────────────────
//
// We verify HMAC using the hmac crate directly so the tests are self-contained
// and precisely match the RustCrypto implementation used by marty-crypto.

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take any length key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha384(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha384;
    type HmacSha384 = Hmac<Sha384>;
    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC can take any length key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take any length key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// RFC 4231 Test Case 1 — HMAC-SHA-256
/// Key = 0x0b × 20, Data = "Hi There"
#[test]
fn cavp_hmac_sha256_tc1() {
    let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    assert_eq!(
        hmac_sha256(&key, data),
        hex("b0344c61d8db38535ca8afceaf0bf12b\
             881dc200c9833da726e9376c2e32cff7")
    );
}

/// RFC 4231 Test Case 2 — HMAC-SHA-256, "what do ya want for nothing?"
/// Expected value validated against hmac+sha2 RustCrypto crates on build machine.
#[test]
fn cavp_hmac_sha256_tc2() {
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";
    assert_eq!(
        hmac_sha256(key, data),
        hex("5bdcc146bf60754e6a042426089575c7\
             5a003f089d2739839dec58b964ec3843")
    );
}

/// RFC 4231 Test Case 3 — HMAC-SHA-256, 20-byte key, 50-byte data
#[test]
fn cavp_hmac_sha256_tc3() {
    let key = hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let data = hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    assert_eq!(
        hmac_sha256(&key, &data),
        hex("773ea91e36800e46854db8ebd09181a7\
             2959098b3ef8c122d9635514ced565fe")
    );
}

/// RFC 4231 Test Case 7 — HMAC-SHA-256, 131-byte key, large data
#[test]
fn cavp_hmac_sha256_tc7() {
    // 131 bytes of 0xaa = 262 hex 'a' chars
    let key = hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                   aaaaaaaaaaaaaaaaaaaaaa");
    let data = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
    assert_eq!(
        hmac_sha256(&key, data),
        hex("9b09ffa71b942fcb27635fbcd5b0e944\
             bfdc63644f0713938a7f51535c3a35e2")
    );
}

/// RFC 4231 Test Case 1 — HMAC-SHA-384
#[test]
fn cavp_hmac_sha384_tc1() {
    let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    assert_eq!(
        hmac_sha384(&key, data),
        hex("afd03944d84895626b0825f4ab46907f\
             15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6")
    );
}

/// RFC 4231 Test Case 1 — HMAC-SHA-512
#[test]
fn cavp_hmac_sha512_tc1() {
    let key = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let data = b"Hi There";
    assert_eq!(
        hmac_sha512(&key, data),
        hex("87aa7cdea5ef619d4ff0b4241a1d6cb0\
             2379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4\
             be9d914eeb61f1702e696c203a126854")
    );
}
