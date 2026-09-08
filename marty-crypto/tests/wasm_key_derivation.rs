// Copyright 2026 ElevenID
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(target_family = "wasm")]

use marty_crypto::{
    kdf::{concat_kdf_sha256, hkdf_sha256, hkdf_sha384, hkdf_sha512, pbkdf2_sha256, pbkdf2_sha512},
    symmetric::{aes_128_cmac, hmac_sha256},
};
use wasm_bindgen_test::wasm_bindgen_test;

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).expect("valid test vector")
}

#[wasm_bindgen_test]
fn wasm_hkdf_sha2_variants_match_known_answers() {
    let ikm = [0x0b; 22];
    let salt = decode("000102030405060708090a0b0c");
    let info = decode("f0f1f2f3f4f5f6f7f8f9");

    assert_eq!(
        hkdf_sha256(&ikm, &salt, &info, 42).unwrap().as_slice(),
        decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
    assert_eq!(
        hkdf_sha384(&ikm, &salt, &info, 82).unwrap().as_slice(),
        decode(
            "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5d95d1da3e62587b22eb8943d0fab6bb631a2fe9df1a68c6ce5d56116a52005b3f122b88b39b7251f"
        )
    );
    assert_eq!(
        hkdf_sha512(&ikm, &salt, &info, 82).unwrap().as_slice(),
        decode(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137be3fb62f3cf32b84feba8f1eb1b563e20d97"
        )
    );
    assert!(hkdf_sha256(b"ikm", b"salt", b"info", 255 * 32 + 1).is_err());
}

#[wasm_bindgen_test]
fn wasm_pbkdf2_hmac_and_concat_kdf_match_known_answers() {
    assert_eq!(
        pbkdf2_sha256(b"password", b"salt", 1, 32).as_slice(),
        decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    );
    assert_eq!(
        pbkdf2_sha512(b"password", b"salt", 1, 64).as_slice(),
        decode("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce")
    );
    assert_eq!(
        pbkdf2_sha256(b"password", b"salt", 2, 40).as_slice(),
        decode("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43830651afcb5c862f")
    );
    assert_eq!(
        pbkdf2_sha512(b"password", b"salt", 2, 80).as_slice(),
        decode("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e473e311ad827b68945f4e2dddb204c78")
    );
    assert_eq!(
        hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog").unwrap(),
        decode("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8")
    );
    assert_eq!(
        aes_128_cmac(&decode("2b7e151628aed2a6abf7158809cf4f3c"), b"").unwrap(),
        decode("bb1d6929e95937287fa37d129b756746")
    );
    assert_eq!(
        concat_kdf_sha256(
            &[
                158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
                110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
            ],
            b"A128GCM",
            b"Alice",
            b"Bob",
            16,
        )
        .unwrap()
        .as_slice(),
        [86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]
    );
}
