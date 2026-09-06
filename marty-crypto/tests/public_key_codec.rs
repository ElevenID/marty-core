//! Fixed-vector characterization for the public-key-only codec surface.

use marty_crypto::serialization;

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
fn p256_public_key_round_trips_through_spki() {
    let raw = hex(concat!(
        "04",
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    ));

    let spki = serialization::raw_public_key_to_spki(&raw, "P256").unwrap();
    let (decoded, key_type) = serialization::spki_to_raw_public_key(&spki).unwrap();

    assert_eq!(decoded, raw);
    assert_eq!(key_type, "EC_P256");
    assert_eq!(serialization::get_key_size(&spki).unwrap(), 256);
}

#[test]
fn ed25519_public_key_round_trips_through_spki_and_pem() {
    let raw = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    let spki = serialization::raw_public_key_to_spki(&raw, "Ed25519").unwrap();
    let pem = serialization::save_public_key_pem(&spki).unwrap();
    let decoded_spki = serialization::load_public_key_pem(&pem).unwrap();
    let (decoded, key_type) = serialization::spki_to_raw_public_key(&decoded_spki).unwrap();

    assert_eq!(decoded, raw);
    assert_eq!(key_type, "Ed25519");
}
