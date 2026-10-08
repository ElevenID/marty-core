//! Fixed-vector characterization for the verifier-only feature surface.

use marty_crypto::{ecdsa, ed25519};
use std::sync::OnceLock;

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

fn vector(name: &str, field: &str) -> Vec<u8> {
    static VECTORS: OnceLock<serde_json::Value> = OnceLock::new();
    let vectors = VECTORS.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/verification_only_public.json"))
            .expect("public verification vectors")
    });
    hex(vectors[name][field].as_str().expect("named public vector"))
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
    let wrong_public = vector("wrong_p256", "sec1");

    assert!(!ecdsa::verify_p256_sha256(&wrong_public, b"sample", &signature).unwrap());
}

#[test]
fn p384_verifier_accepts_valid_and_rejects_tampered_inputs() {
    let public_key = vector("p384_boundary", "sec1");
    let message = b"P-384 verifier-only boundary";
    let signature = vector("p384_boundary", "signature_der");

    assert!(ecdsa::verify_p384_sha384(&public_key, message, &signature).unwrap());
    assert!(!ecdsa::verify_p384_sha384(&public_key, b"wrong message", &signature).unwrap());

    let mut tampered = signature;
    *tampered.last_mut().expect("non-empty DER signature") ^= 1;
    assert!(!ecdsa::verify_p384_sha384(&public_key, message, &tampered).unwrap_or(false));
}

#[test]
fn p521_verifier_accepts_valid_and_rejects_wrong_key() {
    let public_key = vector("p521_boundary", "sec1");
    let wrong_public = vector("wrong_p521", "sec1");
    let message = b"P-521 verifier-only boundary";
    let signature = vector("p521_boundary", "signature_der");

    assert!(ecdsa::verify_p521_sha512(&public_key, message, &signature).unwrap());
    assert!(!ecdsa::verify_p521_sha512(&wrong_public, message, &signature).unwrap());
}

#[test]
fn verifier_rejects_cross_curve_signature_confusion() {
    let p384_public = vector("cross_p384", "sec1");
    let message = b"cross-curve verifier boundary";
    let p256_signature = vector("cross_p256", "signature_der");

    assert!(!ecdsa::verify_p384_sha384(&p384_public, message, &p256_signature).unwrap_or(false));
}

#[test]
fn verification_only_build_accepts_public_spki_for_every_ec_family() {
    let message = b"public-only SPKI verification";

    let p256_signature = vector("spki_p256", "signature_raw");
    let p256_spki = vector("spki_p256", "spki");
    assert!(
        ecdsa::verify_p256_sha256(&p256_spki, message, &p256_signature)
            .expect("P-256 SPKI verification")
    );

    let p384_signature = vector("spki_p384", "signature_raw");
    let p384_spki = vector("spki_p384", "spki");
    assert!(
        ecdsa::verify_p384_sha384(&p384_spki, message, &p384_signature)
            .expect("P-384 SPKI verification")
    );

    let p521_signature = vector("spki_p521", "signature_raw");
    let p521_spki = vector("spki_p521", "spki");
    assert!(
        ecdsa::verify_p521_sha512(&p521_spki, message, &p521_signature)
            .expect("P-521 SPKI verification")
    );

    let ed25519_signature = vector("spki_ed25519", "signature_raw");
    let ed25519_spki = vector("spki_ed25519", "spki");
    assert!(
        ed25519::verify_ed25519_spki(&ed25519_spki, message, &ed25519_signature,)
            .expect("Ed25519 SPKI verification")
    );
}

#[test]
fn ecdsa_spki_rejects_a_mismatched_named_curve_identifier() {
    use der::{Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let spki = vector("wrong_curve_p256", "spki");
    let mut wrong_curve = SubjectPublicKeyInfoOwned::from_der(&spki).expect("decode test SPKI");
    wrong_curve.algorithm.parameters = Some(
        der::Any::from_der(
            &const_oid::db::rfc5912::SECP_384_R_1
                .to_der()
                .expect("curve OID DER"),
        )
        .expect("curve OID as ANY"),
    );
    let wrong_curve = wrong_curve.to_der().expect("encode wrong-curve SPKI");
    let signature = vector("wrong_curve_p256", "signature_raw");
    let error = ecdsa::verify_p256_sha256(&wrong_curve, b"curve binding", &signature)
        .expect_err("mismatched named curve must fail before verification");
    assert!(error.to_string().contains("unexpected named curve"));
}

#[test]
fn ecdsa_verifier_rejects_spki_public_point_with_unused_bits() {
    use der::{asn1::BitString, Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let document = vector("unused_bits_p256", "spki");
    let mut spki = SubjectPublicKeyInfoOwned::from_der(&document).expect("decode P-256 SPKI");
    let mut point = spki.subject_public_key.raw_bytes().to_vec();
    *point.last_mut().expect("non-empty SEC1 point") &= 0xfe;
    spki.subject_public_key = BitString::new(1, point).expect("P-256 point with one unused bit");
    let malformed = spki.to_der().expect("encode malformed SPKI");
    let signature = vector("unused_bits_p256", "signature_raw");

    let error = ecdsa::verify_p256_sha256(&malformed, b"unused-bit binding", &signature)
        .expect_err("verification entry point must reject non-canonical BIT STRING metadata");
    assert!(error.to_string().contains("BIT STRING has unused bits"));
}

#[test]
fn public_spki_rejects_invalid_algorithm_identifiers() {
    use der::{Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let p256_spki = vector("wrong_algorithm_p256", "spki");
    let mut wrong_algorithm =
        SubjectPublicKeyInfoOwned::from_der(&p256_spki).expect("decode P-256 SPKI");
    wrong_algorithm.algorithm.oid = const_oid::db::rfc8410::ID_ED_25519;
    wrong_algorithm.algorithm.parameters = None;
    let wrong_algorithm = wrong_algorithm
        .to_der()
        .expect("encode wrong-algorithm SPKI");
    let p256_signature = vector("wrong_algorithm_p256", "signature_raw");
    let p256_error =
        ecdsa::verify_p256_sha256(&wrong_algorithm, b"algorithm binding", &p256_signature)
            .expect_err("non-EC algorithm identifier must be rejected");
    assert!(p256_error.to_string().contains("not id-ecPublicKey"));

    let ed25519_spki = vector("wrong_algorithm_ed25519", "spki");
    let mut parameters_present =
        SubjectPublicKeyInfoOwned::from_der(&ed25519_spki).expect("decode Ed25519 SPKI");
    parameters_present.algorithm.parameters =
        Some(der::Any::from_der(&[0x05, 0x00]).expect("DER NULL"));
    let parameters_present = parameters_present
        .to_der()
        .expect("encode parameterized Ed25519 SPKI");
    let ed25519_signature = vector("wrong_algorithm_ed25519", "signature_raw");
    let ed25519_error = ed25519::verify_ed25519_spki(
        &parameters_present,
        b"algorithm binding",
        &ed25519_signature,
    )
    .expect_err("RFC 8410 forbids Ed25519 algorithm parameters");
    assert!(ed25519_error
        .to_string()
        .contains("Invalid Ed25519 SPKI algorithm identifier"));
}

#[test]
fn strict_ed25519_verification_rejects_identity_key_forgery() {
    use der::{asn1::BitString, Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut forged_signature = [0x66u8; 64];
    forged_signature[0] = 0x58;
    forged_signature[32..].fill(0);
    forged_signature[32] = 1;

    let key = ed25519::Ed25519VerifyingKey::from_bytes(&identity)
        .expect("dalek parses the small-order identity encoding");
    assert!(key.verify(b"any message", &forged_signature).is_err());
    assert!(!key.verify_strict(b"a different message", &forged_signature));
    assert!(ed25519::verify(&identity, b"any message", &forged_signature).is_err());

    let template_spki = vector("identity_template_ed25519", "spki");
    let mut identity_spki =
        SubjectPublicKeyInfoOwned::from_der(&template_spki).expect("decode SPKI");
    identity_spki.subject_public_key =
        BitString::from_bytes(&identity).expect("identity public-key bit string");
    let identity_spki = identity_spki.to_der().expect("encode identity SPKI");
    assert!(
        !ed25519::verify_ed25519_spki(&identity_spki, b"any message", &forged_signature)
            .expect("well-formed identity SPKI must reach strict verification")
    );
}

#[test]
fn public_ed25519_parsers_bind_the_complete_spki_metadata() {
    use base64::Engine as _;
    use der::{asn1::BitString, Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let expected: [u8; 32] = vector("parser_ed25519", "raw")
        .try_into()
        .expect("Ed25519 public point");
    let document = vector("parser_ed25519", "spki");
    assert_eq!(
        ed25519::parse_public_key_der(&document)
            .expect("valid DER")
            .to_bytes(),
        expected
    );

    let body = base64::engine::general_purpose::STANDARD.encode(&document);
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n");
    assert_eq!(
        ed25519::parse_public_key_pem(&pem)
            .expect("valid public-key PEM")
            .to_bytes(),
        expected
    );
    let wrong_label = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
    assert!(ed25519::parse_public_key_pem(&wrong_label).is_err());

    let mut wrong_oid = SubjectPublicKeyInfoOwned::from_der(&document).expect("decode SPKI");
    wrong_oid.algorithm.oid = const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
    wrong_oid.algorithm.parameters = None;
    assert!(ed25519::parse_public_key_der(&wrong_oid.to_der().expect("wrong OID DER")).is_err());

    let mut parameters_present =
        SubjectPublicKeyInfoOwned::from_der(&document).expect("decode SPKI");
    parameters_present.algorithm.parameters =
        Some(der::Any::from_der(&[0x05, 0x00]).expect("DER NULL"));
    assert!(ed25519::parse_public_key_der(
        &parameters_present.to_der().expect("parameterized DER")
    )
    .is_err());

    let mut unused_bits = SubjectPublicKeyInfoOwned::from_der(&document).expect("decode SPKI");
    let mut padded_key = expected;
    padded_key[31] &= 0xfe;
    unused_bits.subject_public_key =
        BitString::new(1, padded_key).expect("bit string with one unused bit");
    assert!(ed25519::parse_public_key_der(&unused_bits.to_der().expect("unused-bit DER")).is_err());

    let mut trailing = document;
    trailing.extend_from_slice(&[0x05, 0x00]);
    assert!(ed25519::parse_public_key_der(&trailing).is_err());
}

#[test]
fn ec_point_extractor_requires_named_curve_spki_metadata() {
    use der::{asn1::BitString, Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let expected = vector("extract_p256", "sec1");
    let document = vector("extract_p256", "spki");
    assert_eq!(
        ecdsa::extract_ec_point_from_spki(&document).expect("named-curve EC SPKI"),
        expected
    );

    let mut missing_curve =
        SubjectPublicKeyInfoOwned::from_der(&document).expect("decode P-256 SPKI");
    missing_curve.algorithm.parameters = None;
    assert!(
        ecdsa::extract_ec_point_from_spki(&missing_curve.to_der().expect("missing-curve DER"))
            .is_err()
    );

    let mut invalid_curve =
        SubjectPublicKeyInfoOwned::from_der(&document).expect("decode P-256 SPKI");
    invalid_curve.algorithm.parameters = Some(der::Any::from_der(&[0x05, 0x00]).expect("DER NULL"));
    assert!(
        ecdsa::extract_ec_point_from_spki(&invalid_curve.to_der().expect("invalid-curve DER"))
            .is_err()
    );

    let mut unused_bits =
        SubjectPublicKeyInfoOwned::from_der(&document).expect("decode P-256 SPKI");
    let mut padded_point = expected;
    let final_byte = padded_point.last_mut().expect("non-empty EC point");
    *final_byte &= 0xfe;
    unused_bits.subject_public_key =
        BitString::new(1, padded_point).expect("EC point with one unused bit");
    assert!(
        ecdsa::extract_ec_point_from_spki(&unused_bits.to_der().expect("unused-bit DER")).is_err()
    );

    let ed25519_document = vector("extract_ed25519", "spki");
    assert!(ecdsa::extract_ec_point_from_spki(&ed25519_document).is_err());
}
