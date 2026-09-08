//! Fixed-vector characterization for the verifier-only feature surface.

use marty_crypto::{ecdsa, ed25519};
use pkcs8::EncodePublicKey;
use signature::Signer;

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
    let wrong_key = p256::ecdsa::SigningKey::from_slice(&[1; 32]).expect("valid test scalar");
    let wrong_public = wrong_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();

    assert!(!ecdsa::verify_p256_sha256(&wrong_public, b"sample", &signature).unwrap());
}

#[test]
fn p384_verifier_accepts_valid_and_rejects_tampered_inputs() {
    let signing_key =
        p384::ecdsa::SigningKey::from_slice(&[2; 48]).expect("valid P-384 test scalar");
    let public_key = signing_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let message = b"P-384 verifier-only boundary";
    let signature: p384::ecdsa::Signature = signing_key.sign(message);
    let signature = signature.to_der().as_bytes().to_vec();

    assert!(ecdsa::verify_p384_sha384(&public_key, message, &signature).unwrap());
    assert!(!ecdsa::verify_p384_sha384(&public_key, b"wrong message", &signature).unwrap());

    let mut tampered = signature;
    *tampered.last_mut().expect("non-empty DER signature") ^= 1;
    assert!(!ecdsa::verify_p384_sha384(&public_key, message, &tampered).unwrap_or(false));
}

#[test]
fn p521_verifier_accepts_valid_and_rejects_wrong_key() {
    let mut scalar = [0; 66];
    scalar[65] = 3;
    let signing_key =
        p521::ecdsa::SigningKey::from_slice(&scalar).expect("valid P-521 test scalar");
    scalar[65] = 4;
    let wrong_key = p521::ecdsa::SigningKey::from_slice(&scalar).expect("valid P-521 test scalar");
    let public_key = p521::ecdsa::VerifyingKey::from(&signing_key)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let wrong_public = p521::ecdsa::VerifyingKey::from(&wrong_key)
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let message = b"P-521 verifier-only boundary";
    let signature: p521::ecdsa::Signature = signing_key.sign(message);
    let signature = signature.to_der().as_bytes().to_vec();

    assert!(ecdsa::verify_p521_sha512(&public_key, message, &signature).unwrap());
    assert!(!ecdsa::verify_p521_sha512(&wrong_public, message, &signature).unwrap());
}

#[test]
fn verifier_rejects_cross_curve_signature_confusion() {
    let p256_key = p256::ecdsa::SigningKey::from_slice(&[5; 32]).expect("valid P-256 scalar");
    let p384_key = p384::ecdsa::SigningKey::from_slice(&[6; 48]).expect("valid P-384 scalar");
    let p384_public = p384_key
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let message = b"cross-curve verifier boundary";
    let p256_signature: p256::ecdsa::Signature = p256_key.sign(message);
    let p256_signature = p256_signature.to_der();

    assert!(
        !ecdsa::verify_p384_sha384(&p384_public, message, p256_signature.as_bytes())
            .unwrap_or(false)
    );
}

#[test]
fn verification_only_build_accepts_public_spki_for_every_ec_family() {
    let message = b"public-only SPKI verification";

    let p256_key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).expect("valid P-256 scalar");
    let p256_signature: p256::ecdsa::Signature = p256_key.sign(message);
    let p256_spki = p256_key
        .verifying_key()
        .to_public_key_der()
        .expect("P-256 SPKI");
    assert!(
        ecdsa::verify_p256_sha256(p256_spki.as_bytes(), message, &p256_signature.to_bytes())
            .expect("P-256 SPKI verification")
    );

    let p384_key = p384::ecdsa::SigningKey::from_slice(&[8; 48]).expect("valid P-384 scalar");
    let p384_signature: p384::ecdsa::Signature = p384_key.sign(message);
    let p384_spki = p384_key
        .verifying_key()
        .to_public_key_der()
        .expect("P-384 SPKI");
    assert!(
        ecdsa::verify_p384_sha384(p384_spki.as_bytes(), message, &p384_signature.to_bytes())
            .expect("P-384 SPKI verification")
    );

    let mut p521_scalar = [0u8; 66];
    p521_scalar[65] = 9;
    let p521_key = p521::ecdsa::SigningKey::from_slice(&p521_scalar).expect("valid P-521 scalar");
    let p521_signature: p521::ecdsa::Signature = p521_key.sign(message);
    let p521_verifying_key = p521::ecdsa::VerifyingKey::from(&p521_key);
    let p521_point = p521_verifying_key.to_encoded_point(false);
    let p521_spki = {
        use der::{asn1::BitString, Decode, Encode};
        use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

        let curve_parameters = der::Any::from_der(
            &const_oid::db::rfc5912::SECP_521_R_1
                .to_der()
                .expect("P-521 OID DER"),
        )
        .expect("P-521 OID as ANY");
        SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
                parameters: Some(curve_parameters),
            },
            subject_public_key: BitString::from_bytes(p521_point.as_bytes())
                .expect("P-521 point bit string"),
        }
        .to_der()
        .expect("P-521 SPKI")
    };
    assert!(
        ecdsa::verify_p521_sha512(&p521_spki, message, &p521_signature.to_bytes())
            .expect("P-521 SPKI verification")
    );

    let ed25519_key = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
    let ed25519_signature: ed25519_dalek::Signature = ed25519_key.sign(message);
    let ed25519_spki = ed25519_key
        .verifying_key()
        .to_public_key_der()
        .expect("Ed25519 SPKI");
    assert!(ed25519::verify_ed25519_spki(
        ed25519_spki.as_bytes(),
        message,
        &ed25519_signature.to_bytes(),
    )
    .expect("Ed25519 SPKI verification"));
}

#[test]
fn ecdsa_spki_rejects_a_mismatched_named_curve_identifier() {
    use der::{Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let key = p256::ecdsa::SigningKey::from_slice(&[11; 32]).expect("valid P-256 scalar");
    let spki = key.verifying_key().to_public_key_der().expect("P-256 SPKI");
    let mut wrong_curve =
        SubjectPublicKeyInfoOwned::from_der(spki.as_bytes()).expect("decode test SPKI");
    wrong_curve.algorithm.parameters = Some(
        der::Any::from_der(
            &const_oid::db::rfc5912::SECP_384_R_1
                .to_der()
                .expect("curve OID DER"),
        )
        .expect("curve OID as ANY"),
    );
    let wrong_curve = wrong_curve.to_der().expect("encode wrong-curve SPKI");
    let signature: p256::ecdsa::Signature = key.sign(b"curve binding");
    let error = ecdsa::verify_p256_sha256(&wrong_curve, b"curve binding", &signature.to_bytes())
        .expect_err("mismatched named curve must fail before verification");
    assert!(error.to_string().contains("unexpected named curve"));
}

#[test]
fn public_spki_rejects_invalid_algorithm_identifiers() {
    use der::{Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let p256_key = p256::ecdsa::SigningKey::from_slice(&[12; 32]).expect("valid P-256 scalar");
    let p256_spki = p256_key
        .verifying_key()
        .to_public_key_der()
        .expect("P-256 SPKI");
    let mut wrong_algorithm =
        SubjectPublicKeyInfoOwned::from_der(p256_spki.as_bytes()).expect("decode P-256 SPKI");
    wrong_algorithm.algorithm.oid = const_oid::db::rfc8410::ID_ED_25519;
    wrong_algorithm.algorithm.parameters = None;
    let wrong_algorithm = wrong_algorithm
        .to_der()
        .expect("encode wrong-algorithm SPKI");
    let p256_signature: p256::ecdsa::Signature = p256_key.sign(b"algorithm binding");
    let p256_error = ecdsa::verify_p256_sha256(
        &wrong_algorithm,
        b"algorithm binding",
        &p256_signature.to_bytes(),
    )
    .expect_err("non-EC algorithm identifier must be rejected");
    assert!(p256_error.to_string().contains("not id-ecPublicKey"));

    let ed25519_key = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
    let ed25519_spki = ed25519_key
        .verifying_key()
        .to_public_key_der()
        .expect("Ed25519 SPKI");
    let mut parameters_present =
        SubjectPublicKeyInfoOwned::from_der(ed25519_spki.as_bytes()).expect("decode Ed25519 SPKI");
    parameters_present.algorithm.parameters =
        Some(der::Any::from_der(&[0x05, 0x00]).expect("DER NULL"));
    let parameters_present = parameters_present
        .to_der()
        .expect("encode parameterized Ed25519 SPKI");
    let ed25519_signature: ed25519_dalek::Signature = ed25519_key.sign(b"algorithm binding");
    let ed25519_error = ed25519::verify_ed25519_spki(
        &parameters_present,
        b"algorithm binding",
        &ed25519_signature.to_bytes(),
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

    let template_key = ed25519_dalek::SigningKey::from_bytes(&[14; 32]);
    let template_spki = template_key
        .verifying_key()
        .to_public_key_der()
        .expect("Ed25519 SPKI");
    let mut identity_spki =
        SubjectPublicKeyInfoOwned::from_der(template_spki.as_bytes()).expect("decode SPKI");
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

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[15; 32]);
    let expected = signing_key.verifying_key().to_bytes();
    let document = signing_key
        .verifying_key()
        .to_public_key_der()
        .expect("Ed25519 SPKI");
    assert_eq!(
        ed25519::parse_public_key_der(document.as_bytes())
            .expect("valid DER")
            .to_bytes(),
        expected
    );

    let body = base64::engine::general_purpose::STANDARD.encode(document.as_bytes());
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n");
    assert_eq!(
        ed25519::parse_public_key_pem(&pem)
            .expect("valid public-key PEM")
            .to_bytes(),
        expected
    );
    let wrong_label = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");
    assert!(ed25519::parse_public_key_pem(&wrong_label).is_err());

    let mut wrong_oid =
        SubjectPublicKeyInfoOwned::from_der(document.as_bytes()).expect("decode SPKI");
    wrong_oid.algorithm.oid = const_oid::db::rfc5912::ID_EC_PUBLIC_KEY;
    wrong_oid.algorithm.parameters = None;
    assert!(ed25519::parse_public_key_der(&wrong_oid.to_der().expect("wrong OID DER")).is_err());

    let mut parameters_present =
        SubjectPublicKeyInfoOwned::from_der(document.as_bytes()).expect("decode SPKI");
    parameters_present.algorithm.parameters =
        Some(der::Any::from_der(&[0x05, 0x00]).expect("DER NULL"));
    assert!(ed25519::parse_public_key_der(
        &parameters_present.to_der().expect("parameterized DER")
    )
    .is_err());

    let mut unused_bits =
        SubjectPublicKeyInfoOwned::from_der(document.as_bytes()).expect("decode SPKI");
    let mut padded_key = expected;
    padded_key[31] &= 0xfe;
    unused_bits.subject_public_key =
        BitString::new(1, padded_key).expect("bit string with one unused bit");
    assert!(ed25519::parse_public_key_der(&unused_bits.to_der().expect("unused-bit DER")).is_err());

    let mut trailing = document.as_bytes().to_vec();
    trailing.extend_from_slice(&[0x05, 0x00]);
    assert!(ed25519::parse_public_key_der(&trailing).is_err());
}

#[test]
fn ec_point_extractor_requires_named_curve_spki_metadata() {
    use der::{asn1::BitString, Decode, Encode};
    use x509_cert::spki::SubjectPublicKeyInfoOwned;

    let p256_key = p256::ecdsa::SigningKey::from_slice(&[16; 32]).expect("valid P-256 scalar");
    let expected = p256_key.verifying_key().to_encoded_point(false);
    let document = p256_key
        .verifying_key()
        .to_public_key_der()
        .expect("P-256 SPKI");
    assert_eq!(
        ecdsa::extract_ec_point_from_spki(document.as_bytes()).expect("named-curve EC SPKI"),
        expected.as_bytes()
    );

    let mut missing_curve =
        SubjectPublicKeyInfoOwned::from_der(document.as_bytes()).expect("decode P-256 SPKI");
    missing_curve.algorithm.parameters = None;
    assert!(
        ecdsa::extract_ec_point_from_spki(&missing_curve.to_der().expect("missing-curve DER"))
            .is_err()
    );

    let mut invalid_curve =
        SubjectPublicKeyInfoOwned::from_der(document.as_bytes()).expect("decode P-256 SPKI");
    invalid_curve.algorithm.parameters = Some(der::Any::from_der(&[0x05, 0x00]).expect("DER NULL"));
    assert!(
        ecdsa::extract_ec_point_from_spki(&invalid_curve.to_der().expect("invalid-curve DER"))
            .is_err()
    );

    let mut unused_bits =
        SubjectPublicKeyInfoOwned::from_der(document.as_bytes()).expect("decode P-256 SPKI");
    let mut padded_point = expected.as_bytes().to_vec();
    let final_byte = padded_point.last_mut().expect("non-empty EC point");
    *final_byte &= 0xfe;
    unused_bits.subject_public_key =
        BitString::new(1, padded_point).expect("EC point with one unused bit");
    assert!(
        ecdsa::extract_ec_point_from_spki(&unused_bits.to_der().expect("unused-bit DER")).is_err()
    );

    let ed25519_key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let ed25519_document = ed25519_key
        .verifying_key()
        .to_public_key_der()
        .expect("Ed25519 SPKI");
    assert!(ecdsa::extract_ec_point_from_spki(ed25519_document.as_bytes()).is_err());
}
