use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use marty_verification::jwk::{
    certificate_der_to_jwk, certificate_pem_to_jwk, public_key_der_to_jwk, public_key_pem_to_jwk,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u8,
    vectors: Vec<KeyVector>,
    certificate: CertificateVector,
    invalid: Vec<InvalidVector>,
}

#[derive(Deserialize)]
struct KeyVector {
    name: String,
    pem: String,
    der_b64: String,
    expected_jwk: Value,
}

#[derive(Deserialize)]
struct CertificateVector {
    pem: String,
    der_b64: String,
    expected_jwk: Value,
}

#[derive(Deserialize)]
struct InvalidVector {
    name: String,
    der_b64: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/public_key_jwk_vectors.json"))
        .expect("valid public-key golden-vector fixture")
}

fn value(jwk: &marty_verification::jwk::Jwk) -> Value {
    serde_json::to_value(jwk).expect("serializable JWK")
}

#[test]
fn public_key_pem_and_der_match_language_neutral_vectors() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);

    for vector in fixture.vectors {
        let der = STANDARD
            .decode(&vector.der_b64)
            .unwrap_or_else(|error| panic!("{} DER is valid base64: {error}", vector.name));
        let from_pem = public_key_pem_to_jwk(&vector.pem)
            .unwrap_or_else(|error| panic!("{} PEM conversion failed: {error}", vector.name));
        let from_der = public_key_der_to_jwk(&der)
            .unwrap_or_else(|error| panic!("{} DER conversion failed: {error}", vector.name));

        assert_eq!(value(&from_pem), vector.expected_jwk, "{} PEM", vector.name);
        assert_eq!(value(&from_der), vector.expected_jwk, "{} DER", vector.name);
        assert!(
            !from_pem.is_private(),
            "{} exposed private material",
            vector.name
        );
    }
}

#[test]
fn certificate_pem_and_der_extract_the_same_public_jwk() {
    let certificate = fixture().certificate;
    let der = STANDARD
        .decode(&certificate.der_b64)
        .expect("certificate DER is valid base64");

    assert_eq!(
        value(&certificate_pem_to_jwk(&certificate.pem).expect("PEM certificate conversion")),
        certificate.expected_jwk
    );
    assert_eq!(
        value(&certificate_der_to_jwk(&der).expect("DER certificate conversion")),
        certificate.expected_jwk
    );
}

#[test]
fn malformed_public_keys_fail_closed() {
    for vector in fixture().invalid {
        let der = STANDARD
            .decode(&vector.der_b64)
            .unwrap_or_else(|error| panic!("{} is valid base64: {error}", vector.name));
        assert!(
            public_key_der_to_jwk(&der).is_err(),
            "{} unexpectedly converted",
            vector.name
        );
    }
}

#[test]
fn malformed_certificates_fail_closed() {
    assert!(certificate_pem_to_jwk("not a certificate").is_err());
    assert!(certificate_der_to_jwk(&[0, 1, 2]).is_err());
}
