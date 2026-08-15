use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use marty_crypto::jwk::{
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
    serde_json::from_str(include_str!(
        "../../marty-verification/tests/fixtures/public_key_jwk_vectors.json"
    ))
    .expect("valid language-neutral public-key vectors")
}

#[test]
fn public_keys_match_language_neutral_vectors() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);

    for vector in fixture.vectors {
        let der = STANDARD
            .decode(&vector.der_b64)
            .unwrap_or_else(|error| panic!("{} DER base64: {error}", vector.name));
        let pem = public_key_pem_to_jwk(&vector.pem)
            .unwrap_or_else(|error| panic!("{} PEM conversion: {error}", vector.name));
        let der = public_key_der_to_jwk(&der)
            .unwrap_or_else(|error| panic!("{} DER conversion: {error}", vector.name));
        assert_eq!(serde_json::to_value(pem).unwrap(), vector.expected_jwk);
        assert_eq!(serde_json::to_value(der).unwrap(), vector.expected_jwk);
    }
}

#[test]
fn certificates_match_language_neutral_vectors() {
    let vector = fixture().certificate;
    let der = STANDARD
        .decode(vector.der_b64)
        .expect("certificate DER base64");
    assert_eq!(
        serde_json::to_value(certificate_pem_to_jwk(&vector.pem).unwrap()).unwrap(),
        vector.expected_jwk
    );
    assert_eq!(
        serde_json::to_value(certificate_der_to_jwk(&der).unwrap()).unwrap(),
        vector.expected_jwk
    );
}

#[test]
fn malformed_inputs_fail_closed() {
    for vector in fixture().invalid {
        let der = STANDARD
            .decode(vector.der_b64)
            .unwrap_or_else(|error| panic!("{} DER base64: {error}", vector.name));
        assert!(
            public_key_der_to_jwk(&der).is_err(),
            "{} unexpectedly converted",
            vector.name
        );
    }
    assert!(certificate_pem_to_jwk("not a certificate").is_err());
    assert!(certificate_der_to_jwk(&[0, 1, 2]).is_err());
}
