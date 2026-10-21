use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use marty_crypto::jwk::{
    certificate_der_to_jwk, certificate_pem_to_jwk, public_key_der_to_jwk, public_key_pem_to_jwk,
    PublicJwk,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

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

#[test]
fn public_jwk_rejects_every_registered_private_member() {
    for member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let json = format!(r#"{{"kty":"EC","{member}":"secret"}}"#);
        assert!(
            PublicJwk::from_json(&json).is_err(),
            "PublicJwk accepted private member {member}"
        );
    }

    let public =
        PublicJwk::from_json(r#"{"kty":"EC","crv":"P-256","x":"x","y":"y","custom":true}"#)
            .unwrap();
    assert_eq!(public.extensions().get("custom"), Some(&Value::Bool(true)));
    let serialized = serde_json::to_string(&public).unwrap();
    let debug = format!("{public:?}");
    assert!(!serialized.contains("secret"));
    assert!(!debug.contains("secret"));
}

#[test]
fn public_jwk_extensions_have_a_safe_external_construction_path() {
    let extensions = HashMap::from([("custom".to_owned(), serde_json::json!({"safe": true}))]);
    let mut public = PublicJwk::default();
    public.kty = "EC".to_owned();
    let public = public.with_extensions(extensions.clone()).unwrap();
    assert_eq!(public.extensions(), &extensions);
    let round_trip: PublicJwk = serde_json::from_str(&public.to_json().unwrap()).unwrap();
    assert_eq!(round_trip.extensions(), &extensions);

    for reserved in ["d", "k", "kty", "x", "x5t#S256"] {
        let extensions = HashMap::from([(reserved.to_owned(), Value::String("value".into()))]);
        assert!(PublicJwk::default().with_extensions(extensions).is_err());
    }

    let too_many = (0..=32)
        .map(|index| (format!("extension-{index}"), Value::Bool(true)))
        .collect();
    assert!(PublicJwk::default().with_extensions(too_many).is_err());

    let oversized_array =
        HashMap::from([("custom".to_owned(), Value::Array(vec![Value::Null; 129]))]);
    assert!(PublicJwk::default()
        .with_extensions(oversized_array)
        .is_err());

    assert!(serde_json::from_str::<PublicJwk>(r#"{"kty":"EC","kty":"RSA"}"#).is_err());
    assert!(serde_json::from_str::<PublicJwk>(r#"{"kty":"EC","custom":1,"custom":2}"#).is_err());
}
