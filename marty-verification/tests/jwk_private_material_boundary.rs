use marty_verification::jwk::Jwk;
#[cfg(not(feature = "local-key-operations"))]
use marty_verification::jwk::JwkSet;
use serde_json::Value;
use std::collections::HashMap;

#[test]
#[cfg(not(feature = "local-key-operations"))]
fn verification_build_rejects_private_jwk_members() {
    for member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        let json = format!(r#"{{"kty":"EC","{member}":"secret"}}"#);
        assert!(
            Jwk::from_json(&json).is_err(),
            "verification build accepted private JWK member {member}"
        );
    }
}

#[test]
fn verification_jwk_extensions_are_read_only_and_safe_to_serialize_or_debug() {
    let jwk = Jwk::from_json(r#"{"kty":"EC","custom":{"safe":true}}"#).unwrap();
    assert!(jwk.extensions().contains_key("custom"));
    assert!(!jwk.to_json().unwrap().contains("secret"));
    assert!(!format!("{jwk:?}").contains("secret"));
}

#[test]
#[cfg(not(feature = "local-key-operations"))]
fn verification_build_rejects_private_members_in_jwk_sets() {
    let json = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"secret"}]}"#;
    assert!(JwkSet::from_json(json).is_err());
}

#[test]
fn verification_build_still_accepts_public_jwks() {
    let json = r#"{"kty":"EC","crv":"P-256","x":"x","y":"y"}"#;
    assert!(Jwk::from_json(json).is_ok());
}

#[test]
fn verification_jwk_extensions_have_a_safe_external_construction_path() {
    let extensions = HashMap::from([("custom".to_owned(), serde_json::json!({"safe": true}))]);
    let jwk = Jwk::new("EC").with_extensions(extensions.clone()).unwrap();
    assert_eq!(jwk.extensions(), &extensions);
    let round_trip = Jwk::from_json(&jwk.to_json().unwrap()).unwrap();
    assert_eq!(round_trip.extensions(), &extensions);

    for reserved in ["d", "k", "kty", "x", "x5t#S256"] {
        let extensions = HashMap::from([(reserved.to_owned(), Value::String("value".into()))]);
        assert!(Jwk::new("EC").with_extensions(extensions).is_err());
    }
}
