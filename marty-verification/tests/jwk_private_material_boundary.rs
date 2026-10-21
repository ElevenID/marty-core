use marty_verification::jwk::Jwk;
use marty_verification::jwk::JwkSet;
use marty_verification::jwk::{
    MAX_JWK_SET_JSON_BYTES, MAX_JWK_SET_KEYS, MAX_PUBLIC_JWK_JSON_BYTES,
};
use serde_json::Value;
use std::collections::HashMap;

#[test]
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

#[test]
fn public_jwk_json_limits_fail_before_unbounded_deserialization() {
    let base = r#"{"kty":"EC"}"#;
    let at_limit = format!(
        "{base}{}",
        " ".repeat(MAX_PUBLIC_JWK_JSON_BYTES - base.len())
    );
    assert_eq!(at_limit.len(), MAX_PUBLIC_JWK_JSON_BYTES);
    assert!(Jwk::from_json(&at_limit).is_ok());
    assert!(Jwk::from_json(&(at_limit + " ")).is_err());

    let oversized_private = format!(
        r#"{{"kty":"EC","d":"{}"}}"#,
        "S".repeat(MAX_PUBLIC_JWK_JSON_BYTES)
    );
    assert!(Jwk::from_json(&oversized_private).is_err());
}

#[test]
fn jwk_set_json_and_key_count_limits_are_enforced() {
    let at_key_limit = format!(
        r#"{{"keys":[{}]}}"#,
        std::iter::repeat_n(r#"{"kty":"EC"}"#, MAX_JWK_SET_KEYS)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert_eq!(
        JwkSet::from_json(&at_key_limit).unwrap().keys.len(),
        MAX_JWK_SET_KEYS
    );

    let over_key_limit = format!(
        r#"{{"keys":[{}]}}"#,
        std::iter::repeat_n(r#"{"kty":"EC"}"#, MAX_JWK_SET_KEYS + 1)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(JwkSet::from_json(&over_key_limit).is_err());

    let prefix = r#"{"keys":[],"padding":""#;
    let suffix = r#""}"#;
    let at_size_limit = format!(
        "{prefix}{}{suffix}",
        "A".repeat(MAX_JWK_SET_JSON_BYTES - prefix.len() - suffix.len())
    );
    assert_eq!(at_size_limit.len(), MAX_JWK_SET_JSON_BYTES);
    assert!(JwkSet::from_json(&at_size_limit).is_ok());
    assert!(JwkSet::from_json(&(at_size_limit + " ")).is_err());
}

#[test]
fn direct_and_nested_serde_paths_enforce_the_same_member_limits() {
    let oversized_public_member = format!(r#"{{"kty":"EC","x":"{}"}}"#, "A".repeat(16 * 1024 + 1));
    assert!(serde_json::from_str::<Jwk>(&oversized_public_member).is_err());

    let oversized_private_member = format!(r#"{{"kty":"EC","d":"{}"}}"#, "S".repeat(16 * 1024 + 1));
    assert!(serde_json::from_str::<Jwk>(&oversized_private_member).is_err());

    let nested = format!(r#"{{"keys":[{oversized_public_member}]}}"#);
    assert!(serde_json::from_str::<JwkSet>(&nested).is_err());

    let oversized_extension = format!(r#"{{"kty":"EC","custom":"{}"}}"#, "A".repeat(16 * 1024 + 1));
    assert!(serde_json::from_str::<Jwk>(&oversized_extension).is_err());
    let nested_extension = format!(r#"{{"keys":[{oversized_extension}]}}"#);
    assert!(serde_json::from_str::<JwkSet>(&nested_extension).is_err());

    let too_many_keys = format!(
        r#"{{"keys":[{}]}}"#,
        std::iter::repeat_n(r#"{"kty":"EC"}"#, MAX_JWK_SET_KEYS + 1)
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(serde_json::from_str::<JwkSet>(&too_many_keys).is_err());

    assert!(serde_json::from_str::<Jwk>(r#"{"kty":"EC","kty":"RSA"}"#).is_err());
    assert!(serde_json::from_str::<Jwk>(r#"{"kty":"EC","custom":1,"custom":2}"#).is_err());

    let member = "A".repeat(16 * 1024);
    let aggregate = format!(
        r#"{{"kty":"EC","x":"{member}","y":"{member}","n":"{member}","e":"{member}","alg":"{member}"}}"#
    );
    assert!(serde_json::from_str::<Jwk>(&aggregate).is_err());
}
