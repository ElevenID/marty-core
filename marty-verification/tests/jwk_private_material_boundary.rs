use marty_verification::jwk::{Jwk, JwkSet};

#[test]
fn verification_build_rejects_private_jwk_members() {
    for member in ["d", "rsa_d", "p", "q", "dp", "dq", "qi", "k"] {
        let json = format!(r#"{{"kty":"EC","{member}":"secret"}}"#);
        assert!(
            Jwk::from_json(&json).is_err(),
            "verification build accepted private JWK member {member}"
        );
    }
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
