use marty_oid4vci::formats::sd_jwt::{
    verify_sd_jwt, verify_sd_jwt_with_policy, SdJwtVerificationPolicy,
};
use marty_oid4vci::types::SigningAlgorithm;

fn fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/remote_sd_jwt_wallet_public.json")).unwrap()
}

fn policy(fixture: &serde_json::Value) -> SdJwtVerificationPolicy {
    SdJwtVerificationPolicy {
        expected_issuer: fixture["issuer"].as_str().unwrap().into(),
        issuer_algorithm: SigningAlgorithm::ES256,
        holder_algorithms: vec![SigningAlgorithm::ES256],
    }
}

#[test]
fn authenticated_identity_requires_the_exact_issuer_key_relationship() {
    let fixture = fixture();
    let credential = fixture["credential"].as_str().unwrap();
    let public_jwk = fixture["issuer_public_jwk"].to_string();
    let mut policy = policy(&fixture);
    let verified = verify_sd_jwt_with_policy(credential, &public_jwk, &policy, None, None).unwrap();
    assert_eq!(verified.issuer(), policy.expected_issuer);
    assert_eq!(verified.claims()["iss"], policy.expected_issuer);
    // The same valid signature does not authorize the key for another issuer.
    assert!(verify_sd_jwt(credential, &public_jwk, None, None).is_ok());
    policy.expected_issuer.push_str("/other-issuer");
    assert!(verify_sd_jwt_with_policy(credential, &public_jwk, &policy, None, None).is_err());
    policy.expected_issuer = fixture["issuer"].as_str().unwrap().to_uppercase();
    assert!(verify_sd_jwt_with_policy(credential, &public_jwk, &policy, None, None).is_err());
}

#[test]
fn configured_signature_roles_cannot_be_selected_by_the_credential() {
    let fixture = fixture();
    let credential = fixture["credential"].as_str().unwrap();
    let public_jwk = fixture["issuer_public_jwk"].to_string();
    let mut policy = policy(&fixture);
    policy.issuer_algorithm = SigningAlgorithm::ES384;
    assert!(verify_sd_jwt_with_policy(credential, &public_jwk, &policy, None, None).is_err());
    policy.issuer_algorithm = SigningAlgorithm::ES256;
    policy.holder_algorithms.clear();
    assert!(verify_sd_jwt_with_policy(credential, &public_jwk, &policy, None, None).is_ok());
    assert!(verify_sd_jwt_with_policy(
        credential,
        &public_jwk,
        &policy,
        Some("https://verifier.example".into()),
        Some(uuid::Uuid::new_v4().to_string()),
    )
    .is_err());
    policy.holder_algorithms.push(SigningAlgorithm::ES256K);
    assert!(verify_sd_jwt_with_policy(credential, &public_jwk, &policy, None, None).is_err());
}

#[test]
fn verification_rejects_private_or_incompatible_public_key_metadata() {
    let fixture = fixture();
    let credential = fixture["credential"].as_str().unwrap();
    let policy = policy(&fixture);
    for (name, value) in [
        ("d", serde_json::json!(uuid::Uuid::new_v4().to_string())),
        ("alg", serde_json::json!("ES384")),
        ("use", serde_json::json!("enc")),
        ("key_ops", serde_json::json!(["sign"])),
    ] {
        let mut public_jwk = fixture["issuer_public_jwk"].clone();
        public_jwk[name] = value;
        assert!(
            verify_sd_jwt_with_policy(credential, &public_jwk.to_string(), &policy, None, None,)
                .is_err(),
            "accepted invalid {name}"
        );
    }
}
