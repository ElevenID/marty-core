#![cfg(feature = "wallet")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use marty_oid4vci::formats::sd_jwt::{sign_sd_jwt, verify_sd_jwt};
use marty_oid4vci::signer::CredentialSigner;
use marty_oid4vci::types::{
    CredentialClaims, CredentialPayloadFormat, IssuerKey, SignedCredential, SigningAlgorithm,
};
use marty_oid4vci::{
    Oid4vciError, Oid4vciResult, ResolvedSdJwtIssuerKey, SdJwtIssuerKeyResolver, WalletEngine,
};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;

#[derive(Clone)]
struct StaticResolver {
    key: ResolvedSdJwtIssuerKey,
}

impl SdJwtIssuerKeyResolver for StaticResolver {
    fn resolve(
        &self,
        _issuer: &str,
        _key_id: Option<&str>,
        _algorithm: SigningAlgorithm,
    ) -> Oid4vciResult<ResolvedSdJwtIssuerKey> {
        Ok(self.key.clone())
    }
}

#[derive(Default)]
struct CountingResolver {
    calls: AtomicUsize,
}

impl SdJwtIssuerKeyResolver for CountingResolver {
    fn resolve(
        &self,
        _issuer: &str,
        _key_id: Option<&str>,
        _algorithm: SigningAlgorithm,
    ) -> Oid4vciResult<ResolvedSdJwtIssuerKey> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Err(Oid4vciError::KeyError("resolver must not be called".into()))
    }
}

struct Fixture {
    credential: String,
    issuer: String,
    issuer_public_jwk: String,
    issuer_private_jwk: String,
    holder_private_jwk: String,
}

fn p256_jwk(key: &SigningKey, include_private: bool) -> serde_json::Value {
    let point = key.verifying_key().to_encoded_point(false);
    let mut jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    if include_private {
        jwk["d"] = serde_json::Value::String(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes()),
        );
    }
    jwk
}

fn fixture() -> Fixture {
    fixture_with_cnf(false)
}

fn fixture_with_cnf(include_private_cnf: bool) -> Fixture {
    let issuer_signing_key = SigningKey::random(&mut OsRng);
    let holder_signing_key = SigningKey::random(&mut OsRng);
    let issuer = "did:example:verified-wallet-issuer".to_string();
    let issuer_private_jwk = p256_jwk(&issuer_signing_key, true).to_string();
    let holder_cnf_jwk = p256_jwk(&holder_signing_key, include_private_cnf);
    let holder_private_jwk = p256_jwk(&holder_signing_key, true).to_string();

    let claims = CredentialClaims {
        subject_id: Some("did:example:holder".into()),
        credential_type: "VerifiedWalletCredential".into(),
        claims: HashMap::from([
            ("email".into(), serde_json::json!("member@example.com")),
            ("role".into(), serde_json::json!("member")),
            ("cnf".into(), serde_json::json!({"jwk": holder_cnf_jwk})),
        ]),
        expiration_seconds: None,
        selective_disclosure_claims: vec!["email".into()],
        mdoc_namespace: None,
        mdoc_doctype: None,
        zk_predicate_claims: Vec::new(),
        credential_payload_format: CredentialPayloadFormat::IetfSdJwt,
        w3c_context: Vec::new(),
        w3c_types: Vec::new(),
    };
    let signed = sign_sd_jwt(
        &IssuerKey {
            issuer_id: issuer.clone(),
            jwk_json: issuer_private_jwk.clone(),
            algorithm: SigningAlgorithm::ES256,
        },
        &claims,
    )
    .unwrap();
    let credential = match signed {
        SignedCredential::SdJwt { compact, .. } => compact,
        _ => panic!("expected SD-JWT"),
    };

    let mut issuer_public_jwk = p256_jwk(&issuer_signing_key, false);
    issuer_public_jwk["kid"] = serde_json::Value::String(issuer.clone());
    issuer_public_jwk["alg"] = serde_json::Value::String("ES256".into());

    Fixture {
        credential,
        issuer,
        issuer_public_jwk: issuer_public_jwk.to_string(),
        issuer_private_jwk,
        holder_private_jwk,
    }
}

fn resolver_for(fixture: &Fixture) -> StaticResolver {
    StaticResolver {
        key: ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some(fixture.issuer.clone()),
            SigningAlgorithm::ES256,
            fixture.issuer_public_jwk.clone(),
        ),
    }
}

fn tamper_issuer_signature(credential: &str) -> String {
    let (issuer_jws, suffix) = credential.split_once('~').unwrap();
    let mut segments = issuer_jws
        .split('.')
        .map(str::to_string)
        .collect::<Vec<_>>();
    let signature = segments.get_mut(2).unwrap();
    let replacement = if signature.starts_with('A') { "B" } else { "A" };
    signature.replace_range(..1, replacement);
    format!("{}~{suffix}", segments.join("."))
}

fn mutate_issuer_header(credential: &str, mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let (issuer_jws, suffix) = credential.split_once('~').unwrap();
    let mut segments = issuer_jws
        .split('.')
        .map(str::to_string)
        .collect::<Vec<_>>();
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&segments[0])
        .unwrap();
    let mut header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    mutate(&mut header);
    segments[0] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap());
    format!("{}~{suffix}", segments.join("."))
}

fn mutate_issuer_header_and_resign(
    fixture: &Fixture,
    mutate: impl FnOnce(&mut serde_json::Value),
) -> String {
    let (issuer_jws, suffix) = fixture.credential.split_once('~').unwrap();
    let segments = issuer_jws.split('.').collect::<Vec<_>>();
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[0])
        .unwrap();
    let mut header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    mutate(&mut header);
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).unwrap());
    let signing_input = format!("{header}.{}", segments[1]);
    let signature = IssuerKey {
        issuer_id: fixture.issuer.clone(),
        jwk_json: fixture.issuer_private_jwk.clone(),
        algorithm: SigningAlgorithm::ES256,
    }
    .sign(signing_input.as_bytes())
    .unwrap();
    format!(
        "{signing_input}.{}~{suffix}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    )
}

fn mutate_issuer_payload(credential: &str, mutate: impl FnOnce(&mut serde_json::Value)) -> String {
    let (issuer_jws, suffix) = credential.split_once('~').unwrap();
    let mut segments = issuer_jws
        .split('.')
        .map(str::to_string)
        .collect::<Vec<_>>();
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&segments[1])
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
    mutate(&mut payload);
    segments[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    format!("{}~{suffix}", segments.join("."))
}

fn replace_issuer_algorithm(credential: &str, algorithm: &str) -> String {
    mutate_issuer_header(credential, |header| {
        header["alg"] = serde_json::Value::String(algorithm.into());
    })
}

#[test]
fn verified_presentation_authenticates_issuer_and_holder_before_kb_jwt() {
    let fixture = fixture();
    let presentation = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &fixture.holder_private_jwk,
            &resolver_for(&fixture),
        )
        .unwrap();

    let verified = verify_sd_jwt(
        &presentation,
        &fixture.issuer_public_jwk,
        Some("https://verifier.example".into()),
        Some("nonce-123".into()),
    )
    .unwrap();
    assert_eq!(verified["email"], "member@example.com");
    assert_eq!(verified["role"], "member");
}

#[test]
fn verified_presentation_accepts_transitional_dc_sd_jwt_type() {
    let fixture = fixture();
    let credential = mutate_issuer_header_and_resign(&fixture, |header| {
        header["typ"] = serde_json::json!("dc+sd-jwt");
    });

    WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &fixture.holder_private_jwk,
            &resolver_for(&fixture),
        )
        .unwrap();
}

#[test]
fn verified_presentation_rejects_invalid_issuer_signature() {
    let fixture = fixture();
    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &tamper_issuer_signature(&fixture.credential),
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            "not-a-holder-jwk",
            &resolver_for(&fixture),
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
    assert!(error.to_string().contains("issuer verification failed"));
}

#[test]
fn unsupported_issuer_algorithm_is_rejected_before_resolution() {
    let fixture = fixture();
    let resolver = CountingResolver::default();
    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &replace_issuer_algorithm(&fixture.credential, "HS256"),
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &fixture.holder_private_jwk,
            &resolver,
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
    assert!(error
        .to_string()
        .contains("Unsupported SD-JWT issuer algorithm"));
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn unsupported_critical_header_is_rejected_before_resolution() {
    let fixture = fixture();
    let resolver = CountingResolver::default();
    let credential = mutate_issuer_header(&fixture.credential, |header| {
        header["crit"] = serde_json::json!(["b64"]);
        header["b64"] = serde_json::json!(false);
    });
    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &fixture.holder_private_jwk,
            &resolver,
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
    assert!(error.to_string().contains("unsupported critical JOSE"));
    assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn missing_or_unrecognized_credential_type_is_rejected_before_resolution() {
    let fixture = fixture();
    let credentials = [
        mutate_issuer_header(&fixture.credential, |header| {
            header.as_object_mut().unwrap().remove("typ");
        }),
        mutate_issuer_header(&fixture.credential, |header| {
            header["typ"] = serde_json::json!("JWT");
        }),
    ];

    for credential in credentials {
        let resolver = CountingResolver::default();
        let error = WalletEngine::new()
            .create_verified_sd_jwt_presentation(
                &credential,
                &["email".into()],
                "nonce-123",
                "https://verifier.example",
                &fixture.holder_private_jwk,
                &resolver,
            )
            .unwrap_err();

        assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
        assert!(error.to_string().contains("protected `typ`"));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn missing_or_empty_vct_is_rejected_before_resolution() {
    let fixture = fixture();
    let credentials = [
        mutate_issuer_payload(&fixture.credential, |payload| {
            payload.as_object_mut().unwrap().remove("vct");
        }),
        mutate_issuer_payload(&fixture.credential, |payload| {
            payload["vct"] = serde_json::json!("   ");
        }),
    ];

    for credential in credentials {
        let resolver = CountingResolver::default();
        let error = WalletEngine::new()
            .create_verified_sd_jwt_presentation(
                &credential,
                &["email".into()],
                "nonce-123",
                "https://verifier.example",
                &fixture.holder_private_jwk,
                &resolver,
            )
            .unwrap_err();

        assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
        assert!(error.to_string().contains("string `vct`"));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn empty_transaction_binding_is_rejected_before_resolution() {
    let fixture = fixture();
    for (nonce, audience) in [
        ("", "https://verifier.example"),
        ("nonce-123", ""),
        ("   ", "https://verifier.example"),
        ("nonce-123", "   "),
    ] {
        let resolver = CountingResolver::default();
        let error = WalletEngine::new()
            .create_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                nonce,
                audience,
                &fixture.holder_private_jwk,
                &resolver,
            )
            .unwrap_err();
        assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn verified_presentation_rejects_holder_key_not_bound_by_cnf() {
    let fixture = fixture();
    let other_holder_jwk = p256_jwk(&SigningKey::random(&mut OsRng), true).to_string();
    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &other_holder_jwk,
            &resolver_for(&fixture),
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::KeyError(_)));
    assert!(error
        .to_string()
        .contains("does not match the verified SD-JWT `cnf.jwk`"));
}

#[test]
fn verified_presentation_rejects_resolver_identity_or_algorithm_mismatch() {
    let fixture = fixture();
    let mismatches = [
        ResolvedSdJwtIssuerKey::new(
            "did:example:wrong-issuer",
            Some(fixture.issuer.clone()),
            SigningAlgorithm::ES256,
            fixture.issuer_public_jwk.clone(),
        ),
        ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some("did:example:wrong-key".into()),
            SigningAlgorithm::ES256,
            fixture.issuer_public_jwk.clone(),
        ),
        ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some(fixture.issuer.clone()),
            SigningAlgorithm::ES384,
            fixture.issuer_public_jwk.clone(),
        ),
    ];

    for key in mismatches {
        let error = WalletEngine::new()
            .create_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                "nonce-123",
                "https://verifier.example",
                &fixture.holder_private_jwk,
                &StaticResolver { key },
            )
            .unwrap_err();
        assert!(matches!(error, Oid4vciError::KeyError(_)));
    }
}

#[test]
fn verified_presentation_rejects_incompatible_issuer_jwk_policy() {
    let fixture = fixture();
    let base: serde_json::Value = serde_json::from_str(&fixture.issuer_public_jwk).unwrap();
    let mut encryption_use = base.clone();
    encryption_use["use"] = serde_json::json!("enc");
    let mut signing_only = base.clone();
    signing_only["key_ops"] = serde_json::json!(["sign"]);
    let mut wrong_jwk_kid = base.clone();
    wrong_jwk_kid["kid"] = serde_json::json!("did:example:wrong-key");
    let mut wrong_curve = base;
    wrong_curve["crv"] = serde_json::json!("P-384");

    for public_jwk in [encryption_use, signing_only, wrong_jwk_kid, wrong_curve] {
        let resolver = StaticResolver {
            key: ResolvedSdJwtIssuerKey::new(
                fixture.issuer.clone(),
                Some(fixture.issuer.clone()),
                SigningAlgorithm::ES256,
                public_jwk.to_string(),
            ),
        };
        let error = WalletEngine::new()
            .create_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                "nonce-123",
                "https://verifier.example",
                &fixture.holder_private_jwk,
                &resolver,
            )
            .unwrap_err();
        assert!(matches!(error, Oid4vciError::KeyError(_)));
    }
}

#[test]
fn malformed_or_duplicate_resolver_jwk_is_a_key_error() {
    let fixture = fixture();
    let duplicate =
        fixture
            .issuer_public_jwk
            .replacen("\"kty\":\"EC\"", "\"kty\":\"EC\",\"kty\":\"EC\"", 1);
    for public_jwk in ["{".to_string(), duplicate] {
        let resolver = StaticResolver {
            key: ResolvedSdJwtIssuerKey::new(
                fixture.issuer.clone(),
                Some(fixture.issuer.clone()),
                SigningAlgorithm::ES256,
                public_jwk,
            ),
        };
        let error = WalletEngine::new()
            .create_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                "nonce-123",
                "https://verifier.example",
                &fixture.holder_private_jwk,
                &resolver,
            )
            .unwrap_err();
        assert!(matches!(error, Oid4vciError::KeyError(_)));
        assert_eq!(error.to_string(), "Key error: Invalid issuer public JWK");
    }
}

#[test]
fn no_kid_binding_rejects_a_present_malformed_jwk_kid() {
    let fixture = fixture();
    let credential = mutate_issuer_header_and_resign(&fixture, |header| {
        header.as_object_mut().unwrap().remove("kid");
    });
    let mut public_jwk: serde_json::Value =
        serde_json::from_str(&fixture.issuer_public_jwk).unwrap();
    public_jwk.as_object_mut().unwrap().remove("kid");

    WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &fixture.holder_private_jwk,
            &StaticResolver {
                key: ResolvedSdJwtIssuerKey::new(
                    fixture.issuer.clone(),
                    None,
                    SigningAlgorithm::ES256,
                    public_jwk.to_string(),
                ),
            },
        )
        .unwrap();

    for malformed_kid in [serde_json::Value::Null, serde_json::json!("")] {
        public_jwk["kid"] = malformed_kid;
        let error = WalletEngine::new()
            .create_verified_sd_jwt_presentation(
                &credential,
                &["email".into()],
                "nonce-123",
                "https://verifier.example",
                &fixture.holder_private_jwk,
                &StaticResolver {
                    key: ResolvedSdJwtIssuerKey::new(
                        fixture.issuer.clone(),
                        None,
                        SigningAlgorithm::ES256,
                        public_jwk.to_string(),
                    ),
                },
            )
            .unwrap_err();

        assert!(matches!(error, Oid4vciError::KeyError(_)));
        assert!(error.to_string().contains("non-empty string when present"));
    }
}

#[test]
fn verified_presentation_rejects_private_issuer_material_from_resolver() {
    let fixture = fixture();
    let resolver = StaticResolver {
        key: ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some(fixture.issuer.clone()),
            SigningAlgorithm::ES256,
            fixture.issuer_private_jwk.clone(),
        ),
    };
    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &fixture.holder_private_jwk,
            &resolver,
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::KeyError(_)));
    assert!(error
        .to_string()
        .contains("contains private key material: d"));
}

#[test]
fn verified_presentation_rejects_private_holder_material_in_signed_cnf() {
    let fixture = fixture_with_cnf(true);
    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &fixture.holder_private_jwk,
            &resolver_for(&fixture),
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::KeyError(_)));
    assert!(error
        .to_string()
        .contains("contains private key material: d"));
}

#[test]
fn verified_presentation_derives_holder_public_key_from_private_scalar() {
    let fixture = fixture();
    let other_holder = p256_jwk(&SigningKey::random(&mut OsRng), false);
    let mut inconsistent_holder: serde_json::Value =
        serde_json::from_str(&fixture.holder_private_jwk).unwrap();
    inconsistent_holder["x"] = other_holder["x"].clone();
    inconsistent_holder["y"] = other_holder["y"].clone();

    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &inconsistent_holder.to_string(),
            &resolver_for(&fixture),
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
    assert!(error
        .to_string()
        .contains("public coordinates do not match the private key"));
}

#[test]
fn verified_presentation_uses_the_canonical_holder_jwk_boundary() {
    let fixture = fixture();
    let mut noncanonical: serde_json::Value =
        serde_json::from_str(&fixture.holder_private_jwk).unwrap();
    noncanonical["alg"] = serde_json::json!("ES256");
    let error = WalletEngine::new()
        .create_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            "nonce-123",
            "https://verifier.example",
            &noncanonical.to_string(),
            &resolver_for(&fixture),
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn resolved_issuer_key_debug_is_redacted() {
    let fixture = fixture();
    let resolved = ResolvedSdJwtIssuerKey::new(
        fixture.issuer.clone(),
        Some(fixture.issuer.clone()),
        SigningAlgorithm::ES256,
        fixture.issuer_private_jwk.clone(),
    );
    let diagnostic = format!("{resolved:?}");

    assert_eq!(diagnostic, "ResolvedSdJwtIssuerKey([redacted])");
    assert!(!diagnostic.contains(&fixture.issuer_private_jwk));
}
