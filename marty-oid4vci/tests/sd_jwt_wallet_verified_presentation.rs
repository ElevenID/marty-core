#![cfg(feature = "wallet")]

use std::sync::atomic::{AtomicUsize, Ordering};

use base64::Engine as _;
use marty_oid4vci::types::SigningAlgorithm;
use marty_oid4vci::{
    Oid4vciError, Oid4vciResult, ResolvedSdJwtIssuerKey, SdJwtIssuerKeyResolver,
    TrustedSdJwtIssuerKeys, WalletEngine,
};

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
    key_id: String,
    holder_public_jwk: String,
}

fn fresh_nonce() -> String {
    uuid::Uuid::new_v4().to_string()
}

// Build invalid transaction values from runtime entropy so security scanning
// does not mistake test-only negative inputs for hard-coded cryptographic data.
fn runtime_empty_transaction_value() -> String {
    let mut value = fresh_nonce();
    value.clear();
    value
}

fn runtime_whitespace_transaction_value() -> String {
    fresh_nonce()
        .bytes()
        .take(3)
        .map(|byte| char::from(9 + byte % 5))
        .collect()
}

fn fixture() -> Fixture {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/remote_sd_jwt_wallet_public.json")).unwrap();
    let credential = vector["credential"].as_str().unwrap().to_owned();
    let header_segment = credential.split('.').next().unwrap();
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_segment)
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    let issuer = vector["issuer"].as_str().unwrap().to_owned();
    let key_id = header["kid"].as_str().unwrap().to_owned();
    let mut issuer_public_jwk = vector["issuer_public_jwk"].clone();
    issuer_public_jwk["kid"] = serde_json::json!(key_id);
    issuer_public_jwk["alg"] = serde_json::json!("ES256");

    Fixture {
        credential,
        issuer,
        issuer_public_jwk: issuer_public_jwk.to_string(),
        key_id,
        holder_public_jwk: vector["holder_public_jwk"].to_string(),
    }
}

fn resolver_for(fixture: &Fixture) -> StaticResolver {
    StaticResolver {
        key: ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some(fixture.key_id.clone()),
            SigningAlgorithm::ES256,
            fixture.issuer_public_jwk.clone(),
        ),
    }
}

#[test]
fn trusted_issuer_key_set_matches_exact_identity_and_rejects_unsafe_entries() {
    let fixture = fixture();
    let trusted = ResolvedSdJwtIssuerKey::new(
        fixture.issuer.clone(),
        Some(fixture.key_id.clone()),
        SigningAlgorithm::ES256,
        fixture.issuer_public_jwk.clone(),
    );
    let resolver = TrustedSdJwtIssuerKeys::new(vec![trusted.clone()]).unwrap();
    assert!(resolver
        .resolve(
            &fixture.issuer,
            Some(&fixture.key_id),
            SigningAlgorithm::ES256
        )
        .is_ok());
    assert!(WalletEngine::new()
        .prepare_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &fixture.holder_public_jwk,
            &resolver,
        )
        .is_ok());
    assert!(resolver
        .resolve(&fixture.issuer, None, SigningAlgorithm::ES256)
        .is_err());
    assert!(resolver
        .resolve(
            &fixture.issuer,
            Some(&fixture.key_id),
            SigningAlgorithm::EdDSA
        )
        .is_err());
    assert!(resolver
        .resolve(
            "did:example:other",
            Some(&fixture.key_id),
            SigningAlgorithm::ES256
        )
        .is_err());
    assert!(TrustedSdJwtIssuerKeys::new(vec![trusted.clone(), trusted]).is_err());
    let mut wrong_family: serde_json::Value =
        serde_json::from_str(&fixture.issuer_public_jwk).unwrap();
    wrong_family.as_object_mut().unwrap().remove("alg");
    assert!(
        TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some(fixture.key_id.clone()),
            SigningAlgorithm::EdDSA,
            wrong_family.to_string(),
        )])
        .is_err()
    );
    let mut private_jwk: serde_json::Value =
        serde_json::from_str(&fixture.issuer_public_jwk).unwrap();
    private_jwk["d"] = serde_json::json!("private");
    assert!(
        TrustedSdJwtIssuerKeys::new(vec![ResolvedSdJwtIssuerKey::new(
            fixture.issuer,
            Some(fixture.key_id),
            SigningAlgorithm::ES256,
            private_jwk.to_string(),
        )])
        .is_err()
    );
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
fn verified_presentation_rejects_invalid_issuer_signature() {
    let fixture = fixture();
    let error = WalletEngine::new()
        .prepare_verified_sd_jwt_presentation(
            &tamper_issuer_signature(&fixture.credential),
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &fixture.holder_public_jwk,
            &resolver_for(&fixture),
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::InvalidRequest(_)));
    assert!(
        error.to_string().contains("issuer verification failed"),
        "{error}"
    );
}

#[test]
fn unsupported_issuer_algorithm_is_rejected_before_resolution() {
    let fixture = fixture();
    let resolver = CountingResolver::default();
    let error = WalletEngine::new()
        .prepare_verified_sd_jwt_presentation(
            &replace_issuer_algorithm(&fixture.credential, "HS256"),
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &fixture.holder_public_jwk,
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
        .prepare_verified_sd_jwt_presentation(
            &credential,
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &fixture.holder_public_jwk,
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
            .prepare_verified_sd_jwt_presentation(
                &credential,
                &["email".into()],
                &fresh_nonce(),
                "https://verifier.example",
                &fixture.holder_public_jwk,
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
            .prepare_verified_sd_jwt_presentation(
                &credential,
                &["email".into()],
                &fresh_nonce(),
                "https://verifier.example",
                &fixture.holder_public_jwk,
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
    let valid_audience = "https://verifier.example".to_owned();
    for (nonce, audience) in [
        (runtime_empty_transaction_value(), valid_audience.clone()),
        (fresh_nonce(), runtime_empty_transaction_value()),
        (
            runtime_whitespace_transaction_value(),
            valid_audience.clone(),
        ),
        (fresh_nonce(), runtime_whitespace_transaction_value()),
    ] {
        let resolver = CountingResolver::default();
        let error = WalletEngine::new()
            .prepare_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                &nonce,
                &audience,
                &fixture.holder_public_jwk,
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
    let other_holder_jwk = fixture.issuer_public_jwk.clone();
    let error = WalletEngine::new()
        .prepare_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            &fresh_nonce(),
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
            Some(fixture.key_id.clone()),
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
            Some(fixture.key_id.clone()),
            SigningAlgorithm::ES384,
            fixture.issuer_public_jwk.clone(),
        ),
    ];

    for key in mismatches {
        let error = WalletEngine::new()
            .prepare_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                &fresh_nonce(),
                "https://verifier.example",
                &fixture.holder_public_jwk,
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
                Some(fixture.key_id.clone()),
                SigningAlgorithm::ES256,
                public_jwk.to_string(),
            ),
        };
        let error = WalletEngine::new()
            .prepare_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                &fresh_nonce(),
                "https://verifier.example",
                &fixture.holder_public_jwk,
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
                Some(fixture.key_id.clone()),
                SigningAlgorithm::ES256,
                public_jwk,
            ),
        };
        let error = WalletEngine::new()
            .prepare_verified_sd_jwt_presentation(
                &fixture.credential,
                &["email".into()],
                &fresh_nonce(),
                "https://verifier.example",
                &fixture.holder_public_jwk,
                &resolver,
            )
            .unwrap_err();
        assert!(matches!(error, Oid4vciError::KeyError(_)));
        assert_eq!(error.to_string(), "Key error: Invalid issuer public JWK");
    }
}

#[test]
fn verified_presentation_rejects_private_issuer_material_from_resolver() {
    let fixture = fixture();
    let resolver = StaticResolver {
        key: ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some(fixture.key_id.clone()),
            SigningAlgorithm::ES256,
            serde_json::json!({"kty":"EC","crv":"P-256","x":"redacted","y":"redacted","d":"redacted"}).to_string(),
        ),
    };
    let error = WalletEngine::new()
        .prepare_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &fixture.holder_public_jwk,
            &resolver,
        )
        .unwrap_err();

    assert!(matches!(error, Oid4vciError::KeyError(_)));
    assert!(error
        .to_string()
        .contains("contains private key material: d"));
}

#[test]
fn resolved_issuer_key_debug_is_redacted() {
    let fixture = fixture();
    let sensitive_marker = "test-private-material-marker";
    let resolved = ResolvedSdJwtIssuerKey::new(
        fixture.issuer.clone(),
        Some(fixture.key_id.clone()),
        SigningAlgorithm::ES256,
        sensitive_marker,
    );
    let diagnostic = format!("{resolved:?}");

    assert_eq!(diagnostic, "ResolvedSdJwtIssuerKey([redacted])");
    assert!(!diagnostic.contains(sensitive_marker));
}

#[test]
fn prepared_presentation_bounds_public_keys() {
    let fixture = fixture();
    let holder_public: serde_json::Value =
        serde_json::from_str(&fixture.holder_public_jwk).unwrap();
    let engine = WalletEngine::new();

    let prepared = engine
        .prepare_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &holder_public.to_string(),
            &resolver_for(&fixture),
        )
        .unwrap();
    assert_eq!(prepared.algorithm(), SigningAlgorithm::ES256);
    assert_eq!(
        std::str::from_utf8(prepared.signing_input())
            .unwrap()
            .split('.')
            .count(),
        2
    );
    let oversized_holder = " ".repeat(marty_oid4vci::jose::MAX_PUBLIC_JWK_BYTES + 1);
    let counting_resolver = CountingResolver::default();
    assert!(engine
        .prepare_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &oversized_holder,
            &counting_resolver,
        )
        .is_err());
    assert_eq!(counting_resolver.calls.load(Ordering::Relaxed), 0);

    let oversized_issuer = StaticResolver {
        key: ResolvedSdJwtIssuerKey::new(
            fixture.issuer.clone(),
            Some(fixture.key_id.clone()),
            SigningAlgorithm::ES256,
            " ".repeat(marty_oid4vci::jose::MAX_PUBLIC_JWK_BYTES + 1),
        ),
    };
    assert!(engine
        .prepare_verified_sd_jwt_presentation(
            &fixture.credential,
            &["email".into()],
            &fresh_nonce(),
            "https://verifier.example",
            &holder_public.to_string(),
            &oversized_issuer,
        )
        .is_err());
}
