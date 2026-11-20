#![cfg(target_family = "wasm")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn marty_and_sd_jwt_share_curve_verification_provider() {
    sd_jwt_rs::install_crypto_provider().expect("SD-JWT provider installs idempotently");

    let message = b"shared browser verification provider";
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/wasm_provider_public.json"))
            .expect("public browser verification vectors");

    {
        let public_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "alg": "ES384",
            "x": vectors["p384"]["x"],
            "y": vectors["p384"]["y"],
        })
        .to_string();
        let signature = URL_SAFE_NO_PAD
            .decode(vectors["p384"]["signature"].as_str().unwrap())
            .unwrap();
        assert!(
            marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                message,
                &signature,
                &public_jwk,
                "ES384",
            )
            .unwrap()
        );
    }

    {
        let public_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": vectors["ed25519"]["x"],
        })
        .to_string();
        let signature = URL_SAFE_NO_PAD
            .decode(vectors["ed25519"]["signature"].as_str().unwrap())
            .unwrap();
        assert!(
            marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                message,
                &signature,
                &public_jwk,
                "EdDSA",
            )
            .unwrap()
        );
    }
}

#[wasm_bindgen_test]
fn browser_build_rejects_every_rsa_algorithm() {
    let public_jwk = |algorithm: &str| {
        serde_json::json!({
            "kty": "RSA",
            "alg": algorithm,
            "n": URL_SAFE_NO_PAD.encode([0xA5; 256]),
            "e": "AQAB",
        })
        .to_string()
    };

    for algorithm in ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"] {
        assert!(
            marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                b"browser RSA must remain unavailable",
                &[0x5A; 256],
                &public_jwk(algorithm),
                algorithm,
            )
            .is_err(),
            "{algorithm} unexpectedly became available in the browser build"
        );
    }
}

#[wasm_bindgen_test]
fn browser_public_key_admission_rejects_unknown_and_malformed_jwk_shapes() {
    for jwk in [
        serde_json::json!({"kty":"future-key-family","public":"opaque"}),
        serde_json::json!({"kty":"EC","crv":"P-256","x":"AA"}),
        serde_json::json!({"kty":"EC","crv":"future-curve","x":"AA","y":"AA"}),
        serde_json::json!({"kty":"RSA","n":"AQAB"}),
        serde_json::json!({"kty":"OKP","crv":"Ed25519"}),
    ] {
        assert!(
            marty_oid4vci::jose::validate_public_signing_jwk_json(&jwk.to_string(), "ES256",)
                .is_err()
        );
        let header =
            URL_SAFE_NO_PAD.encode(serde_json::json!({"alg": "ES256", "jwk": jwk}).to_string());
        let error = marty_oid4vci::jose::verify_compact_jwt_with_public_jwk(
            &format!("{header}.e30.AA"),
            "external JWK must not be parsed",
            "ES256",
        )
        .unwrap_err();
        assert!(error.to_string().contains("protected header public JWK"));
    }
}

#[wasm_bindgen_test]
fn browser_provider_rejects_local_signing_and_private_key_utilities() {
    use jsonwebtoken::{errors::ErrorKind, jwk::Jwk, Algorithm, EncodingKey};

    sd_jwt_rs::install_crypto_provider().unwrap();
    for (algorithm, key) in [
        (Algorithm::ES256, EncodingKey::from_ec_der(&[0; 48])),
        (Algorithm::EdDSA, EncodingKey::from_ed_der(&[0; 48])),
        (Algorithm::RS256, EncodingKey::from_rsa_der(&[0; 48])),
        (
            Algorithm::HS256,
            EncodingKey::from_secret(b"not a credential key"),
        ),
    ] {
        let error = jsonwebtoken::crypto::sign(b"prepared.payload", &key, algorithm)
            .expect_err("Core must use the verification-only browser provider");
        assert!(matches!(error.kind(), ErrorKind::Provider(_)));
        if algorithm != Algorithm::HS256 {
            assert!(matches!(
                Jwk::from_encoding_key(&key, algorithm).unwrap_err().kind(),
                ErrorKind::Provider(_)
            ));
        }
    }
}

#[wasm_bindgen_test]
fn browser_uuid_uses_the_explicit_randomness_source() {
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    assert_eq!(first.get_version(), Some(uuid::Version::Random));
    assert_eq!(second.get_version(), Some(uuid::Version::Random));
    assert_ne!(first, second);
}
