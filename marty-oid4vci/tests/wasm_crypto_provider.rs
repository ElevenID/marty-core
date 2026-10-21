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
fn browser_build_rejects_every_rsa_pss_algorithm() {
    let public_jwk = |algorithm: &str| {
        serde_json::json!({
            "kty": "RSA",
            "alg": algorithm,
            "n": URL_SAFE_NO_PAD.encode([0xA5; 256]),
            "e": "AQAB",
        })
        .to_string()
    };

    for algorithm in ["PS256", "PS384", "PS512"] {
        assert!(
            marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                b"browser RSA-PSS must remain unavailable",
                &[0x5A; 256],
                &public_jwk(algorithm),
                algorithm,
            )
            .is_err(),
            "{algorithm} unexpectedly became available in the browser build"
        );
    }
}
