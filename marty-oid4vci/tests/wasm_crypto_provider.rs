#![cfg(target_family = "wasm")]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn marty_and_sd_jwt_share_curve_verification_provider() {
    sd_jwt_rs::install_crypto_provider().expect("SD-JWT provider installs idempotently");

    let message = b"shared browser verification provider";

    {
        use p384::ecdsa::signature::Signer as _;
        let key = p384::ecdsa::SigningKey::from_slice(&[9u8; 48]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let public_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "alg": "ES384",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
        .to_string();
        let signature: p384::ecdsa::Signature = key.sign(message);
        assert!(
            marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                message,
                signature.to_bytes().as_slice(),
                &public_jwk,
                "ES384",
            )
            .unwrap()
        );
    }

    {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
        let public_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
        })
        .to_string();
        let signature = key.sign(message);
        assert!(
            marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                message,
                &signature.to_bytes(),
                &public_jwk,
                "EdDSA",
            )
            .unwrap()
        );
    }
}
