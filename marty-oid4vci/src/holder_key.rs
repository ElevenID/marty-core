//! Canonical holder-key generation and `did:jwk` encoding.
//!
//! This module is network-free and is shared by native, Python, Flutter, and
//! WebAssembly adapters. Protocol adapters must not reimplement JWK or DID
//! construction in their host language.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Oid4vciError, Oid4vciResult};

const MAX_HOLDER_JWK_BYTES: usize = 16 * 1024;

/// Canonical P-256 `did:jwk` holder material for wallet storage.
///
/// The DID method-specific identifier is the unpadded base64url encoding of
/// [`Self::public_jwk`]. The private JWK is never embedded in the DID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidJwkHolderKeyMaterial {
    /// Self-contained public `did:jwk` identifier used as the proof JWT `kid`.
    pub kid: String,
    /// Private P-256 JWK. Callers must store this as sensitive key material.
    pub private_jwk: String,
    /// Canonical public P-256 JWK safe to disclose to issuers.
    pub public_jwk: String,
}

#[derive(Serialize)]
struct PublicP256Jwk<'a> {
    kty: &'static str,
    crv: &'static str,
    x: &'a str,
    y: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateP256Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
    d: String,
}

/// Generate canonical P-256 holder material represented as `did:jwk`.
pub fn generate_p256_did_jwk_holder_key() -> Oid4vciResult<DidJwkHolderKeyMaterial> {
    let signing_key = generate_p256_signing_key();
    did_jwk_holder_material_from_signing_key(&signing_key)
}

/// Validate stored private P-256 JWK material and derive its canonical public
/// JWK and `did:jwk` identifier.
///
/// Malformed or mismatched public coordinates fail closed instead of being
/// trusted by a host-language adapter.
pub fn p256_did_jwk_holder_key_from_private_jwk(
    private_jwk: &str,
) -> Oid4vciResult<DidJwkHolderKeyMaterial> {
    let signing_key = p256_signing_key_from_private_jwk(private_jwk)?;
    did_jwk_holder_material_from_signing_key(&signing_key)
}

pub(crate) fn p256_signing_key_from_private_jwk(
    private_jwk: &str,
) -> Oid4vciResult<p256::ecdsa::SigningKey> {
    if private_jwk.is_empty() {
        return Err(Oid4vciError::InvalidRequest(
            "Holder private JWK is empty".into(),
        ));
    }
    if private_jwk.len() > MAX_HOLDER_JWK_BYTES {
        return Err(Oid4vciError::InvalidRequest(
            "Holder private JWK exceeds the maximum size".into(),
        ));
    }
    if private_jwk.contains('\0') {
        return Err(Oid4vciError::InvalidRequest(
            "Holder private JWK contains a NUL byte".into(),
        ));
    }

    let parsed: PrivateP256Jwk = serde_json::from_str(private_jwk).map_err(|error| {
        Oid4vciError::InvalidRequest(format!("Invalid holder private JWK: {error}"))
    })?;
    if parsed.kty != "EC" || parsed.crv != "P-256" {
        return Err(Oid4vciError::InvalidRequest(
            "Holder JWK must be an EC P-256 private key".into(),
        ));
    }

    let d = decode_p256_coordinate("d", &parsed.d)?;
    let signing_key = p256::ecdsa::SigningKey::from_slice(&d).map_err(|error| {
        Oid4vciError::KeyError(format!("Invalid P-256 holder private key: {error}"))
    })?;
    let supplied_x = decode_p256_coordinate("x", &parsed.x)?;
    let supplied_y = decode_p256_coordinate("y", &parsed.y)?;
    let (expected_x, expected_y) = p256_public_coordinates(&signing_key)?;
    if supplied_x != expected_x || supplied_y != expected_y {
        return Err(Oid4vciError::InvalidRequest(
            "Holder JWK public coordinates do not match the private key".into(),
        ));
    }

    Ok(signing_key)
}

pub(crate) fn generate_p256_signing_key() -> p256::ecdsa::SigningKey {
    use p256::elliptic_curve::rand_core::OsRng;

    p256::ecdsa::SigningKey::random(&mut OsRng)
}

pub(crate) fn p256_public_coordinates(
    signing_key: &p256::ecdsa::SigningKey,
) -> Oid4vciResult<(Vec<u8>, Vec<u8>)> {
    let encoded_point = signing_key.verifying_key().to_encoded_point(false);
    let x = encoded_point
        .x()
        .ok_or_else(|| Oid4vciError::KeyError("P-256 public key has no x coordinate".into()))?;
    let y = encoded_point
        .y()
        .ok_or_else(|| Oid4vciError::KeyError("P-256 public key has no y coordinate".into()))?;
    Ok((x.to_vec(), y.to_vec()))
}

fn did_jwk_holder_material_from_signing_key(
    signing_key: &p256::ecdsa::SigningKey,
) -> Oid4vciResult<DidJwkHolderKeyMaterial> {
    let (x_bytes, y_bytes) = p256_public_coordinates(signing_key)?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let x = b64.encode(x_bytes);
    let y = b64.encode(y_bytes);
    let d = b64.encode(signing_key.to_bytes());
    let public_jwk = serde_json::to_string(&PublicP256Jwk {
        kty: "EC",
        crv: "P-256",
        x: &x,
        y: &y,
    })
    .map_err(|error| Oid4vciError::KeyError(format!("Public JWK encoding failed: {error}")))?;
    let private_jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "d": d,
    })
    .to_string();
    let kid = format!("did:jwk:{}", b64.encode(public_jwk.as_bytes()));

    Ok(DidJwkHolderKeyMaterial {
        kid,
        private_jwk,
        public_jwk,
    })
}

fn decode_p256_coordinate(name: &str, value: &str) -> Oid4vciResult<Vec<u8>> {
    if value.contains('=') {
        return Err(Oid4vciError::InvalidRequest(format!(
            "Holder JWK '{name}' must use unpadded base64url"
        )));
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| {
            Oid4vciError::InvalidRequest(format!("Holder JWK '{name}' decode error: {error}"))
        })?;
    if decoded.len() != 32 {
        return Err(Oid4vciError::InvalidRequest(format!(
            "Holder JWK '{name}' must decode to 32 bytes"
        )));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_did_jwk_holder_material_is_canonical_and_round_trips() {
        let generated = generate_p256_did_jwk_holder_key().unwrap();
        let encoded_public = generated.kid.strip_prefix("did:jwk:").unwrap();
        let decoded_public = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded_public)
            .unwrap();
        assert_eq!(decoded_public, generated.public_jwk.as_bytes());

        let public: serde_json::Value = serde_json::from_str(&generated.public_jwk).unwrap();
        assert_eq!(public["kty"], "EC");
        assert_eq!(public["crv"], "P-256");
        assert!(public.get("d").is_none());

        let restored = p256_did_jwk_holder_key_from_private_jwk(&generated.private_jwk).unwrap();
        assert_eq!(restored.kid, generated.kid);
        assert_eq!(restored.public_jwk, generated.public_jwk);
        assert_eq!(restored.private_jwk, generated.private_jwk);
    }

    #[test]
    fn stored_holder_jwk_fails_closed_on_mismatched_public_key() {
        let first = generate_p256_did_jwk_holder_key().unwrap();
        let second = generate_p256_did_jwk_holder_key().unwrap();
        let second_public: serde_json::Value = serde_json::from_str(&second.public_jwk).unwrap();
        let mut tampered: serde_json::Value = serde_json::from_str(&first.private_jwk).unwrap();
        tampered["x"] = second_public["x"].clone();

        let error = match p256_did_jwk_holder_key_from_private_jwk(&tampered.to_string()) {
            Ok(_) => panic!("mismatched public coordinates must be rejected"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("public coordinates do not match"));
    }

    #[test]
    fn stored_holder_jwk_rejects_noncanonical_and_oversized_input() {
        let generated = generate_p256_did_jwk_holder_key().unwrap();
        let mut padded: serde_json::Value = serde_json::from_str(&generated.private_jwk).unwrap();
        padded["d"] = serde_json::Value::String(format!("{}=", padded["d"].as_str().unwrap()));
        assert!(p256_did_jwk_holder_key_from_private_jwk(&padded.to_string()).is_err());
        assert!(
            p256_did_jwk_holder_key_from_private_jwk(&"x".repeat(MAX_HOLDER_JWK_BYTES + 1))
                .is_err()
        );
    }
}
