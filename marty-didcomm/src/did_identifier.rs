//! Canonical derivation of self-describing DID identifiers from public JWKs.

use crate::error::{DidcommError, DidcommResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::Value;
use std::collections::BTreeMap;

const P256_COORDINATE_BYTES: usize = 32;

fn invalid_jwk(reason: impl Into<String>) -> DidcommError {
    DidcommError::Crypto(format!("invalid P-256 public JWK: {}", reason.into()))
}

fn public_p256_jwk(jwk_json: &str) -> DidcommResult<BTreeMap<String, Value>> {
    let value: Value = serde_json::from_str(jwk_json)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid_jwk("expected a JSON object"))?;

    if object.get("kty").and_then(Value::as_str) != Some("EC")
        || object.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(invalid_jwk("kty must be EC and crv must be P-256"));
    }
    if object.contains_key("d") {
        return Err(invalid_jwk("private key material is not accepted"));
    }

    let mut public = BTreeMap::new();
    for name in ["kty", "crv", "x", "y", "kid", "alg", "use"] {
        if let Some(value) = object.get(name) {
            let text = value
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid_jwk(format!("{name} must be a non-empty string")))?;
            public.insert(name.to_string(), Value::String(text.to_string()));
        }
    }

    for coordinate in ["x", "y"] {
        let encoded = public
            .get(coordinate)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_jwk(format!("missing {coordinate} coordinate")))?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| invalid_jwk(format!("invalid {coordinate} coordinate: {error}")))?;
        if decoded.len() != P256_COORDINATE_BYTES {
            return Err(invalid_jwk(format!(
                "{coordinate} coordinate must be {P256_COORDINATE_BYTES} bytes"
            )));
        }
    }

    Ok(public)
}

/// Derive a canonical `did:jwk` from a P-256 public JWK.
///
/// The optional `kid` member is excluded because it identifies an existing key
/// rather than contributing to the self-describing DID. Supported public JWK
/// metadata is preserved to retain the established Marty identifier contract.
pub fn derive_p256_did_jwk(jwk_json: &str) -> DidcommResult<String> {
    let mut public = public_p256_jwk(jwk_json)?;
    public.remove("kid");
    let canonical = serde_json::to_vec(&public)?;
    Ok(format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(canonical)))
}

/// Derive a standards-conformant P-256 `did:key` from a public JWK.
pub fn derive_p256_did_key(jwk_json: &str) -> DidcommResult<String> {
    let public = public_p256_jwk(jwk_json)?;
    let decode_coordinate = |name: &str| -> DidcommResult<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(public[name].as_str().expect("validated string coordinate"))
            .map_err(|error| invalid_jwk(format!("invalid {name} coordinate: {error}")))
    };
    let x = decode_coordinate("x")?;
    let y = decode_coordinate("y")?;

    let mut uncompressed = Vec::with_capacity(1 + 2 * P256_COORDINATE_BYTES);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    let public_key = p256::PublicKey::from_sec1_bytes(&uncompressed)
        .map_err(|error| invalid_jwk(format!("point is not on P-256: {error}")))?;

    let compressed = public_key.to_encoded_point(true);
    let mut multicodec = Vec::with_capacity(2 + compressed.as_bytes().len());
    multicodec.extend_from_slice(&[0x80, 0x24]);
    multicodec.extend_from_slice(compressed.as_bytes());
    Ok(format!(
        "did:key:z{}",
        bs58::encode(multicodec).into_string()
    ))
}

/// Derive one of the supported self-describing DID identifiers.
pub fn derive_p256_did_identifier(jwk_json: &str, method: &str) -> DidcommResult<String> {
    match method {
        "did:jwk" | "jwk" => derive_p256_did_jwk(jwk_json),
        "did:key" | "key" => derive_p256_did_key(jwk_json),
        _ => Err(DidcommError::UnsupportedMethod {
            method: method.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_JWK: &str = r#"{"alg":"ES256","crv":"P-256","kid":"key-1","kty":"EC","use":"sig","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#;

    #[test]
    fn did_jwk_is_canonical_and_excludes_kid() {
        let did = derive_p256_did_jwk(PUBLIC_JWK).unwrap();
        let encoded = did.strip_prefix("did:jwk:").unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        assert_eq!(
            String::from_utf8(decoded).unwrap(),
            r#"{"alg":"ES256","crv":"P-256","kty":"EC","use":"sig","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"}"#
        );
    }

    #[test]
    fn did_key_round_trips_through_resolver() {
        let did = derive_p256_did_key(PUBLIC_JWK).unwrap();
        let encoded = did.strip_prefix("did:key:z").unwrap();
        let decoded = bs58::decode(encoded).into_vec().unwrap();
        assert_eq!(&decoded[..2], &[0x80, 0x24]);
        assert!(p256::PublicKey::from_sec1_bytes(&decoded[2..]).is_ok());
    }

    #[test]
    fn rejects_private_or_invalid_public_keys() {
        let private = PUBLIC_JWK.replace("\"kid\":\"key-1\"", "\"d\":\"secret\"");
        assert!(derive_p256_did_jwk(&private).is_err());
        let invalid_point = PUBLIC_JWK.replace(
            "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        assert!(derive_p256_did_key(&invalid_point).is_err());
    }

    #[test]
    fn rejects_unsupported_method() {
        assert!(matches!(
            derive_p256_did_identifier(PUBLIC_JWK, "did:web"),
            Err(DidcommError::UnsupportedMethod { .. })
        ));
    }
}
