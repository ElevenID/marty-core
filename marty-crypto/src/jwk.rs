//! Public JSON Web Key conversion primitives.
//!
//! This module owns the format conversion from SPKI public keys and X.509
//! certificates into public RFC 7517 parameters. Protocol crates may add JOSE
//! policy, but must not duplicate key parsing or coordinate extraction.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::certificate::{get_certificate_public_key, load_certificate_pem};
use crate::serialization::{load_public_key_pem, spki_to_raw_public_key};
use crate::{CryptoError, CryptoResult};

/// Public-only RFC 7517 JSON Web Key parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicJwk {
    /// Key type (`EC`, `RSA`, or `OKP`).
    pub kty: String,
    /// Intended key use.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Permitted key operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    /// Intended algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Key identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// X.509 URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// X.509 certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    /// X.509 SHA-1 thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    /// X.509 SHA-256 thumbprint.
    #[serde(rename = "x5t#S256", skip_serializing_if = "Option::is_none")]
    pub x5t_s256: Option<String>,
    /// EC or OKP curve.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate or OKP public bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// RSA modulus.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// Extension members retained during serialization.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl PublicJwk {
    /// Serialize the public JWK as JSON.
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(|error| {
            CryptoError::encoding_error(format!("JWK serialization failed: {error}"))
        })
    }
}

/// Convert a PEM SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_pem_to_jwk(pem: &str) -> CryptoResult<PublicJwk> {
    public_key_der_to_jwk(&load_public_key_pem(pem)?)
}

/// Convert a DER SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_der_to_jwk(spki: &[u8]) -> CryptoResult<PublicJwk> {
    let (raw, key_type) = spki_to_raw_public_key(spki)?;

    match key_type.as_str() {
        "EC_P256" => jwk_from_ec("P-256", &raw),
        "EC_P384" => jwk_from_ec("P-384", &raw),
        "EC_P521" => jwk_from_ec("P-521", &raw),
        "Ed25519" | "Ed448" => Ok(PublicJwk {
            kty: "OKP".to_string(),
            crv: Some(key_type),
            x: Some(URL_SAFE_NO_PAD.encode(raw)),
            ..PublicJwk::default()
        }),
        "RSA" => jwk_from_rsa(&raw),
        _ => Err(CryptoError::key_error(format!(
            "Unsupported public key type: {key_type}"
        ))),
    }
}

/// Extract a PEM X.509 certificate public key and convert it to JWK.
pub fn certificate_pem_to_jwk(pem: &str) -> CryptoResult<PublicJwk> {
    certificate_der_to_jwk(&load_certificate_pem(pem)?)
}

/// Extract a DER X.509 certificate public key and convert it to JWK.
pub fn certificate_der_to_jwk(der: &[u8]) -> CryptoResult<PublicJwk> {
    public_key_der_to_jwk(&get_certificate_public_key(der)?)
}

fn jwk_from_ec(curve: &str, raw: &[u8]) -> CryptoResult<PublicJwk> {
    let (x, y) = match curve {
        "P-256" => point_coordinates::<p256::NistP256>(raw, curve)?,
        "P-384" => point_coordinates::<p384::NistP384>(raw, curve)?,
        "P-521" => point_coordinates::<p521::NistP521>(raw, curve)?,
        _ => {
            return Err(CryptoError::unsupported_algorithm(format!(
                "Unsupported EC curve: {curve}"
            )))
        }
    };

    Ok(PublicJwk {
        kty: "EC".to_string(),
        crv: Some(curve.to_string()),
        x: Some(URL_SAFE_NO_PAD.encode(x)),
        y: Some(URL_SAFE_NO_PAD.encode(y)),
        ..PublicJwk::default()
    })
}

fn point_coordinates<C>(raw: &[u8], curve: &str) -> CryptoResult<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let point = elliptic_curve::sec1::EncodedPoint::<C>::from_bytes(raw)
        .map_err(|error| CryptoError::key_error(format!("Invalid {curve} key: {error}")))?;
    let x = point
        .x()
        .ok_or_else(|| CryptoError::key_error(format!("Missing {curve} x")))?;
    let y = point
        .y()
        .ok_or_else(|| CryptoError::key_error(format!("Missing {curve} y")))?;
    Ok((x.to_vec(), y.to_vec()))
}

fn jwk_from_rsa(raw: &[u8]) -> CryptoResult<PublicJwk> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;

    let key = rsa::RsaPublicKey::from_pkcs1_der(raw)
        .map_err(|error| CryptoError::key_error(format!("Invalid RSA public key: {error}")))?;

    Ok(PublicJwk {
        kty: "RSA".to_string(),
        n: Some(URL_SAFE_NO_PAD.encode(key.n().to_bytes_be())),
        e: Some(URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())),
        ..PublicJwk::default()
    })
}
