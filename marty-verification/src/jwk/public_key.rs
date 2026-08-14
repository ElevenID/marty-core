//! Canonical conversion of public keys and certificate keys to public JWKs.
//!
//! The conversion accepts SubjectPublicKeyInfo keys for every signing
//! algorithm supported by the Marty signing-key service. It intentionally
//! emits public parameters only and fails closed for malformed or unsupported
//! key types.

use marty_crypto::certificate::{get_certificate_public_key, load_certificate_pem};
use marty_crypto::serialization::{load_public_key_pem, spki_to_raw_public_key};

use super::{base64url_encode, Jwk};
use crate::{VerificationError, VerificationResult};

/// Convert a PEM SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_pem_to_jwk(pem: &str) -> VerificationResult<Jwk> {
    let spki = load_public_key_pem(pem)
        .map_err(|error| VerificationError::key_error(error.to_string()))?;
    public_key_der_to_jwk(&spki)
}

/// Convert a DER SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_der_to_jwk(spki: &[u8]) -> VerificationResult<Jwk> {
    let (raw, key_type) = spki_to_raw_public_key(spki)
        .map_err(|error| VerificationError::key_error(error.to_string()))?;

    match key_type.as_str() {
        "EC_P256" => jwk_from_ec("P-256", &raw),
        "EC_P384" => jwk_from_ec("P-384", &raw),
        "EC_P521" => jwk_from_ec("P-521", &raw),
        "Ed25519" | "Ed448" => Ok(Jwk {
            kty: "OKP".to_string(),
            crv: Some(key_type),
            x: Some(base64url_encode(&raw)),
            ..Jwk::default()
        }),
        "RSA" => jwk_from_rsa(&raw),
        _ => Err(VerificationError::key_error(format!(
            "Unsupported public key type: {key_type}"
        ))),
    }
}

/// Extract the public key from a PEM X.509 certificate and convert it to JWK.
pub fn certificate_pem_to_jwk(pem: &str) -> VerificationResult<Jwk> {
    let der = load_certificate_pem(pem)
        .map_err(|error| VerificationError::key_error(error.to_string()))?;
    certificate_der_to_jwk(&der)
}

/// Extract the public key from a DER X.509 certificate and convert it to JWK.
pub fn certificate_der_to_jwk(der: &[u8]) -> VerificationResult<Jwk> {
    let spki = get_certificate_public_key(der)
        .map_err(|error| VerificationError::key_error(error.to_string()))?;
    public_key_der_to_jwk(&spki)
}

fn jwk_from_ec(curve: &str, raw: &[u8]) -> VerificationResult<Jwk> {
    let (x, y) = match curve {
        "P-256" => point_coordinates::<p256::NistP256>(raw, curve)?,
        "P-384" => point_coordinates::<p384::NistP384>(raw, curve)?,
        "P-521" => point_coordinates::<p521::NistP521>(raw, curve)?,
        _ => {
            return Err(VerificationError::key_error(format!(
                "Unsupported EC curve: {curve}"
            )))
        }
    };

    Ok(Jwk {
        kty: "EC".to_string(),
        crv: Some(curve.to_string()),
        x: Some(base64url_encode(&x)),
        y: Some(base64url_encode(&y)),
        ..Jwk::default()
    })
}

fn point_coordinates<C>(raw: &[u8], curve: &str) -> VerificationResult<(Vec<u8>, Vec<u8>)>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let point = elliptic_curve::sec1::EncodedPoint::<C>::from_bytes(raw)
        .map_err(|error| VerificationError::key_error(format!("Invalid {curve} key: {error}")))?;
    let x = point
        .x()
        .ok_or_else(|| VerificationError::key_error(format!("Missing {curve} x")))?;
    let y = point
        .y()
        .ok_or_else(|| VerificationError::key_error(format!("Missing {curve} y")))?;
    Ok((x.to_vec(), y.to_vec()))
}

fn jwk_from_rsa(raw: &[u8]) -> VerificationResult<Jwk> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::traits::PublicKeyParts;

    let key = rsa::RsaPublicKey::from_pkcs1_der(raw).map_err(|error| {
        VerificationError::key_error(format!("Invalid RSA public key: {error}"))
    })?;

    Ok(Jwk {
        kty: "RSA".to_string(),
        n: Some(base64url_encode(&key.n().to_bytes_be())),
        e: Some(base64url_encode(&key.e().to_bytes_be())),
        ..Jwk::default()
    })
}
