//! Verification-facing adapters for canonical public-JWK conversion.

use super::Jwk;
use crate::{VerificationError, VerificationResult};

fn verification_jwk(value: marty_crypto::jwk::PublicJwk) -> VerificationResult<Jwk> {
    serde_json::from_value(
        serde_json::to_value(value)
            .map_err(|error| VerificationError::key_error(error.to_string()))?,
    )
    .map_err(|error| VerificationError::key_error(error.to_string()))
}

/// Convert a PEM SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_pem_to_jwk(pem: &str) -> VerificationResult<Jwk> {
    verification_jwk(marty_crypto::jwk::public_key_pem_to_jwk(pem)?)
}

/// Convert a DER SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_der_to_jwk(spki: &[u8]) -> VerificationResult<Jwk> {
    verification_jwk(marty_crypto::jwk::public_key_der_to_jwk(spki)?)
}

/// Extract a PEM X.509 certificate public key and convert it to JWK.
pub fn certificate_pem_to_jwk(pem: &str) -> VerificationResult<Jwk> {
    verification_jwk(marty_crypto::jwk::certificate_pem_to_jwk(pem)?)
}

/// Extract a DER X.509 certificate public key and convert it to JWK.
pub fn certificate_der_to_jwk(der: &[u8]) -> VerificationResult<Jwk> {
    verification_jwk(marty_crypto::jwk::certificate_der_to_jwk(der)?)
}
