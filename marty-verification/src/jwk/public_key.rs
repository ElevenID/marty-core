//! Verification-facing adapters for canonical public-JWK conversion.

use super::Jwk;
use crate::VerificationResult;

impl From<marty_crypto::jwk::PublicJwk> for Jwk {
    fn from(value: marty_crypto::jwk::PublicJwk) -> Self {
        // Exhaustive destructuring makes added source fields a compile-time review point.
        let marty_crypto::jwk::PublicJwk {
            kty,
            use_,
            key_ops,
            alg,
            kid,
            x5u,
            x5c,
            x5t,
            x5t_s256,
            crv,
            x,
            y,
            n,
            e,
            extra,
        } = value;
        Self {
            kty,
            use_,
            key_ops,
            alg,
            kid,
            x5u,
            x5c,
            x5t,
            x5t_s256,
            crv,
            x,
            y,
            n,
            e,
            extra,
            ..Self::default()
        }
    }
}

/// Convert a PEM SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_pem_to_jwk(pem: &str) -> VerificationResult<Jwk> {
    Ok(marty_crypto::jwk::public_key_pem_to_jwk(pem)?.into())
}

/// Convert a DER SubjectPublicKeyInfo public key to a public JWK.
pub fn public_key_der_to_jwk(spki: &[u8]) -> VerificationResult<Jwk> {
    Ok(marty_crypto::jwk::public_key_der_to_jwk(spki)?.into())
}

/// Extract a PEM X.509 certificate public key and convert it to JWK.
pub fn certificate_pem_to_jwk(pem: &str) -> VerificationResult<Jwk> {
    Ok(marty_crypto::jwk::certificate_pem_to_jwk(pem)?.into())
}

/// Extract a DER X.509 certificate public key and convert it to JWK.
pub fn certificate_der_to_jwk(der: &[u8]) -> VerificationResult<Jwk> {
    Ok(marty_crypto::jwk::certificate_der_to_jwk(der)?.into())
}
