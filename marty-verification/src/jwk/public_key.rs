//! Verification-facing adapters for canonical public-JWK conversion.

use super::Jwk;
use crate::VerificationResult;

impl From<marty_crypto::jwk::PublicJwk> for Jwk {
    fn from(value: marty_crypto::jwk::PublicJwk) -> Self {
        let extensions = value.extensions().clone();
        let mut jwk = Self {
            kty: value.kty,
            use_: value.use_,
            key_ops: value.key_ops,
            alg: value.alg,
            kid: value.kid,
            x5u: value.x5u,
            x5c: value.x5c,
            x5t: value.x5t,
            x5t_s256: value.x5t_s256,
            crv: value.crv,
            x: value.x,
            y: value.y,
            n: value.n,
            e: value.e,
            ..Self::default()
        };
        jwk.set_public_extensions(extensions)
            .expect("PublicJwk extensions are validated at every construction boundary");
        jwk
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
