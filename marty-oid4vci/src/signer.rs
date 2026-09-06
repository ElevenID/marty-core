//! Credential signing abstraction.
//!
//! Provides the [`CredentialSigner`] trait that decouples credential construction
//! from key material, enabling local JWK signing, HSM-backed signing, or
//! remote KMS signing through a unified interface.
//!
//! `IssuerKey` implements `CredentialSigner` directly, preserving full backward
//! compatibility — existing call-sites that pass `&IssuerKey` work unchanged.

#[cfg(any(test, feature = "local-key-operations"))]
use ssi_crypto::AlgorithmInstance;
#[cfg(any(test, feature = "local-key-operations"))]
use ssi_jwk::{Params, JWK};

use crate::error::{Oid4vciError, Oid4vciResult};
#[cfg(any(test, feature = "local-key-operations"))]
use crate::types::IssuerKey;
use crate::types::SigningAlgorithm;

// =============================================================================
// CredentialSigner trait
// =============================================================================

/// Smallest supported RSA remote-signing modulus (2048 bits).
pub const MIN_REMOTE_RSA_SIGNATURE_BYTES: usize = 256;
/// Largest supported RSA remote-signing modulus (8192 bits).
pub const MAX_REMOTE_RSA_SIGNATURE_BYTES: usize = crate::bounded_jwt::MAX_RSA_SIGNATURE_BYTES;

/// Trait for signing credential payloads.
///
/// Abstracts key material so that signing can be performed locally (JWK),
/// via a hardware security module, or through a remote KMS.
///
/// # Implementors
///
/// - `IssuerKey` — local JWK-based signer in local-key-enabled builds.
/// - (future) `KmsSigner` — delegates to an external KMS via callback.
///
/// Implementors must ensure their [`std::fmt::Debug`] representation never
/// includes private key material, credentials, signing payloads, or backend
/// secrets. Executors that retain signers must own a redacted diagnostic
/// representation instead of delegating formatting to the signer.
pub trait CredentialSigner: std::fmt::Debug + Send + Sync {
    /// Sign raw bytes and return the raw signature.
    ///
    /// The exact encoding of the returned bytes depends on the algorithm:
    /// - ECDSA (ES256, ES256K, ES384): raw `r || s` (IEEE P1363)
    /// - EdDSA: 64-byte Ed25519 signature
    /// - RSA (RS256): PKCS#1 v1.5 signature
    fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>>;

    /// The signing algorithm used by this signer.
    fn algorithm(&self) -> SigningAlgorithm;

    /// The issuer identifier (DID or URI).
    fn issuer_id(&self) -> &str;

    /// The key ID URL for JWT/COSE headers.
    fn kid_url(&self) -> String;
}

/// Validate the raw signature encoding returned by a remote signer before it
/// can be embedded into a JOSE or COSE credential.
pub(crate) fn validate_remote_signature(
    algorithm: SigningAlgorithm,
    signature: &[u8],
) -> Oid4vciResult<()> {
    let valid = match algorithm {
        SigningAlgorithm::ES256 => p256::ecdsa::Signature::from_slice(signature).is_ok(),
        SigningAlgorithm::ES256K => k256::ecdsa::Signature::from_slice(signature).is_ok(),
        SigningAlgorithm::ES384 => p384::ecdsa::Signature::from_slice(signature).is_ok(),
        SigningAlgorithm::EdDSA => validate_ed25519_encoding(signature),
        // The prepared state does not yet carry the KMS-managed modulus, so
        // enforce the library's supported 2048..=8192-bit RSA range.
        SigningAlgorithm::RS256 => validate_rsa_signature_encoding(signature),
    };
    if !valid {
        return Err(Oid4vciError::SigningError(format!(
            "invalid {algorithm} remote signature encoding: got {} bytes",
            signature.len()
        )));
    }
    Ok(())
}

pub(crate) fn validate_rsa_signature_encoding(signature: &[u8]) -> bool {
    (MIN_REMOTE_RSA_SIGNATURE_BYTES..=MAX_REMOTE_RSA_SIGNATURE_BYTES).contains(&signature.len())
        && signature.iter().any(|byte| *byte != 0)
}

fn validate_ed25519_encoding(signature: &[u8]) -> bool {
    let Ok(bytes) = <&[u8; 64]>::try_from(signature) else {
        return false;
    };
    let (encoded_r, encoded_s) = bytes.split_at(32);
    let Ok(encoded_r) = <[u8; 32]>::try_from(encoded_r) else {
        return false;
    };
    let Ok(encoded_s) = <[u8; 32]>::try_from(encoded_s) else {
        return false;
    };
    let Some(point) = curve25519_dalek::edwards::CompressedEdwardsY(encoded_r).decompress() else {
        return false;
    };
    point.compress().to_bytes() == encoded_r
        && !point.is_small_order()
        && bool::from(curve25519_dalek::scalar::Scalar::from_canonical_bytes(encoded_s).is_some())
        && signature.iter().any(|byte| *byte != 0)
}

// =============================================================================
// IssuerKey as CredentialSigner (backward compat)
// =============================================================================

#[cfg(any(test, feature = "local-key-operations"))]
impl CredentialSigner for IssuerKey {
    fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        let jwk: JWK = serde_json::from_str(&self.jwk_json)
            .map_err(|e| Oid4vciError::KeyError(format!("Invalid issuer JWK: {}", e)))?;
        validate_issuer_key_algorithm(self, &jwk)?;
        sign_with_jwk(&jwk, message)
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    fn kid_url(&self) -> String {
        IssuerKey::kid_url(self)
    }
}

// =============================================================================
// JWK signing helpers (shared with format modules)
// =============================================================================

/// Derive the signing algorithm from a JWK's structural key family.
///
/// `alg` is deliberately excluded from this decision. Callers validate that
/// optional metadata separately so it can only narrow, never override, the
/// key type and exact curve.
#[cfg(any(test, feature = "local-key-operations"))]
pub(crate) fn derive_signing_algorithm(
    key_type: Option<&str>,
    curve: Option<&str>,
) -> Oid4vciResult<SigningAlgorithm> {
    match key_type {
        Some("OKP") => match curve {
            Some("Ed25519") => Ok(SigningAlgorithm::EdDSA),
            Some(curve) => Err(Oid4vciError::KeyError(format!(
                "Unsupported OKP curve: {curve}"
            ))),
            None => Err(Oid4vciError::KeyError("Missing curve for OKP key".into())),
        },
        Some("EC") => match curve {
            Some("P-256") => Ok(SigningAlgorithm::ES256),
            Some("P-384") => Ok(SigningAlgorithm::ES384),
            Some("secp256k1") => Ok(SigningAlgorithm::ES256K),
            Some(curve) => Err(Oid4vciError::KeyError(format!(
                "Unsupported EC curve: {curve}"
            ))),
            None => Err(Oid4vciError::KeyError("Missing curve for EC key".into())),
        },
        Some("RSA") => Ok(SigningAlgorithm::RS256),
        Some(key_type) => Err(Oid4vciError::KeyError(format!(
            "Unsupported key type: {key_type}"
        ))),
        None => Err(Oid4vciError::KeyError("Missing kty in JWK".into())),
    }
}

/// Require optional JWK `alg` metadata to agree with the structural family.
#[cfg(any(test, feature = "local-key-operations"))]
pub(crate) fn validate_declared_jwk_algorithm(
    structural_algorithm: SigningAlgorithm,
    declared_algorithm: Option<&str>,
) -> Oid4vciResult<()> {
    let Some(declared_algorithm) = declared_algorithm else {
        return Ok(());
    };
    let declared = match declared_algorithm {
        "ES256" => SigningAlgorithm::ES256,
        "EdDSA" => SigningAlgorithm::EdDSA,
        "ES256K" => SigningAlgorithm::ES256K,
        "ES384" => SigningAlgorithm::ES384,
        "RS256" => SigningAlgorithm::RS256,
        unsupported => {
            return Err(Oid4vciError::KeyError(format!(
                "Unsupported algorithm: {unsupported}"
            )))
        }
    };
    if declared != structural_algorithm {
        return Err(Oid4vciError::KeyError(format!(
            "JWK alg {declared} does not match JWK key family {structural_algorithm}"
        )));
    }
    Ok(())
}

#[cfg(any(test, feature = "local-key-operations"))]
fn derive_typed_jwk_algorithm(jwk: &JWK) -> Oid4vciResult<SigningAlgorithm> {
    let (key_type, curve) = match &jwk.params {
        Params::OKP(params) => (Some("OKP"), Some(params.curve.as_str())),
        Params::EC(params) => (Some("EC"), params.curve.as_deref()),
        Params::RSA(_) => (Some("RSA"), None),
        Params::Symmetric(_) => (Some("oct"), None),
    };
    let structural_algorithm = derive_signing_algorithm(key_type, curve)?;
    validate_declared_jwk_algorithm(
        structural_algorithm,
        jwk.algorithm.map(|algorithm| algorithm.as_str()),
    )?;
    Ok(structural_algorithm)
}

/// Bind an [`IssuerKey`]'s public algorithm hint to its actual JWK family.
#[cfg(any(test, feature = "local-key-operations"))]
pub(crate) fn validate_issuer_key_algorithm(
    issuer_key: &IssuerKey,
    jwk: &JWK,
) -> Oid4vciResult<()> {
    let structural_algorithm = derive_typed_jwk_algorithm(jwk)?;
    if issuer_key.algorithm != structural_algorithm {
        return Err(Oid4vciError::KeyError(format!(
            "IssuerKey algorithm {} does not match JWK key family {structural_algorithm}",
            issuer_key.algorithm
        )));
    }
    Ok(())
}

/// Sign a message using a JWK's private key.
#[cfg(any(test, feature = "local-key-operations"))]
pub(crate) fn sign_with_jwk(jwk: &JWK, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
    let secret_key = extract_secret_key(jwk)?;
    let alg_instance = get_algorithm_instance(jwk)?;

    secret_key
        .sign(alg_instance, message)
        .map_err(|e| Oid4vciError::SigningError(format!("Signing failed: {:?}", e)))
}

/// Extract a [`SecretKey`](ssi_crypto::SecretKey) from a JWK for signing.
#[cfg(any(test, feature = "local-key-operations"))]
pub(crate) fn extract_secret_key(jwk: &JWK) -> Oid4vciResult<ssi_crypto::SecretKey> {
    match &jwk.params {
        Params::OKP(params) => {
            let d = params.private_key.as_ref().ok_or_else(|| {
                Oid4vciError::KeyError("Missing private key (d) in OKP JWK".into())
            })?;
            ssi_crypto::SecretKey::new_ed25519(&d.0)
                .map_err(|e| Oid4vciError::KeyError(format!("Invalid Ed25519 key: {:?}", e)))
        }
        Params::EC(params) => {
            let d = params.ecc_private_key.as_ref().ok_or_else(|| {
                Oid4vciError::KeyError("Missing private key (d) in EC JWK".into())
            })?;
            match params.curve.as_deref() {
                Some("P-256") => ssi_crypto::SecretKey::new_p256(&d.0)
                    .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 key: {:?}", e))),
                Some("secp256k1") => ssi_crypto::SecretKey::new_secp256k1(&d.0)
                    .map_err(|e| Oid4vciError::KeyError(format!("Invalid secp256k1 key: {:?}", e))),
                curve => Err(Oid4vciError::KeyError(format!(
                    "Unsupported EC curve: {:?}",
                    curve
                ))),
            }
        }
        _ => Err(Oid4vciError::KeyError(
            "Unsupported key type for signing (need OKP or EC)".into(),
        )),
    }
}

/// Get the [`AlgorithmInstance`] for a JWK.
#[cfg(any(test, feature = "local-key-operations"))]
pub(crate) fn get_algorithm_instance(jwk: &JWK) -> Oid4vciResult<AlgorithmInstance> {
    match &jwk.params {
        Params::OKP(_) => Ok(AlgorithmInstance::EdDSA),
        Params::EC(ec) => match ec.curve.as_deref() {
            Some("P-256") => Ok(AlgorithmInstance::ES256),
            Some("secp256k1") => Ok(AlgorithmInstance::ES256K),
            curve => Err(Oid4vciError::KeyError(format!(
                "Unsupported EC curve: {:?}",
                curve
            ))),
        },
        _ => Err(Oid4vciError::KeyError(
            "Unsupported key type for algorithm selection".into(),
        )),
    }
}

#[cfg(test)]
mod remote_signature_tests {
    use super::*;

    #[test]
    fn rejects_empty_wrong_width_and_der_ecdsa_signatures() {
        assert!(validate_remote_signature(SigningAlgorithm::ES256, &[]).is_err());
        assert!(validate_remote_signature(SigningAlgorithm::ES256, &[0; 63]).is_err());

        let mut der = [0u8; 70];
        der[0] = 0x30;
        assert!(validate_remote_signature(SigningAlgorithm::ES256, &der).is_err());

        assert!(validate_remote_signature(SigningAlgorithm::ES256, &[0; 64]).is_err());
        assert!(validate_remote_signature(SigningAlgorithm::ES256, &[0xff; 64]).is_err());
        let mut valid_es256 = [0u8; 64];
        valid_es256[31] = 1;
        valid_es256[63] = 1;
        assert!(validate_remote_signature(SigningAlgorithm::ES256, &valid_es256).is_ok());

        let mut valid_es384 = [0u8; 96];
        valid_es384[47] = 1;
        valid_es384[95] = 1;
        assert!(validate_remote_signature(SigningAlgorithm::ES384, &valid_es384).is_ok());

        let mut valid_es256k = [0u8; 64];
        valid_es256k[31] = 1;
        valid_es256k[63] = 1;
        assert!(validate_remote_signature(SigningAlgorithm::ES256K, &valid_es256k).is_ok());

        let mut valid_ed25519 = [0x66u8; 64];
        valid_ed25519[0] = 0x58;
        valid_ed25519[32..].fill(0);
        valid_ed25519[32] = 1;
        assert!(validate_remote_signature(SigningAlgorithm::EdDSA, &valid_ed25519).is_ok());
        assert!(validate_remote_signature(SigningAlgorithm::EdDSA, &[0; 64]).is_err());
        assert!(validate_remote_signature(SigningAlgorithm::RS256, &[0; 255]).is_err());
        assert!(validate_remote_signature(SigningAlgorithm::RS256, &[0; 256]).is_err());
        assert!(validate_remote_signature(SigningAlgorithm::RS256, &[1; 256]).is_ok());
        assert!(validate_remote_signature(SigningAlgorithm::RS256, &[1; 384]).is_ok());
        assert!(validate_remote_signature(SigningAlgorithm::RS256, &[1; 1024]).is_ok());
        assert!(validate_remote_signature(SigningAlgorithm::RS256, &[1; 1025]).is_err());
    }
}
