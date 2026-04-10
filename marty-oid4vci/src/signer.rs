//! Credential signing abstraction.
//!
//! Provides the [`CredentialSigner`] trait that decouples credential construction
//! from key material, enabling local JWK signing, HSM-backed signing, or
//! remote KMS signing through a unified interface.
//!
//! `IssuerKey` implements `CredentialSigner` directly, preserving full backward
//! compatibility — existing call-sites that pass `&IssuerKey` work unchanged.

use ssi::crypto::AlgorithmInstance;
use ssi::jwk::{Params, JWK};

use crate::error::{Oid4vciError, Oid4vciResult};
use crate::types::{IssuerKey, SigningAlgorithm};

// =============================================================================
// CredentialSigner trait
// =============================================================================

/// Trait for signing credential payloads.
///
/// Abstracts key material so that signing can be performed locally (JWK),
/// via a hardware security module, or through a remote KMS.
///
/// # Implementors
///
/// - [`IssuerKey`] — local JWK-based signer (in-process private key).
/// - (future) `KmsSigner` — delegates to an external KMS via callback.
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

// =============================================================================
// IssuerKey as CredentialSigner (backward compat)
// =============================================================================

impl CredentialSigner for IssuerKey {
    fn sign(&self, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
        let jwk: JWK = serde_json::from_str(&self.jwk_json)
            .map_err(|e| Oid4vciError::KeyError(format!("Invalid issuer JWK: {}", e)))?;
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

/// Sign a message using a JWK's private key.
pub(crate) fn sign_with_jwk(jwk: &JWK, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
    let secret_key = extract_secret_key(jwk)?;
    let alg_instance = get_algorithm_instance(jwk)?;

    secret_key
        .sign(alg_instance, message)
        .map_err(|e| Oid4vciError::SigningError(format!("Signing failed: {:?}", e)))
}

/// Extract a [`SecretKey`](ssi::crypto::SecretKey) from a JWK for signing.
pub(crate) fn extract_secret_key(jwk: &JWK) -> Oid4vciResult<ssi::crypto::SecretKey> {
    match &jwk.params {
        Params::OKP(params) => {
            let d = params
                .private_key
                .as_ref()
                .ok_or_else(|| {
                    Oid4vciError::KeyError("Missing private key (d) in OKP JWK".into())
                })?;
            ssi::crypto::SecretKey::new_ed25519(&d.0)
                .map_err(|e| Oid4vciError::KeyError(format!("Invalid Ed25519 key: {:?}", e)))
        }
        Params::EC(params) => {
            let d = params
                .ecc_private_key
                .as_ref()
                .ok_or_else(|| {
                    Oid4vciError::KeyError("Missing private key (d) in EC JWK".into())
                })?;
            match params.curve.as_deref() {
                Some("P-256") => ssi::crypto::SecretKey::new_p256(&d.0)
                    .map_err(|e| Oid4vciError::KeyError(format!("Invalid P-256 key: {:?}", e))),
                Some("secp256k1") => ssi::crypto::SecretKey::new_secp256k1(&d.0).map_err(|e| {
                    Oid4vciError::KeyError(format!("Invalid secp256k1 key: {:?}", e))
                }),
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
