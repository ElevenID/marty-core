//! Credential signing abstraction.
//!
//! Provides the [`CredentialSigner`] trait that decouples credential construction
//! from key material. Production implementors delegate to a remote KMS or HSM;
//! local JWK signing exists only in the crate's non-selectable test build.

#[cfg(test)]
use ssi_crypto::AlgorithmInstance;
use ssi_jwk::{Params, JWK};

use crate::error::{Oid4vciError, Oid4vciResult};
#[cfg(test)]
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
/// Abstracts key material so that signing can be delegated to a hardware
/// security module or remote KMS.
///
/// # Implementors
///
/// Product implementations delegate to an external key manager. The crate's
/// local JWK implementation is available only to its own `cfg(test)` build.
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

    /// Public-only JWK trusted to verify this signer's output.
    ///
    /// Production implementations obtain this from the KMS key metadata or a
    /// trusted DID-resolution result. Private and symmetric JWKs are rejected.
    fn public_jwk(&self) -> Oid4vciResult<String>;
}

pub(crate) fn validate_signer_public_jwk(signer: &dyn CredentialSigner) -> Oid4vciResult<String> {
    validate_signer_public_jwk_for_algorithm(signer, signer.algorithm())
}

pub(crate) fn validate_signer_public_jwk_for_algorithm(
    signer: &dyn CredentialSigner,
    algorithm: SigningAlgorithm,
) -> Oid4vciResult<String> {
    let public_jwk = signer.public_jwk()?;
    if public_jwk.len() > crate::jose::MAX_PUBLIC_JWK_BYTES {
        return Err(Oid4vciError::KeyError(
            "Issuer public JWK exceeds its size limit".into(),
        ));
    }
    let value = crate::jose::parse_unique_object(public_jwk.as_bytes(), "issuer public JWK")?;
    crate::jose::validate_public_jwk(&value, algorithm.as_str())?;
    let jwk: JWK = serde_json::from_value(value.clone())
        .map_err(|error| Oid4vciError::KeyError(format!("Invalid issuer public JWK: {error}")))?;
    validate_public_key_for_algorithm(algorithm, &jwk)?;
    if let Some(kid) = value.get("kid") {
        if kid.as_str() != Some(signer.kid_url().as_str()) {
            return Err(Oid4vciError::KeyError(
                "Issuer public JWK kid does not match the credential verification method".into(),
            ));
        }
    }
    Ok(public_jwk)
}

fn validate_public_key_for_algorithm(algorithm: SigningAlgorithm, jwk: &JWK) -> Oid4vciResult<()> {
    let valid = match (algorithm, &jwk.params) {
        (SigningAlgorithm::ES256, Params::EC(params))
            if params.curve.as_deref() == Some("P-256") =>
        {
            p256::PublicKey::from_sec1_bytes(&ec_public_key(params, 32)?).is_ok()
        }
        (SigningAlgorithm::ES384, Params::EC(params))
            if params.curve.as_deref() == Some("P-384") =>
        {
            p384::PublicKey::from_sec1_bytes(&ec_public_key(params, 48)?).is_ok()
        }
        (SigningAlgorithm::ES256K, Params::EC(params))
            if params.curve.as_deref() == Some("secp256k1") =>
        {
            k256::PublicKey::from_sec1_bytes(&ec_public_key(params, 32)?).is_ok()
        }
        (SigningAlgorithm::EdDSA, Params::OKP(params)) if params.curve == "Ed25519" => {
            let Ok(bytes) = <[u8; 32]>::try_from(params.public_key.0.as_slice()) else {
                return Err(Oid4vciError::KeyError(
                    "Ed25519 issuer public key must contain 32 bytes".into(),
                ));
            };
            ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_ok()
        }
        (SigningAlgorithm::RS256, Params::RSA(_)) => true,
        _ => false,
    };
    if !valid {
        return Err(Oid4vciError::KeyError(
            "Issuer public JWK does not contain a valid key for the credential signing algorithm"
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_remote_signature(
    algorithm: SigningAlgorithm,
    public_jwk: &str,
    message: &[u8],
    signature: &[u8],
) -> Oid4vciResult<()> {
    validate_remote_signature(algorithm, signature)?;
    let jwk: JWK = serde_json::from_str(public_jwk)
        .map_err(|error| Oid4vciError::KeyError(format!("Invalid issuer public JWK: {error}")))?;

    let verified = match (algorithm, &jwk.params) {
        (SigningAlgorithm::ES256, Params::EC(params))
            if params.curve.as_deref() == Some("P-256") =>
        {
            use sha2::Digest as _;

            let key =
                p256::PublicKey::from_sec1_bytes(&ec_public_key(params, 32)?).map_err(|error| {
                    Oid4vciError::KeyError(format!("Invalid P-256 issuer public key: {error}"))
                })?;
            let signature = p256::ecdsa::Signature::from_slice(signature).map_err(|error| {
                Oid4vciError::SigningError(format!("Invalid ES256 signature: {error}"))
            })?;
            let digest = sha2::Sha256::digest(message);
            let z = ecdsa_core::hazmat::bits2field::<p256::NistP256>(&digest).map_err(|error| {
                Oid4vciError::SigningError(format!(
                    "Could not prepare ES256 signature digest: {error}"
                ))
            })?;
            let public_point = p256::ProjectivePoint::from(*key.as_affine());
            ecdsa_core::hazmat::verify_prehashed::<p256::NistP256>(&public_point, &z, &signature)
                .is_ok()
        }
        (SigningAlgorithm::ES384, Params::EC(params))
            if params.curve.as_deref() == Some("P-384") =>
        {
            use sha2::Digest as _;

            let key =
                p384::PublicKey::from_sec1_bytes(&ec_public_key(params, 48)?).map_err(|error| {
                    Oid4vciError::KeyError(format!("Invalid P-384 issuer public key: {error}"))
                })?;
            let signature = p384::ecdsa::Signature::from_slice(signature).map_err(|error| {
                Oid4vciError::SigningError(format!("Invalid ES384 signature: {error}"))
            })?;
            let digest = sha2::Sha384::digest(message);
            let z = ecdsa_core::hazmat::bits2field::<p384::NistP384>(&digest).map_err(|error| {
                Oid4vciError::SigningError(format!(
                    "Could not prepare ES384 signature digest: {error}"
                ))
            })?;
            let public_point = p384::ProjectivePoint::from(*key.as_affine());
            ecdsa_core::hazmat::verify_prehashed::<p384::NistP384>(&public_point, &z, &signature)
                .is_ok()
        }
        (SigningAlgorithm::ES256K, Params::EC(params))
            if params.curve.as_deref() == Some("secp256k1") =>
        {
            use sha2::Digest as _;

            let key =
                k256::PublicKey::from_sec1_bytes(&ec_public_key(params, 32)?).map_err(|error| {
                    Oid4vciError::KeyError(format!("Invalid secp256k1 issuer public key: {error}"))
                })?;
            let signature = k256::ecdsa::Signature::from_slice(signature).map_err(|error| {
                Oid4vciError::SigningError(format!("Invalid ES256K signature: {error}"))
            })?;
            let digest = sha2::Sha256::digest(message);
            let z =
                k256::ecdsa::hazmat::bits2field::<k256::Secp256k1>(&digest).map_err(|error| {
                    Oid4vciError::SigningError(format!(
                        "Could not prepare ES256K signature digest: {error}"
                    ))
                })?;
            let public_point = k256::ProjectivePoint::from(*key.as_affine());
            k256::ecdsa::hazmat::verify_prehashed::<k256::Secp256k1>(&public_point, &z, &signature)
                .is_ok()
        }
        (SigningAlgorithm::EdDSA, Params::OKP(params)) if params.curve == "Ed25519" => {
            let bytes: [u8; 32] = params.public_key.0.as_slice().try_into().map_err(|_| {
                Oid4vciError::KeyError("Ed25519 issuer public key must contain 32 bytes".into())
            })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|error| {
                Oid4vciError::KeyError(format!("Invalid Ed25519 issuer public key: {error}"))
            })?;
            let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|error| {
                Oid4vciError::SigningError(format!("Invalid Ed25519 signature: {error}"))
            })?;
            ed25519_dalek::Verifier::verify(&key, message, &signature).is_ok()
        }
        (SigningAlgorithm::RS256, Params::RSA(_)) => {
            crate::jose::verify_detached_signature_with_public_jwk(
                message,
                signature,
                public_jwk,
                algorithm.as_str(),
            )?
        }
        _ => {
            return Err(Oid4vciError::KeyError(
                "Issuer public JWK does not match the credential signing algorithm".into(),
            ))
        }
    };

    if !verified {
        return Err(Oid4vciError::SigningError(
            "remote signature does not verify with the configured issuer public key".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_es256_public_jwk() -> String {
    let signing_key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into())
        .expect("fixed P-256 test key must be valid");
    test_es256_public_jwk_for_key(&signing_key)
}

#[cfg(test)]
pub(crate) fn test_es256_public_jwk_for_key(signing_key: &p256::ecdsa::SigningKey) -> String {
    use base64::Engine as _;

    let point = signing_key.verifying_key().to_encoded_point(false);
    serde_json::json!({
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    })
    .to_string()
}

#[cfg(test)]
pub(crate) fn test_public_jwk(algorithm: SigningAlgorithm) -> String {
    match algorithm {
        SigningAlgorithm::ES256 => test_es256_public_jwk(),
        SigningAlgorithm::ES384 => {
            use base64::Engine as _;

            let signing_key = p384::ecdsa::SigningKey::from_bytes((&[7u8; 48]).into())
                .expect("fixed P-384 test key must be valid");
            let point = signing_key.verifying_key().to_encoded_point(false);
            serde_json::json!({
                "alg": "ES384",
                "crv": "P-384",
                "kty": "EC",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            })
            .to_string()
        }
        _ => panic!("no fixed public test key for {algorithm}"),
    }
}

#[cfg(test)]
pub(crate) fn test_signature(algorithm: SigningAlgorithm, message: &[u8]) -> Vec<u8> {
    match algorithm {
        SigningAlgorithm::ES256 => {
            use p256::ecdsa::signature::Signer as _;
            let key = p256::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
            let signature: p256::ecdsa::Signature = key.sign(message);
            signature.to_bytes().to_vec()
        }
        SigningAlgorithm::ES384 => {
            use p384::ecdsa::signature::Signer as _;
            let key = p384::ecdsa::SigningKey::from_bytes((&[7u8; 48]).into()).unwrap();
            let signature: p384::ecdsa::Signature = key.sign(message);
            signature.to_bytes().to_vec()
        }
        _ => panic!("no fixed signing test key for {algorithm}"),
    }
}

fn ec_public_key(params: &ssi_jwk::ECParams, coordinate_len: usize) -> Oid4vciResult<Vec<u8>> {
    let x = params
        .x_coordinate
        .as_ref()
        .ok_or_else(|| Oid4vciError::KeyError("Issuer EC JWK is missing x".into()))?;
    let y = params
        .y_coordinate
        .as_ref()
        .ok_or_else(|| Oid4vciError::KeyError("Issuer EC JWK is missing y".into()))?;
    if x.0.len() != coordinate_len || y.0.len() != coordinate_len {
        return Err(Oid4vciError::KeyError(format!(
            "Issuer EC JWK coordinates must each contain {coordinate_len} bytes"
        )));
    }
    let mut key = Vec::with_capacity(1 + 2 * coordinate_len);
    key.push(4);
    key.extend_from_slice(&x.0);
    key.extend_from_slice(&y.0);
    Ok(key)
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
// Fixture-only IssuerKey implementation
// =============================================================================

#[cfg(test)]
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

    fn public_jwk(&self) -> Oid4vciResult<String> {
        let jwk: JWK = serde_json::from_str(&self.jwk_json)
            .map_err(|error| Oid4vciError::KeyError(format!("Invalid issuer JWK: {error}")))?;
        serde_json::to_string(&jwk.to_public()).map_err(Into::into)
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
#[cfg(test)]
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
#[cfg(test)]
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

#[cfg(test)]
/// Derive the signing family from a parsed JWK and validate its optional `alg` metadata.
pub fn derive_typed_jwk_algorithm(jwk: &JWK) -> Oid4vciResult<SigningAlgorithm> {
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
#[cfg(test)]
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
#[cfg(test)]
pub(crate) fn sign_with_jwk(jwk: &JWK, message: &[u8]) -> Oid4vciResult<Vec<u8>> {
    let secret_key = extract_secret_key(jwk)?;
    let alg_instance = get_algorithm_instance(jwk)?;

    secret_key
        .sign(alg_instance, message)
        .map_err(|e| Oid4vciError::SigningError(format!("Signing failed: {:?}", e)))
}

/// Extract a [`SecretKey`](ssi_crypto::SecretKey) from a JWK for signing.
#[cfg(test)]
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
#[cfg(test)]
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
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    #[cfg(not(target_family = "wasm"))]
    const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8rUj8OT3yKej3\nmQFlOO8ZYGNBcWUzdpPotih5ogCMnUA+kekZ9wbvw8m4YTpwlD/S3g/hdbUBHRDx\nxIHG0xmmTM+vfQVb2xgXZCgriXmX/eBhWIGpv/r7R7YWDhhVCmc55KcJivSbh3E7\nzehccigOIWTJ9AVoaFRGYxp8hN4saMv9hNVojxVgizFKg+yFFvVLOjO78WX0i3RJ\nRXJf7g5UeP/Bs0TAMbkVO/fBpUjOJKcT59jdl1/7u0WCTMTfpyt3eLXTtivhh6QE\n6zNWZ3TaB1FFP4SQ8+B8UpoVub4SoUsUpt1kytM5lI1+8BBuwO1izF+awnMts9sg\n5SzvjE63AgMBAAECggEAOhUiRbsdbcInHKm2e0G2oVpB0/Cjld8oE1iYRzFu99qk\n314tozefpAnivGb6BZQtva1suBxzNz+KatLynJF58O7udHiJQMjGttS3ZQeyLe8S\ntwT3DZmzGs3tqQZ3yR4lvvW70j07pfFhE2cE5Aikeg0fqOf9DjIn129ExRZmCsdD\nR7NnblNhDdqmkFiPgbhBqxxDOFPiQyFH2PvR1Pj8b7p6nlCZSrmqesHmTYjFOAEv\nNNz48OuRVV1pGxaEwyT5PaOkW0OKZvlibyaeuFr8jbdtSA4Vh+yePmfExsol0L1I\nvoPYTRjVCxkAGRq0KgkeRwysMk2tQbIvf8vjWQumwQKBgQD/Q4a8Gl3VliK2F9yL\nTwlC6XjAcBLrXc4cL4lttvgB7YyoQB8UvHAySbJoDgBPaPaqbofws6YieMsd1oeY\nVMSzTeXJkMQC3VkKYUaO5IlMFT5PD2F967fJZV/q2V+BL6s6Vsl1PqnHyP1w54qk\n4s02qoJBU+FuFCeUGZyXnar5lwKBgQC9OJgt6m8g49pvguj1TPKJmEfzBBySOmuj\n4C52XlbvrYaVpYyhQnckJUgZIWcx2fA9W/D4PfwFzsiItbxep9GgULIMix9C1PTV\ns7go3gHHQfmOgZpmJH2Tand1qKdhDTOWjKZJzDNdo81rAgYsW+Hx+anquM1bi4cC\nUWHYXoS34QKBgHmMxxC1IW9+QWMiM6OmbAuPry87btbi4S1suW0kDi6k1jCb7/Do\n1igsDacc26r0mViIr3S/puGNUXMQ35p66vtSoZP8ukl+61JVBcsvKe2vw+7TrSHP\n58Ef46+p+J9Eeq2Z++43e5MlswFbUBq54Owh/0pqTdMkB8Cu/XD45BxbAoGBAId0\ncyQzdZgi5KT9Hs0zZ1Bujdr+r4FShunKOxiLUkrDetu3piNulCFw+tramagLLrqO\nDcN3g+mYbN/I0W8lTaApBDyMfzV1g0tUG1pOCxHcPczxJFlIeAjGp3u33xJPxAVa\n7FNZ9c9rykp3KXop0GZLZoLcBk4pZN2Y6qVcjD+hAoGBANXlp2ZCuCYws17lCT+I\nxHlUJDu9t6o6rJGYezXFyrzrZDDS6CrrqARXqOFSKpfZN1f8dHsdaLafqBb9iADe\noqLZ4c0NyDjyxLBhiht/NDrMcfxf5FLrwmdO/iV6Hn6GWVvS8s3x4mYKuns5sJ6b\nYTa2y89NkNgCn0f1CWNdFbJk\n-----END PRIVATE KEY-----\n";

    fn p256_public_jwk(key: &p256::ecdsa::SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(false);
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
        .to_string()
    }

    fn assert_binding(
        algorithm: SigningAlgorithm,
        public_jwk: &str,
        wrong_public_jwk: &str,
        payload: &[u8],
        signature: &[u8],
    ) {
        assert!(verify_remote_signature(algorithm, public_jwk, payload, signature).is_ok());
        assert!(
            verify_remote_signature(algorithm, public_jwk, b"substituted payload", signature,)
                .is_err()
        );
        assert!(verify_remote_signature(algorithm, wrong_public_jwk, payload, signature,).is_err());
    }

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

    #[test]
    fn signature_binding_rejects_payload_and_public_key_substitution() {
        use p256::ecdsa::signature::Signer as _;

        let key = p256::ecdsa::SigningKey::from_slice(&[1u8; 32]).unwrap();
        let other_key = p256::ecdsa::SigningKey::from_slice(&[2u8; 32]).unwrap();
        let payload = b"canonical prepared credential payload";
        let signature: p256::ecdsa::Signature = key.sign(payload);

        assert!(verify_remote_signature(
            SigningAlgorithm::ES256,
            &p256_public_jwk(&key),
            payload,
            signature.to_bytes().as_slice(),
        )
        .is_ok());
        assert!(verify_remote_signature(
            SigningAlgorithm::ES256,
            &p256_public_jwk(&key),
            b"substituted payload",
            signature.to_bytes().as_slice(),
        )
        .is_err());
        assert!(verify_remote_signature(
            SigningAlgorithm::ES256,
            &p256_public_jwk(&other_key),
            payload,
            signature.to_bytes().as_slice(),
        )
        .is_err());
    }

    #[test]
    fn every_remote_algorithm_accepts_valid_and_rejects_substituted_bindings() {
        let payload = b"canonical prepared credential payload";

        {
            use p384::ecdsa::signature::Signer as _;
            let key = p384::ecdsa::SigningKey::from_slice(&[3u8; 48]).unwrap();
            let wrong = p384::ecdsa::SigningKey::from_slice(&[4u8; 48]).unwrap();
            let point = key.verifying_key().to_encoded_point(false);
            let wrong_point = wrong.verifying_key().to_encoded_point(false);
            let jwk = |point: &p384::EncodedPoint| {
                serde_json::json!({
                    "kty": "EC", "crv": "P-384", "alg": "ES384",
                    "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                })
                .to_string()
            };
            let signature: p384::ecdsa::Signature = key.sign(payload);
            assert_binding(
                SigningAlgorithm::ES384,
                &jwk(&point),
                &jwk(&wrong_point),
                payload,
                signature.to_bytes().as_slice(),
            );
        }

        {
            use k256::ecdsa::signature::Signer as _;
            let key = k256::ecdsa::SigningKey::from_slice(&[5u8; 32]).unwrap();
            let wrong = k256::ecdsa::SigningKey::from_slice(&[6u8; 32]).unwrap();
            let jwk = |key: &k256::ecdsa::SigningKey| {
                let point = key.verifying_key().to_encoded_point(false);
                serde_json::json!({
                    "kty": "EC", "crv": "secp256k1", "alg": "ES256K",
                    "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                    "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
                })
                .to_string()
            };
            let signature: k256::ecdsa::Signature = key.sign(payload);
            assert_binding(
                SigningAlgorithm::ES256K,
                &jwk(&key),
                &jwk(&wrong),
                payload,
                signature.to_bytes().as_slice(),
            );
        }

        {
            use ed25519_dalek::Signer as _;
            let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let wrong = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
            let jwk = |key: &ed25519_dalek::SigningKey| {
                serde_json::json!({
                    "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
                    "x": URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                })
                .to_string()
            };
            let signature = key.sign(payload);
            assert_binding(
                SigningAlgorithm::EdDSA,
                &jwk(&key),
                &jwk(&wrong),
                payload,
                &signature.to_bytes(),
            );
        }

        #[cfg(not(target_family = "wasm"))]
        {
            use aws_lc_rs::signature::KeyPair as _;
            let encoding_key =
                jsonwebtoken::EncodingKey::from_rsa_pem(RSA_PRIVATE_KEY.as_bytes()).unwrap();
            let key_pair =
                aws_lc_rs::signature::RsaKeyPair::from_der(encoding_key.inner()).unwrap();
            let public = aws_lc_rs::signature::RsaPublicKeyComponents::<Vec<u8>>::from(
                key_pair.public_key(),
            );
            let mut signature = vec![0u8; key_pair.public_modulus_len()];
            key_pair
                .sign(
                    &aws_lc_rs::signature::RSA_PKCS1_SHA256,
                    &aws_lc_rs::rand::SystemRandom::new(),
                    payload,
                    &mut signature,
                )
                .unwrap();
            let public_jwk = serde_json::json!({
                "kty": "RSA", "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(&public.n),
                "e": URL_SAFE_NO_PAD.encode(&public.e),
            });
            let mut wrong_n = public.n.clone();
            *wrong_n.last_mut().unwrap() ^= 1;
            let wrong_public_jwk = serde_json::json!({
                "kty": "RSA", "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(wrong_n),
                "e": URL_SAFE_NO_PAD.encode(&public.e),
            });
            assert_binding(
                SigningAlgorithm::RS256,
                &public_jwk.to_string(),
                &wrong_public_jwk.to_string(),
                payload,
                &signature,
            );
        }
    }
}
