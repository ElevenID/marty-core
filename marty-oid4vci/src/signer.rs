//! Credential signing abstraction.
//!
//! Provides the [`CredentialSigner`] trait that decouples credential construction
//! from key material. Production implementors delegate to a remote KMS or HSM.

use ssi_jwk::{Params, JWK};

use crate::error::{Oid4vciError, Oid4vciResult};
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
/// Product implementations delegate to an external key manager.
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
            strict_ed25519_verifying_key(params.public_key.0.as_slice()).is_ok()
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
            let key = strict_ed25519_verifying_key(params.public_key.0.as_slice())?;
            let signature = ed25519_dalek::Signature::from_slice(signature).map_err(|error| {
                Oid4vciError::SigningError(format!("Invalid Ed25519 signature: {error}"))
            })?;
            key.verify_strict(message, &signature).is_ok()
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

fn strict_ed25519_verifying_key(bytes: &[u8]) -> Oid4vciResult<ed25519_dalek::VerifyingKey> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        Oid4vciError::KeyError("Ed25519 issuer public key must contain 32 bytes".into())
    })?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|error| {
        Oid4vciError::KeyError(format!("Invalid Ed25519 issuer public key: {error}"))
    })?;
    if key.is_weak() {
        return Err(Oid4vciError::KeyError(
            "Ed25519 issuer public key has small order".into(),
        ));
    }
    Ok(key)
}

#[cfg(test)]
pub(crate) fn test_es256_public_jwk() -> String {
    // Public half of the historical fixed test vector. Preparation-only
    // fixtures do not need access to its private scalar.
    serde_json::json!({
        "alg": "ES256",
        "crv": "P-256",
        "kty": "EC",
        "x": "HhhTL9R1TALzBB2cdc6zO4P_2BrHzk_ogsyxyYvFiW4",
        "y": "pGwxHE4v9A3ZajZT5uRURdMt_khuztdcepDGoYiBwKM",
    })
    .to_string()
}

#[cfg(all(test, feature = "issuer"))]
pub(crate) fn test_public_jwk(algorithm: SigningAlgorithm) -> String {
    match algorithm {
        SigningAlgorithm::ES256 => test_es256_public_jwk(),
        SigningAlgorithm::ES384 => serde_json::json!({
            "alg": "ES384",
            "crv": "P-384",
            "kty": "EC",
            "x": "sBv8Si1_4gleZifMXK-avRU9W1Uf5_baYV2p0b_RAejRkehZAsCjTqo6FuZmiAtz",
            "y": "BZ9ljE1qblfAlZ3oAQmw-mtWvWPR1XAak9FTIvImehVSZkHGDNB8kSpt9Yqpk9ib",
        })
        .to_string(),
        _ => panic!("no fixed public test key for {algorithm}"),
    }
}

#[cfg(all(test, feature = "issuer"))]
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
    // Small-order R is structurally well formed. Leave its rejection to the
    // strict cryptographic verifier so this encoding check cannot mask a
    // regression from verify_strict() to legacy verification.
    point.compress().to_bytes() == encoded_r
        && bool::from(curve25519_dalek::scalar::Scalar::from_canonical_bytes(encoded_s).is_some())
        && signature.iter().any(|byte| *byte != 0)
}

#[cfg(test)]
mod remote_signature_tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

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

    #[cfg(not(target_family = "wasm"))]
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn es256_remote_signature_binds_payload_and_public_key() {
        let provider = crate::openbao_transit::DisposableOpenBao::from_marked_env();
        let signer = provider.create_es256();
        let wrong_signer = provider.create_es256();
        let payload = b"canonical prepared credential payload";
        let signature = signer.sign(payload).unwrap();
        assert_binding(
            SigningAlgorithm::ES256,
            signer.public_jwk(),
            wrong_signer.public_jwk(),
            payload,
            &signature,
        );
    }

    #[test]
    fn remote_eddsa_rejects_identity_key_arbitrary_message_forgery() {
        let mut identity_key = [0u8; 32];
        identity_key[0] = 1;
        let identity_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": URL_SAFE_NO_PAD.encode(identity_key),
        })
        .to_string();
        let mut signature = [0u8; 64];
        signature[0] = 0x58;
        signature[1..32].fill(0x66);
        signature[32] = 1;
        assert!(validate_remote_signature(SigningAlgorithm::EdDSA, &signature).is_ok());

        let error = verify_remote_signature(
            SigningAlgorithm::EdDSA,
            &identity_jwk,
            b"arbitrary attacker-selected credential payload",
            &signature,
        )
        .expect_err("remote completion must reject an identity issuer key forgery");
        assert!(error.to_string().contains("small order"));

        let jwk: JWK = serde_json::from_str(&identity_jwk).unwrap();
        assert!(validate_public_key_for_algorithm(SigningAlgorithm::EdDSA, &jwk).is_err());
    }

    #[test]
    fn remote_eddsa_strictly_rejects_small_order_r_with_nonweak_key() {
        // C2SP CCTV Ed25519 vector 5: ordinary verification accepts this
        // low-order R signature, while strict verification must reject it.
        fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
            assert_eq!(value.len(), 2 * N);
            let mut bytes = [0u8; N];
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16).unwrap();
            }
            bytes
        }
        let public_key =
            decode_hex("10eb7c3acfb2bed3e0d6ab89bf5a3d6afddd1176ce4812e38d9fd485058fdb1f");
        let signature = decode_hex(
            "00000000000000000000000000000000000000000000000000000000000000009472a69cd9a701a50d130ed52189e2455b23767db52cacb8716fb896ffeeac09",
        );
        let message = b"ed25519vectors 3";
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": URL_SAFE_NO_PAD.encode(public_key),
        })
        .to_string();

        let key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
        let parsed_signature = ed25519_dalek::Signature::from_bytes(&signature);
        assert!(!key.is_weak());
        assert!(ed25519_dalek::Verifier::verify(&key, message, &parsed_signature).is_ok());
        assert!(key.verify_strict(message, &parsed_signature).is_err());
        assert!(validate_remote_signature(SigningAlgorithm::EdDSA, &signature).is_ok());

        verify_remote_signature(SigningAlgorithm::EdDSA, &jwk, message, &signature)
            .expect_err("remote completion must use strict Ed25519 verification");
    }

    #[test]
    fn es256k_rejects_substituted_bindings() {
        let payload = b"canonical prepared credential payload";
        // Public-only signed vector preserves ES256K verifier coverage until
        // the remote provider exposes secp256k1 signing.
        let public_jwk = serde_json::json!({
            "kty": "EC", "crv": "secp256k1", "alg": "ES256K",
            "x": "75ly36FbnJzTT6bZT4KR_aVx3AlzR7WF6YWBSoi-3lQ",
            "y": "RswUWdEwFdU7zoC-Ov2YPYG7CrNKXjSMl6C2iwub97Y",
        });
        let wrong_public_jwk = serde_json::json!({
            "kty": "EC", "crv": "secp256k1", "alg": "ES256K",
            "x": "a3OraLg19-yg49xqGpakSsEf9os09-hDjt51hW-Rm8U",
            "y": "HaxjsiGpFq2HaRl2anX_I7x2Brp8ZW65DbFcnlN507k",
        });
        let signature = URL_SAFE_NO_PAD
            .decode("ldm8BHtz5gQ8LQsc87_KDMeLXk9rrR43mLneWXfEcZv58QcEDLRfNmHXnf3_cCHYFMTeYg5xGQDznvhmosUSQQ")
            .unwrap();
        assert_binding(
            SigningAlgorithm::ES256K,
            &public_jwk.to_string(),
            &wrong_public_jwk.to_string(),
            payload,
            &signature,
        );
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn es384_and_eddsa_remote_signatures_bind_payload_and_public_key() {
        let provider = crate::openbao_transit::DisposableOpenBao::from_marked_env();
        let payload = b"canonical prepared credential payload";
        let es384 = provider.create_es384();
        let wrong_es384 = provider.create_es384();
        let es384_signature = es384.sign_es384(payload).unwrap();
        assert_binding(
            SigningAlgorithm::ES384,
            es384.public_jwk(),
            wrong_es384.public_jwk(),
            payload,
            &es384_signature,
        );

        let eddsa = provider.create_ed25519();
        let wrong_eddsa = provider.create_ed25519();
        let eddsa_signature = eddsa.sign_ed25519(payload).unwrap();
        assert_binding(
            SigningAlgorithm::EdDSA,
            eddsa.public_jwk(),
            wrong_eddsa.public_jwk(),
            payload,
            &eddsa_signature,
        );
    }

    #[cfg(not(target_family = "wasm"))]
    #[test]
    #[ignore = "requires marked disposable OpenBao Transit and scoped signer"]
    fn rsa_remote_signature_binds_payload_and_public_key() {
        let provider = crate::openbao_transit::DisposableOpenBao::from_marked_env();
        let signer = provider.create_rsa2048();
        let wrong_signer = provider.create_rsa2048();
        let payload = b"canonical prepared credential payload";
        let signature = signer.sign_rsa_pkcs1(payload).unwrap();
        assert_binding(
            SigningAlgorithm::RS256,
            signer.public_jwk(),
            wrong_signer.public_jwk(),
            payload,
            &signature,
        );
    }
}
