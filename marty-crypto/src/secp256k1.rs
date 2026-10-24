//! Public-only ES256K verification for JOSE and COSE.
//!
//! Backend signing is unavailable in the verification role:
//!
//! ```compile_fail
//! let _: Option<ecdsa_core::SigningKey<k256::Secp256k1>> = None;
//! ```

use crate::{CryptoError, CryptoResult};

/// Verify a fixed-width, 64-byte ES256K signature over `message`.
///
/// RFC 8812 section 3.2 specifies ordinary ECDSA, without a Bitcoin low-S
/// requirement. Normalize only the parsed public signature copy for the
/// backend's low-S policy. The caller's original signed bytes remain untouched.
/// https://www.rfc-editor.org/rfc/rfc8812.html#section-3.2
pub fn verify_sha256(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    use sha2::Digest;

    let key = k256::PublicKey::from_sec1_bytes(public_key).map_err(|error| {
        CryptoError::invalid_signature_with_context(
            "ES256K",
            format!("Invalid public key: {error}"),
        )
    })?;
    let signature = k256::ecdsa::Signature::from_slice(signature)
        .map_err(|error| {
            CryptoError::invalid_signature_with_context(
                "ES256K",
                format!("Invalid signature: {error}"),
            )
        })?
        .normalize_s();
    let digest = sha2::Sha256::digest(message);
    let point = k256::ProjectivePoint::from(*key.as_affine());
    Ok(
        ecdsa_core::hazmat::verify_prehashed::<k256::Secp256k1>(&point, &digest, &signature)
            .is_ok(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    #[test]
    fn verifies_both_public_s_representations_without_mutating_input() {
        let mut key = vec![4];
        key.extend(
            URL_SAFE_NO_PAD
                .decode("75ly36FbnJzTT6bZT4KR_aVx3AlzR7WF6YWBSoi-3lQ")
                .unwrap(),
        );
        key.extend(
            URL_SAFE_NO_PAD
                .decode("RswUWdEwFdU7zoC-Ov2YPYG7CrNKXjSMl6C2iwub97Y")
                .unwrap(),
        );
        let signature = URL_SAFE_NO_PAD.decode("ldm8BHtz5gQ8LQsc87_KDMeLXk9rrR43mLneWXfEcZv58QcEDLRfNmHXnf3_cCHYFMTeYg5xGQDznvhmosUSQQ").unwrap();
        let original = signature.clone();
        let low = k256::ecdsa::Signature::from_slice(&signature)
            .unwrap()
            .normalize_s()
            .to_bytes();
        assert_ne!(signature.as_slice(), low.as_slice());
        for bytes in [signature.as_slice(), low.as_slice()] {
            assert!(verify_sha256(&key, b"canonical prepared credential payload", bytes).unwrap());
            assert!(!verify_sha256(&key, b"changed", bytes).unwrap());
        }
        assert_eq!(signature, original);
        assert!(verify_sha256(&key, b"payload", &signature[..63]).is_err());
        assert!(verify_sha256(&key, b"payload", &[0; 64]).is_err());
    }
}
