//! Ed448 (Edwards curve over 448-bit field) verification operations.
//!
//! Production builds expose Ed448 verification for eMRTD Active Authentication.
//! Key generation and signing exist only in crate-internal regression tests.
//!
//! Ed448 provides 224-bit security (vs 128-bit for Ed25519) and is used
//! in newer ePassports with higher security requirements.
//!
//! Verification accepts only public-key bytes, a message, and a signature.

use der::Decode;
use ed448_goldilocks_plus::elliptic_curve::Group;
use ed448_goldilocks_plus::sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use ed448_goldilocks_plus::{
    CompressedEdwardsY, EdwardsPoint, Scalar, ScalarBytes, WideScalarBytes,
};

use crate::{CryptoError, CryptoResult};

const HASH_HEAD: [u8; 8] = *b"SigEd448";

/// Ed448 public key size in bytes (57 bytes).
pub const ED448_PUBLIC_KEY_SIZE: usize = 57;

/// Ed448 signature size in bytes (114 bytes).
pub const ED448_SIGNATURE_SIZE: usize = 114;

/// Verify an Ed448 signature.
///
/// # Arguments
/// * `public_key` - 57-byte public key
/// * `message` - Message that was signed
/// * `signature` - 114-byte signature
///
/// # Returns
/// `true` if signature is valid
pub fn ed448_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
    verify_ed448_inner(public_key, message, signature, &[])
}

/// Verify an Ed448 signature with a context string.
///
/// # Arguments
/// * `public_key` - 57-byte public key
/// * `message` - Message that was signed
/// * `signature` - 114-byte signature
/// * `context` - Context string used during signing
///
/// # Returns
/// `true` if signature is valid
pub fn ed448_verify_with_context(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> CryptoResult<bool> {
    verify_ed448_inner(public_key, message, signature, context)
}

// Adapted from the verification-only half of ed448-goldilocks-plus 0.16's
// RFC 8032 implementation. The dependency's public curve/scalar operations are
// used directly so its combined SigningKey/VerifyingKey module stays disabled.
fn verify_ed448_inner(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> CryptoResult<bool> {
    if public_key.len() != ED448_PUBLIC_KEY_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 public key size: expected {}, got {}",
            ED448_PUBLIC_KEY_SIZE,
            public_key.len()
        )));
    }

    if signature.len() != ED448_SIGNATURE_SIZE {
        return Err(CryptoError::crypto_error(format!(
            "Invalid Ed448 signature size: expected {}, got {}",
            ED448_SIGNATURE_SIZE,
            signature.len()
        )));
    }

    if context.len() > 255 {
        return Err(CryptoError::crypto_error(
            "Ed448 context must be at most 255 bytes",
        ));
    }

    let public_key: [u8; ED448_PUBLIC_KEY_SIZE] = public_key
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid public key length"))?;
    let compressed_public_key = CompressedEdwardsY(public_key);
    let Some(public_point) = Option::<EdwardsPoint>::from(compressed_public_key.decompress())
    else {
        return Ok(false);
    };
    if bool::from(public_point.is_identity()) {
        return Ok(false);
    }

    let signature: [u8; ED448_SIGNATURE_SIZE] = signature
        .try_into()
        .map_err(|_| CryptoError::crypto_error("Invalid signature length"))?;
    let mut r_bytes = [0u8; ED448_PUBLIC_KEY_SIZE];
    r_bytes.copy_from_slice(&signature[..ED448_PUBLIC_KEY_SIZE]);
    let compressed_r = CompressedEdwardsY(r_bytes);
    let Some(r) = Option::<EdwardsPoint>::from(compressed_r.decompress()) else {
        return Ok(false);
    };
    if bool::from(r.is_identity()) {
        return Ok(false);
    }

    let mut s_bytes = [0u8; ED448_PUBLIC_KEY_SIZE];
    s_bytes.copy_from_slice(&signature[ED448_PUBLIC_KEY_SIZE..]);
    if s_bytes[56] != 0 {
        return Ok(false);
    }
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(ScalarBytes::from_slice(
        &s_bytes,
    ))) else {
        return Ok(false);
    };
    if bool::from(s.is_zero()) {
        return Ok(false);
    }

    // SHAKE256(dom4(F, C) || R || A || PH(M), 114) -> scalar k.
    let mut hash_output = WideScalarBytes::default();
    let mut reader = Shake256::default()
        .chain(HASH_HEAD)
        .chain([0])
        .chain([context.len() as u8])
        .chain(context)
        .chain(r_bytes)
        .chain(public_key)
        .chain(message)
        .finalize_xof();
    reader.read(&mut hash_output);
    let k = Scalar::from_bytes_mod_order_wide(&hash_output);

    // RFC 8032 verification equation: [S]B = R + [k]A.
    Ok(EdwardsPoint::GENERATOR * s == r + (public_point * k))
}

/// Verify an Ed448 signature using a SPKI-encoded public key.
///
/// This function accepts DER-encoded SubjectPublicKeyInfo format public keys,
/// which is the standard format used in X.509 certificates.
///
/// # Arguments
///
/// * `public_key_der` - DER-encoded SubjectPublicKeyInfo or raw 57-byte public key
/// * `message` - Original message
/// * `signature` - 114-byte signature
///
/// # Returns
///
/// `Ok(true)` if signature is valid, `Ok(false)` if invalid.
pub fn verify_ed448_spki(
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> CryptoResult<bool> {
    let public_key: [u8; ED448_PUBLIC_KEY_SIZE] = if public_key_der.len() == ED448_PUBLIC_KEY_SIZE {
        public_key_der
            .try_into()
            .map_err(|_| CryptoError::invalid_key("Invalid raw Ed448 public key length"))?
    } else {
        let spki = x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(public_key_der)
            .map_err(|error| CryptoError::der_error(format!("Invalid Ed448 SPKI: {error}")))?;
        if spki.algorithm.oid != const_oid::db::rfc8410::ID_ED_448
            || spki.algorithm.parameters.is_some()
        {
            return Err(CryptoError::invalid_key(
                "Invalid Ed448 SPKI algorithm identifier",
            ));
        }
        if spki.subject_public_key.unused_bits() != 0 {
            return Err(CryptoError::invalid_key(
                "Invalid Ed448 SPKI public key bit string",
            ));
        }
        spki.subject_public_key
            .raw_bytes()
            .try_into()
            .map_err(|_| CryptoError::invalid_key("Invalid Ed448 SPKI public key length"))?
    };

    ed448_verify(&public_key, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode<const N: usize>(value: &str) -> [u8; N] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn empty_message_vector() -> ([u8; 57], [u8; 114]) {
        (
            decode("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"),
            decode("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"),
        )
    }

    #[test]
    fn verifies_rfc8032_empty_message_vector() {
        let (public_key, signature) = empty_message_vector();
        assert!(ed448_verify(&public_key, b"", &signature).unwrap());
    }

    #[test]
    fn rejects_wrong_message_for_rfc8032_vector() {
        let (public_key, signature) = empty_message_vector();
        assert!(!ed448_verify(&public_key, b"not empty", &signature).unwrap());
    }

    #[test]
    fn verifies_rfc8032_context_vector() {
        let public_key = decode::<57>("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
        let signature = decode::<114>("d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00");

        assert!(ed448_verify_with_context(&public_key, &[3], &signature, b"foo").unwrap());
        assert!(!ed448_verify_with_context(&public_key, &[3], &signature, b"bar").unwrap());
        assert!(!ed448_verify(&public_key, &[3], &signature).unwrap());
    }

    #[test]
    fn rejects_invalid_sizes_and_identity_components() {
        assert!(ed448_verify(&[0u8; 32], b"message", &[0u8; 114]).is_err());
        assert!(ed448_verify(&[0u8; 57], b"message", &[0u8; 64]).is_err());

        let mut identity = [0u8; 57];
        identity[0] = 1;
        let (_, valid_signature) = empty_message_vector();
        assert!(!ed448_verify(&identity, b"", &valid_signature).unwrap());

        let (public_key, mut identity_r_signature) = empty_message_vector();
        identity_r_signature[..57].fill(0);
        identity_r_signature[0] = 1;
        assert!(!ed448_verify(&public_key, b"", &identity_r_signature).unwrap());
    }

    #[test]
    fn spki_requires_exact_ed448_algorithm_metadata() {
        let (public_key, signature) = empty_message_vector();
        let mut spki = hex::decode("3043300506032b6571033a00").unwrap();
        spki.extend_from_slice(&public_key);
        assert!(verify_ed448_spki(&spki, b"", &signature).unwrap());

        let mut arbitrary_suffix_container = vec![0u8; 12];
        arbitrary_suffix_container.extend_from_slice(&public_key);
        assert!(verify_ed448_spki(&arbitrary_suffix_container, b"", &signature).is_err());

        let mut wrong_oid = spki.clone();
        wrong_oid[8] = 0x70;
        assert!(verify_ed448_spki(&wrong_oid, b"", &signature).is_err());

        let mut null_parameters = hex::decode("3045300706032b65710500033a00").unwrap();
        null_parameters.extend_from_slice(&public_key);
        assert!(verify_ed448_spki(&null_parameters, b"", &signature).is_err());
    }
}
