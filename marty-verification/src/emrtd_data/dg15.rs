use der::{Decode, Encode};
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::EncodePublicKey,
    traits::PublicKeyParts,
    BigUint, RsaPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoOwned;

use super::elementary::parse_tlv;
use super::{ensure_bounded, EmrtdDataError, EmrtdDataResult};

const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
const MIN_ACTIVE_AUTH_RSA_BITS: usize = 1024;

/// Construct a canonical RSA SubjectPublicKeyInfo value from public components.
///
/// This keeps compatibility adapters free of ASN.1 and big-integer logic while
/// retaining the historical ability to represent a DG15 RSA public key.
pub fn rsa_public_key_spki(modulus: &str, public_exponent: u64) -> EmrtdDataResult<Vec<u8>> {
    let modulus = BigUint::parse_bytes(modulus.as_bytes(), 10).ok_or_else(|| {
        EmrtdDataError::InvalidFormat("RSA modulus must be a decimal integer".into())
    })?;
    let public_exponent = BigUint::from(public_exponent);
    let key = RsaPublicKey::new(modulus, public_exponent).map_err(|error| {
        EmrtdDataError::InvalidFormat(format!("invalid RSA public key: {error}"))
    })?;
    key.to_public_key_der()
        .map(|document| document.as_bytes().to_vec())
        .map_err(|error| EmrtdDataError::Encoding(format!("SPKI encoding failed: {error}")))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dg15Info {
    pub algorithm: String,
    pub algorithm_oid: String,
    pub key_size: usize,
    pub public_exponent: u64,
    pub modulus: String,
    pub key_usage: String,
    pub spki_der: Vec<u8>,
    pub fingerprint_sha256: String,
    pub valid_for_active_authentication: bool,
}

pub fn parse_dg15(data: &[u8]) -> EmrtdDataResult<Dg15Info> {
    ensure_bounded(data, "DG15")?;
    let outer = parse_tlv(data, 0)?;
    if outer.tag != 0x6f {
        return Err(EmrtdDataError::InvalidFormat(format!(
            "invalid DG15 tag 0x{:X}; expected 0x6F",
            outer.tag
        )));
    }
    if outer.next_offset != data.len() {
        return Err(EmrtdDataError::InvalidTlv(
            "trailing data after DG15".into(),
        ));
    }

    inspect_rsa_public_key(outer.value)
}

/// Inspect and canonicalize a DER RSA SubjectPublicKeyInfo value.
pub fn inspect_rsa_public_key(spki_der: &[u8]) -> EmrtdDataResult<Dg15Info> {
    ensure_bounded(spki_der, "RSA public key")?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|error| EmrtdDataError::Encoding(format!("invalid DG15 SPKI: {error}")))?;
    let canonical_input = spki
        .to_der()
        .map_err(|error| EmrtdDataError::Encoding(format!("DG15 SPKI encoding failed: {error}")))?;
    if canonical_input != spki_der {
        return Err(EmrtdDataError::InvalidFormat(
            "DG15 SPKI must use canonical DER".into(),
        ));
    }

    let algorithm_oid = spki.algorithm.oid.to_string();
    if algorithm_oid != RSA_ENCRYPTION_OID {
        return Err(EmrtdDataError::Unsupported(format!(
            "unsupported DG15 public key algorithm: {algorithm_oid}"
        )));
    }
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| EmrtdDataError::InvalidFormat("DG15 key has unused bits".into()))?;
    let key = RsaPublicKey::from_pkcs1_der(key_bytes)
        .map_err(|error| EmrtdDataError::Encoding(format!("invalid DG15 RSA key: {error}")))?;
    let canonical_pkcs1 = key
        .to_pkcs1_der()
        .map_err(|error| EmrtdDataError::Encoding(format!("RSA encoding failed: {error}")))?;
    if canonical_pkcs1.as_bytes() != key_bytes {
        return Err(EmrtdDataError::InvalidFormat(
            "DG15 RSA key must use canonical DER".into(),
        ));
    }

    let exponent_bytes = key.e().to_bytes_be();
    let public_exponent = exponent_bytes.iter().try_fold(0u64, |value, octet| {
        value
            .checked_mul(256)
            .and_then(|current| current.checked_add(u64::from(*octet)))
    });
    let public_exponent = public_exponent.ok_or_else(|| {
        EmrtdDataError::Unsupported("DG15 RSA exponent is larger than 64 bits".into())
    })?;
    let spki_der = key
        .to_public_key_der()
        .map_err(|error| EmrtdDataError::Encoding(format!("SPKI encoding failed: {error}")))?
        .as_bytes()
        .to_vec();
    let key_size = key.n().bits();

    Ok(Dg15Info {
        algorithm: "RSA".into(),
        algorithm_oid,
        key_size,
        public_exponent,
        modulus: key.n().to_string(),
        key_usage: "chip_authentication".into(),
        fingerprint_sha256: hex::encode(Sha256::digest(&spki_der)),
        spki_der,
        valid_for_active_authentication: key_size >= MIN_ACTIVE_AUTH_RSA_BITS,
    })
}
