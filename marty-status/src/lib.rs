//! Canonical credential status-list encoding and mutation.
//!
//! IETF Token Status Lists use least-significant-bit-first entries and a
//! DEFLATE stream carried in the ZLIB data format. W3C Bitstring Status Lists
//! use most-significant-bit-first entries and multibase base64url over GZIP.
//! All decoding is bounded and requires the exact advertised uncompressed
//! size.

use base64::Engine;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use thiserror::Error;

pub const MAX_STATUS_LIST_ENTRIES: usize = 16_777_216;
pub const W3C_MIN_STATUS_LIST_BITS: usize = 131_072;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StatusListError {
    #[error("status list size {size} exceeds maximum {maximum}")]
    SizeLimit { size: usize, maximum: usize },
    #[error("bits must be 1, 2, 4, or 8")]
    InvalidBits,
    #[error("index {index} out of range [0, {size})")]
    IndexOutOfRange { index: usize, size: usize },
    #[error("status {status} exceeds the {bits}-bit maximum {maximum}")]
    StatusOutOfRange { status: u8, bits: u8, maximum: u8 },
    #[error("encoded status list exceeds its size bound")]
    EncodedSizeLimit,
    #[error("invalid base64url status list: {0}")]
    InvalidBase64(String),
    #[error("W3C encodedList must use the base64url multibase prefix 'u'")]
    InvalidMultibase,
    #[error("invalid compressed status list: {0}")]
    InvalidCompression(String),
    #[error("decoded status list length {actual} does not match expected {expected}")]
    DecodedLength { actual: usize, expected: usize },
    #[error("W3C status lists require at least {minimum} entries")]
    PrivacyFloor { minimum: usize },
    #[error("status-list id and purpose must not be empty")]
    InvalidSubject,
}

pub type Result<T> = std::result::Result<T, StatusListError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenStatusList {
    bits: u8,
    data: Vec<u8>,
    size: usize,
}

impl TokenStatusList {
    pub fn new(size: usize, bits: u8) -> Result<Self> {
        validate_size(size)?;
        validate_bits(bits)?;
        Ok(Self {
            bits,
            data: vec![0; token_byte_len(size, bits)],
            size,
        })
    }

    pub fn from_bytes(data: Vec<u8>, size: usize, bits: u8) -> Result<Self> {
        validate_size(size)?;
        validate_bits(bits)?;
        let expected = token_byte_len(size, bits);
        if data.len() != expected {
            return Err(StatusListError::DecodedLength {
                actual: data.len(),
                expected,
            });
        }
        Ok(Self { bits, data, size })
    }

    pub fn get(&self, index: usize) -> Result<u8> {
        self.validate_index(index)?;
        let entries_per_byte = 8 / usize::from(self.bits);
        let byte_index = index / entries_per_byte;
        let shift = (index % entries_per_byte) * usize::from(self.bits);
        Ok((self.data[byte_index] >> shift) & self.mask())
    }

    pub fn set(&mut self, index: usize, status: u8) -> Result<()> {
        self.validate_index(index)?;
        let mask = self.mask();
        if status > mask {
            return Err(StatusListError::StatusOutOfRange {
                status,
                bits: self.bits,
                maximum: mask,
            });
        }
        let entries_per_byte = 8 / usize::from(self.bits);
        let byte_index = index / entries_per_byte;
        let shift = (index % entries_per_byte) * usize::from(self.bits);
        self.data[byte_index] = (self.data[byte_index] & !(mask << shift)) | (status << shift);
        Ok(())
    }

    pub fn is_revoked(&self, index: usize) -> Result<bool> {
        Ok(self.get(index)? != 0)
    }

    pub fn revoke(&mut self, index: usize) -> Result<()> {
        self.set(index, 1)
    }

    pub fn reinstate(&mut self, index: usize) -> Result<()> {
        self.set(index, 0)
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn bits_per_status(&self) -> u8 {
        self.bits
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn compress(&self) -> Result<Vec<u8>> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&self.data).map_err(compression_error)?;
        encoder.finish().map_err(compression_error)
    }

    pub fn to_base64url(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.compress()?))
    }

    pub fn from_compressed(data: &[u8], size: usize, bits: u8) -> Result<Self> {
        validate_size(size)?;
        validate_bits(bits)?;
        let expected = token_byte_len(size, bits);
        let decoded = read_exact_bounded(ZlibDecoder::new(data), expected)?;
        Self::from_bytes(decoded, size, bits)
    }

    pub fn from_base64url(encoded: &str, size: usize, bits: u8) -> Result<Self> {
        validate_size(size)?;
        validate_bits(bits)?;
        validate_encoded_len(encoded.len(), token_byte_len(size, bits))?;
        let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| StatusListError::InvalidBase64(error.to_string()))?;
        Self::from_compressed(&compressed, size, bits)
    }

    pub fn claim(&self) -> Result<TokenStatusListClaim> {
        Ok(TokenStatusListClaim {
            bits: self.bits,
            list: self.to_base64url()?,
        })
    }

    fn mask(&self) -> u8 {
        ((1u16 << self.bits) - 1) as u8
    }

    fn validate_index(&self, index: usize) -> Result<()> {
        if index >= self.size {
            return Err(StatusListError::IndexOutOfRange {
                index,
                size: self.size,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitstringStatusList {
    data: Vec<u8>,
    size: usize,
}

impl BitstringStatusList {
    pub fn new(size: usize) -> Result<Self> {
        validate_size(size)?;
        Ok(Self {
            data: vec![0; bitstring_byte_len(size)],
            size,
        })
    }

    pub fn from_bytes(data: Vec<u8>, size: usize) -> Result<Self> {
        validate_size(size)?;
        let expected = bitstring_byte_len(size);
        if data.len() != expected {
            return Err(StatusListError::DecodedLength {
                actual: data.len(),
                expected,
            });
        }
        Ok(Self { data, size })
    }

    pub fn get(&self, index: usize) -> Result<bool> {
        self.validate_index(index)?;
        let byte_index = index / 8;
        let shift = 7 - (index % 8);
        Ok(((self.data[byte_index] >> shift) & 1) == 1)
    }

    pub fn set(&mut self, index: usize, revoked: bool) -> Result<()> {
        self.validate_index(index)?;
        let byte_index = index / 8;
        let shift = 7 - (index % 8);
        if revoked {
            self.data[byte_index] |= 1 << shift;
        } else {
            self.data[byte_index] &= !(1 << shift);
        }
        Ok(())
    }

    pub fn is_revoked(&self, index: usize) -> Result<bool> {
        self.get(index)
    }

    pub fn revoke(&mut self, index: usize) -> Result<()> {
        self.set(index, true)
    }

    pub fn reinstate(&mut self, index: usize) -> Result<()> {
        self.set(index, false)
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub fn count_revoked(&self) -> usize {
        self.data
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn compress(&self) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&self.data).map_err(compression_error)?;
        encoder.finish().map_err(compression_error)
    }

    pub fn to_base64url(&self) -> Result<String> {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.compress()?);
        Ok(format!("u{encoded}"))
    }

    pub fn from_compressed(data: &[u8], size: usize) -> Result<Self> {
        validate_size(size)?;
        let expected = bitstring_byte_len(size);
        let decoded = read_exact_bounded(GzDecoder::new(data), expected)?;
        Self::from_bytes(decoded, size)
    }

    pub fn from_base64url(encoded: &str, size: usize) -> Result<Self> {
        validate_size(size)?;
        let payload = encoded
            .strip_prefix('u')
            .ok_or(StatusListError::InvalidMultibase)?;
        validate_encoded_len(payload.len(), bitstring_byte_len(size))?;
        let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| StatusListError::InvalidBase64(error.to_string()))?;
        Self::from_compressed(&compressed, size)
    }

    pub fn credential_subject(
        &self,
        id: impl Into<String>,
        status_purpose: impl Into<String>,
    ) -> Result<BitstringStatusListCredentialSubject> {
        if self.size < W3C_MIN_STATUS_LIST_BITS {
            return Err(StatusListError::PrivacyFloor {
                minimum: W3C_MIN_STATUS_LIST_BITS,
            });
        }
        let id = id.into();
        let status_purpose = status_purpose.into();
        if id.is_empty() || status_purpose.is_empty() {
            return Err(StatusListError::InvalidSubject);
        }
        Ok(BitstringStatusListCredentialSubject {
            id,
            subject_type: "BitstringStatusList".to_string(),
            status_purpose,
            encoded_list: self.to_base64url()?,
        })
    }

    fn validate_index(&self, index: usize) -> Result<()> {
        if index >= self.size {
            return Err(StatusListError::IndexOutOfRange {
                index,
                size: self.size,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TokenStatusListClaim {
    pub bits: u8,
    #[serde(rename = "lst")]
    pub list: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BitstringStatusListCredentialSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub subject_type: String,
    #[serde(rename = "statusPurpose")]
    pub status_purpose: String,
    #[serde(rename = "encodedList")]
    pub encoded_list: String,
}

fn validate_size(size: usize) -> Result<()> {
    if size > MAX_STATUS_LIST_ENTRIES {
        return Err(StatusListError::SizeLimit {
            size,
            maximum: MAX_STATUS_LIST_ENTRIES,
        });
    }
    Ok(())
}

fn validate_bits(bits: u8) -> Result<()> {
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(StatusListError::InvalidBits);
    }
    Ok(())
}

fn token_byte_len(size: usize, bits: u8) -> usize {
    size.div_ceil(8 / usize::from(bits))
}

fn bitstring_byte_len(size: usize) -> usize {
    size.div_ceil(8)
}

fn validate_encoded_len(encoded_len: usize, expected_bytes: usize) -> Result<()> {
    let max_compressed = expected_bytes.saturating_mul(2).saturating_add(1024);
    let max_encoded = max_compressed.div_ceil(3).saturating_mul(4);
    if encoded_len > max_encoded {
        return Err(StatusListError::EncodedSizeLimit);
    }
    Ok(())
}

fn read_exact_bounded<R: Read>(reader: R, expected: usize) -> Result<Vec<u8>> {
    let limit =
        u64::try_from(expected.saturating_add(1)).map_err(|_| StatusListError::SizeLimit {
            size: expected,
            maximum: MAX_STATUS_LIST_ENTRIES,
        })?;
    let mut output = Vec::with_capacity(expected);
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(compression_error)?;
    if output.len() != expected {
        return Err(StatusListError::DecodedLength {
            actual: output.len(),
            expected,
        });
    }
    Ok(output)
}

fn compression_error(error: impl std::fmt::Display) -> StatusListError {
    StatusListError::InvalidCompression(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::Value;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/status_list_vectors.json")).unwrap()
    }

    #[test]
    fn ietf_normative_vector_uses_lsb_first_packing_and_zlib() {
        let vector = &vectors()["vectors"][0];
        let values: Vec<u8> = serde_json::from_value(vector["statuses"].clone()).unwrap();
        let mut list = TokenStatusList::new(values.len(), 1).unwrap();
        for (index, value) in values.into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        assert_eq!(hex::encode(list.as_bytes()), vector["raw_hex"]);
        assert_eq!(
            hex::encode(list.compress().unwrap()),
            vector["compressed_hex"]
        );
        assert_eq!(list.to_base64url().unwrap(), vector["encoded"]);
    }

    #[test]
    fn token_status_roundtrip_preserves_multibit_values() {
        let mut list = TokenStatusList::new(100, 2).unwrap();
        for (index, value) in [0, 1, 2, 3].into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        let restored =
            TokenStatusList::from_base64url(&list.to_base64url().unwrap(), 100, 2).unwrap();
        assert_eq!(restored.as_bytes()[0], 0b1110_0100);
        for (index, value) in [0, 1, 2, 3].into_iter().enumerate() {
            assert_eq!(restored.get(index).unwrap(), value);
        }
    }

    #[test]
    fn w3c_status_uses_msb_first_gzip_and_multibase() {
        let mut list = BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS).unwrap();
        list.revoke(0).unwrap();
        list.revoke(7).unwrap();
        assert_eq!(list.as_bytes()[0], 0b1000_0001);
        let encoded = list.to_base64url().unwrap();
        assert!(encoded.starts_with('u'));
        let restored = BitstringStatusList::from_base64url(&encoded, list.len()).unwrap();
        assert!(restored.get(0).unwrap());
        assert!(restored.get(7).unwrap());
        assert_eq!(restored.count_revoked(), 2);
    }

    #[test]
    fn w3c_recommendation_vector_decodes_at_the_privacy_floor() {
        let vector = &vectors()["vectors"][1];
        let size = vector["size"].as_u64().unwrap() as usize;
        let encoded = vector["encoded"].as_str().unwrap();
        let list = BitstringStatusList::from_base64url(encoded, size).unwrap();
        assert_eq!(list.len(), W3C_MIN_STATUS_LIST_BITS);
        assert_eq!(hex::encode(&list.as_bytes()[..8]), vector["raw_hex_prefix"]);
        assert_eq!(list.count_revoked(), 0);
    }

    #[test]
    fn malformed_wrong_sized_and_oversized_payloads_fail_closed() {
        assert!(TokenStatusList::from_compressed(&[1, 2, 3], 100, 8).is_err());
        let list = TokenStatusList::new(8, 8).unwrap();
        assert!(TokenStatusList::from_base64url(&list.to_base64url().unwrap(), 9, 8).is_err());
        assert!(BitstringStatusList::from_base64url("not-multibase", 8).is_err());
        assert!(TokenStatusList::new(MAX_STATUS_LIST_ENTRIES + 1, 8).is_err());
        assert!(BitstringStatusList::new(MAX_STATUS_LIST_ENTRIES + 1).is_err());
    }

    #[test]
    fn generated_subject_enforces_privacy_floor_and_contract() {
        let small = BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS - 1).unwrap();
        assert!(small
            .credential_subject("urn:example:list", "revocation")
            .is_err());
        let valid = BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS).unwrap();
        let subject = valid
            .credential_subject("https://issuer.example/status#list", "revocation")
            .unwrap();
        let value = serde_json::to_value(subject).unwrap();
        assert_eq!(value["type"], "BitstringStatusList");
        assert!(value["encodedList"].as_str().unwrap().starts_with('u'));
    }

    proptest! {
        #[test]
        fn token_mutation_roundtrips(
            size in 1usize..4096,
            bits in prop::sample::select(vec![1u8, 2, 4, 8]),
            operations in prop::collection::vec((0usize..4096, any::<u8>()), 0..128),
        ) {
            let mut list = TokenStatusList::new(size, bits).unwrap();
            let mask = ((1u16 << bits) - 1) as u8;
            for (candidate, value) in operations {
                let index = candidate % size;
                list.set(index, value & mask).unwrap();
            }
            let restored = TokenStatusList::from_base64url(
                &list.to_base64url().unwrap(), size, bits,
            ).unwrap();
            prop_assert_eq!(restored, list);
        }

        #[test]
        fn bitstring_mutation_roundtrips(
            size in 1usize..4096,
            operations in prop::collection::vec((0usize..4096, any::<bool>()), 0..128),
        ) {
            let mut list = BitstringStatusList::new(size).unwrap();
            for (candidate, value) in operations {
                list.set(candidate % size, value).unwrap();
            }
            let restored = BitstringStatusList::from_base64url(
                &list.to_base64url().unwrap(), size,
            ).unwrap();
            prop_assert_eq!(restored, list);
        }
    }
}
