//! Native credential status-list encoding and mutation.
//!
//! IETF Token Status Lists use LSB-first entries and ZLIB-wrapped DEFLATE.
//! W3C Bitstring Status Lists use MSB-first entries and multibase base64url
//! over GZIP. Decoding is bounded and requires the exact advertised size.

use base64::Engine;
use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use pyo3::exceptions::{PyIndexError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::io::{Read, Write};

const MAX_STATUS_LIST_ENTRIES: usize = 16_777_216;
const W3C_MIN_STATUS_LIST_BITS: usize = 131_072;

fn value_error(message: impl Into<String>) -> PyErr {
    PyErr::new::<PyValueError, _>(message.into())
}

fn runtime_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<PyRuntimeError, _>(error.to_string())
}

fn validate_size(size: usize) -> PyResult<()> {
    if size > MAX_STATUS_LIST_ENTRIES {
        return Err(value_error(format!(
            "status list size {size} exceeds maximum {MAX_STATUS_LIST_ENTRIES}"
        )));
    }
    Ok(())
}

fn validate_bits(bits: u8) -> PyResult<()> {
    if !matches!(bits, 1 | 2 | 4 | 8) {
        return Err(value_error("bits must be 1, 2, 4, or 8"));
    }
    Ok(())
}

fn token_byte_len(size: usize, bits: u8) -> usize {
    size.div_ceil(8 / usize::from(bits))
}

fn bitstring_byte_len(size: usize) -> usize {
    size.div_ceil(8)
}

fn validate_encoded_len(encoded_len: usize, expected_bytes: usize) -> PyResult<()> {
    // Valid compressed data has small framing overhead and cannot reasonably
    // exceed twice the uncompressed payload. Reject before base64 allocation.
    let max_compressed = expected_bytes.saturating_mul(2).saturating_add(1024);
    let max_encoded = max_compressed.div_ceil(3).saturating_mul(4);
    if encoded_len > max_encoded {
        return Err(value_error("encoded status list exceeds its size bound"));
    }
    Ok(())
}

fn read_exact_bounded<R: Read>(reader: R, expected: usize) -> PyResult<Vec<u8>> {
    let limit = u64::try_from(expected.saturating_add(1))
        .map_err(|_| value_error("status list size is unsupported"))?;
    let mut output = Vec::with_capacity(expected);
    reader
        .take(limit)
        .read_to_end(&mut output)
        .map_err(|error| value_error(format!("invalid compressed status list: {error}")))?;
    if output.len() != expected {
        return Err(value_error(format!(
            "decoded status list length {} does not match expected {expected}",
            output.len()
        )));
    }
    Ok(output)
}

/// IETF Token Status List byte array.
#[pyclass]
pub struct TokenStatusList {
    bits: u8,
    data: Vec<u8>,
    size: usize,
}

#[pymethods]
impl TokenStatusList {
    #[new]
    #[pyo3(signature = (size, bits=8))]
    pub fn new(size: usize, bits: u8) -> PyResult<Self> {
        validate_size(size)?;
        validate_bits(bits)?;
        Ok(Self {
            bits,
            data: vec![0; token_byte_len(size, bits)],
            size,
        })
    }

    pub fn get(&self, index: usize) -> PyResult<u8> {
        if index >= self.size {
            return Err(PyErr::new::<PyIndexError, _>(format!(
                "index {index} out of range [0, {})",
                self.size
            )));
        }
        let entries_per_byte = 8 / usize::from(self.bits);
        let byte_index = index / entries_per_byte;
        let shift = (index % entries_per_byte) * usize::from(self.bits);
        let mask = ((1u16 << self.bits) - 1) as u8;
        Ok((self.data[byte_index] >> shift) & mask)
    }

    pub fn set(&mut self, index: usize, status: u8) -> PyResult<()> {
        if index >= self.size {
            return Err(PyErr::new::<PyIndexError, _>(format!(
                "index {index} out of range [0, {})",
                self.size
            )));
        }
        let mask = ((1u16 << self.bits) - 1) as u8;
        if status > mask {
            return Err(value_error(format!(
                "status {status} exceeds the {}-bit maximum {mask}",
                self.bits
            )));
        }
        let entries_per_byte = 8 / usize::from(self.bits);
        let byte_index = index / entries_per_byte;
        let shift = (index % entries_per_byte) * usize::from(self.bits);
        self.data[byte_index] = (self.data[byte_index] & !(mask << shift)) | (status << shift);
        Ok(())
    }

    pub fn is_revoked(&self, index: usize) -> PyResult<bool> {
        Ok(self.get(index)? != 0)
    }

    pub fn revoke(&mut self, index: usize) -> PyResult<()> {
        self.set(index, 1)
    }

    pub fn reinstate(&mut self, index: usize) -> PyResult<()> {
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

    pub fn compress(&self) -> PyResult<Vec<u8>> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&self.data).map_err(runtime_error)?;
        encoder.finish().map_err(runtime_error)
    }

    pub fn to_base64url(&self) -> PyResult<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.compress()?))
    }

    #[staticmethod]
    #[pyo3(signature = (data, size, bits=8))]
    pub fn from_compressed(data: Vec<u8>, size: usize, bits: u8) -> PyResult<Self> {
        validate_size(size)?;
        validate_bits(bits)?;
        let expected = token_byte_len(size, bits);
        let decoded = read_exact_bounded(ZlibDecoder::new(data.as_slice()), expected)?;
        Ok(Self {
            bits,
            data: decoded,
            size,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (encoded, size, bits=8))]
    pub fn from_base64url(encoded: &str, size: usize, bits: u8) -> PyResult<Self> {
        validate_size(size)?;
        validate_bits(bits)?;
        validate_encoded_len(encoded.len(), token_byte_len(size, bits))?;
        let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| value_error(format!("invalid base64url status list: {error}")))?;
        Self::from_compressed(compressed, size, bits)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// W3C Bitstring Status List byte array.
#[pyclass]
pub struct BitstringStatusList {
    data: Vec<u8>,
    size: usize,
}

#[pymethods]
impl BitstringStatusList {
    #[new]
    pub fn new(size: usize) -> PyResult<Self> {
        validate_size(size)?;
        Ok(Self {
            data: vec![0; bitstring_byte_len(size)],
            size,
        })
    }

    pub fn get(&self, index: usize) -> PyResult<bool> {
        if index >= self.size {
            return Err(PyErr::new::<PyIndexError, _>(format!(
                "index {index} out of range [0, {})",
                self.size
            )));
        }
        let byte_index = index / 8;
        let shift = 7 - (index % 8);
        Ok(((self.data[byte_index] >> shift) & 1) == 1)
    }

    pub fn set(&mut self, index: usize, revoked: bool) -> PyResult<()> {
        if index >= self.size {
            return Err(PyErr::new::<PyIndexError, _>(format!(
                "index {index} out of range [0, {})",
                self.size
            )));
        }
        let byte_index = index / 8;
        let shift = 7 - (index % 8);
        if revoked {
            self.data[byte_index] |= 1 << shift;
        } else {
            self.data[byte_index] &= !(1 << shift);
        }
        Ok(())
    }

    pub fn is_revoked(&self, index: usize) -> PyResult<bool> {
        self.get(index)
    }

    pub fn revoke(&mut self, index: usize) -> PyResult<()> {
        self.set(index, true)
    }

    pub fn reinstate(&mut self, index: usize) -> PyResult<()> {
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

    pub fn compress(&self) -> PyResult<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&self.data).map_err(runtime_error)?;
        encoder.finish().map_err(runtime_error)
    }

    pub fn to_base64url(&self) -> PyResult<String> {
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.compress()?);
        Ok(format!("u{encoded}"))
    }

    #[staticmethod]
    pub fn from_compressed(data: Vec<u8>, size: usize) -> PyResult<Self> {
        validate_size(size)?;
        let expected = bitstring_byte_len(size);
        let decoded = read_exact_bounded(GzDecoder::new(data.as_slice()), expected)?;
        Ok(Self {
            data: decoded,
            size,
        })
    }

    #[staticmethod]
    pub fn from_base64url(encoded: &str, size: usize) -> PyResult<Self> {
        validate_size(size)?;
        let payload = encoded.strip_prefix('u').ok_or_else(|| {
            value_error("W3C encodedList must use the base64url multibase prefix 'u'")
        })?;
        validate_encoded_len(payload.len(), bitstring_byte_len(size))?;
        let compressed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|error| {
                value_error(format!("invalid multibase base64url status list: {error}"))
            })?;
        Self::from_compressed(compressed, size)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

#[pyfunction]
pub fn create_status_list_claim(status_list: &TokenStatusList) -> PyResult<String> {
    serde_json::to_string(&serde_json::json!({
        "bits": status_list.bits_per_status(),
        "lst": status_list.to_base64url()?,
    }))
    .map_err(runtime_error)
}

#[pyfunction]
#[pyo3(signature = (status_list, id, status_purpose="revocation"))]
pub fn create_bitstring_credential_subject(
    status_list: &BitstringStatusList,
    id: &str,
    status_purpose: &str,
) -> PyResult<String> {
    if status_list.len() < W3C_MIN_STATUS_LIST_BITS {
        return Err(value_error(format!(
            "W3C status lists require at least {W3C_MIN_STATUS_LIST_BITS} entries"
        )));
    }
    if id.is_empty() || status_purpose.is_empty() {
        return Err(value_error("status-list id and purpose must not be empty"));
    }
    serde_json::to_string(&serde_json::json!({
        "id": id,
        "type": "BitstringStatusList",
        "statusPurpose": status_purpose,
        "encodedList": status_list.to_base64url()?,
    }))
    .map_err(runtime_error)
}

pub fn register_status_list_bindings(parent: &Bound<'_, PyModule>) -> PyResult<()> {
    let module = PyModule::new(parent.py(), "status_list")?;
    module.add_class::<TokenStatusList>()?;
    module.add_class::<BitstringStatusList>()?;
    module.add_function(wrap_pyfunction!(create_status_list_claim, &module)?)?;
    module.add_function(wrap_pyfunction!(
        create_bitstring_credential_subject,
        &module
    )?)?;
    parent.add_submodule(&module)?;

    parent.add_class::<TokenStatusList>()?;
    parent.add_class::<BitstringStatusList>()?;
    parent.add_function(wrap_pyfunction!(create_status_list_claim, parent)?)?;
    parent.add_function(wrap_pyfunction!(
        create_bitstring_credential_subject,
        parent
    )?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ietf_vector_uses_lsb_first_packing_and_zlib() {
        let values = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        let mut list = TokenStatusList::new(values.len(), 1).unwrap();
        for (index, value) in values.into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        assert_eq!(list.to_bytes(), vec![0xb9, 0xa3]);
        assert_eq!(
            hex::encode(list.compress().unwrap()),
            "78dadbb918000217015d"
        );
    }

    #[test]
    fn token_status_roundtrip_preserves_multibit_values() {
        let mut list = TokenStatusList::new(100, 2).unwrap();
        for (index, value) in [0, 1, 2, 3].into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        let restored =
            TokenStatusList::from_base64url(&list.to_base64url().unwrap(), 100, 2).unwrap();
        assert_eq!(restored.to_bytes()[0], 0b1110_0100);
        for (index, value) in [0, 1, 2, 3].into_iter().enumerate() {
            assert_eq!(restored.get(index).unwrap(), value);
        }
    }

    #[test]
    fn bitstring_uses_msb_first_and_multibase() {
        let mut list = BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS).unwrap();
        list.revoke(0).unwrap();
        list.revoke(7).unwrap();
        assert_eq!(list.to_bytes()[0], 0b1000_0001);
        let encoded = list.to_base64url().unwrap();
        assert!(encoded.starts_with('u'));
        let restored = BitstringStatusList::from_base64url(&encoded, list.len()).unwrap();
        assert!(restored.get(0).unwrap());
        assert!(restored.get(7).unwrap());
        assert_eq!(restored.count_revoked(), 2);
    }

    #[test]
    fn malformed_or_wrong_sized_payloads_fail_closed() {
        assert!(TokenStatusList::from_compressed(vec![1, 2, 3], 100, 8).is_err());
        let list = TokenStatusList::new(8, 8).unwrap();
        assert!(TokenStatusList::from_base64url(&list.to_base64url().unwrap(), 9, 8).is_err());
        assert!(BitstringStatusList::from_base64url("not-multibase", 8).is_err());
    }

    #[test]
    fn generated_w3c_subject_enforces_privacy_floor() {
        let small = BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS - 1).unwrap();
        assert!(
            create_bitstring_credential_subject(&small, "urn:example:list", "revocation").is_err()
        );
        let valid = BitstringStatusList::new(W3C_MIN_STATUS_LIST_BITS).unwrap();
        let subject = create_bitstring_credential_subject(
            &valid,
            "https://issuer.example/status#list",
            "revocation",
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&subject).unwrap();
        assert!(value["encodedList"].as_str().unwrap().starts_with('u'));
    }

    #[test]
    fn unreasonable_allocations_are_rejected() {
        assert!(TokenStatusList::new(MAX_STATUS_LIST_ENTRIES + 1, 8).is_err());
        assert!(BitstringStatusList::new(MAX_STATUS_LIST_ENTRIES + 1).is_err());
    }
}
