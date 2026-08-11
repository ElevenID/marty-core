//! Thin Python adapters for the canonical `marty-status` implementation.

use marty_status::StatusListError;
use pyo3::exceptions::{PyIndexError, PyValueError};
use pyo3::prelude::*;

fn native_error(error: StatusListError) -> PyErr {
    match error {
        StatusListError::IndexOutOfRange { .. } => PyErr::new::<PyIndexError, _>(error.to_string()),
        _ => PyErr::new::<PyValueError, _>(error.to_string()),
    }
}

#[pyclass]
pub struct TokenStatusList {
    inner: marty_status::TokenStatusList,
}

#[pymethods]
impl TokenStatusList {
    #[new]
    #[pyo3(signature = (size, bits=8))]
    pub fn new(size: usize, bits: u8) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::TokenStatusList::new(size, bits).map_err(native_error)?,
        })
    }

    pub fn get(&self, index: usize) -> PyResult<u8> {
        self.inner.get(index).map_err(native_error)
    }

    pub fn set(&mut self, index: usize, status: u8) -> PyResult<()> {
        self.inner.set(index, status).map_err(native_error)
    }

    pub fn is_revoked(&self, index: usize) -> PyResult<bool> {
        self.inner.is_revoked(index).map_err(native_error)
    }

    pub fn revoke(&mut self, index: usize) -> PyResult<()> {
        self.inner.revoke(index).map_err(native_error)
    }

    pub fn reinstate(&mut self, index: usize) -> PyResult<()> {
        self.inner.reinstate(index).map_err(native_error)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn bits_per_status(&self) -> u8 {
        self.inner.bits_per_status()
    }

    pub fn compress(&self) -> PyResult<Vec<u8>> {
        self.inner.compress().map_err(native_error)
    }

    pub fn to_base64url(&self) -> PyResult<String> {
        self.inner.to_base64url().map_err(native_error)
    }

    #[staticmethod]
    #[pyo3(signature = (data, size, bits=8))]
    pub fn from_bytes(data: Vec<u8>, size: usize, bits: u8) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::TokenStatusList::from_bytes(data, size, bits)
                .map_err(native_error)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (data, size, bits=8))]
    pub fn from_compressed(data: Vec<u8>, size: usize, bits: u8) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::TokenStatusList::from_compressed(&data, size, bits)
                .map_err(native_error)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (encoded, size, bits=8))]
    pub fn from_base64url(encoded: &str, size: usize, bits: u8) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::TokenStatusList::from_base64url(encoded, size, bits)
                .map_err(native_error)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[pyclass]
pub struct BitstringStatusList {
    inner: marty_status::BitstringStatusList,
}

#[pymethods]
impl BitstringStatusList {
    #[new]
    pub fn new(size: usize) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::BitstringStatusList::new(size).map_err(native_error)?,
        })
    }

    pub fn get(&self, index: usize) -> PyResult<bool> {
        self.inner.get(index).map_err(native_error)
    }

    pub fn set(&mut self, index: usize, revoked: bool) -> PyResult<()> {
        self.inner.set(index, revoked).map_err(native_error)
    }

    pub fn is_revoked(&self, index: usize) -> PyResult<bool> {
        self.inner.is_revoked(index).map_err(native_error)
    }

    pub fn revoke(&mut self, index: usize) -> PyResult<()> {
        self.inner.revoke(index).map_err(native_error)
    }

    pub fn reinstate(&mut self, index: usize) -> PyResult<()> {
        self.inner.reinstate(index).map_err(native_error)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn count_revoked(&self) -> usize {
        self.inner.count_revoked()
    }

    pub fn compress(&self) -> PyResult<Vec<u8>> {
        self.inner.compress().map_err(native_error)
    }

    pub fn to_base64url(&self) -> PyResult<String> {
        self.inner.to_base64url().map_err(native_error)
    }

    #[staticmethod]
    pub fn from_bytes(data: Vec<u8>, size: usize) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::BitstringStatusList::from_bytes(data, size)
                .map_err(native_error)?,
        })
    }

    #[staticmethod]
    pub fn from_compressed(data: Vec<u8>, size: usize) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::BitstringStatusList::from_compressed(&data, size)
                .map_err(native_error)?,
        })
    }

    #[staticmethod]
    pub fn from_base64url(encoded: &str, size: usize) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::BitstringStatusList::from_base64url(encoded, size)
                .map_err(native_error)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[pyfunction]
pub fn create_status_list_claim(status_list: &TokenStatusList) -> PyResult<String> {
    let claim = status_list.inner.claim().map_err(native_error)?;
    serde_json::to_string(&claim).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
#[pyo3(signature = (status_list, id, status_purpose="revocation"))]
pub fn create_bitstring_credential_subject(
    status_list: &BitstringStatusList,
    id: &str,
    status_purpose: &str,
) -> PyResult<String> {
    let subject = status_list
        .inner
        .credential_subject(id, status_purpose)
        .map_err(native_error)?;
    serde_json::to_string(&subject).map_err(|error| PyValueError::new_err(error.to_string()))
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
    fn binding_preserves_ietf_normative_vector() {
        let values = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        let mut list = TokenStatusList::new(values.len(), 1).unwrap();
        for (index, value) in values.into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        assert_eq!(list.to_bytes(), vec![0xb9, 0xa3]);
        assert_eq!(list.to_base64url().unwrap(), "eNrbuRgAAhcBXQ");
    }

    #[test]
    fn binding_preserves_multibit_roundtrip() {
        let mut list = TokenStatusList::new(100, 2).unwrap();
        for (index, value) in [0, 1, 2, 3].into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        let restored =
            TokenStatusList::from_base64url(&list.to_base64url().unwrap(), 100, 2).unwrap();
        assert_eq!(restored.to_bytes()[0], 0b1110_0100);
    }

    #[test]
    fn binding_preserves_w3c_multibase_contract() {
        let mut list = BitstringStatusList::new(marty_status::W3C_MIN_STATUS_LIST_BITS).unwrap();
        list.revoke(0).unwrap();
        list.revoke(7).unwrap();
        assert_eq!(list.to_bytes()[0], 0b1000_0001);
        let encoded = list.to_base64url().unwrap();
        assert!(encoded.starts_with('u'));
        let restored = BitstringStatusList::from_base64url(&encoded, list.len()).unwrap();
        assert_eq!(restored.count_revoked(), 2);
    }

    #[test]
    fn binding_rejects_malformed_and_unreasonable_inputs() {
        assert!(TokenStatusList::from_bytes(vec![0], 2, 8).is_err());
        assert!(BitstringStatusList::from_bytes(vec![0], 9).is_err());
        assert!(TokenStatusList::from_compressed(vec![1, 2, 3], 100, 8).is_err());
        assert!(BitstringStatusList::from_base64url("not-multibase", 8).is_err());
        assert!(TokenStatusList::new(marty_status::MAX_STATUS_LIST_ENTRIES + 1, 8).is_err());
    }

    #[test]
    fn binding_restores_persisted_raw_bytes() {
        let mut token = TokenStatusList::from_bytes(vec![0, 7], 2, 8).unwrap();
        assert_eq!(token.get(1).unwrap(), 7);
        token.set(0, 3).unwrap();
        assert_eq!(token.to_bytes(), vec![3, 7]);

        let mut bitstring = BitstringStatusList::from_bytes(vec![0b1000_0000], 8).unwrap();
        assert!(bitstring.get(0).unwrap());
        bitstring.reinstate(0).unwrap();
        assert_eq!(bitstring.to_bytes(), vec![0]);
    }

    #[test]
    fn binding_subject_uses_canonical_privacy_floor() {
        let small = BitstringStatusList::new(marty_status::W3C_MIN_STATUS_LIST_BITS - 1).unwrap();
        assert!(
            create_bitstring_credential_subject(&small, "urn:example:list", "revocation").is_err()
        );
    }
}
