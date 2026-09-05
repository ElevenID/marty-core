//! Status-list adapters with stable full and compressed-only Python API profiles.
//!
//! Explicit profiles prevent Cargo feature unification from adding raw-byte
//! constructors to consumers that historically did not expose them.

macro_rules! status_profile {
    ($name:ident, [$($token_raw:tt)*], [$($bitstring_raw:tt)*]) => {
        pub mod $name {
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

            $($token_raw)*
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

            $($bitstring_raw)*
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

            pub fn register(parent: &Bound<'_, PyModule>) -> PyResult<()> {
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


        }
    };
}

status_profile!(compressed, [], []);

status_profile!(full, [
    #[staticmethod]
    #[pyo3(signature = (data, size, bits=8))]
    pub fn from_bytes(data: Vec<u8>, size: usize, bits: u8) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::TokenStatusList::from_bytes(data, size, bits)
                .map_err(native_error)?,
        })
    }

], [
    #[staticmethod]
    pub fn from_bytes(data: Vec<u8>, size: usize) -> PyResult<Self> {
        Ok(Self {
            inner: marty_status::BitstringStatusList::from_bytes(data, size)
                .map_err(native_error)?,
        })
    }

]);
