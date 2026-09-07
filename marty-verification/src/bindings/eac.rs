//! Python adapters for eac.

use super::to_pyerr;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
#[cfg(feature = "ephemeral-session-keys")]
use pyo3::types::PyDict;

// ============================================================================
// EAC Bindings
// ============================================================================

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pyclass(name = "NativeEacChipAuthentication")]
pub(super) struct PyNativeEacChipAuthentication {
    algorithm: crate::eac::EacAlgorithm,
    algorithm_name: String,
    handshake: Option<crate::eac::EacHandshake>,
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
impl PyNativeEacChipAuthentication {}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
impl Drop for PyNativeEacChipAuthentication {
    fn drop(&mut self) {}
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pymethods]
impl PyNativeEacChipAuthentication {
    #[new]
    fn new(algorithm: &str) -> PyResult<Self> {
        Ok(Self {
            algorithm: crate::eac::EacAlgorithm::parse(algorithm).map_err(to_pyerr)?,
            algorithm_name: algorithm.to_string(),
            handshake: None,
        })
    }

    fn generate_ephemeral_public_key<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let handshake = crate::eac::EacHandshake::begin(self.algorithm).map_err(to_pyerr)?;
        let public_key = PyBytes::new(py, handshake.public_key());
        self.handshake = Some(handshake);
        Ok(public_key)
    }

    fn establish_secure_messaging(
        &mut self,
        chip_public_key: &[u8],
    ) -> PyResult<PyNativeEacSecureMessaging> {
        let handshake = self.handshake.take().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("EAC ephemeral keypair has not been generated")
        })?;
        let inner = handshake.complete(chip_public_key).map_err(to_pyerr)?;
        Ok(PyNativeEacSecureMessaging {
            inner,
            algorithm: self.algorithm_name.clone(),
        })
    }
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pyclass(name = "NativeEacSecureMessaging")]
pub(super) struct PyNativeEacSecureMessaging {
    inner: crate::eac::EacSecureMessaging,
    algorithm: String,
}

#[cfg(all(feature = "csca", feature = "ephemeral-session-keys"))]
#[pymethods]
impl PyNativeEacSecureMessaging {
    fn encrypt_apdu<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let protected = self.inner.encrypt(plaintext).map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &protected))
    }

    fn decrypt_apdu<'py>(
        &mut self,
        py: Python<'py>,
        protected: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let plaintext = self.inner.decrypt(protected).map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &plaintext))
    }

    fn status<'py>(&self, py: Python<'py>) -> PyResult<Py<PyDict>> {
        let output = PyDict::new(py);
        let (send_counter, receive_counter) = self.inner.counters();
        output.set_item("send_sequence_counter", send_counter)?;
        output.set_item("receive_sequence_counter", receive_counter)?;
        output.set_item("algorithm", &self.algorithm)?;
        Ok(output.unbind())
    }
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn eac_verify_certificate_signature(
    algorithm: &str,
    signer_public_key_der: &[u8],
    certificate_body: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    crate::eac::verify_certificate_signature(
        crate::eac::EacAlgorithm::parse(algorithm).map_err(to_pyerr)?,
        signer_public_key_der,
        certificate_body,
        signature,
    )
    .map_err(to_pyerr)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn eac_certificate_fingerprint(data: &[u8]) -> String {
    crate::eac::certificate_fingerprint(data)
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn eac_serialize_certificate<'py>(
    py: Python<'py>,
    holder: &str,
    authority: &str,
    authorization: u32,
    effective: &str,
    expiration: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let encoded = crate::eac::serialize_certificate_metadata(
        holder,
        authority,
        authorization,
        effective,
        expiration,
    )
    .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &encoded))
}
