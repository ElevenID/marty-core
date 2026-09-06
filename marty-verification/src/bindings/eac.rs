//! Python adapters for eac.

use super::*;

#[cfg(feature = "csca")]
#[pyclass(name = "NativeEacChipAuthentication")]
pub(super) struct PyNativeEacChipAuthentication {
    algorithm: crate::eac::EacAlgorithm,
    private_key: Option<Vec<u8>>,
}

#[cfg(feature = "csca")]
#[pymethods]
impl PyNativeEacChipAuthentication {
    #[new]
    fn new(algorithm: &str) -> PyResult<Self> {
        Ok(Self {
            algorithm: crate::eac::EacAlgorithm::parse(algorithm).map_err(to_pyerr)?,
            private_key: None,
        })
    }

    fn generate_ephemeral_keypair<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let (private_key, public_key) =
            crate::eac::generate_ephemeral_keypair(self.algorithm).map_err(to_pyerr)?;
        let private_key_der =
            crate::eac::encode_private_key(self.algorithm, &private_key).map_err(to_pyerr)?;
        self.private_key = Some(private_key);
        Ok((
            PyBytes::new(py, &public_key),
            PyBytes::new(py, &private_key_der),
        ))
    }

    fn perform_chip_authentication<'py>(
        &mut self,
        py: Python<'py>,
        chip_public_key: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let private_key = self.private_key.take().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("EAC ephemeral keypair has not been generated")
        })?;
        let shared =
            crate::eac::agree(self.algorithm, &private_key, chip_public_key).map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &shared))
    }
}

#[cfg(feature = "csca")]
#[pyclass(name = "NativeEacSecureMessaging")]
pub(super) struct PyNativeEacSecureMessaging {
    inner: crate::eac::EacSecureMessaging,
    algorithm: String,
}

#[cfg(feature = "csca")]
#[pymethods]
impl PyNativeEacSecureMessaging {
    #[new]
    fn new(shared_secret: &[u8], algorithm: &str) -> PyResult<Self> {
        let parsed = crate::eac::EacAlgorithm::parse(algorithm).map_err(to_pyerr)?;
        Ok(Self {
            inner: crate::eac::EacSecureMessaging::new(shared_secret, parsed).map_err(to_pyerr)?,
            algorithm: algorithm.to_string(),
        })
    }

    fn encrypt_apdu<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let protected = self.inner.encrypt(plaintext).map_err(to_pyerr)?;
        Ok(PyBytes::new(py, &protected))
    }

    fn encrypt_apdu_with_iv<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
        iv: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let protected = self
            .inner
            .encrypt_with_iv(plaintext, iv)
            .map_err(to_pyerr)?;
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

    fn state<'py>(&self, py: Python<'py>) -> PyResult<Py<PyDict>> {
        let output = PyDict::new(py);
        let (mac_key, encryption_key) = self.inner.keys();
        let (send_counter, receive_counter) = self.inner.counters();
        output.set_item("mac_key", PyBytes::new(py, mac_key))?;
        output.set_item("encryption_key", PyBytes::new(py, encryption_key))?;
        output.set_item("send_sequence_counter", send_counter)?;
        output.set_item("receive_sequence_counter", receive_counter)?;
        output.set_item("algorithm", &self.algorithm)?;
        Ok(output.unbind())
    }
}

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn eac_sign_terminal_challenge<'py>(
    py: Python<'py>,
    algorithm: &str,
    private_key_der: &[u8],
    challenge: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = crate::eac::sign_terminal_challenge(
        crate::eac::EacAlgorithm::parse(algorithm).map_err(to_pyerr)?,
        private_key_der,
        challenge,
    )
    .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
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

#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn eac_calculate_mac<'py>(
    py: Python<'py>,
    key: &[u8],
    data: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let mac = crate::eac::calculate_mac(key, data).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &mac))
}
