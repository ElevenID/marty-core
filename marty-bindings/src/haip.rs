use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
#[cfg(feature = "ephemeral-session-keys")]
use pyo3::types::PyBytes;

pyo3::create_exception!(_marty_rs, HaipJweError, PyValueError);

fn native_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<HaipJweError, _>(format!("HAIP.JWE_OPERATION_FAILED: {error}"))
}

/// Opaque one-use HAIP response decryption state.
#[pyclass(name = "HaipResponseDecryptionSession")]
#[cfg(feature = "ephemeral-session-keys")]
struct PyHaipResponseDecryptionSession {
    inner: Option<marty_verification::jwk::HaipResponseDecryptionSession>,
}

#[cfg(feature = "ephemeral-session-keys")]
#[pymethods]
impl PyHaipResponseDecryptionSession {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: Some(
                marty_verification::jwk::HaipResponseDecryptionSession::generate()
                    .map_err(native_error)?,
            ),
        })
    }

    fn public_jwk_json(&self) -> PyResult<String> {
        self.inner
            .as_ref()
            .ok_or_else(|| native_error("HAIP session already consumed"))?
            .public_jwk_json()
            .map_err(native_error)
    }

    fn decrypt<'py>(
        &mut self,
        py: Python<'py>,
        compact_jwe: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let session = self
            .inner
            .take()
            .ok_or_else(|| native_error("HAIP session already consumed"))?;
        let plaintext = session.decrypt(compact_jwe).map_err(native_error)?;
        Ok(PyBytes::new(py, &plaintext))
    }
}

/// Validate a HAIP compact-JWE envelope before the caller requests KMS unwrap.
#[pyfunction]
fn haip_validate_response_header(compact_jwe: &str) -> PyResult<String> {
    let header = marty_verification::jwk::validate_haip_response_header(compact_jwe)
        .map_err(native_error)?;
    serde_json::to_string(&header).map_err(native_error)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("HaipJweError", module.py().get_type::<HaipJweError>())?;
    #[cfg(feature = "ephemeral-session-keys")]
    {
        module.add_class::<PyHaipResponseDecryptionSession>()?;
    }
    module.add_function(wrap_pyfunction!(haip_validate_response_header, module)?)?;
    Ok(())
}

#[cfg(all(test, feature = "ephemeral-session-keys"))]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_binding_contract() {
        Python::initialize();
        let mut session = PyHaipResponseDecryptionSession::new().unwrap();
        let public_json = session.public_jwk_json().unwrap();
        let public = marty_verification::jwk::Jwk::from_json(&public_json).unwrap();
        let compact = marty_verification::jwk::jwe_encrypt_direct(
            b"{\"vp_token\":\"fixture\"}",
            &public,
            "A256GCM",
        )
        .unwrap();
        let header: serde_json::Value =
            serde_json::from_str(&haip_validate_response_header(&compact).unwrap()).unwrap();
        assert_eq!(header["alg"], "ECDH-ES");
        assert_eq!(header["enc"], "A256GCM");

        Python::attach(|py| {
            let plaintext = session.decrypt(py, &compact).unwrap();
            assert_eq!(plaintext.as_bytes(), b"{\"vp_token\":\"fixture\"}");
            assert!(session.decrypt(py, &compact).is_err());
        });
        assert!(session.public_jwk_json().is_err());
    }

    #[test]
    fn malformed_jwe_uses_typed_fail_closed_error() {
        Python::initialize();
        let mut session = PyHaipResponseDecryptionSession::new().unwrap();
        Python::attach(|py| {
            let error = session.decrypt(py, "not-a-jwe").unwrap_err();
            assert!(error.to_string().contains("HAIP.JWE_OPERATION_FAILED"));
        });
        let error = haip_validate_response_header("not-a-jwe").unwrap_err();
        assert!(error.to_string().contains("HAIP.JWE_OPERATION_FAILED"));
    }
}
