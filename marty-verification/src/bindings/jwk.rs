//! Python adapters for jwk.

use super::to_pyerr;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

// ============================================================================
// JWK/JWS/JWE Bindings
// ============================================================================

/// Python wrapper for JWK.
#[cfg(feature = "local-key-operations")]
#[pyclass(name = "Jwk", from_py_object)]
#[derive(Clone)]
pub struct PyJwk {
    inner: crate::jwk::Jwk,
}

#[cfg(feature = "local-key-operations")]
#[pymethods]
impl PyJwk {
    /// Get the key type.
    #[getter]
    fn kty(&self) -> String {
        self.inner.kty.clone()
    }

    /// Get the curve (for EC/OKP keys).
    #[getter]
    fn crv(&self) -> Option<String> {
        self.inner.crv.clone()
    }

    /// Get the key ID.
    #[getter]
    fn kid(&self) -> Option<String> {
        self.inner.kid.clone()
    }

    /// Set the key ID.
    #[setter]
    fn set_kid(&mut self, kid: Option<String>) {
        self.inner.kid = kid;
    }

    /// Get the algorithm.
    #[getter]
    fn alg(&self) -> Option<String> {
        self.inner.alg.clone()
    }

    /// Set the algorithm.
    #[setter]
    fn set_alg(&mut self, alg: Option<String>) {
        self.inner.alg = alg;
    }

    /// Check if this is a private key.
    fn is_private(&self) -> bool {
        self.inner.is_private()
    }

    /// Check if this is a symmetric key.
    fn is_symmetric(&self) -> bool {
        self.inner.is_symmetric()
    }

    /// Get the public key portion.
    fn to_public(&self) -> Self {
        Self {
            inner: self.inner.to_public(),
        }
    }

    /// Serialize to JSON.
    fn to_json(&self) -> PyResult<String> {
        self.inner.to_json().map_err(to_pyerr)
    }

    /// Parse from JSON.
    #[staticmethod]
    fn from_json(json: &str) -> PyResult<Self> {
        let inner = crate::jwk::Jwk::from_json(json).map_err(to_pyerr)?;
        Ok(Self { inner })
    }

    /// Compute the thumbprint.
    fn thumbprint(&self) -> PyResult<String> {
        self.inner.thumbprint().map_err(to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!(
            "Jwk(kty='{}', crv={:?}, kid={:?})",
            self.inner.kty, self.inner.crv, self.inner.kid
        )
    }
}

/// Generate a JWK of the specified type.
#[cfg(feature = "local-key-operations")]
#[pyfunction]
pub(super) fn jwk_generate(key_type: &str) -> PyResult<PyJwk> {
    let inner = match key_type.to_lowercase().as_str() {
        "ec_p256" | "p256" | "es256" => crate::jwk::generate_ec_p256(),
        "ec_p384" | "p384" | "es384" => crate::jwk::generate_ec_p384(),
        "ed25519" | "eddsa" => crate::jwk::generate_ed25519(),
        "x25519" => crate::jwk::generate_x25519(),
        "oct" | "symmetric" => crate::jwk::generate_symmetric(32),
        _ => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown key type: {}. Use 'p256', 'p384', 'ed25519', 'x25519', or 'oct'",
                key_type
            )))
        }
    }
    .map_err(to_pyerr)?;

    Ok(PyJwk { inner })
}

/// Sign data and create a JWS.
#[cfg(feature = "local-key-operations")]
#[pyfunction]
pub(super) fn jws_sign(payload: &[u8], key: &PyJwk, algorithm: &str) -> PyResult<String> {
    let header = crate::jwk::JwsHeader::new(algorithm);
    crate::jwk::jws_sign(&header, payload, &key.inner).map_err(to_pyerr)
}

/// Verify a JWS and return the payload.
#[cfg(feature = "local-key-operations")]
#[pyfunction]
pub(super) fn jws_verify<'py>(
    py: Python<'py>,
    jws: &str,
    key: &PyJwk,
) -> PyResult<Bound<'py, PyBytes>> {
    let (_, payload) = crate::jwk::jws_verify(jws, &key.inner).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &payload))
}

/// Encrypt data and create a JWE.
#[cfg(all(feature = "local-key-operations", feature = "ephemeral-session-keys"))]
#[pyfunction]
pub(super) fn jwe_encrypt(
    plaintext: &[u8],
    recipient_key: &PyJwk,
    encryption: &str,
) -> PyResult<String> {
    crate::jwk::jwe_encrypt_direct(plaintext, &recipient_key.inner, encryption).map_err(to_pyerr)
}

/// Decrypt a JWE.
#[cfg(all(feature = "local-key-operations", feature = "ephemeral-session-keys"))]
#[pyfunction]
pub(super) fn jwe_decrypt<'py>(
    py: Python<'py>,
    jwe: &str,
    key: &PyJwk,
) -> PyResult<Bound<'py, PyBytes>> {
    let plaintext = crate::jwk::jwe_decrypt(jwe, &key.inner).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &plaintext))
}
