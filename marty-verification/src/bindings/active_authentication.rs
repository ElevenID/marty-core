//! Python adapters for active authentication.

use super::*;

/// Generate a native Active Authentication challenge.
#[cfg(feature = "csca")]
#[pyfunction]
#[pyo3(signature = (key_size_bits=128, hash_algorithm="SHA-256"))]
pub(super) fn active_authentication_generate_challenge<'py>(
    py: Python<'py>,
    key_size_bits: usize,
    hash_algorithm: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    parse_iso9796_hash_algorithm(hash_algorithm)?;
    let challenge =
        crate::active_authentication::generate_challenge(key_size_bits).map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &challenge))
}

/// Build an INTERNAL AUTHENTICATE command APDU.
#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn active_authentication_build_apdu<'py>(
    py: Python<'py>,
    challenge: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let command = crate::active_authentication::build_internal_authenticate_apdu(challenge)
        .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &command))
}

/// Parse a successful INTERNAL AUTHENTICATE response APDU.
#[cfg(feature = "csca")]
#[pyfunction]
pub(super) fn active_authentication_parse_response<'py>(
    py: Python<'py>,
    response: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let signature = crate::active_authentication::parse_internal_authenticate_response(response)
        .map_err(to_pyerr)?;
    Ok(PyBytes::new(py, &signature))
}

/// Verify an Active Authentication response against the exact challenge.
#[cfg(feature = "csca")]
#[pyfunction]
#[pyo3(signature = (public_key_der, challenge, signature, hash_algorithm="SHA-256"))]
pub(super) fn active_authentication_verify<'py>(
    py: Python<'py>,
    public_key_der: &[u8],
    challenge: &[u8],
    signature: &[u8],
    hash_algorithm: &str,
) -> PyResult<Py<PyDict>> {
    let result = crate::active_authentication::verify_challenge(
        public_key_der,
        challenge,
        signature,
        parse_iso9796_hash_algorithm(hash_algorithm)?,
    )
    .map_err(to_pyerr)?;
    let output = PyDict::new(py);
    output.set_item("is_valid", result.is_valid)?;
    output.set_item(
        "recovered_message",
        result
            .recovered_message
            .as_deref()
            .map(|value| PyBytes::new(py, value)),
    )?;
    Ok(output.unbind())
}
