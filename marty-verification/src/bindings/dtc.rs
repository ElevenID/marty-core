//! Python adapters for dtc.

use super::*;
use crate::dtc;

#[pyfunction]
pub(super) fn dtc_create(request_json: &str) -> PyResult<String> {
    dtc::create_dtc_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn dtc_prepare_signing(dtc_json: &str) -> PyResult<String> {
    dtc::prepare_dtc_signing_json(dtc_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn dtc_assemble_signature(signature_envelope_json: &str) -> PyResult<String> {
    dtc::assemble_dtc_signature_json(signature_envelope_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn dtc_sign(dtc_json: &str) -> PyResult<String> {
    dtc::sign_dtc_json(dtc_json).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn dtc_verify(dtc_json: &str) -> PyResult<String> {
    dtc::verify_dtc_json(dtc_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
