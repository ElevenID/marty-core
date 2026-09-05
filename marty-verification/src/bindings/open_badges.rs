//! Python adapters for open badges.

use pyo3::prelude::*;

#[cfg(feature = "local-key-operations")]
#[pyfunction]
pub(super) fn open_badge_ob2_issue(request_json: &str) -> PyResult<String> {
    crate::open_badges::issue_ob2_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn open_badge_ob2_verify(request_json: &str) -> PyResult<String> {
    crate::open_badges::verify_ob2_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[cfg(feature = "local-key-operations")]
#[pyfunction]
pub(super) fn open_badge_ob3_issue(request_json: &str) -> PyResult<String> {
    crate::open_badges::issue_ob3_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn open_badge_ob3_verify(request_json: &str) -> PyResult<String> {
    crate::open_badges::verify_ob3_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
