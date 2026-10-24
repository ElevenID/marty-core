//! Python adapters for open badges.

use chrono::{DateTime, Utc};
use pyo3::prelude::*;

#[pyfunction]
pub(super) fn open_badge_ob2_verify(request_json: &str) -> PyResult<String> {
    crate::open_badges::verify_ob2_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn open_badge_ob3_verify(request_json: &str) -> PyResult<String> {
    crate::open_badges::verify_ob3_json(request_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}

#[pyfunction]
pub(super) fn open_badge_ob3_verify_at(
    request_json: &str,
    evaluation_time: &str,
) -> PyResult<String> {
    let evaluation_time = DateTime::parse_from_rfc3339(evaluation_time)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(
                "evaluation_time must be RFC 3339 with an explicit offset",
            )
        })?;
    crate::open_badges::verify_ob3_json_at(request_json, evaluation_time)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
}
