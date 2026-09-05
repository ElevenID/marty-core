//! Python adapters for trust sync.

use pyo3::prelude::*;

pub(super) fn trust_sync_pyerr(error: crate::trust_sync::TrustSyncError) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(error.to_string())
}

#[pyfunction]
#[pyo3(signature = (framework=None))]
pub(super) fn trust_registry_catalog_json(framework: Option<&str>) -> PyResult<String> {
    crate::trust_sync::registry_catalog_json(framework).map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_behavior_fixture_json() -> &'static str {
    crate::trust_sync::behavior_fixture_json()
}

#[pyfunction]
#[pyo3(signature = (registry_type, now_rfc3339, requested_formats_json=None, sync_interval_hours=None))]
pub(super) fn trust_registry_import_decision_json(
    registry_type: &str,
    now_rfc3339: &str,
    requested_formats_json: Option<&str>,
    sync_interval_hours: Option<u16>,
) -> PyResult<String> {
    crate::trust_sync::import_decision_json(
        registry_type,
        requested_formats_json,
        sync_interval_hours,
        now_rfc3339,
    )
    .map_err(trust_sync_pyerr)
}

#[pyfunction]
#[pyo3(signature = (since=None))]
pub(super) fn trust_registry_public_sync_query_json(since: Option<&str>) -> PyResult<String> {
    crate::trust_sync::public_sync_query_json(since).map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_public_sync_metadata_json(
    current_sequence: u64,
    generated_at_rfc3339: &str,
) -> PyResult<String> {
    crate::trust_sync::public_sync_metadata_json(current_sequence, generated_at_rfc3339)
        .map_err(trust_sync_pyerr)
}

#[pyfunction]
#[pyo3(signature = (refresh_interval_hours, now_rfc3339, last_synchronized_at_rfc3339=None))]
pub(super) fn trust_registry_sync_is_due_json(
    refresh_interval_hours: u16,
    now_rfc3339: &str,
    last_synchronized_at_rfc3339: Option<&str>,
) -> PyResult<String> {
    crate::trust_sync::sync_is_due_json(
        last_synchronized_at_rfc3339,
        refresh_interval_hours,
        now_rfc3339,
    )
    .map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_validate_url(url: &str) -> PyResult<String> {
    crate::trust_sync::validate_registry_url(url).map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_destination_decision_json(
    url: &str,
    addresses_json: &str,
    private_host_allowlist: &str,
) -> PyResult<String> {
    crate::trust_sync::destination_decision_json(url, addresses_json, private_host_allowlist)
        .map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_private_host_allowlist_json(configured: &str) -> PyResult<String> {
    crate::trust_sync::private_host_allowlist_json(configured).map_err(trust_sync_pyerr)
}

#[pyfunction]
#[pyo3(signature = (url, token=None, address=None))]
pub(super) fn trust_registry_request_plan_json(
    url: &str,
    token: Option<&str>,
    address: Option<&str>,
) -> PyResult<String> {
    crate::trust_sync::request_plan_json(url, token, address).map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_validate_feed_json(feed_json: &str) -> PyResult<String> {
    crate::trust_sync::validate_feed_json(feed_json).map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_validate_state_json(state_json: &str) -> PyResult<String> {
    crate::trust_sync::validate_state_json(state_json).map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_evaluate_pages_json(
    previous_state_json: &str,
    pages_json: &str,
    now_rfc3339: &str,
) -> PyResult<String> {
    crate::trust_sync::evaluate_pages_json(previous_state_json, pages_json, now_rfc3339)
        .map_err(trust_sync_pyerr)
}

#[pyfunction]
pub(super) fn trust_registry_revalidate_state_json(
    state_json: &str,
    now_rfc3339: &str,
) -> PyResult<String> {
    crate::trust_sync::revalidate_state_json(state_json, now_rfc3339).map_err(trust_sync_pyerr)
}
