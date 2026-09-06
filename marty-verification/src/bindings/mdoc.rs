//! Python adapters for mdoc.

use super::*;

/// Python wrapper for parsed DeviceResponse.
#[pyclass(name = "DeviceResponse", from_py_object)]
#[derive(Clone)]
pub struct PyDeviceResponse {
    #[pyo3(get)]
    pub version: String,
    #[pyo3(get)]
    pub status: u64,
    inner: crate::mdoc::DeviceResponse,
}

#[pymethods]
impl PyDeviceResponse {
    /// Get the number of documents in the response.
    fn document_count(&self) -> usize {
        self.inner.documents.len()
    }

    /// Get list of document types (doc_type values).
    fn document_types(&self) -> Vec<String> {
        self.inner
            .documents
            .iter()
            .map(|d| d.doc_type.clone())
            .collect()
    }

    /// Get mDL fields from the first org.iso.18013.5.1 namespace.
    fn get_mdl_fields(&self) -> PyResult<std::collections::HashMap<String, String>> {
        let fields = self.inner.get_mdl_fields().map_err(to_pyerr)?;
        // Convert Vec<(String, Value)> to HashMap<String, String>
        let map: std::collections::HashMap<String, String> = fields
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        Ok(map)
    }

    /// Get a specific mDL element by identifier.
    fn get_mdl_element(&self, element_id: &str) -> Option<String> {
        self.inner
            .get_mdl_element(element_id)
            .map(|v| v.to_string())
    }

    /// Check if subject is over 21.
    fn is_age_over_21(&self) -> Option<bool> {
        self.inner.is_age_over_21()
    }

    /// Get family name.
    fn get_family_name(&self) -> Option<String> {
        self.inner.get_family_name()
    }

    /// Get given name.
    fn get_given_name(&self) -> Option<String> {
        self.inner.get_given_name()
    }

    fn __repr__(&self) -> String {
        format!(
            "DeviceResponse(version='{}', status={}, documents={})",
            self.version,
            self.status,
            self.inner.documents.len()
        )
    }

    fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("version", self.version.clone())?;
        dict.set_item("status", self.status)?;
        dict.set_item("document_count", self.inner.documents.len())?;
        dict.set_item("document_types", self.document_types())?;

        // Add mDL fields if available
        if let Ok(fields) = self.get_mdl_fields() {
            let fields_dict = PyDict::new(py);
            for (k, v) in fields {
                fields_dict.set_item(k, v)?;
            }
            dict.set_item("mdl_fields", fields_dict)?;
        }

        Ok(dict.into())
    }
}

/// Parse a CBOR-encoded DeviceResponse.
///
/// Args:
///     cbor_bytes: CBOR-encoded DeviceResponse bytes
///
/// Returns:
///     DeviceResponse with parsed information
#[pyfunction]
pub(super) fn parse_device_response(cbor_bytes: &[u8]) -> PyResult<PyDeviceResponse> {
    let response = crate::mdoc::DeviceResponse::from_cbor(cbor_bytes).map_err(to_pyerr)?;

    Ok(PyDeviceResponse {
        version: response.version.clone(),
        status: response.status,
        inner: response,
    })
}
