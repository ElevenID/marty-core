use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::IntoPyObjectExt;

/// Convert JSON without passing through text, preserving signed and unsigned integers.
pub fn json_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    use serde_json::Value;

    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(value) => Ok(value.into_py_any(py)?),
        Value::Number(value) => {
            if let Some(integer) = value.as_i64() {
                Ok(integer.into_py_any(py)?)
            } else if let Some(unsigned) = value.as_u64() {
                Ok(unsigned.into_py_any(py)?)
            } else if let Some(float) = value.as_f64() {
                Ok(float.into_py_any(py)?)
            } else {
                Err(pyo3::exceptions::PyValueError::new_err(
                    "Invalid JSON number",
                ))
            }
        }
        Value::String(value) => Ok(value.into_py_any(py)?),
        Value::Array(values) => {
            let result = pyo3::types::PyList::empty(py);
            for value in values {
                result.append(json_to_python(py, value)?)?;
            }
            Ok(result.into())
        }
        Value::Object(values) => {
            let result = PyDict::new(py);
            for (key, value) in values {
                result.set_item(key, json_to_python(py, value)?)?;
            }
            Ok(result.into())
        }
    }
}
