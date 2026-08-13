use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pyo3::create_exception!(_marty_rs, SiopVerificationError, PyValueError);

fn native_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<SiopVerificationError, _>(error.to_string())
}

fn verify_jwk_id_token_impl(id_token: &str) -> Result<String, String> {
    let result = marty_oid4vci::siop::verify_jwk_thumbprint_id_token(id_token)
        .map_err(|error| error.to_string())?;
    serde_json::to_string(&result).map_err(|error| format!("SIOP.SERIALIZATION_FAILED: {error}"))
}

#[pyfunction]
fn siop_verify_jwk_id_token(id_token: &str) -> PyResult<String> {
    verify_jwk_id_token_impl(id_token).map_err(native_error)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "SiopVerificationError",
        module.py().get_type::<SiopVerificationError>(),
    )?;
    module.add_function(wrap_pyfunction!(siop_verify_jwk_id_token, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_input_returns_typed_code() {
        assert!(verify_jwk_id_token_impl("not-a-token")
            .unwrap_err()
            .contains("SIOP.ID_TOKEN_MALFORMED"));
    }
}
