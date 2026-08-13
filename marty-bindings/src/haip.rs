use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pyo3::create_exception!(_marty_rs, HaipJweError, PyValueError);

fn native_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<HaipJweError, _>(format!("HAIP.JWE_OPERATION_FAILED: {error}"))
}

/// Generate public and private P-256 JWK JSON for one HAIP response flow.
#[pyfunction]
fn haip_generate_response_encryption_key() -> PyResult<(String, String)> {
    marty_verification::jwk::generate_haip_response_encryption_jwk_pair().map_err(native_error)
}

/// Validate a HAIP compact-JWE envelope before the caller requests KMS unwrap.
#[pyfunction]
fn haip_validate_response_header(compact_jwe: &str) -> PyResult<String> {
    let header = marty_verification::jwk::validate_haip_response_header(compact_jwe)
        .map_err(native_error)?;
    serde_json::to_string(&header).map_err(native_error)
}

/// Decrypt a bounded ECDH-ES compact JWE with a private P-256 JWK JSON value.
#[pyfunction]
fn haip_decrypt_response<'py>(
    py: Python<'py>,
    compact_jwe: &str,
    private_jwk_json: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let plaintext = marty_verification::jwk::decrypt_haip_response(compact_jwe, private_jwk_json)
        .map_err(native_error)?;
    Ok(PyBytes::new(py, &plaintext))
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("HaipJweError", module.py().get_type::<HaipJweError>())?;
    module.add_function(wrap_pyfunction!(
        haip_generate_response_encryption_key,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(haip_validate_response_header, module)?)?;
    module.add_function(wrap_pyfunction!(haip_decrypt_response, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_round_trip_through_binding_contract() {
        Python::initialize();
        let (public_json, private_json) = haip_generate_response_encryption_key().unwrap();
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
            let plaintext = haip_decrypt_response(py, &compact, &private_json).unwrap();
            assert_eq!(plaintext.as_bytes(), b"{\"vp_token\":\"fixture\"}");
        });
    }

    #[test]
    fn malformed_jwe_uses_typed_fail_closed_error() {
        Python::initialize();
        let (_, private_json) = haip_generate_response_encryption_key().unwrap();
        Python::attach(|py| {
            let error = haip_decrypt_response(py, "not-a-jwe", &private_json).unwrap_err();
            assert!(error.to_string().contains("HAIP.JWE_OPERATION_FAILED"));
        });
        let error = haip_validate_response_header("not-a-jwe").unwrap_err();
        assert!(error.to_string().contains("HAIP.JWE_OPERATION_FAILED"));
    }
}
