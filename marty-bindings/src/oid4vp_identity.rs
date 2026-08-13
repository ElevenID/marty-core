use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pyo3::create_exception!(_marty_rs, Oid4vpIdentityError, PyValueError);

fn native_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<Oid4vpIdentityError, _>(error.to_string())
}

fn x509_hash_client_identity_impl(
    certificate_bundle_pem: &str,
    public_jwk_json: &str,
) -> Result<String, String> {
    let public_jwk = marty_verification::jwk::Jwk::from_json(public_jwk_json)
        .map_err(|error| format!("OID4VP.X509_PUBLIC_JWK_INVALID: {error}"))?;
    let identity =
        marty_verification::oid4vp::x509_hash_client_identity(certificate_bundle_pem, &public_jwk)
            .map_err(|error| error.to_string())?;
    serde_json::to_string(&identity)
        .map_err(|error| format!("OID4VP.X509_SERIALIZATION_FAILED: {error}"))
}

/// Build the canonical OID4VP `x509_hash` client identifier and `x5c` header.
#[pyfunction]
fn oid4vp_x509_hash_client_identity(
    certificate_bundle_pem: &str,
    public_jwk_json: &str,
) -> PyResult<String> {
    x509_hash_client_identity_impl(certificate_bundle_pem, public_jwk_json).map_err(native_error)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "Oid4vpIdentityError",
        module.py().get_type::<Oid4vpIdentityError>(),
    )?;
    module.add_function(wrap_pyfunction!(oid4vp_x509_hash_client_identity, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_inputs_return_typed_codes() {
        let error = x509_hash_client_identity_impl("not pem", r#"{"kty":"EC"}"#)
            .expect_err("missing certificate must fail");
        assert!(error.contains("OID4VP.X509_CERTIFICATE_MISSING"));
    }
}
