use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pyo3::create_exception!(_marty_rs, DeviceAuthError, PyValueError);

const MAX_DEVICE_AUTH_JSON_BYTES: usize = 64 * 1024;

fn native_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<DeviceAuthError, _>(error.to_string())
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &str, kind: &str) -> PyResult<T> {
    if value.len() > MAX_DEVICE_AUTH_JSON_BYTES {
        return Err(native_error(format!(
            "DEVICE_AUTH.INPUT_TOO_LARGE: {kind} exceeds {MAX_DEVICE_AUTH_JSON_BYTES} bytes"
        )));
    }
    serde_json::from_str(value)
        .map_err(|error| native_error(format!("DEVICE_AUTH.INVALID_JSON: {kind}: {error}")))
}

#[pyfunction]
fn device_public_key_inspect(public_key_der: &str) -> PyResult<String> {
    let result = marty_verification::device_auth::inspect_device_public_key(public_key_der)
        .map_err(native_error)?;
    serde_json::to_string(&result).map_err(native_error)
}

#[pyfunction]
fn device_public_key_validate(public_key_der: &str, public_key_kid: &str) -> PyResult<String> {
    let result =
        marty_verification::device_auth::validate_device_public_key(public_key_der, public_key_kid)
            .map_err(native_error)?;
    serde_json::to_string(&result).map_err(native_error)
}

#[pyfunction]
fn device_build_challenge_message(challenge_json: &str) -> PyResult<String> {
    let challenge: marty_verification::device_auth::DeviceChallengeRecord =
        parse_json(challenge_json, "challenge")?;
    challenge.encoded_message().map_err(native_error)
}

#[pyfunction]
fn device_challenge_is_expired(challenge_json: &str, now: &str) -> PyResult<bool> {
    let challenge: marty_verification::device_auth::DeviceChallengeRecord =
        parse_json(challenge_json, "challenge")?;
    challenge.is_expired_at(now).map_err(native_error)
}

#[pyfunction]
fn device_verify_challenge_signature(
    public_key_der: &str,
    challenge_json: &str,
    signature_b64url: &str,
) -> PyResult<()> {
    let challenge: marty_verification::device_auth::DeviceChallengeRecord =
        parse_json(challenge_json, "challenge")?;
    marty_verification::device_auth::verify_device_challenge_signature(
        public_key_der,
        &challenge,
        signature_b64url,
    )
    .map_err(native_error)
}

#[pyfunction]
fn device_challenge_binding(request_json: &str) -> PyResult<String> {
    let request: marty_verification::device_auth::DeviceChallengeBindingRequest =
        parse_json(request_json, "challenge binding request")?;
    let result = marty_verification::device_auth::evaluate_device_challenge_binding(&request)
        .map_err(native_error)?;
    serde_json::to_string(&result).map_err(native_error)
}

#[pyfunction]
fn device_key_eligibility(request_json: &str) -> PyResult<String> {
    let request: marty_verification::device_auth::DeviceKeyEligibilityRequest =
        parse_json(request_json, "eligibility request")?;
    let result = marty_verification::device_auth::evaluate_device_key_eligibility(&request)
        .map_err(native_error)?;
    serde_json::to_string(&result).map_err(native_error)
}

pub fn register_device_auth_bindings(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("DeviceAuthError", module.py().get_type::<DeviceAuthError>())?;
    module.add_function(wrap_pyfunction!(device_public_key_inspect, module)?)?;
    module.add_function(wrap_pyfunction!(device_public_key_validate, module)?)?;
    module.add_function(wrap_pyfunction!(device_build_challenge_message, module)?)?;
    module.add_function(wrap_pyfunction!(device_challenge_is_expired, module)?)?;
    module.add_function(wrap_pyfunction!(device_verify_challenge_signature, module)?)?;
    module.add_function(wrap_pyfunction!(device_challenge_binding, module)?)?;
    module.add_function(wrap_pyfunction!(device_key_eligibility, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_requests_fail_closed_with_typed_codes() {
        Python::initialize();
        let error = device_key_eligibility("{}").unwrap_err().to_string();
        assert!(error.contains("DEVICE_AUTH.INVALID_JSON"));
        let error = device_public_key_inspect("AA").unwrap_err().to_string();
        assert!(error.contains("DEVICE_AUTH.INVALID_PUBLIC_KEY"));
    }
}
