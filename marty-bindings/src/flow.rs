use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pyo3::create_exception!(_marty_rs, FlowEvaluationError, PyValueError);

const MAX_FLOW_JSON_BYTES: usize = 512 * 1024;

fn native_error(error: impl std::fmt::Display) -> PyErr {
    PyErr::new::<FlowEvaluationError, _>(error.to_string())
}

fn parse_json<T: serde::de::DeserializeOwned>(value: &str, kind: &str) -> PyResult<T> {
    if value.len() > MAX_FLOW_JSON_BYTES {
        return Err(native_error(format!(
            "FLOW.LIMIT_EXCEEDED: {kind} exceeds {MAX_FLOW_JSON_BYTES} bytes"
        )));
    }
    serde_json::from_str(value)
        .map_err(|error| native_error(format!("FLOW.INVALID_REQUEST: {kind}: {error}")))
}

fn serialize_json<T: serde::Serialize>(value: &T) -> PyResult<String> {
    serde_json::to_string(value)
        .map_err(|error| native_error(format!("FLOW.SERIALIZATION_FAILED: {error}")))
}

#[pyfunction]
fn flow_evaluate_transition(request_json: &str) -> PyResult<String> {
    let request: marty_verification::flow::FlowTransitionRequest =
        parse_json(request_json, "transition request")?;
    let decision = marty_verification::flow::evaluate_transition(request).map_err(native_error)?;
    serialize_json(&decision)
}

#[pyfunction]
fn flow_validate_graph(request_json: &str) -> PyResult<String> {
    let request: marty_verification::flow::FlowGraphRequest =
        parse_json(request_json, "graph request")?;
    let decision = marty_verification::flow::validate_graph(&request).map_err(native_error)?;
    serialize_json(&decision)
}

#[pyfunction]
fn flow_select_next_step(
    request_json: &str,
    current_step_id: &str,
    outcome: &str,
) -> PyResult<Option<String>> {
    let request: marty_verification::flow::FlowGraphRequest =
        parse_json(request_json, "graph request")?;
    let outcome: marty_verification::flow::TransitionOutcome =
        serde_json::from_value(serde_json::Value::String(outcome.to_owned()))
            .map_err(|error| native_error(format!("FLOW.INVALID_REQUEST: outcome: {error}")))?;
    marty_verification::flow::select_next_step(&request, current_step_id, outcome)
        .map_err(native_error)
}

pub fn register_flow_bindings(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add(
        "FlowEvaluationError",
        module.py().get_type::<FlowEvaluationError>(),
    )?;
    module.add_function(wrap_pyfunction!(flow_evaluate_transition, module)?)?;
    module.add_function(wrap_pyfunction!(flow_validate_graph, module)?)?;
    module.add_function(wrap_pyfunction!(flow_select_next_step, module)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_invalid_requests_fail_closed_with_typed_codes() {
        Python::initialize();
        let error = flow_evaluate_transition("{}").unwrap_err().to_string();
        assert!(error.contains("FLOW.INVALID_REQUEST"));

        let request = serde_json::json!({
            "current": "completed",
            "target": "in_progress"
        });
        let error = flow_evaluate_transition(&request.to_string())
            .unwrap_err()
            .to_string();
        assert!(error.contains("FLOW.TRANSITION_NOT_ALLOWED"));
    }
}
