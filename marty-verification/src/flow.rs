//! Canonical flow lifecycle and graph decisions.
//!
//! Service layers own persistence, clocks, authorization, and side effects.
//! This module is the sole owner of legal lifecycle transitions and deterministic
//! graph traversal decisions.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use thiserror::Error;

const MAX_STEPS: usize = 1_024;
const MAX_TRANSITIONS: usize = 8_192;
const MAX_STEP_ID_BYTES: usize = 128;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FlowError {
    #[error("FLOW.TRANSITION_NOT_ALLOWED: {from} -> {to}")]
    TransitionNotAllowed {
        from: FlowInstanceStatus,
        to: FlowInstanceStatus,
    },
    #[error("FLOW.INVALID_GRAPH: {0}")]
    InvalidGraph(String),
    #[error("FLOW.AMBIGUOUS_TRANSITION: {from_step_id} has multiple {outcome} transitions")]
    AmbiguousTransition {
        from_step_id: String,
        outcome: TransitionOutcome,
    },
    #[error("FLOW.LIMIT_EXCEEDED: {0}")]
    LimitExceeded(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowInstanceStatus {
    Created,
    Pending,
    InProgress,
    AwaitingWallet,
    AwaitingApproval,
    AwaitingEvidence,
    Completed,
    Failed,
    Cancelled,
    Expired,
}

impl std::fmt::Display for FlowInstanceStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        formatter.write_str(value.as_str().ok_or(std::fmt::Error)?)
    }
}

impl FlowInstanceStatus {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Expired
        )
    }

    #[must_use]
    pub const fn can_transition_to(self, target: Self) -> bool {
        use FlowInstanceStatus as S;
        matches!(
            (self, target),
            (S::Created, S::Pending | S::InProgress | S::Cancelled)
                | (S::Pending, S::InProgress | S::Cancelled)
                | (
                    S::InProgress,
                    S::AwaitingWallet
                        | S::AwaitingApproval
                        | S::AwaitingEvidence
                        | S::Completed
                        | S::Failed
                        | S::Cancelled
                        | S::Expired
                )
                | (S::AwaitingWallet, S::InProgress | S::Cancelled | S::Expired)
                | (
                    S::AwaitingApproval,
                    S::InProgress | S::Failed | S::Cancelled
                )
                | (
                    S::AwaitingEvidence,
                    S::InProgress | S::Cancelled | S::Expired
                )
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTransitionRequest {
    pub current: FlowInstanceStatus,
    pub target: FlowInstanceStatus,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTransitionDecision {
    pub prior_state: FlowInstanceStatus,
    pub new_state: FlowInstanceStatus,
    pub terminal: bool,
    pub no_op: bool,
    pub actor: Option<String>,
    pub event: String,
}

/// Evaluate a lifecycle transition without mutating caller-owned state.
pub fn evaluate_transition(
    request: FlowTransitionRequest,
) -> Result<FlowTransitionDecision, FlowError> {
    if request.current == request.target {
        return Ok(FlowTransitionDecision {
            prior_state: request.current,
            new_state: request.target,
            terminal: request.target.is_terminal(),
            no_op: true,
            actor: request.actor,
            event: request
                .event
                .unwrap_or_else(|| format!("{}_to_{}", request.current, request.target)),
        });
    }
    if !request.current.can_transition_to(request.target) {
        return Err(FlowError::TransitionNotAllowed {
            from: request.current,
            to: request.target,
        });
    }
    Ok(FlowTransitionDecision {
        prior_state: request.current,
        new_state: request.target,
        terminal: request.target.is_terminal(),
        no_op: false,
        actor: request.actor,
        event: request
            .event
            .unwrap_or_else(|| format!("{}_to_{}", request.current, request.target)),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionOutcome {
    Success,
    Failure,
    Timeout,
    UserCancel,
    ApprovalGranted,
    ApprovalDenied,
    ConditionMet,
    Always,
    QrScanned,
    TokenExchanged,
    CredentialIssued,
}

impl std::fmt::Display for TransitionOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        formatter.write_str(value.as_str().ok_or(std::fmt::Error)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowGraphStep {
    pub step_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowGraphTransition {
    pub from_step_id: String,
    pub to_step_id: String,
    pub outcome: TransitionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowGraphRequest {
    pub entry_step_id: String,
    pub steps: Vec<FlowGraphStep>,
    #[serde(default)]
    pub transitions: Vec<FlowGraphTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowGraphDecision {
    pub valid: bool,
    pub step_count: usize,
    pub transition_count: usize,
}

fn valid_step_id(value: &str) -> bool {
    if value.is_empty() || value.len() > MAX_STEP_ID_BYTES || !value.is_ascii() {
        return false;
    }
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// Validate a bounded, deterministic, acyclic flow graph.
pub fn validate_graph(request: &FlowGraphRequest) -> Result<FlowGraphDecision, FlowError> {
    if request.steps.is_empty() {
        return Err(FlowError::InvalidGraph(
            "at least one step is required".to_owned(),
        ));
    }
    if request.steps.len() > MAX_STEPS {
        return Err(FlowError::LimitExceeded(format!(
            "graph contains more than {MAX_STEPS} steps"
        )));
    }
    if request.transitions.len() > MAX_TRANSITIONS {
        return Err(FlowError::LimitExceeded(format!(
            "graph contains more than {MAX_TRANSITIONS} transitions"
        )));
    }
    if !valid_step_id(&request.entry_step_id) {
        return Err(FlowError::InvalidGraph(
            "entry_step_id is invalid".to_owned(),
        ));
    }

    let mut step_ids = HashSet::with_capacity(request.steps.len());
    for step in &request.steps {
        if !valid_step_id(&step.step_id) {
            return Err(FlowError::InvalidGraph(format!(
                "invalid step_id: {}",
                step.step_id
            )));
        }
        if !step_ids.insert(step.step_id.as_str()) {
            return Err(FlowError::InvalidGraph(
                "step_id values must be unique".to_owned(),
            ));
        }
    }
    if !step_ids.contains(request.entry_step_id.as_str()) {
        return Err(FlowError::InvalidGraph(
            "entry_step_id must reference a declared step".to_owned(),
        ));
    }

    let mut adjacency: HashMap<&str, Vec<&str>> = request
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), Vec::new()))
        .collect();
    let mut indegree: HashMap<&str, usize> = request
        .steps
        .iter()
        .map(|step| (step.step_id.as_str(), 0))
        .collect();
    let mut decisions = HashSet::with_capacity(request.transitions.len());

    for transition in &request.transitions {
        if !step_ids.contains(transition.from_step_id.as_str())
            || !step_ids.contains(transition.to_step_id.as_str())
        {
            return Err(FlowError::InvalidGraph(
                "transitions must reference declared steps".to_owned(),
            ));
        }
        if !decisions.insert((transition.from_step_id.as_str(), transition.outcome)) {
            return Err(FlowError::AmbiguousTransition {
                from_step_id: transition.from_step_id.clone(),
                outcome: transition.outcome,
            });
        }
        adjacency
            .get_mut(transition.from_step_id.as_str())
            .expect("validated source")
            .push(transition.to_step_id.as_str());
        *indegree
            .get_mut(transition.to_step_id.as_str())
            .expect("validated destination") += 1;
    }

    let mut reachable = HashSet::with_capacity(request.steps.len());
    let mut frontier = VecDeque::from([request.entry_step_id.as_str()]);
    while let Some(step_id) = frontier.pop_front() {
        if !reachable.insert(step_id) {
            continue;
        }
        frontier.extend(adjacency[step_id].iter().copied());
    }
    if reachable.len() != request.steps.len() {
        return Err(FlowError::InvalidGraph(
            "every step must be reachable from entry_step_id".to_owned(),
        ));
    }

    let mut roots: VecDeque<&str> = indegree
        .iter()
        .filter_map(|(step_id, degree)| (*degree == 0).then_some(*step_id))
        .collect();
    let mut visited = 0usize;
    while let Some(step_id) = roots.pop_front() {
        visited += 1;
        for destination in &adjacency[step_id] {
            let degree = indegree
                .get_mut(destination)
                .expect("validated destination");
            *degree -= 1;
            if *degree == 0 {
                roots.push_back(destination);
            }
        }
    }
    if visited != request.steps.len() {
        return Err(FlowError::InvalidGraph(
            "flow graph must be acyclic".to_owned(),
        ));
    }

    Ok(FlowGraphDecision {
        valid: true,
        step_count: request.steps.len(),
        transition_count: request.transitions.len(),
    })
}

/// Select the sole next step for an outcome after validating the whole graph.
pub fn select_next_step(
    request: &FlowGraphRequest,
    current_step_id: &str,
    outcome: TransitionOutcome,
) -> Result<Option<String>, FlowError> {
    validate_graph(request)?;
    if !request
        .steps
        .iter()
        .any(|step| step.step_id == current_step_id)
    {
        return Err(FlowError::InvalidGraph(
            "current_step_id must reference a declared step".to_owned(),
        ));
    }
    Ok(request
        .transitions
        .iter()
        .find(|transition| {
            transition.from_step_id == current_step_id && transition.outcome == outcome
        })
        .map(|transition| transition.to_step_id.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph() -> FlowGraphRequest {
        FlowGraphRequest {
            entry_step_id: "start".to_owned(),
            steps: ["start", "approve", "end"]
                .into_iter()
                .map(|step_id| FlowGraphStep {
                    step_id: step_id.to_owned(),
                })
                .collect(),
            transitions: vec![
                FlowGraphTransition {
                    from_step_id: "start".to_owned(),
                    to_step_id: "approve".to_owned(),
                    outcome: TransitionOutcome::Success,
                },
                FlowGraphTransition {
                    from_step_id: "approve".to_owned(),
                    to_step_id: "end".to_owned(),
                    outcome: TransitionOutcome::ApprovalGranted,
                },
            ],
        }
    }

    #[test]
    fn lifecycle_matches_the_service_contract() {
        let decision = evaluate_transition(FlowTransitionRequest {
            current: FlowInstanceStatus::InProgress,
            target: FlowInstanceStatus::AwaitingWallet,
            actor: Some("wallet".to_owned()),
            event: None,
        })
        .expect("legal transition");
        assert_eq!(decision.event, "in_progress_to_awaiting_wallet");
        assert!(!decision.terminal);
        assert!(!decision.no_op);

        let error = evaluate_transition(FlowTransitionRequest {
            current: FlowInstanceStatus::Completed,
            target: FlowInstanceStatus::InProgress,
            actor: None,
            event: None,
        })
        .expect_err("terminal state must be immutable");
        assert!(error.to_string().starts_with("FLOW.TRANSITION_NOT_ALLOWED"));
    }

    #[test]
    fn shared_vectors_are_byte_stable_across_callers() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/vectors/flow_state.json"))
                .expect("flow fixture");
        for case in fixture["transition_cases"]
            .as_array()
            .expect("transition cases")
        {
            let request: FlowTransitionRequest =
                serde_json::from_value(case["request"].clone()).expect("request");
            let decision = evaluate_transition(request).expect("valid transition");
            assert_eq!(
                serde_json::to_value(decision).expect("decision JSON"),
                case["expected"]
            );
        }
        for request in fixture["invalid_transitions"]
            .as_array()
            .expect("invalid transitions")
        {
            let request: FlowTransitionRequest =
                serde_json::from_value(request.clone()).expect("request");
            assert!(evaluate_transition(request).is_err());
        }
        let graph: FlowGraphRequest =
            serde_json::from_value(fixture["graph"].clone()).expect("graph");
        assert!(validate_graph(&graph).expect("valid graph").valid);
    }

    #[test]
    fn lifecycle_no_op_preserves_existing_behavior() {
        let decision = evaluate_transition(FlowTransitionRequest {
            current: FlowInstanceStatus::Expired,
            target: FlowInstanceStatus::Expired,
            actor: None,
            event: None,
        })
        .expect("same-state transition is a no-op");
        assert!(decision.no_op);
        assert!(decision.terminal);
    }

    #[test]
    fn lifecycle_matrix_is_complete_and_terminal_states_are_immutable() {
        use FlowInstanceStatus as S;
        let statuses = [
            S::Created,
            S::Pending,
            S::InProgress,
            S::AwaitingWallet,
            S::AwaitingApproval,
            S::AwaitingEvidence,
            S::Completed,
            S::Failed,
            S::Cancelled,
            S::Expired,
        ];
        let expected = [
            (S::Created, S::Pending),
            (S::Created, S::InProgress),
            (S::Created, S::Cancelled),
            (S::Pending, S::InProgress),
            (S::Pending, S::Cancelled),
            (S::InProgress, S::AwaitingWallet),
            (S::InProgress, S::AwaitingApproval),
            (S::InProgress, S::AwaitingEvidence),
            (S::InProgress, S::Completed),
            (S::InProgress, S::Failed),
            (S::InProgress, S::Cancelled),
            (S::InProgress, S::Expired),
            (S::AwaitingWallet, S::InProgress),
            (S::AwaitingWallet, S::Cancelled),
            (S::AwaitingWallet, S::Expired),
            (S::AwaitingApproval, S::InProgress),
            (S::AwaitingApproval, S::Failed),
            (S::AwaitingApproval, S::Cancelled),
            (S::AwaitingEvidence, S::InProgress),
            (S::AwaitingEvidence, S::Cancelled),
            (S::AwaitingEvidence, S::Expired),
        ];
        let expected: HashSet<_> = expected.into_iter().collect();
        for current in statuses {
            for target in statuses {
                assert_eq!(
                    current.can_transition_to(target),
                    expected.contains(&(current, target)),
                    "unexpected lifecycle edge {current} -> {target}"
                );
            }
            if current.is_terminal() {
                assert!(!statuses
                    .iter()
                    .copied()
                    .any(|target| current.can_transition_to(target)));
            }
        }
    }

    #[test]
    fn graph_validation_and_selection_are_deterministic() {
        let decision = validate_graph(&graph()).expect("valid graph");
        assert_eq!(decision.step_count, 3);
        assert_eq!(
            select_next_step(&graph(), "approve", TransitionOutcome::ApprovalGranted)
                .expect("selection"),
            Some("end".to_owned())
        );
        assert_eq!(
            select_next_step(&graph(), "approve", TransitionOutcome::Failure)
                .expect("no matching transition"),
            None
        );
    }

    #[test]
    fn malformed_graphs_fail_closed() {
        let mut candidate = graph();
        candidate.transitions.push(FlowGraphTransition {
            from_step_id: "approve".to_owned(),
            to_step_id: "start".to_owned(),
            outcome: TransitionOutcome::Failure,
        });
        assert!(validate_graph(&candidate)
            .expect_err("cycle")
            .to_string()
            .contains("acyclic"));

        let mut candidate = graph();
        candidate.transitions.push(FlowGraphTransition {
            from_step_id: "start".to_owned(),
            to_step_id: "end".to_owned(),
            outcome: TransitionOutcome::Success,
        });
        assert!(matches!(
            validate_graph(&candidate),
            Err(FlowError::AmbiguousTransition { .. })
        ));

        let mut candidate = graph();
        candidate.steps.push(FlowGraphStep {
            step_id: "orphan".to_owned(),
        });
        assert!(validate_graph(&candidate)
            .expect_err("unreachable step")
            .to_string()
            .contains("reachable"));
    }
}
