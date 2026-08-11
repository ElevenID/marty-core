# Canonical flow decision contract

`marty-verification::flow` is the sole owner of Marty flow-instance lifecycle
legality and deterministic extension-graph decisions.

Service and binding layers may map DTOs, persist decisions, attach timestamps,
authorize callers, and perform side effects. They must not maintain transition
tables, decide whether terminal states can change, validate graph reachability
or cycles, or select a competing next step.

The kernel:

- preserves the existing same-state no-op behavior;
- makes completed, failed, cancelled, and expired states immutable otherwise;
- rejects unknown states, outcomes, and JSON fields;
- rejects oversized, cyclic, unreachable, ambiguous, and malformed graphs;
- returns normalized `FLOW.*` errors; and
- performs no I/O and reads no ambient clock.

Shared vectors live in `tests/vectors/flow_state.json`. A caller cutover is not
complete until its adapter executes those vectors and the old transition/graph
implementation is deleted.
