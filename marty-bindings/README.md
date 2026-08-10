# marty-bindings

Python bindings for marty-core Rust crates via PyO3.

The `verify_vcdm_data_integrity(request_json)` API verifies W3C VCDM v2
`eddsa-rdfc-2022` credentials and presentations through Marty's Rust
cryptographic implementation. Presentation requests must supply
`expected_challenge` and `expected_domain`; embedded credentials are verified
independently from the outer presentation proof.

The `verify_presentation_structure(verifier_id, response_uri,
definition_json, submission_json)` API exposes the OID4VP descriptor-mapping
check already implemented by `marty-oid4vci`. It returns scoped low-level
evidence: callers must inspect `check_valid`, `scope`, and `evidence`; the
result deliberately does not claim a final credential decision.
