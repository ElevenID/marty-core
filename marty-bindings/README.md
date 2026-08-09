# marty-bindings

Python bindings for marty-core Rust crates via PyO3.

The `verify_vcdm_data_integrity(request_json)` API verifies W3C VCDM v2
`eddsa-rdfc-2022` credentials and presentations through Marty's Rust
cryptographic implementation. Presentation requests must supply
`expected_challenge` and `expected_domain`; embedded credentials are verified
independently from the outer presentation proof.
