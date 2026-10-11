# Offline trust-chain consumer (PKG03 boundary probe)

This independent Cargo project consumes `marty-verification` with default
features disabled. It takes DER evidence, one locally approved trust anchor,
and a caller-supplied validation moment. Its four tests exercise valid,
tampered, wrong-trust, and expired certificate chains without Redis, Flow,
issuer services, or Canvas. The tested call path contains no network I/O;
network-blocked execution has not yet been demonstrated.

From this directory, run `cargo test --offline`. This project is a local
dependency-closure proof, not a released library binding or supported product.
Certificate-chain success alone does **not** establish a valid credential or
presentation. In particular, this sample does not check revocation/status,
document signatures, session authentication, replay, or protocol policy.
Those obligations remain with each qualified verifier profile.

Dependency audit caveat: `default-features = false` still resolves `reqwest`
through Core's mandatory `ssi-dids`/`ssi-claims` dependencies. This consumer
proves an application/runtime boundary but **not** a network-client-free build
closure. A dedicated kernel extraction or upstream feature split is needed
before claiming the latter.
