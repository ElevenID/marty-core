# Offline trust-chain consumer (PKG03 boundary probe)

This independent Cargo project consumes the shared `marty-x509-verification`
kernel directly. It takes DER evidence, one locally approved trust anchor,
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

The package's normal dependency tree excludes `reqwest`, SSI, Flow, Redis,
and issuance crates. The full `marty-verification` crate retains its existing
public chain-validator API through a compatibility facade over the same kernel.
This is a dependency-closure proof for X.509 chain checking only; no complete
credential/presentation profile or network-blocked runtime test is qualified.
