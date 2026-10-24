# Offline chain headless boundary probe

This independent Cargo executable accepts exactly one JSON document on stdin
and writes one JSON result on stdout. It directly calls
`marty-x509-verification` with default features disabled. It is a stateless,
chain-only integration probe, not a credential or presentation verifier and
not a supported product interface.

Input fields are `chain_der_base64` (array ordered leaf to root, 1-8 DER
certificates), `trust_anchor_der_base64` (one caller-approved DER certificate), and
`validation_time` (RFC 3339 timestamp). Standard padded base64 is required.
The request is capped at 1 MiB; each decoded certificate is capped at 64 KiB.
No implicit clock, platform trust store, network fetch, or service is used.

Output fields are `valid`, `code`, `errors`, and `warnings`. Exit status is 0
for a valid chain, 1 for a well-formed but invalid chain, and 2 for invalid
input. The verifier kernel owns all certificate parsing and trust decisions.

Run from this directory with `cargo +1.97.1 test --locked`. CI explicitly tests
this independent example; the root workspace commands do not include it.
These tests do not qualify network-isolated execution of this port.

As an independent workspace, this example does not inherit Core's root Cargo
patches. Its manifest explicitly selects the same reviewed verification-only
ECDSA fork as accepted Core; its separate lockfile and advisory gate must be
qualified whenever that dependency graph changes.

The sample does not check revocation, credential signatures, replay, protocol
policy, or the caller's authority to designate a trust anchor. Its success
must not be presented as a verified credential.
