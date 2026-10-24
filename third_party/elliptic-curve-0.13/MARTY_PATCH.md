# Legacy public arithmetic compatibility port

Upstream: RustCrypto elliptic-curve 0.13.8; archive SHA-256
`b5e6043086bf7973472e0c7dff2142ea0b680d30e18d9cc40f267efbf222bd47`.
Original VCS receipt, source, tests and licenses are retained.

This owned port keeps the legacy curve/hash-to-field interface needed by the
BBS verifier while using actual crypto-bigint >=0.7.6 arithmetic. Changes are
limited to Cargo backend selection, explicit legacy trait bounds and choice
conversions, nonzero modulus wrappers and a delegating rand_core 0.6/0.10 adapter.
Uniform sampling remains the maintained backend's variable-time sampler with a
public modulus. No scalar arithmetic, BBS signatures, proof generators,
ciphersuite constants or protocol assertions are replaced. Package versions
are not altered to evade advisory checks. Rust minimum follows the new backend.

The supported production surface is the BBS hash2curve/hazmat graph, not a
replacement for old ECDSA/private-key codecs. Modern curves use elliptic-curve
0.14 separately. Downstream Cargo roots must select this same owned package;
patch tables are not transitive. The consuming root lock is authoritative.

Verification: six existing public BBS signature/proof/tamper tests and five
scalar/encoding/choice/sampling controls pass on native x86_64 and wasm32.
The locked all-feature advisory/yank gate passes without advisory exceptions.
These controls are compatibility evidence, not official conformance results.

Upstream trailing whitespace in ancillary files is normalized for Git checks.
