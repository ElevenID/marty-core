# BLS byte-encoding compatibility port

Upstream bls12_381_plus 0.8.18 archive SHA-256:
`1fa37cf2a8c96054d2dc3d708efe35cc0347014af0d30b86c736b4388ff8491c`.
Original VCS receipt, licenses, pairing algorithms, ciphersuite constants and
public test vectors are retained.

The owned change adapts fixed-width byte-array boundaries to crypto-bigint
0.7.6 through the companion legacy elliptic-curve port. Integer/scalar bridges
use canonical byte encodings shared across targets instead of assuming the
integer backend word width matches the target pointer width. This fixes the
old target-specific conversion ordering and prevents wasm32 out-of-range word
access with the modern backend. ScalarPrimitive and U256/U384/U512 conversions
round-trip the same nontrivial public scalar on native and wasm32; U512
reduction still delegates to the existing BLS reduction. No pairing, field
multiplication, hashing or proof algorithms are replaced.

Five ineffective must_use annotations on trait implementation methods are
removed for current Rust compatibility; inherent method attributes remain.
The previously invalid target_arch="64" branch was never active and is removed
without enabling an additional conversion API.

Six existing BBS signature/proof/tamper tests and five compatibility controls
pass on native x86_64 and wasm32. These are local compatibility controls, not
production demo evidence or official conformance qualification. The consuming
Cargo root must patch both owned packages explicitly and retain its lock.

Upstream trailing whitespace in ancillary files is normalized for Git checks.
