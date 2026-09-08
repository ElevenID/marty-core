# Cryptography audit follow-ups

Status: implementation and executable regression matrix pass; clean independent re-review and integration CI pending

Recorded: 2026-09-07

Scope owner: ElevenID

No upstream push or pull request is authorized by this work. Imported
third-party compliance tests are unchanged. Public-fork commits are deliberately
small and independently cherry-pickable; Marty commits may be larger when that
improves delivery speed without weakening review.

## Recovery checkpoint

The exact implementation heads entering final review are:

| Repository | Review head | Work completed |
| --- | --- | --- |
| `isomdl-elevenid` | `aefcab7ce18f5fab58249a1ecbe47e7f3287785a` | single-owner and zeroizing session secrets, redacted diagnostics, verification-only default, removal of production local mdoc signing, transactional authenticated-decryption counters, cleanup-safe native/browser AEAD and HMAC state |
| `sd-jwt-rust` | `edef0328327caeacc7139d025238d3156b16172d` | cryptographically bound opaque remote completion, backend-free issuer planning, holder/verifier confirmation-key policy across every serialization, holder/issuer/tooling feature isolation, secure nonce generation, maintained native RSA backend, restricted WebAssembly verifier, publishable package carrier |
| `longfellow-zk` | `1f822278396b8d6ba7084cab983efa8b80d680d0` | verifier-only default; guarded Rust and C++ prover secrets; bounded quadratic-constraint indices; fixed-capacity witness buffers; transactional commits; cleanup-safe transcript, sampling, Merkle, and witness state; executable sanitizer, unwind, allocation, and vendor-parity regressions |
| `marty-core` | `4659adf9bcb8a48f4c827a2726211ea44bbba9a6` | exact KMS-signature binding for all supported credential formats, native and browser VDS signature-binding regressions, bounded native proving, zeroizing ZK inputs, audited Longfellow source parity, zeroizing native/browser KDF and MAC state, exact-user authenticated OS-IPC signer agent, and final fork pins |

These are review heads, not final integrated or merged revisions. Update this
section after every correction round and after ElevenID merge-queue CI.

## Implemented security properties

### Authenticated-decryption state

ISO 18013 session receive counters are committed only after authenticated
decryption succeeds. A forged, corrupted, or truncated message therefore cannot
consume counter state and desynchronize an otherwise valid session.

### Remote signer and KMS binding

Marty verifies every returned JWT, SD-JWT, and mdoc signature against the exact
prepared bytes and expected public JWK before assembly. A signature over another
payload, from another key, or using an incompatible algorithm fails closed.

The test-wallet holder signer uses only OS-local IPC: a Windows named pipe that
rejects remote clients or a Unix socket in a private directory. Every request
and response is HMAC-bound to an operator-provisioned, canonical 32-byte
authentication key. The launcher must generate a new random value for each
agent/wallet launch; this crate validates encoding and length but does not claim
to generate or rotate that key. Requests also
bind the version, random nonce, timestamp, algorithm, key ID, and exact signing
input; stale and replayed requests fail closed. The implemented signer agent is
the only component that can contact its operator-configured HTTPS KMS endpoint.
Neither wallet nor agent handles a private key.

On Windows, every pipe instance has a protected DACL granting access only to
the exact current-user SID, is non-inheritable, rejects remote clients, and uses
anonymous client security QoS because the signer never needs to identify or
impersonate the wallet. Runtime tests exercise the actual protected pipe rather
than substituting an in-memory transport.

### Secret and witness lifetime

Mdoc session keys use zeroizing storage. The audited Longfellow/Marty witness,
prover, transcript-working, RNG, padding, hash, MAC, and auxiliary allocations
now use zeroizing guards or C++ destructor wipes on normal, error, and unwind
paths covered by their owning scopes. Diagnostic representations no longer
reveal mdoc session-key material. Marty FFI inputs that can contain requested
claims or witness data also clear on drop. This is a targeted lifetime claim,
not a claim that every allocation in either repository has been proven erased.

Browser HKDF, PBKDF2, HMAC, and Concat-KDF use an owned SHA-2 implementation
whose compression state, partial blocks, HMAC pads, PRK, and iteration buffers
are explicitly erased. Real `wasm-bindgen-test-runner` tests cover known answers,
multi-block output, maximum-length rejection, cleanup on returned errors, and
the public KDF/MAC APIs. Native keyed operations continue to use AWS-LC.

### Native prover resource bound

Marty uses one process-wide native-ZK memory permit across circuit identity,
circuit generation, proving, and verification. This prevents concurrent native
operations from multiplying Longfellow's large working-set allocation. It is a
memory-safety/resource-control boundary, not a protocol change.

### QR and image dependency boundary

`marty-iso18013` retains its historical default QR API, while consumers that do
not render QR images can build with `--no-default-features --features
session-protocol`. That graph has no raster-image dependency. QR builds enable
only PNG support; unused image codecs are absent.

### SD-JWT role and tooling boundary

Production defaults use opaque signing. Holder binding is prepared separately
for an external signer, test fixture generation is isolated, and issuer
planning does not compile a cryptographic backend. Local private-key signing is
not a selectable production feature.

## RSA backend and browser compatibility

The public SD-JWT fork no longer resolves RustCrypto `rsa`, including in its
all-features graph. Native holder/verifier builds use `jsonwebtoken` with
AWS-LC. This retains native verification of the RSA PKCS#1 v1.5 (`RS256`,
`RS384`, `RS512`) and RSA-PSS (`PS256`, `PS384`, `PS512`) algorithm families.

WebAssembly deliberately uses a restricted provider and supports `ES256`,
`ES384`, and `EdDSA` verification. It rejects all `RS*` and `PS*` algorithms.
Consequently, a browser cannot directly verify an RSA-signed issuer SD-JWT/JWT
or RSA-signed holder-binding JWT. VDS-NC signature validation uses the same
provider, so browser builds also cannot assemble or verify RSA-PSS-signed VDS-NC
credentials. This is an explicit compatibility restriction for ElevenID's
curve-only browser profile; browser-local private signing was already outside
the architecture.

If product requirements later demand browser RSA verification, add a separately
reviewed WebCrypto-backed provider with exact algorithm/key binding and runtime
tests. Do not restore the vulnerable RustCrypto implementation to obtain that
functionality.

Marty's larger workspace still reports `RUSTSEC-2023-0071` through other direct
RSA/CMS/eMRTD and historical dependency paths. That is distinct from the public
SD-JWT fork replacement. The published attack concerns private RSA operations;
ElevenID's production credential paths use remote KMS signing and local public
verification, but test/authority compatibility paths still require separate
dependency removal or migration. Do not describe the whole Marty workspace as
free of this advisory until its remaining graph is resolved.

## Validation evidence before final review

- isomdl unit/feature tests, strict linting, and offline advisory audit pass.
- isomdl's dependency audit records GHASH/POLYVAL as intentional feature
  carriers for AES-GCM schedule zeroization; `cargo machete`, strict linting,
  and all four selected session-crypto cleanup/known-answer tests pass.
- SD-JWT native all-feature tests, role/feature checks, WebAssembly compilation,
  three WebAssembly runtime provider tests, strict linting, dependency-tree
  exclusion of `rsa`, and offline advisory audit pass.
- The SD-JWT issuer-completion-only graph now explicitly enables its strict
  EdDSA encoding dependency. Its dedicated lane runs 39 tests with no ignored
  cases. The fixed-binary launch-barrier harness also ran all five normally
  environment-gated tests against the built benchmark binary; all passed.
- Longfellow's complete Rust workspace passes, including algebra, sumcheck,
  Ligero, runtime-ZK, mdoc-ZK unit and end-to-end proof vectors and current and
  legacy proof flows, with no ignored tests. The changed C++ translation unit
  passes syntax compilation in both verifier and prover configurations; its
  utility has direct object/vector/scope-exit wipe tests. The full local native
  link is unavailable on this Windows host because OpenSSL and zstd development
  headers are absent, so ElevenID CI must run that required lane before merge.
- Marty KMS/credential, bindings, ZK unit and conformance, ISO 18013 unit/CBOR/
  COSE/mdoc/selective-disclosure, no-render QR profile, and authenticated signer
  tests pass. The full ISO all-feature matrix runs 123 tests/doctests, including
  the permanent Python-module/session-conformance feature-interaction test, with
  no ignored cases. The full verification matrix runs 425 library and 65
  integration tests; the new public-only mdoc signer JWK test is included. The
  previously ignored wrong-witness ZK test now runs in mock mode and passes.
  Signer-agent tests exercise real Windows named-pipe success and wrong-key
  rejection plus missing MAC, stale nonce, replay, response binding, and key
  validation, with no ignored tests. Native and browser crypto cleanup tests,
  affected-crate strict linting, formatting, and vendored-source parity pass.

Every behavior or security gap discovered in this round has a selected,
executable regression test. Ignored, compile-only, or zero-selected runs are not
accepted as evidence for those gaps.

Final acceptance still requires both independent reviewers to report no
corrections, full post-pin tests, ElevenID-only pull requests, successful
protected CI, self-review, and merge. The fork pins and ElevenID feature branches
are current. No upstream repository will receive a branch, issue, or pull request.

## Deferred items

- Re-evaluate performance after the security series is integrated. The separate
  Marty-performance work remains a TODO by instruction.
- Revisit browser RSA only if a concrete relying-party compatibility requirement
  appears; WebCrypto is the preferred implementation boundary.
- Resolve the remaining non-SD-JWT Marty `rsa` dependency paths without removing
  required eMRTD verification functionality.
- Security disclosure is deferred. If later authorized, use an anonymous,
  confidential upstream security channel rather than a public issue or pull
  request.
