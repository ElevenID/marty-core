# Cryptography audit follow-ups

Status: implementation and executable regression matrix pass; isomdl and
SD-JWT integrated with green post-merge CI; Longfellow reviewed at `c4004b5`
with ElevenID integration pending; Marty correction review and integration pending

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
| `isomdl-elevenid` | reviewed `784a52943469622873c7ae3200dbc11e89d6bd8e`; merged `8915a0357c78dc91ee15a41ccc0103a8b5afe97a` | versioned single-owner and zeroizing session secrets, redacted diagnostics and prepared credentials, verification-only default, authenticated KMS completion against the exact payload and certificate key, strict public-point-only certificate decoding without curve private-key codecs, transactional authenticated-decryption counters, cleanup-safe native/browser AEAD and HMAC state |
| `sd-jwt-rust` | `82143d688355315f22297b40ca18050a94cd2525` | versioned cryptographically bound opaque remote completion, backend-free issuer planning, standalone signing-free verification provider, signing-free issuer-completion/holder/verifier graphs, holder/verifier confirmation-key policy across every serialization, secure nonce generation, maintained native RSA backend, restricted WebAssembly verifier, publishable package carrier, and locked interop generator; this permanent rebase-merge revision is tree-equivalent to reviewed head `200ad57a276d28c7108255235b34afea67f07d06` |
| `longfellow-zk` | `c4004b5edee8cbc4e2a76588c531f07994e3e7ab` | verifier-only default; zeroizing Rust prover, derived sumcheck state, and accumulators by default; guarded Rust and C++ prover secrets; bounded quadratic-constraint indices; fixed-capacity witness buffers; transactional commits; cleanup-safe transcript, sampling, Merkle, and witness state; non-elidable OpenSSL PRF-wrapper teardown; strict UTF-8, canonical CBOR lengths/scalars/wrappers, unambiguous map lookup, exact input consumption, semantic dates, overflow-safe lengths, and null rejection; executable sanitizer, unwind, allocation, vendor-parity, parser, real-proof, and production-random retry-verification regressions with complete public-statement binding |
| `marty-core` | code checkpoint `3369d5b9d4aede9624a3e47a79217a810016992e` | exact KMS-signature binding for all supported credential formats, strict rejection of small-order remote Ed25519 issuer keys and low-order-R signatures with a nonweak C2SP vector, signing-free KMS issuer dependency graphs with an executable current JOSE/ISO feature-route gate, verification-only Ed448 with explicit eMRTD selection and executable KMS+CSCA graph gates, canonical Ed448 public-key/R enforcement with reserved-bit and y-at-or-above-p negatives, strict Ed448 RFC 8032/SPKI metadata and unused-bit regressions, role-less JOSE removal, strict public-only EC and Ed25519 SPKI decoding, strict Ed25519 verification, native and browser signature-binding regressions, bounded native proving, zeroizing ZK inputs, audited Longfellow source parity through `c4004b5`, direct native decoder/parser/proof/MSO tests, Cargo vendor-change invalidation, checked-accessor CBOR validation with end-to-end accepted/rejected-value regressions, zeroizing native/browser KDF and MAC state, exact-user authenticated OS-IPC signer agent, synchronized 0.2 release metadata, isolated lockfile updates, and permanent integrated fork pins |

The table records reviewed implementation heads and, where integration has
completed, final ElevenID main revisions. Longfellow and Marty remain
pre-integration. Update this section after every correction round and after
ElevenID merge-queue CI.

The Marty branch was rebased onto Marty PR #317 by dropping the duplicated PR
commits and replaying only the later audit series. The PR #317 merge tree was
verified byte-for-byte equal to the dropped head, and the final feature-tree was
verified unchanged across the rebase. The permanent SD-JWT rebase-merge revision
is likewise byte-for-byte equal to its reviewed PR head.

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
The agent, rather than the wallet request, owns the permitted ES256 algorithm
and single KMS key identifier. A mismatch is rejected before any outbound
request. Neither wallet nor agent handles a private key.

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

### Code-scanning triage

Marty PR #318's Rust CodeQL analysis initially reported 15 new alerts. Every
location was inspected before triage; the language analyses themselves remained
enabled and passing, and no test was deleted, ignored, or excluded:

- nine hard-coded-value alerts were deterministic test vectors or cleanup
  fixtures compiled only under `cfg(test)`;
- three zero-IV alerts were the public, mandatory initial chaining value for
  ISO 9797-1 Algorithm 3 Retail MAC;
- two apparent HKDF salts were public EAC domain-separation labels whose
  distinct values prevent MAC/encryption key reuse; and
- one weak-algorithm alert was test coverage of deliberately feature-scoped
  3DES retained for required eMRTD/BAC interoperability, not new general-purpose
  encryption, signing, or key storage.

Each alert was dismissed individually through GitHub's auditable code-scanning
triage with its own reason and location-specific comment. The PR subsequently
reported zero open alerts and a passing aggregate CodeQL check. Future alerts at
different locations require fresh review rather than relying on this triage.

## Validation evidence before final review

- isomdl unit/feature tests, strict linting, and offline advisory audit pass.
- isomdl's issuer-planning production-only graph compiles without dev-feature
  unification, its curve-feature guard excludes signing, and the selected ES384
  and ES512 remote-completion test verifies both certificate-bound signatures.
- isomdl's dependency audit records GHASH/POLYVAL as intentional feature
  carriers for AES-GCM schedule zeroization; `cargo machete`, strict linting,
  and all four selected session-crypto cleanup/known-answer tests pass.
- SD-JWT native all-feature tests, role/feature checks, WebAssembly compilation,
  six WebAssembly runtime provider tests, strict linting, dependency-tree
  exclusion of `rsa`, and offline advisory audit pass.
- The SD-JWT issuer-completion-only graph now explicitly enables its strict
  EdDSA encoding dependency. Its dedicated lane runs 41 tests with no ignored
  cases. The fixed-binary launch-barrier harness also ran all five normally
  environment-gated tests against the built benchmark binary; all passed.
- Longfellow's complete Rust workspace passes, including algebra, sumcheck,
  Ligero, runtime-ZK, mdoc-ZK unit and end-to-end proof vectors and current and
  legacy proof flows, with no ignored tests. The changed C++ translation unit
  passes syntax compilation in both verifier and prover configurations; its
  utility has direct object/vector/scope-exit wipe tests. A fresh isolated Linux
  GCC build ran all 243 native tests successfully, including exactly one selected
  complete-public-statement retry regression and exactly one selected PRF
  teardown regression, with no ignored tests. The corresponding GitHub GCC lane
  also passes. The complete GitHub matrix passes, including the 24-minute
  ASan+UBSan lane and 24-minute release-mode production Rust workspace.
- Marty KMS/credential, bindings, ZK unit and conformance, ISO 18013 unit/CBOR/
  COSE/mdoc/selective-disclosure, no-render QR profile, and authenticated signer
  tests pass. The full ISO all-feature matrix runs 123 tests/doctests, including
  the permanent Python-module/session-conformance feature-interaction test, with
  no ignored cases. The full verification matrix runs 425 library and 65
  integration tests; the new public-only mdoc signer JWK test is included. The
  wrong-witness ZK regression is explicitly selected beside the real native
  round trip in required Linux CI; broad local Rust coverage uses the mock only
  because this Windows host lacks the native OpenSSL/zstd headers. The KMS-only
  issuer matrix now selects and runs the ZK mdoc external-signer regression, so
  its public-key metadata contract cannot silently drift again.
  The role-less OID4VCI build runs 115 library tests with no ignored cases and
  a warnings-as-errors lint; the exact no-default Marty verification feature
  combination runs all 382 selected tests. The public verification entry-point
  suite runs 13 tests, including malformed ECDSA SPKI unused-bit rejection.
  Signer-agent tests exercise real Windows named-pipe success and wrong-key
  rejection plus missing MAC, stale nonce, replay, response binding, and key
  validation, with no ignored tests. The signer policy regression proves that
  wrong key and algorithm requests cause exactly zero network calls. Native and
  browser crypto cleanup tests, two browser provider-policy tests, three browser
  KDF/MAC tests, affected-crate strict linting, formatting, and vendored-source
  parity pass.
- Marty PR #318's first post-rebase CI run exposed two evidence gaps rather than
  skipped tests. The new WASM jobs inherited `RUSTC_WRAPPER=sccache` without
  installing the wrapper; both jobs now install the pinned cache action, and a
  69-test release-contract suite exact-allowlists the workflow preamble, each
  audited Ubuntu job and its full top-level mapping, every action configuration,
  the full environment, each complete test step, and the final CI gate, including
  scripts, selectors, runner pins, checkout, gate needs, result bindings, and
  success assertions. It rejects duplicate or noncanonical root and audited-job
  mappings, token-permission escalation, shell injection, execution overrides,
  hidden or replacement actions, folded-comment suppression, control flow,
  pipelines, nonexecuting flags, and zero-selection filter substitutions while
  ignoring inert literal comments or
  echoed Cargo text. The real Linux ZKP build also detected an incomplete
  Longfellow algebra sync:
  `fp24.h` and `fp_generic.h` used the audited base-aware `digit` API while
  `nat.h` and `nat.cc` retained the old signature. The exact audited `nat` pair is
  now synchronized and covered by the executable source-parity manifest. The
  following exact-head Linux run exposed the same class of omission at the CBOR
  boundary: audited `mdoc_witness.h` expected Longfellow's current
  `CborDoc` API, while the parity manifest had not pinned its header-only
  `cbor/host_decoder.h` dependency. The decoder is now synchronized from
  Longfellow commit `c4004b5` and included in executable source parity.
  Marty's local CBOR allowlist uses the decoder's checked public accessors, and
  two end-to-end verifier regressions exercise all supported scalar/date forms
  plus malformed, trailing, container, null, and unsupported-tag rejection. A
  fresh Rust 1.97.1 Linux verifier build passes all five selected tests (the
  original three circuit-identity checks and both CBOR behavior regressions)
  with no ignored or filtered cases. The complete real-backend verifier-only
  package also passes five library tests, those five integration tests, one
  vendor-parity test, and two compile-fail documentation contracts. The browser
  lanes pass one cleanup/KAT unit test, two KDF integration tests, and two
  provider-policy tests with no ignored or filtered cases.
- Synchronizing Marty's vendored Longfellow boundary exposed a build-cache gap:
  Cargo watched only Marty's wrapper sources, so a changed vendored C++ parser
  could reuse a stale native object. `build.rs` now watches the complete vendor
  source directory and revision marker, and the parity test enforces that watch.
  Marty's required CI builds and directly executes all four native binaries; the
  release contract freezes the complete job and fails if any binary is removed,
  filtered, sharded, skipped, conditioned, or returns a different pass count.
  The proof-fixture header is also pinned by source parity. An isolated Linux
  run passes all 36 native tests (12 decoder, 9 parser, 11 real ZK, 4 MSO), the
  complete verifier package (5 library, 5 circuit/CBOR identity, 1 parity, and 2
  compile-fail tests), and all 27 real-prover conformance tests with zero ignored
  or filtered cases. Strict verifier linting passes with warnings denied.
- The final affected-feature CI run exposed a test-only conditional-compilation
  error in `marty-bindings`: its assertion that the opaque HAIP response session
  is absent without `ephemeral-session-keys` was scoped outside the feature guard.
  The assertion is now wholly guarded, while the existing enabled-feature test
  still requires the opaque session export. The complete bindings suite passes
  both configurations: 59 tests with the feature and 56 without it, with zero
  ignored or filtered cases.
- Linux strict lint also found that the signer agent's listener is mutable only
  for the Windows named-pipe implementation. The binding is now immutable on
  Unix and explicitly shadowed as mutable on Windows. The exact full-workspace
  Windows clippy command passes with warnings denied after exercising the
  platform-specific binding.
- The dependency-health checkpoint was re-run on 2026-09-08. RustCrypto's
  certificate/signature/elliptic-curve majors are stable but compatible RSA
  0.10 remains a release candidate; Affinidi DIDComm 0.15.8 requires the new
  curve/Ed25519 stack and Rust 1.95. Both migrations remain coordinated behind
  the existing issue rather than introducing duplicate production crypto
  stacks, with the next mandatory review on 2026-10-08.

Every behavior or security gap discovered in this round has a selected,
executable regression test. Ignored, compile-only, or zero-selected runs are not
accepted as evidence for those gaps.

Final acceptance still requires all independent reviewers to report no
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
