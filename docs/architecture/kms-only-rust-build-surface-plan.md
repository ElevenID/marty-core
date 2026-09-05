# KMS-only Rust build surface plan

Status: implementation and corrective security review in progress

Recorded: 2026-09-05

Scope owner: ElevenID

## Recovery checkpoint (2026-09-05)

The positive-capability/KMS-only implementation is substantially complete and
is being corrected under independent maintainer/security review. The current
ElevenID-only review branch is `codex/kms-only-build-surface`; marty-core PR 308
tracks it. No upstream pull request or push has been made.

Committed marty-core implementation currently ends at `18fa9cc`, with the
corrective review batch still uncommitted so it can be tested as one coherent
Marty checkpoint. Published ElevenID fork heads on
`codex/kms-only-build-surface` are isomdl
`dfd0ca68405b43f5afed0ad218b3c282cc21be61`, sd-jwt
`18049cadba138d9b67a21f753f67c9238cdeae0a`, and Longfellow
`2b55340a2e9930e6699a647501225bae3e5468b0`. The public-fork corrections are
split into small DCO-signed commits. Marty now pins the exact isomdl and sd-jwt
heads; no upstream branch was pushed and no upstream pull request was opened.

Review corrections already implemented include fail-closed remote signature
assembly (including VDS-NC), private-DTC signing feature gates, wallet feature
closure, real native-ZKP CI setup, exact fork pins, circuit-ID authentication,
bounded Longfellow archive decompression, declared-size archive allocation,
native C ABI exception containment, strict verifier timestamps, proof parsing
without copies, and explicit output-allocation failure handling. ZK verifier
state is now opaque, one-use, and bound internally to the canonical OID4VP
SessionTranscript, an exact registered issuer-signed boolean predicate, the
trust-resolved issuer key and docType, and a retained verifier-selected time.

Remaining release blockers are: complete the native Longfellow CI run; rerun
all strict role matrices and unchanged third-party compliance suites; record
dependency/build/final-artifact measurements; commit the Marty correction
batch without the unrelated tracked bytecode; replace the current Marty PR
history with a DCO-clean branch based on the current target; and obtain a clean
independent maintainer/security re-review before merge.

Security disclosure remains deferred by instruction. Candidate confidential,
anonymous upstream reports are the inherited Longfellow circuit/archive and
native allocation/DoS boundaries after ElevenID corrections are validated.

## Purpose

ElevenID production issuer and verifier services use remote signing or key
management systems for long-term credential keys. Those services must not
compile APIs that create, import, serialize, retain, or locally use long-term
private signing keys. Cargo capability selection should also avoid compiling
unused dependencies and reduce build and distributable artifacts where the
dependency graph permits it.

This plan is the recovery document for that work. It records the investigation,
the intended security boundary, the repository-specific work, validation, and
commit strategy.

## Starting revisions

The investigation was performed against these revisions:

- `marty-core`: `44e3cbafed6e2de897a2dc0dc9474b8a3401a7cf`
- `isomdl-elevenid`: `defca84d50ff314addf6dce1379f040a35beed05`
- `sd-jwt-rust`: `439feef451297891b892bc9352058cb07fac6a49`
- `longfellow-zk`: `3a4d5c94e54ee2ff318d0a96fbc3a4788a56c1a3`

Reconfirm the heads and rebase maintained forks from their upstreams before
implementation when they have advanced. Do not push to, or open a pull request
against, any upstream repository under this goal without separate authorization.

## Security boundary

`kms-only` means that a production issuer or verifier artifact cannot call an
ElevenID API to:

- generate a long-term asymmetric credential-signing key;
- import or parse a long-term private JWK, PEM, DER, PKCS#8, PKCS#12, or SEC1 key;
- export or serialize a long-term private key;
- derive a public key from private credential-key material;
- locally sign a credential, assertion, certificate, CRL, SOD, JWT, SD-JWT, or
  mdoc using private credential-key bytes; or
- construct a local signer from private credential-key material.

The absence must hold at the public API, crate-module, Cargo-feature, dependency,
and production-service configuration levels. Hiding a Python export alone is
not sufficient.

The following secret classes are separate and must not be misrepresented as
long-term issuer-key handling:

- TLS server/client identity keys, where the process terminates TLS;
- short-lived ISO 18013 presentation/session ECDH secrets;
- holder/device keys in wallet or authenticator products, when that product is
  explicitly designed to own or access them; and
- test-only fixture keys in non-production targets.

These capabilities require their own positive features or separate crates. A
credential-issuer `kms-only` build must not accidentally gain them through a
broad umbrella feature.

## Investigation findings

### Cargo behavior

Cargo features are additive. A negative feature such as `no-keygen` cannot
reliably disable a capability that another dependency enables. Use positive
capability features, `default-features = false`, optional dependencies, narrow
service roots, and compile-time rejection of forbidden combinations.

Conditional source compilation can remove ElevenID functions and modules, but
it does not remove an unconditional dependency. Release LTO can discard
unreachable machine code from a final binary, but that is not a compile-time API
security boundary and does not avoid compiling the dependency.

### `marty-crypto`

The crate already defines features, but the current names are too broad for a
KMS-only guarantee:

- `ecdsa`, `eddsa`, and `rsa` modules each combine verification with key
  generation, signing, private-key parsing, or secret-key types;
- `serialization` combines public- and private-key codecs;
- `ecdh` creates and retains ephemeral secret keys;
- `keygen` is not the only path to key creation; and
- only `rsa`, `cms`, and `zkryptium` are optional dependencies. Most curve,
  private-key codec, symmetric, random, and certificate dependencies compile
  even with no features.

The historical `default = ["full"]` is unsuitable for production service roots.
Internal consumers already use `default-features = false` in several places,
but broad features still expose local operations.

### `marty-verification` and `marty-bindings`

`marty-verification` gates many Python key operations behind
`local-key-operations`; that is a useful outer guard. Its normal
`marty-crypto` feature set still compiles modules containing local signing and
private-key APIs.

`marty-bindings` explicitly enables `ecdsa`, `eddsa`, `rsa`, and
`serialization`, and exports local key generation, signing, and private-key
conversion. A KMS-only production artifact must not contain that API surface.
Local development compatibility, if retained, must be a separately named and
separately built artifact.

### `marty-oid4vci`

The protocol layer already has the correct remote-signing shape:

1. prepare deterministic signing input;
2. call `CredentialSigner`; and
3. assemble the returned signature.

However, `IssuerKey` still implements `CredentialSigner` by extracting and
using private JWK material in process. The default `issuer` feature also
compiles local JWK signing and broad, unconditional cryptographic dependencies.
Legacy direct-sign SD-JWT and mdoc paths remain available beside the external
signer paths.

The KMS-only service configuration should depend on signing identity metadata
(`issuer_id`, `kid`, algorithm, public certificate chain) and a remote signer,
not on an `IssuerKey` value containing private JWK JSON.

### `isomdl-elevenid`

The fork has remote-signing seams: `prepare`, `signature_payload`, and
`complete`. It nevertheless compiles direct `Signer`/`AsyncSigner` issuance,
P-256/P-384 signing-key implementations, presentation device/reader code, and
ephemeral ECDH key generation in the same default library.

Its `p256` and `p384` dependencies retain default features in addition to ECDH,
and production `x509-cert` enables `builder` even though certificate builder use
is test-only in the inspected tree.

### `sd-jwt-rust`

The fork has no issuer/holder/verifier capability split. `SDJWTIssuer` and its
`jsonwebtoken::EncodingKey` compile in every normal build, alongside verifier
code. Verification-only consumers therefore cannot exclude issuer signing
surfaces. Issuance planning and disclosure generation should be separable from
local signing so a KMS route can prepare and assemble without constructing an
`EncodingKey`.

### `longfellow-zk`

The Rust `verifier_only` binary depends on the common runtime, which currently
exports prover APIs and unconditionally depends on runtime randomness, circuit
compilation, and test-only circuit features. Its name is not presently a build
isolation guarantee.

`marty-zkp` separately compiles a fixed list of vendored C++ sources, including
`mdoc_generate_circuit.cc`. Rust feature changes alone will not reduce that C++
surface; the build script needs an explicit verifier-only source set.

## Baseline measurements

Measurements are illustrative build evidence from one Windows development
machine, not distributable binary-size promises:

| `marty-crypto` release build | Time | Isolated target directory | Crate `.rlib` |
| --- | ---: | ---: | ---: |
| all features | 57.2 s | 288 MB | 7.72 MB |
| no default features, no features | 32.3 s | 241 MB | 162 KB |

The crate object became much smaller, but the isolated build directory shrank
only about 16 percent because nearly all cryptographic dependencies remained
mandatory. The unique dependency-tree entry count changed only from 182 to 161.
This confirms that optional dependencies and role-separated crates are required
for material build savings.

Re-measure clean builds, final executables/libraries, stripped symbols, and
package/container size after each workstream. Do not treat target-directory
size as shipped artifact size.

## Target architecture

### Capability crates

Prefer hard crate boundaries where practical:

- `marty-signing-contract`: signing algorithm, key identifier, public signing
  metadata, redacted errors, signing request/response, and remote signer trait;
- `marty-crypto-verify`: hashing, public-key parsing, signature verification,
  certificate/CRL/OCSP verification, and no private-key types or parsers; and
- `marty-crypto-local`: local signing, key generation, private-key codecs,
  certificate/SOD/CRL construction, and compatibility bindings.

If migration must begin inside `marty-crypto`, split source modules before
declaring the feature boundary complete.

### Positive feature vocabulary

Use positive features similar to:

- `verify-ecdsa`, `verify-eddsa`, `verify-rsa`;
- `hashing`;
- `public-key-codec`;
- `x509-verify`, `crl-verify`, `ocsp-verify`;
- `local-signing`;
- `key-generation`;
- `private-key-codec`;
- `certificate-builder`, `crl-builder`, `sod-builder`;
- `session-key-agreement`;
- `wallet-local-key`; and
- `kms-only` as an enforcement marker, not an umbrella that enables crypto.

Do not use negative capability names. Make dependencies optional and connect
them only to the features that need them. Use upstream dependency
`default-features = false` wherever the selected public operations permit it.

Reject contradictory builds, for example:

```rust
#[cfg(all(
    feature = "kms-only",
    any(
        feature = "local-signing",
        feature = "key-generation",
        feature = "private-key-codec"
    )
))]
compile_error!("kms-only builds cannot include local private-key capabilities");
```

### API removal

Feature work is incomplete until APIs that can invoke excluded capabilities are
also absent from the KMS-only build. This includes:

- local key-pair generators and private-key constructors;
- `sign_*` functions accepting raw private bytes;
- private JWK/PEM/DER/PKCS#8/PKCS#12 import and export;
- certificate, CRL, SOD, or credential builders that own local signers;
- local `IssuerKey: CredentialSigner` implementations;
- direct SD-JWT/mdoc/JWT signing entry points that bypass the remote signer;
- Python/Rust/FFI bindings for any excluded operation; and
- re-exports that make excluded dependency secret types part of the API.

Removing an API from a feature configuration may be a deliberate breaking
change. Prefer a clearly versioned migration over a deprecated callable stub:
a stub preserves the forbidden API surface and can be accidentally re-enabled.

## Repository workstreams

### 1. `marty-core`

1. Add characterization and compile-fail tests for the current production
   feature sets.
2. Split public verification from local generation/signing/private codecs in
   `marty-crypto`.
3. Make cryptographic dependencies optional and assign them to the narrowest
   capabilities.
4. Introduce the signing-contract boundary.
5. Gate or remove local `IssuerKey` signing and legacy direct-sign paths from
   KMS-only `marty-oid4vci` builds.
6. Split issuer, verifier, wallet, transport, and local-holder capabilities.
7. Remove prohibited exports from `marty-bindings` and Python modules in the
   production profile.
8. Add a KMS-only production build target and feature-tree allowlist.
9. Add verifier-only source selection to `marty-zkp` C++ compilation.

Large cohesive commits are acceptable in ElevenID-only repositories when they
increase execution speed, but every commit must remain reviewable, pass its
tests, and preserve a buildable migration sequence.

### 2. `isomdl-elevenid` public fork

Suggested independently cherry-pickable commits:

1. tests that characterize current feature/API behavior;
2. dependency-default cleanup and moving test-only certificate builder support
   to dev dependencies;
3. issuance preparation/completion feature boundary;
4. local direct-signing feature boundary;
5. presentation reader/device and session-ECDH feature boundaries;
6. verification-only feature boundary;
7. downstream migration documentation and size evidence.

Keep each commit narrowly scoped, DCO-signed, and suitable for a possible future
upstream contribution. Do not modify imported third-party compliance fixtures.

### 3. `sd-jwt-rust` public fork

Suggested independently cherry-pickable commits:

1. role and dependency characterization tests;
2. `verifier`, `holder`, and `issuer-planning` module features;
3. prepare/assemble issuance contract without an `EncodingKey`;
4. separate `local-signing` compatibility feature;
5. optional issuance randomness and benchmark-only dependencies;
6. verifier-only and KMS-issuer artifact evidence.

Keep production behavior unchanged for explicitly full-featured builds and keep
the commits small, DCO-signed, and upstream-portable. Do not modify imported
third-party compliance fixtures.

### 4. `longfellow-zk` public fork

Suggested independently cherry-pickable commits:

1. verifier/prover dependency graph characterization;
2. verifier-only runtime modules and exports;
3. optional prover randomness;
4. optional compiler and circuit generation;
5. removal of `testonly` circuit features from production verifier dependencies;
6. verifier-only binary and size/build-time evidence.

Keep these commits small, DCO-signed, and independently useful upstream. Do not
change cryptographic protocol semantics or imported compliance vectors.

## Validation and enforcement

For every production root:

1. build with `--no-default-features` and an explicit capability list;
2. inspect the resolved feature graph, including feature unification from every
   transitive path;
3. run compile-fail probes proving prohibited imports and calls are absent;
4. scan exported symbols and language bindings for key generation, private-key
   codecs, and local signing;
5. scan the dependency graph against an approved KMS-only allowlist;
6. run unit, integration, protocol, and unchanged third-party compliance tests;
7. test KMS prepare/sign/assemble behavior and byte-for-byte output equivalence;
8. test that KMS errors fail closed without a local fallback;
9. build all supported targets, including WebAssembly where applicable;
10. record clean build time and sizes for crate objects, final binaries or
    libraries, packages, containers, and WebAssembly modules; and
11. perform an independent maintainer and security review, correct all findings,
    and repeat until the reviewer reports no corrections.

Add CI guards that fail when `kms-only` is combined with local signing,
generation, private codecs, authority builders, wallet-local keys, or unintended
feature unification. Full-feature test jobs may retain test-only fixture key
creation; production artifact jobs must not.

## Acceptance criteria

The goal is complete only when:

- KMS-only issuer and verifier artifacts expose no ElevenID local credential-key
  creation, import/export, or signing API in Rust, Python, or FFI;
- all credential issuance paths in those artifacts use prepare, remote sign,
  and assemble, with no local fallback;
- prohibited modules are not compiled for KMS-only roots;
- unused private-key dependencies are absent from the resolved production graph
  where protocol requirements allow;
- ephemeral session, holder/device, and TLS key capabilities are separately
  named and enabled only by products that need them;
- verifier-only Longfellow builds exclude prover, random, compiler, and circuit
  generation components that verification does not require;
- behavior and protocol compliance remain unchanged;
- artifact and build-time results are recorded without overstating build-cache
  size as shipped size;
- public-fork history is small, DCO-signed, reviewable, and cherry-pickable;
- no upstream pull request or push was made without separate authorization; and
- independent maintainer/security review reports no remaining corrections.

## Disclosure assessment

The investigation found an ElevenID architectural enforcement gap and excess
compiled capability. It also found inherited Longfellow native input/resource
boundaries (archive allocation, exception containment, timestamp validation,
and circuit-generation allocation handling) that remain candidates for a
confidential upstream security report after ElevenID validation. Disclosure is
deferred by instruction and must use an anonymous secure channel; no upstream
issue, push, or pull request is authorized by this plan.
