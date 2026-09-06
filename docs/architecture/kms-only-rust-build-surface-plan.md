# KMS-only Rust build surface plan

Status: complete; implementation, independent review, full CI, and ElevenID merges verified

Recorded: 2026-09-05

Scope owner: ElevenID

## Recovery checkpoint (2026-09-06)

The positive-capability/KMS-only implementation is merged in the four ElevenID
repositories. No upstream pull request or push was made. This document is the
durable recovery record; the exact reviewed heads, merge commits, test evidence,
and deferred work below supersede chat context.

The final independently reviewed Marty head is
`99b06345c0429149536b23ecfa5156d93457ab92`; PR 308 merged it as
`72d4f214c8e71b4ed41b7d60cdbb638231c112a6`. Exact reviewed public-fork heads
and ElevenID merge commits are:

- isomdl PR 17: `2db80a9d34cf549b76d9d5e4fb8ca9c33b41e5e9`, merged as
  `4e3fd6398467032c80b1023855e674a65481bfa3`;
- sd-jwt PR 33: `302984b4431c331408c58c62f23a07339394c986`, merged as
  `74c086841f8086507e5dc8b6a1acf59feecf0809`; and
- Longfellow PR 15: `72183da18032a737bb70260dfaeb3cba15e402e6`, merged as
  `dd745a47074288865c5be038f485d96219380f09`.

The SD-JWT feature branch is deliberately retained because GitHub required a
squash merge and Marty pins its reviewed tip. The public-fork corrections remain
available as small DCO-signed commits. Marty pins the exact isomdl and sd-jwt
reviewed heads. No upstream branch was pushed and no upstream pull request was
opened.

Review corrections implemented after the base checkpoint include fail-closed remote signature
assembly (including VDS-NC), private-DTC signing feature gates, wallet feature
closure, real native-ZKP CI setup, exact fork pins, circuit-ID authentication,
bounded Longfellow archive decompression, declared-size archive allocation,
native C ABI exception containment, strict verifier timestamps, proof parsing
without copies, and explicit output-allocation failure handling. ZK verifier
state is now opaque, one-use, and bound internally to the canonical OID4VP
SessionTranscript, an exact registered issuer-signed boolean predicate, the
trust-resolved issuer key and docType, and a retained verifier-selected time.
Public JWK containers now reject all registered private members at parsing and
validated-extension boundaries; DIDComm verification methods are public-key
only; ordinary proof, remote credential, and signing-batch entry points reject
rather than retain or silently strip holder private keys. Open Badges 3 local
private-JWK issuance is excluded from verification/KMS-only Rust APIs.

The latest correction also narrows workspace curve, X.509, CMS, PKCS#8, and
Ed25519 dependency defaults so public-key-only builds do not inherit Marty-owned
ECDH, builder, private-key encryption, PEM-private-key, or key-generation
features. Issuer-only remote-signature validation opts into the curve ECDSA
type support it needs; ECDH remains under the ephemeral-session capability.
Marty proof verification now uses verifier-only Ed25519, P-256, P-384, and
secp256k1 paths rather than SSI signing backends. Isomdl presentation
verification likewise uses public points and prehashed verification without its
curve signing features. Static boundary tests and Cargo-tree negative checks
enforce this split.

Final Linux CI also exposed that `affinidi-messaging-didcomm` unconditionally
compiles Ed25519, P-256, and secp256k1 signing/private-key machinery even for
Marty's public DID resolver and anoncrypt-only use. Marty now makes that
dependency and the Rust/Python encrypted-envelope API an explicit
`encrypted-envelope` / `didcomm-encrypted-envelope` capability. Historical
default builds retain the API, while KMS-only base and resolver-only builds omit
the dependency and API entirely. SD-JWT's WebAssembly-only `getrandom` adapter
is now unconditional on that target because `jsonwebtoken` reaches entropy even
without issuer planning; native dependency graphs are unchanged.

Longfellow's full release workspace then exposed stale Rust v8 circuit registry
identifiers: the registered values did not equal the deterministic combined IDs
of the signature and hash circuits regenerated from the checked-in Rust sources.
The new strict archive/spec binding correctly failed closed instead of accepting
that mismatch. Longfellow now registers the four generated combined IDs and
regenerates every current archive in its integration test to assert that each
embedded ID equals the advertised specification ID. This restores current proof
generation without weakening exact circuit authentication.

The final local matrix is green: formatting, strict workspace and role-specific
clippy, five negative KMS/local-capability compile probes, default verification
tests, the full mock-ZKP workspace suite, unchanged third-party compliance
suites, the corrected Longfellow current-v8 proof flow, runtime limit tests, and
the verifier-only release build. Native Longfellow/ZKP C++ cannot build in this
Windows environment because its Linux prerequisites are absent; ElevenID Linux
merge-queue CI supplied that native gate. Both independent reviewers reported
clean final heads. Marty PR 308 passed its complete merge-group matrix, including
the corrected production and development Python binding surfaces, before
merging. Longfellow PR 15 passed all supported CMake platforms,
reference/AArch64 checks, and its production workspace merge-group run before
merging. The unrelated tracked Python bytecode remains excluded.

Longfellow's obsolete Debian 11 workflow lane was retired after Debian 11 LTS
ended. Its strict branch protection was updated to remove only the stale
`Build on Debian 11` context; the other 13 required checks remain enabled.

Security disclosure remains deferred by instruction. Candidate confidential,
anonymous upstream reports are the inherited Longfellow circuit/archive and
native allocation/DoS boundaries. The stale Rust v8 registry identifiers are
supporting evidence for the circuit/spec-binding concern, not a separate
vulnerability or disclosure item.

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

RustCrypto's P-256/P-384/P-521 `ecdsa` features combine verification and
signing implementations inside the dependency. Marty verifier APIs expose only
verification, but those dependency-internal signing implementations cannot be
selected independently today. `jsonwebtoken` and SSI likewise enable broad
curve backends for verification. CI therefore distinguishes prohibited
Marty-owned feature leakage from documented, dependency-internal feature
coupling; replacing or further forking those dependencies is a separate hard
boundary if binary-level absence of every signing implementation is required.

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

### Implemented role-build measurements

Clean release builds from the DCO-clean Marty worktree produced:

| `marty-oid4vci` release role | Time | Isolated target directory | Crate `.rlib` | Unique `cargo tree` lines |
| --- | ---: | ---: | ---: | ---: |
| current default | 86.69 s | 816,938,789 bytes | 10,701,104 bytes | 365 |
| KMS issuer (`kms-only,issuer,jwt_vc_json,sd_jwt,mso_mdoc`) | 65.10 s | 789,364,340 bytes | 9,783,004 bytes | 350 |
| KMS verifier (`kms-only,verifier,jwt_vc_json,sd_jwt`) | 71.57 s | 779,021,250 bytes | 8,806,392 bytes | 348 |
| ZK verifier (`verifier,zk_mdoc`) | not re-timed | not re-measured | not re-measured | 338 |
| ZK verifier plus mdoc issuer planning | not re-timed | not re-measured | not re-measured | 360 |

The isolated target directory is compiler cache/intermediate output and is not
a shipped artifact. The `.rlib` is the protocol crate artifact, not a complete
service binary or container. Against the current default, the KMS issuer removes
15 unique dependency-tree lines, 3.4 percent of isolated build bytes, and 8.6
percent of the protocol `.rlib`. The KMS verifier removes 17 lines, 4.6 percent
of isolated build bytes, and 17.7 percent of the `.rlib`; its clean build was
17.4 percent faster on this sample. Build timing is sensitive to machine load
and should be treated as noisy; the graph and object reductions are
deterministic. Final service/container
measurements remain a deployment-repository task because this workspace does
not contain the ElevenID production service roots.

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
and circuit-generation allocation handling), plus an inherited SD-JWT issuer
path that accepted an `oct` holder confirmation JWK and could embed its shared
secret in the issued credential. These remain candidates for confidential
upstream security reports after ElevenID validation. Disclosure is deferred by
instruction and must use an anonymous secure channel; no upstream issue, push,
or pull request is authorized by this plan.
