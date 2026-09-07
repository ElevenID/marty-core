# Cryptography audit follow-ups

Status: implementation complete; independent review and integration in progress

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
| `isomdl-elevenid` | `135df12ac4257e212b96ca632c2f609d6b98f876` | single-owner and zeroizing session secrets, redacted diagnostics, verification-only default, removal of production local mdoc signing, transactional authenticated-decryption counters |
| `sd-jwt-rust` | `ea04ab35245814b6131b7984df796db76c2ca975` | opaque remote signing, holder/issuer/tooling feature isolation, secure nonce generation, maintained native RSA backend, restricted WebAssembly verifier |
| `longfellow-zk` | `d92f2588f94be0567e8f26254bca7b9845cbe77c` | verifier-only default and guaranteed clearing of prover RNG, witness, field, folding, tableau, proof-auxiliary, padding, hash, and mdoc MAC buffers |
| `marty-core` | `179b6bbe717946c641aa99fa7b553143c612d218` | exact KMS-signature binding, bounded native proving, zeroizing ZK inputs, QR/PNG feature isolation, fixed loopback signer boundary and mandatory authenticated requests |

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

The test-wallet holder signer is confined to a fixed loopback endpoint, bypasses
proxies, refuses redirects, and requires a fresh 32-byte canonical base64url
bearer token. The token is stored in zeroizing memory and the authorization
header is marked sensitive. The sidecar contract requires the same token and
must reject missing or incorrect authentication.

### Secret and witness lifetime

Mdoc session keys and Longfellow/Marty witness, prover, transcript-working, RNG,
padding, hash, MAC, and auxiliary buffers are cleared on all normal and early
return paths by zeroizing guards or guaranteed destructor paths. Diagnostic
representations no longer reveal mdoc session-key material. Marty FFI inputs
that can contain requested claims or witness data also clear on drop.

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
or RSA-signed holder-binding JWT. This is an explicit compatibility restriction
for ElevenID's curve-only browser profile; browser-local private signing was
already outside the architecture.

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
- SD-JWT native all-feature tests, role/feature checks, WebAssembly compilation,
  three WebAssembly runtime provider tests, strict linting, dependency-tree
  exclusion of `rsa`, and offline advisory audit pass.
- Longfellow algebra, sumcheck, Ligero, runtime-ZK, mdoc-ZK unit and end-to-end
  proof-vector tests pass, including current and legacy proof flows; affected
  crates pass strict linting and the offline advisory audit.
- Marty KMS/credential, bindings, ZK unit and conformance, ISO 18013 unit/CBOR/
  COSE/mdoc/selective-disclosure, QR dependency-tree, and authenticated signer
  tests pass. A strict all-features lint failure is confined to pre-existing
  generated PyO3 deprecations outside this work's files.

Final acceptance still requires both independent reviewers to report no
corrections, exact fork pin updates in Marty, full post-pin tests, ElevenID-only
feature branches and pull requests, successful protected CI, self-review, and
merge. No upstream repository will receive a branch, issue, or pull request.

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
