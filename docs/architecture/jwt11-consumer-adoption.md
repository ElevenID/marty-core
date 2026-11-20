# JWT 11 consumer boundary

`marty-oid4vci` and the SD-JWT fork must resolve the same `jsonwebtoken` 11
package. Core passes public JWT types into the fork and uses the fork's
verification provider for direct JOSE operations. A provider installed for one
JWT package identity does not configure another identity. Normal and test
SD-JWT dependencies therefore use the same immutable Git revision, and the
feature-boundary guard checks that both packages share one locked JWT edge.

The adoption updates those dependencies together. Core's own rand 0.8 and
curve25519-dalek 4 dependencies retain their existing roles; the fork's RNG and
signature-shape dependencies do not require a workspace-wide migration.

## Public key admission

JWT 11 can deserialize unknown or incomplete JWK shapes into
`AlgorithmParameters::Other`. Core explicitly accepts only the existing typed
EC, RSA and OKP shapes. It checks raw JSON for private members before typed
deserialization can discard them. Unknown key types, unknown curves and missing
required public parameters fail at this boundary.

The generic JOSE routing decoder also checks an embedded protected-header JWK
before returning untrusted hints, including when the verifier will use an
external key. LTI applies the same typed-shape check immediately after its
existing header decoder. Absent or null optional header keys keep their
existing behavior; embedded keys never acquire issuer authority.

The shared parser applies to direct JOSE operations, issuer and wallet key
preflight, trusted issuer keys, SD-JWT confirmation keys and the selected LTI
verification key. It does not choose a signing algorithm or a credential
profile. Existing algorithm, key-family, use, key-operation and caller-selected
profile checks remain with their existing callers. Parsing a public key does
not authenticate a credential or authorize an issuer.

Invalid SD-JWT confirmation keys fail before UUID, clock and salt sources are
used, including keys supplied through explicit options or top-level IETF
claims. A subject's ordinary `cnf` claim in the explicit legacy VCDM envelope
retains its existing claim semantics.

## Provider and custody

Core selects the verification-only fork provider through role features.
`jsonwebtoken` defaults and global signing backends remain disabled. The
production provider rejects local signing and private-key conversion calls;
issuer and holder preparations still require an opaque external signer.
Native and WASM regressions exercise the actual shared provider with fixed
public signature vectors and reject algorithm confusion. WASM continues to
reject every RSA PKCS#1 and RSA-PSS verifier.

The feature-boundary mutation tests reject global JWT backend feature routes,
divergent normal/test fork revisions and separate Core/fork JWT identities.
Native KMS issuer checks exercise the production dependency graph without dev
feature unification.

The browser target explicitly selects UUID's `js` randomness source. The fork's
RNG migration no longer supplies the feature indirectly; Core owns the target
configuration required by its UUID v4 issuer identifiers. A WASM regression
executes that randomness source as well as the verification provider.

## Regression coverage

The JOSE unit tests cover known public shapes, unknown and malformed shapes,
existing metadata restrictions, public signature verification, tampering,
algorithm confusion and private capability rejection. LTI tests cover malformed
selected keys. SD-JWT tests retain explicit digest and signature-role admission,
trusted issuer identity checks, public wallet fixtures, deterministic source
ordering and opaque completion.

The deterministic preparation and shared remote-batch contract fixtures use a
complete existing public P-256 point. Their signing-input goldens include that
point; protected headers, disclosure bytes, routing order and contract version
remain unchanged. No fixture signing key is introduced.

The `wasm_crypto_provider` and `sd_jwt_multi_digest` runtime suites exercise the
same public-only verification and digest policy on the WASM target. Live KMS
qualification remains in the existing disposable OpenBao workflow; offline
public-vector tests do not substitute for that workflow.
