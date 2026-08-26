# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Validate RSASSA-PSS algorithm parameters across certificate, CRL, OCSP, SOD,
  master-list, and eMRTD chain verification, including declared salt length
  and matching MGF1 digest.

## [0.1.59] - 2026-08-20

### Changed

- Require the explicit `authority-issuance` feature for CSCA and document-signer
  authority APIs while retaining eMRTD verification in the default verifier.
- Separate CRL verification from CRL construction and narrow the normal crypto
  feature composition used by Verification, Bindings, OID4VCI, and ISO 18013.

### Security

- Exclude certificate, CRL, SOD, and key-generation builder features from the
  default verifier and released Python verifier wheel dependency graphs.

## [0.1.58] - 2026-08-15

### Fixed

- Resolve standards-conformant `did:web` identifiers with percent-encoded
  non-default ports through configured managed resolvers and direct HTTPS
  resolution.

### Security

- Restrict decoded `did:web` authorities to domain names and a single valid
  `%3Aport` delimiter, and require an exact `host:port` allowlist entry before
  direct resolution on a non-default port.

## [0.1.57] - 2026-08-15

### Added

- Add canonical credential evidence, reconciliation, governance, VCDM,
  key-attestation, and status-token decisions for fail-closed service adapters.
- Add canonical passport-chip active-authentication, EAC, APDU, DG14/DG15,
  MRZ, SOD, and LDS parsing kernels, plus trust-registry synchronization
  planning and verification.
- Add SPKI and X.509 public-key-to-JWK conversion and DER-to-P1363 ECDSA
  normalization for signing, JWKS, DID, and OID4VCI consumers.
- Add bounded W3C Bitstring Status List decoding that derives list length from
  GZIP output while enforcing the privacy floor and global size limit.
- Add strict one-recipient-DID X25519 DIDComm authcrypt encryption and
  decryption APIs using the existing ECDH-1PU/A256CBC-HS512 engine, including
  every authorized recipient key-agreement method and Python bindings that
  return authenticated sender and recipient key identifiers.

### Security

- Reject malformed credential decisions, attestations, document data,
  certificates, public keys, signatures, trust synchronization inputs, and
  compressed status lists without falling back to non-Rust implementations.
- Select DIDComm key IDs and public-key material atomically from verification
  methods explicitly authorized by each DID document's `keyAgreement`
  relationship. Reject sender/private-key mismatch, anoncrypt downgrade,
  legacy ECDH-1PU derivation, and authenticated plaintext party substitution.

## [0.1.56] - 2026-08-14

### Fixed

- Correct the `0.1.55` mobile-document issuance regression by computing each
  MSO value digest over the complete serialized tag-24
  `IssuerSignedItemBytes`, matching Marty verification and interoperable wallet
  implementations in both direct and externally signed issuance paths.

### Security

- Keep verification fail-closed while ensuring issuer-authenticated mdoc
  disclosures bind the exact bytes delivered to wallets; the former inner-item
  commitment produced credentials whose disclosures failed standards-aligned
  digest verification.

## [0.1.55] - 2026-08-13

### Fixed

- Restore ISO 18013-5 mobile-document value digests to the encoded
  `IssuerSignedItem` bytes carried by `IssuerSignedItemBytes`, matching the
  unchanged EUDI/Multipaz verifier calculation in direct and externally signed
  issuance paths.

### Security

- Preserve operating-system CSPRNG salts while preventing standards-compliant
  wallets from rejecting issued mdoc credentials because the digest included
  the surrounding tag-24 wrapper.

## [0.1.54] - 2026-08-13

### Fixed

- Compute ISO 18013-5 mobile-document value digests over the complete tagged
  `IssuerSignedItemBytes` encoding in both direct and externally signed
  issuance paths.

### Security

- Generate issuer-signed item salts atomically with the operating system CSPRNG
  and bind every MSO digest entry to the exact encoded item delivered to the
  wallet, preventing valid third-party wallets from rejecting credentials whose
  issuer authentication cannot be reproduced.

## [0.1.53] - 2026-08-13

### Added

- Add canonical P-256 `did:jwk` and `did:key` identifier derivation to
  `marty-didcomm` and expose it through `_marty_rs`.
- Advertise `did_identifier_derivation` in native backend diagnostics for
  startup and readiness enforcement.

### Changed

- Consolidate self-describing verifier DID construction in Rust so Python
  callers no longer canonicalize JWKs, compress curve points, or encode
  multicodec identifiers.

### Security

- Reject private JWK material, malformed or incorrectly sized coordinates,
  off-curve P-256 points, and unsupported DID methods.

## [0.1.52] - 2026-08-13

### Added

- Add canonical ISO 18013-7 OpenID4VP mdoc handover and SessionTranscript
  construction with RFC 7638 client identifier thumbprints.
- Expose non-reversible OpenID4VP response-URI and nonce binding digests
  through `_marty_rs` with shared cross-language golden vectors.
- Add canonical HAIP response-encryption key generation and compact JWE
  decryption with RFC 7518 Concat KDF interoperability vectors.
- Add bounded OID4VP `x509_hash` identity construction with certificate-chain
  parsing, SHA-256 client identifiers, and `x5c` shaping.
- Add canonical SIOPv2 ID-token verification for JWK-thumbprint subjects.
- Add network-free P-256 holder-key generation and reconstruction for public
  `did:jwk` identifiers with separately returned private key material.

### Changed

- Make `marty-iso18013` the single owner of OpenID4VP mdoc transcript and
  handover encoding used by Python compatibility adapters.
- Route HAIP ECDH, KDF, authenticated decryption, OID4VP x509 identity, SIOPv2
  signature and subject binding, and wallet holder-key decisions through their
  canonical Rust owners and typed `_marty_rs` operations.

### Security

- Bound and validate OpenID4VP handover inputs and fail closed for malformed
  JWKs, unsupported keys, empty identifiers or nonces, and oversized values.
- Reject malformed or oversized JWE, certificate, token, and holder-key input;
  unsupported algorithms or curves; certificate/key mismatches; unauthenticated
  SIOPv2 subjects; and private key material embedded in `did:jwk` identifiers.

## [0.1.51] - 2026-08-13

### Added

- Add an explicit presentation-proof policy obligation independently from
  credential obligations and expose it through the native binding.
- Expose controlled DID resolution with native source, timestamp, and content
  digest provenance through `_marty_rs`.
- Add a canonical OID4VP request builder for equivalent Presentation Exchange
  and DCQL credential queries and expose it through `_marty_rs`.

### Changed

- Run faster affected-package pull-request feedback while preserving the full
  verification matrix on merge candidates, and cancel superseded workflow runs.
- Dispatch and await the full verification matrix on the exact protected-main
  release source before creating an immutable stable tag.
- Centralize OID4VP format normalization, algorithm policy, Open Badge aliases,
  mdoc claim paths, disclosure requirements, and resource limits in Rust.

### Security

- Require independently verified presentation proof when configured, without
  allowing that proof to satisfy a missing credential obligation or create
  credential-policy partiality.
- Reject private, duplicate, malformed, or incomplete `did:jwk` key material
  before returning a DID document, and preserve validated document members.
- Reject empty OID4VP policies, incompatible formats, duplicate descriptors or
  claims, incomplete credential metadata, and missing mdoc mappings.

## [0.1.50] - 2026-08-12

### Added

- Add a canonical Open Badges 3.0 profile validator beside the Rust issuance
  profile builder.
- Expose composite Open Badge VC-JWT verification through `_marty_rs`.

### Changed

- Authenticate VC-JWT signatures, issuer binding, validity, VCDM structure,
  and Open Badge semantics through one Rust verification boundary.

### Security

- Clear credential claims when the JWT signature or Open Badge profile is
  rejected so callers cannot consume unverified badge data.

## [0.1.49] - 2026-08-12

### Added

- Add canonical Rust-owned OID4VP and DCQL presentation metadata for Open
  Badges 3.0 VC-JWT and legacy SD-JWT application profiles.
- Expose an explicit `credential_presentation_metadata` native capability for
  startup and health diagnostics.

### Changed

- Reuse the Open Badges 3.0 credential type emitted by the Rust issuer when
  constructing presentation requirements.
- Preserve current and legacy Open Badge SD-JWT VCT matching through the same
  Rust profile resolver instead of caller-side mappings.

### Security

- Reject unknown profiles, unsupported presentation formats, missing SD-JWT
  VCT identifiers, and malformed native presentation metadata fail closed.

## [0.1.48] - 2026-08-12

### Added

- Add canonical Open Badges 3.0 JWT-VC profile construction and a dedicated
  native preparation capability for fail-closed caller startup validation.
- Add canonical native credential-format routing for JSON, JWT VC, SD-JWT,
  Open Badges, and mdoc verification candidates.

### Changed

- Discover OID4VCI authorization-server metadata before token exchange and
  require exact issuer metadata instead of guessing a token endpoint.
- Consolidate Open Badges context, credential type, achievement subject, and
  achievement construction in the Rust OID4VCI owner.

### Security

- Reject malformed or conflicting Open Badges profile data, unknown native
  profile requests, malformed compact tokens, and unavailable native routing
  operations instead of falling back to caller-side interpretation.

## [0.1.47] - 2026-08-12

### Added

- Add VC-JWT receipt, credential inventory, DCQL matching, and presentation to
  the Rust browser test wallet through the canonical OID4VCI/OID4VP engine.

### Changed

- Preserve strict SD-JWT VCT matching while allowing the browser test wallet
  to exercise the conformant Open Badge VC-JWT login path.

### Security

- Reject unsupported credential formats and VC-JWT type mismatches instead of
  selecting or presenting an incompatible credential.

## [0.1.46] - 2026-08-11

### Added

- Add the canonical public status-list crate and Python raw-byte constructors
  for Token Status List and Bitstring Status List compatibility adapters.
- Add canonical Rust flow-decision and device-authentication kernels with
  bounded inputs, normalized outcomes, and fail-closed transition/proof rules.
- Add canonical wallet QR classification for OID4VCI, OID4VP, and ISO 18013
  mdoc inputs for Flutter Rust Bridge consumers.
- Add a bounded VDS-NC CMC, MRV, and eVisa profile kernel with canonical JSON,
  barcode correction, signing, verification, and Python bindings.
- Add a canonical external DTC signing handoff that prepares exact signing
  bytes and authenticates provider signatures before assembly.

### Changed

- Centralize status-list, flow, device-authentication, wallet QR, VDS-NC, and
  DTC signing decisions in their reusable Rust owners for thin caller adapters.
- Consolidate the retained VDS-NC document profile, canonical envelope,
  component policy, barcode selection, and typed Python operations in Rust.

### Security

- Reject malformed, oversized, unsupported, replayed, or cryptographically
  invalid inputs across the new kernels instead of allowing caller fallbacks.
- Require Rust to verify externally produced DTC signatures against the exact
  canonical payload before a DTC can be marked signed.

## [0.1.45] - 2026-08-10

### Added

- Add the canonical service-level presentation-policy request, decision,
  violation, and normalized result API to `marty-verification` and `_marty_rs`.
- Add bounded policy parsing, verified credential facts, holder-binding,
  freshness, revocation, issuer, alternative-requirement, and external
  authorization evaluation with stable error codes.

### Changed

- Route the legacy wallet policy evaluator and claim, issuer, and freshness
  compatibility helpers through the canonical service evaluator so there is
  one maintained allow/deny implementation.

### Security

- Fail closed when policy facts are malformed, unsupported, ambiguous,
  incomplete, stale, untrusted, revoked, replayable, or missing required
  cryptographic and authorization evidence.

## [0.1.44] - 2026-08-10

### Security

- Stop treating a DTC's issuance-time `is_revoked: false` claim as current
  lifecycle evidence. Current-good status now requires fresh, exactly bound,
  provenance-bearing evidence supplied through a governed orchestrator context.
- Preserve declared or authenticated revocation as fail-closed while keeping
  cryptographic validity separate from unavailable, stale, malformed, or
  mismatched lifecycle evidence.
- Add explicit passed, failed, not-performed, and error outcomes to DTC checks,
  with stable diagnostics for unavailable and unusable current-status evidence.

## [0.1.43] - 2026-08-10

### Added

- Add canonical fail-closed OpenID Connect token validation with typed stable
  error codes, issuer/audience/authorized-party/nonce/time-claim policy, JWKS
  key selection, algorithm allowlisting, and access-token hash verification.
- Expose OIDC validation and native backend/version/capability diagnostics
  through the supported `_marty_rs` Python binding surface.

### Security

- Reject malformed, unsigned, ambiguously keyed, expired, not-yet-valid,
  incorrectly issued, incorrectly addressed, or nonce-mismatched OIDC tokens.
- Require callers to receive an explicit native error when the Rust extension
  or required capability is unavailable; no Python validation fallback exists.

## [0.1.42] - 2026-08-10

### Fixed

- Build Linux aarch64 wheels natively on ARM against the supported manylinux
  2.28 ABI so compilers, system libraries, and package architecture agree.

### Changed

- Preflight the affected Linux aarch64 Python packages when release workflow
  or Rust dependency metadata changes, before creating an immutable tag.

## [0.1.41] - 2026-08-10

### Fixed

- Use distro-native Perl packaging in Linux release-wheel containers and
  verify the OpenSSL build modules are available before cross compilation.

## [0.1.40] - 2026-08-10

### Fixed

- Make Linux release-wheel dependency installation portable across the current
  Debian-family cross images and RPM-family manylinux images.

### Security

- Require verifier-governed CSCA trust anchors and a validated DTC Signer
  certificate chain before a Digital Travel Credential can be accepted.
- Require the critical ICAO DTC-signing extended key usage and reject missing,
  partial, malformed, mismatched, or wrong-purpose trust material with a stable
  trust-chain failure.

## [0.1.36] - 2026-08-09

### Added

- Expose typed, signature-authenticated mdoc document evidence from the Python
  presentation-verification binding, including the authenticated document type,
  algorithms, MSO validity interval, and issuer-certificate fingerprint.

### Security

- Require a protected ES256 issuer algorithm and a valid Tag24 Mobile Security
  Object whose version, document type, chronology, and current validity agree
  with the authenticated document.
- Report revocation as unchecked and unknown when no status authority ran,
  preventing downstream consumers from inventing positive non-revocation.

## [0.1.35] - 2026-08-09

### Fixed

- Verify every disclosed issuer-signed mdoc value against the namespace and
  digest-ID commitment authenticated by the Mobile Security Object.
- Replace the permissive mdoc validity placeholder with deterministic verifier-
  time evaluation, including inclusive validity boundaries.

### Security

- Reject altered disclosures, missing namespace or digest commitments,
  malformed timestamps, contradictory validity chronology, not-yet-valid
  evidence, and expired evidence.

## [0.1.34] - 2026-08-07

### Documentation

- Correct the public Python binding documentation to describe the implemented
  DIDComm Messaging 2.1 X25519 anoncrypt profile: `ECDH-ES+A256KW` key wrapping
  with required `A256CBC-HS512` content encryption.
- Scope `marty-didcomm` package metadata to the credential-delivery capability
  that is implemented and tested instead of implying a complete DIDComm agent.

## [0.1.33] - 2026-08-07

### Fixed

- Replace the partial hand-written DIDComm JWE implementation with a maintained,
  exact-pinned envelope engine.
- Produce DIDComm Messaging 2.1 X25519 anoncrypt envelopes whose `epk`, `apv`,
  `alg`, `enc`, and media type are integrity protected.
- Use `ECDH-ES+A256KW` with the required `A256CBC-HS512` content-encryption
  profile, and fail closed on malformed recipient binding or authentication.

### Changed

- Raise the workspace MSRV to Rust 1.95 to match the maintained DIDComm
  dependency; the repository toolchain remains pinned to Rust 1.97.1.
- Document the exact credential-delivery profile Marty currently supports and
  keep full-agent authcrypt, routing, additional curves, and state-machine
  interoperability as explicit tracked capabilities rather than broad claims.

### Security

- Remove Marty's duplicate JOSE, ECDH, AES, and key-wrapping implementation from
  the DIDComm boundary.
- Add negative tests for wrong recipient keys and missing protected `apv`, plus
  an unmodified DIDComm Messaging 2.1 Appendix C authcrypt vector that verifies
  sender authentication and the corrected ECDH-1PU key derivation.

## [0.1.32] - 2026-08-02

### Fixed

- Implement the current ETSI TS 119 472-3 key-attestation proof rule used by
  the official EUDI wallet: the canonical `kid` value `"0"` selects only the
  first public key in the issuer-policy-validated `attested_keys` array.
- Correct the 0.1.31 interpretation that rejected the current ETSI first-key
  selector as a non-standard compatibility convention.

### Security

- Accept `"0"` only for a proof carrying the exact issuer-validated key
  attestation; reject every other numeric value, alternate spelling, named key
  identifier, missing key, private key, and signature made by a later array
  element.
- Keep imported official compliance-suite sources byte-for-byte unchanged.

## [0.1.31] - 2026-08-01

### Fixed

- Align key-attestation-bound OID4VCI proofs with the Final specification by
  accepting an embedded public `jwk` only when its RFC 7638 thumbprint matches
  a key in the issuer-policy-validated attestation.
- Resolve a proof `kid` only when it uniquely identifies an attested JWK or a
  self-certifying `did:key` whose public key is present in the attestation.
- Remove Marty's pre-1.0, non-standard numeric `kid`-as-array-index convention.

### Security

- Continue requiring the exact issuer-profile-validated attestation token and
  verify the proof signature with the public key bound to that token.
- Reject private, unattested, ambiguous, or mutually conflicting proof keys.
- Keep imported official compliance suites, fixtures, assertions, expected
  results, selections, and exclusions unchanged; the interoperability fix is
  entirely in ElevenID product code.

## [0.1.30] - 2026-08-01

### Added

- Verify OID4VCI proofs whose numeric `kid` selects a public key from the
  `attested_keys` claim in an issuer-policy-validated key-attestation JWT.
- Expose the same fail-closed key-attestation proof boundary through the
  production Python binding used by credential services.

### Security

- Require the proof header to carry the exact validated attestation token and
  derive its verification key directly from that token; callers cannot supply
  a separate key list that could drift from the issuer's trust decision.
- Reject unvalidated key-attestation headers, mismatched or malformed tokens,
  empty key sets, nonnumeric or out-of-range key indices, private/symmetric
  keys, and signatures made by a key other than the selected attested key.
- Keep imported official compliance suites, fixtures, assertions, expected
  results, selections, and exclusions unchanged; remediation remains entirely
  in ElevenID product code.

## [0.1.29] - 2026-08-01

### Fixed

- Require an explicitly typed OID4VCI holder proof with audience and issued-at
  claims, and verify every accepted proof signature against resolved public
  key material.
- Preserve a self-certifying `did:key` client identifier only when it resolves
  to the exact key that verified the proof; arbitrary OAuth client IDs no
  longer become holder identities.
- Scope Cargo target caches by operating system, architecture, and Rust
  toolchain so native build artifacts are never restored across incompatible
  runners.

### Security

- Remove the fail-open path that accepted an unresolved, non-`did:key` `kid`
  without cryptographic verification.
- Reject missing or invalid `typ`, `aud`, and `iat` claims, conflicting `kid`
  and `jwk` headers, tampered signatures, and mismatched self-certifying DIDs.
- Keep imported official compliance suites, fixtures, assertions, and
  expected results unchanged; remediation is entirely in product code.

## [0.1.28] - 2026-07-29

### Fixed

- Verify mdoc issuer and device signatures against the exact session transcript
  bytes supplied by the verifier instead of reconstructing a substitute.

## [0.1.27] - 2026-07-29

### Fixed

- Enforce W3C Verifiable Credentials Data Model v2 protected-context
  boundaries.
- Record and pin the maintained ElevenID `isomdl` compatibility fork while its
  upstream synchronization remains review-only.

## [0.1.26] - 2026-07-28

### Fixed

- Accept standards-compliant mdoc presentations whose optional disclosed
  namespaces are empty while preserving issuer and device authentication.
- Separate exact document-signer certificate pinning from root-CA trust:
  pinned issuer certificates require an exact DER match, while root-CA trust
  continues to enforce the full PKIX chain and signing key-usage policy.
- Expose pinned document-signer certificates through the stable Python
  verification binding without changing existing call behavior.

### Security

- Continue failing closed for wrong pins, expired certificates, invalid
  embedded certificate chains, invalid issuer signatures, and invalid holder
  device-authentication signatures.
- Pin the maintained ElevenID `isomdl` compatibility fork by immutable commit
  while its monthly upstream synchronization remains review-only.

## [0.1.25] - 2026-07-28

### Fixed

- Emit ISO 18013-5 `x5chain` certificate material in the COSE unprotected
  header while retaining the signing algorithm in the protected header.
- Preserve the same certificate-chain behavior across local signing and
  remote issuer-profile prepare/assemble signing.

### Security

- Continue requiring certificate material to come from the resolved
  issuer-profile context; credential claims cannot override the trusted chain.

## [0.1.24] - 2026-07-28

### Added

- Allow the internal verification boundary to consume resolver-owned public
  verification methods for tenant-scoped DID documents while retaining
  offline `did:key` resolution.

### Security

- Require exact verification-method IDs and controllers, reject duplicate or
  conflicting methods and private JWK parameters, and fail verification for
  wrong keys, invalid signatures, and tampered credentials.
- Keep DID resolution and tenant authorization outside the cryptographic
  verifier so no public profile, key, KMS, provider, or custody selector is
  introduced.

## [0.1.23] - 2026-07-28

### Fixed

- Allow W3C VC Data Model v2 credentials with syntactically valid past or
  future validity periods to complete remote Data Integrity signing.
- Keep current-time expiration and premature-credential policy in the normal
  public verifier instead of applying it to issuance.

### Security

- Validate RFC 3339 validity fields and reject reversed validity periods
  before signing.
- Continue verifying the exact remotely returned Data Integrity proof and
  reject invalid signatures, tampered credentials, and signing substitutions.

## [0.1.22] - 2026-07-28

### Added

- Prepare and complete native W3C VC Data Model v2
  `eddsa-rdfc-2022` Data Integrity proofs around externally managed signing.
- Expose the canonical signing bytes to issuer-profile-mediated custody and
  return only public verification material with the completed credential.

### Security

- Reject private JWK parameters at the binding boundary.
- Bind completion to the DID, verification method, algorithm, cryptosuite,
  proof purpose, and unsigned credential established during preparation.
- Verify the completed proof before returning it so invalid or substituted
  signatures fail closed.

## [0.1.21] - 2026-07-26

### Bug Fixes

- Extract authenticated claims from every disclosed mdoc document type and
  namespace, including ICAO Digital Travel Credentials.
- Preserve unique element identifiers as flat compatibility keys and expose
  the complete document/namespace structure under `_mdoc`; omit ambiguous flat
  names rather than overwriting claims.
- Keep verification independent of KMS coordinates. Issuer signing remains
  selected through the issuer profile and its DID verification method.

## [0.1.20] - 2026-07-26

### Bug Fixes

- Bind the public key from the wallet's cryptographically verified OID4VCI
  proof into `MobileSecurityObject.deviceKeyInfo.deviceKey`, enabling
  standards-compliant mdoc holder `DeviceAuthentication`.
- Encode only the public EC coordinates in the canonical COSE_Key and reject
  incomplete or unsupported holder keys.
- Keep issuer authentication signing behind the selected issuer profile and
  its DID verification method; no caller-facing KMS identifier or holder
  private key is introduced.

## [0.1.19] - 2026-07-26

### Bug Fixes

- Expose complete ISO 18013-5 issuer, trust-chain, and holder
  `DeviceAuthentication` verification through the released `marty_rs` Python
  binding used by production presentation-policy services.
- Retain the existing VCDM, SD-JWT, OID4VCI, OID4VP, and DIDComm binding
  surface while adding mdoc parsing and disclosed-claim extraction.
- Keep signing behind issuer profiles and DID verification methods; verifier
  bindings accept no KMS service or key coordinate.

## [0.1.18] - 2026-07-26

### Bug Fixes

- Embed ISO 18013-5 `issuerAuth` as the untagged COSE_Sign1 array expected by
  mdoc wallet parsers while retaining tag-24 `MobileSecurityObjectBytes`.
- Preserve issuer-profile and DID verification-method signing; KMS routing
  remains an internal profile binding and is not exposed to issuance callers.

## [0.1.17] - 2026-07-25

### Bug Fixes

- Encode ISO 18013-5 `MobileSecurityObjectBytes` as tagged encoded CBOR in
  issuer authentication payloads for both local and issuer-profile signing.

## [0.1.16] - 2026-07-25

### Features

- Verify holder `DeviceAuthentication` signatures for every ISO 18013-5
  document against a verifier-supplied session transcript.

### Maintenance

- Adopt PyO3 0.29's explicit `from_py_object` behavior for existing Python
  classes without changing their conversion semantics.

## [0.1.15] - 2026-07-24

### Bug Fixes

- Preserve an issuance service's reserved mdoc credential identifier across
  issuer-profile signing so retry protection does not reject a successfully
  assembled credential.

## [0.1.14] - 2026-07-22

### Bug Fixes

- Accept cryptographically valid VCDM v2 presentations that omit the optional `holder` property while continuing to bind a supplied holder to the Data Integrity verification method controller.

## [0.1.13] - 2026-07-22

### Bug Fixes

- Make the VCDM JWT tampering regression deterministic by changing decoded
  signature bytes rather than ambiguous base64url padding bits.

## [0.1.12] - 2026-07-22

### Features

- Verify standalone W3C VCDM v2 JWT credentials with EdDSA or ES256 through the released Python binding.
- Resolve `did:key` verification methods or consume only public issuer-profile JWK material.

### Security

- Reject private JWK members, unsupported algorithms, issuer/controller mismatches, tampering, and invalid temporal or registered-claim mappings.

## [0.1.11] - 2026-07-21

### Features

- Verify W3C VCDM v2 `eddsa-rdfc-2022` credentials and presentations through the released Python binding.
- Resolve `did:key` verification methods offline, bind presentation challenge and domain, and independently verify embedded credentials.

### Security

- Reject unsupported proof suites, proof purposes, malformed multibase proof values, signature tampering, and challenge or domain mismatches.

## [0.1.10] - 2026-07-21

### Bug Fixes

- Encode ISO 18013-5 full-date claims with RFC 8943 CBOR tag 1004 while retaining tag 0 for RFC 3339 date-times.

### CI

- Enforce append-only release metadata and Cargo-derived Python package versions.

## [0.1.2] - 2026-07-17

### Bug Fixes

- **release**: Install OpenSSL for Linux wheels ([322bd19](322bd1937481fb2e6ef106ad9033692e49c46245))
- **release**: Install OpenSSL Perl build support ([5375d05](5375d057d08d155f5cdd19749a315b515af28f43))
- **release**: Install complete OpenSSL Perl toolchain ([70bb2cf](70bb2cfb588f75a2d39d1bc89179f789502342f4))
- **release**: Build portable Python extension wheels ([3899ffa](3899ffa8ec8e37c0d851bc5610ddbc07a436a7c5))
- **release**: Use Rustls for portable Linux wheels ([51cff7c](51cff7c4b10ae848353455cf108a161126585248))

## [0.1.1] - 2026-07-17

### Bug Fixes

- Restore LTI claim tests for core release ([c224db6](c224db6f7ccc574aa5ca63edae57c311f7a2ac70))

### Styling

- Format LTI claim constants ([5bb833f](5bb833fd4681d062ef6dbb37fda3245f08b5e2fa))

### Ci

- Use license-free publication secret scan ([fc67dac](fc67dacbf3ed093148f672b013ebe5c0d2cae452))

## [0.1.0] - 2026-07-17

### Bug Fixes

- Auto-format code to pass CI checks ([bb7179a](bb7179a8fd5ae80e049db41121e706c015e3ecf9))
- Resolve clippy warnings and compilation errors ([3ac1390](3ac1390fd872f9ee0ef3bddff4219042ac4ff78f))
- Gate chip_io module behind csca feature ([4e0ebae](4e0ebae179a59a70536302650b5b79c986457cf6))
- Update CI workflow for Python tests and feature testing ([1fb3f8e](1fb3f8e4219c3ec34b1f613867ee72ee82540844))
- Add placeholder Python tests and fix pytest path ([83f0aa8](83f0aa85b3d7c3b7b46b30d01721eec7c0b708c8))
- Gate testdata module behind test-fixtures feature ([94d069a](94d069a7ea9a391291b0f26951eeb0bcb851b208))
- Correct relative paths in testdata.rs for include_bytes ([9d26b61](9d26b614c2c94bed1460624e96ac22c751247608))
- Add CHANGELOG.md and fix git-cliff config path ([c9ab7c9](c9ab7c91d2ae87509a9487f884edb2c5205ee514))
- CI improvements - proper feature flags, Windows Python tests, remove MSRV matrix ([e08e449](e08e449565790481786e96131c3a50ae4c6c7bd7))
- Use bundled-sqlcipher-vendored-openssl for Windows compatibility ([0b8b558](0b8b5584d4569eba697852bfa16b834d75fbefce))
- **marty-zkp**: Select highest-version spec; test against real Longfellow library ([dea921d](dea921d5aac76f090cfe82f1b346001de1483fd6))
- Make MIP release checks hermetic ([418b6d9](418b6d940ae72cdd93eda2cc8ba283062c24d04d))
- Clear remaining core CI blockers ([f60e675](f60e675f8f303a38ee84cc8e5bee88c5efae5a0c))
- Stabilize cross-platform core checks ([7f2db11](7f2db117f6d88e848073c54215ae4a71d3b68abb))
- Satisfy Rust 1.97 ISO clippy ([cef6e7a](cef6e7a028181fa7e046dc517150d1556feec8b9))
- Keep PyO3 bindings clean on Rust 1.97 ([e155ee5](e155ee515ae1162298e5826acd54a6485d612109))
- Repair remaining feature matrix checks ([1ea132b](1ea132bd1c9ea5b30974ee5588fad7b41d8e804b))

### Features

- Add automated release pipeline with RC staging ([475fca2](475fca2b5b579b011fe49a4b404c34afec7fd233))
- Add NIST PKITS test fixtures for certificate validation ([d9e050e](d9e050ec9a34e6a3ce1d65d819f7df513761f42d))
- Add Open Badges support and ZKP module ([b3cfb97](b3cfb9734c2ff3c614796e8b8f21215b18adc4d0))
- Add marty-bindings crate with PyO3 0.22 compatibility ([82321b3](82321b38ccf479c5f5eee472e1475ae0c5845dc1))
- **oid4vci**: Add OID4VCI module and update ZKP mock implementation ([beda752](beda752f039a674a03cfe19e02d53a804139fb52))
- **marty-zkp**: Replace mock with real Longfellow ZK C API ([117d1be](117d1bead0c14ca783ade1101393f285d90f2e21))
- **oid4vci,verification**: Add OID4VCI verifier, SD-JWT VC support, and CAVP/conformance test suites ([e130a0a](e130a0ae306a842d7bda05a052fa124d9931a6c4))
- GRPC migration, Cedar authorization, BBS crypto, OID4VC conformance, and service layer enhancements ([025cefb](025cefb5fc69d03b68e589231c66be1c6cd3c213))
- Add vds-nc and lti support to oid4vci ([76eb3f9](76eb3f9081fd80e1218d9906ebc5780a20da5556))
- Add MIP release browser wallet ([d4bbfb9](d4bbfb9c3093efff719ba405ef58667b3f826fd8))
- Adopt OID4VCI Final nonce flow ([6144276](6144276fac4abd4172d7d481a191d87e1cbeacc7))

### Miscellaneous Tasks

- Commit generated types for git dep compatibility ([b375db3](b375db36900347f139679feebdb3490ae466ee41))
- Sync working state for dev environment migration ([1d65c9c](1d65c9c981bab956ff1bf73a3a40f83454d78be8))
- Prepare for automated improvements ([56288cc](56288cc3488af80b9a4c2f08b3535033d09b6e71))

### Security

- Add comprehensive security and quality checks ([2826d48](2826d48a7d81d8943f77b8a40c6dfaa93b21950f))
- Make security checks non-blocking to prevent repeated failures ([b5c7091](b5c7091dd2c66c85b5bca0e1323d16d988c82218))

### Testing

- **marty-zkp**: Multi-attribute coverage + attribute count validation ([0050122](005012210c90ad863855e633dfbc2b5336ffed98))

### Ci

- Enable all features including test-fixtures in CI ([fbc9ecd](fbc9ecdb373929b223b867a03d09b0b110e9a48a))
- Add repository_dispatch to notify downstream repos on release ([f21287e](f21287e22a1f7d7ac53112dc4aabe6f18f538de7))
- Use REPO_ACCESS_TOKEN for cross-repo dispatch ([438d0f8](438d0f817b6f6c5e19827045d92d4bf28280eb99))
- Remove stale vendored core gate ([cf8cae7](cf8cae7a2a955074429353cf65e4496882b83fd7))

### Security

- **marty-zkp**: Hard-block ZK mock from release builds ([53c2d35](53c2d354f56c980c9595fac0f98e064e46e576ed))

<!-- generated by git-cliff -->
