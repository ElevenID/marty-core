# Private-key API removal

Status: implementation complete; validation and review in progress

Recorded: 2026-09-06

Scope: ElevenID Marty production artifacts. No upstream push or pull request is
authorized by this work.

## Decision

Marty issuer and verifier artifacts do not support locally owned credential
private keys. They prepare canonical, exact signing inputs, send those inputs to a
remote signer/KMS, and assemble the returned signatures. A deprecated callable
stub or a production-selectable Cargo feature is not an acceptable boundary.

Holder/device keys, protocol session keys, and TLS identities are separate
capabilities. They must live in explicitly selected product crates and must not
re-enable issuer key generation, import, serialization, or signing.

Public cryptography forks retain non-default compatibility capabilities only
where preserving an upstream-portable patch series requires them. This Marty
work does not change imported third-party compliance tests.

## Breaking-change and migration boundary

This change must ship on the next Marty minor release boundary (`0.2.0`), not
as a `0.1.x` patch. The removed Python operations and their replacements are:

| Removed operation class | Replacement |
| --- | --- |
| key generation and raw `sign_*` | remote KMS/key-manager client |
| direct JWT-VC, SD-JWT, and mdoc signing | format-specific `prepare_*` / `assemble_*` APIs |
| VDS-NC and ZK mdoc issuance | unavailable in production bindings; remote-signing support is deferred |
| wallet proof-key generation | wallet/authenticator product crate |
| DIDComm authcrypt/decrypt with raw private bytes | messaging-agent product crate |
| generic Python KDF, random-secret, AES/3DES, and HMAC helpers | protocol-specific opaque session handles |

The legacy generic `oid4vci_prepare_credential` / `oid4vci_assemble_credential`
tuple API is also removed. It reconstructed caller-controlled state and lacked
the bounds, explicit key identifier, and one-use guarantees of the existing
format-specific remote signing handles.

## Implemented in this branch

- Marty crypto, verification, DIDComm, and Python binding defaults no longer
  select local signing, key generation, session keys, or encrypted envelopes.
- The Python extension no longer has features capable of exporting credential
  key generation, private-key signing, proof-key generation, or DIDComm
  long-lived-key decryption/authcrypt functions.
- The unsafe generic tuple-based signing wrapper was removed. Production uses
  the bounded, format-specific remote-signing APIs, which retain opaque,
  one-use preparation state and require explicit verification-method IDs.
- Rust and Python surface tests reject the removed names while requiring the
  remote-signing replacements.
- `marty-oid4vci` no longer declares a `local-key-operations` feature or a
  production `ssi-crypto` dependency. Its legacy local issuer implementation is
  compiled only by Rust's non-selectable `cfg(test)` boundary.
- Imported third-party compliance test sources are unchanged. First-party
  local-signing tests remain crate-internal and may be adapted to the production
  prepare/assemble boundary. Downstream fixture signers use the same
  prepare -> signer callback -> assemble contract as a remote KMS.
- `marty-crypto` no longer declares selectable signing, key-generation,
  private-key codec, PKCS#12, BBS signing, or certificate/SOD builder features.
  BBS signature/proof verification and holder proof generation remain available
  through `bbs-verification`; BBS secret keys, key generation, and signing are
  test-only. Historical local vectors run only under rustc's non-selectable
  `cfg(test)` boundary.
- Cross-crate fixture signing lives in `marty-crypto-test-support`, which is
  `publish = false` and used only as a dev-dependency.
- `marty-verification` no longer declares local-key, certificate-builder, or
  authority-issuance features. Explicit, zeroizing ECDH/BAC/PACE/EAC session
  state and TLS clients remain separate capabilities.
- Public JWK parsing remains Serde-compatible but now uses bounded visitors:
  member strings, arrays, extension depth/count, aggregate bytes, duplicate
  names, and private members all fail closed before unbounded allocation.
- X25519 agreement rejects non-contributory peer keys before a shared secret can
  reach JWE/ECIES key derivation.
- BAC uses opaque, zeroizing handshake/session state. The old named raw-key
  export helper is test-only; APDU encoding is fallible; command/response sizes,
  `Le`, and SSC overflow are checked transactionally before committing state.
- ISO 18013 session configuration accepts a bounded 1–3600 second lifetime.
  The monotonic deadline is checked before key agreement and traffic-key use;
  timeout or explicit termination clears both pending ECDH private state and
  established traffic keys.
- The required pull-request lane exercises the explicit crypto capability set,
  private test-support crate, verification/session boundaries, Python bindings,
  and the full DIDComm agent capability set.

VDS-NC verification remains available. VDS-NC and ZK mdoc issuance are
intentionally unavailable until they have bounded, opaque, format-specific KMS
handles; callers must not fall back to local signing.

Rust callers must also migrate three now-fallible boundaries: handle
`ApduCommand::to_bytes()` as a `Result`, handle ISO 18013
`Session::public_key()` as a `Result`, and replace production
`MrzKeyInfo::from_mrz_fields(...)` calls with
`MrzKeyInfo::try_from_mrz_fields(...)` and propagate validation errors.

## Remaining migration

1. Run dependency/symbol checks against each final shipping artifact and
   re-measure wheel/library size when release packaging is assembled.
2. Re-evaluate performance after the security/API-removal series is merged;
   the separate Marty performance work remains deferred.

## Required validation

- Compile Marty bindings with no defaults and with the KMS-only feature set.
- Prove removed Cargo features are rejected and removed Python names are absent.
- Exercise prepare -> remote sign -> assemble with a test-only signer and verify
  equivalence to the prior credential output.
- Run first-party unit/integration tests and unchanged third-party compliance
  suites.
- Obtain independent maintainer and security review and correct all findings
  before merge.
