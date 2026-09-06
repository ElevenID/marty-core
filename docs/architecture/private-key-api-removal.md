# Private-key API removal

Status: in progress

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

VDS-NC verification remains available. VDS-NC and ZK mdoc issuance are
intentionally unavailable until they have bounded, opaque, format-specific KMS
handles; callers must not fall back to local signing.

## Remaining migration

1. Move test fixture signers out of production crates into a publish-disabled
   test-support crate.
2. Remove the `local-key-operations` API from `marty-oid4vci` and retain only
   preparation, remote signer contracts, signature validation, and assembly.
3. Split `marty-crypto` into a verification crate and a publish-disabled local
   test-support crate, then remove its production-selectable keygen, private
   codec, signing, and authority-builder features.
4. Move wallet/holder and DIDComm agent key ownership to their explicit product
   roots; do not expose those capabilities through the issuer bindings.
5. Add dependency/symbol checks for each shipping artifact and re-measure final
   wheel/library size.

## Required validation

- Compile Marty bindings with no defaults and with the KMS-only feature set.
- Prove removed Cargo features are rejected and removed Python names are absent.
- Exercise prepare -> remote sign -> assemble with a test-only signer and verify
  equivalence to the prior credential output.
- Run first-party unit/integration tests and unchanged third-party compliance
  suites.
- Obtain independent maintainer and security review and correct all findings
  before merge.
