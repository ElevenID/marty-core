# Device-authentication kernel contract

`marty_verification::device_auth` is the sole implementation of deterministic
device-registration trust decisions. `_marty_rs` exposes it to Python through
typed `DeviceAuthError` failures. Service code may allocate/store challenges
and transact key history, but it must not parse keys, calculate thumbprints,
construct signed messages, verify proofs, or decide key eligibility itself.

## Preserved contracts

| Boundary | Preserved behavior | Canonical Rust API |
|---|---|---|
| Public key submission | Strict base64url, canonical PKCS#1 DER RSA, 2048-bit minimum, exact RFC 7638 `kid`, SHA-256 DER digest | `validate_device_public_key` |
| Challenge message | Legacy v1 and deterministic v2 byte layouts, audience/user/device/key/nonce/registration/version binding | `DeviceChallengeRecord::message` |
| Challenge binding and expiry | Exact user, device, key, digest, registration, version, purpose, audience, and RFC 3339 expiry context | `evaluate_device_challenge_binding`, `DeviceChallengeRecord::is_expired_at` |
| Proof of possession | RSA-PSS SHA-256 with digest-sized salt; malformed and invalid signatures fail closed | `verify_device_challenge_signature` |
| Key resolution | Registration activity, exact key/version/digest binding, purpose/audience, expiry, validity, state, and bounded pre-rotation grace | `evaluate_device_key_eligibility` |
| Python interface | JSON DTOs, 64 KiB input bound, normalized `DEVICE_AUTH.*` errors, backend capability diagnostic | `marty-bindings::device_auth` |

## Orchestration retained outside Rust

- Redis challenge allocation and atomic consume-once semantics.
- PostgreSQL persistence, compare-and-swap rotation, tenancy, and API routing.
- Notification and audit-event delivery.

## Cutover and rollback

The dependent service PR must run the shared vectors in
`tests/vectors/device_auth.json`, preserve the existing REST/error contracts,
and delete Python cryptographic and eligibility logic. Beta rollback selects
the previous immutable service image; no Python runtime fallback is permitted.

The beta deletion gate requires valid/invalid proof, replay, expiry, stale key,
rotation-grace, weak-key, malformed DER/base64url, and unavailable-backend
tests, followed by the roadmap's fourteen-day security evidence window.
