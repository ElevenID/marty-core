# Marty Browser Test Wallet

This non-production wallet gives Playwright a user-visible browser surface for
the Marty credential lifecycle gate. It uses `marty-oid4vci` for protocol and
cryptographic operations and supports:

- OID4VCI pre-authorized SD-JWT VC and W3C VC-JWT receipt
- signed OpenID4VP request objects with DCQL
- SD-JWT selective disclosure with nonce/audience key binding
- W3C VC-JWT presentation for `jwt_vc_json` DCQL queries

Credential material remains in the local wallet process, but private keys do
not. The test wallet requires an opaque ES256 signer agent and an explicit
issuer-key trust set. The signer agent accepts only local OS IPC (a Windows
named pipe or Unix domain socket) and owns all remote KMS connectivity and
policy; the browser wallet cannot send signing requests to operator- or
request-selected network locations.

- `MARTY_TEST_WALLET_HOLDER_KID`: signer-owned holder key identifier.
- `MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK`: public-only P-256 JWK JSON.
- `MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT`: `\\.\pipe\marty-test-wallet-*`
  on Windows, or an absolute Unix socket path whose existing parent directory
  is private (`0700`).
- `MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY`: a canonical base64url
  encoding of exactly 32 fresh random bytes, shared only with the signer agent.
- `MARTY_TEST_WALLET_TRUSTED_ISSUER_KEYS`: JSON array of exact trust entries,
  each with `issuer`, optional `key_id`, `algorithm`, and `public_jwk`.

Each request is bound by HMAC-SHA-256 to its protocol version, random nonce,
timestamp, algorithm, key ID, and exact signing input. The agent rejects stale,
replayed, missing-MAC, and wrong-MAC requests. Its response MAC binds the raw
ES256 signature to that request nonce.

The signer agent additionally requires `MARTY_TEST_SIGNER_AGENT_KMS_URL`, which
must use HTTPS, and `MARTY_TEST_SIGNER_AGENT_ALLOWED_KEY_ID`, which independently
pins the only KMS key the agent may use. That value must match the wallet's
holder key identifier; authenticated requests for any other key or any algorithm
other than ES256 are rejected before a network request. The optional
`MARTY_TEST_SIGNER_AGENT_KMS_BEARER_TOKEN` supports KMSs that use bearer
authentication; workload identity may be used instead. The KMS endpoint receives
the agent-owned `{ algorithm, key_id }` policy plus `signing_input` and returns
`{ "signature": "<base64url raw ES256>" }`. Neither Marty process loads a
private key: the agent is only a policy and transport bridge to the KMS.

For a non-exportable OpenBao Transit ECDSA P-256 key, set
`MARTY_TEST_SIGNER_AGENT_KMS_PROVIDER=openbao-transit` and point
`MARTY_TEST_SIGNER_AGENT_KMS_URL` at the exact HTTPS
`/v1/transit/sign/<key-name>` route. Set
`MARTY_TEST_SIGNER_AGENT_KMS_BEARER_TOKEN` to an agent-scoped OpenBao token;
the agent sends it as `X-Vault-Token`. The optional
`MARTY_TEST_SIGNER_AGENT_KMS_CA_CERT_PEM` names a trusted CA PEM for a
disposable or private TLS endpoint. The agent sends SHA-256 of the exact
signing input with `prehashed=true` and `hash_algorithm=sha2-256`, then
normalizes OpenBao's versioned DER signature to raw ES256. Give issuer and
holder agents different Transit keys and tokens whose policies allow only
their respective sign routes. The existing generic HTTPS contract remains
the default when the provider variable is omitted.

Before credential operations, `marty-test-holder-signing-probe` can verify a fresh
challenge through that same authenticated agent and the configured public holder
key. It opens no HTTP endpoint and receives no KMS token. See
[holder signing preflight](../docs/holder-signing-preflight.md) for source-bound
capture integration, public receipts and focused disposable-KMS checks.

The browser API returns display metadata only. Run it after configuring those
values:

```text
cargo run -p marty-test-wallet
```

Run the agent separately after configuring the same IPC endpoint and
authentication key:

```text
cargo run -p marty-test-wallet --bin marty-test-signer-agent
```

The default browser URL is `http://127.0.0.1:8787`.

## Isolated demo sessions

`POST /api/present` preserves verifier rejection as HTTP 400 with `ok: false`.
When the verifier actually responded, `submission` records `submitted`,
`verifier_http_status`, and `verifier_error`. A failed request before submission
does not produce that record. This transport evidence does not establish a
relying party decision: negative demos must independently corroborate the fresh
verifier session's terminal denial and its expected reason. Successful demos
still require successful submission and a terminal allow decision.

Automated browser demos must create a session in a fresh browser context before
receiving credentials or resetting wallet storage. `GET /ready` advertises
`features.isolated_sessions: 1` and the current process `instance_id`.

`POST /api/sessions` with `{ "run_id": "<unique-run-id>" }` creates an empty
wallet and sets an opaque `HttpOnly; SameSite=Strict` session cookie. Its JSON
response contains public `session_id`, `instance_id`, `run_id` and lifetime
metadata; it never exposes the cookie capability. `GET /api/session` returns
those fields with the credential count. `DELETE /api/session` erases that
session's storage and clears its cookie. The server drains in-flight receive,
present and storage operations before acknowledging deletion; later operations
are rejected. A teardown timeout must remain an incomplete cleanup in the run
report. Closing a browser context alone does
not immediately free server storage, so demo runners must call the delete
endpoint before closing the context and retain any cleanup error in the report.

All credential operations use the cookie's separate Rust storage. Run-aware
requests also send `x-marty-wallet-run-id`; a missing cookie, wrong run, expired
session or ambiguous cookie is rejected before storage or protocol access. Open
the visible wallet as `/?wallet_run=<run-id>` so its Receive, Present and Reset
controls send this guard. This also prevents a cleared cookie from silently
redirecting an automated operation to the interactive wallet. Marty UI's
`tests/scripts/demo-wallet-session.js` supplies this transport consistently.

Sessions expire after six hours and are limited to 128 concurrent runs. Capacity
errors do not evict an active run. The session cookie lasts for the browser
context so server expiry rejects a stale cookie instead of selecting other
storage. The existing interactive wallet remains available to requests without
a session cookie or run marker. Issuer trust and holder signing configuration
are still shared process prerequisites; storage isolation is not an independent
wallet interoperability or hardware custody qualification.

## Remote positive verifier input

`marty-kms-positive-verifier-input` is a non-publishable acceptance binary. It
uses the canonical Core SD-JWT issuer preparation and wallet presentation
preparation APIs, then asks two separately scoped signer agents to sign their
exact inputs. It emits only `{ "presentation", "issuer_public_jwk" }` JSON for
the Marty UI verifier probe. It does not create, load or serialize an issuer or
holder private key.

Configure one instance of `marty-test-signer-agent` for the issuer KMS key and
another for the holder KMS key. Each agent needs its own authenticated local IPC
endpoint, authentication key, `MARTY_TEST_SIGNER_AGENT_ALLOWED_KEY_ID`, HTTPS
KMS URL and provider authorization. The producer needs:

- `MARTY_POSITIVE_GATE_ISSUER_PUBLIC_JWK`: public P-256 JWK with `kid` set to
  `did:example:verifier-runtime-gate-issuer#key-1` and `alg` set to `ES256`;
- `MARTY_POSITIVE_GATE_ISSUER_KID`: that same verification-method ID;
- `MARTY_POSITIVE_GATE_ISSUER_SIGNER_ENDPOINT` and
  `MARTY_POSITIVE_GATE_ISSUER_SIGNER_AUTHENTICATION_KEY`: the issuer agent's
  authenticated IPC configuration;
- `MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK`: the holder agent's public P-256 JWK;
- `MARTY_TEST_WALLET_HOLDER_KID`: `did:example:runtime-gate-holder` or one of
  its fragment keys;
- `MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT` and
  `MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY`: the holder agent's
  authenticated IPC configuration.

Run `cargo run -p marty-test-wallet --bin marty-kms-positive-verifier-input`
after both agents are ready. The producer first verifies the issuer signature
against the supplied public key before asking the wallet to prepare a holder
proof. Either backend failing makes the command fail closed. Its output is a
fresh public input for the verifier probe, not a standalone custody or release
attestation. The integration runner pins the exact producer executable digest
and verifies the result against the released service image; live KMS provider,
tenant, wallet and release provenance still require their own evidence.


### Signer readiness and one-use offers

`GET /ready` succeeds only after the existing authenticated IPC holder probe
obtains a remote-KMS signature and verifies it against the configured public
JWK. Routine checks are single-flight and cache success or failure for at most
60 seconds, so repeated health polls do not spend all 128 uses of a scoped
one-hour leaf. A cancelled HTTP poll does not cancel the owned, bounded IPC probe; later
polls share its result. Failed probe tasks retain backoff rather than immediately
spending another token use. Errors return a generic 503 without KMS credentials.

Credential receipt always performs a fresh probe after validating the offer
and before exchanging its pre-authorized code; cached health cannot authorize
that exchange. This detects an already failed signer, not an atomic guarantee
that a provider cannot fail later. An actual signing failure invalidates health.

The signer does not mint or renew tokens. A nonrenewable, revoked or expired
leaf must be replaced by its governed owner under the existing scoped-token
lifecycle, with the signer restarted to consume the new configuration. No
software-key fallback or broader signing authority is introduced.


Request-object endpoint failures keep the wallet HTTP400 behavior and include an
optional `request_object_error` with the upstream `http_status` and allowlisted
public Flow error/detail identifiers. Error bodies are capped at4KiB; malformed,
oversized or unknown bodies reduce to status only. Dynamic provider suffixes,
URLs, JWTs and tokens are never copied. These are observations of request retrieval,
not a presentation submission or verifier decision. The actual previous server
subtype remains unknown until a fresh, separately owned run obtains that response.
