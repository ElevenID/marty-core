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
must use HTTPS. `MARTY_TEST_SIGNER_AGENT_KMS_BEARER_TOKEN` is optional for KMSs
that use bearer authentication; workload identity may be used instead. The KMS
endpoint receives `{ algorithm, key_id, signing_input }` and returns
`{ "signature": "<base64url raw ES256>" }`. Neither Marty process loads a
private key: the agent is only a policy and transport bridge to the KMS.

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
