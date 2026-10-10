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
