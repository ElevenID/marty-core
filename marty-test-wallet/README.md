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
issuer-key trust set. The signer agent listens only on the fixed
`http://127.0.0.1:8788/sign` sidecar endpoint and owns all remote KMS
connectivity and policy; the browser wallet cannot send signing requests to
operator- or request-selected network locations.

- `MARTY_TEST_WALLET_HOLDER_KID`: signer-owned holder key identifier.
- `MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK`: public-only P-256 JWK JSON.
- `MARTY_TEST_WALLET_HOLDER_SIGNER_TOKEN`: a canonical base64url encoding of
  exactly 32 random bytes. The wallet sends it as a sensitive bearer credential;
  the loopback sidecar must reject every request without the exact value.
- `MARTY_TEST_WALLET_TRUSTED_ISSUER_KEYS`: JSON array of exact trust entries,
  each with `issuer`, optional `key_id`, `algorithm`, and `public_jwk`.

After authenticating the bearer credential, the sidecar receives `algorithm`,
`key_id`, and base64url `signing_input`, and returns
`{ "signature": "<base64url raw ES256>" }`. Generate a fresh token for each
test run and expose it only to the wallet and signer processes.

The browser API returns display metadata only. Run it after configuring those
values:

```text
cargo run -p marty-test-wallet
```

The default browser URL is `http://127.0.0.1:8787`.
