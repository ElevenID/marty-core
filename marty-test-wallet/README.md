# Marty Browser Test Wallet

This non-production wallet gives Playwright a user-visible browser surface for
the Marty credential lifecycle gate. It uses `marty-oid4vci` for protocol and
cryptographic operations and supports only:

- OID4VCI pre-authorized SD-JWT VC receipt
- signed OpenID4VP request objects with DCQL
- SD-JWT selective disclosure with nonce/audience key binding

Private keys and credential material remain in the local wallet process. The
browser API returns display metadata only. Run it with:

```text
cargo run -p marty-test-wallet
```

The default browser URL is `http://127.0.0.1:8787`.
