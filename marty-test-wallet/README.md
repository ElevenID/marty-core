# Marty Browser Test Wallet

This non-production wallet gives Playwright a user-visible browser surface for
the Marty credential lifecycle gate. It uses `marty-oid4vci` for protocol and
cryptographic operations and supports:

- OID4VCI pre-authorized SD-JWT VC and W3C VC-JWT receipt
- signed OpenID4VP request objects with DCQL
- SD-JWT selective disclosure with nonce/audience key binding
- W3C VC-JWT presentation for `jwt_vc_json` DCQL queries

Private keys and credential material remain in the local wallet process. The
browser API returns display metadata only. Run it with:

```text
cargo run -p marty-test-wallet
```

The default browser URL is `http://127.0.0.1:8787`.
