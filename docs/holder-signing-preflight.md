# Verify the holder signing path before credential operations

`marty-test-holder-signing-probe` requests a fresh domain-separated challenge
signature through the same authenticated OS-local IPC used by the browser test
wallet. The existing `marty-test-signer-agent` performs the remote HTTPS operation.
The probe verifies ES256 with the configured public holder key using Core's JOSE
verifier. A healthy socket or KMS health response alone cannot pass this check.

Build it with the existing wallet binaries:

```sh
cargo build --locked --release -p marty-test-wallet --bins
```

Run the probe inside the governed capture container with the existing wallet-side
environment, after the scoped signer agent has bound its IPC endpoint:

```sh
marty-test-holder-signing-probe
```

It accepts no command-line arguments. Its only configuration inputs are
`MARTY_TEST_WALLET_HOLDER_SIGNER_ENDPOINT`,
`MARTY_TEST_WALLET_HOLDER_SIGNER_AUTHENTICATION_KEY`,
`MARTY_TEST_WALLET_HOLDER_KID`, and
`MARTY_TEST_WALLET_HOLDER_PUBLIC_JWK`. Keep the KMS token in the signer agent's
separate environment; do not give it to the probe or browser. Preserve the
existing private socket directory, fresh authentication key, process ownership
and shutdown rules. No additional HTTP route or local private-key capability is
introduced by this binary.

A successful JSON receipt has scope `HOLDER_SIGNING_PREFLIGHT_ONLY`,
`productionDemoReady=false`, and the public challenge, signature, holder ID and
public P-256 coordinates needed for independent verification. Arbitrary JWK
metadata is excluded. Private fields, duplicate members, algorithm/use confusion
and a wrong curve fail configuration validation before IPC. An authenticated
signature from another key fails verification. Errors emit one generic message
and a nonzero exit, without raw environment or remote response content.

The challenge is a non-JWT string with a dedicated protocol domain and fresh UUID.
It is not a credential, authentication assertion, credential proof or issuance
request. Retain the receipt only with its actual run, exact image/source identity,
configured holder binding and beta release observations. Verify the public key
against the operator-owned KMS public binding; do not treat a caller-supplied key
or a receipt copied from another run as current evidence. Signing success cannot
qualify issuance, wallet receipt, verification policy, Canvas, a recording or the
demo portfolio.

Focused checks use the real authenticated local transport and Core's shared
marked disposable OpenBao fixture to cover independent verification/freshness,
another signing key, and invalid public configuration. These fixtures are
engineering tests, not production demo results. Run their focused live-fixture
lane with `MARTY_TEST_HOLDER_SIGNING_PROBE_ONLY=1 bash scripts/test_remote_issuer_live_kms.sh`.
The normal live-KMS CI lane also executes them; unconfigured offline runs explicitly
ignore the two remote-signing cases. No local private-key generator is added.
Git for Windows preserves Docker container paths, normalizes captured line endings,
and uses a native public-CA filename. Its disposable-CA curl requests use the
documented [best-effort Schannel revocation option](https://curl.se/docs/manpage.html#--ssl-revoke-best-effort)
while retaining CA/hostname verification; fixture requests explicitly bypass proxies.
Failure diagnostics report state instead of dumping dev-mode logs with unseal material.
The binary still needs integration
into an approved source-bound capture image and a real scoped remote-signing run.
Do not relabel existing older image receipts or approved Core pins as containing
this new binary.
