# Verification-only RustCrypto ECDSA

Source: RustCrypto `ecdsa` 0.17.0, crates.io archive SHA-256
`c0681a4fc24c767085329728d8dfba959af91228aa4610cca4f8ce317ba46ae0`.
The upstream VCS receipt and both licenses are retained.

This owned patch restores separate `verifying` and `signing` capabilities.
`algorithm` retains upstream combined behavior; `signing` implies `verifying`.
Code changes are limited to Cargo features, module/function cfg gates, and
conditional imports. One trailing space in the upstream changelog is removed.
The verification implementation and scalar conversion are unchanged upstream
code. No arithmetic or protocol-test assertion is replaced. Production Marty
selects `verifying` without `signing`, `algorithm`, or RFC 6979 signing support.

Upstream Cargo.lock and Cargo.toml.orig are omitted: the selected consuming
workspace lock is authoritative, including patched crypto-bigint 0.7.6. There
are no advisory suppressions. Downstream consumers must select this same shared
package from the core source revision; dependency-root patches are not transitive.
