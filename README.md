# marty-core

Foundational Rust crates for the Marty ecosystem.

## Crates

| Crate | Description | Status |
|-------|-------------|--------|
| [`marty-crypto`](./marty-crypto) | Pure cryptographic primitives (x509, ECDSA, EdDSA, RSA, symmetric, KDF) | 🚧 |
| [`marty-verification`](./marty-verification) | Trust chain verification for mDL (IACA) and eMRTD (CSCA) | 🚧 |
| [`marty-secure-storage`](./marty-secure-storage) | Encrypted SQLite with platform keychain integration | 🚧 |

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    marty-secure-storage                      │
│              (Encrypted storage + keychain)                  │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                    marty-verification                        │
│       (IACA/CSCA trust chains, PKD clients, mDoc)           │
└──────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│                       marty-crypto                           │
│    (X.509, ECDSA, EdDSA, RSA, AES, HKDF, certificate ops)   │
└──────────────────────────────────────────────────────────────┘
```

## Versioning

Each crate is versioned independently following [SemVer](https://semver.org/):

- `marty-crypto` - Core crypto primitives, high stability requirement
- `marty-verification` - Verification logic, depends on marty-crypto
- `marty-secure-storage` - Storage layer, depends on marty-crypto

## Development

```bash
# Build all crates
cargo build --workspace

# Test all crates  
cargo test --workspace

# Test specific crate
cargo test -p marty-crypto

# Check formatting
cargo fmt --all -- --check

# Lint
cargo clippy --workspace --all-targets
```

## Publishing

Crates are published to a private registry. To release:

1. Update version in crate's `Cargo.toml`
2. Update `CHANGELOG.md` in crate directory
3. Tag with `<crate-name>-v<version>` (e.g., `marty-crypto-v0.2.0`)
4. CI will publish automatically

## License

Licensed under MIT OR Apache-2.0 at your option.
