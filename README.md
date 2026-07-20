# marty-core

Foundational Rust crates for the Marty ecosystem.

## Crates

| Crate | Description | Status |
|-------|-------------|--------|
| [`marty-crypto`](./marty-crypto) | Pure cryptographic primitives (x509, ECDSA, EdDSA, RSA, symmetric, KDF) | ✅ |
| [`marty-verification`](./marty-verification) | Trust chain verification for mDL (IACA), eMRTD (CSCA), DTC, Open Badges | ✅ |
| [`marty-secure-storage`](./marty-secure-storage) | Encrypted SQLite with platform keychain integration | 🚧 |
| [`marty-biometrics`](./marty-biometrics) | Biometric authentication (iOS Face ID, Touch ID, Android) | 🚧 |

**Note:** marty-core is the canonical source for all Rust verification and crypto libraries. All other projects ([marty-credentials](../marty-credentials), [marty-verifier](../marty-verifier)) depend on these crates.

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

All crates in this workspace use synchronized versioning following [SemVer](https://semver.org/). When marty-crypto has a breaking change, all crates bump their major/minor version together. Independent patch versions are allowed for bugfixes.

The authoritative current version is `[workspace.package].version` in the root
`Cargo.toml`. The four Python extension packages declare a dynamic version, so
Maturin derives their distribution versions from their corresponding Cargo
packages instead of a second hard-coded value.

### Version Strategy

- **Synchronized major.minor**: All crates move together (e.g., 0.1.0 → 0.2.0)
- **Independent patches**: Bugfixes can increment patch independently (e.g., 0.2.0 → 0.2.1 for one crate)
- **Tight coupling**: marty-verification depends on marty-crypto and shares the same version baseline

## Development

### Quick Start

```bash
# Using Make (recommended)
make test              # Run all tests
make check             # Run clippy + deny + fmt-check
make watch             # Watch mode for development
make ci                # Full CI pipeline

# Using Docker (isolated environment)
make docker-shell      # Start development container
make docker-test       # Run tests in container
make docker-watch      # Watch mode in container

# Direct cargo commands
cargo build --workspace
cargo test --workspace --features test-fixtures
cargo clippy --workspace --all-targets -- -D warnings
```

### Docker Development

The project includes a multi-stage Docker development environment:

```bash
# Build images
make docker-build              # Build all images
make docker-build-rust         # Rust-only (lighter weight)
make docker-build-full         # Full environment

# Development workflows
docker compose -f docker-compose.dev.yml up -d dev
docker compose -f docker-compose.dev.yml exec dev bash

# Inside container
cd /workspace/marty-core
cargo test --workspace --features test-fixtures
cargo watch -x check
```

### Testing

All tests require the `test-fixtures` feature which provides NIST PKITS certificates:

```bash
# Run all tests (145 tests)
cargo test --workspace --features test-fixtures

# Run specific test suite
cargo test -p marty-verification --test chain_validation_tests --features test-fixtures
cargo test -p marty-verification --test dtc_tests --features test-fixtures
cargo test -p marty-verification --test open_badges_tests --features test-fixtures

# Quick test (no fixtures)
cargo test --workspace --lib

# With nextest (faster)
cargo nextest run --workspace --features test-fixtures
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Lint
cargo clippy --workspace --all-targets -- -D warnings

# Security audit
cargo deny check
cargo audit

# Coverage report
cargo llvm-cov --workspace --features test-fixtures --html
```

See [Makefile](./Makefile) for all available targets.

## Release Process

Stable tags matching `vMAJOR.MINOR.PATCH` run the release workflow in
`.github/workflows/release.yml`. The tag version must match the workspace
version in `Cargo.toml`.

### Conventional Commits

All commits should follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New features
- `fix:` - Bug fixes  
- `docs:` - Documentation changes
- `chore:` - Maintenance tasks
- `BREAKING:` - Breaking changes

GitHub release notes are generated from the tagged commit history. Review and
update the versioned `CHANGELOG.md` in the release pull request.

### Creating a Stable Release

**1. Bump and review the version**

```bash
# Use the helper script to update workspace version
./scripts/bump-version.sh 0.2.0

# Review and update CHANGELOGs with actual changes
# Then commit
git add -A
git commit -m "chore: bump version to 0.2.0"
git push
```

**2. Run the required CI checks and tag the reviewed commit**

```bash
# After the version change is merged to main:
git tag v0.2.0 <reviewed-main-commit>
git push origin v0.2.0
```

The workflow tests the tagged source, builds the release artifacts, optionally
publishes registries when `ENABLE_PUBLIC_REGISTRY_PUBLISHING` is enabled, and
then creates the GitHub Release. A failed release must be corrected with a new
version; an existing tag must not be moved.

### Artifacts

The current GitHub release job produces:

- a **workspace source archive** and Cargo metadata;
- **Python wheels and source distributions** for marty-bindings,
  marty-verification, marty-biometrics, and marty-iso18013;
- a source **SPDX SBOM**, SHA-256 checksums, Sigstore bundles, and GitHub build
  provenance; and
- generated GitHub release notes.

Crates.io and PyPI publication are optional and remain gated by repository
configuration.

### Published-asset retention

Published release assets are retained. The former scheduled workflow that
deleted assets from older releases has been retired, and CI rejects workflows
that reintroduce release-asset deletion operations.

The current release workflow does not yet provide terminal immutable-release
finalization, so this repository does not claim that the full pipeline is
immutable. Until that hardening is complete, maintainers must treat published
tags and assets as append-only and issue a new version for corrections.

## License

Licensed under MIT OR Apache-2.0 at your option.
