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

**Current Version:** 0.1.0

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

This workspace uses an automated release pipeline with RC (Release Candidate) staging:

### Conventional Commits

All commits should follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New features
- `fix:` - Bug fixes  
- `docs:` - Documentation changes
- `chore:` - Maintenance tasks
- `BREAKING:` - Breaking changes

Changelogs are automatically generated from commit messages.

### Creating a Release

**1. Bump Version**

```bash
# Use the helper script to update workspace version
./scripts/bump-version.sh 0.2.0

# Review and update CHANGELOGs with actual changes
# Then commit
git add -A
git commit -m "chore: bump version to 0.2.0"
git push
```

**2. Create RC Release**

```bash
# Create and push RC tag
git tag v0.2.0-rc.1
git push origin v0.2.0-rc.1

# This triggers:
# - Build all artifacts (Rust crates, Python wheels, WASM)
# - Upload to GitHub pre-release
# - Generate changelog from commits
```

**3. Test RC Release**

- Download and test artifacts from GitHub Releases
- Verify functionality across platforms
- Create additional RCs if needed: `v0.2.0-rc.2`, etc.

**4. Promote to Stable**

```bash
# Use helper script to promote RC to stable
./scripts/promote-rc.sh v0.2.0-rc.1

# This:
# - Runs tests
# - Creates stable tag v0.2.0
# - Triggers stable release workflow
# - Auto-triggers marty-credentials and marty-verifier updates
```

### Automated Downstream Updates

When a stable marty-core release is published:

1. **marty-credentials** and **marty-verifier** are automatically notified
2. Their workflows update dependencies to the new marty-core version
3. Tests run automatically
4. If tests pass: Version bumps and new release created automatically
5. If tests fail: GitHub Issue created for manual intervention

### Artifacts

Each release produces:

- **Rust source tarballs** for all 4 crates
- **Python wheels** for marty-biometrics (Linux, macOS, Windows × x86_64, aarch64)
- **WASM packages** for marty-biometrics (web, nodejs, bundler targets)
- **SHA256 checksums** for all artifacts
- **Auto-generated changelog** from commits

All artifacts are published to **GitHub Releases only** (not crates.io or PyPI).

### Artifact Cleanup

- Pre-1.0 releases: Assets deleted after 6 months
- Last 3 RC releases: Always kept
- 1.0+ releases: Kept indefinitely

Cleanup runs automatically on the 1st of each month.

## License

Licensed under MIT OR Apache-2.0 at your option.
