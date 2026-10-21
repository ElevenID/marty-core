# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-21

### Added

- Expose shared, fallible platform and process-local keyring initialization,
  scoped database extension access, and the common PII encryption boundary for
  Rust service consumers.

### Changed

- Centralize schema migrations and trust-package provenance decoding so every
  storage path applies the same validation and consistency rules.

### Security

- Preserve governed trust provenance, signed expiry, signer-transition state,
  and legacy-write protections through transactional, repeatable migrations;
  incomplete pre-release provenance remains unusable rather than synthesized.

## [0.1.61] - 2026-08-27

### Fixed

- Track offline reporting attempts and acknowledgements independently from trust synchronization, including atomic exact-batch acknowledgement and durable retry metadata.
- Allow an explicitly installed process-local credential store for headless
  qualification while retaining the platform keychain as the production
  default.

## [0.1.40] - 2026-08-10

### Security

- Persist and atomically enforce monotonic Open Badge trust-package provenance so replayed, conflicting, or cross-domain key sets cannot replace active trust state.
- Extend that authority to the complete IACA, CSCA, DSC, and Open Badge trust package so bounded signed/import clock skew, signed expiry, records, package state, sync metadata, and a minimized audit outcome are enforced and commit or roll back together.
- Require explicit signed next-signer and stable recovery-signer policy for key transitions, consume authorizations atomically, and reject unauthorized rotation or recovery without mutating trust state.

## [0.1.0] - 2026-01-07

### Added
- Initial release of marty-secure-storage
- SQLite database with SQLCipher encryption support
- Secure keychain integration for credential storage
- Cross-platform secure storage (macOS, Windows, Linux)
- Database schema with migrations
- Encryption layer for sensitive data
- Model definitions for stored data
