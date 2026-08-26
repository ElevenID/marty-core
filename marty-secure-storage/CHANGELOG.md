# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Track offline reporting attempts and acknowledgements independently from trust synchronization, including atomic exact-batch acknowledgement and durable retry metadata.

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
