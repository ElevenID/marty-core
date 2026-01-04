# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-01-03

### Added

- Initial extraction from marty-verification
- ECDSA support for P-256, P-384, P-521 curves
- EdDSA support for Ed25519 and Ed448
- RSA PKCS#1 v1.5 and PSS signature support
- X.509 certificate parsing and information extraction
- AES-GCM and AES-CBC symmetric encryption
- 3DES support for legacy BAC/PACE protocols
- HKDF and PBKDF2 key derivation
- ECDH key agreement (X25519)
- PKCS#12 bundle parsing
- CRL and OCSP response parsing
