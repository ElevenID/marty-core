# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Fail closed when an Open Badge declares unavailable, unsupported, malformed, or undecodable credential status evidence.
- Require Open Badge issuer proofs to use assertion authorization and reject wrong-controller, unlinked, or ambiguously resolved methods.
- Require separately authenticated status-authority provenance, secured status-list credentials, signed/cache freshness, exact issuer/URL/purpose bindings, and bounded normative Bitstring Status List processing before a positive Open Badge status result.

## [0.1.0] - 2026-01-07

### Added
- Initial release of marty-verification
- Trust anchor management (IACA, CSCA)
- eMRTD verification support
- mDL (mobile driver's license) verification
- Open Badges v2/v3 verification
- Digital Travel Credential (DTC) support
- JWK (JSON Web Key) implementation
- MRZ parsing and validation
- ASN.1 parsing for ICAO documents
- PKD clients (AAMVA DTS, ICAO PKD)
- Python bindings for verification functionality
