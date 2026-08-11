# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Distinguish a DTC's signed issuance-time `is_revoked` claim from current
  lifecycle status. Missing or unusable live evidence is explicit and no longer
  reported as passed; only fresh, exactly bound status from a governed,
  provenance-bearing orchestrator context can establish current-good status.

## [0.1.40] - 2026-08-10

### Added

- Add the framework-neutral canonical required-check reducer and explicit
  verification decision, check outcome, and category-summary domain types;
  reducer outputs are serialize-only and externally immutable.
- Add canonical decision-result assembly with exclusive authorization context,
  exact provenance, and cross-array component-reference validation.
- Add strict caller-fact deserialization for the canonical builder and expose it
  through the Python binding without accepting reducer-derived fields.

### Security

- Require verifier-governed CSCA trust anchors and a validated DTC Signer
  certificate chain before a Digital Travel Credential can be accepted.
- Require the critical ICAO DTC Signer EKU `2.23.136.1.1.12.1` and fail closed
  on missing, partial, malformed, mismatched, or wrong-purpose trust material.
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
