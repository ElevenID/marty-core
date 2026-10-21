# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-21

### Added

- Add a language-neutral verification and quality behavior contract covering
  the retired unpublished Python MMF biometric adapter.

### Changed

- Run native and liveness feature tests, including malformed-request and mock
  provider parity cases, in the feature-combination gate.

### Fixed

- Load the packaged Rust extension through one package-relative adapter boundary
  and report the installed wheel version from distribution metadata.

## [0.1.0] - 2026-01-07

### Added
- Initial release of marty-biometrics
- Biometric liveness detection support
- Multi-provider architecture (OpenCV, SITA, NEC, IDEMIA)
- Python bindings via PyO3
- WebAssembly support via wasm-bindgen
- Native platform support
- Configurable biometric provider plugins
