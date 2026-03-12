# Makefile for marty-core development
#
# Common targets:
#   make test       - Run all tests
#   make check      - Run clippy and deny
#   make dev        - Start development container
#   make ci         - Run full CI suite
#
# Docker targets:
#   make docker-build  - Build development images
#   make docker-shell  - Shell into dev container

.PHONY: all test check fmt lint deny build clean dev ci
.PHONY: docker-build docker-shell docker-test docker-watch docker-clean
.PHONY: conformance conformance-crypto conformance-iso18013 conformance-zkp
.PHONY: conformance-verification conformance-oid4vci

# Default target
all: check test

# =============================================================================
# Local development (no Docker)
# =============================================================================

# Run all tests with test-fixtures feature
test:
	cargo nextest run --workspace --features test-fixtures

# Quick test without fixtures
test-quick:
	cargo test --workspace --lib

# Run clippy linter
lint:
	cargo clippy --workspace --all-targets -- -D warnings

# Check dependencies for security/license issues
deny:
	cargo deny check

# Format code
fmt:
	cargo fmt --all

# Format check (CI mode)
fmt-check:
	cargo fmt --all -- --check

# Run all checks (lint + deny + format check)
check: lint deny fmt-check

# Build all crates
build:
	cargo build --workspace

# Build release
build-release:
	cargo build --workspace --release

# Clean build artifacts
clean:
	cargo clean

# Watch mode for development
watch:
	cargo watch -x "check --workspace"

# Watch tests
watch-test:
	cargo watch -x "test --workspace --features test-fixtures"

# =============================================================================
# Documentation
# =============================================================================

# Generate documentation
doc:
	cargo doc --workspace --no-deps --open

# Generate documentation (no open)
doc-build:
	cargo doc --workspace --no-deps

# =============================================================================
# Coverage
# =============================================================================

# Run tests with coverage (requires cargo-llvm-cov)
coverage:
	cargo llvm-cov --workspace --features test-fixtures --html

# Coverage report to terminal
coverage-text:
	cargo llvm-cov --workspace --features test-fixtures

# =============================================================================
# Security Audit
# =============================================================================

# Run security audit
audit:
	cargo audit

# Check for outdated dependencies
outdated:
	cargo outdated

# =============================================================================
# Miri (unsafe code verification)
# =============================================================================

# Run miri on crypto crate (nightly required)
miri:
	cargo +nightly miri test -p marty-crypto

# =============================================================================
# Docker Development
# =============================================================================

# Build all Docker images
docker-build:
	docker compose -f docker-compose.dev.yml build

# Build specific target
docker-build-rust:
	docker build --target rust-dev -t marty-dev:rust -f docker/Dockerfile.dev .

docker-build-python:
	docker build --target python-dev -t marty-dev:python -f docker/Dockerfile.dev .

docker-build-full:
	docker build --target full-dev -t marty-dev:full -f docker/Dockerfile.dev .

# Start development container
docker-shell:
	docker compose -f docker-compose.dev.yml run --rm dev

# Start rust-only container
docker-rust:
	docker compose -f docker-compose.dev.yml run --rm rust

# Run tests in container
docker-test:
	docker compose -f docker-compose.dev.yml run --rm test-runner

# Start watch mode in container
docker-watch:
	docker compose -f docker-compose.dev.yml up watch

# Clean up Docker resources
docker-clean:
	docker compose -f docker-compose.dev.yml down -v
	docker image rm marty-dev:rust marty-dev:python marty-dev:full 2>/dev/null || true

# =============================================================================
# CI Pipeline
# =============================================================================

# Full CI pipeline (mirrors GitHub Actions)
ci: fmt-check lint deny test
	@echo "✅ All CI checks passed!"

# CI with coverage
ci-coverage: fmt-check lint deny coverage-text
	@echo "✅ All CI checks with coverage passed!"

# =============================================================================
# Release
# =============================================================================

# Prepare for release (run all checks + build release)
release-check: ci build-release doc-build
	@echo "✅ Ready for release!"

# =============================================================================
# Help
# =============================================================================

help:
	@echo "marty-core Makefile"
	@echo ""
	@echo "Development:"
	@echo "  make test          Run all tests"
	@echo "  make test-quick    Run quick tests (no fixtures)"
	@echo "  make check         Run lint + deny + fmt-check"
	@echo "  make watch         Watch mode for development"
	@echo "  make watch-test    Watch mode for tests"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build  Build all Docker images"
	@echo "  make docker-shell  Start development container"
	@echo "  make docker-test   Run tests in container"
	@echo "  make docker-watch  Start watch mode in container"
	@echo "  make docker-clean  Clean up Docker resources"
	@echo ""
	@echo "CI/Release:"
	@echo "  make ci            Run full CI pipeline"
	@echo "  make ci-coverage   CI with coverage report"
	@echo "  make release-check Prepare for release"
	@echo ""
	@echo "Other:"
	@echo "  make doc           Generate and open documentation"
	@echo "  make coverage      Generate HTML coverage report"
	@echo "  make audit         Security audit"
	@echo "  make miri          Run miri (unsafe verification)"
	@echo "  make conformance               Run all conformance test suites"
	@echo "  make conformance-crypto        Phase 1: NIST CAVP crypto primitives"
	@echo "  make conformance-iso18013      Phase 2: ISO 18013-5 CBOR/COSE/mDoc structure"
	@echo "  make conformance-verification  Phase 2/4: MDL trust-chain + Open Badges 3.0"
	@echo "  make conformance-oid4vci       Phase 3: OID4VCI SD-JWT-VC format"
	@echo "  make conformance-zkp           Phase 6: Longfellow ZK (Ligero)"

# =============================================================================
# Conformance Tests
# =============================================================================

# Run all conformance test suites
# Phase 1: crypto, Phase 2: ISO/mDoc + mDoc structure + MDL/OB3 verification,
# Phase 3: SD-JWT VC, Phase 6: Longfellow ZK
conformance: conformance-crypto conformance-iso18013 conformance-verification conformance-oid4vci conformance-zkp
	@echo "✅ All conformance tests passed!"

# Phase 1 — Cryptographic primitive conformance (NIST CAVP / IETF RFCs)
#   CAVP SHA-256/384/512, HMAC-SHA-256/384/512 (FIPS 180-4 / RFC 4231)
#   CAVP ECDSA P-256/384 (FIPS 186-4)
#   CAVP ECDH P-256/384/X25519 (RFC 7748)
#   CAVP AES-256-GCM (FIPS 197 / SP 800-38D)
#   RFC 5869 HKDF test vectors
#   RSA PKCS#1 v1.5 / PSS round-trip + rejection tests (FIPS 186-4)
conformance-crypto:
	@echo "==> Running Phase 1: crypto conformance tests"
	cargo test -p marty-crypto \
	    cavp_sha_hmac \
	    cavp_ecdsa \
	    cavp_ecdh \
	    cavp_aes_gcm \
	    rfc5869_hkdf \
	    cavp_rsa \
	    -- --nocapture

# Phase 2 — ISO 18013-5 / mDoc conformance (RFC 8949 CBOR, RFC 9052 COSE, selective disclosure, session)
#   + ISO 18013-5 data-model structure tests (namespace constants, DeviceEngagement, protocol types)
conformance-iso18013:
	@echo "==> Running Phase 2: ISO mDoc conformance tests"
	cargo test -p marty-iso18013 \
	    cbor_conformance \
	    cose_conformance \
	    selective_disclosure \
	    session_conformance \
	    mdoc_structure \
	    -- --nocapture

# Phase 2 (continued) — MDL trust-chain + OB3 credential verification conformance
#   mdl_conformance:         X5Chain/IACA/MdlVerificationResult conformance (ISO 18013-5 §9)
#   open_badges_conformance: 1EdTech Open Badges 3.0 + OB2 backward-compat conformance
conformance-verification:
	@echo "==> Running Phase 2/4: verification conformance tests"
	cargo test -p marty-verification \
	    mdl_conformance \
	    open_badges_conformance \
	    -- --nocapture

# Phase 3 — OID4VCI SD-JWT-VC credential format conformance
#   sd_jwt_vc_conformance: sign_sd_jwt engine — IETF flat, W3C VCDM v2, SD payload, credential_id
conformance-oid4vci:
	@echo "==> Running Phase 3: OID4VCI SD-JWT-VC conformance tests"
	cargo test -p marty-oid4vci \
	    sd_jwt_vc_conformance \
	    -- --nocapture

# Phase 6 — Longfellow ZK (Ligero) conformance
#   ZkPredicate wire IDs and round-trips (§1)
#   ZkTranscript nonce binding and isolation (§2)
#   Prove → Verify round-trips for all predicate variants (§3)
#   Soundness / rejection: empty inputs, empty proof, tampered proof (§4)
#   MdocZkInput helper construction from raw fields and COSE_Sign1 (§5)
#   prove_by_id / verify_by_id convenience APIs (§6)
#   Privacy: proof must not contain plaintext claim value (§7)
#   ZkError model mapping (§8)
conformance-zkp:
	@echo "==> Running Phase 6: Longfellow ZK conformance tests"
	USE_ZK_MOCK=1 cargo test -p marty-zkp --test conformance -- --nocapture
