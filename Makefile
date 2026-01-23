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
