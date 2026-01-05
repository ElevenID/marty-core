.PHONY: all dev-python build-python build-wasm test test-rust test-python lint clean help

# Default target
all: test

# ============================================================================
# Development
# ============================================================================

## Install Python bindings in development mode
dev-python:
	maturin develop --features python

## Install Python bindings with all features
dev-python-full:
	maturin develop --features "python,liveness"

# ============================================================================
# Build
# ============================================================================

## Build Python wheel (release)
build-python:
	maturin build --release --features python

## Build WASM package for web
build-wasm:
	wasm-pack build --target web --features wasm --no-default-features

## Build WASM package for Node.js
build-wasm-node:
	wasm-pack build --target nodejs --features wasm --no-default-features

## Build WASM package for bundlers
build-wasm-bundler:
	wasm-pack build --target bundler --features wasm --no-default-features

## Build native library (for Rust consumers)
build-native:
	cargo build --release --features native

# ============================================================================
# Testing
# ============================================================================

## Run all tests
test: test-rust test-python

## Run Rust tests
test-rust:
	cargo test --features "native,liveness"

## Run Python tests
test-python: dev-python
	pytest tests/ -v

## Run Rust tests with coverage
test-coverage:
	cargo llvm-cov --features "native,liveness" --html

# ============================================================================
# Linting & Formatting
# ============================================================================

## Lint Rust code
lint:
	cargo clippy --features "native,liveness" -- -D warnings

## Format Rust code
fmt:
	cargo fmt

## Check Rust formatting
fmt-check:
	cargo fmt -- --check

## Lint Python code
lint-python:
	ruff check python/

## Format Python code
fmt-python:
	ruff format python/

# ============================================================================
# Documentation
# ============================================================================

## Build Rust documentation
doc:
	cargo doc --no-deps --features "native,liveness"

## Build and open Rust documentation
doc-open:
	cargo doc --no-deps --open --features "native,liveness"

# ============================================================================
# Cleanup
# ============================================================================

## Clean build artifacts
clean:
	cargo clean
	rm -rf target/
	rm -rf pkg/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# ============================================================================
# Help
# ============================================================================

## Show this help
help:
	@echo "marty-biometrics - Biometric verification for the Marty ecosystem"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Development:"
	@echo "  dev-python       Install Python bindings in development mode"
	@echo "  dev-python-full  Install Python bindings with all features"
	@echo ""
	@echo "Build:"
	@echo "  build-python     Build Python wheel (release)"
	@echo "  build-wasm       Build WASM package for web"
	@echo "  build-wasm-node  Build WASM package for Node.js"
	@echo "  build-native     Build native library (for Rust consumers)"
	@echo ""
	@echo "Testing:"
	@echo "  test             Run all tests"
	@echo "  test-rust        Run Rust tests"
	@echo "  test-python      Run Python tests"
	@echo "  test-coverage    Run Rust tests with coverage"
	@echo ""
	@echo "Linting:"
	@echo "  lint             Lint Rust code"
	@echo "  lint-python      Lint Python code"
	@echo "  fmt              Format Rust code"
	@echo "  fmt-python       Format Python code"
	@echo ""
	@echo "Documentation:"
	@echo "  doc              Build Rust documentation"
	@echo "  doc-open         Build and open Rust documentation"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean            Clean build artifacts"
