#!/usr/bin/env bash
#
# test-feature-combinations.sh - Validate critical Cargo feature combinations
#
# Usage:
#   bash ./scripts/test-feature-combinations.sh
#   INCLUDE_SYSTEM_COMBOS=1 bash ./scripts/test-feature-combinations.sh
#
# The default matrix focuses on portable, high-value combinations that catch
# cross-feature regressions without requiring NFC/BLE system libraries.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INCLUDE_SYSTEM_COMBOS="${INCLUDE_SYSTEM_COMBOS:-0}"
MATRIX_CARGO_TARGET_DIR="${MATRIX_CARGO_TARGET_DIR:-$REPO_ROOT/target/feature-matrix}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
step() { echo -e "${BLUE}[STEP]${NC} $1"; }

mkdir -p "$MATRIX_CARGO_TARGET_DIR"
export CARGO_TARGET_DIR="$MATRIX_CARGO_TARGET_DIR"

PASS=0
FAIL=0
XFAIL=0

run_check() {
    local label="$1"
    shift

    step "$label"
    echo "  $*"
    if ( cd "$REPO_ROOT" && "$@" ); then
        info "Passed: $label"
        ((PASS++)) || true
    else
        echo -e "${RED}[FAIL]${NC} $label"
        ((FAIL++)) || true
    fi
}

# run_check_xfail: expect the command to fail (non-zero exit).
run_check_xfail() {
    local label="$1"
    shift

    step "$label (expect failure)"
    echo "  $*"
    if ( cd "$REPO_ROOT" && "$@" ) 2>/dev/null; then
        echo -e "${RED}[FAIL]${NC} UNEXPECTED PASS: $label — should have failed"
        ((FAIL++)) || true
    else
        info "Expected failure confirmed: $label"
        ((XFAIL++)) || true
    fi
}

info "Running marty-core feature combination matrix"
info "Repository root: $REPO_ROOT"
info "Cargo target dir: $CARGO_TARGET_DIR"

# =============================================================================
# 1. marty-crypto — algorithm isolation
# =============================================================================
info "── marty-crypto ──"

run_check \
    "marty-crypto: ecdsa alone" \
    cargo check -p marty-crypto --no-default-features --features ecdsa

run_check \
    "marty-crypto: eddsa alone" \
    cargo check -p marty-crypto --no-default-features --features eddsa

run_check \
    "marty-crypto: bbs standalone" \
    cargo check -p marty-crypto --no-default-features --features bbs

run_check \
    "marty-crypto: symmetric + kdf" \
    cargo check -p marty-crypto --no-default-features --features symmetric,kdf

run_check \
    "marty-crypto: default features" \
    cargo test -p marty-crypto

run_check \
    "marty-crypto: explicit algorithm mix (ecdsa,rsa,x509)" \
    cargo test -p marty-crypto --no-default-features --features ecdsa,rsa,x509

run_check \
    "marty-crypto: full feature set" \
    cargo test -p marty-crypto --no-default-features --features full

# =============================================================================
# 2. marty-verification — trust chain isolation + clients
# =============================================================================
info "── marty-verification ──"

run_check \
    "marty-verification: iaca chain only" \
    cargo check -p marty-verification --no-default-features --features iaca

run_check \
    "marty-verification: csca chain only" \
    cargo check -p marty-verification --no-default-features --features csca

run_check \
    "marty-verification: eudi chain only" \
    cargo check -p marty-verification --no-default-features --features eudi

run_check \
    "marty-verification: iaca + csca together" \
    cargo check -p marty-verification --no-default-features --features iaca,csca

run_check \
    "marty-verification: default features" \
    cargo build -p marty-verification

run_check \
    "marty-verification: full client stack" \
    cargo build -p marty-verification --no-default-features --features full

run_check \
    "marty-verification: Python bindings" \
    cargo check -p marty-verification --features python

# =============================================================================
# 3. marty-secure-storage
# =============================================================================
info "── marty-secure-storage ──"

run_check \
    "marty-secure-storage: sqlcipher backend" \
    cargo check -p marty-secure-storage --features sqlcipher

# =============================================================================
# 4. marty-oid4vci — role/format isolation
# =============================================================================
info "── marty-oid4vci ──"

run_check \
    "marty-oid4vci: issuer role alone" \
    cargo check -p marty-oid4vci --no-default-features --features issuer

run_check \
    "marty-oid4vci: verifier role alone" \
    cargo check -p marty-oid4vci --no-default-features --features verifier

run_check \
    "marty-oid4vci: issuer + verifier dual-role" \
    cargo check -p marty-oid4vci --no-default-features --features issuer,verifier

run_check \
    "marty-oid4vci: default features" \
    cargo check -p marty-oid4vci

run_check \
    "marty-oid4vci: issuer + mDoc + ZK mock" \
    env USE_ZK_MOCK=1 cargo test -p marty-oid4vci --no-default-features --features issuer,mso_mdoc,zk_mdoc

run_check \
    "marty-oid4vci: verifier + wallet + all formats" \
    cargo check -p marty-oid4vci --no-default-features --features verifier,wallet,jwt_vc_json,sd_jwt,mso_mdoc

# =============================================================================
# 5. marty-zkp — mock guard validation
# =============================================================================
info "── marty-zkp ──"

run_check_xfail \
    "marty-zkp: zk-mock must fail in release mode" \
    cargo build -p marty-zkp --features zk-mock --release

run_check \
    "marty-zkp: zk-mock debug build" \
    env USE_ZK_MOCK=1 cargo check -p marty-zkp --features zk-mock

# =============================================================================
# 6. marty-iso18013 — Python + transport isolation
# =============================================================================
info "── marty-iso18013 ──"

run_check \
    "marty-iso18013: Python bindings" \
    cargo check -p marty-iso18013 --features python

# =============================================================================
# 7. marty-biometrics — provider/platform combos
# =============================================================================
info "── marty-biometrics ──"

run_check \
    "marty-biometrics: Python bindings" \
    cargo check -p marty-biometrics --no-default-features --features python

run_check \
    "marty-biometrics: native + liveness" \
    cargo check -p marty-biometrics --no-default-features --features native,liveness

run_check \
    "marty-biometrics: full inference stack" \
    cargo check -p marty-biometrics --no-default-features --features full

# =============================================================================
# 8. marty-bindings — aggregator
# =============================================================================
info "── marty-bindings ──"

run_check \
    "marty-bindings: default features" \
    cargo check -p marty-bindings

run_check \
    "marty-bindings: async split" \
    cargo check -p marty-bindings --no-default-features --features async

# =============================================================================
# 9. System-dependent combos (opt-in)
# =============================================================================
if [[ "$INCLUDE_SYSTEM_COMBOS" == "1" ]]; then
    info "── system-dependent combos ──"
    run_check \
        "marty-iso18013: BLE + NFC transports" \
        cargo build -p marty-iso18013 --features all-transports
else
    warn "Skipping system-dependent transport combo (set INCLUDE_SYSTEM_COMBOS=1 to enable all-transports build)"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
info "════════════════════════════════════════════════════"
info "Feature matrix results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${YELLOW}${XFAIL} expected failures${NC}"
info "════════════════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}[ERROR]${NC} $FAIL combination(s) failed"
    exit 1
fi
info "All feature combinations passed"
