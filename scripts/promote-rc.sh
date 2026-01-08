#!/usr/bin/env bash
#
# promote-rc.sh - Promote RC to stable release
#
# Usage: ./scripts/promote-rc.sh <rc-tag>
# Example: ./scripts/promote-rc.sh v0.2.0-rc.1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check arguments
if [ $# -ne 1 ]; then
    error "Usage: $0 <rc-tag>\nExample: $0 v0.2.0-rc.1"
fi

RC_TAG="$1"

# Validate RC tag format
if ! [[ "$RC_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]; then
    error "Invalid RC tag format. Expected: vMAJOR.MINOR.PATCH-rc.N (e.g., v0.2.0-rc.1)"
fi

# Extract stable version
STABLE_VERSION=$(echo "$RC_TAG" | sed 's/-rc\.[0-9]*$//')
VERSION_NUMBER="${STABLE_VERSION#v}"

info "RC Tag: $RC_TAG"
info "Stable Version: $STABLE_VERSION"

# Verify RC tag exists
cd "$REPO_ROOT"
if ! git rev-parse "$RC_TAG" >/dev/null 2>&1; then
    error "RC tag $RC_TAG does not exist"
fi

# Check if stable tag already exists
if git rev-parse "$STABLE_VERSION" >/dev/null 2>&1; then
    error "Stable tag $STABLE_VERSION already exists"
fi

# Verify we're on main branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    warn "Not on main branch (currently on $CURRENT_BRANCH)"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# Check working directory is clean
if ! git diff-index --quiet HEAD --; then
    error "Working directory is not clean. Commit or stash changes first."
fi

# Verify version in Cargo.toml matches
CARGO_VERSION=$(grep '^version = ' "$REPO_ROOT/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/')
if [ "$CARGO_VERSION" != "$VERSION_NUMBER" ]; then
    error "Version mismatch: Cargo.toml has $CARGO_VERSION but tag is $VERSION_NUMBER"
fi

# Run tests
info "Running tests..."
if ! cargo test --workspace --all-features; then
    error "Tests failed. Fix issues before promoting to stable."
fi

# Confirm promotion
echo ""
info "Ready to promote $RC_TAG to $STABLE_VERSION"
echo ""
echo "This will:"
echo "  1. Create stable tag: $STABLE_VERSION"
echo "  2. Push tag to origin"
echo "  3. Trigger stable release workflow"
echo ""
read -p "Proceed? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    warn "Aborted by user"
    exit 0
fi

# Create and push stable tag
info "Creating stable tag $STABLE_VERSION..."
git tag -a "$STABLE_VERSION" -m "Release $VERSION_NUMBER"

info "Pushing tag to origin..."
git push origin "$STABLE_VERSION"

info "Promotion complete!"
echo ""
echo "Stable release workflow should now be running."
echo "Check: https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\(.*\)\.git/\1/')/actions"
