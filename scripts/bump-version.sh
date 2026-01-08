#!/usr/bin/env bash
#
# bump-version.sh - Bump version across marty-core workspace
#
# Usage: ./scripts/bump-version.sh <new-version>
# Example: ./scripts/bump-version.sh 0.2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print colored message
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check arguments
if [ $# -ne 1 ]; then
    error "Usage: $0 <new-version>\nExample: $0 0.2.0"
fi

NEW_VERSION="$1"

# Validate version format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error "Invalid version format. Expected: MAJOR.MINOR.PATCH (e.g., 0.2.0)"
fi

# Get current version
CURRENT_VERSION=$(grep '^version = ' "$REPO_ROOT/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/')
info "Current version: $CURRENT_VERSION"
info "New version: $NEW_VERSION"

# Confirm with user
read -p "Proceed with version bump? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    warn "Aborted by user"
    exit 0
fi

# Update workspace Cargo.toml
info "Updating workspace Cargo.toml..."
sed -i.bak "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" "$REPO_ROOT/Cargo.toml"
rm -f "$REPO_ROOT/Cargo.toml.bak"

# Update Cargo.lock
info "Updating Cargo.lock..."
cd "$REPO_ROOT"
cargo update --workspace

# Update CHANGELOGs
info "Preparing CHANGELOGs..."
for changelog in "$REPO_ROOT"/*/CHANGELOG.md "$REPO_ROOT/CHANGELOG.md"; do
    if [ -f "$changelog" ]; then
        # Add new version header if [Unreleased] exists
        if grep -q "## \[Unreleased\]" "$changelog"; then
            DATE=$(date +%Y-%m-%d)
            # Insert new version section after Unreleased
            sed -i.bak "/## \[Unreleased\]/a\\
\\
## [$NEW_VERSION] - $DATE" "$changelog"
            rm -f "$changelog.bak"
            info "Updated $(basename $(dirname $changelog))/CHANGELOG.md"
        fi
    fi
done

# Summary
info "Version bump complete!"
echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Run tests: cargo test --workspace --all-features"
echo "  3. Commit changes: git add -A && git commit -m 'chore: bump version to $NEW_VERSION'"
echo "  4. Create tag: git tag v$NEW_VERSION"
echo "  5. Push: git push && git push origin v$NEW_VERSION"
echo ""
warn "Remember to update CHANGELOG.md with actual changes before committing!"
