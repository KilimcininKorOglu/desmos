#!/usr/bin/env bash
# Pre-flight checks before tagging a release.
#
# Usage: ./scripts/release.sh 1.0.0
#
# Verifies:
#   1. Working tree is clean.
#   2. Current branch is main.
#   3. All workspace Cargo.toml versions match the target.
#   4. CHANGELOG.md has an entry for the target version.
#   5. cargo test --workspace passes.
#   6. cargo clippy passes.
#   7. cargo deny check passes.

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 1.0.0"
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

echo "=== Desmos Release Pre-Flight: ${TAG} ==="
echo

# 1. Clean working tree.
if [ -n "$(git status --porcelain)" ]; then
    fail "Working tree is not clean. Commit or stash changes first."
fi
pass "Working tree is clean"

# 2. On main branch.
BRANCH=$(git branch --show-current)
if [ "$BRANCH" != "main" ]; then
    fail "Not on main branch (current: ${BRANCH})"
fi
pass "On main branch"

# 3. Cargo.toml versions match.
MISMATCHED=0
for toml in Cargo.toml crates/*/Cargo.toml; do
    if [ ! -f "$toml" ]; then continue; fi
    # Check workspace version or package version.
    TOML_VERSION=$(grep -m1 '^version' "$toml" | sed 's/.*"\(.*\)".*/\1/' | head -1)
    if [ "$TOML_VERSION" != "$VERSION" ] && [ "$TOML_VERSION" != "" ]; then
        # Skip workspace references like version.workspace = true
        if echo "$TOML_VERSION" | grep -q "workspace"; then
            continue
        fi
        echo "  Version mismatch in $toml: got $TOML_VERSION, expected $VERSION"
        MISMATCHED=1
    fi
done
if [ "$MISMATCHED" -eq 1 ]; then
    fail "Cargo.toml versions do not match ${VERSION}"
fi
pass "All Cargo.toml versions match ${VERSION}"

# 4. CHANGELOG entry exists.
if ! grep -q "## \[${VERSION}\]" CHANGELOG.md; then
    fail "CHANGELOG.md has no entry for [${VERSION}]"
fi
pass "CHANGELOG.md has [${VERSION}] entry"

# 5. Tests pass.
echo "Running cargo test --workspace..."
if ! cargo test --workspace --quiet 2>/dev/null; then
    fail "cargo test --workspace failed"
fi
pass "All tests pass"

# 6. Clippy passes.
echo "Running cargo clippy..."
if ! cargo clippy --workspace -- -D warnings 2>/dev/null; then
    fail "cargo clippy found warnings"
fi
pass "Clippy clean"

# 7. cargo deny (if installed).
if command -v cargo-deny &>/dev/null; then
    echo "Running cargo deny check..."
    if ! cargo deny check bans licenses sources 2>/dev/null; then
        fail "cargo deny check failed"
    fi
    pass "cargo deny check passed"
else
    echo "SKIP: cargo-deny not installed"
fi

echo
echo "=== All pre-flight checks passed ==="
echo
echo "To create the release:"
echo "  git tag -a ${TAG} -m 'Release ${TAG}'"
echo "  git push origin ${TAG}"
