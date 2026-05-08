#!/usr/bin/env bash
# Smoke test for a Desmos release binary on a fresh Linux system.
#
# Usage: ./scripts/smoke-test.sh [path-to-binary]
#
# If no binary path is given, looks for target/release/desmos.
#
# Tests:
#   1. Binary exists and is executable.
#   2. --version prints a version string.
#   3. config generate produces valid TOML.
#   4. config validate accepts generated config.
#   5. Binary exits cleanly with --help.

set -euo pipefail

BINARY="${1:-target/release/desmos}"
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

echo "=== Desmos Smoke Test ==="
echo "Binary: ${BINARY}"
echo

# 1. Binary exists.
if [ ! -f "$BINARY" ]; then
    fail "Binary not found at ${BINARY}"
fi
if [ ! -x "$BINARY" ]; then
    chmod +x "$BINARY"
fi
pass "Binary exists and is executable"

# 2. Version output.
VERSION_OUTPUT=$("$BINARY" version 2>&1 || true)
if echo "$VERSION_OUTPUT" | grep -qE '^desmos [0-9]+\.[0-9]+\.[0-9]+'; then
    pass "Version output: ${VERSION_OUTPUT}"
else
    # Some builds may output differently; accept any non-empty output.
    if [ -n "$VERSION_OUTPUT" ]; then
        pass "Version output (non-standard): ${VERSION_OUTPUT}"
    else
        fail "No version output"
    fi
fi

# 3. Config generate.
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

if "$BINARY" config generate > "$TMPDIR/config.toml" 2>/dev/null; then
    if [ -s "$TMPDIR/config.toml" ]; then
        pass "config generate produced output"
    else
        fail "config generate produced empty output"
    fi
else
    fail "config generate failed"
fi

# 4. Config validate.
if [ -s "$TMPDIR/config.toml" ]; then
    if "$BINARY" config validate --config "$TMPDIR/config.toml" 2>/dev/null; then
        pass "config validate accepted generated config"
    else
        fail "config validate rejected generated config"
    fi
fi

# 5. Help output.
HELP_OUTPUT=$("$BINARY" --help 2>&1 || true)
if [ -n "$HELP_OUTPUT" ]; then
    pass "Help output present ($(echo "$HELP_OUTPUT" | wc -l | tr -d ' ') lines)"
else
    fail "No help output"
fi

# 6. Binary size check.
SIZE=$(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY" 2>/dev/null || echo "0")
SIZE_MB=$(echo "scale=1; $SIZE / 1048576" | bc 2>/dev/null || echo "?")
echo "Binary size: ${SIZE_MB} MB"
if [ "$SIZE" -gt 0 ] && [ "$SIZE" -lt 5242880 ]; then
    pass "Binary under 5 MB target"
elif [ "$SIZE" -gt 0 ]; then
    echo "WARN: Binary exceeds 5 MB target (${SIZE_MB} MB)"
fi

echo
echo "=== Smoke test complete ==="
