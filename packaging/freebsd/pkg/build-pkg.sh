#!/usr/bin/env bash
# build-pkg.sh — Build a FreeBSD .pkg for Desmos.
#
# Usage:
#   ./packaging/freebsd/pkg/build-pkg.sh [BINARY_PATH] [OUTPUT_DIR]
#
# Arguments:
#   BINARY_PATH  Path to the compiled desmos binary
#                (default: target/x86_64-unknown-freebsd/release/desmos)
#   OUTPUT_DIR   Directory for the output .pkg file
#                (default: dist/freebsd)
#
# The script assembles a staging directory, copies in the binary,
# rc script, sample config, and pfSense integration files, then
# calls `pkg create` to produce the .pkg.
#
# Prerequisites:
#   - FreeBSD host with pkg(8) installed, OR
#   - Cross-build environment with pkg-static available.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

BINARY="${1:-$PROJECT_ROOT/target/x86_64-unknown-freebsd/release/desmos}"
OUTPUT_DIR="${2:-$PROJECT_ROOT/dist/freebsd}"

PKG_NAME="desmos"
PKG_VERSION="1.0.0"

# ---- Helpers -----------------------------------------------------------------

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# ---- Validate ----------------------------------------------------------------

[ -f "$BINARY" ] || die "Binary not found: $BINARY"
command -v pkg 2>/dev/null || command -v pkg-static 2>/dev/null || \
    die "pkg or pkg-static not found (need FreeBSD pkg tools)"

PKG_CMD="$(command -v pkg 2>/dev/null || command -v pkg-static)"

# ---- Stage -------------------------------------------------------------------

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

info "Staging package contents"

# Binary.
install -d -m 0755 "$STAGING/usr/local/bin"
install -m 0755 "$BINARY" "$STAGING/usr/local/bin/desmos"

# RC script.
install -d -m 0755 "$STAGING/usr/local/etc/rc.d"
install -m 0755 "$SCRIPT_DIR/desmos.rc" "$STAGING/usr/local/etc/rc.d/desmos.sh"

# Sample config.
install -d -m 0755 "$STAGING/usr/local/etc/desmos"
if [ -f "$PROJECT_ROOT/config/desmos.toml.example" ]; then
    install -m 0644 "$PROJECT_ROOT/config/desmos.toml.example" \
        "$STAGING/usr/local/etc/desmos/desmos.toml.sample"
else
    # Minimal sample if the full example isn't available.
    cat > "$STAGING/usr/local/etc/desmos/desmos.toml.sample" <<'TOML'
[general]
mode = "client"
log_level = "info"

[client]
server = "vpn.example.com:51820"

[interface]
name = "desmos0"
mtu = 1420

[bonding]
strategy = "latency_adaptive"
TOML
fi

# pfSense integration files (optional — only if targeting pfSense).
if [ -d "$PROJECT_ROOT/packaging/pfsense" ]; then
    info "Including pfSense integration files"

    install -d -m 0755 "$STAGING/usr/local/share/pfSense/packages"
    install -m 0644 "$PROJECT_ROOT/packaging/pfsense/desmos.xml" \
        "$STAGING/usr/local/share/pfSense/packages/desmos.xml"

    install -d -m 0755 "$STAGING/usr/local/pkg/desmos"
    install -m 0644 "$PROJECT_ROOT/packaging/pfsense/desmos.inc" \
        "$STAGING/usr/local/pkg/desmos/desmos.inc"
fi

# ---- Manifest ----------------------------------------------------------------

install -d -m 0755 "$STAGING/+MANIFEST_DIR"
cp "$SCRIPT_DIR/+MANIFEST" "$STAGING/+MANIFEST_DIR/+MANIFEST"

# ---- Build pkg ---------------------------------------------------------------

mkdir -p "$OUTPUT_DIR"

info "Creating package"
"$PKG_CMD" create \
    -M "$STAGING/+MANIFEST_DIR/+MANIFEST" \
    -r "$STAGING" \
    -o "$OUTPUT_DIR" \
    2>&1 || die "pkg create failed"

info "Done. Package:"
ls -lh "$OUTPUT_DIR/${PKG_NAME}-${PKG_VERSION}"*.pkg 2>/dev/null || \
    ls -lh "$OUTPUT_DIR/"*.pkg 2>/dev/null || \
    info "Warning: .pkg file not found in output dir"
