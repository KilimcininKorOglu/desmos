#!/usr/bin/env bash
# build-openwrt.sh — Build Desmos IPK packages for OpenWrt targets.
#
# Usage:
#   ./scripts/build-openwrt.sh [SDK_ROOT] [TARGETS...]
#
# Arguments:
#   SDK_ROOT   Path to the extracted OpenWrt SDK (default: ./openwrt-sdk)
#   TARGETS    Space-separated list of OpenWrt architecture names
#              (default: mips_24kc arm_cortex-a7 aarch64_cortex-a53)
#
# The script:
#   1. Validates the SDK root exists.
#   2. Symlinks packaging/openwrt into the SDK package tree.
#   3. Installs required Rust cross-compile targets.
#   4. Runs `make package/desmos/compile` for each target.
#   5. Collects IPK files into dist/openwrt/.
#
# Prerequisites:
#   - Rust toolchain (rustup) with cross-compile targets.
#   - Extracted OpenWrt SDK for the desired platform.
#   - Standard build tools (make, gcc, etc.).
#
# Environment variables:
#   CARGO       Path to cargo binary (default: cargo)
#   RUSTUP      Path to rustup binary (default: rustup)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SDK_ROOT="${1:-./openwrt-sdk}"
shift 2>/dev/null || true
TARGETS="${*:-mips_24kc arm_cortex-a7 aarch64_cortex-a53}"

CARGO="${CARGO:-cargo}"
RUSTUP="${RUSTUP:-rustup}"

# ---- Helpers -----------------------------------------------------------------

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# ---- Validate ----------------------------------------------------------------

[ -d "$SDK_ROOT" ] || die "SDK root not found: $SDK_ROOT"
[ -f "$SDK_ROOT/rules.mk" ] || die "Not a valid OpenWrt SDK: $SDK_ROOT/rules.mk missing"
command -v "$CARGO" >/dev/null || die "cargo not found"
command -v "$RUSTUP" >/dev/null || die "rustup not found"

# ---- Map OpenWrt arch to Rust target -----------------------------------------

rust_target_for() {
    case "$1" in
        mips_24kc)                   echo "mips-unknown-linux-musl" ;;
        mipsel_24kc)                 echo "mipsel-unknown-linux-musl" ;;
        arm_cortex-a7*|arm_cortex-a9*) echo "armv7-unknown-linux-musleabihf" ;;
        aarch64_cortex-a53|aarch64_generic) echo "aarch64-unknown-linux-musl" ;;
        x86_64)                      echo "x86_64-unknown-linux-musl" ;;
        *) die "unknown OpenWrt arch: $1" ;;
    esac
}

# ---- Setup SDK package link --------------------------------------------------

info "Linking package into SDK tree"
mkdir -p "$SDK_ROOT/package/desmos"
ln -sf "$PROJECT_ROOT/packaging/openwrt/Makefile" "$SDK_ROOT/package/desmos/Makefile"
if [ -d "$PROJECT_ROOT/packaging/openwrt/files" ]; then
    ln -sf "$PROJECT_ROOT/packaging/openwrt/files" "$SDK_ROOT/package/desmos/files"
fi

# ---- Install Rust targets ----------------------------------------------------

for arch in $TARGETS; do
    target=$(rust_target_for "$arch")
    info "Ensuring Rust target: $target"
    "$RUSTUP" target add "$target" 2>/dev/null || true
done

# ---- Build each target -------------------------------------------------------

mkdir -p "$PROJECT_ROOT/dist/openwrt"

for arch in $TARGETS; do
    target=$(rust_target_for "$arch")
    info "Building IPK for $arch (Rust target: $target)"

    # Copy source into SDK build dir (OpenWrt expects it there).
    build_dir="$SDK_ROOT/build_dir/target-*/desmos-1.0.0"
    # shellcheck disable=SC2086
    mkdir -p "$SDK_ROOT/dl"

    # Set RUST_TARGET so the Makefile picks it up.
    export RUST_TARGET="$target"
    export PKG_BUILD_DIR="$PROJECT_ROOT"

    (
        cd "$SDK_ROOT"
        make package/desmos/compile \
            ARCH="$arch" \
            V=sc \
            -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)" \
        || die "Build failed for $arch"
    )

    # Collect IPK.
    ipk=$(find "$SDK_ROOT/bin" -name "desmos_*_${arch}.ipk" -print -quit 2>/dev/null || true)
    if [ -n "$ipk" ]; then
        cp "$ipk" "$PROJECT_ROOT/dist/openwrt/"
        info "IPK: $(basename "$ipk")"
    else
        info "Warning: IPK not found for $arch (check SDK output)"
    fi
done

info "Done. IPKs in dist/openwrt/:"
ls -la "$PROJECT_ROOT/dist/openwrt/" 2>/dev/null || true
