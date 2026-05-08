#!/usr/bin/env sh
# Desmos installer — downloads the latest release binary for the current platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/KilimcininKorOglu/desmos/main/scripts/install.sh | sh
#
# Options (via environment variables):
#   DESMOS_VERSION=1.1.0    Install a specific version (default: latest)
#   DESMOS_INSTALL_DIR=/usr/local/bin   Installation directory (default: /usr/local/bin)
#   DESMOS_NO_VERIFY=1      Skip SHA256 checksum verification

set -eu

REPO="KilimcininKorOglu/desmos"
INSTALL_DIR="${DESMOS_INSTALL_DIR:-/usr/local/bin}"
NO_VERIFY="${DESMOS_NO_VERIFY:-0}"

# --- Helpers ----------------------------------------------------------------

log()  { printf '  \033[1;32m%s\033[0m %s\n' "$1" "$2"; }
warn() { printf '  \033[1;33mwarn:\033[0m %s\n' "$1" >&2; }
die()  { printf '  \033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# --- Detect platform --------------------------------------------------------

detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$OS" in
        linux)
            case "$ARCH" in
                x86_64|amd64)  TARGET="x86_64-unknown-linux-musl" ;;
                aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
                *)             die "unsupported Linux architecture: $ARCH" ;;
            esac
            ;;
        darwin)
            case "$ARCH" in
                arm64|aarch64) TARGET="aarch64-apple-darwin" ;;
                x86_64)        die "macOS x86_64 is not shipped as a release binary. Build from source: cargo build --release" ;;
                *)             die "unsupported macOS architecture: $ARCH" ;;
            esac
            ;;
        freebsd)
            case "$ARCH" in
                amd64|x86_64) TARGET="x86_64-unknown-freebsd" ;;
                *)            die "unsupported FreeBSD architecture: $ARCH" ;;
            esac
            ;;
        *)
            die "unsupported OS: $OS (use Windows MSI from the releases page)"
            ;;
    esac

    log "platform" "$OS/$ARCH -> $TARGET"
}

# --- Resolve version --------------------------------------------------------

resolve_version() {
    if [ -n "${DESMOS_VERSION:-}" ]; then
        VERSION="$DESMOS_VERSION"
        log "version" "$VERSION (pinned)"
        return
    fi

    need curl
    VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' \
        | head -1 \
        | sed 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/')

    [ -n "$VERSION" ] || die "could not resolve latest version from GitHub API"
    log "version" "$VERSION (latest)"
}

# --- Download ---------------------------------------------------------------

download() {
    ARCHIVE="desmos-${TARGET}.tar.gz"
    URL="https://github.com/$REPO/releases/download/v${VERSION}/${ARCHIVE}"
    SUMS_URL="https://github.com/$REPO/releases/download/v${VERSION}/SHA256SUMS.txt"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    log "download" "$URL"
    curl -fSL --progress-bar -o "$TMPDIR/$ARCHIVE" "$URL" \
        || die "download failed — check that v$VERSION exists at $URL"

    if [ "$NO_VERIFY" = "1" ]; then
        warn "skipping checksum verification (DESMOS_NO_VERIFY=1)"
    else
        log "verify" "downloading SHA256SUMS.txt"
        curl -fsSL -o "$TMPDIR/SHA256SUMS.txt" "$SUMS_URL" \
            || die "could not download SHA256SUMS.txt"

        EXPECTED=$(grep "$ARCHIVE" "$TMPDIR/SHA256SUMS.txt" | awk '{print $1}')
        [ -n "$EXPECTED" ] || die "archive not found in SHA256SUMS.txt"

        if command -v sha256sum >/dev/null 2>&1; then
            ACTUAL=$(sha256sum "$TMPDIR/$ARCHIVE" | awk '{print $1}')
        elif command -v shasum >/dev/null 2>&1; then
            ACTUAL=$(shasum -a 256 "$TMPDIR/$ARCHIVE" | awk '{print $1}')
        else
            warn "no sha256sum or shasum found — skipping verification"
            ACTUAL="$EXPECTED"
        fi

        if [ "$ACTUAL" != "$EXPECTED" ]; then
            die "checksum mismatch: expected $EXPECTED, got $ACTUAL"
        fi
        log "verify" "SHA256 OK"
    fi
}

# --- Install ----------------------------------------------------------------

install_binary() {
    log "extract" "$TMPDIR/$ARCHIVE"
    tar xzf "$TMPDIR/$ARCHIVE" -C "$TMPDIR"

    if [ ! -f "$TMPDIR/desmos" ]; then
        die "archive does not contain 'desmos' binary"
    fi

    if [ -w "$INSTALL_DIR" ]; then
        install -m 755 "$TMPDIR/desmos" "$INSTALL_DIR/desmos"
    else
        log "sudo" "installing to $INSTALL_DIR (requires privilege)"
        sudo install -m 755 "$TMPDIR/desmos" "$INSTALL_DIR/desmos"
    fi

    log "installed" "$INSTALL_DIR/desmos"
}

# --- Post-install -----------------------------------------------------------

post_install() {
    INSTALLED_VERSION=$("$INSTALL_DIR/desmos" version 2>/dev/null || echo "unknown")
    log "version" "$INSTALLED_VERSION"

    echo ""
    echo "  Desmos installed successfully."
    echo ""
    echo "  Next steps:"
    echo "    1. Generate a config:   desmos config generate > /etc/desmos/config.toml"
    echo "    2. Edit the config:     sudo vi /etc/desmos/config.toml"
    echo "    3. Validate:            desmos config validate --config /etc/desmos/config.toml"
    echo "    4. Start the tunnel:    sudo desmos up --config /etc/desmos/config.toml"
    echo ""
    echo "  Full guide: https://github.com/$REPO/blob/main/docs/getting-started.md"
    echo ""
}

# --- Main -------------------------------------------------------------------

main() {
    echo ""
    echo "  Desmos Installer"
    echo "  ================"
    echo ""

    need curl
    need tar

    detect_platform
    resolve_version
    download
    install_binary
    post_install
}

main
