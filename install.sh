#!/usr/bin/env bash
set -e

# Aegis CLI Universal Installer
# Usage: curl -fsSL https://aegis.ilyankhan.tech | bash

REPO="Ilyan321/aegis-cli"
BINARY_NAME="aegis"
INSTALL_DIR="/usr/local/bin"

if [ ! -w "$INSTALL_DIR" ]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo "🛡️ Installing Aegis CLI..."

# Detect OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux|darwin) ;;
    *) echo "Unsupported operating system: $OS"; exit 1 ;;
esac

# If Go is installed, prefer building clean from source
if command -v go >/dev/null 2>&1; then
    echo "📦 Go toolchain detected. Installing via go install..."
    go install "github.com/${REPO}/cmd/aegis@latest"
    echo "✅ Aegis installed to $(go env GOPATH)/bin/aegis"
    exit 0
fi

# Fallback: Download precompiled binary from latest release
RELEASE_URL="https://github.com/${REPO}/releases/latest/download/${BINARY_NAME}_${OS}_${ARCH}.tar.gz"
echo "⬇️ Downloading ${BINARY_NAME} for ${OS}/${ARCH}..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if curl -fsSL "$RELEASE_URL" -o "$TMP_DIR/aegis.tar.gz" 2>/dev/null; then
    tar -xzf "$TMP_DIR/aegis.tar.gz" -C "$TMP_DIR"
    chmod +x "$TMP_DIR/$BINARY_NAME"
    mv "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
    echo "✅ Aegis installed successfully to $INSTALL_DIR/$BINARY_NAME"
else
    echo "⚠️ Precompiled binary release not available yet. Please install Go (https://go.dev) or build from source:"
    echo "   git clone https://github.com/${REPO}.git && cd aegis-cli && make install"
    exit 1
fi

echo ""
"$INSTALL_DIR/$BINARY_NAME" version
echo "Run 'aegis --help' to see all available commands."
