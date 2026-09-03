#!/usr/bin/env bash
set -e

# Aegis CLI Universal Installer (Linux, macOS, WSL, Windows Git-Bash)
# Usage: curl -fsSL https://aegis.ilyankhan.tech | bash

REPO="Ilyan321/aegis-cli"
BINARY_NAME="aegis"
INSTALL_DIR="/usr/local/bin"

# Detect OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
    linux|darwin) ;;
    mingw*|msys*|cygwin*|windows*)
        OS="windows"
        BINARY_NAME="aegis.exe"
        if [ -d "$HOME/bin" ]; then
            INSTALL_DIR="$HOME/bin"
        elif [ -d "$USERPROFILE/bin" ]; then
            INSTALL_DIR="$USERPROFILE/bin"
        else
            INSTALL_DIR="/usr/bin"
        fi
        ;;
    *) echo "Unsupported operating system: $OS"; exit 1 ;;
esac

if [ ! -w "$INSTALL_DIR" ]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

echo "Installing Aegis CLI..."

# If Go is installed, prefer building directly via go install
if command -v go >/dev/null 2>&1; then
    echo "Go toolchain detected. Installing via go install..."
    go install "github.com/${REPO}/cmd/aegis@latest"
    GOPATH_BIN="$(go env GOPATH)/bin"
    if [ -f "${GOPATH_BIN}/${BINARY_NAME}" ]; then
        cp "${GOPATH_BIN}/${BINARY_NAME}" "$INSTALL_DIR/${BINARY_NAME}" 2>/dev/null || true
    fi
    echo "Aegis installed successfully to $INSTALL_DIR/${BINARY_NAME}"
    echo ""
    "$INSTALL_DIR/${BINARY_NAME}" version 2>/dev/null || "${GOPATH_BIN}/${BINARY_NAME}" version
    echo "Run 'aegis --help' to get started."
    exit 0
fi

# Fallback: Download precompiled binary from latest GitHub release
if [ "$OS" = "windows" ]; then
    RELEASE_URL="https://github.com/${REPO}/releases/latest/download/aegis_windows_${ARCH}.zip"
else
    RELEASE_URL="https://github.com/${REPO}/releases/latest/download/aegis_${OS}_${ARCH}.tar.gz"
fi

echo "Downloading ${BINARY_NAME} for ${OS}/${ARCH}..."

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [ "$OS" = "windows" ]; then
    if curl -fsSL "$RELEASE_URL" -o "$TMP_DIR/aegis.zip" 2>/dev/null; then
        unzip -q "$TMP_DIR/aegis.zip" -d "$TMP_DIR"
        chmod +x "$TMP_DIR"/*/"$BINARY_NAME" 2>/dev/null || chmod +x "$TMP_DIR/$BINARY_NAME"
        cp "$TMP_DIR"/*/"$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || cp "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
        echo "Aegis installed successfully to $INSTALL_DIR/$BINARY_NAME"
    else
        echo "Precompiled release binary not found yet. Please install Go (https://go.dev) or build from source."
        exit 1
    fi
else
    if curl -fsSL "$RELEASE_URL" -o "$TMP_DIR/aegis.tar.gz" 2>/dev/null; then
        tar -xzf "$TMP_DIR/aegis.tar.gz" -C "$TMP_DIR"
        chmod +x "$TMP_DIR"/*/"$BINARY_NAME" 2>/dev/null || chmod +x "$TMP_DIR/$BINARY_NAME"
        cp "$TMP_DIR"/*/"$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME" 2>/dev/null || cp "$TMP_DIR/$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"
        echo "Aegis installed successfully to $INSTALL_DIR/$BINARY_NAME"
    else
        echo "Precompiled release binary not found yet. Please install Go (https://go.dev) or build from source."
        exit 1
    fi
fi

echo ""
"$INSTALL_DIR/$BINARY_NAME" version
echo "Run 'aegis --help' to get started."
