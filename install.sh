#!/bin/sh
set -e

REPO="dev-zeph/Trojan"
BINARY="trojan"
INSTALL_DIR="/usr/local/bin"

# Detect OS and architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin) OS="darwin" ;;
  Linux)  OS="linux" ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

# Get the latest release version from GitHub
echo "Fetching latest Trojan release..."
VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"v\([^"]*\)".*/\1/')"

if [ -z "$VERSION" ]; then
  echo "Could not determine latest version. Check your internet connection."
  exit 1
fi

echo "Installing Trojan v${VERSION} (${OS}/${ARCH})..."

# Build download URL
FILENAME="trojan_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/${REPO}/releases/download/v${VERSION}/${FILENAME}"

# Download and extract
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL "$URL" -o "$TMP_DIR/$FILENAME"
tar -xzf "$TMP_DIR/$FILENAME" -C "$TMP_DIR"

# Install binary
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
else
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv "$TMP_DIR/$BINARY" "$INSTALL_DIR/$BINARY"
fi

chmod +x "$INSTALL_DIR/$BINARY"

echo ""
echo "Trojan v${VERSION} installed successfully."
echo "Run 'trojan scan' to get started."
