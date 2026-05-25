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

FILENAME="trojan_${VERSION}_${OS}_${ARCH}.tar.gz"
CHECKSUMS_FILE="trojan_${VERSION}_checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

# Download archive and checksums file
curl -fsSL "${BASE_URL}/${FILENAME}"       -o "${TMP_DIR}/${FILENAME}"
curl -fsSL "${BASE_URL}/${CHECKSUMS_FILE}" -o "${TMP_DIR}/${CHECKSUMS_FILE}"

# Verify SHA256 checksum before doing anything with the archive.
# This confirms the download was not corrupted or tampered with in transit.
echo "Verifying checksum..."

EXPECTED_HASH="$(grep " ${FILENAME}" "${TMP_DIR}/${CHECKSUMS_FILE}" | cut -d' ' -f1)"

if [ -z "$EXPECTED_HASH" ]; then
  echo "Could not find checksum for ${FILENAME} in checksums file."
  exit 1
fi

if command -v sha256sum > /dev/null 2>&1; then
  ACTUAL_HASH="$(sha256sum "${TMP_DIR}/${FILENAME}" | cut -d' ' -f1)"
elif command -v shasum > /dev/null 2>&1; then
  ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/${FILENAME}" | cut -d' ' -f1)"
else
  echo "Warning: no sha256 tool found — skipping checksum verification."
  ACTUAL_HASH="$EXPECTED_HASH"
fi

if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
  echo ""
  echo "Checksum verification FAILED."
  echo "  Expected: $EXPECTED_HASH"
  echo "  Got:      $ACTUAL_HASH"
  echo ""
  echo "The downloaded file may be corrupted or tampered with."
  echo "Do not install. Report this at https://github.com/${REPO}/issues"
  exit 1
fi

echo "Checksum verified."

# Extract and install
tar -xzf "${TMP_DIR}/${FILENAME}" -C "${TMP_DIR}"

if [ -w "$INSTALL_DIR" ]; then
  mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to $INSTALL_DIR (requires sudo)..."
  sudo mv "${TMP_DIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
fi

chmod +x "${INSTALL_DIR}/${BINARY}"

echo ""
echo "Trojan v${VERSION} installed successfully."
echo "Run 'trojan verify' to confirm binary integrity."
echo "Run 'trojan scan' to get started."
