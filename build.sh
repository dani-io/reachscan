#!/bin/bash
# build.sh — Cross-compile scanner for Windows and package as zip
# Run from the project root on Linux/macOS

set -e

VERSION="1.0"
DIST_DIR="dist"
PKG_NAME="reachscan-v${VERSION}"
PKG_DIR="${DIST_DIR}/${PKG_NAME}"

echo "[*] Cleaning previous build..."
rm -rf "${DIST_DIR}"
mkdir -p "${PKG_DIR}"

echo ""
echo "[*] Building scanner.exe for Windows 64-bit..."
# CGO_ENABLED=0 -> static binary, no DLL dependencies
# -ldflags="-s -w" -> strip debug symbols for smaller binary
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-s -w" -o "${PKG_DIR}/scanner.exe" main.go

echo "[OK] Built: $(ls -lh ${PKG_DIR}/scanner.exe | awk '{print $5}')"

echo ""
echo "[*] Copying companion files..."
cp targets.txt "${PKG_DIR}/"
cp run.bat "${PKG_DIR}/"
cp README.txt "${PKG_DIR}/"

echo ""
echo "[*] Package contents:"
ls -lh "${PKG_DIR}/"

echo ""
echo "[*] Creating zip..."
cd "${DIST_DIR}"
zip -r "${PKG_NAME}.zip" "${PKG_NAME}/" >/dev/null
cd - >/dev/null

echo ""
echo "[OK] Distribution ready!"
echo "[*] Output:"
ls -lh "${DIST_DIR}/${PKG_NAME}.zip"

echo ""
echo "[*] Send to a friend via:"
echo "    - Telegram/WhatsApp (1.8MB, easy)"
echo "    - scp ${DIST_DIR}/${PKG_NAME}.zip user@server:/path/"
echo "    - Google Drive / file sharing"
