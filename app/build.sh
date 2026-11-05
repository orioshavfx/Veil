#!/bin/bash
# Builds a portable dist/Veil.app (ad-hoc signed, helper and geo data inside)
# plus dist/Veil.zip for copying it to another Mac.
set -euo pipefail
cd "$(dirname "$0")/.."
TRIPLE=$(rustc -vV | awk '/^host:/{print $2}')
cargo build --release -p veil-helper
mkdir -p app/src-tauri/binaries
cp target/release/veil-helper "app/src-tauri/binaries/veil-helper-$TRIPLE"
(cd app/src-tauri && cargo tauri build "$@")

# Only the macOS outputs: dist/windows is built by build-windows.sh.
rm -rf dist/Veil.app dist/Veil.zip && mkdir -p dist
# ditto keeps the bundle's extended attributes and signature intact.
ditto target/release/bundle/macos/Veil.app dist/Veil.app
codesign --verify --deep --strict dist/Veil.app
ditto -c -k --keepParent dist/Veil.app dist/Veil.zip
echo "dist/Veil.app ($(du -sh dist/Veil.app | cut -f1)), dist/Veil.zip ($(du -sh dist/Veil.zip | cut -f1))"
