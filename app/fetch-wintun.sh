#!/bin/bash
# Downloads the Wintun driver DLL (amd64) into app/src-tauri/resources/wintun.dll.
# Veil's Windows TUN mode loads it from the folder of Veil.exe; build-windows.sh copies it there.
set -euo pipefail

URL="https://www.wintun.net/builds/wintun-0.14.1.zip"
EXPECTED="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
DIR="$(cd "$(dirname "$0")" && pwd)/src-tauri/resources"
mkdir -p "$DIR"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if ! curl -fL --retry 3 -o "$work/wintun.zip" "$URL"; then
  echo "failed to download $URL" >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$work/wintun.zip" | cut -d' ' -f1)"
else
  actual="$(sha256sum "$work/wintun.zip" | cut -d' ' -f1)"
fi
echo "sha256 of the archive: $actual"
if [ "$actual" != "$EXPECTED" ]; then
  echo "warning: sha256 differs from the expected $EXPECTED" >&2
fi

unzip -q -o "$work/wintun.zip" "wintun/bin/amd64/wintun.dll" -d "$work/x" || { echo "wintun.dll not found in the archive" >&2; exit 1; }
# A broken download must not replace a working file.
if [ "$(wc -c < "$work/x/wintun/bin/amd64/wintun.dll")" -lt 10000 ]; then
  echo "wintun.dll looks too small" >&2
  exit 1
fi
tmp="$(mktemp "$DIR/.wintun.dll.XXXXXX")"
cp "$work/x/wintun/bin/amd64/wintun.dll" "$tmp"
mv -f "$tmp" "$DIR/wintun.dll"
echo "ok: wintun.dll ($(wc -c < "$DIR/wintun.dll") bytes)"
