#!/bin/bash
# Downloads geoip.dat / geosite.dat into app/src-tauri/resources/.
# The app bundles them (tauri.conf.json) and build-windows.sh copies them, so run this
# once after cloning, and again whenever you want fresh lists.
set -euo pipefail

BASE="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download"
DIR="$(cd "$(dirname "$0")" && pwd)/src-tauri/resources"
mkdir -p "$DIR"

for f in geoip.dat geosite.dat; do
  tmp="$(mktemp "$DIR/.$f.XXXXXX")"
  if ! curl -fL --retry 3 -o "$tmp" "$BASE/$f"; then
    rm -f "$tmp"
    echo "failed to download $f" >&2
    exit 1
  fi
  # A broken download must not replace a working file.
  if [ "$(wc -c < "$tmp")" -lt 100000 ]; then
    rm -f "$tmp"
    echo "$f looks too small, keeping the old one" >&2
    exit 1
  fi
  mv -f "$tmp" "$DIR/$f"
  echo "ok: $f ($(wc -c < "$DIR/$f") bytes)"
done
