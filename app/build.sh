#!/bin/bash
# Builds a portable dist/Veil.app (ad-hoc signed, helper inside; no geo lists) plus:
#   dist/Veil.zip             for Homebrew and for copying it to another Mac
#   dist/Veil.app.tar.gz      the in-app update package (Tauri's macOS format: Veil.app at the top)
#   dist/Veil.app.tar.gz.sig  its minisign signature, when an update signing key is available
# Local builds: the key comes from the environment, as `cargo tauri signer sign` reads it:
#   TAURI_SIGNING_PRIVATE_KEY (the key itself) or TAURI_SIGNING_PRIVATE_KEY_PATH (a file),
#   and TAURI_SIGNING_PRIVATE_KEY_PASSWORD. Without a key (or without tauri-cli) the build
#   goes on and only warns: the unsigned package is not usable for in-app updates.
# VEIL_SIGN=0: never sign here, even with a key in the environment. The release workflow
#   builds that way and signs in a separate step, so the key never reaches the build.
# Arguments go to `cargo tauri build`; the build is always `--locked` (Cargo.lock as committed).
set -euo pipefail
cd "$(dirname "$0")/.."
TRIPLE=$(rustc -vV | awk '/^host:/{print $2}')
VERSION=$(python3 -c 'import json; print(json.load(open("app/src-tauri/tauri.conf.json"))["version"])')
cargo build --release -p veil-helper --locked
mkdir -p app/src-tauri/binaries
cp target/release/veil-helper "app/src-tauri/binaries/veil-helper-$TRIPLE"
# What follows `--` goes to `cargo build`: add --locked there (after the caller's own `--`, if any).
has_runner_args=0
for a in "$@"; do [ "$a" = "--" ] && has_runner_args=1; done
if [ "$has_runner_args" = 1 ]; then
  (cd app/src-tauri && cargo tauri build "$@" --locked)
else
  (cd app/src-tauri && cargo tauri build "$@" -- --locked)
fi

# Only the macOS outputs: dist/windows is built by build-windows.sh.
rm -rf dist/Veil.app dist/Veil.zip dist/Veil.app.tar.gz dist/Veil.app.tar.gz.sig && mkdir -p dist
# ditto keeps the bundle's extended attributes and signature intact.
ditto target/release/bundle/macos/Veil.app dist/Veil.app
codesign --verify --deep --strict dist/Veil.app
ditto -c -k --keepParent dist/Veil.app dist/Veil.zip

# Update package. COPYFILE_DISABLE: no ._ AppleDouble entries (the code signature lives in
# the bundle's files, not in extended attributes).
(cd dist && COPYFILE_DISABLE=1 tar -czf Veil.app.tar.gz Veil.app)

warn() { printf '\n\033[33mWARNING: %s\033[0m\n\n' "$*" >&2; }
if [ "${VEIL_SIGN:-}" = 0 ]; then
  echo "VEIL_SIGN=0: dist/Veil.app.tar.gz is not signed here (sign it separately with cargo tauri signer sign --app-version $VERSION)."
elif [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ] && [ -z "${TAURI_SIGNING_PRIVATE_KEY_PATH:-}" ]; then
  warn "no TAURI_SIGNING_PRIVATE_KEY / TAURI_SIGNING_PRIVATE_KEY_PATH: dist/Veil.app.tar.gz is NOT signed and cannot be offered as an in-app update."
elif ! cargo tauri signer sign --help >/dev/null 2>&1; then
  warn "tauri-cli is missing (cargo install tauri-cli --version =2.12.4 --locked): dist/Veil.app.tar.gz is NOT signed."
else
  # --app-version binds the signature to this version (the app requires that).
  # The key as a string wins over a key file; the CLI refuses to get both.
  if [ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
    env -u TAURI_SIGNING_PRIVATE_KEY_PATH cargo tauri signer sign --app-version "$VERSION" dist/Veil.app.tar.gz >/dev/null
  else
    cargo tauri signer sign --app-version "$VERSION" dist/Veil.app.tar.gz >/dev/null
  fi
  [ -s dist/Veil.app.tar.gz.sig ] || { echo "signing produced no dist/Veil.app.tar.gz.sig" >&2; exit 1; }
fi

echo "Veil $VERSION:"
for f in dist/Veil.app dist/Veil.zip dist/Veil.app.tar.gz dist/Veil.app.tar.gz.sig; do
  [ -e "$f" ] && echo "  $f ($(du -sh "$f" | cut -f1))"
done
exit 0
