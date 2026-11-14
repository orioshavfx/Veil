#!/bin/bash
# ONE-TIME: creates the key pair that signs Veil's in-app updates, on your Mac, outside the
# repository (~/.veil-signing/update.key, mode 0600). Prints only the PUBLIC key and what to
# do with it; the private key is never printed. Keep a backup of the key file and its
# password somewhere safe: without them no update can be signed for the installed apps.
set -euo pipefail

KEY_DIR="$HOME/.veil-signing"
KEY="$KEY_DIR/update.key"

if [ -e "$KEY" ] || [ -e "$KEY.pub" ]; then
  echo "A key already exists at $KEY; not overwriting it." >&2
  [ -r "$KEY.pub" ] && { echo "Its public key:"; cat "$KEY.pub"; echo; }
  exit 1
fi

if ! cargo tauri signer generate --help >/dev/null 2>&1; then
  echo "Installing tauri-cli (cargo install tauri-cli --version \"^2.12\" --locked)…"
  cargo install tauri-cli --version "^2.12" --locked
fi

umask 077
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"

echo "Choose a password for the signing key when asked (it goes into a GitHub Secret too)."
# With -w the CLI writes the key files and prints only their paths, never the private key.
env -u CI cargo tauri signer generate -w "$KEY"   # CI set would skip the password
chmod 600 "$KEY" "$KEY.pub"

cat <<MSG

Done. The private key is in $KEY (mode 0600). Do not commit it, do not share it.

1. Public key: put this line into UPDATER_PUBKEY in app/src-tauri/src/updater.rs:

$(cat "$KEY.pub")

2. GitHub Secrets of orioshavfx/Veil (Settings → Secrets and variables → Actions), for example:
     gh secret set TAURI_SIGNING_PRIVATE_KEY -R orioshavfx/Veil < "$KEY"
     gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD -R orioshavfx/Veil   # asks for the password

3. Back up $KEY and its password (a password manager, an encrypted disk). If they are lost,
   installed copies of Veil can no longer be updated from inside the app.
MSG
