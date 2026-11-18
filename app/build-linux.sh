#!/bin/bash
# Builds dist/veil-<version>-linux-<arch>.tar.gz (unsigned) from the sources:
#   veil, veil-helper, dev.veil.app.desktop, veil-helper@.service, icons, LICENSE, README
# plus dist/SHA256SUMS. Needs the usual Tauri build deps (webkit2gtk-4.1, gtk3, libayatana-appindicator).
# The build is always `--locked`. Extra arguments go to the app's `cargo build`.
set -euo pipefail
cd "$(dirname "$0")/.."
TRIPLE=$(rustc -vV | awk '/^host:/{print $2}')
ARCH=${TRIPLE%%-*}
VERSION=$(python3 -c 'import json; print(json.load(open("app/src-tauri/tauri.conf.json"))["version"])')
NAME="veil-$VERSION-linux-$ARCH"

# The helper first: the app crate expects it as a sidecar at build time.
cargo build --release -p veil-helper --locked
mkdir -p app/src-tauri/binaries
cp target/release/veil-helper "app/src-tauri/binaries/veil-helper-$TRIPLE"
# custom-protocol embeds the UI (what `cargo tauri build` enables), so tauri-cli is not needed.
cargo build --release -p veil-app --locked --features tauri/custom-protocol "$@"

rm -rf "dist/$NAME" "dist/$NAME.tar.gz" dist/SHA256SUMS
mkdir -p "dist/$NAME/icons"
install -m755 target/release/veil-app "dist/$NAME/veil"
install -m755 target/release/veil-helper "dist/$NAME/veil-helper"
install -m644 packaging/linux/dev.veil.app.desktop "dist/$NAME/"
install -m644 packaging/linux/veil-helper@.service "dist/$NAME/"
install -m644 packaging/linux/README.md "dist/$NAME/README.md"
install -m644 LICENSE "dist/$NAME/"
for s in 32x32:32 128x128:128 128x128@2x:256 icon:512; do
  install -m644 "app/src-tauri/icons/${s%%:*}.png" "dist/$NAME/icons/${s##*:}.png"
done

(cd dist && tar --owner=0 --group=0 --numeric-owner -czf "$NAME.tar.gz" "$NAME")
(cd dist && sha256sum "$NAME.tar.gz" > SHA256SUMS)
rm -rf "dist/$NAME"

echo "Veil $VERSION:"
echo "  dist/$NAME.tar.gz ($(du -sh "dist/$NAME.tar.gz" | cut -f1))"
echo "  dist/SHA256SUMS"
