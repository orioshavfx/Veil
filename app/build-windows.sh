#!/bin/bash
# Cross-builds the portable Windows x64 test kit on this Mac:
# dist/windows/ (Veil.exe, veil-cli.exe, geo/, test script) and dist/Veil-windows-x64.zip.
# Needs: rustup target x86_64-pc-windows-msvc, cargo-xwin, llvm, nasm.
set -euo pipefail
cd "$(dirname "$0")/.."
T=x86_64-pc-windows-msvc
OUT=target/$T/release

# tauri-build wants the sidecar the macOS bundle uses; TUN is not wired up on Windows yet.
cargo xwin build --release --target $T -p veil-helper
mkdir -p app/src-tauri/binaries
cp $OUT/veil-helper.exe app/src-tauri/binaries/veil-helper-$T.exe
cargo xwin build --release --target $T -p veil-app -p veil-cli

rm -rf dist/windows dist/Veil-windows-*.zip
mkdir -p dist/windows/geo
cp $OUT/veil-app.exe dist/windows/Veil.exe
cp $OUT/veil.exe dist/windows/veil-cli.exe  # not veil.exe: macOS file names ignore case
cp app/src-tauri/resources/geoip.dat app/src-tauri/resources/geosite.dat dist/windows/geo/
cp app/windows-kit/README.txt app/windows-kit/windows-test.ps1 dist/windows/
(cd dist && rm -rf Veil-windows && cp -R windows Veil-windows && ditto -c -k --norsrc --noextattr --keepParent Veil-windows Veil-windows-x64.zip && rm -rf Veil-windows)
echo "dist/Veil-windows-x64.zip ($(du -sh dist/Veil-windows-x64.zip | cut -f1))"
