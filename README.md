# Veil

VPN client: Rust workspace (`crates/`) plus a Tauri app (`app/`). macOS is the main target; the Windows port is in progress (system proxy and app-level TUN work; TUN needs `wintun.dll` next to `Veil.exe`).

## Build

1. Download the geo lists (not stored in git): `bash app/fetch-geo.sh`
2. macOS app: `bash app/build.sh`
3. Windows test build: `bash app/build-windows.sh`
4. Check and tests: `cargo check --workspace --locked && cargo test --workspace --locked`

### TUN on Windows

The app normally runs without administrator rights (Proxy mode). Choosing TUN and pressing Connect restarts Veil through the UAC prompt (`runas`, argument `--connect-tun`); the elevated copy runs the engine in-process and connects. There is no helper service on Windows. It needs `wintun.dll` next to `Veil.exe` (`bash app/fetch-wintun.sh` downloads it; `build-windows.sh` copies it into the kit). If the prompt is declined, Veil stays as it was. To undo TUN: disconnect or close the app, the adapter disappears with the process.

`vendor/ipstack` is ipstack 1.0.1 without its `build.rs` (see `vendor/README.md`).
