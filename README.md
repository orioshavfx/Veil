# Veil

VPN client: Rust workspace (`crates/`) plus a Tauri app (`app/`). macOS is the main target; the Windows port is in progress (system proxy works, TUN is not done).

## Build

1. Download the geo lists (not stored in git): `bash app/fetch-geo.sh`
2. macOS app: `bash app/build.sh`
3. Windows test build: `bash app/build-windows.sh`
4. Check and tests: `cargo check --workspace --locked && cargo test --workspace --locked`

`vendor/ipstack` is ipstack 1.0.1 without its `build.rs` (see `vendor/README.md`).
