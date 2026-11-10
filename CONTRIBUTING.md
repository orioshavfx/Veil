# Contributing

Bug reports and pull requests are welcome.

## Build and check

```
bash app/fetch-geo.sh          # geo lists, not stored in git
cargo check --workspace --locked
cargo clippy --workspace --locked
cargo test --workspace --locked
bash app/build.sh              # macOS app in dist/
```

Rust 1.85 or newer (edition 2024) and `cargo install tauri-cli --locked` are needed for the app build.

## Before you open a pull request

- Keep it small and focused; do not reformat unrelated code.
- `cargo clippy` must have no warnings and the tests must pass.
- Changes to `veil-helper` or to anything that touches routes, DNS or the system proxy
  need a short note on what can go wrong and how the system is restored.

## Bug reports

Include the macOS version, the Veil version, the mode (Proxy or TUN), the protocol, and the
relevant lines of `~/Library/Logs/Veil/veil.log` (and `/var/log/dev.veil.helper.log` for
TUN). Remove server addresses, UUIDs, passwords and subscription URLs first.
