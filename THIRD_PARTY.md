# Third-party components

Veil's own code is MIT-licensed (see `LICENSE`). It builds on the following.

## Rust dependencies

All crates come from crates.io and are pinned in `Cargo.lock`. `deny.toml` lists the
licenses accepted for them; CI runs `cargo deny check licenses`.

In-app updates (macOS) use [tauri-plugin-updater](https://github.com/tauri-apps/plugins-workspace)
(Apache-2.0 OR MIT), which verifies signatures with
[minisign-verify](https://github.com/jedisct1/rust-minisign-verify) (MIT). Release signatures
are made with the Tauri CLI (`cargo tauri signer`), a build tool that is not shipped.

## Vendored

- `vendor/ipstack` — [ipstack](https://github.com/narrowlink/ipstack) 1.0.1, Apache-2.0
  (Narrowlink). Unchanged except that `build.rs` is removed (see `vendor/README.md`).
  Its `LICENSE` file is kept in the directory.

## Data files

None. Veil does not bundle or download geoip/geosite lists. If you use `geosite:` / `geoip:`
rules with your own `geoip.dat` / `geosite.dat`, the license and terms of those files are yours
to check.

## Windows only (not in the macOS app)

- [Wintun](https://www.wintun.net) driver DLL, downloaded by `app/fetch-wintun.sh`;
  distributed under the Wintun license.
