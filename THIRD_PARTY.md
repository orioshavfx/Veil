# Third-party components

Veil's own code is MIT-licensed (see `LICENSE`). It builds on the following.

## Rust dependencies

All crates come from crates.io and are pinned in `Cargo.lock`. `deny.toml` lists the
licenses accepted for them; CI runs `cargo deny check licenses`.

## Vendored

- `vendor/ipstack` — [ipstack](https://github.com/narrowlink/ipstack) 1.0.1, Apache-2.0
  (Narrowlink). Unchanged except that `build.rs` is removed (see `vendor/README.md`).
  Its `LICENSE` file is kept in the directory.

## Data files bundled in the macOS app

`geoip.dat` and `geosite.dat` are downloaded at build time by `app/fetch-geo.sh` from
[Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) and copied
into the app. The app also downloads fresh copies from the same place when you update
them. They are not part of this repository.

The Loyalsoldier repository is labelled GPL-3.0 on GitHub. Its README names the upstream
sources it is built from: MaxMind GeoLite2 Country (via Loyalsoldier/geoip),
gaoyifan/china-operator-ip, v2fly/domain-list-community, Loyalsoldier/domain-list-custom,
felixonmars/dnsmasq-china-list, gfwlist, EasyList / EasyListChina, AdGuard DNS Filter,
Peter Lowe's list, Dan Pollock's hosts and WindowsSpyBlocker. Each has its own license
and terms; check them before redistributing the lists in your own build.

## Windows only (not in the macOS app)

- [Wintun](https://www.wintun.net) driver DLL, downloaded by `app/fetch-wintun.sh`;
  distributed under the Wintun license.
