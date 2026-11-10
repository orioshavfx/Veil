# Veil

A VPN / proxy client for macOS, written in Rust with a [Tauri 2](https://tauri.app) interface.

> **Status: early preview (0.1.0).** macOS on Apple Silicon is the supported platform. The
> Windows build exists, but its TUN mode has not been verified on real machines. Expect rough
> edges. Read [Security notes](#security-notes) before using it.

## Features

- Protocols: VLESS (REALITY, Vision), VMess, Trojan, Shadowsocks (AEAD and 2022), Hysteria2 (with Salamander).
- Import share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`) and subscription URLs.
- Routing presets and custom rules (domains, IPs, geosite/geoip lists, per-app rules).
- **Proxy** mode: sets the macOS system proxy. No administrator password needed.
- **TUN** mode: routes all traffic of the system, including apps that ignore the proxy.
  Installs a small root helper (`dev.veil.helper`) and asks for an administrator password once.
  Follows network changes (Wi-Fi switch, new gateway or DNS).
- Menu bar panel: connect/disconnect, current server and its ping, pinned servers.

The interface is English only.

## Install (macOS, Apple Silicon, macOS 11 or newer)

1. Download `Veil.zip` from the [Releases](../../releases) page and check it against `Veil.zip.sha256`:
   `shasum -a 256 -c Veil.zip.sha256`.
2. Unzip it and move `Veil.app` to `/Applications`.
3. The app is **not notarized** (ad-hoc signed only), so macOS blocks the first launch.
   Right-click `Veil.app` → **Open** → **Open**, or run
   `xattr -dr com.apple.quarantine /Applications/Veil.app`.

Intel Macs: no prebuilt binary; build from source.

## Build from source

Requirements: Rust 1.85 or newer, Xcode command line tools, `cargo install tauri-cli --locked`.

```
bash app/fetch-geo.sh           # geo lists (not stored in git); see THIRD_PARTY.md
bash app/build.sh               # dist/Veil.app and dist/Veil.zip
cargo test --workspace --locked # checks and tests
```

Layout: `crates/veil-proto` (protocols), `veil-config` (links, subscriptions, routing),
`veil-engine` (router, TUN, DNS), `veil-helper` (root daemon), `veil-sysproxy` (system proxy
and DNS), `veil-cli` (debug CLI), `app/` (Tauri app and UI).

## Where things are

- Logs: `~/Library/Logs/Veil/veil.log`; TUN helper: `/var/log/dev.veil.helper.log`.
- Settings and profiles: `~/Library/Application Support/dev.veil.veil`.
- Geo lists are downloaded from GitHub (Loyalsoldier/v2ray-rules-dat) when needed or when you update them.
  Subscriptions are fetched from the URLs you add. Apart from your own traffic and the pings to your
  servers, those are the only HTTP requests in the code (`crates/veil-config`); there is no telemetry and no update check.

## If the network stops working

Quit Veil first. If the internet is still down:

```
networksetup -setdnsservers Wi-Fi Empty        # use the DNS from DHCP again (replace Wi-Fi with your service name)
networksetup -setwebproxystate Wi-Fi off
networksetup -setsecurewebproxystate Wi-Fi off
networksetup -setsocksfirewallproxystate Wi-Fi off
```

`networksetup -listallnetworkservices` lists your service names.

## Remove the TUN helper

```
sudo launchctl bootout system/dev.veil.helper
sudo rm /Library/LaunchDaemons/dev.veil.helper.plist /Library/PrivilegedHelperTools/dev.veil.helper
sudo rm -r "/Library/Application Support/dev.veil.helper"
sudo rm /var/log/dev.veil.helper.log
```

## Security notes

- TUN mode runs a helper as **root**. It has not had an independent security audit. Do not use it
  on a machine where you do not trust the other local users. See [SECURITY.md](SECURITY.md).
- Builds are not notarized. Verify the checksum, or build from source.
- Veil is a client only. It does not provide servers, and it does not make you anonymous.

## License

MIT, see [LICENSE](LICENSE). Third-party components: [THIRD_PARTY.md](THIRD_PARTY.md).
