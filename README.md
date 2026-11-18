# Veil

```
brew install --cask orioshavfx/veil/veil
```

The full name `orioshavfx/veil/veil` installs this one cask from the third-party tap without
trusting the whole tap. To trust everything in the tap instead (so that `brew install --cask veil`
works too): `brew tap orioshavfx/veil && brew trust orioshavfx/veil`. Or download `Veil.zip` from
[Releases](https://github.com/orioshavfx/Veil/releases/latest) and see [Install](#install-macos-apple-silicon-macos-11-or-newer).

A VPN / proxy client for macOS, written in Rust with a [Tauri 2](https://tauri.app) interface.

Veil is **only a client**: it has no built-in servers, subscriptions or VPN service. You add your
own servers (share links or subscription URLs) and set up routing rules yourself.

> **Status: beta (1.0.0-beta.2).** macOS on Apple Silicon is the supported platform. The
> Windows build exists, but its TUN mode has not been verified on real machines. Expect rough
> edges. Read [Security notes](#security-notes) before using it.

## Features

- Protocols: VLESS (REALITY, Vision), VMess, Trojan, Shadowsocks (AEAD and 2022), Hysteria2 (with Salamander).
- Import share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`) and subscription URLs.
- Routing: two base modes, "Everything via VPN" (local network direct) and "Only selected via VPN",
  plus your own rules (domains, IPs and CIDR ranges, ports, apps). No ready-made country or
  service presets.
- Optional `geosite:` / `geoip:` rules: Veil ships no geo lists and never downloads them. To use
  such rules, put your own `geoip.dat` and `geosite.dat` (v2fly format) into the data folder (see
  [Where things are](#where-things-are)); without them Veil refuses those rules with an error that
  names the folder. `geoip:private` (local and private ranges) is built in and needs no file.
  If you updated from an older version, the `geoip.dat` / `geosite.dat` it put into the data
  folder may still be there: Veil uses any files with these names in that folder.
- **Proxy** mode: sets the macOS system proxy. No administrator password needed.
- **TUN** mode: routes all traffic of the system, including apps that ignore the proxy.
  Installs a small root helper (`dev.veil.helper`) and asks for an administrator password once.
  Follows network changes (Wi-Fi switch, new gateway or DNS).
- Menu bar panel: connect/disconnect, current server and its ping, pinned servers.
- Optional kill switch for rules (TUN mode, macOS; off by default, Settings → "Block sites that
  use VPN while it is off"): while Veil is open and disconnected, connections that the rules send
  through the VPN are blocked instead of going out directly; direct ones keep working. Quit Veil
  to restore normal internet. Limits: TUN mode only; a connection to a bare IP address (no domain
  name, e.g. hard-coded in an app) is not matched against domain rules, only against IP rules
  and the routing mode.

The interface is English only.

## Install (macOS, Apple Silicon, macOS 11 or newer)

With Homebrew: `brew install --cask orioshavfx/veil/veil` (see the top of this page).

By hand:

1. Download `Veil.zip` and `SHA256SUMS` from the [latest release](https://github.com/orioshavfx/Veil/releases/latest)
   and check the download: `shasum -a 256 -c SHA256SUMS --ignore-missing`.
2. Unzip it and move `Veil.app` to `/Applications`.
3. Open it once as described in [First launch](#first-launch).

Intel Macs: no prebuilt binary; build from source.

## First launch

Veil is not signed with an Apple Developer ID and not notarized (it is ad-hoc signed only), so
macOS blocks the first launch. Right-click (or Control-click) `Veil.app` → **Open** → **Open**.
On newer macOS versions, if there is no **Open** button: try to open Veil once, then go to
System Settings → Privacy & Security and click **Open Anyway**. You need to do this once per
install, not for in-app updates.

## Updating

- **In the app:** Settings → Updates → **Check for updates**, then **Install and restart**. Veil
  downloads the new version from GitHub Releases, checks its signature, turns the VPN off (as
  Quit does), replaces itself and restarts. If Veil is in a folder you cannot write to, macOS
  asks for an administrator password. After an update, the first TUN connection reinstalls the
  TUN helper and asks for the administrator password again.
- **Homebrew:** the cask is marked `auto_updates true`, so `brew upgrade` leaves Veil alone (the
  app updates itself); `brew upgrade --greedy` or `brew reinstall --cask veil` upgrades it anyway.
- **By hand:** download the new `Veil.zip` and replace `Veil.app`.

In-app updates are macOS only. The Windows build is a portable zip: download new versions from
the [releases page](https://github.com/orioshavfx/Veil/releases).

## Network access

Besides your own traffic, the pings to your servers and the subscription URLs you add, Veil
makes one kind of request of its own: on macOS it asks `github.com` for the latest release
(`releases/latest/download/latest.json`) once at startup and when you click **Check for
updates**; **Install and restart** then downloads `Veil.app.tar.gz` from the same release.
GitHub redirects these downloads, so they can also come from `*.githubusercontent.com`.

What GitHub sees: your IP address (your real one if the VPN is not connected at that moment;
with the VPN connected the request goes through it, in TUN mode and in Proxy mode with the system
proxy set, since the updater uses the macOS system proxy), the User-Agent
`tauri-plugin-updater/<plugin version>` and an `Accept` header. The request is a plain GET of a
fixed URL: your Veil version, servers, settings or any identifier are not sent, and there is no
telemetry. Turn the startup check off in Settings → Updates → "Check for updates at startup";
then Veil asks GitHub only when you click **Check for updates**.

## Build from source

Requirements: Rust 1.90 or newer, Xcode command line tools, `cargo install tauri-cli --version =2.12.4 --locked`.

```
bash app/build.sh               # dist/Veil.app, dist/Veil.zip, dist/Veil.app.tar.gz (+ .sig with a signing key)
cargo test --workspace --locked # checks and tests
```

Layout: `crates/veil-proto` (protocols), `veil-config` (links, subscriptions, routing),
`veil-engine` (router, TUN, DNS), `veil-helper` (root daemon), `veil-sysproxy` (system proxy
and DNS), `veil-cli` (debug CLI), `app/` (Tauri app and UI).

## Where things are

- Logs: `~/Library/Logs/Veil/veil.log`; TUN helper: `/var/log/dev.veil.helper.log`.
- Settings and profiles (the data folder): `~/Library/Application Support/dev.veil.veil` on macOS,
  `%APPDATA%\veil\veil\data` on Windows. Optional `geoip.dat` / `geosite.dat` go here too.
- Subscriptions are fetched from the URLs you add (`crates/veil-config`). The only other request
  is the update check to github.com (see [Network access](#network-access)); there are no built-in
  server or subscription addresses, no geo-list downloads and no telemetry.

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
- Builds are not notarized. Verify the checksum, or build from source. In-app updates are
  checked against the project's update signing key before they are installed (see SECURITY.md).
- Veil is a client only. It does not provide servers, and it does not make you anonymous.

## License

MIT, see [LICENSE](LICENSE). Third-party components: [THIRD_PARTY.md](THIRD_PARTY.md).
