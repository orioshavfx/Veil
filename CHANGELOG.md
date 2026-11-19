# Changelog

## Unreleased

Version 1.0.0-beta.3.

### Fixed

- Subscriptions: a refresh no longer pins (or selects) every server that shares a name with a
  pinned (selected) one; old servers are matched one-to-one, by server settings first, then by a
  name that is unique on both sides.
- Standby (macOS): after "Connect" from standby the app now drops its standby mark; before, the
  standby watch took the helper's "no standby" for a lost one and stopped the TUN a second later
  ("Standby ended: the TUN helper stopped").
- Windows: every PowerShell call and every step of the TUN start is timed in `veil.log`.

Version 1.0.0-beta.2.

### Added

- Settings → Startup: "Launch Veil when I log in" (macOS LaunchAgent, Windows `Run` key; starts
  hidden with `--hidden`) and "Connect when Veil opens" (`launch_at_login`, `auto_connect` in
  `state.json`, both off by default; a failed auto-connect is retried a few times).
- Kill switch (macOS, TUN): the tunnel now comes up on standby when Veil starts, and when the
  switch is turned on while disconnected, so VPN traffic is blocked before the first connection
  too. It needs the installed helper and never asks for the password at start.

- In-app updates on macOS (Settings → Updates): "Check for updates", release notes, "Install and
  restart" with progress. Uses the Rust API of `tauri-plugin-updater` 2.14 (no JS package, no
  `updater:*` permissions for the window). Updates come from the latest GitHub release
  (`latest.json`, HTTPS only), must be newer (semver, prereleases included) and must carry a valid
  minisign signature for exactly that version. The VPN is stopped like on Quit only after the
  download and signature check; no update while connecting, one at a time; then the app restarts.
  Builds without a public key (`UPDATER_PUBKEY` empty) make no update requests.
- "Check for updates at startup" (on by default, `check_updates` in `state.json`): one quiet
  request to github.com per start; a small "Update available" mark in the header.
- Windows: Settings → Updates shows the version and points to the releases page (no self-update).
- `app/build.sh` also writes `dist/Veil.app.tar.gz` and, with `TAURI_SIGNING_PRIVATE_KEY` /
  `TAURI_SIGNING_PRIVATE_KEY_PATH` set, its signature `Veil.app.tar.gz.sig`
  (`cargo tauri signer sign --app-version`); without a key it warns and goes on. `VEIL_SIGN=0`
  skips signing; the build is always `--locked`.
- `app/tools/gen-update-key.sh` (one-time signing key pair in `~/.veil-signing`, prints only the
  public key) and `app/tools/make-latest-json.py` (writes `latest.json`, checks its inputs,
  `--self-test`).
- Release workflow: tag `v*` → build, sign, `latest.json`, `SHA256SUMS`, a published (not draft,
  not prerelease) GitHub release with generated notes, and a bump of the Homebrew tap
  (`orioshavfx/homebrew-veil`, when the `TAP_TOKEN` secret is set). The signing key and password
  reach only the signing step (tauri-cli `=2.12.4`, installed before the build); the build runs
  without them. The workflow fails before publishing when `UPDATER_PUBKEY` is empty or the
  signature does not verify with it for the tagged version (`app/tools/update-sig-check`).
- Installing an update while the VPN is connected or on standby first asks for confirmation in the
  window. If the installation fails after the VPN was stopped, the tray, window and panel show the
  VPN as off, and the error stays visible until the next connection. Before anything is stopped,
  Veil checks that it can replace itself (an app bundle, not App Translocation, not on a
  read-only disk).
- The Beta badge shows the version line from the app version (`1.0.0-beta.2` → "Beta 1.0") and
  is hidden in stable versions.
- Homebrew: `brew install --cask orioshavfx/veil/veil`.

### Changed

- Version 1.0.0-beta.1 (Cargo workspace and `tauri.conf.json`); the main window shows a
  "Beta 1.0" badge next to the name.
- Veil is a client only: no ready-made routing presets and no bundled geo lists. Routing has two
  base modes, "Everything via VPN" (`global`) and "Only selected via VPN" (`selected-only`), plus
  the user's own rules. Old configs with a removed preset (`ru-direct`, `proxy-all`) start as
  `global`.
- `geoip.dat` / `geosite.dat` are no longer bundled with the app or the Windows kit, copied on
  start or downloaded (removed: `app/fetch-geo.sh`, the CLI `geo-update` command and the CLI's
  automatic download). `geosite:` / `geoip:` rules (except the built-in `geoip:private`) work only
  with the user's own files in the data folder; otherwise saving or applying them fails with an
  error naming the folder and the files. After an update from an older version, `geoip.dat` /
  `geosite.dat` left in the data folder by that version stay there and are used like your own
  files; delete them if you do not want them.
- A TUN helper of another Veil version answers a request it does not understand with
  `bad request: unknown variant …`; the app now shows that as a message that says to disconnect
  and connect again (which reinstalls the helper) instead of the bare serde error.
- UI: elements with the `hidden` attribute are hidden even when their class sets a display
  (the kill-switch row could show where it does not apply).

## 0.1.0 (unreleased)

First public preview. macOS is the supported platform.

- Protocols: VLESS (REALITY, Vision), VMess, Trojan, Shadowsocks (AEAD and 2022),
  Hysteria2 (Salamander).
- Share links and subscriptions, routing modes and user rules.
- Proxy mode (macOS system proxy) and TUN mode (root helper, asks for an administrator
  password once).
- Menu bar panel: connect/disconnect, current server with ping, pinned servers.
- Standby (optional kill switch for rules, macOS TUN only, off by default): with "Block sites
  that use VPN while it is off", Disconnect keeps the tunnel and refuses every connection the
  rules send through the VPN (also the automatic VPN fallback of "direct"); direct traffic keeps
  working. Quitting Veil, switching to Proxy mode or turning the option off restores the network.
- TUN follows network changes (interface, gateway, DNS).
- Windows build exists but TUN there is untested on real machines.

### Hardening in this release

- A DNS backup is deleted only when every network service was restored; otherwise the
  unrestored ones stay in it and the restore is retried on the next start.
- The DNS backup is written without following symlinks, with mode 0600.
- `state.json` (links, passwords, subscription URLs) is written with mode 0600 in a 0700
  directory; `veil.log` is created with mode 0600.
- Subscription and geo-list errors no longer put the URL (which may contain a token) into logs.
- Known limitations of the root helper: see `SECURITY.md`.
