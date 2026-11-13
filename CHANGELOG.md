# Changelog

## 0.1.0 (unreleased)

First public preview. macOS is the supported platform.

- Protocols: VLESS (REALITY, Vision), VMess, Trojan, Shadowsocks (AEAD and 2022),
  Hysteria2 (Salamander).
- Share links and subscriptions, routing presets and rules, geoip/geosite lists.
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
