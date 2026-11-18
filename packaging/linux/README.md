# Veil on Linux (beta)

Tested target: Arch / CachyOS with Hyprland or niri. TUN mode is required: all traffic goes through
the `veil0` device. Other distributions and desktops may work but are not verified.

## Install

From the repository (builds the app and the helper, installs a pacman package):

```
cd packaging/linux
makepkg -si
```

Or build a tarball without pacman (`app/build-linux.sh`, writes `dist/veil-<version>-linux-<arch>.tar.gz`
and `dist/SHA256SUMS`; unsigned). Build deps: `rust`, `webkit2gtk-4.1`, `gtk3`, `libayatana-appindicator`,
`librsvg`, `openssl`, `pkgconf`.

Runtime deps: `webkit2gtk-4.1 gtk3 libayatana-appindicator polkit iproute2`. Optional:
`systemd-resolvconf` / NetworkManager for DNS, and a polkit agent (see below).

The package installs `/usr/bin/veil`, `/usr/lib/veil/veil-helper` and the template unit
`/usr/lib/systemd/system/veil-helper@.service`.

## The TUN helper

TUN needs root, so Veil uses a small root daemon, `veil-helper`, that listens on
`/run/veil/helper.sock` and accepts only your user (uid is checked with `SO_PEERCRED`). The unit is
a template: `veil-helper@<uid>.service` runs `veil-helper --uid <uid>`.

- With the pacman package the binary and the template are already in `/usr/lib`. Installing the
  helper from the app only enables `veil-helper@<your uid>.service`.
- With the tarball the app copies the binary to `/usr/lib/veil/veil-helper` and writes the unit.
- Either way the app asks for the password through `pkexec` (polkit). This needs a running polkit
  agent in your session: `hyprpolkitagent`, `polkit-gnome`, `lxqt-policykit` or similar. Start it
  from your compositor config, for example `exec-once = systemctl --user start hyprpolkitagent`.
- By hand: `sudo systemctl enable --now veil-helper@$(id -u).service`.

How the TUN works: the helper creates `veil0` (198.18.0.1). Veil's own sockets are bound to the
physical interface (`SO_BINDTODEVICE`), so the normal default route stays in place and the helper
adds the split routes `0.0.0.0/1`, `128.0.0.0/1` (and `::/1`, `8000::/1`) through `veil0`. DNS is a
fake-IP resolver on 198.18.0.2: with systemd-resolved it is set on `veil0` via `resolvectl`; without
it `/etc/resolv.conf` is rewritten and the original is saved in `/var/lib/veil`. Everything is
restored on disconnect and again when the helper starts after a crash.

## Autostart and windows

Veil has no XDG autostart on Linux; start it from the compositor and keep it in the tray with
`--hidden`.

Hyprland (`hyprland.conf`):

```
exec-once = veil --hidden
windowrulev2 = float, class:^(dev.veil.app)$
```

niri (`config.kdl`):

```
spawn-at-startup "veil" "--hidden"
```

The window is small (420x700), so a floating rule is recommended in tiling setups.

## Tray

The tray icon uses StatusNotifierItem. You need a StatusNotifier host: waybar with the `tray`
module (`"modules-right": ["tray"]`), or another bar that supports SNI (quickshell, ags, ...).
Without a host the app still works, but there is no tray icon; open it from the launcher.

## If something breaks

Stop the helper first, it undoes its own changes:

```
sudo systemctl stop veil-helper@$(id -u).service
```

If the network is still broken, undo by hand:

```
sudo ip route del 0.0.0.0/1 dev veil0
sudo ip route del 128.0.0.0/1 dev veil0
sudo ip -6 route del ::/1 dev veil0
sudo ip -6 route del 8000::/1 dev veil0
sudo ip link del veil0
sudo resolvectl revert veil0        # systemd-resolved
sudo resolvectl flush-caches
```

Without systemd-resolved, restore `/etc/resolv.conf` from the backup in `/var/lib/veil/`
(or let NetworkManager rewrite it: `sudo systemctl restart NetworkManager`).
Remove the helper: `sudo systemctl disable --now veil-helper@$(id -u).service`.

Logs: `journalctl -u veil-helper@$(id -u)` for the helper; the app writes `veil.log` in its data folder.
