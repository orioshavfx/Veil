# Security

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting: the **Security** tab →
**Report a vulnerability**. Include the Veil version, macOS version and steps to reproduce.
This is a small hobby-scale project: there is no bug bounty and no guaranteed response time.

Supported: the latest release only (1.0.0-beta.x, macOS on Apple Silicon). The Windows build is experimental.

## Known limitations

Veil 1.0.0-beta.1 has had a code review of the root helper but **no independent security audit**.
These are the weaknesses we know about. They are not fixed yet.

### The TUN helper runs as root

TUN mode installs `dev.veil.helper`, a launchd daemon that runs as root and keeps running
(`RunAtLoad`, `KeepAlive`) until you remove it (see the README).

1. **It trusts every process of the user who installed it.** Access is checked by uid only
   (`getpeereid` on `/var/run/dev.veil.helper.sock`), not by code signature. Any program that runs
   as that user can tell the helper to start a tunnel to a server of its choice. It can then route
   all traffic of the machine, including other users and root, through that server, change the
   system DNS, and add or remove host routes. It cannot run arbitrary code as root through this.
   Do not install the helper on a machine where untrusted code runs under your account, and do not
   let a user without administrator rights install it.
2. **Install and update are not signature-checked.** The app installs the `veil-helper` binary from
   its own bundle with `osascript … with administrator privileges`, and asks for the password again
   whenever that file changes. If `/Applications/Veil.app` is writable by malware running as you,
   it could replace the helper and get root after you type the password. Do not enter the password
   if you have not just installed or updated Veil. Builds are not notarized.
3. **The helper log may be readable by other local users.** `/var/log/dev.veil.helper.log` is written
   by launchd. It contains your server address and the destinations of failed connections, and it is
   not rotated. Check the permissions with `ls -l /var/log/dev.veil.helper.log`.
4. **If the helper is killed, DNS stays at `198.18.0.2`** until launchd restarts it (it normally does
   within seconds and restores DNS). If it does not, run
   `networksetup -setdnsservers <service> Empty`.
5. **`veil-cli run --tun` with `sudo`** (debug CLI) makes root read and write files in your user data
   directory. Do not use it on multi-user machines. Use the app instead.
6. **Standby (kill switch) only holds while the app and the helper run.** It lives in the helper's
   memory. If Veil quits or crashes, the helper notices that the app is gone and removes the
   tunnel, and traffic goes out directly again; if the helper itself dies, launchd restarts it
   without a tunnel. Standby is not saved: Veil started again is plainly disconnected. It is a
   convenience against accidental leaks, not a firewall.
7. **Local proxy port without authentication.** In Proxy mode and in the helper, the local
   SOCKS/HTTP port listens on `127.0.0.1` and any local user can use it.

### Your data

- `~/Library/Application Support/dev.veil.veil/state.json` holds your links, UUIDs, passwords and
  subscription URLs. It relies on file permissions (see the hardening notes in `CHANGELOG.md`).
- Check `~/Library/Logs/Veil/veil.log` before attaching it to an issue and remove addresses,
  UUIDs, passwords and subscription URLs.

### Builds

Release builds are ad-hoc signed and **not notarized**. Check `SHA256SUMS` from the release or
build from source.

### In-app updates (macOS)

- **Where from:** only `https://github.com/orioshavfx/Veil/releases/latest/download/latest.json`
  (HTTPS, compiled into the app), and the `Veil.app.tar.gz` it names. GitHub's "latest release"
  is the trust root for *which* version is offered; the signature decides *whether* it is installed.
- **Signature:** every update package is signed with minisign (Tauri's updater format) by a key
  that only the project owner has (on their own Mac and as a GitHub Actions secret; never in the
  repository). The public key is compiled into the app (`UPDATER_PUBKEY` in
  `app/src-tauri/src/updater.rs`). A package whose signature does not verify is not installed.
  The signature also covers the version it was made for, and the app requires it to match the
  announced version, so an older signed release cannot be passed off as a newer one; and only a
  version greater than the running one is installed (no downgrades). The release workflow
  checks the same before it publishes anything: it fails when `UPDATER_PUBKEY` is empty or when
  the signature does not verify with it for the tagged version (`app/tools/update-sig-check`,
  which checks the way the updater plugin does). The private key and its password are given only
  to the signing step, never to the build.
- **Builds without a key** (an empty `UPDATER_PUBKEY`, as in source builds) make no update
  requests at all and say "Updates are not configured in this build".
- **What it cannot protect against:** someone with the signing key or with write access to the
  repository's releases and secrets can ship an update. The app bundle itself is not notarized;
  the update keeps the same ad-hoc signature model.
- **Order of steps:** download and signature check first (the VPN keeps running), then the VPN is
  stopped exactly as on Quit (system proxy, DNS and routes restored, a standby included), then the
  bundle is replaced (macOS asks for an administrator password if the folder is not writable) and
  the app restarts. An update is not started while Veil is connecting, and only one at a time.
  Before the download, Veil checks that it runs from an app bundle that can be replaced (not App
  Translocation, not a read-only disk); otherwise it stops with an error and the VPN is not
  touched. If the installation fails after the VPN was stopped, the VPN stays off (kill switch
  included) and the app says so until you connect again.
- **The TUN helper after an update:** the new app ships a new `veil-helper`. Before the next TUN
  connection the app compares the running helper with the one in its bundle (SHA-256) and
  reinstalls it if they differ, which asks for the administrator password (see item 2 above:
  enter it only right after you installed or updated Veil). A helper of another version that
  gets a request it does not understand answers only `bad request: unknown variant …`; the new
  app turns that answer into a message that says to disconnect and connect again, which
  reinstalls the helper (`error_text` in `crates/veil-helper`).
- **Homebrew:** the cask downloads `Veil.zip` from the same GitHub release and checks its SHA-256.
  It is marked `auto_updates`, so Homebrew leaves updates to the app.
- **Network:** the update check is the only request Veil makes on its own (once at startup, if
  enabled, and when you click "Check for updates"); the download follows "Install and restart".
  Both go to github.com (downloads may be redirected to `*.githubusercontent.com`). GitHub sees
  your IP address (the real one if the VPN is not connected at that moment) and the User-Agent
  `tauri-plugin-updater/<version>`; the app version is not sent. The startup check can be turned
  off in Settings → Updates.

### Network requests and data files (Unreleased)

Veil contains no built-in server, subscription or geo-list addresses and makes no network
requests of its own beyond your servers, their pings, the subscription URLs you add and the
update check described above. Geo
lists are no longer bundled or downloaded: `geoip.dat` / `geosite.dat` are read only if you
put them into the data folder yourself, so their source and integrity are up to you. With the
TUN helper they are copied into a root-owned folder with the checks described in the code
(`crates/veil-helper`).

### Not covered

Veil is a proxy client. It does not make you anonymous, and it cannot protect you from a server
you do not trust.

## Planned hardening

- Install the helper with `SMAppService` and verify the client's code signature (audit token)
  in the helper instead of trusting the uid.
- Verify the helper's signature before installing it, and install it through a temporary file
  and an atomic move.
- Restrict the server address and host routes the helper accepts to public addresses.
- Make the helper log private, rotated and free of destination addresses.
