# Security

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting: the **Security** tab →
**Report a vulnerability**. Include the Veil version, macOS version and steps to reproduce.
This is a small hobby-scale project: there is no bug bounty and no guaranteed response time.

Supported: the latest release only (0.1.x, macOS on Apple Silicon). The Windows build is experimental.

## Known limitations

Veil 0.1.0 has had a code review of the root helper but **no independent security audit**.
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

Release builds are ad-hoc signed and **not notarized**. Check `Veil.zip.sha256` or build from source.
Updates are manual: there is no auto-update.

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
