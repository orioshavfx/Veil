//! macOS: launchd daemon, Unix socket, installation through osascript.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::{LABEL, Request, Response, VERSION, is_current, status};

pub const SOCKET_PATH: &str = "/var/run/dev.veil.helper.sock";
pub const INSTALL_PATH: &str = "/Library/PrivilegedHelperTools/dev.veil.helper";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/dev.veil.helper.plist";

/// Sends one request and waits for the response.
pub fn call(req: &Request) -> Result<Response> {
    let mut s = UnixStream::connect(SOCKET_PATH).context("helper is not running")?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    s.write_all(&line)?;
    let mut resp = String::new();
    BufReader::new(s).read_line(&mut resp)?;
    let resp: Response = serde_json::from_str(&resp)
        .context("bad response from the TUN helper (it may belong to another version of Veil; connect again to reinstall it)")?;
    if let Response::Error { message } = &resp {
        bail!("{}", crate::error_text(message));
    }
    Ok(resp)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn plist(uid: u32) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{INSTALL_PATH}</string><string>--uid</string><string>{uid}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/dev.veil.helper.log</string>
</dict>
</plist>
"#
    )
}

/// Installs (or upgrades) the helper; macOS asks for an administrator password.
pub fn install(helper_binary: &Path) -> Result<()> {
    if !helper_binary.exists() {
        bail!("helper binary not found at {}", helper_binary.display());
    }
    let uid = unsafe { libc::getuid() };
    // Stage both files outside ~/Documents & co.: those folders are privacy
    // protected and the root shell below may not be allowed to read them.
    // The directory is private (0700, unique, must not pre-exist) so nobody
    // else can swap the files before the root script copies them.
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let stage = std::env::temp_dir().join(format!("{LABEL}.install.{}.{}", std::process::id(), nanos));
    std::fs::DirBuilder::new().mode(0o700).create(&stage).context("cannot create stage directory")?;
    let staged_bin = stage.join("veil-helper");
    let staged_plist = stage.join(format!("{LABEL}.plist"));
    std::fs::copy(helper_binary, &staged_bin).context("cannot stage helper binary")?;
    std::fs::write(&staged_plist, plist(uid))?;
    let bin_hash = crate::file_hash(&staged_bin)?;
    let plist_hash = crate::file_hash(&staged_plist)?;
    let bin = shell_quote(&staged_bin.to_string_lossy());
    let plist_src = shell_quote(&staged_plist.to_string_lossy());
    // `bootout` fails when nothing is loaded; everything after it must succeed.
    // The copies are verified after they became root-owned, so a swap of the
    // staged files during the copy cannot get through.
    let script = format!(
        "/bin/launchctl bootout system/{LABEL} 2>/dev/null ; \
         /bin/mkdir -p /Library/PrivilegedHelperTools && \
         /bin/cp -f {bin} {INSTALL_PATH} && \
         /usr/sbin/chown root:wheel {INSTALL_PATH} && \
         /bin/chmod 755 {INSTALL_PATH} && \
         [ \"$(/usr/bin/shasum -a 256 {INSTALL_PATH} | /usr/bin/cut -d' ' -f1)\" = {bin_hash} ] && \
         /bin/cp -f {plist_src} {PLIST_PATH} && \
         /usr/sbin/chown root:wheel {PLIST_PATH} && \
         /bin/chmod 644 {PLIST_PATH} && \
         [ \"$(/usr/bin/shasum -a 256 {PLIST_PATH} | /usr/bin/cut -d' ' -f1)\" = {plist_hash} ] && \
         /bin/launchctl bootstrap system {PLIST_PATH}"
    );
    let result = run_as_admin(&script, "Veil needs to install a helper to route all traffic (TUN mode).");
    let _ = std::fs::remove_dir_all(&stage);
    result?;
    // Wait for launchd to start it.
    for _ in 0..50 {
        if is_current(helper_binary) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    match status() {
        Ok(s) => bail!("helper {} is running instead of {VERSION}", s.version),
        Err(e) => bail!("helper was installed but does not respond: {e:#}"),
    }
}

pub fn uninstall() -> Result<()> {
    let script = format!(
        "/bin/launchctl bootout system/{LABEL} 2>/dev/null ; /bin/rm -f {PLIST_PATH} {INSTALL_PATH} {SOCKET_PATH}"
    );
    run_as_admin(&script, "Veil wants to remove its helper.")
}

fn run_as_admin(script: &str, prompt: &str) -> Result<()> {
    let apple = format!(
        "do shell script \"{}\" with prompt \"{}\" with administrator privileges",
        script.replace('\\', "\\\\").replace('"', "\\\""),
        prompt.replace('"', "\\\"")
    );
    let out = Command::new("/usr/bin/osascript").arg("-e").arg(apple).output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("-128") {
            bail!("cancelled by user");
        }
        bail!("installation failed: {}", err.trim());
    }
    Ok(())
}

