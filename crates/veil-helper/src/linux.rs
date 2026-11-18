//! Linux: systemd service, Unix socket, installation through pkexec (polkit).
//!
//! Nothing user-controlled is interpolated into the root script: the script is a fixed
//! string and the staged paths and hashes are passed as positional parameters.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::{Request, Response, VERSION, is_current, status};

pub const SOCKET_PATH: &str = "/run/veil/helper.sock";
pub const SERVICE_NAME: &str = "veil-helper.service";
pub const UNIT_PATH: &str = "/etc/systemd/system/veil-helper.service";
/// Where a distribution package (pacman) puts the helper; never written by the installer.
pub const PACKAGE_BINARY: &str = "/usr/lib/veil/veil-helper";
/// Where the installer copies the helper when the package one is absent or different.
pub const INSTALL_PATH: &str = "/usr/local/libexec/veil/veil-helper";

const PKEXEC_CANDIDATES: [&str; 2] = ["/usr/bin/pkexec", "/bin/pkexec"];

/// Sends one request and waits for the response.
pub fn call(req: &Request) -> Result<Response> {
    let mut s = UnixStream::connect(SOCKET_PATH)
        .with_context(|| format!("helper is not running (check `systemctl status {SERVICE_NAME}`)"))?;
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

/// Quotes one word of a systemd `ExecStart=` line.
fn systemd_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            // `%` and `$` are expanded by systemd even inside quotes.
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The unit file for a helper at `binary` serving `uid`. Not sandboxed on purpose: the helper
/// has to create TUN devices, change routes and DNS and read the user's geo files.
fn unit_file(binary: &str, uid: u32) -> String {
    format!(
        "[Unit]\n\
         Description=Veil TUN helper\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} --uid {uid}\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         RuntimeDirectory=veil\n\
         RuntimeDirectoryMode=0755\n\
         StateDirectory=veil\n\
         StateDirectoryMode=0700\n\
         LimitNOFILE=65536\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        systemd_quote(binary)
    )
}

/// Copies the binary and the unit, verifies both after they became root-owned, then
/// (re)starts the service. $1 staged binary, $2 its hash, $3 staged unit, $4 its hash.
const COPY_SCRIPT: &str = r#"set -e
systemctl stop veil-helper.service 2>/dev/null || true
install -d -m 755 -o root -g root /usr/local/libexec/veil
install -m 755 -o root -g root "$1" /usr/local/libexec/veil/veil-helper
[ "$(sha256sum /usr/local/libexec/veil/veil-helper | cut -d' ' -f1)" = "$2" ]
install -m 644 -o root -g root "$3" /etc/systemd/system/veil-helper.service
[ "$(sha256sum /etc/systemd/system/veil-helper.service | cut -d' ' -f1)" = "$4" ]
systemctl daemon-reload
systemctl enable veil-helper.service
systemctl restart veil-helper.service
"#;

/// The binary is already installed by the package: only the unit for this uid is written.
/// $1 staged unit, $2 its hash.
const UNIT_ONLY_SCRIPT: &str = r#"set -e
install -m 644 -o root -g root "$1" /etc/systemd/system/veil-helper.service
[ "$(sha256sum /etc/systemd/system/veil-helper.service | cut -d' ' -f1)" = "$2" ]
systemctl daemon-reload
systemctl enable veil-helper.service
systemctl restart veil-helper.service
"#;

/// Never removes the package's binary.
const UNINSTALL_SCRIPT: &str = r#"systemctl disable --now veil-helper.service 2>/dev/null
rm -f /etc/systemd/system/veil-helper.service /usr/local/libexec/veil/veil-helper /run/veil/helper.sock
rmdir /usr/local/libexec/veil 2>/dev/null
systemctl daemon-reload
exit 0
"#;

/// Locates polkit's `pkexec`.
fn find_pkexec() -> Result<&'static str> {
    PKEXEC_CANDIDATES.iter().copied().find(|p| Path::new(p).exists()).context(
        "pkexec not found: install polkit (for example `sudo pacman -S polkit`) and run a polkit \
         authentication agent (hyprpolkitagent, polkit-gnome, ...) in your session",
    )
}

/// Turns a failed pkexec run into advice. pkexec exits with 126 when the user dismissed the
/// dialog and with 127 when authorization could not be obtained.
fn pkexec_error(code: Option<i32>, stderr: &str) -> String {
    let err = stderr.trim();
    match code {
        Some(126) => "cancelled by user".into(),
        Some(127) => format!(
            "authorization failed: {err}. Make sure polkit is installed and a polkit authentication \
             agent (hyprpolkitagent, polkit-gnome, ...) is running in your session"
        ),
        _ => format!("installation failed: {err}"),
    }
}

/// Runs the fixed `script` as root with `args` as $1, $2, ...
fn run_as_root(script: &str, args: &[String]) -> Result<()> {
    let mut cmd = if unsafe { libc::geteuid() } == 0 {
        Command::new("/bin/sh")
    } else {
        let mut c = Command::new(find_pkexec()?);
        c.arg("/bin/sh");
        c
    };
    cmd.arg("-c").arg(script).arg("veil-helper-setup").args(args);
    let out = cmd.output().context("cannot run pkexec")?;
    if !out.status.success() {
        bail!("{}", pkexec_error(out.status.code(), &String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}

/// Private staging directory (0700, unique, must not pre-exist) so nobody else can swap the
/// files before the root script copies them.
fn stage_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && p.is_dir())
        .unwrap_or_else(std::env::temp_dir);
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    let stage = base.join(format!("veil-helper.install.{}.{}", std::process::id(), nanos));
    std::fs::DirBuilder::new().mode(0o700).create(&stage).context("cannot create stage directory")?;
    Ok(stage)
}

/// True when the package binary is exactly the shipped helper, so it can be used in place.
fn package_binary_matches(helper_binary: &Path) -> bool {
    match (crate::file_hash(Path::new(PACKAGE_BINARY)), crate::file_hash(helper_binary)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Installs (or upgrades) the helper; polkit asks for an administrator password.
pub fn install(helper_binary: &Path) -> Result<()> {
    if !helper_binary.exists() {
        bail!("helper binary not found at {}", helper_binary.display());
    }
    let uid = unsafe { libc::getuid() };
    let use_package = package_binary_matches(helper_binary);
    let stage = stage_dir()?;
    let result = (|| {
        let staged_unit = stage.join(SERVICE_NAME);
        let unit = unit_file(if use_package { PACKAGE_BINARY } else { INSTALL_PATH }, uid);
        std::fs::write(&staged_unit, unit)?;
        let unit_hash = crate::file_hash(&staged_unit)?;
        let unit_arg = staged_unit.to_string_lossy().into_owned();
        if use_package {
            run_as_root(UNIT_ONLY_SCRIPT, &[unit_arg, unit_hash])
        } else {
            let staged_bin = stage.join("veil-helper");
            std::fs::copy(helper_binary, &staged_bin).context("cannot stage helper binary")?;
            let bin_hash = crate::file_hash(&staged_bin)?;
            run_as_root(COPY_SCRIPT, &[staged_bin.to_string_lossy().into_owned(), bin_hash, unit_arg, unit_hash])
        }
    })();
    let _ = std::fs::remove_dir_all(&stage);
    result?;
    // Wait for systemd to start it.
    for _ in 0..100 {
        if is_current(helper_binary) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    match status() {
        Ok(s) => bail!("helper {} is running instead of {VERSION}", s.version),
        Err(e) => bail!(
            "helper was installed but does not respond: {e:#} (see `journalctl -u {SERVICE_NAME}`)"
        ),
    }
}

pub fn uninstall() -> Result<()> {
    run_as_root(UNINSTALL_SCRIPT, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_file_has_exec_start_for_uid() {
        let u = unit_file(INSTALL_PATH, 1000);
        assert!(u.contains("ExecStart=\"/usr/local/libexec/veil/veil-helper\" --uid 1000\n"), "{u}");
        assert!(u.contains("[Install]\nWantedBy=multi-user.target"));
        assert!(u.contains("RuntimeDirectory=veil\nRuntimeDirectoryMode=0755"));
        assert!(u.contains("StateDirectory=veil"));
        assert!(unit_file(PACKAGE_BINARY, 0).contains("\"/usr/lib/veil/veil-helper\" --uid 0"));
    }

    #[test]
    fn systemd_quote_escapes_specials() {
        assert_eq!(systemd_quote("/a b/c"), r#""/a b/c""#);
        assert_eq!(systemd_quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(systemd_quote("100%$HOME"), r#""100%%$$HOME""#);
        assert_eq!(systemd_quote("a\nb"), r#""a\nb""#);
    }

    #[test]
    fn scripts_take_paths_as_parameters_only() {
        for s in [COPY_SCRIPT, UNIT_ONLY_SCRIPT] {
            assert!(s.contains("\"$1\"") && s.contains("\"$2\""));
            assert!(!s.contains("/tmp") && !s.contains("XDG_RUNTIME_DIR"));
            assert!(s.starts_with("set -e\n"));
        }
        assert!(COPY_SCRIPT.contains("\"$3\"") && COPY_SCRIPT.contains("\"$4\""));
        // The package binary is never touched by the installer or the uninstaller.
        for s in [COPY_SCRIPT, UNIT_ONLY_SCRIPT, UNINSTALL_SCRIPT] {
            assert!(!s.contains(PACKAGE_BINARY));
        }
        // The paths in the scripts match the constants.
        assert!(COPY_SCRIPT.contains(INSTALL_PATH) && COPY_SCRIPT.contains(UNIT_PATH));
        assert!(UNINSTALL_SCRIPT.contains(INSTALL_PATH) && UNINSTALL_SCRIPT.contains(UNIT_PATH));
        assert!(UNINSTALL_SCRIPT.contains(SOCKET_PATH));
    }

    #[test]
    fn pkexec_errors_are_explained() {
        assert_eq!(pkexec_error(Some(126), ""), "cancelled by user");
        let e = pkexec_error(Some(127), "Error getting authority\n");
        assert!(e.contains("Error getting authority") && e.contains("polkit"), "{e}");
        assert_eq!(pkexec_error(Some(1), " boom "), "installation failed: boom");
        assert_eq!(pkexec_error(None, ""), "installation failed: ");
    }

    #[test]
    fn socket_lives_in_run_veil() {
        assert_eq!(Path::new(SOCKET_PATH).parent(), Some(Path::new("/run/veil")));
    }
}
