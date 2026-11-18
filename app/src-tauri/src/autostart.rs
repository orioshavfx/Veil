//! Start Veil at login (Settings → Startup).
//!
//! macOS: a LaunchAgent in `~/Library/LaunchAgents`. Windows: a value under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Linux: an XDG autostart entry in
//! `~/.config/autostart` (desktop environments that run it; Hyprland and niri need an
//! `exec-once` / `spawn-at-startup` line instead). All of them start the app with `--hidden`
//! (menu bar / tray only, no window). Everything is per user and needs no admin rights;
//! turning the setting off removes the entry again.

use anyhow::Result;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
pub const AVAILABLE: bool = true;
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
pub const AVAILABLE: bool = false;

/// Adds (`on`) or removes the autostart entry for the running executable.
pub fn set(on: bool) -> Result<()> {
    imp::set(on)
}

#[cfg(target_os = "macos")]
mod imp {
    use std::fs;
    use std::path::PathBuf;

    use anyhow::{Context, Result};

    const LABEL: &str = "dev.veil.app.login";

    fn plist_path() -> Result<PathBuf> {
        let home = std::env::var_os("HOME").context("HOME is not set")?;
        Ok(PathBuf::from(home).join("Library/LaunchAgents").join(format!("{LABEL}.plist")))
    }

    fn xml(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    pub fn render(exe: &str) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
\t<key>Label</key>\n\t<string>{LABEL}</string>\n\
\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>{}</string>\n\t\t<string>{}</string>\n\t</array>\n\
\t<key>RunAtLoad</key>\n\t<true/>\n\
</dict>\n</plist>\n",
            xml(exe),
            crate::core::HIDDEN_ARG
        )
    }

    pub fn set(on: bool) -> Result<()> {
        let path = plist_path()?;
        if !on {
            return match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).context("removing the login item"),
            };
        }
        let exe = std::env::current_exe().context("cannot find the app")?;
        let exe = exe.to_str().context("the app path is not valid UTF-8")?;
        fs::create_dir_all(path.parent().context("no LaunchAgents folder")?)?;
        fs::write(&path, render(exe)).context("writing the login item")
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn plist_runs_the_app_hidden_at_load() {
            let p = super::render("/Applications/Veil & Co/Veil.app/Contents/MacOS/veil-app");
            assert!(p.contains("<string>/Applications/Veil &amp; Co/Veil.app/Contents/MacOS/veil-app</string>"));
            assert!(p.contains("<string>--hidden</string>"));
            assert!(p.contains("<key>RunAtLoad</key>\n\t<true/>"));
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs;
    use std::path::PathBuf;

    use anyhow::{Context, Result, bail};

    const FILE_NAME: &str = "dev.veil.app.desktop";

    /// `$XDG_CONFIG_HOME/autostart` (default `~/.config/autostart`).
    fn entry_path() -> Result<PathBuf> {
        let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| std::path::Path::new(v).is_absolute()) {
            Some(d) => PathBuf::from(d),
            None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".config"),
        };
        Ok(base.join("autostart").join(FILE_NAME))
    }

    /// One argument of an `Exec` line, quoted per the Desktop Entry specification: arguments
    /// with reserved characters go in double quotes, `"`, `` ` ``, `$` and `\` get a backslash,
    /// `%` is doubled (field codes), and the backslashes are doubled once more because the
    /// value is itself a desktop-entry string.
    pub fn exec_arg(arg: &str) -> String {
        const RESERVED: &str = " \t\n\"'\\><~|&;$*?#()`";
        let mut out = String::new();
        let quoted = arg.is_empty() || arg.chars().any(|c| RESERVED.contains(c));
        if quoted {
            out.push('"');
        }
        for c in arg.chars() {
            match c {
                '"' | '`' | '$' | '\\' if quoted => {
                    out.push('\\');
                    out.push(c);
                }
                '%' => out.push_str("%%"),
                _ => out.push(c),
            }
        }
        if quoted {
            out.push('"');
        }
        out.replace('\\', "\\\\")
    }

    pub fn render(exe: &str) -> String {
        format!(
            "[Desktop Entry]\nType=Application\nName=Veil\nComment=Veil VPN\nExec={} {}\nTerminal=false\nX-GNOME-Autostart-enabled=true\n",
            exec_arg(exe),
            crate::core::HIDDEN_ARG
        )
    }

    /// `current_exe` of a binary that was replaced (a package upgrade) ends in " (deleted)".
    fn live_exe_path(exe: &str) -> &str {
        exe.strip_suffix(" (deleted)").unwrap_or(exe)
    }

    pub fn set(on: bool) -> Result<()> {
        let path = entry_path()?;
        if !on {
            return match fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).context("removing the autostart entry"),
            };
        }
        let exe = std::env::current_exe().context("cannot find the app")?;
        let exe = exe.to_str().context("the app path is not valid UTF-8")?;
        let exe = live_exe_path(exe);
        if exe.contains('\n') {
            bail!("the app path contains a line break");
        }
        fs::create_dir_all(path.parent().context("no autostart folder")?)?;
        fs::write(&path, render(exe)).context("writing the autostart entry")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn plain_path_stays_unquoted() {
            assert_eq!(exec_arg("/usr/bin/veil-app"), "/usr/bin/veil-app");
        }

        #[test]
        fn reserved_characters_are_quoted_and_escaped() {
            assert_eq!(exec_arg("/opt/Veil App/veil"), "\"/opt/Veil App/veil\"");
            assert_eq!(exec_arg("/opt/a\"b$c`d"), "\"/opt/a\\\\\"b\\\\$c\\\\`d\"");
            // A literal backslash is four in the file, a percent sign is doubled.
            assert_eq!(exec_arg("/opt/a\\b"), "\"/opt/a\\\\\\\\b\"");
            assert_eq!(exec_arg("/opt/100%"), "/opt/100%%");
        }

        #[test]
        fn entry_runs_the_app_hidden_at_login() {
            let e = render("/usr/bin/veil-app");
            assert!(e.starts_with("[Desktop Entry]\nType=Application\n"));
            assert!(e.contains("\nExec=/usr/bin/veil-app --hidden\n"));
            assert!(e.contains("\nX-GNOME-Autostart-enabled=true\n"));
        }

        #[test]
        fn replaced_binary_suffix_is_dropped() {
            assert_eq!(live_exe_path("/usr/bin/veil-app (deleted)"), "/usr/bin/veil-app");
            assert_eq!(live_exe_path("/usr/bin/veil-app"), "/usr/bin/veil-app");
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    use anyhow::{Context, Result, bail};

    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
    const NAME: &str = "Veil";
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub fn set(on: bool) -> Result<()> {
        let mut cmd = Command::new("reg");
        if on {
            let exe = std::env::current_exe().context("cannot find the app")?;
            let value = format!("\"{}\" {}", exe.display(), crate::core::HIDDEN_ARG);
            cmd.args(["add", KEY, "/v", NAME, "/t", "REG_SZ", "/d", &value, "/f"]);
        } else {
            cmd.args(["delete", KEY, "/v", NAME, "/f"]);
        }
        let out = cmd.creation_flags(CREATE_NO_WINDOW).output().context("running reg.exe")?;
        // Deleting a value that is not there is fine.
        if !out.status.success() && on {
            bail!("could not change the autostart entry: {}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
mod imp {
    use anyhow::{Result, bail};

    pub fn set(_on: bool) -> Result<()> {
        bail!("start at login is not available on this system")
    }
}
