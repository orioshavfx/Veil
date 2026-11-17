//! Start Veil at login (Settings → Startup).
//!
//! macOS: a LaunchAgent in `~/Library/LaunchAgents`. Windows: a value under
//! `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`. Both start the app with `--hidden`
//! (menu bar / tray only, no window). Everything is per user and needs no admin rights;
//! turning the setting off removes the entry again.

use anyhow::Result;

#[cfg(any(target_os = "macos", windows))]
pub const AVAILABLE: bool = true;
#[cfg(not(any(target_os = "macos", windows)))]
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

#[cfg(not(any(target_os = "macos", windows)))]
mod imp {
    use anyhow::{Result, bail};

    pub fn set(_on: bool) -> Result<()> {
        bail!("start at login is not available on this system")
    }
}
