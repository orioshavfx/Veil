//! Linux desktop glue: is there a system tray to live in, and one running copy of the app.
//!
//! The tray is a StatusNotifierItem (waybar's `tray` module, KDE, GNOME with an extension);
//! without a StatusNotifierWatcher on the session bus the icon goes nowhere, so a window that
//! was hidden "to the tray" would be lost. A second launch (from a launcher, while the first
//! copy sits in the tray) asks the running copy to show its window instead of starting another.

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::Command;

/// Names the tray host registers on the session bus.
const WATCHER_NAMES: [&str; 2] = ["org.kde.StatusNotifierWatcher", "org.freedesktop.StatusNotifierWatcher"];

/// `busctl` prints `b true`, `gdbus` prints `(true,)`.
pub fn parse_name_has_owner(out: &str) -> bool {
    let t = out.trim();
    t == "b true" || t == "(true,)"
}

/// Whether a tray host is running. When the check itself cannot be made (no `busctl`, no
/// session bus in this environment), assume there is one: that is what the app did before.
pub fn tray_available() -> bool {
    let mut checked = false;
    for name in WATCHER_NAMES {
        let out = Command::new("busctl")
            .args(["--user", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", name])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                checked = true;
                if parse_name_has_owner(&String::from_utf8_lossy(&o.stdout)) {
                    return true;
                }
            }
            _ => {}
        }
    }
    !checked
}

fn socket_path() -> Option<PathBuf> {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|d| d.is_absolute() && d.is_dir())?;
    // The uid in the name keeps a shared fallback directory from mixing users up.
    let uid = std::fs::metadata("/proc/self").ok()?.uid();
    Some(dir.join(format!("veil-app-{uid}.sock")))
}

pub enum Instance {
    /// This copy runs the app; the listener (if any) receives "show" requests.
    Primary(Option<UnixListener>),
    /// Another copy runs and has been asked to show its window: exit.
    Secondary,
}

/// Claims the single-instance socket, or tells the running copy to show its window.
pub fn single_instance() -> Instance {
    let Some(path) = socket_path() else { return Instance::Primary(None) };
    if let Ok(mut s) = UnixStream::connect(&path) {
        let _ = s.write_all(b"show\n");
        return Instance::Secondary;
    }
    // Nobody answers: a stale file of a dead copy (or none).
    let _ = std::fs::remove_file(&path);
    match UnixListener::bind(&path) {
        Ok(l) => Instance::Primary(Some(l)),
        Err(e) => {
            tracing::warn!("single-instance socket {}: {e}", path.display());
            Instance::Primary(None)
        }
    }
}

/// Calls `on_show` for every "show" request of a second launch, on a background thread.
pub fn serve(listener: UnixListener, on_show: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut buf = [0u8; 16];
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
            if stream.read(&mut buf).is_ok_and(|n| buf[..n].starts_with(b"show")) {
                on_show();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_has_owner_answers() {
        assert!(parse_name_has_owner("b true\n"));
        assert!(parse_name_has_owner("(true,)\n"));
        assert!(!parse_name_has_owner("b false\n"));
        assert!(!parse_name_has_owner("(false,)"));
        assert!(!parse_name_has_owner(""));
    }
}
