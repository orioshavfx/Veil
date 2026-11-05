//! Which local process owns a connection, and which apps are installed.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{all_apps, find, process_info, running_apps};

#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod socket_table;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{all_apps, find, process_info, running_apps};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: i32,
    /// Executable file name, e.g. `Google Chrome Helper`.
    pub exe: String,
    /// Outermost `.app` bundle name, e.g. `Google Chrome`.
    pub app: Option<String>,
    pub path: String,
}

impl ProcessInfo {
    /// Case-insensitive match against an app name, executable name (with or
    /// without `.exe`), or path prefix (`/Applications/…`, `C:\Program Files\…`).
    pub fn matches(&self, pattern: &str) -> bool {
        let p = pattern.trim();
        if p.starts_with('/') {
            return self.path.starts_with(p);
        }
        if p.starts_with("\\\\") || p.get(1..3) == Some(":\\") {
            return self.path.to_lowercase().starts_with(&p.to_lowercase());
        }
        let strip = |s: &str| -> String {
            let l = s.to_lowercase();
            l.strip_suffix(".app").or_else(|| l.strip_suffix(".exe")).unwrap_or(&l).to_string()
        };
        let p = strip(p);
        self.app.as_deref().is_some_and(|a| a.to_lowercase() == p) || strip(&self.exe) == p
    }
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn info_from_path(pid: i32, path: String) -> ProcessInfo {
    let exe = path.rsplit('/').next().unwrap_or("").to_string();
    let app = path
        .split('/')
        .find_map(|c| c.strip_suffix(".app"))
        .map(str::to_string);
    ProcessInfo { pid, exe, app, path }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppEntry {
    pub name: String,
    pub running: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_names() {
        let i = info_from_path(1, "/Applications/Google Chrome.app/Contents/Frameworks/x.framework/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper".into());
        assert_eq!(i.app.as_deref(), Some("Google Chrome"));
        assert!(i.matches("google chrome"));
        assert!(i.matches("Google Chrome Helper"));
        assert!(i.matches("/Applications/Google Chrome.app"));
        assert!(!i.matches("Chrome"));
        let c = info_from_path(2, "/usr/bin/curl".into());
        assert_eq!(c.app, None);
        assert!(c.matches("curl"));
    }

    #[test]
    fn windows_names() {
        let w = ProcessInfo {
            pid: 3,
            exe: "chrome.exe".into(),
            app: Some("Google Chrome".into()),
            path: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(),
        };
        assert!(w.matches("Google Chrome"));
        assert!(w.matches("chrome"));
        assert!(w.matches("CHROME.EXE"));
        assert!(w.matches(r"c:\program files\google"));
        assert!(!w.matches("Chromium"));
    }
}
