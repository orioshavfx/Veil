//! Which local process owns a connection, and which apps are installed.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{all_apps, find, process_info, running_apps};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{all_apps, find, process_info, running_apps};

#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
mod socket_table;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{all_apps, find, process_info, running_apps};

/// Reader for the target of a Windows shell link (`.lnk`, MS-SHLLINK). Pure byte
/// handling with bounds checks everywhere, so it is unit-tested on every platform.
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod lnk {
    fn u16_at(b: &[u8], off: usize) -> Option<u16> {
        Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
    }

    fn u32_at(b: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
    }

    /// NUL-terminated single-byte string at `off` (non-ASCII bytes become U+FFFD).
    fn ansi_at(b: &[u8], off: usize) -> Option<String> {
        let rest = b.get(off..)?;
        let end = rest.iter().position(|&c| c == 0)?;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }

    /// NUL-terminated UTF-16LE string at `off`.
    fn utf16_at(b: &[u8], off: usize) -> Option<String> {
        let rest = b.get(off..)?;
        let mut units = Vec::new();
        for pair in rest.chunks_exact(2) {
            let u = u16::from_le_bytes([pair[0], pair[1]]);
            if u == 0 {
                return Some(String::from_utf16_lossy(&units));
            }
            units.push(u);
        }
        None
    }

    /// Local target path from the LinkInfo structure (`LocalBasePath` + `CommonPathSuffix`).
    /// `None` for shortcuts without LinkInfo (Store apps, network targets) or malformed data.
    pub fn target(data: &[u8]) -> Option<String> {
        const HAS_LINK_TARGET_ID_LIST: u32 = 1;
        const HAS_LINK_INFO: u32 = 2;
        const VOLUME_ID_AND_LOCAL_BASE_PATH: u32 = 1;
        if u32_at(data, 0)? != 0x4C {
            return None;
        }
        let flags = u32_at(data, 20)?;
        if flags & HAS_LINK_INFO == 0 {
            return None;
        }
        let mut pos = 0x4Cusize;
        if flags & HAS_LINK_TARGET_ID_LIST != 0 {
            pos = pos.checked_add(2)?.checked_add(usize::from(u16_at(data, pos)?))?;
        }
        let rest = data.get(pos..)?;
        let size = u32_at(rest, 0)? as usize;
        let info = rest.get(..size)?;
        let header_size = u32_at(info, 4)? as usize;
        if u32_at(info, 8)? & VOLUME_ID_AND_LOCAL_BASE_PATH == 0 {
            return None;
        }
        let base_off = u32_at(info, 16)? as usize;
        let suffix_off = u32_at(info, 24)? as usize;
        // Offsets of 0 mean "absent"; they must never be read as string starts.
        let unicode = if header_size >= 0x24 { (u32_at(info, 28)? as usize, u32_at(info, 32)? as usize) } else { (0, 0) };
        let (base, suffix) = if unicode.0 != 0 {
            (utf16_at(info, unicode.0)?, if unicode.1 != 0 { utf16_at(info, unicode.1).unwrap_or_default() } else { String::new() })
        } else {
            if base_off == 0 {
                return None;
            }
            (ansi_at(info, base_off)?, if suffix_off != 0 { ansi_at(info, suffix_off).unwrap_or_default() } else { String::new() })
        };
        let mut path = base;
        if !suffix.is_empty() {
            if !path.is_empty() && !path.ends_with('\\') {
                path.push('\\');
            }
            path.push_str(&suffix);
        }
        (!path.is_empty()).then_some(path)
    }

    /// Last component of a Windows path.
    pub fn file_name(path: &str) -> &str {
        path.rsplit(['\\', '/']).next().unwrap_or("")
    }

    pub fn is_exe(path: &str) -> bool {
        file_name(path).to_lowercase().ends_with(".exe")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Synthetic link: header, optional IDList of `id_list` bytes, ANSI LinkInfo.
        fn make(id_list: Option<usize>, base: &str, suffix: &str) -> Vec<u8> {
            let mut d = vec![0u8; 0x4C];
            d[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
            let flags = 2 | u32::from(id_list.is_some());
            d[20..24].copy_from_slice(&flags.to_le_bytes());
            if let Some(n) = id_list {
                d.extend((n as u16).to_le_bytes());
                d.extend(vec![0xAA; n]);
            }
            let (base_off, suffix_off) = (0x1Cu32, 0x1C + base.len() as u32 + 1);
            let size = suffix_off + suffix.len() as u32 + 1;
            for v in [size, 0x1C, 1, 0x1C, base_off, 0, suffix_off] {
                d.extend(v.to_le_bytes());
            }
            d.extend(base.as_bytes());
            d.push(0);
            d.extend(suffix.as_bytes());
            d.push(0);
            d
        }

        #[test]
        fn reads_target() {
            let p = r"C:\Program Files\Mozilla Firefox\firefox.exe";
            assert_eq!(target(&make(None, p, "")).as_deref(), Some(p));
            assert_eq!(target(&make(Some(7), p, "")).as_deref(), Some(p));
            assert_eq!(
                target(&make(None, r"C:\Program Files\Foo", "foo.exe")).as_deref(),
                Some(r"C:\Program Files\Foo\foo.exe")
            );
            assert!(is_exe(p));
            assert_eq!(file_name(p), "firefox.exe");
            assert!(!is_exe(r"C:\Docs\readme.txt"));
        }

        #[test]
        fn reads_unicode_target() {
            // Header 0x24 with Unicode offsets after the ANSI strings.
            let mut d = vec![0u8; 0x4C];
            d[0..4].copy_from_slice(&0x4Cu32.to_le_bytes());
            d[20..24].copy_from_slice(&2u32.to_le_bytes());
            let ansi = b"C:\\a.exe\0";
            let wide: Vec<u8> = "C:\\\u{43f}.exe".encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
            let base_off = 0x24u32;
            let uni_off = base_off + ansi.len() as u32;
            let size = uni_off + wide.len() as u32 + 2;
            for v in [size, 0x24, 1, 0x24, base_off, 0, base_off, uni_off, size - 2] {
                d.extend(v.to_le_bytes());
            }
            d.extend(ansi);
            d.extend(&wide);
            d.extend([0, 0]);
            assert_eq!(target(&d).as_deref(), Some("C:\\\u{43f}.exe"));
        }

        #[test]
        fn malformed_input_is_none() {
            let full = make(Some(4), r"C:\x\y.exe", "");
            for n in 0..full.len() {
                assert_eq!(target(&full[..n]), None, "prefix {n}");
            }
            let mut bad = full.clone();
            bad[0] = 0x4D;
            assert_eq!(target(&bad), None);
            // Huge IDList size and LinkInfo size must not overflow or panic.
            let mut huge = full.clone();
            huge[0x4C..0x4E].copy_from_slice(&u16::MAX.to_le_bytes());
            assert_eq!(target(&huge), None);
            let mut huge = make(None, "a", "");
            huge[0x4C..0x50].copy_from_slice(&u32::MAX.to_le_bytes());
            assert_eq!(target(&huge), None);
            // String without terminator.
            let mut open = make(None, "abc", "");
            open.truncate(open.len() - 2);
            let link_info_len = ((open.len() - 0x4C) as u32).to_le_bytes();
            open[0x4C..0x50].copy_from_slice(&link_info_len);
            assert_eq!(target(&open), None);
            assert_eq!(target(&[]), None);
        }
    }
}

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

#[cfg_attr(any(windows, target_os = "linux"), allow(dead_code))]
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
