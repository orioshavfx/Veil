//! Linux: socket owners come from `/proc/net/{tcp,tcp6,udp,udp6}` (local endpoint -> inode)
//! and a scan of `/proc/<pid>/fd` (inode -> pid). Both are cached for a short time, so a
//! burst of new connections does not rescan `/proc` for each one. Installed apps come from
//! `.desktop` files (system, user and Flatpak exports).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::{AppEntry, ProcessInfo, Proto};

/// A cached table is rebuilt on a miss only when it is at least this old.
const MISS_REFRESH_AFTER: Duration = Duration::from_millis(50);
/// A cached table is used for hits up to this age.
const TABLE_TTL: Duration = Duration::from_millis(500);
const OWNERS_TTL: Duration = Duration::from_secs(3);
const DESKTOP_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    addr: IpAddr,
    port: u16,
    inode: u64,
}

fn hex_words(s: &str, words: usize) -> Option<Vec<u8>> {
    if s.len() != words * 8 {
        return None;
    }
    let mut out = Vec::with_capacity(words * 4);
    for i in 0..words {
        // The kernel prints each 32-bit word of the address in host byte order.
        out.extend(u32::from_str_radix(s.get(i * 8..i * 8 + 8)?, 16).ok()?.to_ne_bytes());
    }
    Some(out)
}

/// Rows of `/proc/net/{tcp,udp}[6]` with a socket inode.
fn parse_table(text: &str) -> Vec<Entry> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (local, inode) = (f.get(1)?, f.get(9)?);
            let (a, p) = local.split_once(':')?;
            let addr: IpAddr = match a.len() {
                8 => Ipv4Addr::from(<[u8; 4]>::try_from(hex_words(a, 1)?).ok()?).into(),
                32 => Ipv6Addr::from(<[u8; 16]>::try_from(hex_words(a, 4)?).ok()?).into(),
                _ => return None,
            };
            let inode: u64 = inode.parse().ok()?;
            (inode != 0).then(|| Entry { addr, port: u16::from_str_radix(p, 16).ok()?, inode })
        })
        .collect()
}

/// How well a socket bound to `have` serves the local endpoint `want`: 2 exact, 1 wildcard.
fn addr_score(have: IpAddr, want: IpAddr) -> u8 {
    if have == want {
        return 2;
    }
    match (have, want) {
        (h, _) if h.is_unspecified() => 1,
        (IpAddr::V6(h), IpAddr::V4(w)) if h.to_ipv4_mapped() == Some(w) => 2,
        _ => 0,
    }
}

fn find_inode(entries: &[Entry], local: SocketAddr) -> Option<u64> {
    entries
        .iter()
        .filter(|e| e.port == local.port())
        .map(|e| (addr_score(e.addr, local.ip()), e.inode))
        .filter(|(s, _)| *s > 0)
        .max_by_key(|(s, _)| *s)
        .map(|(_, inode)| inode)
}

struct Cached<T> {
    at: Instant,
    value: T,
}

impl<T> Cached<T> {
    fn new(value: T) -> Self {
        Self { at: Instant::now(), value }
    }
}

type Tables = HashMap<u8, Cached<Vec<Entry>>>;
static TABLES: Mutex<Option<Tables>> = Mutex::new(None);
static OWNERS: Mutex<Option<Cached<HashMap<u64, i32>>>> = Mutex::new(None);

fn read_tables(proto: Proto) -> Vec<Entry> {
    let files: [&str; 2] = match proto {
        Proto::Tcp => ["/proc/net/tcp", "/proc/net/tcp6"],
        Proto::Udp => ["/proc/net/udp", "/proc/net/udp6"],
    };
    files.iter().filter_map(|f| std::fs::read_to_string(f).ok()).flat_map(|t| parse_table(&t)).collect()
}

fn lookup_inode(proto: Proto, local: SocketAddr) -> Option<u64> {
    let key = proto as u8;
    let mut guard = TABLES.lock().unwrap();
    let tables = guard.get_or_insert_default();
    if let Some(c) = tables.get(&key)
        && c.at.elapsed() < TABLE_TTL
        && let Some(i) = find_inode(&c.value, local)
    {
        return Some(i);
    }
    // Miss (or stale): the socket may be newer than the snapshot.
    if tables.get(&key).is_some_and(|c| c.at.elapsed() < MISS_REFRESH_AFTER) {
        return None;
    }
    let fresh = Cached::new(read_tables(proto));
    let found = find_inode(&fresh.value, local);
    tables.insert(key, fresh);
    found
}

fn scan_owners() -> HashMap<u64, i32> {
    let mut map: HashMap<u64, i32> = HashMap::new();
    let Ok(procs) = std::fs::read_dir("/proc") else { return map };
    for p in procs.flatten() {
        let Some(pid) = p.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else { continue };
        let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            let Some(inode) = target.to_str().and_then(|t| t.strip_prefix("socket:[")).and_then(|t| t.strip_suffix(']')) else {
                continue;
            };
            if let Ok(inode) = inode.parse::<u64>() {
                map.entry(inode).and_modify(|o| *o = (*o).min(pid)).or_insert(pid);
            }
        }
    }
    map
}

fn owner_of(inode: u64) -> Option<i32> {
    let mut guard = OWNERS.lock().unwrap();
    if let Some(c) = guard.as_ref()
        && c.at.elapsed() < OWNERS_TTL
        && let Some(&pid) = c.value.get(&inode)
    {
        return Some(pid);
    }
    if guard.as_ref().is_some_and(|c| c.at.elapsed() < MISS_REFRESH_AFTER) {
        return None;
    }
    let fresh = Cached::new(scan_owners());
    let pid = fresh.value.get(&inode).copied();
    *guard = Some(fresh);
    pid
}

// ---- desktop entries ----

#[derive(Debug, Clone, PartialEq, Eq)]
struct Desktop {
    /// File stem, e.g. `org.mozilla.firefox`.
    id: String,
    name: String,
    /// Executable (as written, path or bare name) of the launched program.
    exec: Option<String>,
    hidden: bool,
}

/// First word of an `Exec=` line that names the program: skips `env VAR=x`, and for
/// `flatpak run` returns the `--command=` value when present.
fn exec_program(exec: &str) -> Option<String> {
    let mut words = exec.split_whitespace().map(|w| w.trim_matches('"'));
    let mut first = words.next()?;
    if first == "env" || first.ends_with("/env") {
        first = words.find(|w| !w.contains('='))?;
    }
    if first.rsplit('/').next() == Some("flatpak") {
        return words.find_map(|w| w.strip_prefix("--command=")).map(str::to_string);
    }
    (!first.starts_with('%')).then(|| first.to_string())
}

fn parse_desktop(text: &str, id: &str) -> Option<Desktop> {
    let (mut name, mut exec, mut hidden, mut is_app, mut in_entry) = (None, None, false, true, false);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        match line.split_once('=') {
            Some(("Name", v)) => name = Some(v.trim().to_string()),
            Some(("Exec", v)) => exec = exec_program(v),
            Some(("NoDisplay" | "Hidden", v)) => hidden |= v.trim() == "true",
            Some(("Type", v)) => is_app = v.trim() == "Application",
            _ => {}
        }
    }
    let name = name.filter(|n| !n.is_empty())?;
    is_app.then(|| Desktop { id: id.to_string(), name, exec, hidden })
}

fn desktop_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = Path::new(&home);
        dirs.push(home.join(".local/share/applications"));
        dirs.push(home.join(".local/share/flatpak/exports/share/applications"));
    }
    let data = std::env::var("XDG_DATA_DIRS").unwrap_or_default();
    for d in data.split(':').filter(|d| !d.is_empty()) {
        dirs.push(Path::new(d).join("applications"));
    }
    for d in [
        "/usr/local/share/applications",
        "/usr/share/applications",
        "/var/lib/flatpak/exports/share/applications",
        "/var/lib/snapd/desktop/applications",
    ] {
        dirs.push(PathBuf::from(d));
    }
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));
    dirs
}

fn scan_desktops() -> Vec<Desktop> {
    let mut out: Vec<Desktop> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // Earlier directories win (user overrides system), as in the XDG spec.
    for dir in desktop_dirs() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let path = e.path();
            let Some(id) = path.file_name().and_then(|n| n.to_str()).and_then(|n| n.strip_suffix(".desktop")) else {
                continue;
            };
            if !seen.insert(id.to_string()) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&path)
                && let Some(d) = parse_desktop(&text, id)
            {
                out.push(d);
            }
        }
    }
    out
}

static DESKTOPS: Mutex<Option<Cached<std::sync::Arc<Vec<Desktop>>>>> = Mutex::new(None);

fn desktops() -> std::sync::Arc<Vec<Desktop>> {
    let mut guard = DESKTOPS.lock().unwrap();
    if let Some(c) = guard.as_ref()
        && c.at.elapsed() < DESKTOP_TTL
    {
        return c.value.clone();
    }
    let fresh = Cached::new(std::sync::Arc::new(scan_desktops()));
    let v = fresh.value.clone();
    *guard = Some(fresh);
    v
}

/// Flatpak app id from a path under `.../flatpak/app/<id>/...`.
fn flatpak_id(path: &str) -> Option<&str> {
    let rest = path.split_once("/flatpak/app/")?.1;
    rest.split('/').next().filter(|s| !s.is_empty())
}

/// Desktop entry name for a program path (by launched executable, or Flatpak id).
fn app_name(desktops: &[Desktop], path: &str, exe: &str) -> Option<String> {
    if let Some(id) = flatpak_id(path)
        && let Some(d) = desktops.iter().find(|d| d.id == id)
    {
        return Some(d.name.clone());
    }
    let by = |full: bool| {
        desktops.iter().find(|d| {
            d.exec.as_deref().is_some_and(|e| if full { e == path } else { e.rsplit('/').next() == Some(exe) })
        })
    };
    by(true).or_else(|| by(false)).map(|d| d.name.clone())
}

// ---- processes ----

/// Executable path of `pid` without the kernel's ` (deleted)` marker (updated packages).
fn pid_path(pid: i32) -> Option<String> {
    let p = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let s = p.to_str()?;
    Some(s.strip_suffix(" (deleted)").unwrap_or(s).to_string())
}

fn pid_comm(pid: i32) -> Option<String> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(s.trim_end().to_string()).filter(|s| !s.is_empty())
}

pub fn process_info(pid: i32) -> Option<ProcessInfo> {
    let (path, exe) = match pid_path(pid) {
        Some(p) => {
            let exe = p.rsplit('/').next().unwrap_or("").to_string();
            (p, exe)
        }
        // Other users' processes hide their exe link without root; comm is still readable.
        None => (String::new(), pid_comm(pid)?),
    };
    let app = app_name(&desktops(), &path, &exe);
    Some(ProcessInfo { pid, exe, app, path })
}

/// The process that owns the local socket `local` (the client side of a connection).
pub fn find(proto: Proto, local: SocketAddr) -> Option<ProcessInfo> {
    let inode = lookup_inode(proto, local)?;
    process_info(owner_of(inode)?)
}

fn all_pids() -> Vec<i32> {
    std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect()
}

/// Names (from `.desktop` entries) of running apps.
pub fn running_apps() -> Vec<String> {
    let ds = desktops();
    let mut apps: Vec<String> = all_pids()
        .into_iter()
        .filter_map(|pid| {
            let path = pid_path(pid)?;
            let exe = path.rsplit('/').next().unwrap_or("").to_string();
            app_name(&ds, &path, &exe)
        })
        .collect();
    apps.sort();
    apps.dedup();
    apps
}

pub fn all_apps() -> Vec<AppEntry> {
    let mut installed: Vec<String> = desktops().iter().filter(|d| !d.hidden).map(|d| d.name.clone()).collect();
    let running = running_apps();
    installed.extend(running.iter().cloned());
    installed.sort_by_key(|a| a.to_lowercase());
    installed.dedup();
    installed.into_iter().map(|name| AppEntry { running: running.contains(&name), name }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 20 4 30 10 -1
   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn parses_tcp4() {
        let e = parse_table(TCP);
        assert_eq!(e.len(), 2); // inode 0 is skipped
        assert_eq!(e[0], Entry { addr: "127.0.0.1".parse().unwrap(), port: 8080, inode: 12345 });
        assert_eq!(find_inode(&e, "127.0.0.1:50000".parse().unwrap()), Some(23456));
        assert_eq!(find_inode(&e, "127.0.0.1:1".parse().unwrap()), None);
    }

    #[test]
    fn parses_tcp6_and_mapped() {
        // ::1 and ::ffff:127.0.0.1, as printed on a little-endian host.
        let w = |a: Ipv6Addr| a.octets().chunks(4).map(|c| format!("{:08X}", u32::from_ne_bytes(c.try_into().unwrap()))).collect::<String>();
        let text = format!(
            "header\n 0: {}:1F90 {}:0000 0A 0:0 0:0 0 1000 0 777 1\n 1: {}:0050 {}:0000 0A 0:0 0:0 0 1000 0 888 1\n",
            w("::1".parse().unwrap()),
            w(Ipv6Addr::UNSPECIFIED),
            w("::ffff:127.0.0.1".parse().unwrap()),
            w(Ipv6Addr::UNSPECIFIED),
        );
        let e = parse_table(&text);
        assert_eq!(find_inode(&e, "[::1]:8080".parse().unwrap()), Some(777));
        assert_eq!(find_inode(&e, "127.0.0.1:80".parse().unwrap()), Some(888));
        assert_eq!(find_inode(&e, "[::1]:80".parse().unwrap()), None);
    }

    #[test]
    fn exact_address_beats_wildcard() {
        let e = vec![
            Entry { addr: "0.0.0.0".parse().unwrap(), port: 53, inode: 1 },
            Entry { addr: "10.0.0.5".parse().unwrap(), port: 53, inode: 2 },
        ];
        assert_eq!(find_inode(&e, "10.0.0.5:53".parse().unwrap()), Some(2));
        assert_eq!(find_inode(&e, "10.0.0.6:53".parse().unwrap()), Some(1));
    }

    #[test]
    fn malformed_rows_are_skipped() {
        assert!(parse_table("h\n 0: ZZ:1F90 0:0 0A 0 0 0 0 0 5\n 1: 0100007F 0 0 0 0 0 0 0 5\n 2: short\n").is_empty());
    }

    #[test]
    fn desktop_entries() {
        let t = "[Desktop Entry]\nType=Application\nName=Firefox Web Browser\nName[ru]=Firefox\nExec=/usr/lib/firefox/firefox %u\n[Desktop Action new-window]\nName=New Window\nExec=firefox --new-window\n";
        let d = parse_desktop(t, "firefox").unwrap();
        assert_eq!(d.name, "Firefox Web Browser");
        assert_eq!(d.exec.as_deref(), Some("/usr/lib/firefox/firefox"));
        assert!(!d.hidden);
        assert_eq!(exec_program("env GDK_BACKEND=x11 steam %U").as_deref(), Some("steam"));
        assert_eq!(
            exec_program("/usr/bin/flatpak run --branch=stable --arch=x86_64 --command=firefox org.mozilla.firefox @@u %u @@").as_deref(),
            Some("firefox")
        );
        assert_eq!(parse_desktop("[Desktop Entry]\nType=Link\nName=X\n", "x"), None);
        assert!(parse_desktop("[Desktop Entry]\nName=Hid\nExec=hid\nNoDisplay=true\n", "hid").unwrap().hidden);
    }

    #[test]
    fn app_name_lookup() {
        let ds = vec![
            Desktop { id: "google-chrome".into(), name: "Google Chrome".into(), exec: Some("/usr/bin/google-chrome-stable".into()), hidden: false },
            Desktop { id: "org.telegram.desktop".into(), name: "Telegram".into(), exec: Some("telegram-desktop".into()), hidden: false },
        ];
        assert_eq!(app_name(&ds, "/opt/google/chrome/google-chrome-stable", "google-chrome-stable").as_deref(), Some("Google Chrome"));
        assert_eq!(app_name(&ds, "/usr/bin/telegram-desktop", "telegram-desktop").as_deref(), Some("Telegram"));
        assert_eq!(
            app_name(&ds, "/var/lib/flatpak/app/org.telegram.desktop/x86_64/stable/abc/files/bin/Telegram", "Telegram").as_deref(),
            Some("Telegram")
        );
        assert_eq!(app_name(&ds, "/usr/bin/curl", "curl"), None);
    }

    #[test]
    fn linux_paths_match() {
        let i = ProcessInfo { pid: 1, exe: "firefox".into(), app: Some("Firefox Web Browser".into()), path: "/usr/lib/firefox/firefox".into() };
        assert!(i.matches("firefox"));
        assert!(i.matches("Firefox Web Browser"));
        assert!(i.matches("/usr/lib/firefox"));
        assert!(!i.matches("/usr/bin"));
    }

    #[test]
    fn finds_own_tcp_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let info = find(Proto::Tcp, client.local_addr().unwrap()).expect("own socket not found");
        assert_eq!(info.pid, std::process::id() as i32);
        assert!(!info.exe.is_empty());
    }

    #[test]
    fn finds_own_udp_socket() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect("127.0.0.1:9").unwrap();
        let info = find(Proto::Udp, sock.local_addr().unwrap()).expect("own socket not found");
        assert_eq!(info.pid, std::process::id() as i32);
    }

    #[test]
    fn lists_running_apps_without_panic() {
        let apps = all_apps();
        let mut names: Vec<_> = apps.iter().map(|a| a.name.to_lowercase()).collect();
        names.dedup();
        assert_eq!(names.len(), apps.len(), "duplicates");
    }
}
