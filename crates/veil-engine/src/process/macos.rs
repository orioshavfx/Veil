//! macOS: reads the kernel's socket tables (`net.inet.{tcp,udp}.pcblist_n`).
//! Each entry is a sequence of self-describing records (`len`, `kind`), so we
//! locate the records by kind and only rely on field offsets inside them.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;

use super::{AppEntry, ProcessInfo, Proto, info_from_path};

const XSO_SOCKET: u32 = 0x001;
const XSO_INPCB: u32 = 0x010;

// xinpcb_n (packed to 4 bytes)
const INP_LPORT: usize = 18;
const INP_VFLAG: usize = 44;
const INP_LADDR6: usize = 64;
const INP_LADDR4: usize = 76;
const INP_V4: u8 = 0x1;
const INP_V6: u8 = 0x2;
// xsocket_n
const SO_LAST_PID: usize = 68;
const SO_E_PID: usize = 72;

fn sysctl_raw(name: &str) -> Option<Vec<u8>> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut len = 0usize;
    unsafe {
        if libc::sysctlbyname(cname.as_ptr(), std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        // The table can grow between the two calls.
        len += len / 4 + 4096;
        let mut buf = vec![0u8; len];
        if libc::sysctlbyname(cname.as_ptr(), buf.as_mut_ptr().cast(), &mut len, std::ptr::null_mut(), 0) != 0 {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Finds the pid owning the local endpoint `local` in a pcblist_n dump.
fn find_in_table(buf: &[u8], local: SocketAddr) -> Option<i32> {
    let mut off = u32_at(buf, 0)? as usize; // skip the leading xinpgen
    let mut inp_match = false;
    while off + 8 <= buf.len() {
        let len = u32_at(buf, off)? as usize;
        let kind = u32_at(buf, off + 4)?;
        if len < 8 {
            break;
        }
        let rec = buf.get(off..off + len)?;
        match kind {
            XSO_INPCB => {
                let port = u16::from_be_bytes([*rec.get(INP_LPORT)?, *rec.get(INP_LPORT + 1)?]);
                let vflag = *rec.get(INP_VFLAG)?;
                inp_match = port == local.port()
                    && match local.ip() {
                        IpAddr::V4(want) => {
                            vflag & INP_V4 != 0 && {
                                let a = Ipv4Addr::from(<[u8; 4]>::try_from(rec.get(INP_LADDR4..INP_LADDR4 + 4)?).ok()?);
                                a == want || a.is_unspecified()
                            }
                        }
                        IpAddr::V6(want) => {
                            vflag & INP_V6 != 0 && {
                                let a = Ipv6Addr::from(<[u8; 16]>::try_from(rec.get(INP_LADDR6..INP_LADDR6 + 16)?).ok()?);
                                a == want || a.is_unspecified()
                            }
                        }
                    };
            }
            XSO_SOCKET if inp_match => {
                let e_pid = u32_at(rec, SO_E_PID)? as i32;
                let last_pid = u32_at(rec, SO_LAST_PID)? as i32;
                // The effective pid names the app when a daemon connects on its behalf.
                return Some(if e_pid > 0 { e_pid } else { last_pid });
            }
            _ => {}
        }
        off += (len + 7) & !7;
    }
    None
}

fn pid_path(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    String::from_utf8(buf).ok()
}

static PATHS: Mutex<Option<HashMap<i32, String>>> = Mutex::new(None);

pub fn process_info(pid: i32) -> Option<ProcessInfo> {
    if let Some(p) = PATHS.lock().unwrap().get_or_insert_default().get(&pid) {
        return Some(info_from_path(pid, p.clone()));
    }
    let path = pid_path(pid)?;
    let mut cache = PATHS.lock().unwrap();
    let map = cache.get_or_insert_default();
    if map.len() > 4096 {
        map.clear(); // pids get reused; keep it simple
    }
    map.insert(pid, path.clone());
    Some(info_from_path(pid, path))
}

/// The process that owns the local socket `local` (the client side of a connection).
pub fn find(proto: Proto, local: SocketAddr) -> Option<ProcessInfo> {
    let table = match proto {
        Proto::Tcp => "net.inet.tcp.pcblist_n",
        Proto::Udp => "net.inet.udp.pcblist_n",
    };
    let pid = find_in_table(&sysctl_raw(table)?, local)?;
    process_info(pid)
}

/// Names of running apps (from `.app` bundles).
pub fn running_apps() -> Vec<String> {
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; n as usize + 64];
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), (pids.len() * 4) as i32) };
    pids.truncate(n.max(0) as usize);
    let mut apps: Vec<String> = pids
        .into_iter()
        .filter_map(pid_path)
        // Skip system daemons and frameworks; keep real applications.
        .filter(|p| p.contains("/Applications/"))
        .filter_map(|p| info_from_path(0, p).app)
        .collect();
    apps.sort();
    apps.dedup();
    apps
}

/// `.app` bundles in `dir`, descending into plain folders (Utilities, Setapp)
/// but not into bundles.
fn scan_apps(dir: &std::path::Path, depth: u8, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if let Some(app) = name.strip_suffix(".app") {
            out.push(app.to_string());
        } else if depth > 0 && e.file_type().is_ok_and(|t| t.is_dir()) {
            scan_apps(&e.path(), depth - 1, out);
        }
    }
}

pub fn all_apps() -> Vec<AppEntry> {
    let mut installed = Vec::new();
    let mut dirs = vec![
        std::path::PathBuf::from("/Applications"),
        std::path::PathBuf::from("/System/Applications"),
    ];
    if let Some(home) = std::env::var_os("HOME") {
        dirs.push(std::path::Path::new(&home).join("Applications"));
    }
    for d in &dirs {
        scan_apps(d, 2, &mut installed);
    }
    let running = running_apps();
    installed.extend(running.iter().cloned());
    installed.sort_by_key(|a| a.to_lowercase());
    installed.dedup();
    installed
        .into_iter()
        .map(|name| AppEntry { running: running.contains(&name), name })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Validates the record offsets on the running macOS version.
    #[test]
    fn finds_own_tcp_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let info = find(Proto::Tcp, client.local_addr().unwrap()).expect("own socket not found");
        assert_eq!(info.pid, std::process::id() as i32);
    }

    #[test]
    fn finds_own_udp_socket() {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.connect("127.0.0.1:9").unwrap();
        let info = find(Proto::Udp, sock.local_addr().unwrap()).expect("own socket not found");
        assert_eq!(info.pid, std::process::id() as i32);
    }

    #[test]
    fn lists_apps() {
        let apps = all_apps();
        // Every Mac has these in /System/Applications.
        assert!(apps.iter().any(|a| a.name == "Calculator"), "{apps:?}");
        let mut names: Vec<_> = apps.iter().map(|a| a.name.to_lowercase()).collect();
        names.dedup();
        assert_eq!(names.len(), apps.len(), "duplicates");
    }
}
