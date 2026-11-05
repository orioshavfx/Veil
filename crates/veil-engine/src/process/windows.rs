//! Windows: owning pid from the IP Helper socket tables, app names from the
//! executable's version resource (`FileDescription`, e.g. "Google Chrome").

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::ptr::null_mut;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows_sys::Win32::System::ProcessStatus::K32EnumProcesses;
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};

use super::socket_table::{self, Layout};
use super::{AppEntry, ProcessInfo, Proto};

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// Socket tables are dumped at most this often; browsers open many connections at once.
const TABLE_TTL: Duration = Duration::from_millis(500);

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn dump(proto: Proto, v6: bool) -> Option<Vec<u8>> {
    let af = u32::from(if v6 { AF_INET6 } else { AF_INET });
    let mut size = 0u32;
    let call = |buf: *mut u8, size: &mut u32| unsafe {
        match proto {
            Proto::Tcp => GetExtendedTcpTable(buf.cast(), size, 0, af, TCP_TABLE_OWNER_PID_ALL, 0),
            Proto::Udp => GetExtendedUdpTable(buf.cast(), size, 0, af, UDP_TABLE_OWNER_PID, 0),
        }
    };
    // The table can grow between the calls; retry a few times.
    for _ in 0..4 {
        let mut buf = vec![0u8; size as usize];
        match call(if buf.is_empty() { null_mut() } else { buf.as_mut_ptr() }, &mut size) {
            0 => {
                buf.truncate(size as usize);
                return Some(buf);
            }
            ERROR_INSUFFICIENT_BUFFER => size += 4096,
            _ => return None,
        }
    }
    None
}

type Tables = HashMap<(bool, bool), (Instant, Vec<u8>)>;
static TABLES: Mutex<Option<Tables>> = Mutex::new(None);

fn table(proto: Proto, v6: bool, max_age: Duration) -> Option<Vec<u8>> {
    let key = (proto == Proto::Tcp, v6);
    let mut guard = TABLES.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_default();
    if let Some((at, t)) = cache.get(&key)
        && at.elapsed() < max_age
    {
        return Some(t.clone());
    }
    let t = dump(proto, v6)?;
    cache.insert(key, (Instant::now(), t.clone()));
    Some(t)
}

fn pid_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// `FileDescription` (falling back to `ProductName`) from the version resource.
fn description(path: &str) -> Option<String> {
    let wpath = wide(path);
    unsafe {
        let size = GetFileVersionInfoSizeW(wpath.as_ptr(), null_mut());
        if size == 0 {
            return None;
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(wpath.as_ptr(), 0, size, data.as_mut_ptr().cast()) == 0 {
            return None;
        }
        let query = |sub: &str| -> Option<(*mut core::ffi::c_void, u32)> {
            let mut ptr = null_mut();
            let mut len = 0u32;
            (VerQueryValueW(data.as_ptr().cast(), wide(sub).as_ptr(), &mut ptr, &mut len) != 0 && !ptr.is_null())
                .then_some((ptr, len))
        };
        // First language/codepage pair, e.g. 0409 04B0.
        let (tr, tr_len) = query("\\VarFileInfo\\Translation")?;
        if tr_len < 4 {
            return None;
        }
        let pair = std::slice::from_raw_parts(tr.cast::<u16>(), 2);
        for key in ["FileDescription", "ProductName"] {
            let sub = format!("\\StringFileInfo\\{:04X}{:04X}\\{key}", pair[0], pair[1]);
            if let Some((p, len)) = query(&sub) {
                let chars = std::slice::from_raw_parts(p.cast::<u16>(), len as usize);
                let text = String::from_utf16_lossy(chars).trim_end_matches('\0').trim().to_string();
                if !text.is_empty() && !text.contains("Operating System") {
                    return Some(text);
                }
            }
        }
        None
    }
}

fn info(pid: u32, path: String) -> ProcessInfo {
    let exe = path.rsplit('\\').next().unwrap_or("").to_string();
    ProcessInfo { pid: pid as i32, exe, app: description(&path), path }
}

static INFOS: Mutex<Option<HashMap<u32, ProcessInfo>>> = Mutex::new(None);

pub fn process_info(pid: i32) -> Option<ProcessInfo> {
    let pid = u32::try_from(pid).ok()?;
    if let Some(i) = INFOS.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_default().get(&pid) {
        return Some(i.clone());
    }
    let i = info(pid, pid_path(pid)?);
    let mut cache = INFOS.lock().unwrap_or_else(|e| e.into_inner());
    let map = cache.get_or_insert_default();
    if map.len() > 4096 {
        map.clear(); // pids get reused; keep it simple
    }
    map.insert(pid, i.clone());
    Some(i)
}

/// The process that owns the local socket `local` (the client side of a connection).
pub fn find(proto: Proto, local: SocketAddr) -> Option<ProcessInfo> {
    let layouts: [(bool, Layout); 2] = match proto {
        Proto::Tcp => [(false, socket_table::TCP4), (true, socket_table::TCP6)],
        Proto::Udp => [(false, socket_table::UDP4), (true, socket_table::UDP6)],
    };
    // An IPv4 client may sit on a dual-stack IPv6 socket, so try both tables.
    let order = if local.is_ipv4() { [0, 1] } else { [1, 0] };
    let lookup = |max_age: Duration| {
        order.into_iter().find_map(|i| {
            let (v6, layout) = layouts[i];
            socket_table::find_pid(&table(proto, v6, max_age)?, layout, local)
        })
    };
    // A connection opened after the last dump is missing from the cache: on a miss, re-dump once.
    let pid = lookup(TABLE_TTL).or_else(|| lookup(Duration::from_millis(30)))?;
    process_info(pid as i32)
}

fn all_pids() -> Vec<u32> {
    let mut pids = vec![0u32; 4096];
    let mut used = 0u32;
    let ok = unsafe { K32EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut used) };
    if ok == 0 {
        return Vec::new();
    }
    pids.truncate(used as usize / 4);
    pids
}

/// Apps of running processes, skipping Windows' own.
pub fn running_apps() -> Vec<String> {
    let mut apps: Vec<String> = all_pids()
        .into_iter()
        .filter_map(pid_path)
        .filter(|p| !p.to_lowercase().starts_with(r"c:\windows\"))
        .filter_map(|p| description(&p).or_else(|| Path::new(&p).file_stem().map(|s| s.to_string_lossy().into_owned())))
        .collect();
    apps.sort();
    apps.dedup();
    apps
}

/// Start menu shortcut names: what users recognise as installed apps.
fn start_menu(dir: &Path, depth: u8, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let path = e.path();
        if depth > 0 && e.file_type().is_ok_and(|t| t.is_dir()) {
            start_menu(&path, depth - 1, out);
        } else if path.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
            let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let lower = name.to_lowercase();
            if !lower.contains("uninstall") && !lower.contains("readme") && !lower.contains("help") {
                out.push(name);
            }
        }
    }
}

/// Installed (Start menu) and running apps, for picking in the UI.
pub fn all_apps() -> Vec<AppEntry> {
    let mut installed = Vec::new();
    for var in ["ProgramData", "APPDATA"] {
        if let Some(base) = std::env::var_os(var) {
            start_menu(&Path::new(&base).join(r"Microsoft\Windows\Start Menu\Programs"), 2, &mut installed);
        }
    }
    let running = running_apps();
    installed.extend(running.iter().cloned());
    installed.sort_by_key(|a| a.to_lowercase());
    installed.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    installed
        .into_iter()
        .map(|name| AppEntry { running: running.iter().any(|r| r.eq_ignore_ascii_case(&name)), name })
        .collect()
}
