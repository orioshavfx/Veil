//! Windows: system proxy via WinINet per-connection options (like v2rayN).
//! TUN routes and DNS come in stage W2; until then those calls fail, and
//! restores succeed as no-ops when there is nothing to undo, because the app
//! calls them on every start.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::TunRoutes;

fn unsupported<T>(what: &str) -> Result<T> {
    bail!("{what} is not supported on Windows yet")
}

/// Hosts that never go through the proxy. WinINet takes `*` masks, not CIDR.
pub const BYPASS: &[&str] = &[
    "localhost", "127.*", "10.*", "192.168.*", "169.254.*", "100.64.*",
    "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.20.*", "172.21.*", "172.22.*", "172.23.*",
    "172.24.*", "172.25.*", "172.26.*", "172.27.*", "172.28.*", "172.29.*", "172.30.*", "172.31.*",
    "[::1]", "<local>",
];

/// WinINet settings of the default (LAN) connection, as saved before we change them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProxyBackup {
    pub flags: u32,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub autoconfig_url: Option<String>,
}

mod wininet {
    use std::ptr::{null, null_mut};

    use anyhow::{Result, bail};
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinInet::*;

    pub const FLAGS: u32 = INTERNET_PER_CONN_FLAGS;
    pub const SERVER: u32 = INTERNET_PER_CONN_PROXY_SERVER;
    pub const BYPASS: u32 = INTERNET_PER_CONN_PROXY_BYPASS;
    pub const AUTOCONFIG: u32 = INTERNET_PER_CONN_AUTOCONFIG_URL;
    pub use windows_sys::Win32::Networking::WinInet::{PROXY_TYPE_DIRECT, PROXY_TYPE_PROXY};

    pub enum Value {
        Flags(u32),
        Text(Option<String>),
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Reads the given options of the default connection.
    pub fn query(options: &[u32]) -> Result<Vec<Value>> {
        let mut opts: Vec<INTERNET_PER_CONN_OPTIONW> = options
            .iter()
            .map(|o| INTERNET_PER_CONN_OPTIONW { dwOption: *o, Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: 0 } })
            .collect();
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: null_mut(),
            dwOptionCount: opts.len() as u32,
            dwOptionError: 0,
            pOptions: opts.as_mut_ptr(),
        };
        let mut len = size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32;
        let ok = unsafe {
            InternetQueryOptionW(null(), INTERNET_OPTION_PER_CONNECTION_OPTION, (&raw mut list).cast(), &mut len)
        };
        if ok == 0 {
            bail!("InternetQueryOptionW failed: {}", std::io::Error::last_os_error());
        }
        Ok(opts
            .iter()
            .map(|o| unsafe {
                if o.dwOption == FLAGS {
                    return Value::Flags(o.Value.dwValue);
                }
                let p = o.Value.pszValue;
                if p.is_null() {
                    return Value::Text(None);
                }
                let len = (0..).take_while(|&i| *p.add(i) != 0).count();
                let text = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
                GlobalFree(p.cast());
                Value::Text(Some(text))
            })
            .collect())
    }

    /// Sets options of the default connection and tells running apps about it.
    pub fn set(values: &[(u32, Value)]) -> Result<()> {
        // Keep the UTF-16 buffers alive until the call returns. "No value" is passed as an
        // empty string, not NULL: WinINet may dereference string options unconditionally.
        let texts: Vec<Option<Vec<u16>>> = values
            .iter()
            .map(|(_, v)| match v {
                Value::Text(t) => Some(wide(t.as_deref().unwrap_or(""))),
                Value::Flags(_) => None,
            })
            .collect();
        let mut opts: Vec<INTERNET_PER_CONN_OPTIONW> = values
            .iter()
            .zip(&texts)
            .map(|((o, v), t)| INTERNET_PER_CONN_OPTIONW {
                dwOption: *o,
                Value: match (v, t) {
                    (Value::Flags(f), _) => INTERNET_PER_CONN_OPTIONW_0 { dwValue: *f },
                    (_, Some(w)) => INTERNET_PER_CONN_OPTIONW_0 { pszValue: w.as_ptr().cast_mut() },
                    (_, None) => INTERNET_PER_CONN_OPTIONW_0 { pszValue: null_mut() },
                },
            })
            .collect();
        let list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: null_mut(),
            dwOptionCount: opts.len() as u32,
            dwOptionError: 0,
            pOptions: opts.as_mut_ptr(),
        };
        let ok = unsafe {
            InternetSetOptionW(
                null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                (&raw const list).cast(),
                size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            )
        };
        if ok == 0 {
            bail!("InternetSetOptionW failed: {}", std::io::Error::last_os_error());
        }
        unsafe {
            InternetSetOptionW(null(), INTERNET_OPTION_SETTINGS_CHANGED, null(), 0);
            InternetSetOptionW(null(), INTERNET_OPTION_REFRESH, null(), 0);
        }
        Ok(())
    }
}

fn read_backup() -> Result<ProxyBackup> {
    use wininet::Value;
    let v = wininet::query(&[wininet::FLAGS, wininet::SERVER, wininet::BYPASS, wininet::AUTOCONFIG])?;
    let text = |i: usize| match &v[i] {
        Value::Text(t) => t.clone(),
        Value::Flags(_) => None,
    };
    let flags = match v[0] {
        Value::Flags(f) => f,
        Value::Text(_) => 0,
    };
    Ok(ProxyBackup { flags, server: text(1), bypass: text(2), autoconfig_url: text(3) })
}

/// Points the default connection's proxy at `host:port` (HTTP CONNECT on the
/// mixed port carries HTTPS too), turning off auto-config and auto-detect.
///
/// An existing backup (a previous run did not clean up) is kept, so the
/// user's original settings are what eventually gets restored.
pub fn enable(host: &str, port: u16, backup_path: &Path) -> Result<()> {
    use wininet::Value;
    // Keep a valid backup from an earlier run; a damaged one (crash mid-write) is replaced.
    let have_backup = std::fs::read(backup_path)
        .ok()
        .and_then(|d| serde_json::from_slice::<ProxyBackup>(&d).ok())
        .is_some();
    if !have_backup {
        let backup = read_backup()?;
        // Write to a temp file and rename, so a crash never leaves a half-written backup.
        let tmp = backup_path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&backup)?).context("cannot write proxy backup")?;
        std::fs::rename(&tmp, backup_path).context("cannot write proxy backup")?;
    }
    wininet::set(&[
        (wininet::FLAGS, Value::Flags(wininet::PROXY_TYPE_DIRECT | wininet::PROXY_TYPE_PROXY)),
        (wininet::SERVER, Value::Text(Some(format!("{host}:{port}")))),
        (wininet::BYPASS, Value::Text(Some(BYPASS.join(";")))),
    ])?;
    tracing::info!("system proxy set to {host}:{port}");
    Ok(())
}

/// Restores settings from the backup and deletes it. No-op without a backup.
pub fn restore(backup_path: &Path) -> Result<bool> {
    use wininet::Value;
    let data = match std::fs::read(backup_path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let b: ProxyBackup = match serde_json::from_slice(&data) {
        Ok(b) => b,
        Err(e) => {
            // Unreadable backup (crash mid-write, edited by hand): the proxy may still point at
            // our dead port, so go DIRECT rather than leave it and fail silently.
            tracing::warn!("corrupt proxy backup ({e}); resetting the system proxy to direct");
            ProxyBackup { flags: wininet::PROXY_TYPE_DIRECT, ..ProxyBackup::default() }
        }
    };
    wininet::set(&[
        (wininet::FLAGS, Value::Flags(b.flags)),
        (wininet::SERVER, Value::Text(b.server)),
        (wininet::BYPASS, Value::Text(b.bypass)),
        (wininet::AUTOCONFIG, Value::Text(b.autoconfig_url)),
    ])?;
    std::fs::remove_file(backup_path)?;
    Ok(true)
}

pub fn services() -> Result<Vec<String>> {
    unsupported("network services")
}

pub fn primary_service() -> Option<String> {
    None
}

pub fn default_interface() -> Result<String> {
    unsupported("finding the default interface")
}

pub fn default_gateway() -> Result<IpAddr> {
    unsupported("finding the default gateway")
}

pub fn system_dns() -> Result<Vec<IpAddr>> {
    unsupported("reading DNS servers")
}

pub fn dns_override(_servers: &[IpAddr], _backup_path: &Path) -> Result<()> {
    unsupported("changing DNS servers")
}

pub fn dns_restore(backup_path: &Path) -> Result<bool> {
    if backup_path.exists() {
        return unsupported("restoring DNS servers");
    }
    Ok(false)
}

pub fn flush_dns_cache() {}

pub fn foreign_split_routes(_own_iface: &str) -> Result<Vec<String>> {
    Ok(Vec::new())
}

pub fn add_tun_routes(_iface: &str, _routes: TunRoutes) -> Result<()> {
    unsupported("TUN routes")
}

pub fn remove_tun_routes(_iface: &str) {}

/// Not needed on Windows: the physical default route stays in place.
pub fn add_scoped_default(_phys: &str, _gateway: IpAddr) -> bool {
    false
}

pub fn remove_scoped_default(_phys: &str) {}

pub fn add_host_route(_ip: IpAddr, _gateway: IpAddr) -> bool {
    false
}

pub fn remove_host_route(_ip: IpAddr) {}
