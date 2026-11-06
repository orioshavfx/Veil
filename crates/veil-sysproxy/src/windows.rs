//! Windows: system proxy via WinINet per-connection options (like v2rayN),
//! and TUN routes/DNS via PowerShell's NetTCPIP cmdlets (needs administrator).
//!
//! Nothing here touches physical adapters' DNS or the default route: the TUN
//! adapter gets on-link split routes and its own DNS, and disappears on exit.

use std::io::Read;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::TunRoutes;
use crate::winnet;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CMD_TIMEOUT: Duration = Duration::from_secs(25);

/// Name of the TUN adapter set up by [`add_tun_routes`]; DNS is applied to it only.
static TUN_NAME: Mutex<Option<String>> = Mutex::new(None);

fn powershell_path() -> std::path::PathBuf {
    std::env::var_os("SystemRoot")
        .map(|r| Path::new(&r).join(r"System32\WindowsPowerShell\v1.0\powershell.exe"))
        .filter(|p| p.exists())
        .unwrap_or_else(|| "powershell.exe".into())
}

/// Runs `cmd` without a console window; kills it after `timeout`.
/// Returns (success, stdout, stderr).
fn run_cmd(mut cmd: Command, timeout: Duration) -> Result<(bool, String, String)> {
    cmd.creation_flags(CREATE_NO_WINDOW).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().context("cannot start command")?;
    let mut out = child.stdout.take().context("no stdout")?;
    let mut err = child.stderr.take().context("no stderr")?;
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(40));
    };
    let decode = |b: Vec<u8>| String::from_utf8_lossy(&b).trim_start_matches('\u{feff}').to_string();
    let stdout = decode(t_out.join().unwrap_or_default());
    let stderr = decode(t_err.join().unwrap_or_default());
    match status {
        Some(st) => Ok((st.success(), stdout, stderr)),
        None => bail!("command timed out after {}s", timeout.as_secs()),
    }
}

/// Runs a PowerShell script (single-quoted strings only, no shell involved).
/// `env` passes values the script reads from `$env:`.
fn ps(script: &str, env: &[(&str, &str)]) -> Result<String> {
    let full = format!("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {script}");
    let mut cmd = Command::new(powershell_path());
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", full.as_str()]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let (ok, stdout, stderr) = run_cmd(cmd, CMD_TIMEOUT).context("PowerShell")?;
    if !ok {
        let msg = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
        let msg: String = msg.chars().take(600).collect();
        bail!("PowerShell failed: {msg}");
    }
    Ok(stdout)
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

fn default_routes() -> Result<Vec<winnet::DefaultRoute>> {
    let routes = winnet::parse_default_routes(&ps(winnet::DEFAULT_ROUTES_SCRIPT, &[])?);
    if routes.is_empty() {
        bail!("no default route (offline?)");
    }
    Ok(routes)
}

/// Interface alias of the best IPv4 default route, e.g. `Ethernet`.
pub fn default_interface() -> Result<String> {
    let routes = default_routes()?;
    Ok(winnet::best_default(&routes).context("no default route (offline?)")?.alias.clone())
}

/// Index of the IPv4 interface with this alias.
pub fn interface_index(name: &str) -> Result<NonZeroU32> {
    winnet::validate_alias(name)?;
    let out = ps(winnet::INTERFACE_INDEX_SCRIPT, &[("VEIL_IF", name)])?;
    winnet::parse_index(&out).with_context(|| format!("unknown interface {name}"))
}

/// Like [`interface_index`], but waits for a freshly created adapter to show up.
fn wait_interface_index(name: &str) -> Result<NonZeroU32> {
    let mut last = None;
    for _ in 0..10 {
        match interface_index(name) {
            Ok(i) => return Ok(i),
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("unknown interface {name}")))
}

/// Gateway of the best IPv4 default route.
pub fn default_gateway() -> Result<IpAddr> {
    let routes = default_routes()?;
    let best = winnet::best_default(&routes).context("no default route (offline?)")?;
    if best.next_hop.is_unspecified() {
        bail!("default route has no gateway");
    }
    Ok(best.next_hop)
}

/// DNS servers configured on the interface carrying the default route.
pub fn system_dns() -> Result<Vec<IpAddr>> {
    let routes = default_routes()?;
    let best = winnet::best_default(&routes).context("no default route (offline?)")?;
    Ok(winnet::parse_ip_lines(&ps(&winnet::dns_of_interface_script(best.index), &[])?))
}

/// Points the TUN adapter (named by an earlier [`add_tun_routes`]) at `servers`.
/// Physical adapters are left alone and the adapter vanishes on exit, so
/// there is nothing to back up.
pub fn dns_override(servers: &[IpAddr], _backup_path: &Path) -> Result<()> {
    let name = TUN_NAME.lock().unwrap().clone().context("TUN adapter is not set up yet")?;
    let idx = interface_index(&name)?;
    ps(&winnet::set_dns_script(idx.get(), servers), &[]).context("cannot set DNS on the TUN adapter")?;
    flush_dns_cache();
    Ok(())
}

/// Resets DNS on the TUN adapter if it still exists. Idempotent. A stale
/// backup file from other platforms' logic is simply deleted.
pub fn dns_restore(backup_path: &Path) -> Result<bool> {
    let _ = std::fs::remove_file(backup_path);
    let Some(name) = TUN_NAME.lock().unwrap().take() else { return Ok(false) };
    // The adapter is usually gone by now; the lookup is by name, so a reused index is never touched.
    let Ok(idx) = interface_index(&name) else { return Ok(false) };
    if let Err(e) = ps(&winnet::reset_dns_script(idx.get()), &[]) {
        tracing::warn!("{e:#}");
        return Ok(false);
    }
    flush_dns_cache();
    Ok(true)
}

pub fn flush_dns_cache() {
    let mut cmd = Command::new("ipconfig.exe");
    cmd.arg("/flushdns");
    let _ = run_cmd(cmd, Duration::from_secs(10));
}

pub fn foreign_split_routes(_own_iface: &str) -> Result<Vec<String>> {
    Ok(Vec::new())
}

/// Sends traffic into the TUN adapter `iface` with on-link split routes (`0/1`,
/// `128/1`, IPv6 `::/1`, `8000::/1`); the real default route stays untouched.
/// The adapter also gets the lowest interface metric so its DNS is preferred.
pub fn add_tun_routes(iface: &str, routes: TunRoutes) -> Result<()> {
    winnet::validate_alias(iface)?;
    *TUN_NAME.lock().unwrap() = Some(iface.to_string());
    let idx = wait_interface_index(iface)?;
    ps(&winnet::add_routes_script(idx.get(), routes), &[])
        .with_context(|| format!("cannot add TUN routes (administrator rights needed) on {iface}"))?;
    Ok(())
}

/// Best effort and idempotent: the routes also disappear with the adapter.
pub fn remove_tun_routes(iface: &str) {
    if winnet::validate_alias(iface).is_err() {
        return;
    }
    let Ok(idx) = interface_index(iface) else { return };
    if let Err(e) = ps(&winnet::remove_routes_script(idx.get()), &[]) {
        tracing::warn!("{e:#}");
    }
}

/// Not needed on Windows: sockets are pinned with `IP_UNICAST_IF`.
pub fn add_scoped_default(_phys: &str, _gateway: IpAddr) -> bool {
    false
}

pub fn remove_scoped_default(_phys: &str) {}

/// Host route to the proxy server through the original gateway and its interface.
pub fn add_host_route(ip: IpAddr, gateway: IpAddr) -> bool {
    if !ip.is_ipv4() || !gateway.is_ipv4() {
        return false;
    }
    match ps(&winnet::add_host_route_script(ip, gateway), &[]) {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("host route to {ip}: {e:#}");
            false
        }
    }
}

pub fn remove_host_route(ip: IpAddr) {
    if ip.is_ipv4() && let Err(e) = ps(&winnet::remove_host_route_script(ip), &[]) {
        tracing::warn!("{e:#}");
    }
}
