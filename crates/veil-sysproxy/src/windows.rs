//! Windows: system proxy via WinINet per-connection options (like v2rayN),
//! and TUN routes/DNS via PowerShell's NetTCPIP cmdlets (needs administrator).
//!
//! Nothing here touches physical adapters' DNS or the default route: the TUN
//! adapter gets on-link split routes and its own DNS, and disappears on exit.

use std::io::Read;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::winnet::{self, TunJournal};
use crate::{CleanupReport, TunRoutes};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CMD_TIMEOUT: Duration = Duration::from_secs(25);
/// How long the system resolver gets to answer after the NRPT rule is added.
const RESOLVE_CHECK_TIMEOUT: Duration = Duration::from_secs(8);

/// Name of the TUN adapter set up by [`add_tun_routes`]; DNS is applied to it only.
static TUN_NAME: Mutex<Option<String>> = Mutex::new(None);
/// This process has changed routes/DNS for a TUN and has not finished undoing it.
static TUN_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Serializes read-modify-write of the journal file.
static JOURNAL_LOCK: Mutex<()> = Mutex::new(());

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
    ps_timeout(script, env, CMD_TIMEOUT)
}

fn ps_timeout(script: &str, env: &[(&str, &str)], timeout: Duration) -> Result<String> {
    let (ok, stdout, stderr) = ps_raw(script, env, timeout)?;
    if !ok {
        let msg = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
        let msg: String = msg.chars().take(600).collect();
        bail!("PowerShell failed: {msg}");
    }
    Ok(stdout)
}

/// Runs a PowerShell script and returns (exit code 0, stdout, stderr) as they are: for
/// scripts that report their result on stdout, which must be read whatever the exit code.
fn ps_raw(script: &str, env: &[(&str, &str)], timeout: Duration) -> Result<(bool, String, String)> {
    let full = format!("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {script}");
    let mut cmd = Command::new(powershell_path());
    cmd.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", full.as_str()]);
    for (k, v) in env {
        cmd.env(k, v);
    }
    run_cmd(cmd, timeout).context("PowerShell")
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

/// Waits (up to about 20 s) until the fresh TUN adapter `alias` has its address in state
/// `Preferred`. Read-only. An error says what state it was left in.
pub fn wait_tun_address(alias: &str) -> Result<()> {
    winnet::validate_alias(alias)?;
    let out = ps_timeout(winnet::TUN_ADDRESS_STATE_SCRIPT, &[("VEIL_IF", alias)], Duration::from_secs(35))?;
    match winnet::parse_address_state(&out) {
        Some(s) if s == "Preferred" => Ok(()),
        s => bail!("address {} on adapter {alias} is {}", winnet::TUN_ADAPTER_ADDR, s.as_deref().unwrap_or("unknown")),
    }
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

/// [`default_interface`], [`default_gateway`] (`None` without one) and [`system_dns`] from
/// a single look at the default routes, for the TUN's network watcher.
pub fn default_route_snapshot() -> Result<(String, Option<IpAddr>, Vec<IpAddr>)> {
    let routes = default_routes()?;
    let best = winnet::best_default(&routes).context("no default route (offline?)")?;
    let gateway = (!best.next_hop.is_unspecified()).then_some(best.next_hop);
    let dns = winnet::parse_ip_lines(&ps(&winnet::dns_of_interface_script(best.index), &[])?);
    Ok((best.alias.clone(), gateway, dns))
}

/// DNS servers configured on the interface carrying the default route.
pub fn system_dns() -> Result<Vec<IpAddr>> {
    let routes = default_routes()?;
    let best = winnet::best_default(&routes).context("no default route (offline?)")?;
    Ok(winnet::parse_ip_lines(&ps(&winnet::dns_of_interface_script(best.index), &[])?))
}

fn journal_file() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| winnet::journal_path(Path::new(&d)))
}

fn read_journal() -> Option<TunJournal> {
    winnet::parse_journal(&std::fs::read(journal_file()?).ok()?)
}

/// Temp file and rename, so a crash never leaves a half-written journal.
fn write_journal(journal: &TunJournal) -> Result<()> {
    let path = journal_file().context("LOCALAPPDATA is not set")?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(journal)?)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Records an intended change before it is made. A journal of another process (a run that
/// died) is replaced by ours. Failing to write is logged, not fatal.
fn update_journal(change: impl FnOnce(&mut TunJournal)) {
    let _guard = JOURNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let me = process::current();
    let pid = std::process::id();
    let mut journal = read_journal()
        .filter(|j| j.pid == pid && j.started == me.started)
        .unwrap_or_else(|| TunJournal {
            pid,
            started: me.started,
            image: winnet::image_name(&me.image).to_string(),
            ..TunJournal::default()
        });
    change(&mut journal);
    if let Err(e) = write_journal(&journal) {
        tracing::warn!("cannot write the TUN journal: {e:#}");
    }
}

fn delete_journal() {
    let _guard = JOURNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(path) = journal_file() {
        let _ = std::fs::remove_file(path);
    }
}

/// Points the TUN adapter (named by an earlier [`add_tun_routes`]) at `servers`.
/// Physical adapters are left alone and the adapter vanishes on exit, so there is nothing
/// to back up. The NRPT rule is a separate step, see [`nrpt_enable`]: unlike this setting
/// it outlives the adapter, so it is added only once the resolver is known to answer.
pub fn dns_override(servers: &[IpAddr], _backup_path: &Path) -> Result<()> {
    let name = TUN_NAME.lock().unwrap().clone().context("TUN adapter is not set up yet")?;
    let idx = interface_index(&name)?;
    ps(&winnet::set_dns_script(idx.get(), servers), &[]).context("cannot set DNS on the TUN adapter")?;
    flush_dns_cache();
    Ok(())
}

/// Sends every DNS name to `servers` only. Windows otherwise also asks the physical
/// adapters' servers in parallel (SMHNR), which leaks names. The rule is stored in the
/// registry and survives the process: call this only when `servers` really answer, and
/// always pair it with [`nrpt_disable`].
pub fn nrpt_enable(servers: &[IpAddr]) -> Result<()> {
    update_journal(|j| j.nrpt = true);
    ps(&winnet::nrpt_add_script(servers), &[]).context("cannot add the NRPT rule")?;
    flush_dns_cache();
    tracing::info!("NRPT rule '{}' added: all DNS names go to {servers:?}", winnet::NRPT_TAG);
    Ok(())
}

/// Removes our NRPT rule (by tag). Idempotent; an error means a rule may still be there.
pub fn nrpt_disable() -> Result<()> {
    remove_nrpt_rules()?;
    nrpt_disabled();
    Ok(())
}

/// [`nrpt_disable`] for a TUN that is dying (its task ended, `Drop`): registry first.
pub fn nrpt_disable_fast() -> Result<()> {
    remove_nrpt_rules_fast()?;
    nrpt_disabled();
    Ok(())
}

fn nrpt_disabled() {
    flush_dns_cache();
    if read_journal().is_some_and(|j| j.pid == std::process::id()) {
        update_journal(|j| j.nrpt = false);
    }
}

/// After an NRPT rule was removed behind the DNS client's back (registry): log whether
/// the system resolver answers a real name now. Informational only: the machine may simply
/// be offline, which says nothing about the rule.
fn log_resolver_state() {
    match ps_timeout(winnet::RESOLVE_CHECK_SCRIPT, &[("VEIL_NAME", "example.com")], RESOLVE_CHECK_TIMEOUT) {
        Ok(out) => tracing::info!("system resolver after the cleanup: {}", out.trim()),
        Err(e) => tracing::info!("system resolver after the cleanup: {e:#}"),
    }
}

/// Whether the system resolver (what every app uses, NRPT included) gets its answers from
/// our TUN resolver: a name unique to this process must resolve into 198.18.0.0/15.
/// Blocks for up to [`RESOLVE_CHECK_TIMEOUT`].
pub fn system_resolver_works() -> bool {
    let name = winnet::resolve_check_name(std::process::id());
    match ps_timeout(winnet::RESOLVE_CHECK_SCRIPT, &[("VEIL_NAME", name.as_str())], RESOLVE_CHECK_TIMEOUT) {
        Ok(out) => {
            let ok = winnet::parse_resolve_check(&out);
            if !ok {
                tracing::warn!("system resolver check for {name}: {}", out.trim());
            }
            ok
        }
        Err(e) => {
            tracing::warn!("system resolver check for {name}: {e:#}");
            false
        }
    }
}

/// Deletes our NRPT rules (by tag), the normal way: the NRPT cmdlets first (they also
/// tell the DNS client), the registry for whatever they leave. Idempotent: no rule is not an
/// error; success only once [`verify_nrpt_gone`] agrees after a registry fallback.
fn remove_nrpt_rules() -> Result<()> {
    let cmdlets = ps(&winnet::nrpt_remove_script(), &[]);
    let registry_clean = nrpt_reg::tagged(winnet::NRPT_TAG).is_ok_and(|v| v.is_empty());
    // The script throws when a rule survives it, so success plus a clean registry is proof.
    if cmdlets.is_ok() && registry_clean {
        return Ok(());
    }
    if let Err(e) = &cmdlets {
        tracing::warn!("removing the NRPT rule with PowerShell: {e:#}; trying the registry");
    }
    registry_fallback()
}

/// Deletes our NRPT rules in the registry, flushes the DNS cache and checks the result.
fn registry_fallback() -> Result<()> {
    match nrpt_reg::remove_tagged(winnet::NRPT_TAG) {
        Ok(o) if !o.removed.is_empty() => tracing::info!("NRPT rules removed from the registry: {:?}", o.removed),
        Ok(o) if !o.left.is_empty() => tracing::warn!("NRPT rules left in the registry: {:?}", o.left),
        Ok(_) => {}
        Err(rc) => tracing::warn!("cannot read the NRPT rules from the registry (error {rc})"),
    }
    flush_dns_cache();
    verify_nrpt_gone().map_err(|e| anyhow::anyhow!("the NRPT rule {} is still present: {e}", winnet::NRPT_TAG))
}

/// Gone means: no rule with our tag in the registry, and none seen by Get-DnsClientNrptRule.
fn verify_nrpt_gone() -> std::result::Result<(), String> {
    let registry = nrpt_reg::tagged(winnet::NRPT_TAG).map(|v| v.len()).map_err(|rc| format!("error {rc}"));
    let cmdlets = match ps(&winnet::nrpt_count_script(), &[]) {
        Ok(out) => winnet::parse_nrpt_count(&out),
        Err(e) => winnet::NrptCount::Error(format!("{e:#}")),
    };
    winnet::nrpt_gone(registry, &cmdlets)
}

/// For exit paths with no time to spare (a dying TUN task, `Drop`): the registry first
/// (in-process, milliseconds), PowerShell only for what that leaves. "Gone" is checked
/// against the registry; the DNS cache is flushed.
fn remove_nrpt_rules_fast() -> Result<()> {
    match nrpt_reg::remove_tagged(winnet::NRPT_TAG) {
        Ok(o) if o.left.is_empty() => {
            if !o.removed.is_empty() {
                tracing::info!("NRPT rules removed from the registry: {:?}", o.removed);
            }
            if nrpt_reg::tagged(winnet::NRPT_TAG).is_ok_and(|v| v.is_empty()) {
                return Ok(());
            }
            tracing::warn!("an NRPT rule is back in the registry; trying PowerShell");
        }
        Ok(o) => tracing::warn!("NRPT rules left in the registry: {:?}; trying PowerShell", o.left),
        Err(rc) => tracing::warn!("cannot read the NRPT rules from the registry (error {rc}); trying PowerShell"),
    }
    ps(&winnet::nrpt_remove_script(), &[]).map(drop).context("cannot remove the NRPT rule")
}

/// Our NRPT rules (by tag) straight from the registry, without PowerShell: one subkey of
/// `DnsPolicyConfig`, named by a GUID, per rule, with the tag as its `Comment` value. The
/// DNS client service watches the key, so a deleted rule stops applying at once. Fast and
/// in-process: usable at the end of a session, in `Drop` and while unwinding a panic.
mod nrpt_reg {
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, KEY_WOW64_64KEY,
        RRF_RT_REG_SZ, RegCloseKey, RegDeleteKeyExW, RegDeleteTreeW, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
    };

    /// Local (not group policy) NRPT rules, the ones `Add-DnsClientNrptRule` creates.
    pub const BASE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    /// The standard `DELETE` access right.
    const DELETE: u32 = 0x0001_0000;

    #[derive(Debug, Default)]
    pub struct Outcome {
        /// Subkey names (rule GUIDs) that were deleted.
        pub removed: Vec<String>,
        /// `name: error` of the ones that are still there.
        pub left: Vec<String>,
        /// At least one deletion was refused for lack of rights.
        pub access_denied: bool,
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(HKEY);

    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }

    fn open(parent: HKEY, path: &str, access: u32) -> Result<Key, u32> {
        let path = wide(path);
        let mut h: HKEY = null_mut();
        let rc = unsafe { RegOpenKeyExW(parent, path.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut h) };
        if rc == ERROR_SUCCESS { Ok(Key(h)) } else { Err(rc) }
    }

    fn subkeys(key: &Key) -> Vec<String> {
        let mut out = Vec::new();
        for i in 0u32.. {
            let mut buf = [0u16; 256];
            let mut len = buf.len() as u32;
            let rc = unsafe {
                RegEnumKeyExW(key.0, i, buf.as_mut_ptr(), &mut len, null(), null_mut(), null_mut(), null_mut())
            };
            if rc != ERROR_SUCCESS {
                break; // ERROR_NO_MORE_ITEMS, or nothing more we can read
            }
            out.push(String::from_utf16_lossy(&buf[..len as usize]));
        }
        out
    }

    /// A `REG_SZ` value of subkey `sub`.
    fn string_value(key: &Key, sub: &str, value: &str) -> Option<String> {
        let (sub, value) = (wide(sub), wide(value));
        let mut len: u32 = 0;
        let rc = unsafe {
            RegGetValueW(key.0, sub.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, null_mut(), null_mut(), &mut len)
        };
        if rc != ERROR_SUCCESS || len == 0 {
            return None;
        }
        let mut buf = vec![0u16; (len as usize).div_ceil(2)];
        let rc = unsafe {
            RegGetValueW(key.0, sub.as_ptr(), value.as_ptr(), RRF_RT_REG_SZ, null_mut(), buf.as_mut_ptr().cast(), &mut len)
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(String::from_utf16_lossy(&buf[..n]))
    }

    fn tagged_in(base: &Key, tag: &str) -> Vec<String> {
        subkeys(base).into_iter().filter(|s| string_value(base, s, "Comment").as_deref() == Some(tag)).collect()
    }

    /// Names of the rules carrying `tag`. Readable without administrator rights.
    pub fn tagged(tag: &str) -> Result<Vec<String>, u32> {
        match open(HKEY_LOCAL_MACHINE, BASE, KEY_READ) {
            Ok(base) => Ok(tagged_in(&base, tag)),
            Err(ERROR_FILE_NOT_FOUND) => Ok(Vec::new()),
            Err(rc) => Err(rc),
        }
    }

    /// Deletes every rule carrying `tag`. `Err` only when the rules cannot even be listed.
    pub fn remove_tagged(tag: &str) -> Result<Outcome, u32> {
        let base = match open(HKEY_LOCAL_MACHINE, BASE, KEY_READ) {
            Ok(b) => b,
            Err(ERROR_FILE_NOT_FOUND) => return Ok(Outcome::default()),
            Err(rc) => return Err(rc),
        };
        let mut out = Outcome::default();
        for name in tagged_in(&base, tag) {
            match delete(&base, &name) {
                ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => out.removed.push(name),
                rc => {
                    out.access_denied |= rc == ERROR_ACCESS_DENIED;
                    out.left.push(format!("{name}: error {rc}"));
                }
            }
        }
        Ok(out)
    }

    /// The values (and any subkeys) of the rule first, through a handle with the rights
    /// `RegDeleteTreeW` needs, then the key itself.
    fn delete(base: &Key, name: &str) -> u32 {
        match open(base.0, name, DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE) {
            Ok(k) => {
                let rc = unsafe { RegDeleteTreeW(k.0, null()) };
                if rc != ERROR_SUCCESS {
                    return rc;
                }
            }
            Err(rc) => return rc,
        }
        let w = wide(name);
        unsafe { RegDeleteKeyExW(base.0, w.as_ptr(), KEY_WOW64_64KEY, 0) }
    }
}

/// Resets DNS on the TUN adapter if it still exists. Idempotent. A stale
/// backup file from other platforms' logic is simply deleted.
pub fn dns_restore(backup_path: &Path) -> Result<bool> {
    let _ = std::fs::remove_file(backup_path);
    // Also cleans a rule left by a crashed run, whether or not this process set up an adapter,
    // but never the rule of another Veil that is running a TUN right now.
    let journal = read_journal();
    let nrpt = if !winnet::is_orphaned(journal.as_ref(), std::process::id(), process::identity) {
        tracing::info!("the NRPT rule belongs to running process {}: left alone", journal.map_or(0, |j| j.pid));
        false
    } else {
        match remove_nrpt_rules() {
            Ok(()) => true,
            Err(e) => {
                tracing::error!("{e:#}");
                false
            }
        }
    };
    let name = TUN_NAME.lock().unwrap().take();
    let reset = match name {
        // The adapter is usually gone by now; the lookup is by name, so a reused index is never touched.
        Some(name) => match interface_index(&name) {
            Ok(idx) => match ps(&winnet::reset_dns_script(idx.get()), &[]) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!("{e:#}");
                    false
                }
            },
            Err(_) => false,
        },
        None => false,
    };
    flush_dns_cache();
    if nrpt {
        // Everything that outlives the adapter is undone: nothing left to remember.
        // With the rule still there the journal stays, for the next cleanup.
        delete_journal();
        TUN_ACTIVE.store(false, Ordering::SeqCst);
    }
    Ok(reset)
}

/// Undoes whatever a TUN session left in the system, whoever set it up: the NRPT rule
/// with our tag, the split routes and DNS of the adapter with the TUN address, the host
/// routes named by the journal, and the DNS cache. Found by tag and address, so it works
/// after a crash, from another process and without a journal. Idempotent. Blocking.
/// Do not call it while another Veil is using the TUN: see [`tun_cleanup_if_orphaned`].
pub fn tun_cleanup() -> CleanupReport {
    let _lock = tun_setup_lock();
    tun_cleanup_unlocked()
}

/// [`tun_cleanup`] for a caller that holds the [`tun_setup_lock`] (or could not get it).
fn tun_cleanup_unlocked() -> CleanupReport {
    let journal = read_journal();
    let hosts = winnet::journal_host_routes(journal.as_ref());
    // The NRPT cmdlets first (in the script, the NRPT rule before anything else), the
    // registry as the fallback, then a check of both.
    let mut script_ran = true;
    let mut report = match ps_raw(&winnet::tun_cleanup_script(&hosts), &[], CMD_TIMEOUT) {
        // What it did is on stdout either way; a non-zero exit means it stopped half-way.
        Ok((ok, out, err)) => {
            let mut r = winnet::parse_cleanup_output(&out);
            if !ok {
                script_ran = false;
                let err: String = err.trim().chars().take(600).collect();
                r.failed.push(format!("cleanup script did not finish: {err}"));
            }
            r
        }
        Err(e) => {
            script_ran = false;
            CleanupReport { failed: vec![format!("cleanup script: {e:#}")], ..CleanupReport::default() }
        }
    };
    let is_nrpt = |f: &String| f.starts_with("NRPT");
    let registry_clean = nrpt_reg::tagged(winnet::NRPT_TAG).is_ok_and(|v| v.is_empty());
    if !script_ran || report.failed.iter().any(is_nrpt) || !registry_clean {
        match nrpt_reg::remove_tagged(winnet::NRPT_TAG) {
            Ok(o) => {
                report.removed.extend(o.removed.iter().map(|n| format!("NRPT rule {n} (registry)")));
                report.needs_admin |= o.access_denied;
            }
            Err(rc) => tracing::warn!("cannot read the NRPT rules from the registry (error {rc})"),
        }
        flush_dns_cache();
        match verify_nrpt_gone() {
            Ok(()) => {
                report.failed.retain(|f| !is_nrpt(f));
                log_resolver_state();
            }
            Err(e) => {
                if !report.failed.iter().any(is_nrpt) {
                    report.failed.push(format!("NRPT rule {}: {e}", winnet::NRPT_TAG));
                }
            }
        }
    }
    // Rights matter only for what is still there.
    report.needs_admin &= !report.failed.is_empty();
    flush_dns_cache();
    if report.failed.is_empty() {
        if journal.is_some() {
            delete_journal();
            report.removed.push("TUN journal".into());
        }
        TUN_ACTIVE.store(false, Ordering::SeqCst);
    }
    if !report.is_empty() {
        tracing::info!("TUN cleanup: removed {:?}, left {:?}, needs admin: {}", report.removed, report.failed, report.needs_admin);
    }
    report
}

/// Name of the mutex that serializes TUN setup and cleanup across processes (the app, the
/// CLI, the guard, an elevated `--tun-cleanup` copy).
const SETUP_LOCK_NAME: &str = r"Global\Veil.TunSetup";
/// Longer than a slow TUN start; after that the caller goes on without the lock rather
/// than hang (a stuck holder must not keep the system broken).
const SETUP_LOCK_WAIT: Duration = Duration::from_secs(120);
/// On the way out (quit, a stuck teardown) nobody waits long: clean up without the lock.
const SETUP_LOCK_WAIT_EXIT: Duration = Duration::from_secs(4);

/// Held while a TUN is being set up or cleaned up; dropping it releases the lock.
pub struct TunSetupLock {
    _release: std::sync::mpsc::Sender<()>,
}

/// Takes the named mutex `Global\Veil.TunSetup`. A Win32 mutex belongs to the thread that
/// took it, and the holders here are async tasks that hop threads, so a dedicated thread
/// takes it and releases it when the returned guard is dropped. `None` (go on unlocked,
/// logged) when it cannot be had within [`SETUP_LOCK_WAIT`] or cannot be opened at all: a
/// process without administrator rights may not open the mutex of an elevated one, but
/// it cannot change the TUN state either. Blocking.
pub fn tun_setup_lock() -> Option<TunSetupLock> {
    tun_setup_lock_within(SETUP_LOCK_WAIT)
}

/// [`tun_setup_lock`] with a given wait.
fn tun_setup_lock_within(wait: Duration) -> Option<TunSetupLock> {
    use std::sync::mpsc;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_ABANDONED: u32 = 0x80;
    let (acquired_tx, acquired_rx) = mpsc::channel::<std::result::Result<(), String>>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let spawned = std::thread::Builder::new().name("tun-setup-lock".into()).spawn(move || {
        let name: Vec<u16> = SETUP_LOCK_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle.is_null() {
            let _ = acquired_tx.send(Err(std::io::Error::last_os_error().to_string()));
            return;
        }
        let waited = unsafe { WaitForSingleObject(handle, wait.as_millis() as u32) };
        // Abandoned: the holder died; the lock is ours now and its state is what cleanup is for.
        let owned = waited == WAIT_OBJECT_0 || waited == WAIT_ABANDONED;
        let _ = acquired_tx.send(if owned { Ok(()) } else { Err(format!("not released within {}s", wait.as_secs())) });
        if owned {
            // Until the guard is dropped (the sender goes away).
            let _ = release_rx.recv();
            unsafe { ReleaseMutex(handle) };
        }
        unsafe { CloseHandle(handle) };
    });
    if let Err(e) = spawned {
        tracing::warn!("TUN setup lock: {e}; going on without it");
        return None;
    }
    match acquired_rx.recv() {
        Ok(Ok(())) => Some(TunSetupLock { _release: release_tx }),
        Ok(Err(e)) => {
            tracing::warn!("TUN setup lock {SETUP_LOCK_NAME}: {e}; going on without it");
            None
        }
        Err(_) => None,
    }
}

/// Cheap check, no PowerShell: is there any sign of a TUN session in the system (a journal,
/// or an NRPT rule with our tag in the registry)? An unreadable registry counts as a sign.
pub fn tun_leftovers_suspected() -> bool {
    journal_file().is_some_and(|p| p.exists()) || nrpt_reg::tagged(winnet::NRPT_TAG).map_or(true, |v| !v.is_empty())
}

/// [`tun_cleanup`] unless the journal names another process that is still running (its
/// TUN is in use, not left over). `None` when it was skipped for that reason.
pub fn tun_cleanup_if_orphaned() -> Option<CleanupReport> {
    // Under the lock: a Veil that is setting a TUN up right now has written its journal by
    // the time we get the lock, or has not touched the system yet.
    let _lock = tun_setup_lock();
    let journal = read_journal();
    if !winnet::is_orphaned(journal.as_ref(), std::process::id(), process::identity) {
        tracing::info!("TUN cleanup skipped: process {} is using the TUN", journal.map_or(0, |j| j.pid));
        return None;
    }
    Some(tun_cleanup_unlocked())
}

/// [`tun_cleanup`] if this very process has TUN changes that are not undone yet: for
/// exit paths that cannot run the normal teardown (panic, end of session, a stuck quit).
pub fn tun_cleanup_own() -> Option<CleanupReport> {
    let ours = TUN_ACTIVE.load(Ordering::SeqCst) || read_journal().is_some_and(|j| j.pid == std::process::id());
    ours.then(tun_cleanup_on_exit)
}

/// [`tun_cleanup`] for exit paths: waits only briefly for the lock, then cleans up without it.
fn tun_cleanup_on_exit() -> CleanupReport {
    let _lock = tun_setup_lock_within(SETUP_LOCK_WAIT_EXIT);
    tun_cleanup_unlocked()
}

/// For the end of a Windows session: if this process has TUN changes in the system, take
/// out the NRPT rule straight from the registry (milliseconds, no PowerShell), and only
/// if that leaves something, fall back to the full [`tun_cleanup`]. The routes and the
/// adapter do not survive a reboot; the rule would.
pub fn tun_cleanup_session_end() {
    let ours = TUN_ACTIVE.load(Ordering::SeqCst) || read_journal().is_some_and(|j| j.pid == std::process::id());
    if !ours {
        return;
    }
    match nrpt_reg::remove_tagged(winnet::NRPT_TAG) {
        Ok(o) if o.left.is_empty() => {
            if !o.removed.is_empty() {
                tracing::info!("end of session: NRPT rules removed from the registry: {:?}", o.removed);
            }
        }
        _ => {
            let _ = tun_cleanup_on_exit();
        }
    }
}

/// Starts `veil-cli.exe tun-guard --pid <this process>` from the folder of this exe: it
/// waits for this process to end, however that happens, and then runs the cleanup. Once
/// per process; without veil-cli.exe there is simply no guard.
pub fn spawn_tun_guard() {
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(cli) = std::env::current_exe().ok().map(|e| e.with_file_name("veil-cli.exe")).filter(|p| p.is_file()) else {
        tracing::info!("veil-cli.exe not found next to the app: no TUN guard process");
        return;
    };
    let mut cmd = Command::new(&cli);
    cmd.args(["tun-guard", "--pid", &std::process::id().to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match cmd.spawn() {
        Ok(child) => tracing::info!("TUN guard started (pid {})", child.id()),
        Err(e) => tracing::warn!("cannot start the TUN guard {}: {e}", cli.display()),
    }
}

/// Starts `veil-cli.exe proxy-guard` for the system proxy this process has just set: it waits
/// for this process to end, however that happens (crash, "End task"), and gives the user's
/// original proxy settings back. Without it a killed Veil leaves the system pointing at a
/// port nobody listens on (browsers stop working, programs that ignore the proxy do not).
/// Without veil-cli.exe there is simply no guard; the next start of Veil restores as before.
pub fn spawn_proxy_guard(host: &str, port: u16, backup_path: &Path) {
    let Some(cli) = std::env::current_exe().ok().map(|e| e.with_file_name("veil-cli.exe")).filter(|p| p.is_file()) else {
        tracing::info!("veil-cli.exe not found next to the app: no system proxy guard process");
        return;
    };
    let mut cmd = Command::new(&cli);
    cmd.args(["proxy-guard", "--pid", &std::process::id().to_string(), "--addr", &format!("{host}:{port}"), "--backup"])
        .arg(backup_path)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match cmd.spawn() {
        Ok(child) => tracing::info!("system proxy guard started (pid {})", child.id()),
        Err(e) => tracing::warn!("cannot start the system proxy guard {}: {e}", cli.display()),
    }
}

/// The proxy guard process: blocks until process `pid` is gone, then restores the system
/// proxy from `backup_path`, but only if it still points at `addr` (the dead process's own
/// setting) and the backup still exists (a normal quit has restored and deleted it already).
/// Appends the outcome to `proxy-guard.log` next to the backup.
pub fn proxy_guard(pid: u32, addr: &str, backup_path: &Path) {
    use std::io::Write;
    // Not allowed to watch it: it may well be alive, so restoring could break its proxy.
    if !process::wait_exit(pid) {
        return;
    }
    let still_ours = wininet::query(&[wininet::SERVER])
        .ok()
        .is_some_and(|v| matches!(v.first(), Some(wininet::Value::Text(Some(t))) if t.as_str() == addr));
    let line = if !backup_path.exists() {
        format!("process {pid} ended: no proxy backup, nothing to restore\r\n")
    } else if !still_ours {
        format!("process {pid} ended: the system proxy is no longer {addr}, left alone\r\n")
    } else {
        match restore(backup_path) {
            Ok(true) => format!("process {pid} ended: system proxy {addr} restored\r\n"),
            Ok(false) => format!("process {pid} ended: nothing to restore\r\n"),
            Err(e) => format!("process {pid} ended: could not restore the system proxy: {e:#}\r\n"),
        }
    };
    let log = backup_path.with_file_name("proxy-guard.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// The guard process: blocks until process `pid` is gone, then cleans up what it left,
/// unless another Veil has taken the TUN over meanwhile. Appends the outcome to
/// `tun-guard.log` next to the journal.
pub fn tun_guard(pid: u32) -> Option<CleanupReport> {
    // Not allowed to watch it: it may well be alive, so cleaning up could break its TUN.
    let report = if process::wait_exit(pid) { tun_cleanup_if_orphaned() } else { None };
    if let Some(log) = journal_file().map(|p| p.with_file_name("tun-guard.log")) {
        use std::io::Write;
        let line = match &report {
            Some(r) => format!("process {pid} ended: removed {:?}, left {:?}\r\n", r.removed, r.failed),
            None => format!("process {pid}: ended with another Veil owning the TUN, or not observable (access denied); nothing done\r\n"),
        };
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
            let _ = f.write_all(line.as_bytes());
        }
    }
    report
}

mod process {
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, FILETIME, GetLastError};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        QueryFullProcessImageNameW, WaitForSingleObject,
    };

    use crate::winnet::{ProcIdentity, ProcLookup};

    const INFINITE: u32 = u32::MAX;
    const STILL_ACTIVE: u32 = 259;

    /// Blocks until the process is gone; true then (also when there is no such process).
    /// False when it may not be opened (access denied): it may be alive, nothing is known.
    pub fn wait_exit(pid: u32) -> bool {
        unsafe {
            let handle = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
            if handle.is_null() {
                return GetLastError() != ERROR_ACCESS_DENIED;
            }
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
            true
        }
    }

    /// Creation time and executable of the running process `pid`. A process that may not
    /// be opened or queried is [`ProcLookup::Denied`]: treated as alive, never cleaned under.
    pub fn identity(pid: u32) -> ProcLookup {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                return if GetLastError() == ERROR_ACCESS_DENIED { ProcLookup::Denied } else { ProcLookup::Gone };
            }
            let id = query(handle);
            CloseHandle(handle);
            id
        }
    }

    unsafe fn query(handle: windows_sys::Win32::Foundation::HANDLE) -> ProcLookup {
        let mut code = 0u32;
        if unsafe { GetExitCodeProcess(handle, &mut code) } == 0 {
            return ProcLookup::Denied;
        }
        if code != STILL_ACTIVE {
            return ProcLookup::Gone;
        }
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        if unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
            return ProcLookup::Denied;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        if unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut len) } == 0 {
            return ProcLookup::Denied;
        }
        ProcLookup::Found(ProcIdentity {
            started: (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
            image: String::from_utf16_lossy(&buf[..len as usize]),
        })
    }

    /// This process, as the journal records it.
    pub fn current() -> ProcIdentity {
        static ME: OnceLock<ProcIdentity> = OnceLock::new();
        ME.get_or_init(|| match identity(std::process::id()) {
            ProcLookup::Found(p) => p,
            _ => ProcIdentity::default(),
        })
        .clone()
    }
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
    // On disk before the system changes: a crash from here on leaves a trace to clean by.
    update_journal(|j| j.adapter = iface.to_string());
    TUN_ACTIVE.store(true, Ordering::SeqCst);
    *TUN_NAME.lock().unwrap() = Some(iface.to_string());
    let idx = wait_interface_index(iface)?;
    let out = ps(&winnet::add_routes_script(idx.get(), routes), &[])
        .with_context(|| format!("cannot add TUN routes (administrator rights needed) on {iface}"))?;
    for f in winnet::parse_route_failures(&out) {
        tracing::warn!("IPv6 route {f}; IPv6 traffic may bypass the tunnel");
    }
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
/// An IPv6 server is routed via the IPv6 default route's gateway instead (`gateway` is IPv4).
pub fn add_host_route(ip: IpAddr, gateway: IpAddr) -> bool {
    if ip.is_ipv4() && !gateway.is_ipv4() {
        return false;
    }
    update_journal(|j| {
        j.gateway = Some(gateway);
        if !j.host_routes.contains(&ip) {
            j.host_routes.push(ip);
        }
    });
    match ps(&winnet::add_host_route_script(ip, gateway), &[]) {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("host route to {ip}: {e:#}");
            false
        }
    }
}

pub fn remove_host_route(ip: IpAddr) {
    remove_host_route_via(ip, None);
}

/// Like [`remove_host_route`], but with a known gateway only a route through it is removed.
pub fn remove_host_route_via(ip: IpAddr, gateway: Option<IpAddr>) {
    if let Err(e) = ps(&winnet::remove_host_route_script(ip, gateway), &[]) {
        tracing::warn!("{e:#}");
    }
}

/// Removes leftover /32 host routes (metric 1) through `gateway` from a run that crashed.
/// Returns how many were removed. Best effort.
pub fn cleanup_orphan_host_routes(gateway: IpAddr) -> usize {
    if !gateway.is_ipv4() {
        return 0;
    }
    let gw = gateway.to_string();
    match ps(winnet::CLEAN_ORPHAN_ROUTES_SCRIPT, &[("VEIL_GW", gw.as_str())]) {
        Ok(out) => {
            let removed: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
            if !removed.is_empty() {
                tracing::info!("removed stale host routes via {gateway}: {removed:?}");
            }
            removed.len()
        }
        Err(e) => {
            tracing::warn!("cleaning stale host routes: {e:#}");
            0
        }
    }
}
