//! macOS: system proxy, DNS and routes via networksetup, scutil and route.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::TunRoutes;

pub const BYPASS: &[&str] = &[
    "127.0.0.1", "localhost", "*.local", "169.254/16", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "100.64.0.0/10", "::1", "fe80::/10",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Web,
    SecureWeb,
    Socks,
}

impl Kind {
    const ALL: [Kind; 3] = [Kind::Web, Kind::SecureWeb, Kind::Socks];

    fn name(self) -> &'static str {
        match self {
            Kind::Web => "webproxy",
            Kind::SecureWeb => "securewebproxy",
            Kind::Socks => "socksfirewallproxy",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProxyEntry {
    pub enabled: bool,
    pub server: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceBackup {
    pub service: String,
    pub web: ProxyEntry,
    pub secure_web: ProxyEntry,
    pub socks: ProxyEntry,
    pub bypass: Vec<String>,
}

impl ServiceBackup {
    fn entry(&self, kind: Kind) -> &ProxyEntry {
        match kind {
            Kind::Web => &self.web,
            Kind::SecureWeb => &self.secure_web,
            Kind::Socks => &self.socks,
        }
    }
}

/// Writes a backup so that a crash never leaves a truncated file behind: temp file in the
/// same directory, fsync, rename over the target.
fn write_backup(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    let res = (|| -> Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn networksetup(args: &[&str]) -> Result<String> {
    let out = Command::new("/usr/sbin/networksetup")
        .args(args)
        .output()
        .context("cannot run networksetup")?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    // networksetup reports some failures on stdout with exit code 0.
    if !out.status.success() || stdout.contains("requires admin privileges") || stdout.starts_with("** Error") {
        bail!(
            "networksetup {} failed: {}{}",
            args.join(" "),
            stdout.trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(stdout)
}

/// Enabled network services (Wi-Fi, Ethernet, ...).
pub fn services() -> Result<Vec<String>> {
    let out = networksetup(&["-listallnetworkservices"])?;
    Ok(parse_services(&out))
}

fn parse_services(out: &str) -> Vec<String> {
    out.lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

fn parse_entry(out: &str) -> ProxyEntry {
    let mut e = ProxyEntry::default();
    for line in out.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        match k.trim() {
            "Enabled" => e.enabled = v == "Yes",
            "Server" => e.server = v.to_string(),
            "Port" => e.port = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    e
}

fn parse_bypass(out: &str) -> Vec<String> {
    if out.contains("There aren't any bypass domains") {
        return Vec::new();
    }
    out.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
}

fn read_service(service: &str) -> Result<ServiceBackup> {
    let get = |k: Kind| networksetup(&[&format!("-get{}", k.name()), service]).map(|o| parse_entry(&o));
    Ok(ServiceBackup {
        service: service.to_string(),
        web: get(Kind::Web)?,
        secure_web: get(Kind::SecureWeb)?,
        socks: get(Kind::Socks)?,
        bypass: parse_bypass(&networksetup(&["-getproxybypassdomains", service])?),
    })
}

fn set_bypass(service: &str, list: &[String]) -> Result<()> {
    let mut args = vec!["-setproxybypassdomains", service];
    if list.is_empty() {
        args.push("Empty");
    } else {
        args.extend(list.iter().map(String::as_str));
    }
    networksetup(&args).map(drop)
}

fn apply_entry(service: &str, kind: Kind, e: &ProxyEntry) -> Result<()> {
    // Setting a server also switches the proxy on, so one call is enough then.
    if e.enabled && !e.server.is_empty() {
        return networksetup(&[&format!("-set{}", kind.name()), service, &e.server, &e.port.to_string()]).map(drop);
    }
    networksetup(&[&format!("-set{}state", kind.name()), service, "off"]).map(drop)
}

/// The service carrying the default route (e.g. "Wi-Fi"); proxy settings of
/// the other services do not matter while it is primary.
pub fn primary_service() -> Option<String> {
    let out = Command::new("/usr/sbin/scutil").arg("--nwi").output().ok()?;
    let nwi = String::from_utf8_lossy(&out.stdout);
    let iface = parse_nwi_primary(&nwi)?;
    let order = networksetup(&["-listnetworkserviceorder"]).ok()?;
    parse_service_for_device(&order, &iface)
}

/// First interface listed under "IPv4 network interface information".
fn parse_nwi_primary(nwi: &str) -> Option<String> {
    let mut in_v4 = false;
    for line in nwi.lines() {
        let line = line.trim();
        if line.starts_with("IPv4 network interface information") {
            in_v4 = true;
        } else if line.starts_with("IPv6 network interface information") {
            in_v4 = false;
        } else if in_v4 && line.contains(" : flags") {
            return line.split_whitespace().next().map(str::to_string);
        }
    }
    None
}

fn parse_service_for_device(order: &str, device: &str) -> Option<String> {
    let mut last_service = None;
    for line in order.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('(')
            && let Some((n, name)) = rest.split_once(") ")
            && n.chars().all(|c| c.is_ascii_digit() || c == '*')
        {
            last_service = Some(name.trim_start_matches('*').to_string());
        } else if line.contains(&format!("Device: {device})")) {
            return last_service.clone();
        }
    }
    None
}

fn target_services() -> Result<Vec<String>> {
    match primary_service() {
        Some(s) => Ok(vec![s]),
        None => services(),
    }
}

/// Points HTTP, HTTPS and SOCKS proxies of every enabled service at `host:port`.
///
/// If a backup already exists (a previous run did not clean up), it is kept, so
/// the user's original settings are what eventually gets restored.
pub fn enable(host: &str, port: u16, backup_path: &Path) -> Result<()> {
    let targets = target_services()?;
    if !backup_path.exists() {
        let backup: Vec<ServiceBackup> = targets.iter().map(|s| read_service(s)).collect::<Result<_>>()?;
        write_backup(backup_path, &serde_json::to_vec_pretty(&backup)?).context("cannot write proxy backup")?;
    }
    let ours = ProxyEntry { enabled: true, server: host.to_string(), port };
    let bypass: Vec<String> = BYPASS.iter().map(|s| s.to_string()).collect();
    for service in targets {
        for kind in Kind::ALL {
            apply_entry(&service, kind, &ours)?;
        }
        set_bypass(&service, &bypass)?;
        tracing::info!("system proxy set for {service}");
    }
    Ok(())
}

/// Restores settings from the backup and deletes it. No-op without a backup.
pub fn restore(backup_path: &Path) -> Result<bool> {
    let data = match std::fs::read(backup_path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let backup: Vec<ServiceBackup> = serde_json::from_slice(&data).context("corrupt proxy backup")?;
    let mut first_err = None;
    for svc in &backup {
        for kind in Kind::ALL {
            if let Err(e) = apply_entry(&svc.service, kind, svc.entry(kind)) {
                // A service may have been removed since; keep restoring the rest.
                tracing::warn!("{e:#}");
                first_err.get_or_insert(e);
            }
        }
        if let Err(e) = set_bypass(&svc.service, &svc.bypass) {
            tracing::warn!("{e:#}");
        }
    }
    std::fs::remove_file(backup_path)?;
    match first_err {
        Some(e) if backup.len() == 1 => Err(e),
        _ => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        let list = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nUSB LAN\n";
        assert_eq!(parse_services(list), vec!["Wi-Fi", "USB LAN"]);
        let e = parse_entry("Enabled: Yes\nServer: 127.0.0.1\nPort: 2080\nAuthenticated Proxy Enabled: 0\n");
        assert_eq!(e, ProxyEntry { enabled: true, server: "127.0.0.1".into(), port: 2080 });
        let e = parse_entry("Enabled: No\nServer: \nPort: 0\n");
        assert_eq!(e, ProxyEntry::default());
        assert!(parse_bypass("There aren't any bypass domains set on Wi-Fi.\n").is_empty());
        assert_eq!(parse_bypass("*.local\n169.254/16\n"), vec!["*.local", "169.254/16"]);
    }
}

// ---- DNS and routing helpers for TUN mode -----------------------------------

fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output().with_context(|| format!("cannot run {cmd}"))?;
    if !out.status.success() {
        bail!("{cmd} {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Interface of the current default route, e.g. `en0`.
pub fn default_interface() -> Result<String> {
    let out = run("/sbin/route", &["-n", "get", "default"])?;
    out.lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|i| i.trim().to_string()))
        .context("no default route (offline?)")
}

/// Name servers of the primary resolver (`scutil --dns`, resolver #1).
pub fn system_dns() -> Result<Vec<std::net::IpAddr>> {
    let out = run("/usr/sbin/scutil", &["--dns"])?;
    Ok(parse_scutil_dns(&out))
}

fn parse_scutil_dns(out: &str) -> Vec<std::net::IpAddr> {
    let mut servers = Vec::new();
    let mut in_first = false;
    for line in out.lines() {
        let line = line.trim();
        if line.starts_with("resolver #") {
            if in_first {
                break;
            }
            in_first = line == "resolver #1";
        } else if in_first
            && line.starts_with("nameserver[")
            && let Ok(ip) = line.split(':').skip(1).collect::<Vec<_>>().join(":").trim().parse()
        {
            servers.push(ip);
        }
    }
    servers
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct DnsBackup {
    service: String,
    servers: Vec<String>,
}

/// Reads a DNS backup, current or legacy:
/// * current: `[{"service": "Wi-Fi", "servers": ["1.1.1.1"]}, ...]`
/// * a single `{"service": ..., "servers": ...}` object
/// * a map `{"Wi-Fi": ["1.1.1.1"], "Ethernet": []}`
///
/// `servers` may be missing, `null`, a string or an array. Entries that could be passed to
/// `networksetup` as something other than a DNS address (or a service starting with `-`)
/// are dropped, since the file is read back by a privileged process.
fn parse_dns_backup(data: &[u8]) -> Result<Vec<DnsBackup>> {
    use serde_json::Value;

    fn servers(v: &Value) -> Vec<String> {
        let raw: Vec<&str> = match v {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        raw.into_iter()
            .map(str::trim)
            .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
            .map(str::to_string)
            .collect()
    }
    fn entry(service: &str, servers: Vec<String>) -> Option<DnsBackup> {
        (!service.is_empty() && !service.starts_with('-')).then(|| DnsBackup { service: service.to_string(), servers })
    }
    fn item(v: &Value) -> Option<DnsBackup> {
        let o = v.as_object()?;
        let service = o.get("service")?.as_str()?;
        entry(service, o.get("servers").map(servers).unwrap_or_default())
    }

    let v: Value = serde_json::from_slice(data).context("corrupt DNS backup")?;
    match &v {
        Value::Array(a) => a.iter().map(|x| item(x).context("corrupt DNS backup: bad entry")).collect(),
        Value::Object(o) if o.contains_key("service") => Ok(vec![item(&v).context("corrupt DNS backup: bad entry")?]),
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| {
                if !matches!(v, Value::Array(_) | Value::Null | Value::String(_)) {
                    bail!("corrupt DNS backup: bad entry for {k}");
                }
                entry(k, servers(v)).with_context(|| format!("corrupt DNS backup: bad service {k:?}"))
            })
            .collect(),
        _ => bail!("corrupt DNS backup: unexpected JSON"),
    }
}

/// Points every enabled service's DNS at `servers`, saving the old values.
pub fn dns_override(servers: &[std::net::IpAddr], backup_path: &Path) -> Result<()> {
    if !backup_path.exists() {
        let mut backup = Vec::new();
        for service in services()? {
            let out = networksetup(&["-getdnsservers", &service])?;
            let servers = if out.contains("aren't any DNS Servers") {
                Vec::new()
            } else {
                out.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect()
            };
            backup.push(DnsBackup { service, servers });
        }
        write_backup(backup_path, &serde_json::to_vec_pretty(&backup)?).context("cannot write DNS backup")?;
    }
    let list: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    for service in services()? {
        let mut args = vec!["-setdnsservers", service.as_str()];
        args.extend(list.iter().map(String::as_str));
        networksetup(&args)?;
    }
    flush_dns_cache();
    Ok(())
}

pub fn dns_restore(backup_path: &Path) -> Result<bool> {
    let data = match std::fs::read(backup_path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let backup = match parse_dns_backup(&data) {
        Ok(b) => b,
        Err(e) => {
            // A broken file must not block every later TUN start: keep it for inspection.
            tracing::error!("{e:#}; moving {} aside", backup_path.display());
            let mut aside = backup_path.as_os_str().to_owned();
            aside.push(".corrupt");
            if std::fs::rename(backup_path, &aside).is_err() {
                let _ = std::fs::remove_file(backup_path);
            }
            return Ok(false);
        }
    };
    for b in &backup {
        let mut args = vec!["-setdnsservers", b.service.as_str()];
        if b.servers.is_empty() {
            args.push("Empty");
        } else {
            args.extend(b.servers.iter().map(String::as_str));
        }
        if let Err(e) = networksetup(&args) {
            tracing::warn!("{e:#}");
        }
    }
    match std::fs::remove_file(backup_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    flush_dns_cache();
    Ok(true)
}

pub fn flush_dns_cache() {
    let _ = Command::new("/usr/bin/dscacheutil").arg("-flushcache").status();
    let _ = Command::new("/usr/bin/killall").args(["-HUP", "mDNSResponder"]).status();
}

/// Interfaces of split routes (`0/1`, `128.0/1`) installed by another VPN.
pub fn foreign_split_routes(own_iface: &str) -> Result<Vec<String>> {
    let out = run("/usr/sbin/netstat", &["-rn", "-f", "inet"])?;
    Ok(parse_split_routes(&out, own_iface))
}

fn parse_split_routes(netstat: &str, own_iface: &str) -> Vec<String> {
    let mut ifaces: Vec<String> = netstat
        .lines()
        .filter(|l| l.starts_with("0/1 ") || l.starts_with("128.0/1 "))
        .filter_map(|l| l.split_whitespace().last().map(str::to_string))
        .filter(|i| i != own_iface)
        .collect();
    ifaces.dedup();
    ifaces
}

/// Gateway of the current default route.
pub fn default_gateway() -> Result<std::net::IpAddr> {
    let out = run("/sbin/route", &["-n", "get", "default"])?;
    out.lines()
        .find_map(|l| l.trim().strip_prefix("gateway:").and_then(|g| g.trim().parse().ok()))
        .context("default route has no gateway")
}

/// Adds routes sending traffic into `iface`; split routes keep the default route intact.
pub fn add_tun_routes(iface: &str, routes: TunRoutes) -> Result<()> {
    let ours = routes.v4();
    let foreign: Vec<String> = foreign_split_routes(iface)?;
    let netstat = run("/usr/sbin/netstat", &["-rn", "-f", "inet"])?;
    let clash = ours.iter().any(|net| {
        let short = if *net == "0.0.0.0/1" { "0/1 " } else { "128.0/1 " };
        netstat.lines().any(|l| l.starts_with(short) && !l.ends_with(iface))
    });
    if clash {
        bail!("another VPN is active ({}): turn it off before enabling TUN mode", foreign.join(", "));
    }
    for net in ours {
        run("/sbin/route", &["-n", "add", "-net", net, "-interface", iface])?;
    }
    if routes == TunRoutes::All {
        for net in ["::/1", "8000::/1"] {
            // IPv6 is best effort: some networks have none.
            if let Err(e) = run("/sbin/route", &["-n", "add", "-inet6", "-net", net, "-interface", iface]) {
                tracing::warn!("{e:#}");
            }
        }
    }
    Ok(())
}

/// Best effort: the routes also disappear when the interface is destroyed.
pub fn remove_tun_routes(iface: &str) {
    for net in ["0.0.0.0/1", "128.0.0.0/1"] {
        let _ = run("/sbin/route", &["-n", "delete", "-net", net, "-interface", iface]);
    }
    for net in ["::/1", "8000::/1"] {
        let _ = run("/sbin/route", &["-n", "delete", "-inet6", "-net", net, "-interface", iface]);
    }
}

/// A default route scoped to the physical interface, so sockets pinned to it
/// (`IP_BOUND_IF`) still find a way out once split routes point into the TUN.
/// Returns whether we added it (and must remove it later).
pub fn add_scoped_default(phys: &str, gateway: std::net::IpAddr) -> bool {
    run("/sbin/route", &["-n", "add", "-ifscope", phys, "-net", "0.0.0.0/0", &gateway.to_string()]).is_ok()
}

pub fn remove_scoped_default(phys: &str) {
    let _ = run("/sbin/route", &["-n", "delete", "-ifscope", phys, "-net", "0.0.0.0/0"]);
}

/// Host route to the proxy server through the original gateway.
pub fn add_host_route(ip: std::net::IpAddr, gateway: std::net::IpAddr) -> bool {
    ip.is_ipv4() && run("/sbin/route", &["-n", "add", "-host", &ip.to_string(), &gateway.to_string()]).is_ok()
}

pub fn remove_host_route(ip: std::net::IpAddr) {
    let _ = run("/sbin/route", &["-n", "delete", "-host", &ip.to_string()]);
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    #[test]
    fn scutil() {
        let out = "DNS configuration\n\nresolver #1\n  nameserver[0] : 192.168.1.1\n  nameserver[1] : fe80::1%en0\n  flags    : Request A records\n\nresolver #2\n  domain   : local\n  nameserver[0] : 8.8.8.8\n";
        let got = parse_scutil_dns(out);
        assert_eq!(got, vec!["192.168.1.1".parse::<std::net::IpAddr>().unwrap()]);
    }

    #[test]
    fn primary_service_lookup() {
        let nwi = "Network information\n\nIPv4 network interface information\n     en0 : flags      : 0x5 (IPv4,DNS)\n           address    : 172.20.10.3\n   REACH : flags 0x00000002 (Reachable)\n\nIPv6 network interface information\n   No IPv6 states found\n";
        assert_eq!(parse_nwi_primary(nwi).as_deref(), Some("en0"));
        let order = "An asterisk (*) denotes that a network service is disabled.\n(1) SZNX LAN 100M\n(Hardware Port: USB 10/100 LAN, Device: en7)\n\n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(*) Old\n(Hardware Port: Foo, Device: en9)\n";
        assert_eq!(parse_service_for_device(order, "en0").as_deref(), Some("Wi-Fi"));
        assert_eq!(parse_service_for_device(order, "en9").as_deref(), Some("Old"));
        assert_eq!(parse_service_for_device(order, "en5"), None);
    }

    #[test]
    fn split_routes() {
        let out = "Destination        Gateway            Flags               Netif Expire\ndefault            172.20.10.1        UGScg                 en0\n128.0/1            169.254.10.1       UGSc              utun225\n";
        assert_eq!(parse_split_routes(out, "utun9"), vec!["utun225"]);
        assert!(parse_split_routes(out, "utun225").is_empty());
    }

    fn dns(service: &str, servers: &[&str]) -> DnsBackup {
        DnsBackup { service: service.into(), servers: servers.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn dns_backup_current_format() {
        let json = serde_json::to_vec_pretty(&vec![dns("Wi-Fi", &["1.1.1.1", "fe80::1"]), dns("USB LAN", &[])]).unwrap();
        let got = parse_dns_backup(&json).unwrap();
        assert_eq!(got, vec![dns("Wi-Fi", &["1.1.1.1", "fe80::1"]), dns("USB LAN", &[])]);
        assert!(parse_dns_backup(b"[]").unwrap().is_empty());
    }

    #[test]
    fn dns_backup_legacy_formats() {
        // single object, map of service -> servers, null / string / missing servers
        assert_eq!(
            parse_dns_backup(br#"{"service":"Wi-Fi","servers":["8.8.8.8"]}"#).unwrap(),
            vec![dns("Wi-Fi", &["8.8.8.8"])]
        );
        let mut m = parse_dns_backup(br#"{"Wi-Fi":["8.8.8.8","8.8.4.4"],"Ethernet":null,"Dock":"9.9.9.9"}"#).unwrap();
        m.sort_by(|a, b| a.service.cmp(&b.service));
        assert_eq!(m, vec![dns("Dock", &["9.9.9.9"]), dns("Ethernet", &[]), dns("Wi-Fi", &["8.8.8.8", "8.8.4.4"])]);
        assert_eq!(
            parse_dns_backup(br#"[{"service":"A","servers":null},{"service":"B"}]"#).unwrap(),
            vec![dns("A", &[]), dns("B", &[])]
        );
    }

    #[test]
    fn dns_backup_rejects_garbage_and_hostile_entries() {
        assert!(parse_dns_backup(b"").is_err());
        assert!(parse_dns_backup(b"{\"service\":\"Wi-Fi\",\"serv").is_err()); // truncated write
        assert!(parse_dns_backup(b"42").is_err());
        assert!(parse_dns_backup(br#"[{"servers":["1.1.1.1"]}]"#).is_err());
        assert!(parse_dns_backup(br#"[{"service":"-setdnsservers","servers":[]}]"#).is_err());
        assert!(parse_dns_backup(br#"{"Wi-Fi":{"x":1}}"#).is_err());
        // non-address strings never reach networksetup
        assert_eq!(
            parse_dns_backup(br#"[{"service":"Wi-Fi","servers":["1.1.1.1","-x","evil.example"]}]"#).unwrap(),
            vec![dns("Wi-Fi", &["1.1.1.1"])]
        );
    }

    #[test]
    fn dns_restore_without_backup_is_noop_and_corrupt_backup_is_moved_aside() {
        let dir = std::env::temp_dir().join(format!("veil-dnsbk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("dns-backup.json");
        assert!(!dns_restore(&p).unwrap());
        std::fs::write(&p, b"{not json").unwrap();
        assert!(!dns_restore(&p).unwrap());
        assert!(!p.exists());
        assert!(dir.join("dns-backup.json.corrupt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_backup_is_atomic_and_overwrites() {
        let dir = std::env::temp_dir().join(format!("veil-wb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("b.json");
        write_backup(&p, b"one").unwrap();
        write_backup(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1); // no .tmp left
        let _ = std::fs::remove_dir_all(&dir);
    }
}
