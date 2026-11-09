//! Pure helpers for the Windows TUN setup: PowerShell script builders and
//! parsers of their output. Kept free of OS calls so the tests run anywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::{CleanupReport, TUN_ADAPTER_NAME, TunRoutes};

/// One IPv4 default route as printed by [`DEFAULT_ROUTES_SCRIPT`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRoute {
    pub index: u32,
    pub alias: String,
    pub next_hop: IpAddr,
    /// Route metric plus interface metric: what Windows actually compares.
    pub metric: u32,
}

/// Prints `index|alias|nexthop|effective metric`, one line per default route.
pub const DEFAULT_ROUTES_SCRIPT: &str = "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | \
     ForEach-Object { $m = [int64]$_.RouteMetric; \
     $i = Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue; \
     if ($i) { $m += [int64]$i.InterfaceMetric }; \
     ($_.InterfaceIndex, $_.InterfaceAlias, $_.NextHop, $m) -join '|' }";

/// Prints the index of the IPv4 interface whose alias is in `$env:VEIL_IF`.
/// The name travels in the environment, so it is never parsed as script text.
pub const INTERFACE_INDEX_SCRIPT: &str = "$n = $env:VEIL_IF; Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
     Where-Object { $_.InterfaceAlias -eq $n } | Select-Object -First 1 -ExpandProperty InterfaceIndex";

pub fn parse_default_routes(out: &str) -> Vec<DefaultRoute> {
    out.lines()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches('\u{feff}');
            let (index, rest) = line.split_once('|')?;
            let mut it = rest.rsplitn(3, '|');
            let metric = it.next()?.trim().parse::<u64>().ok()?;
            let next_hop = it.next()?.trim().parse().ok()?;
            let alias = it.next()?.to_string();
            Some(DefaultRoute {
                index: index.trim().parse().ok()?,
                alias,
                next_hop,
                metric: metric.min(u32::MAX as u64) as u32,
            })
        })
        .collect()
}

/// The route Windows would use: routes with a real gateway first, then lowest metric.
pub fn best_default(routes: &[DefaultRoute]) -> Option<&DefaultRoute> {
    routes.iter().min_by_key(|r| (r.next_hop.is_unspecified(), r.metric))
}

pub fn parse_ip_lines(out: &str) -> Vec<IpAddr> {
    out.lines()
        .filter_map(|l| l.trim().trim_start_matches('\u{feff}').split('%').next()?.parse().ok())
        .collect()
}

pub fn parse_index(out: &str) -> Option<NonZeroU32> {
    out.lines().find_map(|l| l.trim().trim_start_matches('\u{feff}').parse::<u32>().ok().and_then(NonZeroU32::new))
}

/// Rejects names that are empty, absurdly long or carry control/quoting characters.
pub fn validate_alias(name: &str) -> Result<()> {
    if name.is_empty() || name.chars().count() > 256 {
        bail!("invalid interface name length");
    }
    if let Some(c) = name.chars().find(|c| !(c.is_alphanumeric() || " -_.()#:*&+,/".contains(*c))) {
        bail!("interface name {name:?} contains unsupported character {c:?}");
    }
    Ok(())
}

/// Destinations to send into the TUN adapter: (IPv4, IPv6 best effort).
pub fn tun_prefixes(routes: TunRoutes) -> (&'static [&'static str], &'static [&'static str]) {
    match routes {
        TunRoutes::All => (&["0.0.0.0/1", "128.0.0.0/1"], &["::/1", "8000::/1"]),
        TunRoutes::LowerHalf => (&["0.0.0.0/1"], &[]),
        // 198.18.0.0/15 is the adapter's own on-link subnet: no extra route needed.
        TunRoutes::Domains => (&[], &[]),
    }
}

fn quoted(items: &[&str]) -> String {
    items.iter().map(|p| format!("'{p}'")).collect::<Vec<_>>().join(",")
}

/// Low interface metric (so Windows prefers this adapter's DNS) and on-link split routes.
pub fn add_routes_script(if_index: u32, routes: TunRoutes) -> String {
    let (v4, v6) = tun_prefixes(routes);
    let mut s = String::from("$ErrorActionPreference = 'Stop'; ");
    s += &format!("try {{ Set-NetIPInterface -InterfaceIndex {if_index} -InterfaceMetric 1 }} catch {{ }}; ");
    if !v4.is_empty() {
        s += &format!(
            "foreach ($p in {}) {{ New-NetRoute -DestinationPrefix $p -InterfaceIndex {if_index} -NextHop 0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore | Out-Null }}; ",
            quoted(v4)
        );
    }
    if !v6.is_empty() {
        // IPv6 is best effort: the adapter may have no v6 or the stack may be disabled.
        // Failures are reported on stdout (see [`parse_route_failures`]), not swallowed.
        s += &format!(
            "foreach ($p in {}) {{ try {{ New-NetRoute -DestinationPrefix $p -InterfaceIndex {if_index} -NextHop '::' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null }} \
             catch {{ Write-Output ('{ROUTE_FAIL_MARK}' + $p + ': ' + ($_.Exception.Message -replace '\\s+', ' ')) }} }}; ",
            quoted(v6)
        );
    }
    s
}

/// Every split route [`add_routes_script`] may add.
const SPLIT_PREFIXES: [&str; 4] = ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"];

/// Ends the best-effort scripts: `powershell -Command` exits with `$?` of the last
/// command, so a harmless "not found" there would read as a failure of the whole script.
/// With this the exit code says only whether the script ran to the end.
pub const EXIT_OK: &str = "; exit 0";

pub fn remove_routes_script(if_index: u32) -> String {
    let all = quoted(&SPLIT_PREFIXES);
    format!(
        "foreach ($p in {all}) {{ Remove-NetRoute -DestinationPrefix $p -InterfaceIndex {if_index} -Confirm:$false -ErrorAction SilentlyContinue }}{EXIT_OK}"
    )
}

pub fn set_dns_script(if_index: u32, servers: &[IpAddr]) -> String {
    let list: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    let list: Vec<&str> = list.iter().map(String::as_str).collect();
    format!(
        "$ErrorActionPreference = 'Stop'; Set-DnsClientServerAddress -InterfaceIndex {if_index} -ServerAddresses {}",
        quoted(&list)
    )
}

pub fn reset_dns_script(if_index: u32) -> String {
    format!("Set-DnsClientServerAddress -InterfaceIndex {if_index} -ResetServerAddresses -ErrorAction SilentlyContinue{EXIT_OK}")
}

pub fn dns_of_interface_script(if_index: u32) -> String {
    format!(
        "Get-DnsClientServerAddress -InterfaceIndex {if_index} -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
         ForEach-Object {{ $_.ServerAddresses }}"
    )
}

/// Prefix of the stdout lines [`add_routes_script`] prints for routes it could not add.
pub const ROUTE_FAIL_MARK: &str = "ROUTEFAIL ";

/// The failed-route descriptions (`prefix: reason`) in the output of [`add_routes_script`].
pub fn parse_route_failures(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| l.trim().trim_start_matches('\u{feff}').strip_prefix(ROUTE_FAIL_MARK))
        .map(|s| s.trim().to_string())
        .collect()
}

/// Tag (display name and comment) of the NRPT rule that belongs to us.
pub const NRPT_TAG: &str = "Veil";

/// Prints `NRPTCOUNT <n>`: how many NRPT rules with our tag the DNS client cmdlets see,
/// `NRPTCOUNT none` without those cmdlets, `NRPTCOUNT error <why>` when they fail.
pub fn nrpt_count_script() -> String {
    format!(
        "if (-not (Get-Command Get-DnsClientNrptRule -ErrorAction SilentlyContinue)) {{ Write-Output 'NRPTCOUNT none'; exit 0 }}; \
         try {{ $c = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object {{ $_.Comment -eq '{NRPT_TAG}' }}).Count; \
         Write-Output ('NRPTCOUNT ' + $c) }} \
         catch {{ Write-Output ('NRPTCOUNT error ' + ($_.Exception.Message -replace '\\s+', ' ')) }}; exit 0"
    )
}

/// What [`nrpt_count_script`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NrptCount {
    Rules(u32),
    /// The DnsClient module is not there: only the registry can tell.
    NoCmdlets,
    Error(String),
}

pub fn parse_nrpt_count(out: &str) -> NrptCount {
    let Some(v) = out.lines().find_map(|l| l.trim().trim_start_matches('\u{feff}').strip_prefix("NRPTCOUNT ")) else {
        return NrptCount::Error(format!("no answer: {}", out.trim()));
    };
    let v = v.trim();
    if v == "none" {
        NrptCount::NoCmdlets
    } else if let Ok(n) = v.parse() {
        NrptCount::Rules(n)
    } else {
        NrptCount::Error(v.trim_start_matches("error").trim().to_string())
    }
}

/// The NRPT rule counts as gone only when the registry has no rule with our tag and the
/// DNS client cmdlets see none either (or do not exist). Anything unknown is not "gone".
pub fn nrpt_gone(registry_tagged: Result<usize, String>, cmdlets: &NrptCount) -> Result<(), String> {
    match registry_tagged {
        Ok(0) => {}
        Ok(n) => return Err(format!("{n} rule(s) with the tag {NRPT_TAG} still in the registry")),
        Err(e) => return Err(format!("the registry cannot be read: {e}")),
    }
    match cmdlets {
        NrptCount::Rules(0) | NrptCount::NoCmdlets => Ok(()),
        NrptCount::Rules(n) => Err(format!("Get-DnsClientNrptRule still sees {n} rule(s) {NRPT_TAG}")),
        NrptCount::Error(e) => Err(format!("cannot check with Get-DnsClientNrptRule: {e}")),
    }
}

/// Deletes every NRPT rule carrying our tag. Idempotent (no rule is not an error), but the
/// script fails when a tagged rule cannot be removed or is still there afterwards: the
/// rule lives in the registry and outlives the process, so the caller must know.
pub fn nrpt_remove_script() -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
         Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NRPT_TAG}' }} | Remove-DnsClientNrptRule -Force; \
         if (@(Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{NRPT_TAG}' }}).Count -gt 0) \
         {{ throw 'the NRPT rule {NRPT_TAG} is still present' }}"
    )
}

/// Sends every DNS name (namespace `.`) to `servers` only, which stops Windows' parallel
/// queries (SMHNR) on the physical adapters from leaking names. Replaces earlier tagged rules.
pub fn nrpt_add_script(servers: &[IpAddr]) -> String {
    let list: Vec<String> = servers.iter().map(|s| s.to_string()).collect();
    let list: Vec<&str> = list.iter().map(String::as_str).collect();
    format!(
        "$ErrorActionPreference = 'Stop'; {}; Add-DnsClientNrptRule -Namespace '.' -NameServers {} -DisplayName '{NRPT_TAG}' -Comment '{NRPT_TAG}'",
        nrpt_remove_script(),
        quoted(&list)
    )
}

/// Host route to `ip` through `gateway`, on the interface that owns that gateway's default route.
/// An IPv6 `ip` ignores `gateway` and uses the IPv6 default route's own next hop.
pub fn add_host_route_script(ip: IpAddr, gateway: IpAddr) -> String {
    if ip.is_ipv6() {
        return format!(
            "$ErrorActionPreference = 'Stop'; \
             $r = Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' | Where-Object {{ $_.NextHop -ne '::' }} | \
             Sort-Object RouteMetric | Select-Object -First 1; \
             if (-not $r) {{ throw 'no IPv6 default route with a gateway' }}; \
             Remove-NetRoute -DestinationPrefix '{ip}/128' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue; \
             New-NetRoute -DestinationPrefix '{ip}/128' -InterfaceIndex $r.InterfaceIndex -NextHop $r.NextHop -RouteMetric 1 -PolicyStore ActiveStore | Out-Null"
        );
    }
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.NextHop -eq '{gateway}' }} | \
         Sort-Object RouteMetric | Select-Object -First 1; \
         if (-not $r) {{ throw 'no default route via {gateway}' }}; \
         Remove-NetRoute -DestinationPrefix '{ip}/32' -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue; \
         New-NetRoute -DestinationPrefix '{ip}/32' -InterfaceIndex $r.InterfaceIndex -NextHop '{gateway}' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null"
    )
}

/// Removes our host route (metric 1) to `ip`; an IPv4 route is also matched by its next hop
/// when the gateway is known, so a foreign route to the same address stays. A whole script.
pub fn remove_host_route_script(ip: IpAddr, gateway: Option<IpAddr>) -> String {
    remove_host_route_cmd(ip, gateway) + EXIT_OK
}

/// The command of [`remove_host_route_script`], to embed in a larger script (no `exit`).
fn remove_host_route_cmd(ip: IpAddr, gateway: Option<IpAddr>) -> String {
    format!("{} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue", host_route_query(ip, gateway))
}

/// Our host routes to `ip`: metric 1 and, for IPv4 with a known gateway, through that
/// gateway. The one filter for finding, removing and re-checking them.
fn host_route_query(ip: IpAddr, gateway: Option<IpAddr>) -> String {
    let (len, hop) = match (ip, gateway) {
        (IpAddr::V4(_), Some(gw @ IpAddr::V4(_))) => (32, format!(" -and $_.NextHop -eq '{gw}'")),
        (IpAddr::V4(_), _) => (32, String::new()),
        (IpAddr::V6(_), _) => (128, String::new()),
    };
    format!(
        "Get-NetRoute -DestinationPrefix '{ip}/{len}' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.RouteMetric -eq 1{hop} }}"
    )
}

/// Removes IPv4 /32 routes of metric 1 whose next hop is `$env:VEIL_GW`: leftovers of a run
/// that did not clean up. Prints the removed prefixes. The gateway travels in the environment.
pub const CLEAN_ORPHAN_ROUTES_SCRIPT: &str = "$g = $env:VEIL_GW; \
     $rs = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
     Where-Object { $_.DestinationPrefix -like '*/32' -and $_.RouteMetric -eq 1 -and $_.NextHop -eq $g }); \
     foreach ($r in $rs) { Remove-NetRoute -InputObject $r -Confirm:$false -ErrorAction SilentlyContinue; Write-Output $r.DestinationPrefix }";

/// Asks the system resolver (the path every app uses, NRPT included) for the A records of
/// the name in `$env:VEIL_NAME`. Prints `RESOLVED <ip>` lines, or `RESOLVEFAIL <reason>`.
pub const RESOLVE_CHECK_SCRIPT: &str = "$n = $env:VEIL_NAME; \
     try { Resolve-DnsName -Name $n -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | \
     Where-Object { $_.IPAddress } | ForEach-Object { Write-Output ('RESOLVED ' + $_.IPAddress) } } \
     catch { Write-Output ('RESOLVEFAIL ' + ($_.Exception.Message -replace '\\s+', ' ')) }";

/// The name the check asks for: unique to this process, so no cache (ours, Windows', a
/// router's) can hold an answer for it, and only our fake-IP resolver answers it with an
/// address in 198.18.0.0/15.
pub fn resolve_check_name(pid: u32) -> String {
    format!("veil-check-{pid}.example.com")
}

/// Whether `ip` is in 198.18.0.0/15, where all answers of our resolver come from.
pub fn is_tun_answer(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
}

/// Whether the output of [`RESOLVE_CHECK_SCRIPT`] carries an answer of our resolver (an
/// address in 198.18.0.0/15). A real address means some other server answered.
pub fn parse_resolve_check(out: &str) -> bool {
    out.lines()
        .filter_map(|l| l.trim().trim_start_matches('\u{feff}').strip_prefix("RESOLVED "))
        .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
        .any(is_tun_answer)
}

/// Waits (up to about 20 s) for the address 198.18.0.1 on the adapter whose alias is in
/// `$env:VEIL_IF` to become usable, and prints `ADDRSTATE <state>`: `Preferred` when it
/// is, otherwise the last state seen (`Tentative`, `Duplicate`, ...) or `none`.
pub const TUN_ADDRESS_STATE_SCRIPT: &str = "$n = $env:VEIL_IF; $s = 'none'; \
     for ($i = 0; $i -lt 40; $i++) { \
     $a = Get-NetIPAddress -IPAddress '198.18.0.1' -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
     Where-Object { $_.InterfaceAlias -eq $n } | Select-Object -First 1; \
     if ($a) { $s = [string]$a.AddressState; if ($s -eq 'Preferred') { break } }; \
     Start-Sleep -Milliseconds 500 }; \
     Write-Output ('ADDRSTATE ' + $s); exit 0";

/// The state printed by [`TUN_ADDRESS_STATE_SCRIPT`].
pub fn parse_address_state(out: &str) -> Option<String> {
    out.lines()
        .filter_map(|l| l.trim().trim_start_matches('\u{feff}').strip_prefix("ADDRSTATE "))
        .map(|s| s.trim().to_string())
        .find(|s| !s.is_empty())
}

/// Address of the TUN adapter; [`tun_cleanup_script`] finds the adapter by it and by its
/// alias [`TUN_ADAPTER_NAME`]: both have to match.
pub const TUN_ADAPTER_ADDR: &str = "198.18.0.1";

/// Undoes everything a TUN session leaves in the system, found by tag and address rather
/// than by what some process remembers: NRPT rules tagged [`NRPT_TAG`], the split routes
/// and DNS servers of the adapter named [`TUN_ADAPTER_NAME`] that owns [`TUN_ADAPTER_ADDR`], and the given host
/// routes (from the journal; `(address, gateway)`). Idempotent. Prints `ADMIN 0|1`, then
/// `REMOVED <what>` / `LEFT <what>: <why>` lines, see [`parse_cleanup_output`]; exits
/// with 0 when it ran to the end, whatever it found.
pub fn tun_cleanup_script(host_routes: &[(IpAddr, Option<IpAddr>)]) -> String {
    let mut s = String::from(
        "$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())\
         .IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); \
         Write-Output ('ADMIN ' + [int]$admin); ",
    );
    // The NRPT rule first: it is the one thing that survives the adapter and the process.
    s += &format!(
        "$q = {{ @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object {{ $_.Comment -eq '{NRPT_TAG}' }}) }}; \
         $n = @(& $q).Count; \
         if ($n -gt 0) {{ $e = ''; \
         try {{ & $q | Remove-DnsClientNrptRule -Force -ErrorAction Stop }} catch {{ $e = ($_.Exception.Message -replace '\\s+', ' ') }}; \
         if (@(& $q).Count -eq 0) {{ Write-Output ('REMOVED NRPT rule {NRPT_TAG} (' + $n + ')') }} \
         else {{ Write-Output ('LEFT NRPT rule {NRPT_TAG}: ' + $e) }} }}; "
    );
    s += &format!(
        "$ifs = @(Get-NetIPAddress -IPAddress '{TUN_ADAPTER_ADDR}' -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.InterfaceAlias -eq '{TUN_ADAPTER_NAME}' }} | \
         ForEach-Object {{ $_.InterfaceIndex }} | Select-Object -Unique); \
         foreach ($i in $ifs) {{ foreach ($p in {all}) {{ \
         if (@(Get-NetRoute -DestinationPrefix $p -InterfaceIndex $i -ErrorAction SilentlyContinue).Count -gt 0) {{ \
         Remove-NetRoute -DestinationPrefix $p -InterfaceIndex $i -Confirm:$false -ErrorAction SilentlyContinue; \
         if (@(Get-NetRoute -DestinationPrefix $p -InterfaceIndex $i -ErrorAction SilentlyContinue).Count -eq 0) \
         {{ Write-Output ('REMOVED route ' + $p + ' on interface ' + $i) }} \
         else {{ Write-Output ('LEFT route ' + $p + ' on interface ' + $i + ': could not remove') }} }} }}; \
         Set-DnsClientServerAddress -InterfaceIndex $i -ResetServerAddresses -ErrorAction SilentlyContinue }}; ",
        all = quoted(&SPLIT_PREFIXES)
    );
    for (ip, gw) in host_routes {
        // Found, removed and re-checked with the same filter; REMOVED only once it is gone.
        s += &format!(
            "$hr = {{ @({}) }}; \
             if (@(& $hr).Count -gt 0) {{ & $hr | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; \
             if (@(& $hr).Count -eq 0) {{ Write-Output 'REMOVED host route {ip}' }} \
             else {{ Write-Output 'LEFT host route {ip}: could not remove' }} }}; ",
            host_route_query(*ip, *gw)
        );
    }
    // The result is in the REMOVED/LEFT lines; the exit code only says the script ran to the end.
    s += "exit 0";
    s
}

/// Reads the output of [`tun_cleanup_script`]. Administrator rights are needed when
/// something of ours was found, could not be removed and the script ran without them.
pub fn parse_cleanup_output(out: &str) -> CleanupReport {
    let mut report = CleanupReport::default();
    let mut admin = false;
    for line in out.lines() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if let Some(v) = line.strip_prefix("ADMIN ") {
            admin = v.trim() == "1";
        } else if let Some(v) = line.strip_prefix("REMOVED ") {
            report.removed.push(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("LEFT ") {
            report.failed.push(v.trim().to_string());
        }
    }
    report.needs_admin = !admin && !report.failed.is_empty();
    report
}

/// What a TUN session changes in the system, written to disk before the changes are made
/// so that a later run (or the guard process) knows what to undo and whose it is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunJournal {
    /// The process that set the TUN up.
    pub pid: u32,
    /// Its creation time (FILETIME, 100 ns ticks since 1601): with [`TunJournal::image`]
    /// it tells that process from a later one that got the same pid.
    #[serde(default)]
    pub started: u64,
    /// File name of its executable, e.g. `Veil.exe`.
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub adapter: String,
    /// An NRPT rule has been (or is about to be) added.
    #[serde(default)]
    pub nrpt: bool,
    /// Gateway the host routes go through.
    #[serde(default)]
    pub gateway: Option<IpAddr>,
    #[serde(default)]
    pub host_routes: Vec<IpAddr>,
}

/// `<LOCALAPPDATA>\Veil\tun-state.json`.
pub fn journal_path(local_app_data: &Path) -> PathBuf {
    local_app_data.join("Veil").join("tun-state.json")
}

/// A damaged or half-written journal counts as no journal, and so does anything but a
/// JSON object (serde would also take an array for the struct).
pub fn parse_journal(data: &[u8]) -> Option<TunJournal> {
    let value: serde_json::Value = serde_json::from_slice(data).ok()?;
    if !value.is_object() {
        return None;
    }
    serde_json::from_value(value).ok()
}

/// The host routes of a journal as [`tun_cleanup_script`] takes them.
pub fn journal_host_routes(journal: Option<&TunJournal>) -> Vec<(IpAddr, Option<IpAddr>)> {
    journal.map_or_else(Vec::new, |j| j.host_routes.iter().map(|ip| (*ip, j.gateway)).collect())
}

/// Executables that set up a TUN and write the journal.
/// (`veil-app.exe` is the app's name as built, before the kit renames it.)
pub const OWNER_IMAGES: [&str; 3] = ["veil.exe", "veil-cli.exe", "veil-app.exe"];

/// What identifies a running process beyond its (reusable) pid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProcIdentity {
    /// Creation time, FILETIME ticks.
    pub started: u64,
    /// Full path or file name of the executable.
    pub image: String,
}

/// What the system says about a pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcLookup {
    /// No such process (or it has exited).
    Gone,
    /// It exists but may not be queried: nothing can be proven, so it counts as alive.
    Denied,
    Found(ProcIdentity),
}

/// The file name of an executable path, either separator.
pub fn image_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Whether `found` (what the system now says about the journal's pid; `None`: no such
/// process, or it cannot be queried) is the very process that wrote the journal: same
/// creation time and same executable, one of [`OWNER_IMAGES`]. Anything less is a dead owner.
pub fn owner_alive(journal: &TunJournal, found: Option<&ProcIdentity>) -> bool {
    let Some(p) = found else { return false };
    let image = image_name(&journal.image);
    journal.started != 0
        && p.started == journal.started
        && image_name(&p.image).eq_ignore_ascii_case(image)
        && OWNER_IMAGES.iter().any(|o| o.eq_ignore_ascii_case(image))
}

/// Whether the TUN state on this machine may be cleaned by process `own_pid` without
/// being asked to: not while the live process that wrote the journal is using it.
/// `lookup` tells what process now has a given pid.
pub fn is_orphaned(journal: Option<&TunJournal>, own_pid: u32, lookup: impl Fn(u32) -> ProcLookup) -> bool {
    match journal {
        // Our own journal, or one of a dead process whose pid we got: ours to clean.
        Some(j) if j.pid != own_pid => match lookup(j.pid) {
            ProcLookup::Gone => true,
            // The safe side: a process we may not look at might be the owner.
            ProcLookup::Denied => false,
            ProcLookup::Found(p) => !owner_alive(j, Some(&p)),
        },
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_routes() {
        let out = "\u{feff}12|Ethernet 2|192.168.1.1|25\r\n7|Беспроводная сеть|10.0.0.1|40\r\n9|Veil|0.0.0.0|5\r\nbad line\r\n";
        let r = parse_default_routes(out);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], DefaultRoute { index: 12, alias: "Ethernet 2".into(), next_hop: "192.168.1.1".parse().unwrap(), metric: 25 });
        assert_eq!(r[1].alias, "Беспроводная сеть");
        // The on-link route with a lower metric loses to a real gateway.
        assert_eq!(best_default(&r).unwrap().index, 12);
        assert!(best_default(&[]).is_none());
    }

    #[test]
    fn alias_with_pipe_still_parses() {
        let r = parse_default_routes("3|a|b|10.0.0.1|7");
        assert_eq!(r[0].alias, "a|b");
        assert_eq!(r[0].metric, 7);
    }

    #[test]
    fn parses_ips_and_index() {
        let ips = parse_ip_lines("192.168.1.1\r\n\r\nfe80::1%12\r\nnonsense\r\n");
        assert_eq!(ips, vec!["192.168.1.1".parse::<IpAddr>().unwrap(), "fe80::1".parse().unwrap()]);
        assert_eq!(parse_index("\r\n14\r\n").map(NonZeroU32::get), Some(14));
        assert_eq!(parse_index("0"), None);
        assert_eq!(parse_index(""), None);
    }

    #[test]
    fn alias_validation() {
        assert!(validate_alias("Veil Tun").is_ok());
        assert!(validate_alias("Ethernet (2)").is_ok());
        assert!(validate_alias("Беспроводная сеть").is_ok());
        assert!(validate_alias("").is_err());
        assert!(validate_alias("a';calc;'").is_err());
        assert!(validate_alias("a\"b").is_err());
        assert!(validate_alias("a\nb").is_err());
        assert!(validate_alias("a$b").is_err());
    }

    #[test]
    fn route_scripts() {
        let s = add_routes_script(14, TunRoutes::All);
        assert!(s.contains("'0.0.0.0/1','128.0.0.0/1'"));
        assert!(s.contains("'::/1','8000::/1'"));
        assert!(s.contains("-InterfaceIndex 14"));
        let s = add_routes_script(14, TunRoutes::LowerHalf);
        assert!(s.contains("'0.0.0.0/1'") && !s.contains("128.0.0.0/1") && !s.contains("::/1"));
        let s = add_routes_script(14, TunRoutes::Domains);
        assert!(!s.contains("New-NetRoute"));
        let r = remove_routes_script(14);
        assert!(r.contains("Remove-NetRoute") && r.contains("8000::/1"));
        assert!(!add_routes_script(1, TunRoutes::All).contains('"'));
    }

    #[test]
    fn dns_and_host_scripts() {
        let s = set_dns_script(14, &["198.18.0.2".parse().unwrap()]);
        assert!(s.ends_with("-ServerAddresses '198.18.0.2'"));
        assert!(reset_dns_script(14).contains("-ResetServerAddresses"));
        let h = add_host_route_script("203.0.113.5".parse().unwrap(), "192.168.1.1".parse().unwrap());
        assert!(h.contains("'203.0.113.5/32'") && h.contains("'192.168.1.1'"));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(remove_host_route_script(ip, None).contains("203.0.113.5/32"));
        assert!(!remove_host_route_script(ip, None).contains("NextHop"));
        assert!(remove_host_route_script(ip, Some(gw)).contains("$_.NextHop -eq '192.168.1.1'"));
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        let s = remove_host_route_script(v6, Some(gw));
        assert!(s.contains("'2001:db8::5/128'") && !s.contains("NextHop"));
    }

    #[test]
    fn ipv6_host_route_uses_v6_default() {
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        let s = add_host_route_script(v6, "192.168.1.1".parse().unwrap());
        assert!(s.contains("-AddressFamily IPv6") && s.contains("'2001:db8::5/128'") && s.contains("$r.NextHop"));
        assert!(!s.contains("192.168.1.1"));
    }

    #[test]
    fn nrpt_scripts() {
        let add = nrpt_add_script(&["198.18.0.2".parse().unwrap()]);
        assert!(add.contains("Add-DnsClientNrptRule -Namespace '.' -NameServers '198.18.0.2'"));
        assert!(add.contains("-DisplayName 'Veil' -Comment 'Veil'"));
        // Stale tagged rules are dropped first, then the new one is added.
        assert!(add.find("Remove-DnsClientNrptRule").unwrap() < add.find("Add-DnsClientNrptRule").unwrap());
        let rm = nrpt_remove_script();
        assert!(rm.contains("$_.Comment -eq 'Veil'") && rm.contains("Remove-DnsClientNrptRule"));
        assert!(!rm.contains("Add-DnsClientNrptRule"));
        // The result matters: errors are not swallowed and a surviving rule fails the script.
        assert!(!rm.contains("SilentlyContinue"));
        assert!(rm.contains("$ErrorActionPreference = 'Stop'") && rm.contains("throw"));
        assert!(rm.find("Remove-DnsClientNrptRule").unwrap() < rm.find("throw").unwrap());
    }

    #[test]
    fn resolve_check_output() {
        assert!(parse_resolve_check("\u{feff}RESOLVED 198.18.0.7\r\n"));
        assert!(parse_resolve_check("RESOLVED 93.184.216.34\r\nRESOLVED 198.19.255.254\r\n"));
        // Only our resolver's answers count: a real address (v4 or v6) means it was not asked.
        assert!(!parse_resolve_check("RESOLVED 93.184.216.34\r\n"));
        assert!(!parse_resolve_check("noise\r\nRESOLVED 2001:db8::1\r\n"));
        assert!(!parse_resolve_check("RESOLVED 198.20.0.1\r\nRESOLVED 198.17.255.255\r\n"));
        assert!(is_tun_answer("198.18.0.0".parse().unwrap()) && is_tun_answer("198.19.1.2".parse().unwrap()));
        assert!(!is_tun_answer("::ffff:198.18.0.7".parse().unwrap()));
        assert_eq!(resolve_check_name(4242), "veil-check-4242.example.com");
        assert!(validate_alias(&resolve_check_name(u32::MAX)).is_ok());
        assert!(!parse_resolve_check("RESOLVEFAIL DNS name does not exist\r\n"));
        assert!(!parse_resolve_check("RESOLVED \r\nRESOLVED nonsense\r\n"));
        assert!(!parse_resolve_check(""));
        assert!(RESOLVE_CHECK_SCRIPT.contains("$env:VEIL_NAME") && RESOLVE_CHECK_SCRIPT.contains("Resolve-DnsName"));
    }

    #[test]
    fn cleanup_script() {
        let s = tun_cleanup_script(&[]);
        // Only our things: the tagged rule and the adapter that owns the TUN address.
        assert!(s.contains("$_.Comment -eq 'Veil'") && s.contains("Remove-DnsClientNrptRule"));
        assert!(s.contains("Get-NetIPAddress -IPAddress '198.18.0.1'"));
        // Both the address and the alias: a foreign adapter that happens to use 198.18.0.1 is left alone.
        assert!(s.contains("Where-Object { $_.InterfaceAlias -eq 'Veil' }"));
        assert!(s.find("-IPAddress '198.18.0.1'").unwrap() < s.find("InterfaceAlias -eq 'Veil'").unwrap());
        assert!(s.find("InterfaceAlias -eq 'Veil'").unwrap() < s.find("foreach ($i in $ifs)").unwrap());
        assert!(s.contains("'0.0.0.0/1','128.0.0.0/1','::/1','8000::/1'"));
        assert!(s.contains("-InterfaceIndex $i") && s.contains("-ResetServerAddresses"));
        // The NRPT rule goes first.
        assert!(s.find("Remove-DnsClientNrptRule").unwrap() < s.find("Remove-NetRoute").unwrap());
        // Without a journal no host route (/32) is touched, and never the default route.
        assert!(!s.contains("/32") && !s.contains("0.0.0.0/0") && !s.contains("::/0"));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let s = tun_cleanup_script(&[(ip, Some(gw))]);
        assert!(s.contains("'203.0.113.5/32'") && s.contains("$_.NextHop -eq '192.168.1.1'"));
        assert!(s.contains("REMOVED host route 203.0.113.5") && s.contains("LEFT host route 203.0.113.5"));
        // The same filter (metric and gateway) finds, removes and re-checks; REMOVED only after
        // the re-check.
        let hr = s.find("$hr = { @(").unwrap();
        assert!(s[hr..].starts_with(&format!("$hr = {{ @({}) }}", host_route_query(ip, Some(gw)))));
        assert!(s.find("& $hr | Remove-NetRoute").unwrap() < s.find("(& $hr).Count -eq 0").unwrap());
        assert!(s.find("(& $hr).Count -eq 0").unwrap() < s.find("REMOVED host route").unwrap());
        assert_eq!(remove_host_route_script(ip, Some(gw)), format!("{} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; exit 0", host_route_query(ip, Some(gw))));
    }

    #[test]
    fn cleanup_output() {
        let r = parse_cleanup_output("\u{feff}ADMIN 1\r\nREMOVED NRPT rule Veil (1)\r\nREMOVED route 0.0.0.0/1 on interface 7\r\n");
        assert!(!r.needs_admin && r.failed.is_empty());
        assert_eq!(r.removed, vec!["NRPT rule Veil (1)", "route 0.0.0.0/1 on interface 7"]);
        // Found but not removed, without administrator rights.
        let r = parse_cleanup_output("ADMIN 0\r\nLEFT NRPT rule Veil: Access is denied.\r\n");
        assert!(r.needs_admin && r.removed.is_empty());
        assert_eq!(r.failed, vec!["NRPT rule Veil: Access is denied."]);
        // A failure as administrator is a failure, not a rights problem.
        let r = parse_cleanup_output("ADMIN 1\r\nLEFT NRPT rule Veil: boom\r\n");
        assert!(!r.needs_admin && r.failed.len() == 1);
        // Nothing of ours: nothing to do, with or without rights.
        assert_eq!(parse_cleanup_output("ADMIN 0\r\n"), CleanupReport::default());
        assert_eq!(parse_cleanup_output(""), CleanupReport::default());
    }

    #[test]
    fn journal() {
        let j = TunJournal {
            pid: 4242,
            started: 133_000_000_000_000_000,
            image: "Veil.exe".into(),
            adapter: "Veil".into(),
            nrpt: true,
            gateway: Some("192.168.1.1".parse().unwrap()),
            host_routes: vec!["203.0.113.5".parse().unwrap()],
        };
        let data = serde_json::to_vec(&j).unwrap();
        assert_eq!(parse_journal(&data), Some(j.clone()));
        // Half-written, empty or foreign content is no journal.
        assert_eq!(parse_journal(&data[..data.len() / 2]), None);
        assert_eq!(parse_journal(b""), None);
        assert_eq!(parse_journal(b"[1,2]"), None);
        assert_eq!(parse_journal(b"[1,2,3,4,5,6,7]"), None);
        // Fields added later are optional.
        assert_eq!(parse_journal(br#"{"pid":7}"#), Some(TunJournal { pid: 7, ..TunJournal::default() }));
        assert_eq!(journal_host_routes(Some(&j)), vec![("203.0.113.5".parse().unwrap(), j.gateway)]);
        assert!(journal_host_routes(None).is_empty());
        assert!(journal_path(Path::new("base")).ends_with("Veil/tun-state.json") || journal_path(Path::new("base")).ends_with("Veil\\tun-state.json"));
    }

    #[test]
    fn orphan_check() {
        let j = TunJournal { pid: 10, started: 777, image: "Veil.exe".into(), ..TunJournal::default() };
        let same = ProcIdentity { started: 777, image: r"C:\Program Files\Veil\veil.exe".into() };
        let live = |pid: u32| if pid == 10 { ProcLookup::Found(same.clone()) } else { ProcLookup::Gone };
        // No journal, our own journal, or a dead owner: clean. A live other owner: hands off.
        assert!(is_orphaned(None, 1, live));
        assert!(is_orphaned(Some(&j), 10, live));
        assert!(is_orphaned(Some(&j), 1, |_| ProcLookup::Gone));
        assert!(!is_orphaned(Some(&j), 1, live));
        // A process we may not query might be the owner: hands off.
        assert!(!is_orphaned(Some(&j), 1, |_| ProcLookup::Denied));
        // The pid went to another process: other start time or other program.
        let later = ProcIdentity { started: 778, ..same.clone() };
        assert!(is_orphaned(Some(&j), 1, |_| ProcLookup::Found(later.clone())));
        let other = ProcIdentity { image: r"C:\Windows\notepad.exe".into(), ..same.clone() };
        assert!(is_orphaned(Some(&j), 1, |_| ProcLookup::Found(other.clone())));
        // A journal without identity (older version) or naming a foreign program proves nothing.
        let old = TunJournal { pid: 10, ..TunJournal::default() };
        assert!(is_orphaned(Some(&old), 1, |_| ProcLookup::Found(ProcIdentity::default())));
        let foreign = TunJournal { image: "notepad.exe".into(), ..j.clone() };
        assert!(is_orphaned(Some(&foreign), 1, |_| ProcLookup::Found(ProcIdentity { image: "notepad.exe".into(), started: 777 })));
        // veil-cli and the unrenamed app count too, any case, either separator.
        let cli = TunJournal { image: "veil-cli.exe".into(), ..j.clone() };
        assert!(!is_orphaned(Some(&cli), 1, |_| ProcLookup::Found(ProcIdentity { started: 777, image: "D:/x/VEIL-CLI.EXE".into() })));
        let app = TunJournal { image: "veil-app.exe".into(), ..j.clone() };
        assert!(!is_orphaned(Some(&app), 1, |_| ProcLookup::Found(ProcIdentity { started: 777, image: r"C:\t\veil-app.exe".into() })));
    }

    #[test]
    fn nrpt_count_and_gone() {
        assert_eq!(parse_nrpt_count("\u{feff}NRPTCOUNT 0\r\n"), NrptCount::Rules(0));
        assert_eq!(parse_nrpt_count("NRPTCOUNT 2"), NrptCount::Rules(2));
        assert_eq!(parse_nrpt_count("NRPTCOUNT none"), NrptCount::NoCmdlets);
        assert_eq!(parse_nrpt_count("NRPTCOUNT error Access denied"), NrptCount::Error("Access denied".into()));
        assert!(matches!(parse_nrpt_count(""), NrptCount::Error(_)));
        // Gone only when both the registry and the cmdlets agree.
        assert!(nrpt_gone(Ok(0), &NrptCount::Rules(0)).is_ok());
        assert!(nrpt_gone(Ok(0), &NrptCount::NoCmdlets).is_ok());
        assert!(nrpt_gone(Ok(1), &NrptCount::Rules(0)).is_err());
        assert!(nrpt_gone(Ok(0), &NrptCount::Rules(1)).is_err());
        assert!(nrpt_gone(Err("5".into()), &NrptCount::Rules(0)).is_err());
        assert!(nrpt_gone(Ok(0), &NrptCount::Error("x".into())).is_err());
        let s = nrpt_count_script();
        assert!(s.contains("$_.Comment -eq 'Veil'") && s.ends_with("exit 0") && !s.contains('"'));
        assert!(!s.contains("Remove-"));
    }

    #[test]
    fn address_state() {
        assert_eq!(parse_address_state("\u{feff}ADDRSTATE Preferred\r\n").as_deref(), Some("Preferred"));
        assert_eq!(parse_address_state("noise\r\nADDRSTATE Tentative\r\n").as_deref(), Some("Tentative"));
        assert_eq!(parse_address_state("ADDRSTATE \r\n"), None);
        assert_eq!(parse_address_state(""), None);
        let s = TUN_ADDRESS_STATE_SCRIPT;
        assert!(s.contains(&format!("-IPAddress '{TUN_ADAPTER_ADDR}'")) && s.contains("$env:VEIL_IF"));
        assert!(s.contains("InterfaceAlias -eq $n") && s.contains("'Preferred'") && s.ends_with("exit 0"));
        assert!(!s.contains('"'));
    }

    #[test]
    fn image_names() {
        assert_eq!(image_name(r"C:\a\Veil.exe"), "Veil.exe");
        assert_eq!(image_name("a/b/veil-cli.exe"), "veil-cli.exe");
        assert_eq!(image_name("Veil.exe"), "Veil.exe");
        assert_eq!(image_name(""), "");
    }

    #[test]
    fn route_failure_output() {
        let out = "ROUTEFAIL ::/1: Access denied\r\nnoise\r\n\u{feff}ROUTEFAIL 8000::/1: no ipv6\r\n";
        assert_eq!(parse_route_failures(out), vec!["::/1: Access denied", "8000::/1: no ipv6"]);
        assert!(parse_route_failures("").is_empty());
        let s = add_routes_script(14, TunRoutes::All);
        assert!(s.contains("catch { Write-Output ('ROUTEFAIL ' + $p"));
    }

    #[test]
    fn scripts_have_no_double_quotes_or_names() {
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let v6: IpAddr = "2001:db8::5".parse().unwrap();
        let gw: IpAddr = "192.168.1.1".parse().unwrap();
        let all = [
            DEFAULT_ROUTES_SCRIPT.to_string(),
            INTERFACE_INDEX_SCRIPT.to_string(),
            CLEAN_ORPHAN_ROUTES_SCRIPT.to_string(),
            add_routes_script(7, TunRoutes::All),
            add_routes_script(7, TunRoutes::LowerHalf),
            add_routes_script(7, TunRoutes::Domains),
            remove_routes_script(7),
            set_dns_script(7, &[ip]),
            reset_dns_script(7),
            dns_of_interface_script(7),
            add_host_route_script(ip, gw),
            add_host_route_script(v6, gw),
            remove_host_route_script(ip, Some(gw)),
            remove_host_route_script(v6, None),
            nrpt_add_script(&[ip, v6]),
            nrpt_remove_script(),
            RESOLVE_CHECK_SCRIPT.to_string(),
            tun_cleanup_script(&[]),
            tun_cleanup_script(&[(ip, Some(gw)), (v6, None)]),
        ];
        for s in &all {
            assert!(!s.contains('"'), "double quote in: {s}");
            assert!(!s.contains('`'), "backtick in: {s}");
        }
        // Scripts whose result is on stdout (or that are best effort) end with exit 0, once,
        // so the exit code means "ran to the end"; the ones whose failure matters do not.
        let exit_ok = [
            remove_routes_script(7),
            reset_dns_script(7),
            remove_host_route_script(ip, Some(gw)),
            remove_host_route_script(v6, None),
            tun_cleanup_script(&[]),
            tun_cleanup_script(&[(ip, Some(gw)), (v6, None)]),
        ];
        for s in &exit_ok {
            assert!(s.ends_with("exit 0"), "no exit 0 at the end of: {s}");
            assert_eq!(s.matches("exit").count(), 1, "exit inside: {s}");
        }
        for s in [add_routes_script(7, TunRoutes::All), set_dns_script(7, &[ip]), nrpt_add_script(&[ip]), nrpt_remove_script(), add_host_route_script(ip, gw)] {
            assert!(!s.contains("exit"), "a failure must show in the exit code: {s}");
        }
        // Names and the gateway come from the environment, never from script text.
        assert!(INTERFACE_INDEX_SCRIPT.contains("$env:VEIL_IF"));
        assert!(CLEAN_ORPHAN_ROUTES_SCRIPT.contains("$env:VEIL_GW"));
        // Adapter-scoped scripts carry the numeric index only.
        assert!(add_routes_script(7, TunRoutes::All).contains("-InterfaceIndex 7"));
        assert!(!add_routes_script(7, TunRoutes::All).contains("Veil"));
    }
}
