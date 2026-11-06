//! Pure helpers for the Windows TUN setup: PowerShell script builders and
//! parsers of their output. Kept free of OS calls so the tests run anywhere.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::IpAddr;
use std::num::NonZeroU32;

use anyhow::{Result, bail};

use crate::TunRoutes;

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
    if let Some(c) = name.chars().find(|c| !(c.is_alphanumeric() || " -_.()#:".contains(*c))) {
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
        s += &format!(
            "foreach ($p in {}) {{ try {{ New-NetRoute -DestinationPrefix $p -InterfaceIndex {if_index} -NextHop '::' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null }} catch {{ }} }}; ",
            quoted(v6)
        );
    }
    s
}

pub fn remove_routes_script(if_index: u32) -> String {
    let all = quoted(&["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"]);
    format!(
        "foreach ($p in {all}) {{ Remove-NetRoute -DestinationPrefix $p -InterfaceIndex {if_index} -Confirm:$false -ErrorAction SilentlyContinue }}"
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
    format!("Set-DnsClientServerAddress -InterfaceIndex {if_index} -ResetServerAddresses -ErrorAction SilentlyContinue")
}

pub fn dns_of_interface_script(if_index: u32) -> String {
    format!(
        "Get-DnsClientServerAddress -InterfaceIndex {if_index} -AddressFamily IPv4 -ErrorAction SilentlyContinue | \
         ForEach-Object {{ $_.ServerAddresses }}"
    )
}

/// Host route to `ip` through `gateway`, on the interface that owns that gateway's default route.
pub fn add_host_route_script(ip: IpAddr, gateway: IpAddr) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; \
         $r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.NextHop -eq '{gateway}' }} | \
         Sort-Object RouteMetric | Select-Object -First 1; \
         if (-not $r) {{ throw 'no default route via {gateway}' }}; \
         New-NetRoute -DestinationPrefix '{ip}/32' -InterfaceIndex $r.InterfaceIndex -NextHop '{gateway}' -RouteMetric 1 -PolicyStore ActiveStore | Out-Null"
    )
}

pub fn remove_host_route_script(ip: IpAddr) -> String {
    format!(
        "Get-NetRoute -DestinationPrefix '{ip}/32' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.RouteMetric -eq 1 }} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    )
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
        assert!(remove_host_route_script("203.0.113.5".parse().unwrap()).contains("203.0.113.5/32"));
    }
}
