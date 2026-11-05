//! Compiled routing rules.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::RegexSet;
use veil_config::{RouteAction, RoutingConfig, RoutingRule};

use crate::geo::{self, DomainKind};

#[derive(Default)]
struct DomainMatcher {
    full: HashSet<String>,
    suffix: HashSet<String>,
    keyword: Vec<String>,
    regex: Option<RegexSet>,
}

impl DomainMatcher {
    fn is_empty(&self) -> bool {
        self.full.is_empty() && self.suffix.is_empty() && self.keyword.is_empty() && self.regex.is_none()
    }

    fn matches(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.full.contains(&host) {
            return true;
        }
        let mut rest = host.as_str();
        loop {
            if self.suffix.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, parent)) => rest = parent,
                None => break,
            }
        }
        self.keyword.iter().any(|k| host.contains(k.as_str()))
            || self.regex.as_ref().is_some_and(|r| r.is_match(&host))
    }
}

/// Sorted, merged address ranges.
#[derive(Default)]
struct IpMatcher {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy>(mut ranges: Vec<(T, T)>, next: impl Fn(T) -> Option<T>) -> Vec<(T, T)> {
    ranges.sort();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = out.last_mut()
            && (start <= last.1 || next(last.1) == Some(start))
        {
            last.1 = last.1.max(end);
            continue;
        }
        out.push((start, end));
    }
    out
}

fn contains<T: Ord + Copy>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|r| r.0 <= x);
    i > 0 && x <= ranges[i - 1].1
}

impl IpMatcher {
    fn build(cidrs: &[(IpAddr, u8)]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for &(ip, prefix) in cidrs {
            match ip {
                IpAddr::V4(a) => {
                    let p = prefix.min(32) as u32;
                    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                    let start = u32::from(a) & mask;
                    v4.push((start, start | !mask));
                }
                IpAddr::V6(a) => {
                    let p = prefix.min(128) as u32;
                    let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                    let start = u128::from(a) & mask;
                    v6.push((start, start | !mask));
                }
            }
        }
        Self { v4: merge(v4, |x: u32| x.checked_add(1)), v6: merge(v6, |x: u128| x.checked_add(1)) }
    }

    fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    fn matches(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => contains(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(v4) => contains(&self.v4, u32::from(v4)),
                None => contains(&self.v6, u128::from(a)),
            },
        }
    }
}

struct Rule {
    action: RouteAction,
    domain: Option<DomainMatcher>,
    ip: Option<IpMatcher>,
    ports: Vec<(u16, u16)>,
    process: Vec<String>,
}

pub struct Rules {
    rules: Vec<Rule>,
    final_action: RouteAction,
    needs_ip: bool,
    needs_process: bool,
}

/// What we know about a destination when matching.
pub struct Target<'a> {
    pub domain: Option<&'a str>,
    pub ips: &'a [IpAddr],
    pub port: u16,
    /// The local app that opened the connection, when known.
    pub process: Option<&'a crate::process::ProcessInfo>,
}

/// Built-in ranges, so `geoip:private` works without a geoip.dat file.
const PRIVATE: &[&str] = &[
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
];

fn parse_cidr(s: &str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip, Some(p.parse::<u8>().with_context(|| format!("bad prefix in {s}"))?)),
        None => (s, None),
    };
    let ip: IpAddr = ip.parse().with_context(|| format!("bad IP {s}"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    match prefix {
        Some(p) if p > max => bail!("bad prefix in {s}: at most /{max}"),
        p => Ok((ip, p.unwrap_or(max))),
    }
}

fn parse_port(s: &str) -> Result<(u16, u16)> {
    let bad = || format!("bad port {s}");
    Ok(match s.split_once('-') {
        Some((a, b)) => (a.trim().parse().with_context(bad)?, b.trim().parse().with_context(bad)?),
        None => {
            let p = s.trim().parse().with_context(bad)?;
            (p, p)
        }
    })
}

impl Rules {
    pub fn compile(cfg: &RoutingConfig, geo_dir: &Path) -> Result<Self> {
        // Collect geo codes first so each file is scanned only once.
        let mut geoip_codes = Vec::new();
        let mut geosite_codes = Vec::new();
        for r in &cfg.rules {
            for d in &r.domain {
                if let Some(c) = d.strip_prefix("geosite:") {
                    geosite_codes.push(c.to_ascii_uppercase());
                }
            }
            for i in &r.ip {
                if let Some(c) = i.strip_prefix("geoip:") {
                    let c = c.to_ascii_uppercase();
                    if c != "PRIVATE" {
                        geoip_codes.push(c);
                    }
                }
            }
        }
        let geoip = if geoip_codes.is_empty() {
            HashMap::new()
        } else {
            geo::load_geoip(&geo_dir.join("geoip.dat"), &geoip_codes)
                .context("geoip rules need geoip.dat (run `veil geo update`)")?
        };
        let geosite = if geosite_codes.is_empty() {
            HashMap::new()
        } else {
            geo::load_geosite(&geo_dir.join("geosite.dat"), &geosite_codes)
                .context("geosite rules need geosite.dat (run `veil geo update`)")?
        };

        let mut rules = Vec::new();
        for r in &cfg.rules {
            rules.push(compile_rule(r, &geoip, &geosite)?);
        }
        let needs_ip = rules.iter().any(|r| r.ip.is_some());
        let needs_process = rules.iter().any(|r| !r.process.is_empty());
        Ok(Self { rules, final_action: cfg.final_action, needs_ip, needs_process })
    }

    /// Whether any rule looks at the originating app.
    pub fn needs_process(&self) -> bool {
        self.needs_process
    }

    /// Whether resolving a domain could change the decision.
    pub fn needs_ip(&self) -> bool {
        self.needs_ip
    }

    /// First matching rule's action. `None` means no rule matched.
    pub fn first_match(&self, t: &Target) -> Option<RouteAction> {
        self.rules.iter().find(|r| rule_matches(r, t)).map(|r| r.action)
    }

    pub fn final_action(&self) -> RouteAction {
        self.final_action
    }
}

fn rule_matches(r: &Rule, t: &Target) -> bool {
    if !r.process.is_empty() && !t.process.is_some_and(|p| r.process.iter().any(|pat| p.matches(pat))) {
        return false;
    }
    if !r.ports.is_empty() && !r.ports.iter().any(|(a, b)| (*a..=*b).contains(&t.port)) {
        return false;
    }
    if let Some(d) = &r.domain
        && !t.domain.is_some_and(|host| d.matches(host))
    {
        return false;
    }
    if let Some(ipm) = &r.ip
        && !t.ips.iter().any(|ip| ipm.matches(*ip))
    {
        return false;
    }
    true
}

fn compile_rule(
    r: &RoutingRule,
    geoip: &HashMap<String, Vec<(IpAddr, u8)>>,
    geosite: &HashMap<String, Vec<(DomainKind, String)>>,
) -> Result<Rule> {
    let mut dm = DomainMatcher::default();
    let mut regexes = Vec::new();
    let mut add = |kind: DomainKind, v: String, regexes: &mut Vec<String>| match kind {
        DomainKind::Full => {
            dm.full.insert(v);
        }
        DomainKind::Suffix => {
            dm.suffix.insert(v);
        }
        DomainKind::Keyword => dm.keyword.push(v),
        DomainKind::Regex => regexes.push(v),
    };
    for d in &r.domain {
        let d = d.trim();
        if let Some(code) = d.strip_prefix("geosite:") {
            let list = geosite
                .get(&code.to_ascii_uppercase())
                .with_context(|| format!("geosite:{code} not found in geosite.dat"))?;
            for (kind, v) in list {
                add(*kind, v.clone(), &mut regexes);
            }
        } else if let Some(v) = d.strip_prefix("full:") {
            add(DomainKind::Full, v.to_ascii_lowercase(), &mut regexes);
        } else if let Some(v) = d.strip_prefix("domain:") {
            add(DomainKind::Suffix, v.to_ascii_lowercase(), &mut regexes);
        } else if let Some(v) = d.strip_prefix("keyword:") {
            add(DomainKind::Keyword, v.to_ascii_lowercase(), &mut regexes);
        } else if let Some(v) = d.strip_prefix("regexp:") {
            add(DomainKind::Regex, v.to_string(), &mut regexes);
        } else if !d.is_empty() {
            add(DomainKind::Keyword, d.to_ascii_lowercase(), &mut regexes);
        }
    }
    if !regexes.is_empty() {
        dm.regex = Some(RegexSet::new(&regexes).context("invalid regexp in routing rule")?);
    }

    let mut cidrs = Vec::new();
    for i in &r.ip {
        let i = i.trim();
        match i.strip_prefix("geoip:") {
            Some(code) if code.eq_ignore_ascii_case("private") => {
                cidrs.extend(PRIVATE.iter().map(|c| parse_cidr(c).unwrap()));
            }
            Some(code) => cidrs.extend(
                geoip
                    .get(&code.to_ascii_uppercase())
                    .with_context(|| format!("geoip:{code} not found in geoip.dat"))?,
            ),
            None => cidrs.push(parse_cidr(i)?),
        }
    }
    let ipm = IpMatcher::build(&cidrs);

    if r.domain.is_empty() && r.ip.is_empty() && r.port.is_empty() && r.process.is_empty() {
        bail!("routing rule has no conditions");
    }
    Ok(Rule {
        action: r.action,
        domain: (!r.domain.is_empty() && !dm.is_empty()).then_some(dm),
        ip: (!r.ip.is_empty() && !ipm.is_empty()).then_some(ipm),
        ports: r.port.iter().map(|p| parse_port(p)).collect::<Result<_>>()?,
        process: r.process.iter().map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use veil_config::RouteAction::*;

    fn target<'a>(domain: Option<&'a str>, ips: &'a [IpAddr], port: u16) -> Target<'a> {
        Target { domain, ips, port, process: None }
    }

    #[test]
    fn process_rules() {
        let cfg = RoutingConfig {
            rules: vec![
                RoutingRule::processes(Direct, &["Steam", "/Applications/Banking.app"]),
                RoutingRule { process: vec!["Telegram".into()], ..RoutingRule::domains(Block, &["domain:ads.com"]) },
            ],
            final_action: Proxy,
        };
        let r = Rules::compile(&cfg, Path::new("/nonexistent")).unwrap();
        assert!(r.needs_process());
        let steam = crate::process::ProcessInfo {
            pid: 1, exe: "steam_osx".into(), app: Some("Steam".into()),
            path: "/Applications/Steam.app/Contents/MacOS/steam_osx".into(),
        };
        let tg = crate::process::ProcessInfo {
            pid: 2, exe: "Telegram".into(), app: Some("Telegram".into()),
            path: "/Applications/Telegram.app/Contents/MacOS/Telegram".into(),
        };
        let m = |d: &str, p: Option<&crate::process::ProcessInfo>| {
            r.first_match(&Target { domain: Some(d), ips: &[], port: 443, process: p })
        };
        assert_eq!(m("x.com", Some(&steam)), Some(Direct));
        assert_eq!(m("x.com", Some(&tg)), None);
        // Both conditions of the second rule must hold.
        assert_eq!(m("ads.com", Some(&tg)), Some(Block));
        assert_eq!(m("ads.com", Some(&steam)), Some(Direct));
        assert_eq!(m("ads.com", None), None);
    }

    #[test]
    fn domain_kinds() {
        let cfg = RoutingConfig {
            rules: vec![
                RoutingRule::domains(Block, &["full:ads.example.com", "regexp:^track\\d+\\."]),
                RoutingRule::domains(Direct, &["domain:ru", "keyword:yandex"]),
            ],
            final_action: Proxy,
        };
        let r = Rules::compile(&cfg, Path::new("/nonexistent")).unwrap();
        let m = |d: &str| r.first_match(&target(Some(d), &[], 443));
        assert_eq!(m("ads.example.com"), Some(Block));
        assert_eq!(m("x.ads.example.com"), None);
        assert_eq!(m("track12.site.com"), Some(Block));
        assert_eq!(m("mail.RU."), Some(Direct));
        assert_eq!(m("ru"), Some(Direct));
        assert_eq!(m("guru.com"), None);
        assert_eq!(m("music.yandex.com"), Some(Direct));
        assert!(!r.needs_ip());
    }

    #[test]
    fn ips_and_ports() {
        let cfg = RoutingConfig {
            rules: vec![
                RoutingRule::ips(Direct, &["geoip:private", "8.8.8.8", "2001:db8::/32"]),
                RoutingRule { port: vec!["25".into(), "6881-6889".into()], ..RoutingRule::ips(Block, &[]) },
            ],
            final_action: Proxy,
        };
        let r = Rules::compile(&cfg, Path::new("/nonexistent")).unwrap();
        let m = |ip: &str, port| r.first_match(&target(None, &[ip.parse().unwrap()], port));
        assert_eq!(m("192.168.1.5", 80), Some(Direct));
        assert_eq!(m("::ffff:10.1.2.3", 80), Some(Direct));
        assert_eq!(m("8.8.8.8", 80), Some(Direct));
        assert_eq!(m("8.8.4.4", 80), None);
        assert_eq!(m("2001:db8:1::1", 80), Some(Direct));
        assert_eq!(m("1.1.1.1", 6885), Some(Block));
        assert!(r.needs_ip());
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("::/129").is_err());
        // A domain-only target cannot satisfy an IP rule.
        assert_eq!(r.first_match(&target(Some("a.com"), &[], 80)), None);
    }

    #[test]
    fn missing_geo_file_is_reported() {
        let cfg = RoutingConfig::preset("ru-direct").unwrap();
        let err = Rules::compile(&cfg, Path::new("/nonexistent")).err().unwrap();
        assert!(format!("{err:#}").contains("veil geo update"));
    }
}

/// Uses the geo files shipped with Homebrew's xray when present.
#[cfg(test)]
mod geo_file_tests {
    use super::*;

    fn geo_dir() -> Option<std::path::PathBuf> {
        let dir = std::path::PathBuf::from(
            std::env::var("VEIL_GEO_DIR").unwrap_or_else(|_| "/opt/homebrew/share/xray".into()),
        );
        dir.join("geosite.dat").exists().then_some(dir)
    }

    #[test]
    fn ru_direct_preset() {
        let Some(dir) = geo_dir() else {
            eprintln!("no geo files, skipping");
            return;
        };
        let r = Rules::compile(&RoutingConfig::preset("ru-direct").unwrap(), &dir).unwrap();
        let m = |d: Option<&str>, ip: Option<&str>| {
            let ips: Vec<IpAddr> = ip.map(|i| i.parse().unwrap()).into_iter().collect();
            r.first_match(&Target { domain: d, ips: &ips, port: 443, process: None })
        };
        assert_eq!(m(Some("ya.ru"), None), Some(RouteAction::Direct));
        assert_eq!(m(Some("vk.com"), None), Some(RouteAction::Direct), "geosite:category-ru");
        assert_eq!(m(None, Some("77.88.55.88")), Some(RouteAction::Direct), "geoip:ru (Yandex)");
        assert_eq!(m(Some("youtube.com"), None), None);
        assert_eq!(m(None, Some("142.250.74.14")), None);
    }
}
