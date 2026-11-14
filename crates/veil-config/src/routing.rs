//! Routing rules in Xray-style notation, editable by the user.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteAction {
    Proxy,
    Direct,
    Block,
}

/// All non-empty conditions must match; entries inside one list are alternatives.
///
/// `domain` entries: `full:a.com`, `domain:a.com` (a.com and subdomains),
/// `keyword:abc`, `regexp:^a`, `geosite:<code>`, or a bare word (= keyword).
/// `ip` entries: CIDR (`10.0.0.0/8`), single address, `geoip:private` (built in)
/// or `geoip:<code>`. `geosite:`/`geoip:<code>` need the user's own geosite.dat /
/// geoip.dat in the data folder; Veil ships none.
/// `port` entries: `443` or `1000-2000`.
/// `process` entries: an app name (`Telegram`, `Google Chrome`), an executable
/// name (`curl`), or an absolute path prefix (`/Applications/Steam.app`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingRule {
    pub action: RouteAction,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process: Vec<String>,
}

impl RoutingRule {
    fn new(action: RouteAction) -> Self {
        Self { action, domain: Vec::new(), ip: Vec::new(), port: Vec::new(), process: Vec::new() }
    }

    pub fn domains(action: RouteAction, list: &[&str]) -> Self {
        Self { domain: list.iter().map(|s| s.to_string()).collect(), ..Self::new(action) }
    }

    pub fn processes(action: RouteAction, list: &[&str]) -> Self {
        Self { process: list.iter().map(|s| s.to_string()).collect(), ..Self::new(action) }
    }

    pub fn ips(action: RouteAction, list: &[&str]) -> Self {
        Self { ip: list.iter().map(|s| s.to_string()).collect(), ..Self::new(action) }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingConfig {
    pub rules: Vec<RoutingRule>,
    #[serde(rename = "final")]
    pub final_action: RouteAction,
}

/// The two base routing modes: where traffic goes when no user rule matches.
/// They are not geo presets: neither needs geoip.dat / geosite.dat. Anything
/// more specific is up to the user's own rules. A saved name that is not in
/// this list (older versions had more) falls back to `global`.
pub const PRESETS: &[(&str, &str)] = &[
    ("global", "Everything via VPN"),
    ("selected-only", "Only selected via VPN"),
];

impl RoutingConfig {
    /// Whether the rules need the user's own geoip.dat or geosite.dat.
    pub fn uses_geo_files(&self) -> bool {
        self.uses_geoip() || self.uses_geosite()
    }

    /// `geoip:` entries other than the built-in `geoip:private`. Prefixes are
    /// matched as the rule compiler matches them (lower case).
    pub fn uses_geoip(&self) -> bool {
        self.rules
            .iter()
            .any(|r| r.ip.iter().any(|i| i.starts_with("geoip:") && !i.eq_ignore_ascii_case("geoip:private")))
    }

    /// `geosite:` entries.
    pub fn uses_geosite(&self) -> bool {
        self.rules.iter().any(|r| r.domain.iter().any(|d| d.starts_with("geosite:")))
    }

    pub fn proxy_all() -> Self {
        Self { rules: Vec::new(), final_action: RouteAction::Proxy }
    }

    /// Rules of a base mode from [`PRESETS`]; `None` for any other name.
    pub fn preset(name: &str) -> Option<Self> {
        use RouteAction::*;
        match name {
            // Only the user's own "proxy" rules (checked before these) use the VPN.
            "selected-only" => Some(Self { rules: Vec::new(), final_action: Direct }),
            // Local names and private ranges go direct; `geoip:private` is built in.
            "global" => Some(Self {
                rules: vec![
                    RoutingRule::domains(Direct, &["full:localhost", "domain:local", "domain:lan"]),
                    RoutingRule::ips(Direct, &["geoip:private"]),
                ],
                final_action: Proxy,
            }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_base_modes_exist() {
        let names: Vec<&str> = PRESETS.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, ["global", "selected-only"]);
        for name in names {
            let cfg = RoutingConfig::preset(name).unwrap();
            assert!(!cfg.uses_geo_files(), "{name} must work without geo files");
        }
        for gone in ["ru-direct", "proxy-all", "", "GLOBAL"] {
            assert!(RoutingConfig::preset(gone).is_none(), "{gone}");
        }
    }

    #[test]
    fn geo_file_detection() {
        use RouteAction::*;
        let cfg = |rules| RoutingConfig { rules, final_action: Proxy };
        let plain = cfg(vec![
            RoutingRule::domains(Direct, &["domain:example.com", "keyword:geosite"]),
            RoutingRule::ips(Direct, &["geoip:private", "geoip:PRIVATE", "10.0.0.0/8"]),
        ]);
        assert!(!plain.uses_geo_files());
        let site = cfg(vec![RoutingRule::domains(Proxy, &["geosite:netflix"])]);
        assert!(site.uses_geosite() && !site.uses_geoip() && site.uses_geo_files());
        let ip = cfg(vec![RoutingRule::ips(Direct, &["geoip:de"])]);
        assert!(ip.uses_geoip() && !ip.uses_geosite() && ip.uses_geo_files());
    }
}
