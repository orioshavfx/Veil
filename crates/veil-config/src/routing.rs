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
/// `keyword:abc`, `regexp:^a`, `geosite:category-ru`, or a bare word (= keyword).
/// `ip` entries: CIDR (`10.0.0.0/8`), single address, or `geoip:ru`.
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

/// Presets offered in the UI. `ru-direct` and `proxy-all` still work when set
/// from the CLI or an old config, but are not offered any more.
pub const PRESETS: &[(&str, &str)] = &[
    ("global", "Everything via VPN"),
    ("selected-only", "Only selected via VPN"),
];

impl RoutingConfig {
    /// Whether the rules reference geoip.dat / geosite.dat.
    pub fn uses_geo_files(&self) -> bool {
        self.rules.iter().any(|r| {
            r.domain.iter().any(|d| d.starts_with("geosite:"))
                || r.ip.iter().any(|i| i.starts_with("geoip:") && !i.eq_ignore_ascii_case("geoip:private"))
        })
    }

    pub fn proxy_all() -> Self {
        Self { rules: Vec::new(), final_action: RouteAction::Proxy }
    }

    pub fn preset(name: &str) -> Option<Self> {
        use RouteAction::*;
        let lan = RoutingRule::ips(Direct, &["geoip:private"]);
        let local_names = RoutingRule::domains(Direct, &["full:localhost", "domain:local", "domain:lan"]);
        match name {
            "proxy-all" => Some(Self::proxy_all()),
            // Only the user's own "proxy" rules (checked before the preset) use the VPN.
            "selected-only" => Some(Self { rules: Vec::new(), final_action: Direct }),
            "global" => Some(Self { rules: vec![local_names, lan], final_action: Proxy }),
            "ru-direct" => Some(Self {
                rules: vec![
                    local_names,
                    RoutingRule::domains(
                        Direct,
                        &["domain:ru", "domain:su", "domain:xn--p1ai", "geosite:category-ru"],
                    ),
                    lan,
                    RoutingRule::ips(Direct, &["geoip:ru"]),
                ],
                final_action: Proxy,
            }),
            _ => None,
        }
    }
}
