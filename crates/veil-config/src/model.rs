use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single server the user can connect to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub id: Uuid,
    pub name: String,
    /// Subscription this profile came from, `None` for manually added ones.
    #[serde(default)]
    pub subscription_id: Option<Uuid>,
    pub server: ServerConfig,
    #[serde(default)]
    pub latency_ms: Option<u32>,
    /// Shown at the top of the list; survives subscription refreshes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pinned: bool,
}

impl Profile {
    pub fn new(name: impl Into<String>, server: ServerConfig) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            subscription_id: None,
            server,
            latency_ms: None,
            pinned: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub protocol: Protocol,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default)]
    pub security: Security,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Protocol {
    Vless {
        uuid: Uuid,
        #[serde(default)]
        flow: Option<String>,
    },
    Vmess {
        uuid: Uuid,
        #[serde(default)]
        alter_id: u16,
        #[serde(default = "default_vmess_cipher")]
        cipher: String,
    },
    Trojan {
        password: String,
    },
    Shadowsocks {
        method: String,
        password: String,
    },
    /// Hysteria 2 over QUIC; TLS settings come from `security`.
    Hysteria2 {
        auth: String,
        /// Salamander obfuscation password, if the server uses it.
        #[serde(default)]
        obfs_password: Option<String>,
    },
}

fn default_vmess_cipher() -> String {
    "auto".into()
}

impl Protocol {
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Vless { .. } => "vless",
            Protocol::Vmess { .. } => "vmess",
            Protocol::Trojan { .. } => "trojan",
            Protocol::Shadowsocks { .. } => "shadowsocks",
            Protocol::Hysteria2 { .. } => "hysteria2",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Tcp,
    Ws {
        #[serde(default)]
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    Grpc {
        service_name: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Security {
    #[default]
    None,
    Tls(TlsConfig),
    Reality(RealityConfig),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub insecure: bool,
    /// Hysteria 2 `pinSHA256`: lowercase hex SHA-256 digests (64 chars) of the server's leaf
    /// certificate (DER). When non-empty the certificate is accepted only if it matches one
    /// of them, and chain/name verification is replaced by this check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pin_sha256: Vec<String>,
}

/// Parses one certificate pin: 64 hex digits, case-insensitive, optionally separated by `:` or `-`.
pub fn parse_pin_sha256(s: &str) -> Option<[u8; 32]> {
    let digits: Vec<u8> = s.trim().bytes().filter(|b| !matches!(b, b':' | b'-')).collect();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Formats a pin the way `to_link` writes it: lowercase hex.
pub fn format_pin_sha256(pin: &[u8; 32]) -> String {
    pin.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RealityConfig {
    pub sni: String,
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub spider_x: Option<String>,
}

/// A remote list of profiles that is refreshed periodically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    /// Refresh interval in hours.
    #[serde(default = "default_update_interval")]
    pub update_interval_hours: u32,
    #[serde(default)]
    pub last_updated: Option<u64>,
    #[serde(default)]
    pub usage: Option<SubscriptionUsage>,
}

fn default_update_interval() -> u32 {
    12
}

/// Parsed `subscription-userinfo` header.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SubscriptionUsage {
    pub upload: u64,
    pub download: u64,
    pub total: u64,
    /// Unix timestamp, 0 when the subscription never expires.
    pub expire: u64,
}
