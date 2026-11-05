//! Subscriptions that serve full Xray client configs (a JSON array, one config
//! per server), as Remnawave/Marzban do for Happ- and v2rayN-like clients.

use serde_json::Value;
use uuid::Uuid;

use crate::model::*;

/// Parsed profiles plus human-readable reasons for configs that were skipped.
pub struct Parsed {
    pub profiles: Vec<Profile>,
    pub skipped: Vec<String>,
}

pub fn looks_like_json(body: &str) -> bool {
    matches!(body.trim_start().as_bytes().first(), Some(b'[' | b'{'))
}

pub fn parse(body: &str) -> Option<Parsed> {
    let v: Value = serde_json::from_str(body.trim()).ok()?;
    let configs = match v {
        Value::Array(a) => a,
        obj @ Value::Object(_) => vec![obj],
        _ => return None,
    };
    let mut out = Parsed { profiles: Vec::new(), skipped: Vec::new() };
    for cfg in &configs {
        let name = cfg.get("remarks").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let outbounds = cfg.get("outbounds").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut candidates: Vec<&Value> = outbounds
            .iter()
            .filter(|o| !matches!(str_at(o, &["protocol"]), Some("freedom" | "blackhole" | "dns" | "loopback")))
            .collect();
        // Configs with a balancer list several servers. The balancer's fallback is
        // the one the provider guarantees (e.g. the whitelist-bypass server), so
        // try it first, then the rest in order.
        let fallbacks: Vec<&str> = cfg
            .pointer("/routing/balancers")
            .and_then(Value::as_array)
            .map(|bs| bs.iter().filter_map(|b| str_at(b, &["fallbackTag"])).collect())
            .unwrap_or_default();
        candidates.sort_by_key(|o| !str_at(o, &["tag"]).is_some_and(|t| fallbacks.contains(&t)));
        let mut reason = None;
        let server = candidates.iter().find_map(|o| match outbound(o) {
            Ok(s) => Some(s),
            Err(e) => {
                reason.get_or_insert(e);
                None
            }
        });
        match server {
            Some(server) => {
                let name = if name.is_empty() { format!("{}:{}", server.address, server.port) } else { name };
                out.profiles.push(Profile::new(name, server));
            }
            None => out.skipped.push(format!(
                "{}: {}",
                if name.is_empty() { "unnamed" } else { &name },
                reason.unwrap_or_else(|| "no proxy server".into())
            )),
        }
    }
    Some(out)
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(k))?.as_str()
}

fn port_of(v: &Value) -> Option<u16> {
    match v.get("port")? {
        Value::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Server entry: `settings.vnext[0]` / `settings.servers[0]`, or flat `settings` (Xray 25+).
fn endpoint(settings: &Value) -> Option<(&Value, &Value)> {
    for list in ["vnext", "servers"] {
        if let Some(server) = settings.get(list).and_then(|l| l.get(0)) {
            let user = server.get("users").and_then(|u| u.get(0)).unwrap_or(server);
            return Some((server, user));
        }
    }
    settings.get("address").map(|_| (settings, settings))
}

fn outbound(o: &Value) -> Result<ServerConfig, String> {
    let protocol = str_at(o, &["protocol"]).unwrap_or("");
    let settings = o.get("settings").cloned().unwrap_or(Value::Null);
    let (server, user) = endpoint(&settings).ok_or("no server address")?;
    let address = str_at(server, &["address"]).ok_or("no server address")?.to_string();
    let port = port_of(server).ok_or("no port")?;
    let uuid = || {
        str_at(user, &["id"])
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or_else(|| "invalid id".to_string())
    };
    let protocol = match protocol {
        "vless" => Protocol::Vless {
            uuid: uuid()?,
            flow: str_at(user, &["flow"]).filter(|f| !f.is_empty()).map(str::to_string),
        },
        "vmess" => Protocol::Vmess {
            uuid: uuid()?,
            alter_id: user.get("alterId").and_then(Value::as_u64).unwrap_or(0) as u16,
            cipher: str_at(user, &["security"]).unwrap_or("auto").to_string(),
        },
        "trojan" => Protocol::Trojan {
            password: str_at(user, &["password"]).ok_or("no password")?.to_string(),
        },
        "shadowsocks" => Protocol::Shadowsocks {
            method: str_at(user, &["method"]).ok_or("no cipher")?.to_ascii_lowercase(),
            password: str_at(user, &["password"]).ok_or("no password")?.to_string(),
        },
        "hysteria" => {
            let stream = o.get("streamSettings").cloned().unwrap_or(Value::Null);
            let version = settings.get("version").or(stream.pointer("/hysteriaSettings/version")).and_then(Value::as_u64);
            if version.is_some_and(|v| v != 2) {
                return Err("only Hysteria version 2 is supported".into());
            }
            // Obfuscation (e.g. salamander) is declared as UDP masks in the stream
            // settings. The client cannot do it, so skip instead of importing a
            // profile that would silently connect without obfs.
            let masked = |k: &str| match stream.get(k) {
                None | Some(Value::Null) => false,
                Some(Value::Array(a)) => !a.is_empty(),
                Some(Value::Object(m)) => !m.is_empty(),
                Some(Value::String(s)) => !s.is_empty(),
                Some(_) => true,
            };
            if masked("finalmask") || masked("udpmasks") {
                return Err("hysteria2 obfuscation (finalmask) is not supported yet".into());
            }
            let auth = str_at(&stream, &["hysteriaSettings", "auth"])
                .or(str_at(user, &["password"]))
                .ok_or("hysteria without auth")?
                .to_string();
            let t = stream.get("tlsSettings").cloned().unwrap_or(Value::Null);
            return Ok(ServerConfig {
                address,
                port,
                protocol: Protocol::Hysteria2 { auth, obfs_password: None },
                transport: Transport::Tcp,
                security: Security::Tls(TlsConfig {
                    sni: str_at(&t, &["serverName"]).filter(|s| !s.is_empty()).map(str::to_string),
                    alpn: vec!["h3".into()],
                    fingerprint: None,
                    insecure: t.get("allowInsecure").and_then(Value::as_bool).unwrap_or(false),
                    pin_sha256: Vec::new(),
                }),
            });
        }
        other => return Err(format!("protocol {other} is not supported")),
    };

    let stream = o.get("streamSettings").cloned().unwrap_or(Value::Null);
    let transport = match str_at(&stream, &["network"]).unwrap_or("tcp") {
        "tcp" | "raw" => {
            let header = str_at(&stream, &["tcpSettings", "header", "type"])
                .or(str_at(&stream, &["rawSettings", "header", "type"]))
                .unwrap_or("none");
            if header != "none" {
                return Err(format!("TCP with {header} header is not supported"));
            }
            Transport::Tcp
        }
        "ws" => {
            let ws = stream.get("wsSettings").cloned().unwrap_or(Value::Null);
            Transport::Ws {
                path: str_at(&ws, &["path"]).unwrap_or("/").to_string(),
                host: str_at(&ws, &["host"])
                    .or(str_at(&ws, &["headers", "Host"]))
                    .filter(|h| !h.is_empty())
                    .map(str::to_string),
            }
        }
        "grpc" => Transport::Grpc {
            service_name: str_at(&stream, &["grpcSettings", "serviceName"]).unwrap_or("").to_string(),
        },
        other => return Err(format!("transport {other} is not supported")),
    };

    let security = match str_at(&stream, &["security"]).unwrap_or("none") {
        "none" | "" => Security::None,
        "tls" => {
            let t = stream.get("tlsSettings").cloned().unwrap_or(Value::Null);
            Security::Tls(TlsConfig {
                sni: str_at(&t, &["serverName"]).filter(|s| !s.is_empty()).map(str::to_string),
                alpn: t
                    .get("alpn")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
                    .unwrap_or_default(),
                fingerprint: str_at(&t, &["fingerprint"]).map(str::to_string),
                insecure: t.get("allowInsecure").and_then(Value::as_bool).unwrap_or(false),
                pin_sha256: Vec::new(),
            })
        }
        "reality" => {
            let r = stream.get("realitySettings").cloned().unwrap_or(Value::Null);
            Security::Reality(RealityConfig {
                sni: str_at(&r, &["serverName"]).ok_or("REALITY without serverName")?.to_string(),
                // Newer Xray calls the public key "password".
                public_key: str_at(&r, &["publicKey"])
                    .or(str_at(&r, &["password"]))
                    .ok_or("REALITY without publicKey")?
                    .to_string(),
                short_id: str_at(&r, &["shortId"]).unwrap_or("").to_string(),
                fingerprint: str_at(&r, &["fingerprint"]).map(str::to_string),
                spider_x: str_at(&r, &["spiderX"]).map(str::to_string),
            })
        }
        other => return Err(format!("security {other} is not supported")),
    };

    Ok(ServerConfig { address, port, protocol, transport, security })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"[
      {"remarks": "🇫🇷 France", "outbounds": [
        {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "fr.example.com", "port": 8443,
          "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
         "streamSettings": {"network": "tcp", "tcpSettings": {}, "security": "reality",
          "realitySettings": {"serverName": "www.microsoft.com", "publicKey": "PUB", "shortId": "ab", "fingerprint": "firefox"}}},
        {"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]},
      {"remarks": "Gaming", "outbounds": [{"tag": "proxy", "protocol": "hysteria",
        "settings": {"address": "g.example.com", "port": 443, "version": 2},
        "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": "secret"},
          "security": "tls", "tlsSettings": {"serverName": "g.example.com", "alpn": ["h3"]}}}]},
      {"remarks": "Whitelist", "routing": {"balancers": [{"tag": "WL", "fallbackTag": "b"}]}, "outbounds": [
        {"tag": "decoy", "protocol": "vless", "settings": {"vnext": [{"address": "decoy.example.com", "port": 443,
          "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}, "streamSettings": {"network": "tcp"}},
        {"tag": "a", "protocol": "vless", "settings": {"vnext": [{"address": "x.example.com", "port": 443,
          "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811"}]}]}, "streamSettings": {"network": "xhttp", "security": "tls"}},
        {"tag": "b", "protocol": "vless", "settings": {"vnext": [{"address": "w.example.com", "port": "443",
          "users": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": ""}]}]},
         "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "w.example.com", "alpn": ["http/1.1"]},
          "wsSettings": {"path": "/ws", "headers": {"Host": "cdn.example.com"}}}}]},
      {"remarks": "SS", "outbounds": [{"protocol": "shadowsocks",
        "settings": {"servers": [{"address": "1.2.3.4", "port": 8388, "method": "chacha20-ietf-poly1305", "password": "pw"}]}}]}
    ]"#;

    #[test]
    fn parses_xray_configs() {
        let p = parse(SAMPLE).unwrap();
        let names: Vec<_> = p.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["🇫🇷 France", "Gaming", "Whitelist", "SS"]);
        assert!(p.skipped.is_empty(), "{:?}", p.skipped);
        assert!(matches!(&p.profiles[1].server.protocol, Protocol::Hysteria2 { auth, .. } if auth == "secret"));

        let fr = &p.profiles[0].server;
        assert_eq!((fr.address.as_str(), fr.port), ("fr.example.com", 8443));
        assert!(matches!(&fr.protocol, Protocol::Vless { flow: Some(f), .. } if f == "xtls-rprx-vision"));
        let Security::Reality(r) = &fr.security else { panic!() };
        assert_eq!((r.sni.as_str(), r.public_key.as_str(), r.short_id.as_str()), ("www.microsoft.com", "PUB", "ab"));

        // Balancer config: its fallback (the WebSocket server) wins over the decoy.
        let wl = &p.profiles[2].server;
        assert_eq!(wl.address, "w.example.com");
        assert_eq!(wl.port, 443);
        assert_eq!(wl.transport, Transport::Ws { path: "/ws".into(), host: Some("cdn.example.com".into()) });
        assert!(matches!(&wl.protocol, Protocol::Vless { flow: None, .. }));

        assert!(matches!(&p.profiles[3].server.protocol, Protocol::Shadowsocks { method, .. } if method == "chacha20-ietf-poly1305"));
    }

    #[test]
    fn hysteria_with_finalmask_is_skipped() {
        let make = |extra: &str| {
            format!(
                r#"{{"remarks": "Hy", "outbounds": [{{"protocol": "hysteria",
                  "settings": {{"address": "g.example.com", "port": 443, "version": 2}},
                  "streamSettings": {{"network": "hysteria", "hysteriaSettings": {{"version": 2, "auth": "secret"}},
                    "security": "tls", "tlsSettings": {{"serverName": "g.example.com"}}{extra}}}}}]}}"#
            )
        };
        let plain = parse(&make("")).unwrap();
        assert_eq!(plain.profiles.len(), 1);
        assert!(plain.skipped.is_empty(), "{:?}", plain.skipped);

        let masked = parse(&make(r#", "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "pw"}}]}"#)).unwrap();
        assert!(masked.profiles.is_empty());
        assert_eq!(masked.skipped.len(), 1);
        assert!(masked.skipped[0].contains("obfuscation"), "{:?}", masked.skipped);

        let empty = parse(&make(r#", "finalmask": {}"#)).unwrap();
        assert_eq!(empty.profiles.len(), 1);
    }

    #[test]
    fn non_json_is_rejected() {
        assert!(!looks_like_json("dmxlc3M6Ly8="));
        assert!(parse("not json").is_none());
    }
}
