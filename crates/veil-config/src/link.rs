//! Parsing and generation of share links: `vless://`, `vmess://`, `trojan://`, `ss://`.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::model::*;

#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("unsupported scheme: {0}")]
    UnsupportedScheme(String),
    #[error("invalid link: {0}")]
    Invalid(String),
}

fn invalid(msg: impl Into<String>) -> LinkError {
    LinkError::Invalid(msg.into())
}

/// Decodes base64 in any of the common flavours (standard/url-safe, padded or not).
pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| engine.decode(&cleaned).ok())
}

fn decode_base64_str(input: &str) -> Option<String> {
    decode_base64(input).and_then(|b| String::from_utf8(b).ok())
}

fn pct_decode(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn pct_encode(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Parses every recognised link in a newline-separated list, skipping junk lines.
pub fn parse_links(text: &str) -> Vec<Profile> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| match parse_link(l) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::debug!("skipping link: {e}");
                None
            }
        })
        .collect()
}

pub fn parse_link(link: &str) -> Result<Profile, LinkError> {
    let link = link.trim();
    let scheme = link.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    match scheme.as_deref() {
        Some("vless") => parse_vless(link),
        Some("vmess") => parse_vmess(link),
        Some("trojan") => parse_trojan(link),
        Some("ss") => parse_ss(link),
        Some("hysteria2" | "hy2") => parse_hysteria2(link),
        Some(other) => Err(LinkError::UnsupportedScheme(other.to_string())),
        None => Err(invalid("missing scheme")),
    }
}

struct UrlParts {
    user: String,
    host: String,
    port: u16,
    query: HashMap<String, String>,
    name: String,
}

fn split_url(link: &str) -> Result<UrlParts, LinkError> {
    let url = Url::parse(link).map_err(|e| invalid(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| invalid("missing host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let host = pct_decode(&host);
    let port = url.port().ok_or_else(|| invalid("missing port"))?;
    let query = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let name = url.fragment().map(pct_decode).unwrap_or_default();
    Ok(UrlParts {
        user: pct_decode(url.username()),
        host,
        port,
        query,
        name,
    })
}

fn non_empty(q: &HashMap<String, String>, key: &str) -> Option<String> {
    q.get(key).filter(|v| !v.is_empty()).cloned()
}

fn transport_from_query(q: &HashMap<String, String>) -> Result<Transport, LinkError> {
    match q.get("type").map(String::as_str).unwrap_or("tcp") {
        "tcp" | "raw" | "" => Ok(Transport::Tcp),
        "ws" => Ok(Transport::Ws {
            path: q.get("path").cloned().unwrap_or_else(|| "/".into()),
            host: non_empty(q, "host"),
        }),
        "grpc" => Ok(Transport::Grpc {
            service_name: q.get("serviceName").cloned().unwrap_or_default(),
        }),
        other => Err(invalid(format!("unsupported transport: {other}"))),
    }
}

fn security_from_query(
    q: &HashMap<String, String>,
    default: &str,
) -> Result<Security, LinkError> {
    let alpn = q
        .get("alpn")
        .map(|a| a.split(',').map(str::to_string).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    match q.get("security").map(String::as_str).unwrap_or(default) {
        "none" | "" => Ok(Security::None),
        "tls" | "xtls" => Ok(Security::Tls(TlsConfig {
            sni: non_empty(q, "sni").or_else(|| non_empty(q, "peer")),
            alpn,
            fingerprint: non_empty(q, "fp"),
            insecure: matches!(
                q.get("allowInsecure").or(q.get("insecure")).map(String::as_str),
                Some("1" | "true")
            ),
            pin_sha256: Vec::new(),
        })),
        "reality" => Ok(Security::Reality(RealityConfig {
            sni: non_empty(q, "sni").ok_or_else(|| invalid("reality requires sni"))?,
            public_key: non_empty(q, "pbk").ok_or_else(|| invalid("reality requires pbk"))?,
            short_id: q.get("sid").cloned().unwrap_or_default(),
            fingerprint: non_empty(q, "fp"),
            spider_x: non_empty(q, "spx"),
        })),
        other => Err(invalid(format!("unsupported security: {other}"))),
    }
}

fn parse_vless(link: &str) -> Result<Profile, LinkError> {
    let p = split_url(link)?;
    let uuid = Uuid::parse_str(&p.user).map_err(|_| invalid("bad uuid"))?;
    let server = ServerConfig {
        address: p.host,
        port: p.port,
        protocol: Protocol::Vless {
            uuid,
            flow: non_empty(&p.query, "flow"),
        },
        transport: transport_from_query(&p.query)?,
        security: security_from_query(&p.query, "none")?,
    };
    Ok(Profile::new(display_name(p.name, &server), server))
}

fn parse_trojan(link: &str) -> Result<Profile, LinkError> {
    let p = split_url(link)?;
    if p.user.is_empty() {
        return Err(invalid("missing password"));
    }
    let server = ServerConfig {
        address: p.host,
        port: p.port,
        protocol: Protocol::Trojan { password: p.user },
        transport: transport_from_query(&p.query)?,
        security: security_from_query(&p.query, "tls")?,
    };
    Ok(Profile::new(display_name(p.name, &server), server))
}

/// hysteria2://auth@host:port/?sni=..&insecure=1&obfs=salamander&obfs-password=..#name
fn parse_hysteria2(link: &str) -> Result<Profile, LinkError> {
    // `url` only treats special schemes' authorities nicely; normalise the scheme.
    let normalized = format!("hysteria2://{}", link.split_once("://").map_or("", |(_, r)| r));
    let url = Url::parse(&normalized).map_err(|e| invalid(e.to_string()))?;
    let mut auth = pct_decode(url.username());
    if let Some(pw) = url.password() {
        auth = format!("{auth}:{}", pct_decode(pw));
    }
    if auth.is_empty() {
        return Err(invalid("missing auth"));
    }
    let p = split_url(&normalized)?;
    let q = &p.query;
    // Certificate pin(s): one value in the official format, a `,`/`;` list is tolerated. A
    // malformed pin must fail the import: dropping it would silently leave the link unpinned.
    let mut pin_sha256 = Vec::new();
    if let Some(raw) = q.get("pinSHA256").or_else(|| q.get("pinsha256")).filter(|v| !v.is_empty()) {
        for part in raw.split([',', ';']).map(str::trim).filter(|p| !p.is_empty()) {
            let pin = parse_pin_sha256(part).ok_or_else(|| invalid("pinSHA256 must be 64 hex digits (SHA-256 of the certificate)"))?;
            pin_sha256.push(format_pin_sha256(&pin));
        }
        if pin_sha256.is_empty() {
            return Err(invalid("pinSHA256 is empty"));
        }
    }
    let obfs_password = match q.get("obfs").map(String::as_str) {
        None | Some("" | "none") => None,
        Some("salamander") => {
            if non_empty(q, "obfs-password").is_none() {
                return Err(invalid("salamander obfs requires obfs-password"));
            }
            // HysteriaClient::new rejects any obfuscation (Unsupported) for now.
            return Err(invalid("salamander obfs is not supported yet"));
        }
        Some(other) => return Err(invalid(format!("unsupported obfs {other}"))),
    };
    let server = ServerConfig {
        address: p.host,
        port: p.port,
        protocol: Protocol::Hysteria2 { auth, obfs_password },
        transport: Transport::Tcp,
        security: Security::Tls(TlsConfig {
            sni: non_empty(q, "sni"),
            alpn: vec!["h3".into()],
            fingerprint: None,
            insecure: matches!(q.get("insecure").map(String::as_str), Some("1" | "true")),
            pin_sha256,
        }),
    };
    Ok(Profile::new(display_name(p.name, &server), server))
}

fn parse_ss(link: &str) -> Result<Profile, LinkError> {
    let body = &link["ss://".len()..];
    let (body, name) = match body.split_once('#') {
        Some((b, n)) => (b, pct_decode(n)),
        None => (body, String::new()),
    };
    let body = body.split_once('?').map_or(body, |(b, _)| b).trim_end_matches('/');

    // SIP002: ss://userinfo@host:port, userinfo is base64 or percent-encoded "method:password".
    // Legacy: ss://base64(method:password@host:port).
    let full = if body.contains('@') {
        body.to_string()
    } else {
        decode_base64_str(body).ok_or_else(|| invalid("bad legacy ss link"))?
    };
    let (userinfo, hostport) = full.rsplit_once('@').ok_or_else(|| invalid("missing @"))?;
    let creds = if userinfo.contains(':') {
        pct_decode(userinfo)
    } else {
        decode_base64_str(&pct_decode(userinfo)).ok_or_else(|| invalid("bad ss userinfo"))?
    };
    let (method, password) = creds
        .split_once(':')
        .ok_or_else(|| invalid("ss userinfo must be method:password"))?;
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| invalid("missing port"))?;
    let port = port.parse().map_err(|_| invalid("bad port"))?;
    let server = ServerConfig {
        address: host.trim_start_matches('[').trim_end_matches(']').to_string(),
        port,
        protocol: Protocol::Shadowsocks {
            method: method.to_ascii_lowercase(),
            password: password.to_string(),
        },
        transport: Transport::Tcp,
        security: Security::None,
    };
    Ok(Profile::new(display_name(name, &server), server))
}

fn json_str(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse_vmess(link: &str) -> Result<Profile, LinkError> {
    let body = &link["vmess://".len()..];
    let body = body.split_once('#').map_or(body, |(b, _)| b);
    let text = decode_base64_str(body).ok_or_else(|| invalid("vmess payload is not base64"))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| invalid(e.to_string()))?;

    let address = json_str(&v, "add").ok_or_else(|| invalid("missing add"))?;
    let port = json_str(&v, "port")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| invalid("bad port"))?;
    let uuid = json_str(&v, "id")
        .and_then(|id| Uuid::parse_str(&id).ok())
        .ok_or_else(|| invalid("bad id"))?;
    let alter_id = json_str(&v, "aid").and_then(|a| a.parse().ok()).unwrap_or(0);
    let cipher = json_str(&v, "scy").unwrap_or_else(|| "auto".into());

    let mut q = HashMap::new();
    q.insert("type".into(), json_str(&v, "net").unwrap_or_else(|| "tcp".into()));
    for (from, to) in [("path", "path"), ("host", "host"), ("sni", "sni"), ("alpn", "alpn"), ("fp", "fp")] {
        if let Some(val) = json_str(&v, from) {
            q.insert(to.into(), val);
        }
    }
    if q["type"] == "grpc" {
        q.insert("serviceName".into(), json_str(&v, "path").unwrap_or_default());
    }
    q.insert("security".into(), json_str(&v, "tls").unwrap_or_else(|| "none".into()));
    if let Security::Tls(_) = security_from_query(&q, "none")? {
        // v2rayN puts the TLS server name into "host" when "sni" is missing.
        if !q.contains_key("sni")
            && let Some(h) = q.get("host").cloned() {
                q.insert("sni".into(), h);
            }
    }

    let server = ServerConfig {
        address,
        port,
        protocol: Protocol::Vmess { uuid, alter_id, cipher },
        transport: transport_from_query(&q)?,
        security: security_from_query(&q, "none")?,
    };
    Ok(Profile::new(display_name(json_str(&v, "ps").unwrap_or_default(), &server), server))
}

fn display_name(name: String, server: &ServerConfig) -> String {
    if name.is_empty() {
        format!("{}:{}", server.address, server.port)
    } else {
        name
    }
}

fn host_for_url(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn common_query(server: &ServerConfig) -> Vec<(String, String)> {
    let mut q: Vec<(String, String)> = Vec::new();
    match &server.transport {
        Transport::Tcp => q.push(("type".into(), "tcp".into())),
        Transport::Ws { path, host } => {
            q.push(("type".into(), "ws".into()));
            q.push(("path".into(), path.clone()));
            if let Some(h) = host {
                q.push(("host".into(), h.clone()));
            }
        }
        Transport::Grpc { service_name } => {
            q.push(("type".into(), "grpc".into()));
            q.push(("serviceName".into(), service_name.clone()));
        }
    }
    match &server.security {
        Security::None => q.push(("security".into(), "none".into())),
        Security::Tls(t) => {
            q.push(("security".into(), "tls".into()));
            if let Some(s) = &t.sni {
                q.push(("sni".into(), s.clone()));
            }
            if !t.alpn.is_empty() {
                q.push(("alpn".into(), t.alpn.join(",")));
            }
            if let Some(fp) = &t.fingerprint {
                q.push(("fp".into(), fp.clone()));
            }
            if t.insecure {
                q.push(("allowInsecure".into(), "1".into()));
            }
        }
        Security::Reality(r) => {
            q.push(("security".into(), "reality".into()));
            q.push(("sni".into(), r.sni.clone()));
            q.push(("pbk".into(), r.public_key.clone()));
            q.push(("sid".into(), r.short_id.clone()));
            if let Some(fp) = &r.fingerprint {
                q.push(("fp".into(), fp.clone()));
            }
            if let Some(spx) = &r.spider_x {
                q.push(("spx".into(), spx.clone()));
            }
        }
    }
    q
}

fn encode_query(q: &[(String, String)]) -> String {
    q.iter()
        .map(|(k, v)| format!("{k}={}", pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Serialises a profile back into a share link.
pub fn to_link(profile: &Profile) -> String {
    let s = &profile.server;
    let host = host_for_url(&s.address);
    let name = pct_encode(&profile.name);
    match &s.protocol {
        Protocol::Hysteria2 { auth, obfs_password } => {
            let mut q = Vec::new();
            if let Security::Tls(t) = &s.security {
                if let Some(sni) = &t.sni {
                    q.push(("sni".to_string(), sni.clone()));
                }
                if t.insecure {
                    q.push(("insecure".to_string(), "1".to_string()));
                }
                if !t.pin_sha256.is_empty() {
                    q.push(("pinSHA256".to_string(), t.pin_sha256.join(",")));
                }
            }
            if let Some(pw) = obfs_password {
                q.push(("obfs".to_string(), "salamander".to_string()));
                q.push(("obfs-password".to_string(), pw.clone()));
            }
            format!("hysteria2://{}@{host}:{}/?{}#{name}", pct_encode(auth), s.port, encode_query(&q))
        }
        Protocol::Vless { uuid, flow } => {
            let mut q = common_query(s);
            q.insert(0, ("encryption".into(), "none".into()));
            if let Some(f) = flow {
                q.push(("flow".into(), f.clone()));
            }
            format!("vless://{uuid}@{host}:{}?{}#{name}", s.port, encode_query(&q))
        }
        Protocol::Trojan { password } => format!(
            "trojan://{}@{host}:{}?{}#{name}",
            pct_encode(password),
            s.port,
            encode_query(&common_query(s))
        ),
        Protocol::Shadowsocks { method, password } => {
            let userinfo = URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
            format!("ss://{userinfo}@{host}:{}#{name}", s.port)
        }
        Protocol::Vmess { uuid, alter_id, cipher } => {
            let (net, path, ws_host) = match &s.transport {
                Transport::Tcp => ("tcp", String::new(), String::new()),
                Transport::Ws { path, host } => ("ws", path.clone(), host.clone().unwrap_or_default()),
                Transport::Grpc { service_name } => ("grpc", service_name.clone(), String::new()),
            };
            let (tls, sni, alpn, fp) = match &s.security {
                Security::Tls(t) => (
                    "tls",
                    t.sni.clone().unwrap_or_default(),
                    t.alpn.join(","),
                    t.fingerprint.clone().unwrap_or_default(),
                ),
                _ => ("", String::new(), String::new(), String::new()),
            };
            let v = json!({
                "v": "2", "ps": profile.name, "add": s.address, "port": s.port.to_string(),
                "id": uuid.to_string(), "aid": alter_id.to_string(), "scy": cipher,
                "net": net, "type": "none", "host": ws_host, "path": path,
                "tls": tls, "sni": sni, "alpn": alpn, "fp": fp,
            });
            format!("vmess://{}", STANDARD.encode(v.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn vless_reality_vision() {
        let link = format!(
            "vless://{UUID}@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality\
             &sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc\
             &sid=6ba85179e30d4fc2&type=tcp#%F0%9F%87%B3%F0%9F%87%B1%20NL"
        );
        let p = parse_link(&link).unwrap();
        assert_eq!(p.name, "🇳🇱 NL");
        assert_eq!(p.server.address, "example.com");
        assert_eq!(p.server.port, 443);
        assert!(matches!(&p.server.protocol, Protocol::Vless { flow: Some(f), .. } if f == "xtls-rprx-vision"));
        let Security::Reality(r) = &p.server.security else { panic!() };
        assert_eq!(r.sni, "www.microsoft.com");
        assert_eq!(r.short_id, "6ba85179e30d4fc2");
        assert_eq!(r.fingerprint.as_deref(), Some("chrome"));
    }

    #[test]
    fn vless_ws_tls_ipv6() {
        let link = format!("vless://{UUID}@[2001:db8::1]:8443?type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com&security=tls&sni=cdn.example.com&alpn=h2,http/1.1");
        let p = parse_link(&link).unwrap();
        assert_eq!(p.server.address, "2001:db8::1");
        assert_eq!(
            p.server.transport,
            Transport::Ws { path: "/ws?ed=2048".into(), host: Some("cdn.example.com".into()) }
        );
        let Security::Tls(t) = &p.server.security else { panic!() };
        assert_eq!(t.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(p.name, "2001:db8::1:8443");
    }

    #[test]
    fn trojan_defaults_to_tls() {
        let p = parse_link("trojan://p%40ss@t.example.org:443?sni=t.example.org#Trojan").unwrap();
        assert_eq!(p.server.protocol, Protocol::Trojan { password: "p@ss".into() });
        assert!(matches!(p.server.security, Security::Tls(_)));
    }

    #[test]
    fn ss_sip002_base64() {
        // base64("chacha20-ietf-poly1305:secret")
        let p = parse_link("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@1.2.3.4:8388/?plugin=#SS").unwrap();
        assert_eq!(
            p.server.protocol,
            Protocol::Shadowsocks { method: "chacha20-ietf-poly1305".into(), password: "secret".into() }
        );
        assert_eq!(p.server.port, 8388);
        assert_eq!(p.name, "SS");
    }

    #[test]
    fn ss_2022_plain_userinfo() {
        let p = parse_link("ss://2022-blake3-aes-128-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%3D%3D@1.2.3.4:443#x").unwrap();
        assert_eq!(
            p.server.protocol,
            Protocol::Shadowsocks { method: "2022-blake3-aes-128-gcm".into(), password: "YctPZ6U7xPPcU+gp3u+0tx==".into() }
        );
    }

    #[test]
    fn ss_legacy() {
        // base64("aes-256-gcm:pw@5.6.7.8:1234")
        let link = format!("ss://{}#old", STANDARD.encode("aes-256-gcm:pw@5.6.7.8:1234"));
        let p = parse_link(&link).unwrap();
        assert_eq!(p.server.address, "5.6.7.8");
        assert_eq!(p.server.port, 1234);
    }

    #[test]
    fn vmess_v2rayn_json() {
        let json = format!(
            r#"{{"v":"2","ps":"VM","add":"v.example.com","port":443,"id":"{UUID}","aid":"0","scy":"auto","net":"ws","type":"none","host":"v.example.com","path":"/vm","tls":"tls","sni":""}}"#
        );
        let p = parse_link(&format!("vmess://{}", STANDARD.encode(json))).unwrap();
        assert_eq!(p.name, "VM");
        assert_eq!(p.server.port, 443);
        let Security::Tls(t) = &p.server.security else { panic!() };
        assert_eq!(t.sni.as_deref(), Some("v.example.com"));
        assert!(matches!(&p.server.transport, Transport::Ws { path, .. } if path == "/vm"));
    }

    #[test]
    fn roundtrip() {
        let links = [
            format!("vless://{UUID}@example.com:443?flow=xtls-rprx-vision&security=reality&sni=a.com&pbk=KEY&sid=ab&fp=chrome#n"),
            format!("vless://{UUID}@[::1]:80?type=ws&path=%2F&security=none#n"),
            "trojan://pw@t.org:443?type=grpc&serviceName=svc#n".to_string(),
            "ss://2022-blake3-aes-128-gcm:a%2Bb%3D@1.2.3.4:443#n".to_string(),
        ];
        for link in links {
            let p = parse_link(&link).unwrap();
            let again = parse_link(&to_link(&p)).unwrap();
            assert_eq!(p.server, again.server, "{link}");
            assert_eq!(p.name, again.name);
        }
        let vm = format!("vmess://{}", STANDARD.encode(format!(r#"{{"add":"h","port":"1","id":"{UUID}","net":"tcp","ps":"z"}}"#)));
        let p = parse_link(&vm).unwrap();
        assert_eq!(parse_link(&to_link(&p)).unwrap().server, p.server);
    }

    #[test]
    fn hysteria2() {
        let p = parse_link("hysteria2://letmein@hy.example.com:8449/?sni=real.example.com&insecure=1#Gaming").unwrap();
        assert_eq!(p.name, "Gaming");
        assert_eq!(p.server.protocol, Protocol::Hysteria2 { auth: "letmein".into(), obfs_password: None });
        let Security::Tls(t) = &p.server.security else { panic!() };
        assert_eq!((t.sni.as_deref(), t.insecure), (Some("real.example.com"), true));
        let p2 = parse_link("hy2://user:pass@1.2.3.4:443?sni=x.example").unwrap();
        assert_eq!(p2.server.protocol, Protocol::Hysteria2 { auth: "user:pass".into(), obfs_password: None });
        // Unsupported features must be rejected at import, not silently dropped.
        assert!(parse_link("hy2://user:pass@1.2.3.4:443?obfs=salamander&obfs-password=x").is_err());
        assert!(parse_link("hy2://user:pass@1.2.3.4:443?obfs=salamander").is_err());
        // Certificate pin: accepted in any case / separator style, normalised, round-trips.
        let hex = "0123456789ABCDEF".repeat(4);
        let want = hex.to_lowercase();
        let colon = hex.as_bytes().chunks(2).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join(":");
        for form in [hex.clone(), colon.clone(), colon.replace(':', "-"), want.clone()] {
            let pp = parse_link(&format!("hy2://u@1.2.3.4:443?insecure=1&pinSHA256={form}")).unwrap();
            let Security::Tls(t) = &pp.server.security else { panic!() };
            assert_eq!(t.pin_sha256, vec![want.clone()], "{form}");
            assert_eq!(parse_link(&to_link(&pp)).unwrap().server, pp.server);
        }
        let two = parse_link(&format!("hy2://u@1.2.3.4:443?pinSHA256={colon},{}", "ab".repeat(32))).unwrap();
        let Security::Tls(t) = &two.server.security else { panic!() };
        assert_eq!(t.pin_sha256.len(), 2);
        assert_eq!(parse_link(&to_link(&two)).unwrap().server, two.server);
        // Invalid pins must fail the import, never be dropped.
        assert!(parse_link("hy2://user:pass@1.2.3.4:443?insecure=1&pinSHA256=AA:BB").is_err());
        assert!(parse_link(&format!("hy2://u@1.2.3.4:443?pinSHA256={}zz", "a".repeat(62))).is_err());
        assert!(parse_link(&format!("hy2://u@1.2.3.4:443?pinSHA256={},bad", "a".repeat(64))).is_err());
        assert_eq!(parse_link("hy2://u@a%2Eb:443").unwrap().server.address, "a.b");
        assert_eq!(parse_link(&to_link(&p)).unwrap().server, p.server);
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(parse_link("http://x"), Err(LinkError::UnsupportedScheme(_))));
        assert!(parse_link("vless://not-a-uuid@h:1").is_err());
        assert!(parse_link("vless://foo").is_err());
        assert_eq!(parse_links("junk\n\n# c\ntrojan://a@b:1\n").len(), 1);
    }
}
