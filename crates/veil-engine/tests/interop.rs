//! Interoperability with a real Xray server. Skipped when `xray` is not on PATH.
//!
//! Run with `cargo test -p veil-engine --test interop -- --nocapture`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use veil_config::{Profile, parse_link};
use veil_engine::{Engine, EngineConfig};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

struct Xray {
    child: Child,
    dir: PathBuf,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn xray_available() -> bool {
    Command::new("xray").arg("version").stdout(Stdio::null()).status().is_ok()
}

fn xray_json(args: &[&str]) -> Value {
    let out = Command::new("xray").args(args).output().unwrap();
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Returns (private, public) REALITY keys.
fn x25519() -> (String, String) {
    let out = Command::new("xray").arg("x25519").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    let field = |prefix: &str| {
        text.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.split(':').nth(1))
            .unwrap()
            .trim()
            .to_string()
    };
    (field("PrivateKey"), field("Password"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn start_xray(inbound: Value) -> Xray {
    let dir = std::env::temp_dir().join(format!("veil-xray-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = json!({
        "log": { "loglevel": std::env::var("XRAY_LOG").unwrap_or_else(|_| "warning".into()) },
        "inbounds": [inbound],
        // Xray blocks private destinations by default; the echo origin lives on loopback.
        "outbounds": [{ "protocol": "freedom",
                        "settings": { "finalRules": [{ "action": "allow", "ip": ["127.0.0.0/8"] }] } }],
    });
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let child = Command::new("xray").arg("run").arg("-c").arg(&path).spawn().unwrap();
    // Owning the child in `Xray` kills and reaps it even if startup fails.
    let xray = Xray { child, dir };
    let port = inbound["port"].as_u64().unwrap() as u16;
    if inbound["protocol"] == "hysteria" {
        // UDP only: nothing to probe over TCP; the test waits for readiness via `probe`.
        return xray;
    }
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return xray;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("xray did not start");
}

fn tls_settings() -> Value {
    let cert = xray_json(&["tls", "cert", "--domain=localhost"]);
    json!({ "certificates": [{ "certificate": cert["certificate"], "key": cert["key"] }] })
}

async fn origin() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// Sends small and large payloads through the proxy and expects them echoed back.
async fn roundtrip(link: &str) {
    let profile: Profile = parse_link(link).unwrap();
    let engine = Engine::start(EngineConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        server: profile.server,
        routing: veil_config::RoutingConfig::proxy_all(),
        geo_dir: std::env::temp_dir(),
        tun: None,
    })
    .await
    .unwrap();
    let origin = origin().await;

    let mut s = TcpStream::connect(engine.local_addr()).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let SocketAddr::V4(v4) = origin else { panic!() };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();

    for size in [5usize, 1500, 200_000] {
        let data: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
        let (mut rd, mut wr) = s.split();
        let (_, got) = tokio::join!(wr.write_all(&data), async {
            let mut got = vec![0u8; size];
            tokio::time::timeout(Duration::from_secs(30), rd.read_exact(&mut got))
                .await
                .expect("timed out waiting for echo")
                .unwrap();
            got
        });
        assert!(got == data, "{link}: payload of {size} bytes corrupted");
    }
    engine.stop().await;
}

macro_rules! skip_without_xray {
    () => {
        if !xray_available() {
            eprintln!("xray not found, skipping");
            return;
        }
    };
}

#[tokio::test]
async fn vmess_ciphers() {
    skip_without_xray!();
    let port = free_port();
    let _x = start_xray(json!({
        "listen": "127.0.0.1", "port": port, "protocol": "vmess",
        "settings": { "clients": [{ "id": UUID }] },
    }))
    .await;
    use base64::Engine as _;
    // Xray 26 rejects security "none"; it is still sent to older servers.
    for scy in ["aes-128-gcm", "chacha20-poly1305", "auto"] {
        let j = json!({"v":"2","ps":"t","add":"127.0.0.1","port":port.to_string(),"id":UUID,"aid":"0","scy":scy,"net":"tcp"});
        let link = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(j.to_string()));
        roundtrip(&link).await;
    }
}

#[tokio::test]
async fn vless_tcp() {
    skip_without_xray!();
    let port = free_port();
    let _x = start_xray(json!({
        "listen": "127.0.0.1", "port": port, "protocol": "vless",
        "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
    }))
    .await;
    roundtrip(&format!("vless://{UUID}@127.0.0.1:{port}?type=tcp&security=none")).await;
}

#[tokio::test]
async fn vless_ws_tls() {
    skip_without_xray!();
    let port = free_port();
    let _x = start_xray(json!({
        "listen": "127.0.0.1", "port": port, "protocol": "vless",
        "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
        "streamSettings": { "network": "ws", "security": "tls", "tlsSettings": tls_settings(),
                            "wsSettings": { "path": "/ws" } },
    }))
    .await;
    roundtrip(&format!(
        "vless://{UUID}@127.0.0.1:{port}?type=ws&path=%2Fws%3Fed%3D2048&host=localhost&security=tls&sni=localhost&allowInsecure=1"
    ))
    .await;
}

#[tokio::test]
async fn trojan_tls() {
    skip_without_xray!();
    let port = free_port();
    let _x = start_xray(json!({
        "listen": "127.0.0.1", "port": port, "protocol": "trojan",
        "settings": { "clients": [{ "password": "secret" }] },
        "streamSettings": { "security": "tls", "tlsSettings": tls_settings() },
    }))
    .await;
    roundtrip(&format!("trojan://secret@127.0.0.1:{port}?sni=localhost&allowInsecure=1")).await;
}

#[tokio::test]
async fn shadowsocks() {
    skip_without_xray!();
    for (method, password) in [("aes-256-gcm", "pw"), ("2022-blake3-aes-128-gcm", "AAAAAAAAAAAAAAAAAAAAAA==")] {
        let port = free_port();
        let _x = start_xray(json!({
            "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
            "settings": { "method": method, "password": password, "network": "tcp" },
        }))
        .await;
        let enc = |s: &str| percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string();
        roundtrip(&format!("ss://{}:{}@127.0.0.1:{port}", enc(method), enc(password))).await;
    }
}

fn reality_inbound(port: u16, private_key: &str, flow: &str) -> Value {
    json!({
        "listen": "127.0.0.1", "port": port, "protocol": "vless",
        "settings": { "clients": [{ "id": UUID, "flow": flow }], "decryption": "none" },
        "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": {
            "target": "www.microsoft.com:443",
            "serverNames": ["www.microsoft.com"],
            "privateKey": private_key,
            "shortIds": ["", "6ba85179e30d4fc2"],
        }},
    })
}

#[tokio::test]
async fn vless_reality() {
    skip_without_xray!();
    let (private, public) = x25519();
    let port = free_port();
    let _x = start_xray(reality_inbound(port, &private, "")).await;
    roundtrip(&format!(
        "vless://{UUID}@127.0.0.1:{port}?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk={public}&sid=6ba85179e30d4fc2"
    ))
    .await;
}

#[tokio::test]
async fn vless_reality_vision() {
    skip_without_xray!();
    let (private, public) = x25519();
    let port = free_port();
    let _x = start_xray(reality_inbound(port, &private, "xtls-rprx-vision")).await;
    roundtrip(&format!(
        "vless://{UUID}@127.0.0.1:{port}?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk={public}&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision"
    ))
    .await;
}

#[tokio::test]
async fn hysteria2() {
    skip_without_xray!();
    let port = free_port();
    let tls = tls_settings();
    let _x = start_xray(json!({
        "listen": "127.0.0.1", "port": port, "protocol": "hysteria",
        "settings": { "version": 2, "clients": [{ "auth": "secret" }] },
        "streamSettings": { "network": "hysteria", "hysteriaSettings": { "version": 2 },
            "security": "tls", "tlsSettings": { "alpn": ["h3"], "certificates": tls["certificates"] } },
    }))
    .await;
    // Wait until the server answers a valid probe (up to 10 s) instead of a fixed sleep.
    let good = veil_config::parse_link(&format!("hysteria2://secret@127.0.0.1:{port}/?sni=localhost&insecure=1")).unwrap();
    let ready = veil_proto::hysteria::HysteriaClient::new(&good.server).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout(Duration::from_secs(2), ready.probe()).await {
            Ok(Ok(_)) => break,
            other => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "hysteria server not ready within 10s, last probe result: {:?}",
                    other.map(|r| r.map(|_| ()).map_err(|e| e.to_string()))
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    roundtrip(&format!("hysteria2://secret@127.0.0.1:{port}/?sni=localhost&insecure=1")).await;
    // A wrong password must be rejected, not hang.
    let bad = veil_config::parse_link(&format!("hysteria2://wrong@127.0.0.1:{port}/?sni=localhost&insecure=1")).unwrap();
    let client = veil_proto::hysteria::HysteriaClient::new(&bad.server).unwrap();
    let err = tokio::time::timeout(Duration::from_secs(15), client.probe()).await.expect("no hang").unwrap_err();
    assert!(err.to_string().contains("authentication"), "{err}");

    // Certificate pin: SHA-256 of the DER of the very certificate the server presents.
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let pem_lines = &tls["certificates"][0]["certificate"];
    let pem = match pem_lines {
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"),
        other => other.as_str().expect("certificate pem").to_string(),
    };
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).expect("pem base64");
    let pin: String = Sha256::digest(&der).iter().map(|b| format!("{b:02X}")).collect();
    // No `insecure=1`: the pin alone must be enough (the certificate is self-signed).
    roundtrip(&format!("hysteria2://secret@127.0.0.1:{port}/?sni=localhost&pinSHA256={pin}")).await;
    let wrong = "00".repeat(32);
    let bad_pin = veil_config::parse_link(&format!("hysteria2://secret@127.0.0.1:{port}/?sni=localhost&insecure=1&pinSHA256={wrong}")).unwrap();
    let client = veil_proto::hysteria::HysteriaClient::new(&bad_pin.server).unwrap();
    let err = tokio::time::timeout(Duration::from_secs(15), client.probe()).await.expect("no hang").unwrap_err();
    assert!(err.to_string().contains("pinSHA256"), "{err}");
}

/// Hysteria 2 with Salamander obfuscation (`finalmask.udp`). Skipped when this Xray build does
/// not accept the finalmask setting.
#[tokio::test]
async fn hysteria2_salamander() {
    skip_without_xray!();
    let port = free_port();
    let tls = tls_settings();
    let inbound = json!({
        "listen": "127.0.0.1", "port": port, "protocol": "hysteria",
        "settings": { "version": 2, "clients": [{ "auth": "secret" }] },
        "streamSettings": { "network": "hysteria", "hysteriaSettings": { "version": 2 },
            "security": "tls", "tlsSettings": { "alpn": ["h3"], "certificates": tls["certificates"] },
            "finalmask": { "udp": [{ "type": "salamander", "settings": { "password": "pw-salamander" } }] } },
    });
    // `xray run -test` validates the config without starting it.
    let dir = std::env::temp_dir().join(format!("veil-xray-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, serde_json::to_vec(&json!({ "inbounds": [inbound.clone()], "outbounds": [{ "protocol": "freedom" }] })).unwrap()).unwrap();
    let accepted = Command::new("xray").args(["run", "-test", "-c"]).arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    let _ = std::fs::remove_dir_all(&dir);
    if !accepted {
        eprintln!("this xray does not accept finalmask/salamander, skipping");
        return;
    }
    let _x = start_xray(inbound).await;
    let link = format!("hysteria2://secret@127.0.0.1:{port}/?sni=localhost&insecure=1&obfs=salamander&obfs-password=pw-salamander");
    let ready = veil_proto::hysteria::HysteriaClient::new(&veil_config::parse_link(&link).unwrap().server).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::time::timeout(Duration::from_secs(2), ready.probe()).await {
            Ok(Ok(_)) => break,
            other => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "salamander server not ready within 10s, last probe result: {:?}",
                    other.map(|r| r.map(|_| ()).map_err(|e| e.to_string()))
                );
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    }
    roundtrip(&link).await;
    // Wrong obfs password: the server drops everything, the handshake must time out, not hang.
    let wrong = veil_config::parse_link(&link.replace("pw-salamander", "nope")).unwrap();
    let client = veil_proto::hysteria::HysteriaClient::new(&wrong.server).unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(25), client.probe()).await.expect("no hang").is_err());
}
