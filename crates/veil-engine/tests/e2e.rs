//! End-to-end: client -> mixed inbound -> outbound protocol -> test server -> echo origin.

use std::net::SocketAddr;
use std::sync::Arc;

use sha2::{Digest, Sha224};
use shadowsocks::config::{ServerConfig as SsServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::relay::socks5::Address as SsAddress;
use shadowsocks::relay::tcprelay::proxy_listener::ProxyListener;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;
use veil_config::{Protocol, Security, ServerConfig, Transport};
use veil_engine::{Engine, EngineConfig};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// Echo server that prefixes replies with "echo:".
async fn origin() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    let mut out = b"echo:".to_vec();
                    out.extend_from_slice(&buf[..n]);
                    if s.write_all(&out).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

async fn read_socks_addr<S: AsyncRead + Unpin>(s: &mut S, atyp: u8, vless: bool) -> SocketAddr {
    match (atyp, vless) {
        (1, _) => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await.unwrap();
            SocketAddr::from((ip, 0))
        }
        (4, false) | (3, true) => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await.unwrap();
            SocketAddr::from((ip, 0))
        }
        _ => panic!("tests only use IP destinations"),
    }
}

async fn relay<S: AsyncRead + AsyncWrite + Unpin>(mut client: S, dst: SocketAddr) {
    let mut up = TcpStream::connect(dst).await.unwrap();
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
}

async fn trojan_server(password: &str) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let expected: String = Sha224::digest(password.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let expected = expected.clone();
            tokio::spawn(async move {
                let mut hash = [0u8; 56 + 2 + 1 + 1];
                s.read_exact(&mut hash).await.unwrap();
                assert_eq!(&hash[..56], expected.as_bytes());
                assert_eq!(hash[58], 1, "CONNECT");
                let mut dst = read_socks_addr(&mut s, hash[59], false).await;
                dst.set_port(s.read_u16().await.unwrap());
                let mut crlf = [0u8; 2];
                s.read_exact(&mut crlf).await.unwrap();
                relay(s, dst).await;
            });
        }
    });
    addr
}

async fn vless_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = [0u8; 1 + 16 + 1 + 1 + 2 + 1];
                s.read_exact(&mut head).await.unwrap();
                assert_eq!(&head[1..17], Uuid::parse_str(UUID).unwrap().as_bytes());
                let port = u16::from_be_bytes([head[19], head[20]]);
                let mut dst = read_socks_addr(&mut s, head[21], true).await;
                dst.set_port(port);
                s.write_all(&[0, 0]).await.unwrap();
                relay(s, dst).await;
            });
        }
    });
    addr
}

async fn ss_server(method: &str, password: &str) -> SocketAddr {
    let cfg = SsServerConfig::new(("127.0.0.1", 0), password, method.parse().unwrap()).unwrap();
    let l = ProxyListener::bind(Arc::new(Context::new(ServerType::Server)), &cfg).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let SsAddress::SocketAddress(dst) = s.handshake().await.unwrap() else { panic!() };
                relay(s, dst).await;
            });
        }
    });
    addr
}

async fn start(server_addr: SocketAddr, protocol: Protocol) -> Engine {
    let server = ServerConfig {
        address: server_addr.ip().to_string(),
        port: server_addr.port(),
        protocol,
        transport: Transport::Tcp,
        security: Security::None,
    };
    Engine::start(EngineConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        server,
        routing: veil_config::RoutingConfig::proxy_all(),
        geo_dir: std::env::temp_dir(),
        tun: None,
    })
    .await
    .unwrap()
}

async fn via_socks5(proxy: SocketAddr, dst: SocketAddr) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0]);
    let SocketAddr::V4(v4) = dst else { panic!() };
    let mut req = vec![5, 1, 0, 1];
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    s
}

async fn via_http_connect(proxy: SocketAddr, dst: SocketAddr) -> BufReader<TcpStream> {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(format!("CONNECT {dst} HTTP/1.1\r\nHost: {dst}\r\n\r\n").as_bytes()).await.unwrap();
    let mut s = BufReader::new(s);
    let mut line = String::new();
    s.read_line(&mut line).await.unwrap();
    assert!(line.starts_with("HTTP/1.1 200"), "{line}");
    s.read_line(&mut line).await.unwrap();
    s
}

async fn ping<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, msg: &[u8]) {
    s.write_all(msg).await.unwrap();
    let mut out = vec![0u8; 5 + msg.len()];
    s.read_exact(&mut out).await.unwrap();
    assert_eq!(&out[..5], b"echo:");
    assert_eq!(&out[5..], msg);
}

async fn check(engine: Engine, origin: SocketAddr) {
    let mut s = via_socks5(engine.local_addr(), origin).await;
    ping(&mut s, b"hello").await;
    ping(&mut s, b"again").await;
    let mut h = via_http_connect(engine.local_addr(), origin).await;
    ping(&mut h, b"over http").await;
    engine.stop().await;
}

#[tokio::test]
async fn trojan() {
    let origin = origin().await;
    let server = trojan_server("secret").await;
    check(start(server, Protocol::Trojan { password: "secret".into() }).await, origin).await;
}

#[tokio::test]
async fn vless() {
    let origin = origin().await;
    let server = vless_server().await;
    let uuid = Uuid::parse_str(UUID).unwrap();
    check(start(server, Protocol::Vless { uuid, flow: None }).await, origin).await;
}

#[tokio::test]
async fn shadowsocks_aead() {
    let origin = origin().await;
    let server = ss_server("chacha20-ietf-poly1305", "pw").await;
    let proto = Protocol::Shadowsocks { method: "chacha20-ietf-poly1305".into(), password: "pw".into() };
    check(start(server, proto).await, origin).await;
}

#[tokio::test]
async fn shadowsocks_2022() {
    let origin = origin().await;
    let key = "AAAAAAAAAAAAAAAAAAAAAA=="; // 16 zero bytes, base64
    let server = ss_server("2022-blake3-aes-128-gcm", key).await;
    let proto = Protocol::Shadowsocks { method: "2022-blake3-aes-128-gcm".into(), password: key.into() };
    check(start(server, proto).await, origin).await;
}

#[tokio::test]
async fn per_app_rules() {
    use veil_config::{RouteAction, RoutingConfig, RoutingRule};
    let origin = origin().await;
    let server = trojan_server("secret").await;
    let me = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
    let start_with = |rules: Vec<RoutingRule>| {
        let server = ServerConfig {
            address: server.ip().to_string(),
            port: server.port(),
            protocol: Protocol::Trojan { password: "secret".into() },
            transport: Transport::Tcp,
            security: Security::None,
        };
        Engine::start(EngineConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server,
            routing: RoutingConfig { rules, final_action: RouteAction::Proxy },
            geo_dir: std::env::temp_dir(),
            tun: None,
        })
    };

    // This test binary is blocked: the proxy accepts, then closes without data.
    let engine = start_with(vec![RoutingRule::processes(RouteAction::Block, &[me.as_str()])]).await.unwrap();
    let mut s = via_socks5(engine.local_addr(), origin).await;
    s.write_all(b"hello").await.unwrap();
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).await.unwrap_or(0);
    assert_eq!(n, 0, "blocked app must not get a reply");
    engine.stop().await;

    // A rule for some other app does not affect us.
    let engine = start_with(vec![RoutingRule::processes(RouteAction::Block, &["Telegram"])]).await.unwrap();
    let mut s = via_socks5(engine.local_addr(), origin).await;
    ping(&mut s, b"hello").await;
    engine.stop().await;
}

/// Trojan server that sends every request, whatever its destination, to `origin`.
async fn trojan_server_to(origin: SocketAddr) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut head = [0u8; 56 + 2 + 1 + 1];
                s.read_exact(&mut head).await.unwrap();
                let skip = match head[59] {
                    1 => 4 + 2,
                    4 => 16 + 2,
                    _ => s.read_u8().await.unwrap() as usize + 2,
                };
                let mut rest = vec![0u8; skip + 2];
                s.read_exact(&mut rest).await.unwrap();
                relay(s, origin).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn implicit_direct_falls_back_to_proxy() {
    use veil_config::{RouteAction, RoutingConfig, RoutingRule};
    let origin = origin().await;
    let server = trojan_server_to(origin).await;
    let start_with = |rules: Vec<RoutingRule>| {
        let server = ServerConfig {
            address: server.ip().to_string(),
            port: server.port(),
            protocol: Protocol::Trojan { password: "secret".into() },
            transport: Transport::Tcp,
            security: Security::None,
        };
        Engine::start(EngineConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            server,
            routing: RoutingConfig { rules, final_action: RouteAction::Direct },
            geo_dir: std::env::temp_dir(),
            tun: None,
        })
    };
    // A closed local port refuses direct connections, like a censored site. It
    // avoids DNS, which a VPN running on the test machine may answer for any name.
    // The port is held by a bound, non-listening socket until the test ends: a freed
    // port could be taken by a parallel test, and then the "direct" connection would
    // succeed and the fallback to the VPN would never happen.
    let blocked_guard = tokio::net::TcpSocket::new_v4().unwrap();
    blocked_guard.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let blocked: SocketAddr = blocked_guard.local_addr().unwrap();

    let engine = start_with(Vec::new()).await.unwrap();
    let mut s = via_socks5(engine.local_addr(), blocked).await;
    ping(&mut s, b"via vpn").await;
    engine.stop().await;

    // An explicit "direct" rule is respected: no silent detour through the VPN.
    let engine = start_with(vec![RoutingRule::ips(RouteAction::Direct, &["127.0.0.0/8"])]).await.unwrap();
    let mut s = via_socks5(engine.local_addr(), blocked).await;
    s.write_all(b"x").await.unwrap();
    let mut buf = [0u8; 8];
    assert_eq!(s.read(&mut buf).await.unwrap_or(0), 0);
    engine.stop().await;
}
