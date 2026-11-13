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

/// Echo origin like [`origin`] that also counts the connections it accepted.
async fn counting_origin() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
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
    (addr, hits)
}

/// Like [`trojan_server_to`], counting the requests that reached it.
async fn counting_trojan_server(origin: SocketAddr) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut head = [0u8; 56 + 2 + 1 + 1];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                counter.fetch_add(1, Ordering::SeqCst);
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
    (addr, hits)
}

/// The connection is closed by the proxy: no data comes back (and it does not hang).
async fn assert_closed(s: &mut TcpStream) {
    let _ = s.write_all(b"x").await;
    let mut buf = [0u8; 64];
    let r = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf)).await;
    match r {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("got {n} bytes through a blocked connection: {:?}", &buf[..n]),
        Err(_) => panic!("connection was not closed"),
    }
}

/// Standby (kill switch): VPN traffic is refused, also the implicit-direct fallback;
/// direct traffic keeps working; switching back restores the VPN.
#[tokio::test]
async fn standby_blocks_vpn_traffic_only() {
    use std::sync::atomic::Ordering;
    use veil_config::{RouteAction, RoutingConfig, RoutingRule};
    let (origin, origin_hits) = counting_origin().await;
    let (server, server_hits) = counting_trojan_server(origin).await;
    let start_with = |rules: Vec<RoutingRule>, final_action: RouteAction| {
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
            routing: RoutingConfig { rules, final_action },
            geo_dir: std::env::temp_dir(),
            tun: None,
        })
    };
    let hits = || (server_hits.load(Ordering::SeqCst), origin_hits.load(Ordering::SeqCst));

    // Everything through the VPN.
    let engine = start_with(Vec::new(), RouteAction::Proxy).await.unwrap();
    assert!(!engine.is_standby());
    let mut open = via_socks5(engine.local_addr(), origin).await;
    ping(&mut open, b"before").await;
    let (srv, org) = hits();
    assert_eq!((srv, org), (1, 1));

    // Standby: the open VPN connection is closed, new ones neither reach the server
    // nor go out directly.
    engine.set_standby(true);
    assert!(engine.is_standby());
    assert_closed(&mut open).await;
    for _ in 0..3 {
        let mut s = via_socks5(engine.local_addr(), origin).await;
        assert_closed(&mut s).await;
    }
    assert_eq!(hits(), (srv, org), "standby let a connection through");

    // Back on: through the VPN again, without restarting anything.
    engine.set_standby(false);
    let mut s = via_socks5(engine.local_addr(), origin).await;
    ping(&mut s, b"after").await;
    assert_eq!(hits(), (srv + 1, org + 1));
    engine.stop().await;

    // An explicit direct rule keeps working on standby, without the server.
    let engine = start_with(vec![RoutingRule::ips(RouteAction::Direct, &["127.0.0.0/8"])], RouteAction::Proxy)
        .await
        .unwrap();
    engine.set_standby(true);
    let (srv, org) = hits();
    let mut s = via_socks5(engine.local_addr(), origin).await;
    ping(&mut s, b"direct").await;
    assert_eq!(hits(), (srv, org + 1));
    // Going on standby does not touch direct connections.
    engine.set_standby(false);
    engine.set_standby(true);
    ping(&mut s, b"still").await;
    engine.stop().await;

    // Implicit direct to a site that refuses: no fallback to the VPN on standby.
    // (Port held by a bound, non-listening socket; see implicit_direct_falls_back_to_proxy.)
    let blocked_guard = tokio::net::TcpSocket::new_v4().unwrap();
    blocked_guard.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let blocked: SocketAddr = blocked_guard.local_addr().unwrap();
    let engine = start_with(Vec::new(), RouteAction::Direct).await.unwrap();
    engine.set_standby(true);
    let (srv, org) = hits();
    let mut s = via_socks5(engine.local_addr(), blocked).await;
    assert_closed(&mut s).await;
    assert_eq!(hits(), (srv, org), "implicit direct fell back to the VPN on standby");
    // Off standby the same connection does fall back to the VPN.
    engine.set_standby(false);
    let mut s = via_socks5(engine.local_addr(), blocked).await;
    ping(&mut s, b"via vpn").await;
    assert_eq!(hits(), (srv + 1, org + 1));
    engine.stop().await;
}

/// Like [`counting_trojan_server`], but it can be taken down: aborting the returned task
/// closes the listener and every connection it accepted (a server gone with the network).
async fn stoppable_trojan_server(
    origin: SocketAddr,
) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinHandle<()>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let task = tokio::spawn(async move {
        // Dropped with this task: aborts the connections too.
        let mut conns = tokio::task::JoinSet::new();
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let counter = counter.clone();
            conns.spawn(async move {
                let mut head = [0u8; 56 + 2 + 1 + 1];
                if s.read_exact(&mut head).await.is_err() {
                    return;
                }
                counter.fetch_add(1, Ordering::SeqCst);
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
    (addr, hits, task)
}

/// A server that accepts TCP and then never answers (a black hole behind a dead network).
async fn silent_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (s, _) = l.accept().await.unwrap();
            held.push(s);
        }
    });
    addr
}

/// A server that accepts TCP and closes it at once (a server that is down or rejects us).
async fn rejecting_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            drop(l.accept().await.unwrap());
        }
    });
    addr
}

/// No data comes back within `wait` (closed, reset or hanging: anything but a reply).
async fn assert_no_reply(s: &mut TcpStream, wait: std::time::Duration) {
    let _ = s.write_all(b"x").await;
    let mut buf = [0u8; 64];
    if let Ok(Ok(n)) = tokio::time::timeout(wait, s.read(&mut buf)).await {
        assert_eq!(n, 0, "got a reply without a server: {:?}", &buf[..n]);
    }
}

/// [`assert_closed`] that names the connection it failed on.
async fn assert_closed_at(s: &mut TcpStream, what: &str) {
    let _ = s.write_all(b"x").await;
    let mut buf = [0u8; 64];
    // Long enough for the implicit-direct attempt (4 s) to time out where it does not refuse.
    match tokio::time::timeout(std::time::Duration::from_secs(15), s.read(&mut buf)).await {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("{what}: got {n} bytes without a server: {:?}", &buf[..n]),
        Err(_) => panic!("{what}: connection was not closed"),
    }
}

/// Without standby: the server goes away (refuses, then a black hole). Connections the rules
/// send through the VPN, explicit or as the implicit-direct fallback, fail and never go out
/// directly; an explicit direct rule keeps working.
#[tokio::test]
async fn server_down_never_goes_direct() {
    use std::sync::atomic::Ordering;
    use veil_config::{RouteAction, RoutingConfig, RoutingRule};
    let (vpn_origin, vpn_origin_hits) = counting_origin().await;
    let (direct_origin, direct_origin_hits) = counting_origin().await;
    let (server, server_hits, server_task) = stoppable_trojan_server(vpn_origin).await;
    // Implicit direct to this port is refused (bound, never listening; see
    // implicit_direct_falls_back_to_proxy), so it falls back to the VPN.
    let blocked_guard = tokio::net::TcpSocket::new_v4().unwrap();
    blocked_guard.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let blocked: SocketAddr = blocked_guard.local_addr().unwrap();

    let rules = vec![
        RoutingRule { port: vec![vpn_origin.port().to_string()], ..RoutingRule::ips(RouteAction::Proxy, &[]) },
        RoutingRule { port: vec![direct_origin.port().to_string()], ..RoutingRule::ips(RouteAction::Direct, &[]) },
    ];
    let trojan = |addr: SocketAddr| ServerConfig {
        address: addr.ip().to_string(),
        port: addr.port(),
        protocol: Protocol::Trojan { password: "secret".into() },
        transport: Transport::Tcp,
        security: Security::None,
    };
    let engine = Engine::start(EngineConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        server: trojan(server),
        routing: RoutingConfig { rules, final_action: RouteAction::Direct },
        geo_dir: std::env::temp_dir(),
        tun: None,
    })
    .await
    .unwrap();
    let proxy = engine.local_addr();
    let vpn_hits = || (server_hits.load(Ordering::SeqCst), vpn_origin_hits.load(Ordering::SeqCst));

    // Server up: the explicit proxy rule and the implicit-direct fallback both use it.
    let mut open = via_socks5(proxy, vpn_origin).await;
    ping(&mut open, b"proxy rule").await;
    let mut s = via_socks5(proxy, blocked).await;
    ping(&mut s, b"fallback").await;
    assert_eq!(vpn_hits(), (2, 2));
    let mut direct = via_socks5(proxy, direct_origin).await;
    ping(&mut direct, b"direct rule").await;
    assert_eq!(direct_origin_hits.load(Ordering::SeqCst), 1);
    assert_eq!(server_hits.load(Ordering::SeqCst), 2, "the direct rule went through the server");

    // The server goes away: its process dies (listener and connections closed), and what
    // answers at its address from then on drops every connection at once.
    server_task.abort();
    let _ = server_task.await;
    engine.set_server(trojan(rejecting_server().await)).await.unwrap();
    // The VPN connection that was open ends; it is not continued directly.
    assert_closed_at(&mut open, "open").await;
    for _ in 0..2 {
        let mut s = via_socks5(proxy, vpn_origin).await;
        assert_closed_at(&mut s, "proxy rule").await;
        let mut s = via_socks5(proxy, blocked).await;
        assert_closed_at(&mut s, "implicit direct").await;
    }
    assert_eq!(vpn_hits(), (2, 2), "a VPN connection went out directly while the server was down");
    // Direct traffic does not depend on the server.
    ping(&mut direct, b"still direct").await;
    let mut s = via_socks5(proxy, direct_origin).await;
    ping(&mut s, b"new direct").await;
    assert_eq!(direct_origin_hits.load(Ordering::SeqCst), 2);

    // Unreachable (a port nobody listens on: refused, or on macOS no answer at all, like a
    // network that drops everything), then a server that accepts and never answers: the
    // connections hang or fail, but still never go out directly.
    let wait = std::time::Duration::from_millis(1500);
    let server_guard = tokio::net::TcpSocket::new_v4().unwrap();
    server_guard.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    for dead in [server_guard.local_addr().unwrap(), silent_server().await] {
        engine.set_server(trojan(dead)).await.unwrap();
        let mut a = via_socks5(proxy, vpn_origin).await;
        let mut b = via_socks5(proxy, blocked).await;
        tokio::join!(assert_no_reply(&mut a, wait), assert_no_reply(&mut b, wait));
        assert_eq!(vpn_hits(), (2, 2), "a VPN connection went out directly, server {dead} dead");
    }
    let mut s = via_socks5(proxy, direct_origin).await;
    ping(&mut s, b"direct again").await;
    assert_eq!(direct_origin_hits.load(Ordering::SeqCst), 3);
    engine.stop().await;
    drop((server_guard, blocked_guard));
}
