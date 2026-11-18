//! Outgoing sockets and name resolution.
//!
//! In TUN mode the default route points into the tunnel, so every socket we open
//! ourselves is pinned to the physical interface (`IP_BOUND_IF`, `SO_BINDTODEVICE`, `IP_UNICAST_IF`) and names are
//! resolved by querying the original DNS servers over that interface.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpSocket, TcpStream, UdpSocket, lookup_host};
use tokio::time::timeout;

use crate::{Address, dns};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const PRIMARY_HEAD_START: Duration = Duration::from_millis(400);

#[derive(Debug, Clone)]
pub struct Bypass {
    pub if_index: NonZeroU32,
    /// DNS servers reachable through the physical interface.
    pub dns: Vec<IpAddr>,
}

static BYPASS: RwLock<Option<Arc<Bypass>>> = RwLock::new(None);
type DnsCache = HashMap<String, (Vec<IpAddr>, Instant)>;
static DNS_CACHE: Mutex<Option<DnsCache>> = Mutex::new(None);

/// Enables (TUN mode) or disables interface pinning for all new sockets.
pub fn set_bypass(bypass: Option<Bypass>) {
    *BYPASS.write().unwrap() = bypass.map(Arc::new);
    *DNS_CACHE.lock().unwrap() = None;
}

/// DNS servers used for direct resolution in TUN mode (empty otherwise).
pub fn bypass_dns() -> Vec<IpAddr> {
    bypass().map(|b| b.dns.clone()).unwrap_or_default()
}

fn bypass() -> Option<Arc<Bypass>> {
    BYPASS.read().unwrap().clone()
}

fn bound_socket(ip: IpAddr, ty: Type, proto: Protocol, if_index: NonZeroU32) -> io::Result<Socket> {
    let domain = if ip.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let s = Socket::new(domain, ty, Some(proto))?;
    pin_socket(&s, ip.is_ipv4(), if_index)?;
    s.set_nonblocking(true)?;
    Ok(s)
}

/// Sends the socket's traffic out of `if_index` whatever the routing table says.
#[cfg(target_os = "macos")]
fn pin_socket(s: &Socket, v4: bool, if_index: NonZeroU32) -> io::Result<()> {
    if v4 { s.bind_device_by_index_v4(Some(if_index)) } else { s.bind_device_by_index_v6(Some(if_index)) }
}

/// `IP_UNICAST_IF` takes the index in network byte order for IPv4 but in host
/// order for IPv6. Must be set before connect/send.
#[cfg(windows)]
fn pin_socket(s: &Socket, v4: bool, if_index: NonZeroU32) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, setsockopt};
    let (level, name, value) = if v4 {
        (IPPROTO_IP, IP_UNICAST_IF, if_index.get().to_be())
    } else {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, if_index.get())
    };
    let rc = unsafe {
        setsockopt(s.as_raw_socket() as usize, level, name, (&raw const value).cast(), size_of::<u32>() as i32)
    };
    if rc != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Linux: `SO_BINDTODEVICE` by interface name (we run as root in TUN mode, and the option
/// is also allowed unprivileged since 5.7). If it is refused, falls back to
/// `IP_UNICAST_IF`/`IPV6_UNICAST_IF`, which take the index (network byte order for IPv4,
/// host order for IPv6). Must be set before connect/send.
#[cfg(target_os = "linux")]
fn pin_socket(s: &Socket, v4: bool, if_index: NonZeroU32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut name = [0u8; libc::IF_NAMESIZE];
    let ok = unsafe { libc::if_indextoname(if_index.get(), name.as_mut_ptr().cast()) };
    if !ok.is_null() {
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        match s.bind_device(Some(&name[..len])) {
            Ok(()) => return Ok(()),
            Err(e) => tracing::debug!("SO_BINDTODEVICE failed ({e}), trying UNICAST_IF"),
        }
    }
    let (level, opt, value) = if v4 {
        (libc::IPPROTO_IP, libc::IP_UNICAST_IF, if_index.get().to_be())
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_IF, if_index.get())
    };
    let rc = unsafe {
        libc::setsockopt(s.as_raw_fd(), level, opt, (&raw const value).cast(), size_of::<u32>() as libc::socklen_t)
    };
    if rc != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn pin_socket(_s: &Socket, _v4: bool, _if_index: NonZeroU32) -> io::Result<()> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "interface pinning is not supported on this OS"))
}

/// A UDP socket for talking to `peer`, pinned to the physical interface if needed.
pub async fn udp_socket_for(peer: IpAddr) -> io::Result<UdpSocket> {
    udp_socket_with(peer, bypass().as_deref()).await
}

/// Like [`udp_socket_for`], with an explicit interface pinning.
pub async fn udp_socket_with(peer: IpAddr, pin: Option<&Bypass>) -> io::Result<UdpSocket> {
    let unspecified: SocketAddr = if peer.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().unwrap();
    match pin {
        Some(b) => {
            let s = bound_socket(peer, Type::DGRAM, Protocol::UDP, b.if_index)?;
            s.bind(&unspecified.into())?;
            UdpSocket::from_std(s.into())
        }
        None => UdpSocket::bind(unspecified).await,
    }
}

async fn query(server: IpAddr, name: &str, qtype: u16, pin: &Bypass) -> io::Result<(Vec<IpAddr>, u32)> {
    let sock = udp_socket_with(server, Some(pin)).await?;
    sock.connect((server, 53)).await?;
    let id: u16 = rand::random();
    sock.send(&dns::build_query(id, name, qtype)).await?;
    let mut buf = [0u8; 1500];
    loop {
        let n = sock.recv(&mut buf).await?;
        if let Some(r) = dns::parse_answers(&buf[..n], id) {
            return Ok(r);
        }
    }
}

/// Resolves via the bypass DNS servers. The first (system) server is preferred
/// because it knows local CDN nodes; the others answer when it is silent or
/// returns nothing (mobile carriers blank out blocked domains).
async fn resolve_bypass(b: &Bypass, host: &str) -> io::Result<Vec<IpAddr>> {
    if let Some((ips, at)) = DNS_CACHE.lock().unwrap().get_or_insert_default().get(host)
        && at.elapsed() < DNS_CACHE_TTL
    {
        return Ok(ips.clone());
    }
    let mut pending: futures::stream::FuturesUnordered<_> = b
        .dns
        .iter()
        .enumerate()
        .map(|(i, server)| {
            let (server, host) = (*server, host.to_string());
            async move {
                // Give the preferred server a head start before others can win.
                if i > 0 {
                    tokio::time::sleep(PRIMARY_HEAD_START).await;
                }
                let (a, aaaa) = tokio::join!(
                    timeout(DNS_TIMEOUT, query(server, &host, dns::TYPE_A, b)),
                    timeout(DNS_TIMEOUT, query(server, &host, dns::TYPE_AAAA, b)),
                );
                let mut ips = Vec::new();
                let mut err = None;
                for r in [a, aaaa] {
                    match r {
                        Ok(Ok((found, _ttl))) => ips.extend(found),
                        Ok(Err(e)) => err = Some(e.to_string()),
                        Err(_) => err = Some(format!("DNS {server} timed out")),
                    }
                }
                (ips, err)
            }
        })
        .collect();
    let mut last_err = "no answer".to_string();
    while let Some((mut ips, err)) = futures::StreamExt::next(&mut pending).await {
        if ips.is_empty() {
            if let Some(e) = err {
                last_err = e;
            }
            continue;
        }
        // IPv4 first: the tunnel does not carry IPv6 to direct destinations reliably.
        ips.sort_by_key(|ip| ip.is_ipv6());
        DNS_CACHE.lock().unwrap().get_or_insert_default().insert(host.to_string(), (ips.clone(), Instant::now()));
        return Ok(ips);
    }
    Err(io::Error::new(io::ErrorKind::NotFound, format!("{host}: {last_err}")))
}

pub async fn resolve(addr: &Address) -> io::Result<Vec<SocketAddr>> {
    resolve_with(addr, bypass().as_deref()).await
}

/// Like [`resolve`], with an explicit interface pinning.
pub async fn resolve_with(addr: &Address, pin: Option<&Bypass>) -> io::Result<Vec<SocketAddr>> {
    match addr {
        Address::Socket(a) => Ok(vec![*a]),
        Address::Domain(host, port) => {
            let addrs: Vec<SocketAddr> = match pin {
                Some(b) => resolve_bypass(b, host).await?.into_iter().map(|ip| SocketAddr::new(ip, *port)).collect(),
                None => lookup_host((host.as_str(), *port)).await?.collect(),
            };
            if addrs.is_empty() {
                return Err(io::Error::new(io::ErrorKind::NotFound, format!("{host}: no addresses")));
            }
            Ok(addrs)
        }
    }
}

async fn connect_one(sa: SocketAddr, pin: Option<&Bypass>) -> io::Result<TcpStream> {
    match pin {
        Some(b) => {
            let s = bound_socket(sa.ip(), Type::STREAM, Protocol::TCP, b.if_index)?;
            TcpSocket::from_std_stream(std::net::TcpStream::from(s)).connect(sa).await
        }
        None => TcpStream::connect(sa).await,
    }
}

/// Opens a TCP connection, trying each resolved address in turn.
pub async fn tcp_connect(addr: &Address) -> io::Result<TcpStream> {
    tcp_connect_with(addr, bypass().as_deref()).await
}

/// Like [`tcp_connect`], with an explicit interface pinning.
pub async fn tcp_connect_with(addr: &Address, pin: Option<&Bypass>) -> io::Result<TcpStream> {
    let mut last_err = None;
    for sa in resolve_with(addr, pin).await? {
        match timeout(CONNECT_TIMEOUT, connect_one(sa, pin)).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true)?;
                return Ok(s);
            }
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => last_err = Some(io::Error::new(io::ErrorKind::TimedOut, format!("connect {sa} timed out"))),
        }
    }
    Err(last_err.unwrap_or_else(|| io::ErrorKind::NotFound.into()))
}
