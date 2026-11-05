//! SOCKS5 and HTTP proxy on a single port.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use veil_proto::Address;

use crate::engine::Shared;

const MAX_HEADER: usize = 16 * 1024;

pub(crate) async fn handle(stream: TcpStream, shared: &Shared) -> io::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut stream = BufReader::new(stream);
    let first = stream.fill_buf().await?;
    match first.first() {
        None => Ok(()),
        Some(5) => socks5(stream, shared, peer).await,
        Some(_) => http(stream, shared, peer).await,
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

async fn socks5(mut s: BufReader<TcpStream>, shared: &Shared, peer: Option<SocketAddr>) -> io::Result<()> {
    // Greeting: VER NMETHODS METHODS...; we only offer "no authentication".
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        return Err(bad("socks5: client requires authentication"));
    }
    s.write_all(&[5, 0]).await?;

    // Request: VER CMD RSV ATYP DST.ADDR DST.PORT
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    let dst = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await?;
            Address::Socket(SocketAddr::new(Ipv4Addr::from(ip).into(), s.read_u16().await?))
        }
        3 => {
            let len = s.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            s.read_exact(&mut name).await?;
            let name = String::from_utf8(name).map_err(|_| bad("socks5: bad domain"))?;
            Address::from_host(&name, s.read_u16().await?)
        }
        4 => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip).await?;
            Address::Socket(SocketAddr::new(Ipv6Addr::from(ip).into(), s.read_u16().await?))
        }
        _ => return Err(bad("socks5: bad address type")),
    };
    if req[1] != 1 {
        // Only CONNECT for now; UDP ASSOCIATE comes with UDP relay support.
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(bad("socks5: unsupported command"));
    }

    // Reply only after the upstream connection is attempted would be more precise,
    // but replying early lets the client send its first bytes together with our header.
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    shared.relay(s, dst, &[], peer).await
}

async fn http(mut s: BufReader<TcpStream>, shared: &Shared, peer: Option<SocketAddr>) -> io::Result<()> {
    let mut lines = Vec::new();
    let mut total = 0;
    loop {
        let mut line = String::new();
        let n = s.read_line(&mut line).await?;
        total += n;
        if n == 0 || total > MAX_HEADER {
            return Err(bad("http: incomplete or oversized header"));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            break;
        }
        lines.push(line);
    }
    let request_line = lines.first().ok_or_else(|| bad("http: empty request"))?;
    let mut parts = request_line.split_whitespace();
    let (method, target, version) = match (parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v)) => (m.to_string(), t.to_string(), v.to_string()),
        _ => return Err(bad("http: malformed request line")),
    };

    if method.eq_ignore_ascii_case("CONNECT") {
        let dst = parse_authority(&target, 443).ok_or_else(|| bad("http: bad CONNECT target"))?;
        s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
        return shared.relay(s, dst, &[], peer).await;
    }

    // Plain HTTP proxy request with an absolute URI.
    let url = url::Url::parse(&target).map_err(|_| bad("http: expected absolute URI"))?;
    let host = url.host_str().ok_or_else(|| bad("http: missing host"))?;
    let dst = Address::from_host(host, url.port_or_known_default().unwrap_or(80));
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let mut head = format!("{method} {path} {version}\r\n");
    for line in &lines[1..] {
        let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if name.starts_with("proxy-") || name == "connection" || name == "keep-alive" {
            continue;
        }
        head.push_str(line);
        head.push_str("\r\n");
    }
    // One upstream per client connection, so don't let the client reuse it for other hosts.
    head.push_str("Connection: close\r\n\r\n");
    shared.relay(s, dst, head.as_bytes(), peer).await
}

fn parse_authority(s: &str, default_port: u16) -> Option<Address> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':').map_or(Some(default_port), |p| p.parse().ok())?;
        return Some(Address::from_host(host, port));
    }
    match s.rsplit_once(':') {
        Some((host, port)) => Some(Address::from_host(host, port.parse().ok()?)),
        None => Some(Address::from_host(s, default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority() {
        assert_eq!(parse_authority("a.com:8443", 443), Some(Address::Domain("a.com".into(), 8443)));
        assert_eq!(parse_authority("[::1]:80", 443), Some(Address::Socket("[::1]:80".parse().unwrap())));
        assert_eq!(parse_authority("a.com", 443), Some(Address::Domain("a.com".into(), 443)));
    }
}
