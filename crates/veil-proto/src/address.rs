use std::fmt;
use std::net::{IpAddr, SocketAddr};

/// Destination of a proxied connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Address::Socket(a) => a.port(),
            Address::Domain(_, p) => *p,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Address::Socket(a) => a.ip().to_string(),
            Address::Domain(d, _) => d.clone(),
        }
    }

    /// Builds an address from a host string, recognising IP literals.
    pub fn from_host(host: &str, port: u16) -> Self {
        let trimmed = host.trim_start_matches('[').trim_end_matches(']');
        match trimmed.parse::<IpAddr>() {
            Ok(ip) => Address::Socket(SocketAddr::new(ip, port)),
            Err(_) => Address::Domain(host.to_string(), port),
        }
    }

    /// SOCKS5 / Trojan / Shadowsocks encoding: ATYP(1=v4, 3=domain, 4=v6) ADDR PORT.
    pub fn write_socks(&self, out: &mut Vec<u8>) {
        match self {
            Address::Socket(SocketAddr::V4(a)) => {
                out.push(1);
                out.extend_from_slice(&a.ip().octets());
            }
            Address::Socket(SocketAddr::V6(a)) => {
                out.push(4);
                out.extend_from_slice(&a.ip().octets());
            }
            Address::Domain(d, _) => {
                out.push(3);
                out.push(d.len().min(255) as u8);
                out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
        }
        out.extend_from_slice(&self.port().to_be_bytes());
    }

    /// VLESS / VMess encoding: PORT ATYP(1=v4, 2=domain, 3=v6) ADDR.
    pub fn write_vless(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.port().to_be_bytes());
        match self {
            Address::Socket(SocketAddr::V4(a)) => {
                out.push(1);
                out.extend_from_slice(&a.ip().octets());
            }
            Address::Socket(SocketAddr::V6(a)) => {
                out.push(3);
                out.extend_from_slice(&a.ip().octets());
            }
            Address::Domain(d, _) => {
                out.push(2);
                out.push(d.len().min(255) as u8);
                out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
            }
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Socket(a) => write!(f, "{a}"),
            Address::Domain(d, p) => write!(f, "{d}:{p}"),
        }
    }
}

impl From<SocketAddr> for Address {
    fn from(a: SocketAddr) -> Self {
        Address::Socket(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        let mut v = Vec::new();
        Address::Domain("ab".into(), 443).write_socks(&mut v);
        assert_eq!(v, [3, 2, b'a', b'b', 1, 187]);
        v.clear();
        Address::from_host("1.2.3.4", 80).write_vless(&mut v);
        assert_eq!(v, [0, 80, 1, 1, 2, 3, 4]);
        assert_eq!(Address::from_host("[::1]", 1), Address::Socket("[::1]:1".parse().unwrap()));
    }
}
