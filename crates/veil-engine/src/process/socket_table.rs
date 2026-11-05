//! Parsing of Windows `GetExtendedTcpTable` / `GetExtendedUdpTable` dumps.
//! Pure byte handling, so it is unit-tested on every platform.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Row layouts (`*_OWNER_PID`): local address/port and owning pid offsets.
#[derive(Clone, Copy)]
pub struct Layout {
    pub row: usize,
    pub v6: bool,
    pub addr: usize,
    pub port: usize,
    pub pid: usize,
}

pub const TCP4: Layout = Layout { row: 24, v6: false, addr: 4, port: 8, pid: 20 };
pub const TCP6: Layout = Layout { row: 56, v6: true, addr: 0, port: 20, pid: 52 };
pub const UDP4: Layout = Layout { row: 12, v6: false, addr: 0, port: 4, pid: 8 };
pub const UDP6: Layout = Layout { row: 28, v6: true, addr: 0, port: 20, pid: 24 };

fn u32_le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// Owning pid of the socket bound to `local` in a table dump
/// (`dwNumEntries` followed by rows). Ports are stored in network byte order;
/// an unspecified local address (UDP sockets) matches any address.
pub fn find_pid(table: &[u8], layout: Layout, local: SocketAddr) -> Option<u32> {
    let count = u32_le(table, 0)? as usize;
    for i in 0..count {
        let row = table.get(4 + i * layout.row..4 + (i + 1) * layout.row)?;
        let port = u16::from_be_bytes([row[layout.port], row[layout.port + 1]]);
        if port != local.port() {
            continue;
        }
        let addr: IpAddr = if layout.v6 {
            Ipv6Addr::from(<[u8; 16]>::try_from(&row[layout.addr..layout.addr + 16]).ok()?).into()
        } else {
            Ipv4Addr::from(<[u8; 4]>::try_from(&row[layout.addr..layout.addr + 4]).ok()?).into()
        };
        let same = addr == local.ip()
            || addr.is_unspecified()
            || matches!((addr, local.ip()), (IpAddr::V6(a), IpAddr::V4(l)) if a.to_ipv4_mapped() == Some(l));
        if same {
            // pid 0 = TIME_WAIT and similar leftovers: keep looking for the live owner.
            match u32_le(row, layout.pid) {
                Some(0) => continue,
                pid => return pid,
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp4_row(addr: [u8; 4], port: u16, pid: u32) -> Vec<u8> {
        let mut r = vec![0u8; 24];
        r[4..8].copy_from_slice(&addr);
        r[8..10].copy_from_slice(&port.to_be_bytes());
        r[20..24].copy_from_slice(&pid.to_le_bytes());
        r
    }

    #[test]
    fn finds_by_address_and_port() {
        let mut t = 2u32.to_le_bytes().to_vec();
        t.extend(tcp4_row([127, 0, 0, 1], 2080, 4)); // the proxy's own listener
        t.extend(tcp4_row([127, 0, 0, 1], 51234, 9876)); // the client
        let local: SocketAddr = "127.0.0.1:51234".parse().unwrap();
        assert_eq!(find_pid(&t, TCP4, local), Some(9876));
        assert_eq!(find_pid(&t, TCP4, "127.0.0.1:1".parse().unwrap()), None);
        // Truncated dump: no panic.
        assert_eq!(find_pid(&t[..30], TCP4, local), None);
    }

    #[test]
    fn udp_wildcard_and_v6() {
        let mut t = 1u32.to_le_bytes().to_vec();
        let mut row = vec![0u8; 12];
        row[4..6].copy_from_slice(&5353u16.to_be_bytes());
        row[8..12].copy_from_slice(&77u32.to_le_bytes());
        t.extend(row);
        assert_eq!(find_pid(&t, UDP4, "198.18.0.1:5353".parse().unwrap()), Some(77));

        let mut t6 = 1u32.to_le_bytes().to_vec();
        let mut row = vec![0u8; 28];
        row[..16].copy_from_slice(&"::1".parse::<Ipv6Addr>().unwrap().octets());
        row[20..22].copy_from_slice(&443u16.to_be_bytes());
        row[24..28].copy_from_slice(&5u32.to_le_bytes());
        t6.extend(row);
        assert_eq!(find_pid(&t6, UDP6, "[::1]:443".parse().unwrap()), Some(5));
    }

    #[test]
    fn tcp6_rows_skip_pid_zero_and_map_v4() {
        let row = |addr: Ipv6Addr, port: u16, pid: u32| {
            let mut r = vec![0u8; TCP6.row];
            r[..16].copy_from_slice(&addr.octets());
            r[20..22].copy_from_slice(&port.to_be_bytes());
            r[52..56].copy_from_slice(&pid.to_le_bytes());
            r
        };
        let mapped = "::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap();
        let mut t = 3u32.to_le_bytes().to_vec();
        t.extend(row("::1".parse().unwrap(), 4000, 11));
        t.extend(row(mapped, 5000, 0)); // TIME_WAIT leftover
        t.extend(row(mapped, 5000, 12)); // live owner
        assert_eq!(find_pid(&t, TCP6, "[::1]:4000".parse().unwrap()), Some(11));
        // A v4 client on a dual-stack socket; the pid-0 row is skipped.
        assert_eq!(find_pid(&t, TCP6, "127.0.0.1:5000".parse().unwrap()), Some(12));
        assert_eq!(find_pid(&t, TCP6, "[::1]:5000".parse().unwrap()), None);
        assert_eq!(find_pid(&t[..50], TCP6, "[::1]:4000".parse().unwrap()), None);
    }
}
