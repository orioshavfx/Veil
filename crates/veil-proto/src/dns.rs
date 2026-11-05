//! Just enough DNS wire format for a fake-IP server and a stub resolver.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    /// Byte offset just past the question section.
    pub end: usize,
}

/// Reads a (possibly compressed) name starting at `pos`; returns (name, position after it).
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = (len & 0x3f) << 8 | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = ptr;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    None
}

fn u16_at(msg: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]))
}

/// Parses the first question of a query.
pub fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < 12 || u16_at(msg, 4)? == 0 {
        return None;
    }
    let (name, pos) = read_name(msg, 12)?;
    let qtype = u16_at(msg, pos)?;
    Some(Question { id: u16_at(msg, 0)?, name, qtype, end: pos + 4 })
}

/// Builds a response echoing the question with the given address answers.
pub fn build_response(query: &[u8], q: &Question, answers: &[IpAddr], ttl: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.end + answers.len() * 28);
    out.extend_from_slice(&query[..2]);
    let rd = query[2] & 0x01;
    out.extend_from_slice(&[0x80 | rd, 0x80]); // QR, RD copied, RA, NOERROR
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..q.end]);
    for ip in answers {
        out.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        let (ty, data): (u16, Vec<u8>) = match ip {
            IpAddr::V4(a) => (TYPE_A, a.octets().to_vec()),
            IpAddr::V6(a) => (TYPE_AAAA, a.octets().to_vec()),
        };
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}

pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(18 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len().min(63) as u8);
        out.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out
}

/// Extracts A/AAAA records and the minimum TTL from a response.
pub fn parse_answers(msg: &[u8], id: u16) -> Option<(Vec<IpAddr>, u32)> {
    if u16_at(msg, 0)? != id || msg[2] & 0x80 == 0 {
        return None;
    }
    let qd = u16_at(msg, 4)?;
    let an = u16_at(msg, 6)?;
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(msg, pos)?.1 + 4;
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        pos = read_name(msg, pos)?.1;
        let ty = u16_at(msg, pos)?;
        let rr_ttl = u32::from_be_bytes(msg.get(pos + 4..pos + 8)?.try_into().ok()?);
        let len = u16_at(msg, pos + 8)? as usize;
        let data = msg.get(pos + 10..pos + 10 + len)?;
        match (ty, len) {
            (TYPE_A, 4) => ips.push(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?))),
            (TYPE_AAAA, 16) => ips.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
            _ => {}
        }
        if matches!(ty, TYPE_A | TYPE_AAAA) {
            ttl = ttl.min(rr_ttl);
        }
        pos += 10 + len;
    }
    Some((ips, if ttl == u32::MAX { 60 } else { ttl }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_response_roundtrip() {
        let q = build_query(0x1234, "Example.COM", TYPE_A);
        let parsed = parse_question(&q).unwrap();
        assert_eq!(parsed.name, "example.com");
        assert_eq!(parsed.qtype, TYPE_A);
        let ip: IpAddr = "198.18.0.7".parse().unwrap();
        let resp = build_response(&q, &parsed, &[ip], 300);
        assert_eq!(parse_answers(&resp, 0x1234), Some((vec![ip], 300)));
        // Empty answer (used for AAAA in fake-IP mode).
        let resp = build_response(&q, &parsed, &[], 300);
        assert_eq!(parse_answers(&resp, 0x1234), Some((vec![], 60)));
        assert_eq!(parse_answers(&resp, 0x9999), None);
    }
}
