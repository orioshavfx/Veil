//! Readers for v2fly `geoip.dat` / `geosite.dat` (protobuf, decoded by hand).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};

/// Minimal protobuf reader: yields (field number, value) pairs.
struct Pb<'a>(&'a [u8]);

enum Val<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

impl<'a> Pb<'a> {
    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let (&b, rest) = self.0.split_first()?;
            self.0 = rest;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn next_field(&mut self) -> Option<(u64, Val<'a>)> {
        if self.0.is_empty() {
            return None;
        }
        let key = self.varint()?;
        let val = match key & 7 {
            0 => Val::Varint(self.varint()?),
            2 => {
                let len = self.varint()? as usize;
                let (b, rest) = (self.0.get(..len)?, self.0.get(len..)?);
                self.0 = rest;
                Val::Bytes(b)
            }
            1 => {
                self.0 = self.0.get(8..)?;
                Val::Varint(0)
            }
            5 => {
                self.0 = self.0.get(4..)?;
                Val::Varint(0)
            }
            _ => return None,
        };
        Some((key >> 3, val))
    }
}

/// Calls `f(code, entry_bytes)` for each top-level entry whose code is in `wanted`.
fn for_each_entry(data: &[u8], wanted: &[String], mut f: impl FnMut(&str, &[u8])) -> Result<()> {
    let mut list = Pb(data);
    while let Some((field, val)) = list.next_field() {
        let (1, Val::Bytes(entry)) = (field, val) else { continue };
        let mut e = Pb(entry);
        // The country code is the first field in practice; scan to be safe.
        let mut code = None;
        while let Some((f, v)) = e.next_field() {
            if let (1, Val::Bytes(c)) = (f, v) {
                code = std::str::from_utf8(c).ok();
                break;
            }
        }
        if let Some(code) = code {
            let upper = code.to_ascii_uppercase();
            if wanted.contains(&upper) {
                f(&upper, entry);
            }
        }
    }
    if !list.0.is_empty() {
        bail!("truncated geo file");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainKind {
    Keyword,
    Regex,
    Suffix,
    Full,
}

pub type Cidr = (IpAddr, u8);

/// Loads CIDR lists for the given (upper-case) codes.
pub fn load_geoip(path: &Path, codes: &[String]) -> Result<HashMap<String, Vec<Cidr>>> {
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut out: HashMap<String, Vec<Cidr>> = HashMap::new();
    for_each_entry(&data, codes, |code, entry| {
        let list = out.entry(code.to_string()).or_default();
        let mut e = Pb(entry);
        while let Some((f, v)) = e.next_field() {
            let (2, Val::Bytes(cidr)) = (f, v) else { continue };
            let mut c = Pb(cidr);
            let (mut ip, mut prefix) = (None, 0u8);
            while let Some((f, v)) = c.next_field() {
                match (f, v) {
                    (1, Val::Bytes(b)) => {
                        ip = match b.len() {
                            4 => Some(IpAddr::from(<[u8; 4]>::try_from(b).unwrap())),
                            16 => Some(IpAddr::from(<[u8; 16]>::try_from(b).unwrap())),
                            _ => None,
                        }
                    }
                    (2, Val::Varint(p)) => prefix = p as u8,
                    _ => {}
                }
            }
            if let Some(ip) = ip {
                list.push((ip, prefix));
            }
        }
    })?;
    Ok(out)
}

/// Loads domain lists for the given (upper-case) codes.
pub fn load_geosite(path: &Path, codes: &[String]) -> Result<HashMap<String, Vec<(DomainKind, String)>>> {
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut out: HashMap<String, Vec<(DomainKind, String)>> = HashMap::new();
    for_each_entry(&data, codes, |code, entry| {
        let list = out.entry(code.to_string()).or_default();
        let mut e = Pb(entry);
        while let Some((f, v)) = e.next_field() {
            let (2, Val::Bytes(domain)) = (f, v) else { continue };
            let mut d = Pb(domain);
            let (mut kind, mut value) = (DomainKind::Keyword, None);
            while let Some((f, v)) = d.next_field() {
                match (f, v) {
                    (1, Val::Varint(t)) => {
                        kind = match t {
                            1 => DomainKind::Regex,
                            2 => DomainKind::Suffix,
                            3 => DomainKind::Full,
                            _ => DomainKind::Keyword,
                        }
                    }
                    (2, Val::Bytes(b)) => value = std::str::from_utf8(b).ok().map(str::to_ascii_lowercase),
                    _ => {}
                }
            }
            if let Some(value) = value {
                list.push((kind, value));
            }
        }
    })?;
    Ok(out)
}

/// Geosite lists that contain `domain` (as a suffix or full entry), with their
/// sizes. Used to suggest "all domains of this service" for a site rule.
pub fn geosite_codes_for(path: &Path, domain: &str) -> Result<Vec<(String, usize)>> {
    let data = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let mut out = Vec::new();
    let mut list = Pb(&data);
    while let Some((field, val)) = list.next_field() {
        let (1, Val::Bytes(entry)) = (field, val) else { continue };
        let mut e = Pb(entry);
        let (mut code, mut size, mut hit) = (String::new(), 0usize, false);
        while let Some((f, v)) = e.next_field() {
            match (f, v) {
                (1, Val::Bytes(c)) => code = String::from_utf8_lossy(c).to_ascii_lowercase(),
                (2, Val::Bytes(d)) => {
                    size += 1;
                    if hit {
                        continue;
                    }
                    let mut dp = Pb(d);
                    let (mut kind, mut value) = (0u64, "");
                    while let Some((f, v)) = dp.next_field() {
                        match (f, v) {
                            (1, Val::Varint(t)) => kind = t,
                            (2, Val::Bytes(b)) => value = std::str::from_utf8(b).unwrap_or(""),
                            _ => {}
                        }
                    }
                    let value = value.to_ascii_lowercase();
                    hit = match kind {
                        2 => domain == value || domain.ends_with(&format!(".{value}")),
                        3 => domain == value,
                        _ => false,
                    };
                }
                _ => {}
            }
        }
        if hit {
            out.push((code, size));
        }
    }
    Ok(out)
}

/// The narrowest service list for `domain`, skipping broad categories.
pub fn suggest_geosite(path: &Path, domain: &str) -> Result<Option<String>> {
    let broad = |c: &str| {
        c.starts_with("category-") || c.starts_with("geolocation-") || c.starts_with("tld-")
            || matches!(c, "cn" | "private" | "gfw" | "greatfire" | "proxy" | "direct" | "reject" | "apple-cn" | "google-cn")
            || c.contains('@')
    };
    let mut codes: Vec<(String, usize)> = geosite_codes_for(path, domain)?
        .into_iter()
        .filter(|(c, n)| !broad(c) && *n <= 2000)
        .collect();
    codes.sort_by_key(|(_, n)| *n);
    Ok(codes.into_iter().next().map(|(c, _)| c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggestions_from_real_file() {
        let path = Path::new("/opt/homebrew/share/xray/geosite.dat");
        if !path.exists() {
            return;
        }
        let s = |d: &str| suggest_geosite(path, d).unwrap();
        assert_eq!(s("youtube.com").as_deref(), Some("youtube"));
        assert_eq!(s("www.pornhub.com").as_deref(), Some("pornhub"));
        assert_eq!(s("chatgpt.com").as_deref(), Some("openai"));
        assert_eq!(s("no-such-site-xyz.example"), None);
    }

    #[test]
    fn varint_and_fields() {
        // field 1 bytes "RU", field 2 varint 300
        let data = [0x0a, 2, b'R', b'U', 0x10, 0xac, 0x02];
        let mut pb = Pb(&data);
        assert!(matches!(pb.next_field(), Some((1, Val::Bytes(b"RU")))));
        assert!(matches!(pb.next_field(), Some((2, Val::Varint(300)))));
        assert!(pb.next_field().is_none());
    }
}
