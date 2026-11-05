//! VLESS with the `xtls-rprx-vision` flow.
//!
//! The inner TLS handshake travels padded through the outer REALITY tunnel; once
//! the inner connection carries TLS 1.3 application data both sides stop
//! wrapping and splice the raw TCP connection ("direct copy").

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::BytesMut;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::Address;
use crate::reality::RealityStream;

pub const FLOW: &str = "xtls-rprx-vision";

const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;

/// Xray's buffer size; one padded block must fit in it.
const BUF_SIZE: usize = 8192;
const TLS_APP_DATA: [u8; 3] = [0x17, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// What we have learned about the inner (tunnelled) TLS connection.
struct TrafficState {
    packets_to_filter: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    remaining_server_hello: i32,
    cipher: u16,
}

impl TrafficState {
    fn new() -> Self {
        Self {
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            remaining_server_hello: -1,
            cipher: 0,
        }
    }

    /// Port of Xray's `XtlsFilterTls` for a single buffer.
    fn filter(&mut self, b: &[u8]) {
        if b.is_empty() {
            return;
        }
        self.packets_to_filter -= 1;
        if b.len() >= 6 {
            if b[..3] == [0x16, 0x03, 0x03] && b[5] == 2 {
                self.remaining_server_hello = (i32::from(b[3]) << 8 | i32::from(b[4])) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                if b.len() >= 79 && self.remaining_server_hello >= 79 {
                    let sid_len = b[43] as usize;
                    if let Some(cs) = b.get(43 + sid_len + 1..43 + sid_len + 3) {
                        self.cipher = u16::from_be_bytes([cs[0], cs[1]]);
                    }
                }
            } else if b[..2] == [0x16, 0x03] && b[5] == 1 {
                self.is_tls = true;
            }
        }
        if self.remaining_server_hello > 0 {
            let end = (self.remaining_server_hello as usize).min(b.len());
            self.remaining_server_hello -= b.len() as i32;
            if b[..end].windows(6).any(|w| w == TLS13_SUPPORTED_VERSIONS) {
                if matches!(self.cipher, 0x1301..=0x1304) && self.cipher != TLS_AES_128_CCM_8_SHA256 {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
            } else if self.remaining_server_hello <= 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

/// True when `data` consists solely of complete TLS application-data records.
fn is_complete_record(data: &[u8]) -> bool {
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() < 5 || rest[..3] != TLS_APP_DATA {
            return false;
        }
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if rest.len() < 5 + len {
            return false;
        }
        rest = &rest[5 + len..];
    }
    true
}

/// Splits data so every block still fits in one Xray buffer after padding.
fn reshape(mut data: &[u8]) -> Vec<&[u8]> {
    let limit = BUF_SIZE - 21;
    let mut out = Vec::new();
    while data.len() >= limit {
        let window = &data[..limit];
        let mut cut = window
            .windows(3)
            .rposition(|w| w == TLS_APP_DATA)
            .filter(|i| *i >= 21)
            .unwrap_or(BUF_SIZE / 2);
        if cut == 0 {
            cut = BUF_SIZE / 2;
        }
        out.push(&data[..cut]);
        data = &data[cut..];
    }
    if !data.is_empty() {
        out.push(data);
    }
    out
}

struct Unpad {
    command: i32,
    content: i32,
    padding: i32,
    current: i32,
}

impl Unpad {
    fn new() -> Self {
        Self { command: -1, content: -1, padding: -1, current: 0 }
    }

    /// Port of Xray's `XtlsUnpadding`: strips framing, returns the content bytes.
    fn process(&mut self, uuid: &[u8; 16], mut b: &[u8]) -> Vec<u8> {
        if self.command == -1 && self.content == -1 && self.padding == -1 {
            if b.len() >= 21 && b[..16] == uuid[..] {
                b = &b[16..];
                self.command = 5;
            } else {
                return b.to_vec();
            }
        }
        let mut out = Vec::with_capacity(b.len());
        while !b.is_empty() {
            if self.command > 0 {
                let byte = i32::from(b[0]);
                b = &b[1..];
                match self.command {
                    5 => self.current = byte,
                    4 => self.content = byte << 8,
                    3 => self.content |= byte,
                    2 => self.padding = byte << 8,
                    1 => self.padding |= byte,
                    _ => {}
                }
                self.command -= 1;
            } else if self.content > 0 {
                let n = (self.content as usize).min(b.len());
                out.extend_from_slice(&b[..n]);
                b = &b[n..];
                self.content -= n as i32;
            } else {
                let n = (self.padding.max(0) as usize).min(b.len());
                b = &b[n..];
                self.padding -= n as i32;
            }
            if self.command <= 0 && self.content <= 0 && self.padding <= 0 {
                if self.current == i32::from(CMD_CONTINUE) {
                    self.command = 5;
                } else {
                    self.command = -1;
                    self.content = -1;
                    self.padding = -1;
                    out.extend_from_slice(b);
                    break;
                }
            }
        }
        out
    }
}

enum RespHeader {
    Version,
    AddonsLen,
    Addons(usize),
    Done,
}

pub struct VisionStream<S> {
    tls: RealityStream<S>,
    uuid: [u8; 16],
    traffic: TrafficState,
    // write side
    request: Option<Vec<u8>>,
    write_uuid: bool,
    is_padding: bool,
    write_direct: bool,
    // read side
    resp: RespHeader,
    unpad: Unpad,
    within_padding: bool,
    read_direct: bool,
    raw_leftover: BytesMut,
    out: BytesMut,
}

pub fn request_header(uuid: &Uuid, dst: &Address) -> Vec<u8> {
    let mut h = vec![0u8];
    h.extend_from_slice(uuid.as_bytes());
    // Addons protobuf: field 1 (flow), length-delimited.
    h.push(2 + FLOW.len() as u8);
    h.push(0x0a);
    h.push(FLOW.len() as u8);
    h.extend_from_slice(FLOW.as_bytes());
    h.push(1); // TCP
    dst.write_vless(&mut h);
    h
}

pub fn wrap<S>(tls: RealityStream<S>, uuid: &Uuid, dst: &Address) -> VisionStream<S> {
    VisionStream {
        tls,
        uuid: *uuid.as_bytes(),
        traffic: TrafficState::new(),
        request: Some(request_header(uuid, dst)),
        write_uuid: true,
        is_padding: true,
        write_direct: false,
        resp: RespHeader::Version,
        unpad: Unpad::new(),
        within_padding: true,
        read_direct: false,
        raw_leftover: BytesMut::new(),
        out: BytesMut::new(),
    }
}

impl<S> VisionStream<S> {
    /// Port of Xray's `XtlsPadding`.
    fn pad(&mut self, content: &[u8], command: u8, long_padding: bool, out: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        let len = content.len();
        let mut padding = if len < 900 && long_padding {
            rng.gen_range(0..500) + 900 - len
        } else {
            rng.gen_range(0..256)
        };
        padding = padding.min((BUF_SIZE - 21).saturating_sub(len));
        if self.write_uuid {
            out.extend_from_slice(&self.uuid);
            self.write_uuid = false;
        }
        out.extend_from_slice(&[command, (len >> 8) as u8, len as u8, (padding >> 8) as u8, padding as u8]);
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
    }

    /// Strips the VLESS response header; returns the remaining slice.
    fn strip_response<'a>(&mut self, mut b: &'a [u8]) -> io::Result<&'a [u8]> {
        while !b.is_empty() {
            match self.resp {
                RespHeader::Done => break,
                RespHeader::Version => {
                    if b[0] != 0 {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "vless: bad response version"));
                    }
                    self.resp = RespHeader::AddonsLen;
                    b = &b[1..];
                }
                RespHeader::AddonsLen => {
                    self.resp = match b[0] {
                        0 => RespHeader::Done,
                        n => RespHeader::Addons(n as usize),
                    };
                    b = &b[1..];
                }
                RespHeader::Addons(n) => {
                    let k = n.min(b.len());
                    b = &b[k..];
                    self.resp = if n == k { RespHeader::Done } else { RespHeader::Addons(n - k) };
                }
            }
        }
        Ok(b)
    }

    fn encode(&mut self, data: &[u8]) -> Vec<u8> {
        if self.traffic.packets_to_filter > 0 {
            self.traffic.filter(data);
        }
        let mut out = self.request.take().unwrap_or_default();
        if !self.is_padding {
            out.extend_from_slice(data);
            return out;
        }
        let complete = is_complete_record(data);
        let blocks = reshape(data);
        let last = blocks.len().saturating_sub(1);
        let mut long_padding = self.traffic.is_tls;
        let mut rest_raw: &[&[u8]] = &[];
        for (i, b) in blocks.iter().enumerate() {
            if self.traffic.is_tls && b.len() >= 6 && b[..3] == TLS_APP_DATA && complete {
                if self.traffic.enable_xtls {
                    self.write_direct = true;
                }
                let mut cmd = CMD_CONTINUE;
                if i == last {
                    cmd = if self.traffic.enable_xtls { CMD_DIRECT } else { CMD_END };
                }
                self.pad(b, cmd, true, &mut out);
                self.is_padding = false;
                long_padding = false;
                continue;
            } else if !self.traffic.is_tls12_or_above && self.traffic.packets_to_filter <= 1 {
                // Matches Xray: finish padding one packet early for old receivers.
                self.is_padding = false;
                self.pad(b, CMD_END, long_padding, &mut out);
                rest_raw = &blocks[i + 1..];
                break;
            }
            let mut cmd = CMD_CONTINUE;
            if i == last && !self.is_padding {
                cmd = if self.traffic.enable_xtls { CMD_DIRECT } else { CMD_END };
            }
            self.pad(b, cmd, long_padding, &mut out);
        }
        for b in rest_raw {
            out.extend_from_slice(b);
        }
        out
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VisionStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.out.is_empty() {
                let n = this.out.len().min(buf.remaining());
                buf.put_slice(&this.out.split_to(n));
                return Poll::Ready(Ok(()));
            }
            if this.read_direct {
                if !this.raw_leftover.is_empty() {
                    this.out = std::mem::take(&mut this.raw_leftover);
                    continue;
                }
                return Pin::new(this.tls.inner_mut()).poll_read(cx, buf);
            }

            let mut tmp = vec![0u8; 32 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut this.tls).poll_read(cx, &mut rb))?;
            let filled = rb.filled().len();
            if filled == 0 {
                return Poll::Ready(Ok(()));
            }
            let chunk = this.strip_response(&tmp[..filled])?.to_vec();
            if chunk.is_empty() {
                continue;
            }
            let mut data = chunk;
            if this.within_padding || this.traffic.packets_to_filter > 0 {
                data = this.unpad.process(&this.uuid, &data);
                if this.unpad.content > 0 || this.unpad.padding > 0 || this.unpad.current == i32::from(CMD_CONTINUE) {
                    this.within_padding = true;
                } else if this.unpad.current == i32::from(CMD_END) {
                    this.within_padding = false;
                } else if this.unpad.current == i32::from(CMD_DIRECT) {
                    this.within_padding = false;
                    this.read_direct = true;
                    // Everything after the direct block arrives unwrapped.
                    let (plain, raw) = this.tls.take_buffered();
                    this.raw_leftover.extend_from_slice(&plain);
                    this.raw_leftover.extend_from_slice(&raw);
                }
            }
            if this.traffic.packets_to_filter > 0 {
                this.traffic.filter(&data);
            }
            this.out.extend_from_slice(&data);
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VisionStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_direct && this.request.is_none() && !this.is_padding {
            ready!(this.tls.poll_drain(cx))?;
            return Pin::new(this.tls.inner_mut()).poll_write(cx, buf);
        }
        if this.tls.pending_len() >= 64 * 1024 {
            ready!(this.tls.poll_drain(cx))?;
        }
        let n = buf.len().min(32 * 1024);
        let encoded = this.encode(&buf[..n]);
        this.tls.queue(&encoded);
        if let Poll::Ready(Err(e)) = this.tls.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(mut out) = this.request.take() {
            // Nothing written yet: send the header with an empty, long-padded block.
            this.pad(&[], CMD_CONTINUE, true, &mut out);
            this.tls.queue(&out);
        }
        ready!(this.tls.poll_drain(cx))?;
        Pin::new(this.tls.inner_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.tls.poll_drain(cx))?;
        Pin::new(this.tls.inner_mut()).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_records() {
        assert!(is_complete_record(&[0x17, 3, 3, 0, 2, 9, 9, 0x17, 3, 3, 0, 0]));
        assert!(!is_complete_record(&[0x17, 3, 3, 0, 2, 9]));
        assert!(!is_complete_record(&[0x16, 3, 3, 0, 0]));
    }

    #[test]
    fn unpad_roundtrip() {
        let uuid = [7u8; 16];
        let mut framed = uuid.to_vec();
        framed.extend_from_slice(&[CMD_CONTINUE, 0, 3, 0, 2]);
        framed.extend_from_slice(b"abc\0\0");
        framed.extend_from_slice(&[CMD_END, 0, 2, 0, 1]);
        framed.extend_from_slice(b"de\0");
        framed.extend_from_slice(b"raw");
        let mut u = Unpad::new();
        // Feed in awkward pieces to exercise the state machine.
        let mut out = u.process(&uuid, &framed[..23]);
        out.extend(u.process(&uuid, &framed[23..]));
        assert_eq!(out, b"abcderaw");
        assert_eq!(u.current, i32::from(CMD_END));
    }

    #[test]
    fn reshape_limits_block_size() {
        let data = vec![1u8; 20000];
        let blocks = reshape(&data);
        assert!(blocks.iter().all(|b| b.len() < BUF_SIZE - 21));
        assert_eq!(blocks.iter().map(|b| b.len()).sum::<usize>(), 20000);
    }

    #[test]
    fn detects_tls13_server_hello() {
        let mut t = TrafficState::new();
        let mut sh = vec![0x16, 3, 3, 0, 90, 2, 0, 0, 86, 3, 3];
        sh.extend_from_slice(&[0u8; 32]);
        sh.push(32);
        sh.extend_from_slice(&[0u8; 32]);
        sh.extend_from_slice(&[0x13, 0x01, 0]);
        sh.extend_from_slice(&[0, 10]);
        sh.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        sh.extend_from_slice(&[0, 0, 0, 0]);
        t.filter(&sh);
        assert!(t.is_tls && t.enable_xtls);
        assert_eq!(t.cipher, 0x1301);
    }
}
