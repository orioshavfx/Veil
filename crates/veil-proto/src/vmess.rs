//! VMess with AEAD headers (alterId = 0).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::{SystemTime, UNIX_EPOCH};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use bytes::{Buf, BytesMut};
use md5::{Digest as _, Md5};
use rand::{Rng, RngCore};
use sha2::Sha256;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::Address;
use crate::crypto::{Aead, TAG_LEN};

const MAX_CHUNK: usize = 8192 - 2 - TAG_LEN - 64;

const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    Aes128Gcm = 3,
    ChaCha20Poly1305 = 4,
    None = 5,
}

impl Security {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name.to_ascii_lowercase().as_str() {
            "auto" | "" | "aes-128-gcm" => Ok(Security::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Security::ChaCha20Poly1305),
            "none" => Ok(Security::None),
            other => Err(io::Error::new(io::ErrorKind::Unsupported, format!("vmess security {other}"))),
        }
    }
}

// ---- key derivation ------------------------------------------------------

fn hmac_with(hash: &dyn Fn(&[u8]) -> [u8; 32], key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&hash(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = hash(&inner);
    let mut outer = Vec::with_capacity(96);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

/// Nested-HMAC KDF: HMAC(HMAC(...HMAC(SHA256, "VMess AEAD KDF")..., path[n-1]), key).
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    fn level(path: &[&[u8]], msg: &[u8]) -> [u8; 32] {
        match path.split_last() {
            None => hmac_with(&|m| Sha256::digest(m).into(), b"VMess AEAD KDF", msg),
            Some((last, rest)) => hmac_with(&|m| level(rest, m), last, msg),
        }
    }
    level(path, key)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    kdf(key, path)[..16].try_into().unwrap()
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    kdf(key, path)[..12].try_into().unwrap()
}

pub fn cmd_key(uuid: &Uuid) -> [u8; 16] {
    let mut h = Md5::new();
    md5::Digest::update(&mut h, uuid.as_bytes());
    md5::Digest::update(&mut h, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

fn auth_id(cmd_key: &[u8; 16], now: u64) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&now.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut block[8..12]);
    let crc = crc32fast::hash(&block[..12]);
    block[12..].copy_from_slice(&crc.to_be_bytes());
    let cipher = Aes128::new_from_slice(&kdf16(cmd_key, &[b"AES Auth ID Encryption"])).unwrap();
    cipher.encrypt_block((&mut block).into());
    block
}

fn seal_header(cmd_key: &[u8; 16], header: &[u8], now: u64) -> Vec<u8> {
    let aid = auth_id(cmd_key, now);
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let path = |c: &'static [u8]| [c, &aid[..], &nonce[..]];

    let mut len = (header.len() as u16).to_be_bytes().to_vec();
    Aead::aes128(&kdf16(cmd_key, &path(b"VMess Header AEAD Key_Length")))
        .seal(&kdf12(cmd_key, &path(b"VMess Header AEAD Nonce_Length")), &aid, &mut len);
    let mut payload = header.to_vec();
    Aead::aes128(&kdf16(cmd_key, &path(b"VMess Header AEAD Key")))
        .seal(&kdf12(cmd_key, &path(b"VMess Header AEAD Nonce")), &aid, &mut payload);

    let mut out = Vec::with_capacity(16 + len.len() + 8 + payload.len());
    out.extend_from_slice(&aid);
    out.extend_from_slice(&len);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&payload);
    out
}

fn fnv1a(data: &[u8]) -> u32 {
    data.iter().fold(0x811c9dc5u32, |h, b| (h ^ *b as u32).wrapping_mul(0x01000193))
}

// ---- body chunks ---------------------------------------------------------

/// SHAKE128 stream used to mask chunk sizes and pick padding lengths.
struct ShakeMask(Box<dyn XofReader + Send>);

impl ShakeMask {
    fn new(iv: &[u8]) -> Self {
        let mut s = Shake128::default();
        s.update(iv);
        Self(Box::new(s.finalize_xof()))
    }
    fn next(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.0.read(&mut b);
        u16::from_be_bytes(b)
    }
}

struct ChunkCipher {
    aead: Option<Aead>,
    iv: [u8; 16],
    count: u16,
    mask: ShakeMask,
    padding: bool,
}

impl ChunkCipher {
    fn new(security: Security, key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let aead = match security {
            Security::Aes128Gcm => Some(Aead::aes128(key)),
            Security::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                let first: [u8; 16] = Md5::digest(key).into();
                k[..16].copy_from_slice(&first);
                let second: [u8; 16] = Md5::digest(first).into();
                k[16..].copy_from_slice(&second);
                Some(Aead::chacha(&k))
            }
            Security::None => None,
        };
        let padding = aead.is_some();
        Self { aead, iv: *iv, count: 0, mask: ShakeMask::new(iv), padding }
    }

    fn overhead(&self) -> usize {
        if self.aead.is_some() { TAG_LEN } else { 0 }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&self.iv[..12]);
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.wrapping_add(1);
        n
    }

    fn padding_len(&mut self) -> usize {
        if self.padding { (self.mask.next() % 64) as usize } else { 0 }
    }

    fn seal_chunk(&mut self, payload: &[u8], out: &mut BytesMut) {
        let padding = self.padding_len();
        let size = (payload.len() + self.overhead() + padding) as u16;
        out.extend_from_slice(&(size ^ self.mask.next()).to_be_bytes());
        let mut body = payload.to_vec();
        if self.aead.is_some() {
            let nonce = self.nonce();
            self.aead.as_ref().unwrap().seal(&nonce, &[], &mut body);
        }
        out.extend_from_slice(&body);
        let start = out.len();
        out.resize(start + padding, 0);
        rand::thread_rng().fill_bytes(&mut out[start..]);
    }
}

// ---- stream --------------------------------------------------------------

enum ReadState {
    HeaderLen,
    Header(usize),
    ChunkSize,
    Chunk { size: usize, padding: usize },
    Eof,
}

pub struct VmessStream<S> {
    inner: S,
    // write side
    writer: ChunkCipher,
    pending: BytesMut,
    shutdown_sent: bool,
    // read side
    reader: ChunkCipher,
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_auth: u8,
    state: ReadState,
    rbuf: BytesMut,
    plain: BytesMut,
}

pub fn wrap<S>(inner: S, uuid: &Uuid, security: Security, dst: &Address) -> VmessStream<S> {
    let mut rng = rand::thread_rng();
    let mut body_key = [0u8; 16];
    let mut body_iv = [0u8; 16];
    rng.fill_bytes(&mut body_key);
    rng.fill_bytes(&mut body_iv);
    let resp_auth: u8 = rng.r#gen();

    let mut option = OPT_CHUNK_STREAM | OPT_CHUNK_MASKING;
    if security != Security::None {
        option |= OPT_GLOBAL_PADDING;
    }
    let padding_len: u8 = rng.gen_range(0..16);
    let mut header = vec![1u8];
    header.extend_from_slice(&body_iv);
    header.extend_from_slice(&body_key);
    header.push(resp_auth);
    header.push(option);
    header.push(padding_len << 4 | security as u8);
    header.push(0);
    header.push(1); // TCP
    dst.write_vless(&mut header);
    let start = header.len();
    header.resize(start + padding_len as usize, 0);
    rng.fill_bytes(&mut header[start..]);
    let f = fnv1a(&header);
    header.extend_from_slice(&f.to_be_bytes());

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let ck = cmd_key(uuid);
    let pending = BytesMut::from(&seal_header(&ck, &header, now)[..]);

    let resp_key: [u8; 16] = Sha256::digest(body_key)[..16].try_into().unwrap();
    let resp_iv: [u8; 16] = Sha256::digest(body_iv)[..16].try_into().unwrap();
    VmessStream {
        inner,
        writer: ChunkCipher::new(security, &body_key, &body_iv),
        pending,
        shutdown_sent: false,
        reader: ChunkCipher::new(security, &resp_key, &resp_iv),
        resp_key,
        resp_iv,
        resp_auth,
        state: ReadState::HeaderLen,
        rbuf: BytesMut::new(),
        plain: BytesMut::new(),
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("vmess: {msg}"))
}

impl<S: AsyncRead + AsyncWrite + Unpin> VmessStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.pending.advance(n);
        }
        Poll::Ready(Ok(()))
    }

    /// Reads until `rbuf` holds `need` bytes; `false` on clean EOF.
    fn poll_fill(&mut self, cx: &mut Context<'_>, need: usize) -> Poll<io::Result<bool>> {
        while self.rbuf.len() < need {
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Ok(false));
            }
            self.rbuf.extend_from_slice(rb.filled());
        }
        Poll::Ready(Ok(true))
    }

    /// Advances the read state machine until plaintext is available or EOF.
    fn poll_plain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.plain.is_empty() {
            match self.state {
                ReadState::Eof => return Poll::Ready(Ok(())),
                ReadState::HeaderLen => {
                    if !ready!(self.poll_fill(cx, 2 + TAG_LEN))? {
                        return Poll::Ready(Err(invalid("closed before response header")));
                    }
                    let mut len = self.rbuf.split_to(2 + TAG_LEN).to_vec();
                    Aead::aes128(&kdf16(&self.resp_key, &[b"AEAD Resp Header Len Key"]))
                        .open(&kdf12(&self.resp_iv, &[b"AEAD Resp Header Len IV"]), &[], &mut len)
                        .map_err(|_| invalid("bad response header length (wrong uuid?)"))?;
                    self.state = ReadState::Header(u16::from_be_bytes([len[0], len[1]]) as usize);
                }
                ReadState::Header(len) => {
                    if !ready!(self.poll_fill(cx, len + TAG_LEN))? {
                        return Poll::Ready(Err(invalid("closed inside response header")));
                    }
                    let mut h = self.rbuf.split_to(len + TAG_LEN).to_vec();
                    Aead::aes128(&kdf16(&self.resp_key, &[b"AEAD Resp Header Key"]))
                        .open(&kdf12(&self.resp_iv, &[b"AEAD Resp Header IV"]), &[], &mut h)?;
                    if h.first() != Some(&self.resp_auth) {
                        return Poll::Ready(Err(invalid("response auth mismatch")));
                    }
                    self.state = ReadState::ChunkSize;
                }
                ReadState::ChunkSize => {
                    if !ready!(self.poll_fill(cx, 2))? {
                        self.state = ReadState::Eof;
                        continue;
                    }
                    let padding = self.reader.padding_len();
                    let raw = u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]);
                    self.rbuf.advance(2);
                    let size = (raw ^ self.reader.mask.next()) as usize;
                    if size < padding + self.reader.overhead() {
                        return Poll::Ready(Err(invalid("bad chunk size")));
                    }
                    self.state = ReadState::Chunk { size, padding };
                }
                ReadState::Chunk { size, padding } => {
                    if !ready!(self.poll_fill(cx, size))? {
                        return Poll::Ready(Err(invalid("truncated chunk")));
                    }
                    let mut chunk = self.rbuf.split_to(size).to_vec();
                    chunk.truncate(size - padding);
                    if self.reader.aead.is_some() {
                        let nonce = self.reader.nonce();
                        self.reader.aead.as_ref().unwrap().open(&nonce, &[], &mut chunk)?;
                    }
                    if chunk.is_empty() {
                        self.state = ReadState::Eof;
                        continue;
                    }
                    self.plain.extend_from_slice(&chunk);
                    self.state = ReadState::ChunkSize;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_plain(cx))?;
        let n = this.plain.len().min(buf.remaining());
        buf.put_slice(&this.plain.split_to(n));
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Keep the request header in the same write as the first chunk.
        if this.pending.len() > MAX_CHUNK {
            ready!(this.poll_drain(cx))?;
        }
        let n = buf.len().min(MAX_CHUNK);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        this.writer.seal_chunk(&buf[..n], &mut this.pending);
        if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shutdown_sent {
            this.shutdown_sent = true;
            let mut out = std::mem::take(&mut this.pending);
            this.writer.seal_chunk(&[], &mut out);
            this.pending = out;
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_key_and_kdf_are_stable() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let ck = cmd_key(&uuid);
        assert_eq!(ck.len(), 16);
        // KDF with no path is plain HMAC-SHA256 keyed by the salt.
        use hmac::{Hmac, Mac};
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(b"VMess AEAD KDF").unwrap();
        Mac::update(&mut m, b"key");
        assert_eq!(kdf(b"key", &[]), <[u8; 32]>::from(m.finalize().into_bytes()));
        // One level: HMAC whose inner hash is the level-0 HMAC.
        assert_ne!(kdf(b"key", &[b"a"]), kdf(b"key", &[b"b"]));
    }

    #[test]
    fn fnv() {
        assert_eq!(fnv1a(b""), 0x811c9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c292c);
    }
}
