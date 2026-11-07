//! Hysteria 2 Salamander obfuscation: every UDP datagram becomes
//! `salt(8) || (payload XOR key)`, `key = BLAKE2b-256(psk || salt)` repeated cyclically.
//! [`SalamanderSocket`] applies it under a quinn endpoint.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rand::Rng;

use crate::blake2b::blake2b_256;

pub const SALT_LEN: usize = 8;
/// Bytes Salamander adds to every datagram.
pub const OVERHEAD: usize = SALT_LEN;

#[derive(Clone)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl fmt::Debug for Salamander {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Salamander(..)")
    }
}

impl Salamander {
    pub fn new(password: &str) -> Self {
        Self { psk: password.as_bytes().to_vec() }
    }

    fn key(&self, salt: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(self.psk.len() + salt.len());
        input.extend_from_slice(&self.psk);
        input.extend_from_slice(salt);
        blake2b_256(&input)
    }

    fn xor(key: &[u8; 32], data: &mut [u8]) {
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= key[i % 32];
        }
    }

    /// Appends `salt || obfuscated payload` to `out`, using the given salt.
    pub fn obfuscate_with_salt(&self, salt: [u8; SALT_LEN], payload: &[u8], out: &mut Vec<u8>) {
        let key = self.key(&salt);
        let start = out.len();
        out.extend_from_slice(&salt);
        out.extend_from_slice(payload);
        Self::xor(&key, &mut out[start + SALT_LEN..]);
    }

    /// Appends the obfuscated form of `payload` (random salt) to `out`.
    pub fn obfuscate(&self, payload: &[u8], out: &mut Vec<u8>) {
        let salt: [u8; SALT_LEN] = rand::thread_rng().r#gen();
        self.obfuscate_with_salt(salt, payload, out);
    }

    /// Deobfuscates a datagram in place; the plaintext ends up at `buf[..n]` and `n` is returned.
    /// `None` (drop the packet) when it is shorter than the salt.
    pub fn deobfuscate_in_place(&self, buf: &mut [u8]) -> Option<usize> {
        if buf.len() < SALT_LEN {
            return None;
        }
        let key = self.key(&buf[..SALT_LEN]);
        buf.copy_within(SALT_LEN.., 0);
        let n = buf.len() - SALT_LEN;
        Self::xor(&key, &mut buf[..n]);
        Some(n)
    }
}

/// Wraps quinn's own UDP socket: outgoing datagrams are obfuscated one by one (no GSO),
/// incoming ones are deobfuscated in `poll_recv`.
#[derive(Debug)]
pub struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    sal: Salamander,
}

impl SalamanderSocket {
    pub fn new(inner: Arc<dyn AsyncUdpSocket>, sal: Salamander) -> Self {
        Self { inner, sal }
    }

    fn send_one(&self, t: &Transmit, payload: &[u8]) -> io::Result<()> {
        let mut wire = Vec::with_capacity(payload.len() + OVERHEAD);
        self.sal.obfuscate(payload, &mut wire);
        self.inner.try_send(&Transmit { destination: t.destination, ecn: t.ecn, contents: &wire, segment_size: None, src_ip: t.src_ip })
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        match transmit.segment_size {
            // We report max_transmit_segments() == 1, so this is the normal case.
            Some(size) if size > 0 && size < transmit.contents.len() => {
                let mut chunks = transmit.contents.chunks(size);
                if let Some(first) = chunks.next() {
                    self.send_one(transmit, first)?;
                }
                // A failure after the first datagram is just packet loss for QUIC.
                for c in chunks {
                    let _ = self.send_one(transmit, c);
                }
                Ok(())
            }
            _ => self.send_one(transmit, transmit.contents),
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for i in 0..n {
            let buf: &mut [u8] = &mut bufs[i];
            let m = &mut meta[i];
            let len = m.len.min(buf.len());
            let stride = if m.stride == 0 || m.stride >= len { len } else { m.stride };
            // With GRO one buffer holds several equal-sized datagrams; each shrinks by the salt,
            // so the packed result keeps a consistent (smaller) stride.
            let mut written = 0;
            let mut pos = 0;
            while pos < len {
                let end = (pos + stride).min(len);
                if let Some(plain) = self.sal.deobfuscate_in_place(&mut buf[pos..end]) {
                    buf.copy_within(pos..pos + plain, written);
                    written += plain;
                }
                pos = end;
            }
            m.stride = if stride >= len { written.max(1) } else { stride.saturating_sub(OVERHEAD).max(1) };
            m.len = written;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let s = Salamander::new("pw");
        for n in [0usize, 1, 31, 32, 33, 64, 1200, 1452] {
            let payload: Vec<u8> = (0..n).map(|i| (i * 13 + 5) as u8).collect();
            let mut wire = Vec::new();
            s.obfuscate(&payload, &mut wire);
            assert_eq!(wire.len(), n + SALT_LEN);
            let k = s.deobfuscate_in_place(&mut wire).unwrap();
            assert_eq!(&wire[..k], &payload[..], "len {n}");
        }
    }

    #[test]
    fn layout_matches_spec() {
        let s = Salamander::new("pw");
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let payload = [0u8; 40];
        let mut wire = Vec::new();
        s.obfuscate_with_salt(salt, &payload, &mut wire);
        assert_eq!(&wire[..8], &salt);
        let mut input = b"pw".to_vec();
        input.extend_from_slice(&salt);
        let key = blake2b_256(&input);
        // Zero payload: the wire body is the key stream, repeating every 32 bytes.
        assert_eq!(&wire[8..40], &key);
        assert_eq!(&wire[40..48], &key[..8]);
    }

    #[test]
    fn wrong_password_gives_garbage() {
        let payload = b"hello quic datagram, long enough to compare".to_vec();
        let mut wire = Vec::new();
        Salamander::new("right").obfuscate(&payload, &mut wire);
        let k = Salamander::new("wrong").deobfuscate_in_place(&mut wire).unwrap();
        assert_eq!(k, payload.len());
        assert_ne!(&wire[..k], &payload[..]);
    }

    #[test]
    fn short_packets_are_dropped() {
        let s = Salamander::new("pw");
        for n in 0..SALT_LEN {
            assert!(s.deobfuscate_in_place(&mut vec![0u8; n]).is_none());
        }
        assert_eq!(s.deobfuscate_in_place(&mut [0u8; SALT_LEN]), Some(0));
    }

    #[tokio::test]
    async fn socket_obfuscates_on_the_wire() {
        use quinn::Runtime as _;
        let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let dest = raw.local_addr().unwrap();
        let ours = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inner = quinn::TokioRuntime.wrap_udp_socket(ours).unwrap();
        let sock = SalamanderSocket::new(inner, Salamander::new("pw"));
        assert_eq!(sock.max_transmit_segments(), 1);
        let payload = vec![0x42u8; 100];
        // A fresh tokio socket may not be marked writable yet: retry on WouldBlock.
        let mut sent = false;
        for _ in 0..100 {
            match sock.try_send(&Transmit { destination: dest, ecn: None, contents: &payload, segment_size: None, src_ip: None }) {
                Ok(()) => {
                    sent = true;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
                Err(e) => panic!("send failed: {e}"),
            }
        }
        assert!(sent, "socket never became writable");
        let mut buf = [0u8; 2048];
        let (n, _) = raw.recv_from(&mut buf).unwrap();
        assert_eq!(n, 100 + SALT_LEN);
        let k = Salamander::new("pw").deobfuscate_in_place(&mut buf[..n]).unwrap();
        assert_eq!(&buf[..k], &payload[..]);
    }
}
