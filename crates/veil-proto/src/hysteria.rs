//! Hysteria 2 client: QUIC + HTTP/3 authentication, one QUIC stream per TCP
//! connection. One QUIC connection to the server is shared by all streams.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::crypto::rustls::QuicClientConfig;
use rand::Rng;
#[cfg(test)]
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use veil_config::{Protocol, Security, ServerConfig};

use crate::{Address, BoxStream, dial, tls};

const TCP_REQUEST: u64 = 0x401;
/// HTTP status the server answers a successful /auth with.
const AUTH_OK: u16 = 233;

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(format!("hysteria: {}", msg.into()))
}

/// QUIC variable-length integer (RFC 9000 §16).
fn put_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0x3f => out.push(v as u8),
        0x40..=0x3fff => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
        0x4000..=0x3fff_ffff => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

#[cfg(test)]
async fn read_varint<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> io::Result<u64> {
    let first = r.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3f);
    for _ in 1..len {
        v = (v << 8) | u64::from(r.read_u8().await?);
    }
    Ok(v)
}

fn padding(min: usize, max: usize) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let n = rng.gen_range(min..=max);
    (0..n).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())]).collect()
}

pub fn tcp_request(dst: &Address) -> Vec<u8> {
    let addr = dst.to_string();
    let pad = padding(64, 512);
    let mut out = Vec::with_capacity(16 + addr.len() + pad.len());
    put_varint(&mut out, TCP_REQUEST);
    put_varint(&mut out, addr.len() as u64);
    out.extend_from_slice(addr.as_bytes());
    put_varint(&mut out, pad.len() as u64);
    out.extend_from_slice(&pad);
    out
}

struct Session {
    conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
    // Keep HTTP/3 alive: dropping it would close the control streams.
    _h3: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: tokio::task::JoinHandle<()>,
    /// One request/response exchange; a clean round-trip sample.
    auth_rtt: Duration,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.driver.abort();
        self.conn.close(0u32.into(), b"");
    }
}

/// Tears down a half-built session (driver task + QUIC connection) on early
/// returns; `disarm` hands the driver over once the `Session` owns it.
struct SessionGuard {
    conn: quinn::Connection,
    driver: Option<tokio::task::JoinHandle<()>>,
}

impl SessionGuard {
    fn disarm(mut self) -> tokio::task::JoinHandle<()> {
        self.driver.take().expect("guard disarmed twice")
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            driver.abort();
            self.conn.close(0u32.into(), b"");
        }
    }
}

fn timed_out(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, format!("hysteria: {what} timed out"))
}

pub struct HysteriaClient {
    address: String,
    port: u16,
    auth: String,
    sni: String,
    quic: quinn::ClientConfig,
    session: Mutex<Option<Session>>,
    /// Interface pinning for this client only (pings bypassing other VPNs).
    pin: Option<dial::Bypass>,
}

impl HysteriaClient {
    pub fn new(server: &ServerConfig) -> io::Result<Self> {
        let Protocol::Hysteria2 { auth, obfs_password } = &server.protocol else {
            return Err(err("not a hysteria2 server"));
        };
        if obfs_password.is_some() {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "hysteria2 salamander obfuscation is not supported yet"));
        }
        let (sni, insecure) = match &server.security {
            Security::Tls(t) => (t.sni.clone().unwrap_or_else(|| server.address.clone()), t.insecure),
            _ => (server.address.clone(), false),
        };
        let rustls = tls::client_config(&["h3".to_string()], insecure, true)?;
        let crypto = QuicClientConfig::try_from(rustls).map_err(io::Error::other)?;
        let mut quic = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
            .stream_receive_window((8u32 << 20).into())
            .receive_window((20u32 << 20).into())
            .max_concurrent_bidi_streams(1024u32.into());
        quic.transport_config(Arc::new(transport));
        Ok(Self {
            address: server.address.clone(),
            port: server.port,
            auth: auth.clone(),
            sni,
            quic,
            session: Mutex::new(None),
            pin: None,
        })
    }

    /// Sends everything over the given physical interface, whatever the routes say.
    pub fn pinned(mut self, pin: dial::Bypass) -> Self {
        self.pin = Some(pin);
        self
    }

    /// Opens a UDP socket and completes the QUIC handshake with one address.
    async fn quic_connect(&self, addr: SocketAddr) -> io::Result<(quinn::Endpoint, quinn::Connection)> {
        // Pinned to the physical interface in TUN mode, like every other socket of ours.
        let socket = match &self.pin {
            Some(pin) => dial::udp_socket_with(addr.ip(), Some(pin)).await?,
            None => dial::udp_socket_for(addr.ip()).await?,
        }
        .into_std()?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.quic.clone());
        let conn = tokio::time::timeout(dial::CONNECT_TIMEOUT, endpoint.connect(addr, &self.sni).map_err(io::Error::other)?)
            .await
            .map_err(|_| err("QUIC handshake timed out (UDP blocked?)"))?
            .map_err(|e| err(format!("QUIC handshake: {e}")))?;
        Ok((endpoint, conn))
    }

    async fn connect_session(&self) -> io::Result<Session> {
        let target = Address::from_host(&self.address, self.port);
        let addrs = match &self.pin {
            Some(pin) => dial::resolve_with(&target, Some(pin)).await?,
            None => dial::resolve(&target).await?,
        };
        // Try each resolved address in turn (e.g. an AAAA without a route must not block the A record).
        // An overall budget keeps a server with many dead addresses from holding the session
        // lock for 10 s per address; the first attempt always runs.
        let deadline = tokio::time::Instant::now() + dial::CONNECT_TIMEOUT.saturating_mul(2);
        let mut last_err = None;
        let mut established = None;
        for addr in addrs {
            if last_err.is_some() && tokio::time::Instant::now() >= deadline {
                break;
            }
            match self.quic_connect(addr).await {
                Ok(parts) => {
                    established = Some(parts);
                    break;
                }
                Err(e) => last_err = Some(e),
            }
        }
        let (endpoint, conn) = match established {
            Some(parts) => parts,
            None => return Err(last_err.unwrap_or_else(|| err("server has no address"))),
        };

        // The driver is not spawned yet, so on timeout/error nothing leaks
        // except the QUIC connection, which is closed explicitly.
        let h3_setup = tokio::time::timeout(dial::CONNECT_TIMEOUT, h3::client::new(h3_quinn::Connection::new(conn.clone()))).await;
        let (mut driver, mut send_request) = match h3_setup {
            Ok(Ok(parts)) => parts,
            Ok(Err(e)) => {
                conn.close(0u32.into(), b"");
                return Err(err(format!("HTTP/3: {e}")));
            }
            Err(_) => {
                conn.close(0u32.into(), b"");
                return Err(timed_out("HTTP/3 setup"));
            }
        };
        let guard = SessionGuard {
            conn: conn.clone(),
            driver: Some(tokio::spawn(async move {
                let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
            })),
        };
        let request = http::Request::post("https://hysteria/auth")
            .header("Hysteria-Auth", &self.auth)
            .header("Hysteria-CC-RX", "0")
            .header("Hysteria-Padding", String::from_utf8(padding(256, 2048)).unwrap())
            .body(())
            .map_err(io::Error::other)?;
        let sent = std::time::Instant::now();
        let response = tokio::time::timeout(dial::CONNECT_TIMEOUT, async {
            let mut stream = send_request.send_request(request).await.map_err(|e| err(format!("auth request: {e}")))?;
            stream.finish().await.map_err(|e| err(format!("auth request: {e}")))?;
            stream.recv_response().await.map_err(|e| err(format!("auth response: {e}")))
        })
        .await
        .map_err(|_| timed_out("authentication"))??;
        let auth_rtt = sent.elapsed();
        if response.status().as_u16() != AUTH_OK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("hysteria: authentication failed (HTTP {})", response.status()),
            ));
        }
        Ok(Session { conn, _endpoint: endpoint, _h3: send_request, driver: guard.disarm(), auth_rtt })
    }

    /// The live QUIC connection, reconnecting if the previous one died.
    async fn connection(&self) -> io::Result<quinn::Connection> {
        let mut session = self.session.lock().await;
        if let Some(s) = session.as_ref()
            && s.conn.close_reason().is_none()
        {
            return Ok(s.conn.clone());
        }
        let s = self.connect_session().await?;
        let conn = s.conn.clone();
        *session = Some(s);
        Ok(conn)
    }

    pub async fn connect_tcp(&self, dst: &Address) -> io::Result<BoxStream> {
        let conn = self.connection().await?;
        let (mut send, recv) = match open_bi(&conn).await {
            Ok(s) => s,
            // A live connection that merely timed out or hit its stream limit must not be
            // torn down: that would cut every other stream riding on it.
            Err(e) if conn.close_reason().is_none() => return Err(e),
            // The connection died between the check and now: start over once.
            Err(_) => {
                {
                    // Drop the slot only if it still holds the connection that failed;
                    // another task may have already replaced it with a healthy one.
                    let mut slot = self.session.lock().await;
                    if slot.as_ref().is_some_and(|s| s.conn.stable_id() == conn.stable_id()) {
                        *slot = None;
                    }
                }
                open_bi(&self.connection().await?).await?
            }
        };
        tokio::time::timeout(dial::CONNECT_TIMEOUT, send.write_all(&tcp_request(dst)))
            .await
            .map_err(|_| timed_out("sending request"))??;
        // Fast open: hand the stream out now; the server's verdict is checked
        // on the first read instead of costing a round trip per connection.
        Ok(Box::new(HyStream { recv, send, header: Some(Vec::new()), dst: dst.to_string(), leftover: Vec::new() }))
    }

    /// Establishes the QUIC connection ahead of the first request.
    pub async fn warm_up(&self) {
        if let Err(e) = self.connection().await {
            tracing::debug!("hysteria warm-up: {e}");
        }
    }

    /// Round-trip time as measured by QUIC on the live connection, if any.
    pub async fn rtt(&self) -> Option<Duration> {
        self.session.lock().await.as_ref().map(|s| s.conn.rtt())
    }

    /// Network round-trip time to the server, measured by QUIC on a fresh,
    /// authenticated connection (comparable to a TCP connect time).
    pub async fn probe(&self) -> io::Result<Duration> {
        let session = self.connect_session().await?;
        // QUIC's estimate on a fresh connection still includes handshake work on
        // the server; the auth exchange alone is closer to the network RTT.
        Ok(session.conn.rtt().min(session.auth_rtt))
    }
}

async fn open_bi(conn: &quinn::Connection) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
    tokio::time::timeout(dial::CONNECT_TIMEOUT, conn.open_bi())
        .await
        .map_err(|_| timed_out("opening stream"))?
        .map_err(io::Error::other)
}

/// Upper bounds for the server's response header fields (Hysteria 2 uses short ones).
const MAX_MSG_LEN: u64 = 2048;
const MAX_PAD_LEN: u64 = 4096;

/// Parses `status, msg_len, msg, pad_len, pad`; `None` until all of it arrived.
fn parse_response(buf: &[u8]) -> Option<io::Result<(usize, u8, String)>> {
    fn varint(b: &[u8]) -> Option<(u64, usize)> {
        let first = *b.first()?;
        let len = 1usize << (first >> 6);
        let bytes = b.get(..len)?;
        let v = bytes[1..].iter().fold(u64::from(first & 0x3f), |v, x| (v << 8) | u64::from(*x));
        Some((v, len))
    }
    let status = *buf.first()?;
    let mut pos = 1;
    let (msg_len, n) = varint(&buf[pos..])?;
    pos += n;
    if msg_len > MAX_MSG_LEN {
        return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "hysteria: response message too long")));
    }
    let msg_len = msg_len as usize;
    let msg = buf.get(pos..pos + msg_len)?;
    let msg = String::from_utf8_lossy(msg).into_owned();
    pos += msg_len;
    let (pad_len, n) = varint(&buf[pos..])?;
    if pad_len > MAX_PAD_LEN {
        return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "hysteria: response padding too long")));
    }
    pos += n + pad_len as usize;
    if buf.len() < pos {
        return None;
    }
    Some(Ok((pos, status, msg)))
}

/// A proxied TCP connection; validates the server's response header lazily.
struct HyStream {
    recv: quinn::RecvStream,
    send: quinn::SendStream,
    /// Bytes of the response header read so far; `None` once validated.
    header: Option<Vec<u8>>,
    dst: String,
    /// Payload that arrived together with the header.
    leftover: Vec<u8>,
}

impl tokio::io::AsyncRead for HyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        use std::task::{Poll, ready};
        let this = self.get_mut();
        while let Some(head) = this.header.as_mut() {
            if let Some(parsed) = parse_response(head) {
                let (used, status, msg) = parsed?;
                if status != 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("hysteria: server refused {}: {msg}", this.dst),
                    )));
                }
                this.leftover = head.split_off(used);
                this.header = None;
                break;
            }
            let mut tmp = [0u8; 2048];
            let mut rb = tokio::io::ReadBuf::new(&mut tmp);
            ready!(std::pin::Pin::new(&mut this.recv).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "hysteria: stream closed before response")));
            }
            head.extend_from_slice(rb.filled());
        }
        if !this.leftover.is_empty() {
            let n = this.leftover.len().min(buf.remaining());
            buf.put_slice(&this.leftover[..n]);
            this.leftover.drain(..n);
            return Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.get_mut().send), cx, buf)
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.get_mut().send), cx)
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.get_mut().send), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn varints() {
        for v in [0u64, 63, 64, 0x401, 16383, 16384, 1 << 30, (1 << 40) + 5] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(read_varint(&mut &b[..]).await.unwrap(), v, "{v}");
        }
        let mut b = Vec::new();
        put_varint(&mut b, TCP_REQUEST);
        assert_eq!(b, [0x44, 0x01]);
    }

    #[test]
    fn response_parsing() {
        let mut ok = vec![0u8, 2, b'o', b'k', 3, b'x', b'x', b'x'];
        assert!(parse_response(&ok[..5]).is_none(), "incomplete");
        ok.extend_from_slice(b"DATA");
        let (used, status, msg) = parse_response(&ok).unwrap().unwrap();
        assert_eq!((used, status, msg.as_str()), (8, 0, "ok"));
        assert_eq!(&ok[used..], b"DATA");
    }

    #[test]
    fn response_limits() {
        // msg_len above the limit (2049 = 0x4801 as a 2-byte varint) is rejected right away.
        let r = parse_response(&[0u8, 0x48, 0x01]).unwrap();
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);

        // pad_len above the limit (4097 = 0x5001), empty message.
        let r = parse_response(&[0u8, 0, 0x50, 0x01]).unwrap();
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);

        // msg_len == MAX_MSG_LEN (2048 = 0x4800) and pad_len == MAX_PAD_LEN (4096 = 0x5000) are accepted.
        let mut buf = vec![0u8, 0x48, 0x00];
        buf.extend(std::iter::repeat_n(b'm', MAX_MSG_LEN as usize));
        buf.extend_from_slice(&[0x50, 0x00]);
        assert!(parse_response(&buf).is_none(), "padding not yet received");
        buf.extend(std::iter::repeat_n(0u8, MAX_PAD_LEN as usize));
        let (used, status, msg) = parse_response(&buf).unwrap().unwrap();
        assert_eq!((used, status, msg.len()), (buf.len(), 0, MAX_MSG_LEN as usize));
    }

    #[test]
    fn request_layout() {
        let r = tcp_request(&Address::Domain("example.com".into(), 443));
        assert_eq!(&r[..2], &[0x44, 0x01]);
        assert_eq!(r[2] as usize, "example.com:443".len());
        assert_eq!(&r[3..18], b"example.com:443");
    }
}
