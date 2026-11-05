use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use crate::Address;
use crate::stream::HeaderStream;

const VERSION: u8 = 0;
const CMD_TCP: u8 = 1;

/// VER UUID ADDONS_LEN(0) CMD PORT ATYP ADDR
pub fn request_header(uuid: &Uuid, dst: &Address) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 256);
    out.push(VERSION);
    out.extend_from_slice(uuid.as_bytes());
    out.push(0);
    out.push(CMD_TCP);
    dst.write_vless(&mut out);
    out
}

pub fn wrap<S>(stream: S, uuid: &Uuid, dst: &Address) -> VlessStream<S> {
    VlessStream {
        inner: HeaderStream::new(stream, request_header(uuid, dst)),
        response: ResponseState::Version,
    }
}

enum ResponseState {
    Version,
    AddonsLen,
    Addons(usize),
    Done,
}

/// Strips the `VER ADDONS_LEN ADDONS` response prefix from the server's data.
pub struct VlessStream<S> {
    inner: HeaderStream<S>,
    response: ResponseState,
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessStream<S> {
    fn poll_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut scratch = [0u8; 256];
        loop {
            let want = match self.response {
                ResponseState::Version | ResponseState::AddonsLen => 1,
                ResponseState::Addons(0) => {
                    self.response = ResponseState::Done;
                    continue;
                }
                ResponseState::Addons(n) => n,
                ResponseState::Done => return Poll::Ready(Ok(())),
            };
            let mut rb = ReadBuf::new(&mut scratch[..want]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let got = rb.filled();
            if got.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vless: connection closed before response",
                )));
            }
            self.response = match self.response {
                ResponseState::Version if got[0] != VERSION => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("vless: unexpected response version {}", got[0]),
                    )));
                }
                ResponseState::Version => ResponseState::AddonsLen,
                ResponseState::AddonsLen => ResponseState::Addons(got[0] as usize),
                ResponseState::Addons(n) => ResponseState::Addons(n - got.len()),
                ResponseState::Done => unreachable!(),
            };
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_response(cx))?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn request_and_response() {
        let uuid = Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let (client, mut server) = tokio::io::duplex(1024);
        let mut s = wrap(client, &uuid, &Address::Domain("x.y".into(), 443));
        s.write_all(b"GET").await.unwrap();
        s.flush().await.unwrap();

        let mut req = [0u8; 1 + 16 + 1 + 1 + 2 + 1 + 1 + 3 + 3];
        server.read_exact(&mut req).await.unwrap();
        assert_eq!(req[0], 0);
        assert_eq!(&req[1..17], uuid.as_bytes());
        assert_eq!(&req[17..], &[0, 1, 1, 187, 2, 3, b'x', b'.', b'y', b'G', b'E', b'T']);

        // Response with a 2-byte addon block, split across writes.
        server.write_all(&[0, 2, 9]).await.unwrap();
        server.write_all(&[9, b'o', b'k']).await.unwrap();
        drop(server);
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"ok");
    }
}
