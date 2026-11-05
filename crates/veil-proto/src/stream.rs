use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

pub type BoxStream = Box<dyn AsyncStream>;

pub(crate) fn unsupported(what: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("{what} is not supported yet"))
}

/// Sends `header` together with the first chunk of payload, so that the
/// request header and the first data share one packet.
pub struct HeaderStream<S> {
    inner: S,
    pending: BytesMut,
    /// Length of the caller's buffer merged into `pending`, reported once drained.
    merged: Option<usize>,
}

impl<S> HeaderStream<S> {
    pub fn new(inner: S, header: Vec<u8>) -> Self {
        Self { inner, pending: BytesMut::from(&header[..]), merged: None }
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncWrite + Unpin> HeaderStream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            let _ = self.pending.split_to(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for HeaderStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for HeaderStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending.is_empty() && this.merged.is_none() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if this.merged.is_none() {
            this.pending.extend_from_slice(buf);
            this.merged = Some(buf.len());
        }
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(this.merged.take().unwrap_or(0)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn header_is_prepended_once() {
        let (a, mut b) = tokio::io::duplex(4);
        let mut s = HeaderStream::new(a, b"HDR".to_vec());
        let writer = tokio::spawn(async move {
            s.write_all(b"hello").await.unwrap();
            s.write_all(b"!").await.unwrap();
            s.shutdown().await.unwrap();
        });
        let mut out = Vec::new();
        b.read_to_end(&mut out).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, b"HDRhello!");
    }

    #[tokio::test]
    async fn flush_sends_header_without_payload() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut s = HeaderStream::new(a, b"HDR".to_vec());
        s.flush().await.unwrap();
        let mut out = [0u8; 3];
        b.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"HDR");
    }
}
