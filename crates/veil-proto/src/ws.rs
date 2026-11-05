//! WebSocket transport exposed as a byte stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    read_buf: Bytes,
}

/// Performs the WebSocket handshake over an already connected (possibly TLS) stream.
pub async fn connect<S>(stream: S, host: &str, path: &str) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // `?ed=N` asks for early data in Sec-WebSocket-Protocol; servers work without it.
    let path = strip_early_data(if path.is_empty() { "/" } else { path });
    let mut request = format!("ws://{host}{path}")
        .into_client_request()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let headers = request.headers_mut();
    headers.insert("Host", HeaderValue::from_str(host).map_err(io::Error::other)?);
    headers.insert(
        "User-Agent",
        HeaderValue::from_static("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"),
    );
    let (inner, _resp) = tokio_tungstenite::client_async(request, stream)
        .await
        .map_err(to_io)?;
    Ok(WsStream { inner, read_buf: Bytes::new() })
}

fn strip_early_data(path: &str) -> String {
    let Some((base, query)) = path.split_once('?') else { return path.to_string() };
    let rest: Vec<_> = query.split('&').filter(|kv| !kv.starts_with("ed=")).collect();
    if rest.is_empty() { base.to_string() } else { format!("{base}?{}", rest.join("&")) }
}

fn to_io(e: WsError) -> io::Error {
    match e {
        WsError::Io(e) => e,
        WsError::ConnectionClosed | WsError::AlreadyClosed => io::ErrorKind::BrokenPipe.into(),
        e => io::Error::other(e),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let n = this.read_buf.len().min(buf.remaining());
                buf.put_slice(&this.read_buf.split_to(n));
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.read_buf = data,
                Some(Ok(Message::Text(text))) => this.read_buf = Bytes::copy_from_slice(text.as_bytes()),
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(_)) => {} // ping/pong are answered by tungstenite
                Some(Err(WsError::ConnectionClosed | WsError::AlreadyClosed)) => return Poll::Ready(Ok(())),
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut inner = Pin::new(&mut self.get_mut().inner);
        ready!(inner.as_mut().poll_ready(cx)).map_err(to_io)?;
        inner
            .start_send(Message::Binary(Bytes::copy_from_slice(buf)))
            .map_err(to_io)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx).map_err(to_io)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx).map_err(to_io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_data_param_removed() {
        assert_eq!(strip_early_data("/ws?ed=2048"), "/ws");
        assert_eq!(strip_early_data("/ws?a=1&ed=2048"), "/ws?a=1");
        assert_eq!(strip_early_data("/ws"), "/ws");
    }
}
