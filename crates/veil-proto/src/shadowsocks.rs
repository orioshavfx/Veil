use std::io;
use std::sync::Arc;

use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address as SsAddress;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Address;

pub struct SsClient {
    context: SharedContext,
    config: ServerConfig,
}

impl SsClient {
    pub fn new(address: &str, port: u16, method: &str, password: &str) -> io::Result<Self> {
        let kind: CipherKind = method
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("unknown cipher {method}")))?;
        let config = ServerConfig::new((address.to_string(), port), password, kind)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        Ok(Self { context: Arc::new(Context::new(ServerType::Local)), config })
    }

    pub fn wrap<S>(&self, stream: S, dst: &Address) -> ProxyClientStream<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let addr = match dst {
            Address::Socket(a) => SsAddress::SocketAddress(*a),
            Address::Domain(d, p) => SsAddress::DomainNameAddress(d.clone(), *p),
        };
        ProxyClientStream::from_stream(self.context.clone(), stream, &self.config, addr)
    }
}
