use std::io;

use async_trait::async_trait;
use veil_config::{Protocol, Security, ServerConfig, Transport};

use crate::dial::tcp_connect;
use crate::hysteria::HysteriaClient;
use crate::reality::{self, RealityParams};
use crate::shadowsocks::SsClient;
use crate::stream::unsupported;
use crate::tls::TlsClient;
use crate::{Address, BoxStream, trojan, vision, vless, vmess, ws};

#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    async fn connect_tcp(&self, dst: &Address) -> io::Result<BoxStream>;
    /// Prepares long-lived connections (QUIC) before the first request.
    async fn warm_up(&self) {}
}

pub struct DirectOutbound;

#[async_trait]
impl Outbound for DirectOutbound {
    fn name(&self) -> &str {
        "direct"
    }
    async fn connect_tcp(&self, dst: &Address) -> io::Result<BoxStream> {
        Ok(Box::new(tcp_connect(dst).await?))
    }
}

pub struct BlockOutbound;

#[async_trait]
impl Outbound for BlockOutbound {
    fn name(&self) -> &str {
        "block"
    }
    async fn connect_tcp(&self, dst: &Address) -> io::Result<BoxStream> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{dst} blocked by rule")))
    }
}

/// An outbound built from a profile: TCP -> security -> transport -> protocol.
pub struct ProxyOutbound {
    server: ServerConfig,
    tls: Option<TlsClient>,
    reality: Option<RealityParams>,
    ss: Option<SsClient>,
    /// Hysteria runs over its own QUIC connection instead of the TCP stack.
    hysteria: Option<HysteriaClient>,
}

impl ProxyOutbound {
    pub fn new(server: ServerConfig) -> io::Result<Self> {
        if let Protocol::Hysteria2 { .. } = server.protocol {
            let hysteria = Some(HysteriaClient::new(&server)?);
            return Ok(Self { server, tls: None, reality: None, ss: None, hysteria });
        }
        let tls = match &server.security {
            Security::None => None,
            Security::Tls(t) => {
                let sni = t.sni.clone().unwrap_or_else(|| match &server.transport {
                    Transport::Ws { host: Some(h), .. } => h.clone(),
                    _ => server.address.clone(),
                });
                let alpn = if t.alpn.is_empty() {
                    // WebSocket requires HTTP/1.1; offering h2 would break the upgrade.
                    match server.transport {
                        Transport::Ws { .. } => vec!["http/1.1".to_string()],
                        Transport::Grpc { .. } => vec!["h2".to_string()],
                        Transport::Tcp => Vec::new(),
                    }
                } else {
                    t.alpn.clone()
                };
                Some(TlsClient::new(&sni, &alpn, t.insecure)?)
            }
            Security::Reality(_) => None,
        };
        let reality = match &server.security {
            Security::Reality(r) => Some(RealityParams::new(&r.sni, &r.public_key, &r.short_id)?),
            _ => None,
        };
        if let Transport::Grpc { .. } = server.transport {
            return Err(unsupported("gRPC transport"));
        }
        let ss = match &server.protocol {
            Protocol::Shadowsocks { method, password } => {
                Some(SsClient::new(&server.address, server.port, method, password)?)
            }
            Protocol::Vless { flow: Some(flow), .. } if !flow.is_empty() => {
                if flow != vision::FLOW {
                    return Err(unsupported(format!("VLESS flow {flow}")));
                }
                if reality.is_none() || server.transport != Transport::Tcp {
                    return Err(unsupported("xtls-rprx-vision without REALITY over TCP"));
                }
                None
            }
            Protocol::Vmess { alter_id, cipher, .. } => {
                if *alter_id != 0 {
                    return Err(unsupported("VMess with alterId > 0 (legacy MD5 auth)"));
                }
                vmess::Security::parse(cipher)?;
                None
            }
            _ => None,
        };
        Ok(Self { server, tls, reality, ss, hysteria: None })
    }
}

#[async_trait]
impl Outbound for ProxyOutbound {
    fn name(&self) -> &str {
        "proxy"
    }

    async fn warm_up(&self) {
        if let Some(h) = &self.hysteria {
            h.warm_up().await;
        }
    }

    async fn connect_tcp(&self, dst: &Address) -> io::Result<BoxStream> {
        if let Some(h) = &self.hysteria {
            return h.connect_tcp(dst).await;
        }
        let s = &self.server;
        let mut stream: BoxStream =
            Box::new(tcp_connect(&Address::from_host(&s.address, s.port)).await?);
        if let Some(tls) = &self.tls {
            stream = Box::new(tls.connect(stream).await?);
        }
        if let Some(params) = &self.reality {
            let tls = reality::connect(stream, params).await?;
            if let Protocol::Vless { uuid, flow: Some(flow) } = &s.protocol
                && flow == vision::FLOW
            {
                return Ok(Box::new(vision::wrap(tls, uuid, dst)));
            }
            stream = Box::new(tls);
        }
        if let Transport::Ws { path, host } = &s.transport {
            let host = host.as_deref().unwrap_or(&s.address);
            stream = Box::new(ws::connect(stream, host, path).await?);
        }
        Ok(match &s.protocol {
            Protocol::Vless { uuid, .. } => Box::new(vless::wrap(stream, uuid, dst)),
            Protocol::Trojan { password } => Box::new(trojan::wrap(stream, password, dst)),
            Protocol::Shadowsocks { .. } => Box::new(self.ss.as_ref().unwrap().wrap(stream, dst)),
            Protocol::Vmess { uuid, cipher, .. } => {
                Box::new(vmess::wrap(stream, uuid, vmess::Security::parse(cipher)?, dst))
            }
            Protocol::Hysteria2 { .. } => {
                return Err(io::Error::other("hysteria2 outbound is not initialised"));
            }
        })
    }
}
