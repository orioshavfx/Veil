//! Chooses an outbound for every connection.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::watch;

use veil_config::RouteAction;
use veil_proto::{Address, BlockOutbound, DirectOutbound, Outbound};

use crate::process::{self, Proto};
use crate::rules::{Rules, Target};

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);

/// Where a connection goes, and whether a rule said so explicitly (as opposed
/// to falling through to the final action).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub action: RouteAction,
    pub explicit: bool,
}

/// Rules and the proxy outbound can be replaced while connections are running;
/// established connections keep the outbound they started with.
///
/// Standby ("VPN off" with the kill switch on): the proxy outbound is refused, so
/// connections that the rules send through the VPN fail instead of going out directly.
/// Direct and block work as usual.
pub struct Router {
    rules: RwLock<Arc<Rules>>,
    proxy: RwLock<Arc<dyn Outbound>>,
    direct: Arc<dyn Outbound>,
    block: Arc<dyn Outbound>,
    /// The standby flag; a watch channel, so running VPN connections can wait for it.
    standby: watch::Sender<bool>,
}

/// The error of a connection refused because the VPN is on standby.
pub fn standby_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "VPN is off (standby): connection blocked")
}

impl Router {
    pub fn new(rules: Rules, proxy: Arc<dyn Outbound>) -> Self {
        Self {
            rules: RwLock::new(Arc::new(rules)),
            proxy: RwLock::new(proxy),
            direct: Arc::new(DirectOutbound),
            block: Arc::new(BlockOutbound),
            standby: watch::Sender::new(false),
        }
    }

    /// Turns standby on or off. Returns the previous state.
    pub fn set_standby(&self, on: bool) -> bool {
        self.standby.send_replace(on)
    }

    pub fn is_standby(&self) -> bool {
        *self.standby.borrow()
    }

    /// Follows the standby flag; [`watch::Receiver::wait_for`] completes once it is on.
    pub fn standby_watch(&self) -> watch::Receiver<bool> {
        self.standby.subscribe()
    }

    pub fn set_proxy(&self, proxy: Arc<dyn Outbound>) {
        *self.proxy.write().unwrap() = proxy;
    }

    pub fn set_rules(&self, rules: Rules) {
        *self.rules.write().unwrap() = Arc::new(rules);
    }

    /// Domain rules first; if nothing matched and IP rules exist, resolve the
    /// domain and try again (Xray's "IPIfNonMatch").
    /// `src` is the client's local endpoint, used to find the originating app.
    pub async fn decide(&self, dst: &Address, src: Option<(Proto, SocketAddr)>) -> Decision {
        let rules = self.rules.read().unwrap().clone();
        let proc_info = match src {
            Some((proto, addr)) if rules.needs_process() => {
                tokio::task::spawn_blocking(move || process::find(proto, addr)).await.ok().flatten()
            }
            _ => None,
        };
        let process = proc_info.as_ref();
        let decision = match self.decide_with(&rules, dst, process).await {
            Some(action) => Decision { action, explicit: true },
            None => Decision { action: rules.final_action(), explicit: false },
        };
        if let Some(p) = process {
            tracing::debug!("{dst} from {} -> {decision:?}", p.app.as_deref().unwrap_or(&p.exe));
        }
        decision
    }

    /// The first matching rule's action, or `None` when no rule matched.
    async fn decide_with(&self, rules: &Rules, dst: &Address, process: Option<&process::ProcessInfo>) -> Option<RouteAction> {
        let (domain, ips): (Option<&str>, Vec<IpAddr>) = match dst {
            Address::Socket(a) => (None, vec![a.ip()]),
            Address::Domain(d, _) => (Some(d.as_str()), Vec::new()),
        };
        let port = dst.port();
        if let Some(action) = rules.first_match(&Target { domain, ips: &ips, port, process }) {
            return Some(action);
        }
        if domain.is_some() && rules.needs_ip() {
            let resolved = tokio::time::timeout(RESOLVE_TIMEOUT, veil_proto::dial::resolve(dst)).await;
            if let Ok(Ok(addrs)) = resolved {
                let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
                if let Some(action) = rules.first_match(&Target { domain, ips: &ips, port, process }) {
                    return Some(action);
                }
            }
        }
        None
    }

    /// The outbound for `action`. On standby the proxy (VPN) outbound is refused with
    /// [`standby_error`]: this is the only way to get it, so nothing reaches the server.
    pub fn outbound(&self, action: RouteAction) -> io::Result<Arc<dyn Outbound>> {
        match action {
            RouteAction::Proxy if self.is_standby() => Err(standby_error()),
            RouteAction::Proxy => Ok(self.proxy.read().unwrap().clone()),
            RouteAction::Direct => Ok(self.direct.clone()),
            RouteAction::Block => Ok(self.block.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> Arc<dyn Outbound> {
        let server = veil_config::ServerConfig {
            address: "127.0.0.1".into(),
            port: 1,
            protocol: veil_config::Protocol::Trojan { password: "x".into() },
            transport: veil_config::Transport::Tcp,
            security: veil_config::Security::None,
        };
        Arc::new(veil_proto::ProxyOutbound::new(server).unwrap())
    }

    #[test]
    fn standby_refuses_only_the_proxy() {
        let rules = Rules::compile(&veil_config::RoutingConfig::proxy_all(), &std::env::temp_dir()).unwrap();
        let r = Router::new(rules, proxy());
        assert!(!r.is_standby());
        assert_eq!(r.outbound(RouteAction::Proxy).unwrap().name(), "proxy");
        let mut rx = r.standby_watch();
        assert!(!r.set_standby(true));
        assert!(r.is_standby());
        assert!(rx.has_changed().unwrap() && *rx.borrow_and_update());
        let err = r.outbound(RouteAction::Proxy).err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(r.outbound(RouteAction::Direct).unwrap().name(), "direct");
        assert_eq!(r.outbound(RouteAction::Block).unwrap().name(), "block");
        // A new server while on standby is stored, but still not handed out.
        r.set_proxy(proxy());
        assert!(r.outbound(RouteAction::Proxy).is_err());
        assert!(r.set_standby(false));
        assert_eq!(r.outbound(RouteAction::Proxy).unwrap().name(), "proxy");
    }
}
