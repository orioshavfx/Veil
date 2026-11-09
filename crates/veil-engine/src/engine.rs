use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{Context, Result};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};
use veil_config::{RouteAction, RoutingConfig, ServerConfig};
use veil_proto::{Address, ProxyOutbound};

use crate::inbound::mixed;
use crate::router::Router;
use crate::rules::Rules;
use crate::tun::{Tun, TunOptions};

const FIRST_DATA_WAIT: Duration = Duration::from_millis(50);
const IMPLICIT_DIRECT_TIMEOUT: Duration = Duration::from_secs(4);

pub struct EngineConfig {
    pub listen: SocketAddr,
    pub server: ServerConfig,
    pub routing: RoutingConfig,
    /// Directory holding geoip.dat / geosite.dat.
    pub geo_dir: PathBuf,
    /// Capture all system traffic (needs root).
    pub tun: Option<TunOptions>,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub upload: AtomicU64,
    pub download: AtomicU64,
    pub active: AtomicU64,
}

pub(crate) struct Shared {
    pub router: Router,
    pub stats: Arc<Stats>,
}

impl Shared {
    /// Connects to `dst` via the routed outbound and relays until either side closes.
    /// `src` is the client's local endpoint, for per-app routing.
    pub async fn relay<S>(
        &self,
        mut inbound: S,
        dst: Address,
        first: &[u8],
        src: Option<SocketAddr>,
    ) -> std::io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let decision = self.router.decide(&dst, src.map(|a| (crate::process::Proto::Tcp, a))).await;
        let outbound = self.router.outbound(decision.action);
        tracing::debug!("{dst} -> {}", outbound.name());
        let mut remote = if decision.action == RouteAction::Direct && !decision.explicit {
            // Nothing asked for "direct" explicitly: if the site does not open
            // directly (blocked DNS, reset, no route), it is probably censored.
            match tokio::time::timeout(IMPLICIT_DIRECT_TIMEOUT, outbound.connect_tcp(&dst)).await {
                Ok(Ok(r)) => r,
                failed => {
                    let why = match failed {
                        Ok(Err(e)) => e.to_string(),
                        _ => "timed out".to_string(),
                    };
                    tracing::info!("{dst}: direct failed ({why}), retrying via VPN");
                    let proxy = self.router.outbound(RouteAction::Proxy);
                    proxy.connect_tcp(&dst).await.inspect_err(|e| tracing::warn!("{dst} via proxy: {e}"))?
                }
            }
        } else {
            outbound.connect_tcp(&dst).await.inspect_err(|e| {
                tracing::warn!("{dst} via {}: {e}", outbound.name());
            })?
        };
        if !first.is_empty() {
            remote.write_all(first).await?;
            self.stats.upload.fetch_add(first.len() as u64, Ordering::Relaxed);
        } else {
            // Protocol headers ride along with the client's first bytes. If the client
            // is silent (server-speaks-first protocols), send the header on its own.
            let mut buf = vec![0u8; 16 * 1024];
            match tokio::time::timeout(FIRST_DATA_WAIT, inbound.read(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => {}
                Ok(Ok(n)) => {
                    remote.write_all(&buf[..n]).await?;
                    self.stats.upload.fetch_add(n as u64, Ordering::Relaxed);
                }
                Ok(Err(e)) => return Err(e),
            }
        }
        remote.flush().await?;
        self.stats.active.fetch_add(1, Ordering::Relaxed);
        // Bytes are counted as they move, so the speed readout updates continuously
        // instead of once when a connection closes.
        let mut counted = Counted { inner: remote, stats: &self.stats };
        let result = copy_bidirectional(&mut inbound, &mut counted).await;
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
        result.map(|_| ())
    }
}

/// Counts bytes passing through a stream: writes are upload, reads are download.
struct Counted<'a, R> {
    inner: R,
    stats: &'a Stats,
}

impl<R: AsyncRead + Unpin> AsyncRead for Counted<'_, R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &poll {
            let n = buf.filled().len() - before;
            self.stats.download.fetch_add(n as u64, Ordering::Relaxed);
        }
        poll
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for Counted<'_, R> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(n)) = &poll {
            self.stats.upload.fetch_add(*n as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A running proxy. Dropping it (or calling [`Engine::stop`]) closes all connections.
pub struct Engine {
    task: JoinHandle<()>,
    shared: Arc<Shared>,
    tun: Option<Tun>,
    stats: Arc<Stats>,
    local_addr: SocketAddr,
    warm_up: std::sync::Mutex<Option<JoinHandle<()>>>,
}

/// Set by the panic hook of the app or the CLI ([`note_panic`]); cleared when a TUN starts.
pub(crate) static TUN_PANICKED: AtomicBool = AtomicBool::new(false);

/// For a panic hook: records that the process panicked, without touching the system (the
/// hook may run on any thread, in any state). A running TUN then reports
/// [`Engine::tun_failed`] and its owner stops it with the normal teardown.
pub fn note_panic() {
    TUN_PANICKED.store(true, Ordering::SeqCst);
}

impl Engine {
    pub async fn start(config: EngineConfig) -> Result<Self> {
        let outbound: Arc<dyn veil_proto::Outbound> =
            Arc::new(ProxyOutbound::new(config.server.clone()).context("invalid server config")?);
        let rules = Rules::compile(&config.routing, &config.geo_dir).context("invalid routing rules")?;
        let listener = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("cannot listen on {}", config.listen))?;
        let local_addr = listener.local_addr()?;
        let stats = Arc::new(Stats::default());
        let shared = Arc::new(Shared { router: Router::new(rules, outbound.clone()), stats: stats.clone() });
        tracing::info!("mixed inbound listening on {local_addr}");

        let shared_for_tun = shared.clone();
        let shared_for_engine = shared.clone();
        let task = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer)) => {
                            let _ = stream.set_nodelay(true);
                            let shared = shared.clone();
                            conns.spawn(async move {
                                if let Err(e) = mixed::handle(stream, &shared).await {
                                    tracing::debug!("{peer}: {e}");
                                }
                            });
                        }
                        Err(e) => tracing::warn!("accept: {e}"),
                    },
                    Some(_) = conns.join_next(), if !conns.is_empty() => {}
                }
            }
        });
        let tun = match config.tun {
            Some(opts) => match Tun::start(shared_for_tun, opts, &config.server).await {
                Ok(t) => Some(t),
                Err(e) => {
                    // Wait until the listener is really closed, so a retry can bind the port again.
                    task.abort();
                    let _ = task.await;
                    return Err(e);
                }
            },
            None => None,
        };
        // Warm-up starts only after the TUN bypass is installed.
        let warm_up = tokio::spawn(async move { outbound.warm_up().await });
        Ok(Self { task, shared: shared_for_engine, tun, stats, local_addr, warm_up: std::sync::Mutex::new(Some(warm_up)) })
    }

    /// Switches to another server without dropping the listener or TUN.
    pub async fn set_server(&self, server: ServerConfig) -> Result<()> {
        let outbound: Arc<dyn veil_proto::Outbound> =
            Arc::new(ProxyOutbound::new(server.clone()).context("invalid server config")?);
        if let Some(tun) = &self.tun {
            tun.server_changed(&server).await;
        }
        self.shared.router.set_proxy(outbound.clone());
        let handle = tokio::spawn(async move { outbound.warm_up().await });
        if let Some(old) = self.warm_up.lock().unwrap_or_else(|e| e.into_inner()).replace(handle) {
            old.abort();
        }
        tracing::info!("server switched to {}:{}", server.address, server.port);
        Ok(())
    }

    pub fn set_routing(&self, routing: &RoutingConfig, geo_dir: &std::path::Path) -> Result<()> {
        let rules = Rules::compile(routing, geo_dir).context("invalid routing rules")?;
        self.shared.router.set_rules(rules);
        Ok(())
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// True when TUN mode was on and its packet loop has ended on its own (device error), or
    /// (Windows) a panic happened anywhere in the process since the TUN started (see
    /// [`note_panic`]): the tunnel cannot be trusted any more, the engine should be stopped
    /// the normal way. Elsewhere a panic alone does not end the TUN: it leaves nothing
    /// behind in the system that would outlive the process.
    pub fn tun_failed(&self) -> bool {
        let panicked = cfg!(windows) && TUN_PANICKED.load(Ordering::SeqCst);
        self.tun.as_ref().is_some_and(|t| t.is_dead() || panicked)
    }

    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    pub async fn stop(mut self) {
        if let Some(tun) = self.tun.take() {
            tun.stop().await;
        }
        self.abort_warm_up();
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

impl Engine {
    fn abort_warm_up(&self) {
        if let Some(h) = self.warm_up.lock().unwrap_or_else(|e| e.into_inner()).take() {
            h.abort();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.abort_warm_up();
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn counted_counts_upload_and_download() {
        let stats = Stats::default();
        let (near, mut far) = tokio::io::duplex(64);
        let mut counted = Counted { inner: near, stats: &stats };

        counted.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello");
        assert_eq!((stats.upload.load(Ordering::Relaxed), stats.download.load(Ordering::Relaxed)), (5, 0));

        far.write_all(b"0123456789").await.unwrap();
        let mut got = [0u8; 10];
        counted.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"0123456789");
        assert_eq!((stats.upload.load(Ordering::Relaxed), stats.download.load(Ordering::Relaxed)), (5, 10));
    }

    /// A pipe that takes 4 bytes at a time accepts a write in pieces and returns `Pending`
    /// in between: only the bytes actually written may be counted, each exactly once.
    #[tokio::test]
    async fn counted_handles_partial_writes() {
        let stats = Stats::default();
        let (near, mut far) = tokio::io::duplex(4);
        let mut counted = Counted { inner: near, stats: &stats };
        let reader = tokio::spawn(async move {
            let mut got = vec![0u8; 100];
            far.read_exact(&mut got).await.unwrap();
            got
        });
        counted.write_all(&[7u8; 100]).await.unwrap();
        assert_eq!(reader.await.unwrap(), vec![7u8; 100]);
        assert_eq!(stats.upload.load(Ordering::Relaxed), 100);
        assert_eq!(stats.download.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn counted_relays_both_ways() {
        let stats = Stats::default();
        let (mut client, inbound) = tokio::io::duplex(1024);
        let (remote, mut server) = tokio::io::duplex(1024);
        let mut inbound = inbound;
        let relay = async {
            let mut counted = Counted { inner: remote, stats: &stats };
            copy_bidirectional(&mut inbound, &mut counted).await.unwrap();
        };
        let peers = async {
            client.write_all(b"ping").await.unwrap();
            let mut b = [0u8; 4];
            server.read_exact(&mut b).await.unwrap();
            server.write_all(b"pong!!").await.unwrap();
            let mut c = [0u8; 6];
            client.read_exact(&mut c).await.unwrap();
            drop(client);
            drop(server);
        };
        tokio::join!(relay, peers);
        assert_eq!(stats.upload.load(Ordering::Relaxed), 4);
        assert_eq!(stats.download.load(Ordering::Relaxed), 6);
    }
}
