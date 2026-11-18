//! TUN mode: capture all traffic through a utun device.
//!
//! DNS queries are answered with fake addresses from 198.18.0.0/15, so TCP
//! connections arrive with the original domain name and the proxy server does
//! the real resolution (no DNS leaks, domain rules keep working).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackUdpStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::task::JoinHandle;
use tun_rs::{AsyncDevice, DeviceBuilder};
use veil_config::RouteAction;
use veil_proto::dial::{self, Bypass};
use veil_proto::{Address, dns};
pub use veil_sysproxy::TunRoutes;
use veil_config::ServerConfig;

use crate::engine::Shared;

const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
const TUN_PREFIX: u8 = 15;
/// What the system resolver is pointed at; every UDP/53 packet is answered anyway.
pub const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const TUN_ADDR6: Ipv6Addr = Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1);
const FAKE_TTL: u32 = 300;
const UDP_IDLE: Duration = Duration::from_secs(60);
/// Tried after the system DNS server, which may be unreachable or censor answers.
const FALLBACK_DNS: [IpAddr; 3] = [
    IpAddr::V4(Ipv4Addr::new(77, 88, 8, 8)),
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
];
/// Idle established TCP connections are dropped after this long.
const TCP_IDLE: Duration = Duration::from_secs(600);

/// How often the TUN looks for a change of the physical network.
const NET_POLL: Duration = Duration::from_secs(3);
/// How many polls in a row must see the same new network before the TUN follows it
/// (switching networks passes through short-lived states).
const NET_STABLE_POLLS: u32 = 2;

/// The physical interface carrying the default route, and DNS servers usable
/// through it, for sockets that must bypass any tunnel (ours or another VPN's).
pub fn physical_bypass() -> Result<(String, Bypass)> {
    physical_net().map(|(phys, bypass, _)| (phys, bypass))
}

/// Like [`physical_bypass`], plus the system's own DNS servers (without the fallbacks).
fn physical_net() -> Result<(String, Bypass, Vec<IpAddr>)> {
    let phys = veil_sysproxy::default_interface()?;
    let if_index = interface_index(&phys)?;
    let sys = filter_system_dns(veil_sysproxy::system_dns()?);
    let dns = with_fallbacks(&sys);
    Ok((phys, Bypass { if_index, dns }, sys))
}

/// System DNS servers usable directly: not loopback and not our own TUN resolver.
fn filter_system_dns(sys: Vec<IpAddr>) -> Vec<IpAddr> {
    sys.into_iter()
        .filter(|ip| !ip.is_loopback() && !FakeIp::is_fake(*ip) && *ip != IpAddr::V4(DNS_ADDR))
        .collect()
}

/// The bypass DNS list: the system servers first, then [`FALLBACK_DNS`].
fn with_fallbacks(sys: &[IpAddr]) -> Vec<IpAddr> {
    let mut dns = sys.to_vec();
    for ip in FALLBACK_DNS {
        if !dns.contains(&ip) {
            dns.push(ip);
        }
    }
    dns
}

/// Where our own (bypassing) traffic leaves the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NetState {
    phys: String,
    gateway: Option<IpAddr>,
    /// The system's own DNS servers; `None` when it reports none usable (on macOS our DNS
    /// override hides them while the TUN is up), which says nothing about a change.
    dns: Option<Vec<IpAddr>>,
}

impl NetState {
    fn new(phys: String, gateway: Option<IpAddr>, sys_dns: Vec<IpAddr>) -> Self {
        Self { phys, gateway, dns: (!sys_dns.is_empty()).then_some(sys_dns) }
    }
}

/// An observation the watcher may act on: a real interface (not our TUN) with a gateway.
/// Without one the network is gone or switching: nothing is changed then.
fn usable_observation(seen: NetState, tun_name: &str) -> Option<NetState> {
    (seen.gateway.is_some() && !seen.phys.is_empty() && seen.phys != tun_name).then_some(seen)
}

/// Whether `seen` is another network than `cur`: interface, gateway or (when known) DNS.
fn network_changed(cur: &NetState, seen: &NetState) -> bool {
    cur.phys != seen.phys || cur.gateway != seen.gateway || (seen.dns.is_some() && seen.dns != cur.dns)
}

/// The state to switch to: `seen`, keeping the known DNS servers when they cannot be seen
/// and the interface and gateway are the same (another network: its DNS is unknown).
fn next_state(cur: &NetState, seen: &NetState) -> NetState {
    let same_link = cur.phys == seen.phys && cur.gateway == seen.gateway;
    let dns = seen.dns.clone().or_else(|| if same_link { cur.dns.clone() } else { None });
    NetState { phys: seen.phys.clone(), gateway: seen.gateway, dns }
}

/// Follows a new network only after [`NET_STABLE_POLLS`] identical observations in a row.
#[derive(Debug, Default)]
struct NetDebounce {
    candidate: Option<NetState>,
    hits: u32,
}

impl NetDebounce {
    /// Feeds one poll (`None`: no usable network). Returns the state to switch to, once.
    fn feed(&mut self, cur: &NetState, seen: Option<NetState>) -> Option<NetState> {
        let Some(seen) = seen.filter(|s| network_changed(cur, s)) else {
            *self = Self::default();
            return None;
        };
        if self.candidate.as_ref() == Some(&seen) {
            self.hits += 1;
        } else {
            self.candidate = Some(seen.clone());
            self.hits = 1;
        }
        if self.hits < NET_STABLE_POLLS {
            return None;
        }
        *self = Self::default();
        Some(next_state(cur, &seen))
    }
}

/// The physical network as seen now, by the same calls as at start. Blocking.
fn probe_network(tun_name: &str) -> Option<NetState> {
    #[cfg(windows)]
    let (phys, gateway, sys) = veil_sysproxy::default_route_snapshot().ok()?;
    #[cfg(not(windows))]
    let (phys, gateway, sys) = (
        veil_sysproxy::default_interface().ok()?,
        veil_sysproxy::default_gateway().ok(),
        veil_sysproxy::system_dns().unwrap_or_default(),
    );
    usable_observation(NetState::new(phys, gateway, filter_system_dns(sys)), tun_name)
}

/// Routing state that follows the physical network; shared with the watcher task.
struct NetCfg {
    state: NetState,
    /// We added the scoped default route on `state.phys` (and must remove it).
    scoped_default: bool,
    /// Proxy server addresses that have to go around the tunnel.
    servers: Vec<IpAddr>,
    /// Host routes in place, through `state.gateway`.
    host_routes: Vec<IpAddr>,
}

#[cfg(unix)]
fn interface_index(name: &str) -> Result<NonZeroU32> {
    NonZeroU32::new(unsafe { libc::if_nametoindex(std::ffi::CString::new(name)?.as_ptr()) })
        .with_context(|| format!("unknown interface {name}"))
}

#[cfg(windows)]
fn interface_index(name: &str) -> Result<NonZeroU32> {
    veil_sysproxy::interface_index(name)
}

#[derive(Debug, Clone)]
pub struct TunOptions {
    pub mtu: u16,
    /// Where to keep the DNS settings that were replaced, for crash recovery.
    pub dns_backup: PathBuf,
    pub routes: TunRoutes,
}

/// Bidirectional domain <-> fake address map.
pub struct FakeIp {
    inner: Mutex<FakeInner>,
}

struct FakeInner {
    next: u32,
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
}

impl FakeIp {
    // 198.18.0.0/15 minus the network, tun and DNS addresses, minus broadcast.
    const FIRST: u32 = u32::from_be_bytes([198, 18, 0, 3]);
    const LAST: u32 = u32::from_be_bytes([198, 19, 255, 254]);

    pub fn new() -> Self {
        Self { inner: Mutex::new(FakeInner { next: Self::FIRST, by_name: HashMap::new(), by_ip: HashMap::new() }) }
    }

    pub fn lookup_or_assign(&self, name: &str) -> Ipv4Addr {
        let mut g = self.inner.lock().unwrap();
        if let Some(ip) = g.by_name.get(name) {
            return *ip;
        }
        let ip = Ipv4Addr::from(g.next);
        g.next = if g.next >= Self::LAST { Self::FIRST } else { g.next + 1 };
        // Recycle the slot when the pool wraps around.
        if let Some(old) = g.by_ip.insert(ip, name.to_string()) {
            g.by_name.remove(&old);
        }
        g.by_name.insert(name.to_string(), ip);
        ip
    }

    pub fn domain(&self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else { return None };
        self.inner.lock().unwrap().by_ip.get(&v4).cloned()
    }

    pub fn is_fake(ip: IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v4) if (Self::FIRST..=Self::LAST).contains(&u32::from(v4)))
    }
}

impl Default for FakeIp {
    fn default() -> Self {
        Self::new()
    }
}

/// tun-rs device as a packet-per-read stream for ipstack.
struct TunIo(AsyncDevice);

impl AsyncRead for TunIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let n = std::task::ready!(self.0.poll_recv(cx, buf.initialize_unfilled()))?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TunIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.poll_send(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct Tun {
    name: String,
    task: JoinHandle<()>,
    dns_backup: PathBuf,
    /// Physical interface, gateway, scoped default and host routes: always the current ones,
    /// the network watcher updates them when the physical network changes.
    net: Arc<tokio::sync::Mutex<NetCfg>>,
    /// Ends the network watcher (so does dropping it).
    watch_stop: Option<tokio::sync::oneshot::Sender<()>>,
    watcher: Option<JoinHandle<()>>,
    /// The packet loop ended on its own (device error): nothing is tunnelled any more.
    dead: Arc<AtomicBool>,
    /// Our NRPT rule is (or may be) in the system and has to be removed.
    #[cfg(windows)]
    nrpt: Arc<AtomicBool>,
}

/// The decisions around the Windows NRPT rule, kept free of I/O. The rule sends every DNS
/// name to our resolver and is stored in the registry, so it outlives a crashed process:
/// with nobody answering on [`DNS_ADDR`] it takes the whole system's DNS down. Hence the
/// TUN does not start at all unless the resolver answers a probe (before any route or DNS
/// setting), and the rule is checked once added.
#[cfg(any(windows, test))]
mod nrpt {
    use veil_proto::dns;

    use super::FakeIp;

    /// Name asked for by the probe; any name gets a fake address.
    pub const PROBE_NAME: &str = "example.com";

    /// The DNS probe in `bring_up`: one query per entry, each waiting that long for the
    /// answer. Growing pauses, about 14 s in all: a first start may still be installing the
    /// driver, and a fresh address can stay unusable for a moment.
    pub const PROBE_WAITS: [std::time::Duration; 7] = [
        std::time::Duration::from_millis(500),
        std::time::Duration::from_millis(1000),
        std::time::Duration::from_millis(1500),
        std::time::Duration::from_millis(2000),
        std::time::Duration::from_millis(3000),
        std::time::Duration::from_millis(3000),
        std::time::Duration::from_millis(3000),
    ];

    pub fn probe_total() -> std::time::Duration {
        PROBE_WAITS.iter().sum()
    }

    /// Whether `resp` is our fake-IP resolver's answer to the probe query `id`.
    pub fn probe_answered(id: u16, resp: &[u8]) -> bool {
        dns::parse_answers(resp, id).is_some_and(|(ips, _)| ips.iter().any(|ip| FakeIp::is_fake(*ip)))
    }

    /// The probe query: an A question for [`PROBE_NAME`].
    pub fn probe_query(id: u16) -> Vec<u8> {
        dns::build_query(id, PROBE_NAME, dns::TYPE_A)
    }
}

impl Tun {
    pub(crate) async fn start(shared: Arc<Shared>, opts: TunOptions, server: &ServerConfig) -> Result<Self> {
        #[cfg(unix)]
        if unsafe { libc::geteuid() } != 0 {
            anyhow::bail!("TUN mode needs root: run with sudo");
        }
        // One TUN setup or cleanup at a time across processes (Windows): the guard of a
        // dead run must not clean up under a new start, nor read a half-written journal.
        #[cfg(windows)]
        let _setup_lock = blocking(veil_sysproxy::tun_setup_lock).await?;
        let t0 = std::time::Instant::now();
        let step = |what: &str| tracing::info!("TUN start: {what} (+{:.1}s)", t0.elapsed().as_secs_f32());
        step("setup lock taken");
        // A panic before this TUN existed says nothing about it.
        crate::engine::TUN_PANICKED.store(false, Ordering::SeqCst);
        // Undo leftovers of a run that crashed before touching anything else.
        let backup = opts.dns_backup.clone();
        blocking(move || veil_sysproxy::dns_restore(&backup)).await??;
        step("leftover DNS checked");

        let (phys, bypass, sys_dns) = blocking(physical_net).await??;
        let upstream = bypass.dns.clone();
        let gateway = blocking(|| veil_sysproxy::default_gateway().ok()).await?;
        step("gateway found");
        tracing::info!("physical interface {phys}, gateway {gateway:?}, direct DNS {upstream:?}");
        let state = NetState::new(phys, gateway, sys_dns);
        dial::set_bypass(Some(bypass));
        // Host routes of a run that died without cleaning up would outlive it.
        #[cfg(windows)]
        if let Some(gw) = gateway {
            let _ = blocking(move || veil_sysproxy::cleanup_orphan_host_routes(gw)).await;
        }

        step("starting the adapter");
        let result = match Self::bring_up(shared, &opts, state).await {
            // Quitting meanwhile: take down what was set up (routes, DNS) instead of going on.
            Ok(tun) if crate::engine::shutting_down() => {
                tun.stop().await;
                Err(cancelled())
            }
            r => r,
        };
        step(if result.is_ok() { "adapter and routes up" } else { "failed" });
        if let Ok(tun) = &result {
            // From here on the system depends on this process: have someone watch it.
            #[cfg(windows)]
            veil_sysproxy::spawn_tun_guard();
            tun.server_changed(server).await;
            // Last, with the stack running and the server reachable around the tunnel.
            #[cfg(windows)]
            if !crate::engine::shutting_down() {
                tun.enable_nrpt().await;
            }
        }
        if result.is_err() {
            dial::set_bypass(None);
            let backup = opts.dns_backup.clone();
            let _ = blocking(move || veil_sysproxy::dns_restore(&backup)).await;
        }
        result
    }

    /// Scoped default route, split routes and DNS override; undoes itself on failure.
    /// Returns whether a scoped default route was added.
    async fn setup_system(name: &str, phys: &str, gateway: Option<IpAddr>, opts: &TunOptions) -> Result<bool> {
        check_not_quitting()?;
        let (name, phys) = (name.to_string(), phys.to_string());
        // Keep our own sockets (pinned to the physical interface) routable once
        // the split routes send everything else into the tunnel.
        let scoped_default = match gateway {
            Some(gw) if opts.routes != TunRoutes::Domains => {
                let phys = phys.clone();
                blocking(move || veil_sysproxy::add_scoped_default(&phys, gw)).await?
            }
            _ => false,
        };
        let undo = || undo_routes(name.clone(), phys.clone(), scoped_default);
        if let Err(e) = check_not_quitting() {
            undo().await;
            return Err(e);
        }
        let routes = opts.routes;
        let n = name.clone();
        if let Err(e) = blocking(move || veil_sysproxy::add_tun_routes(&n, routes)).await.and_then(|r| r) {
            undo().await;
            return Err(e);
        }
        if let Err(e) = check_not_quitting() {
            undo().await;
            return Err(e);
        }
        let backup = opts.dns_backup.clone();
        if let Err(e) = blocking(move || veil_sysproxy::dns_override(&[IpAddr::V4(DNS_ADDR)], &backup))
            .await
            .and_then(|r| r)
        {
            undo().await;
            return Err(e);
        }
        tracing::info!("TUN {name} up ({:?})", opts.routes);
        Ok(scoped_default)
    }

    async fn bring_up(shared: Arc<Shared>, opts: &TunOptions, state: NetState) -> Result<Self> {
        let (phys, gateway) = (state.phys.clone(), state.gateway);
        let builder = DeviceBuilder::new();
        // A fixed alias: cleanup and veil-rescue.ps1 recognise our adapter by it (and its address).
        #[cfg(windows)]
        let builder = builder.name(veil_sysproxy::TUN_ADAPTER_NAME);
        let dev = builder
            .ipv4(TUN_ADDR, TUN_PREFIX, None)
            .ipv6(TUN_ADDR6, 64)
            .mtu(opts.mtu)
            .build_async()
            .context("cannot create TUN device (on Windows: run as administrator, wintun.dll next to the exe)")?;
        let name = dev.name()?;
        tracing::info!("TUN adapter {name} created");
        #[cfg(not(windows))]
        let scoped_default = Self::setup_system(&name, &phys, gateway, opts).await?;

        // Windows: the packet stack goes first: nothing in the system points at the device yet, so
        // a failure up to the end of the DNS probe leaves nothing behind but the adapter,
        // which disappears with `dev`.
        let mut cfg = IpStackConfig::default();
        if let Err(e) = cfg.mtu(opts.mtu) {
            #[cfg(not(windows))]
            undo_routes(name.clone(), phys.clone(), scoped_default).await;
            return Err(anyhow::anyhow!("{e:?}"));
        }
        cfg.udp_timeout(UDP_IDLE);
        // The default 60 s idle timeout kills quiet HTTP/2 and websocket connections.
        let mut tcp = ipstack::TcpConfig::default();
        tcp.timeout = TCP_IDLE;
        cfg.with_tcp_config(tcp);
        let mut stack = IpStack::new(cfg, TunIo(dev));
        let fake = Arc::new(FakeIp::new());
        let dead = Arc::new(AtomicBool::new(false));
        let dead_flag = dead.clone();
        #[cfg(windows)]
        let nrpt = Arc::new(AtomicBool::new(false));
        #[cfg(windows)]
        let (nrpt_flag, name_for_task) = (nrpt.clone(), name.clone());
        #[cfg_attr(not(windows), allow(unused_mut))]
        let mut task = tokio::spawn(async move {
            // A panic in the loop ends it without reaching the code below: mark it dead anyway.
            let _unwind = DeadOnUnwind(dead_flag.clone());
            loop {
                match stack.accept().await {
                    Ok(IpStackStream::Tcp(tcp)) => {
                        let Some(dst) = target(&fake, tcp.peer_addr()) else { continue };
                        let src = tcp.local_addr();
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            let _ = shared.relay(tcp, dst, &[], Some(src)).await;
                        });
                    }
                    Ok(IpStackStream::Udp(udp)) => {
                        let (shared, fake) = (shared.clone(), fake.clone());
                        tokio::spawn(async move {
                            if let Err(e) = handle_udp(&shared, &fake, udp).await {
                                tracing::debug!("udp: {e}");
                            }
                        });
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("TUN stack stopped: {e:?}");
                        break;
                    }
                }
            }
            // Nobody answers DNS or forwards packets any more. Take out what would now
            // black-hole the system (the NRPT rule first, then the routes into the dead
            // adapter); the owner sees `is_dead` and does the rest of the teardown.
            dead_flag.store(true, Ordering::SeqCst);
            #[cfg(windows)]
            {
                let had_nrpt = nrpt_flag.swap(false, Ordering::SeqCst);
                let _ = tokio::task::spawn_blocking(move || {
                    if had_nrpt && let Err(e) = veil_sysproxy::nrpt_disable_fast() {
                        tracing::error!("{e:#}");
                    }
                    veil_sysproxy::remove_tun_routes(&name_for_task);
                })
                .await;
            }
        });

        // Hard condition (Windows): our resolver answers on DNS_ADDR before any route, DNS
        // setting or NRPT rule points the system at it. DNS_ADDR is reachable already through
        // the adapter's own on-link /15, so this changes nothing in the system. First the
        // adapter has to be there with a usable address (a first start may be installing the
        // driver; IPv4 duplicate address detection keeps it Tentative for a moment).
        #[cfg(windows)]
        {
            let n = name.clone();
            let ready = blocking(move || veil_sysproxy::wait_tun_address(&n)).await.and_then(|r| r);
            tracing::info!("TUN adapter address ready: {}", ready.is_ok());
            if let Err(e) = &ready {
                tracing::warn!("TUN adapter not ready: {e:#}; probing the resolver anyway");
            }
            if crate::engine::shutting_down() {
                task.abort();
                return Err(cancelled());
            }
            let probed = probe_dns().await;
            tracing::info!("TUN resolver probe: {probed}");
            if !probed {
                task.abort();
                let _ = (&mut task).await;
                let state = ready.err().map_or(String::new(), |e| format!(" ({e:#})"));
                anyhow::bail!(
                    "the TUN resolver {DNS_ADDR} did not answer within {} s{state}; nothing in the system was changed. \
                     A third-party firewall blocking the Veil adapter, or another VPN/TUN using 198.18.0.0/15, can cause this",
                    nrpt::probe_total().as_secs()
                );
            }
        }

        // Windows: only now, after the resolver answered the probe. (macOS did this before the
        // stack since always: the order there is deliberately unchanged.)
        #[cfg(windows)]
        let scoped_default = match Self::setup_system(&name, &phys, gateway, opts).await {
            Ok(v) => v,
            Err(e) => {
                task.abort();
                return Err(e);
            }
        };
        let net = Arc::new(tokio::sync::Mutex::new(NetCfg {
            state,
            scoped_default,
            servers: Vec::new(),
            host_routes: Vec::new(),
        }));
        let (watch_stop, watcher) = spawn_net_watch(net.clone(), name.clone(), opts.routes);
        Ok(Self {
            name,
            task,
            dns_backup: opts.dns_backup.clone(),
            net,
            watch_stop: Some(watch_stop),
            watcher: Some(watcher),
            dead,
            #[cfg(windows)]
            nrpt,
        })
    }

    /// True once the packet loop has ended on its own: the tunnel no longer works and
    /// the owner should stop it and report "disconnected".
    pub(crate) fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// Adds the NRPT rule (our resolver has answered the probe in `bring_up` by now) and
    /// takes it out again if the system resolver does not work with it. Never fails the
    /// start: without the rule names may leak to the physical adapters' DNS, but DNS works.
    #[cfg(windows)]
    async fn enable_nrpt(&self) {
        // Set before the rule exists, so that every exit path tries to remove it.
        self.nrpt.store(true, Ordering::SeqCst);
        let added = blocking(|| veil_sysproxy::nrpt_enable(&[IpAddr::V4(DNS_ADDR)])).await.and_then(|r| r);
        let keep = match added {
            Ok(()) => {
                let ok = blocking(veil_sysproxy::system_resolver_works).await.unwrap_or(false);
                if !ok {
                    tracing::warn!("the system resolver does not work with the NRPT rule: removing it, DNS names may leak through other adapters");
                }
                ok
            }
            Err(e) => {
                tracing::warn!("NRPT rule not added, DNS names may leak through other adapters: {e:#}");
                false
            }
        };
        if keep {
            tracing::info!("NRPT rule verified: the system resolver answers through the tunnel");
        } else {
            self.disable_nrpt().await;
        }
    }

    /// Removes the NRPT rule if it may be there. On failure the flag stays set, so the
    /// next exit path (`stop`, `Drop`) tries again.
    #[cfg(windows)]
    async fn disable_nrpt(&self) {
        if !self.nrpt.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Err(e) = blocking(veil_sysproxy::nrpt_disable).await.and_then(|r| r) {
            tracing::error!("{e:#}");
            self.nrpt.store(true, Ordering::SeqCst);
        }
    }

    /// Routes the (new) proxy server's address around the tunnel.
    /// The server is remembered even without a gateway: the network watcher routes it
    /// once there is one, and again through every new gateway.
    pub(crate) async fn server_changed(&self, server: &ServerConfig) {
        let addr = Address::from_host(&server.address, server.port);
        let ips: Vec<IpAddr> = match dial::resolve(&addr).await {
            Ok(a) => a.iter().map(|s| s.ip()).collect(),
            Err(e) => {
                tracing::warn!("cannot resolve server for host route: {e}");
                return;
            }
        };
        // Held across the route changes: the watcher must not re-route meanwhile.
        let mut net = self.net.lock().await;
        for ip in &ips {
            if !net.servers.contains(ip) {
                net.servers.push(*ip);
            }
        }
        let Some(gw) = net.state.gateway else { return };
        let new: Vec<IpAddr> = ips.into_iter().filter(|ip| !net.host_routes.contains(ip)).collect();
        if new.is_empty() {
            return;
        }
        match blocking(move || add_host_routes(new, gw)).await {
            Ok(added) => {
                for ip in added {
                    if !net.host_routes.contains(&ip) {
                        net.host_routes.push(ip);
                    }
                }
            }
            Err(e) => tracing::warn!("host routes: {e:#}"),
        }
    }

    /// Ends the network watcher, letting a re-routing in progress finish first.
    async fn stop_net_watch(&mut self) {
        if let Some(tx) = self.watch_stop.take() {
            let _ = tx.send(());
        }
        if let Some(mut watcher) = self.watcher.take()
            && tokio::time::timeout(Duration::from_secs(30), &mut watcher).await.is_err()
        {
            tracing::warn!("network watcher did not stop in time");
            watcher.abort();
            let _ = watcher.await;
        }
    }

    pub(crate) async fn stop(mut self) {
        // First the one setting that outlives the adapter and breaks DNS for the whole
        // system if anything below hangs or the process dies half-way.
        #[cfg(windows)]
        self.disable_nrpt().await;
        // Before reading the routing state: it must not change under the teardown.
        self.stop_net_watch().await;
        self.task.abort();
        let _ = (&mut self.task).await;
        // The current interface, gateway and routes (the watcher may have replaced the ones from start).
        let (phys, gateway, scoped_default, host_routes) = {
            let mut net = self.net.lock().await;
            let host_routes = std::mem::take(&mut net.host_routes);
            let scoped_default = std::mem::replace(&mut net.scoped_default, false);
            (net.state.phys.clone(), net.state.gateway, scoped_default, host_routes)
        };
        // `Tun` implements `Drop` on Windows, so its fields cannot be moved out.
        let (name, dns_backup) = (self.name.clone(), self.dns_backup.clone());
        let name_log = name.clone();
        let res = blocking(move || {
            veil_sysproxy::remove_tun_routes(&name);
            for ip in host_routes {
                remove_host_route(ip, gateway);
            }
            if scoped_default {
                veil_sysproxy::remove_scoped_default(&phys);
            }
            if let Err(e) = veil_sysproxy::dns_restore(&dns_backup) {
                tracing::error!("restoring DNS: {e:#}");
            }
        })
        .await;
        if let Err(e) = res {
            tracing::error!("TUN teardown: {e:#}");
        }
        dial::set_bypass(None);
        tracing::info!("TUN {name_log} down");
    }
}

/// Dropped without [`Tun::stop`] (an error path, a cancelled task): the NRPT rule must not
/// be left behind. Synchronous on purpose, there is no later moment to do it.
#[cfg(windows)]
impl Drop for Tun {
    fn drop(&mut self) {
        self.task.abort();
        if self.nrpt.swap(false, Ordering::SeqCst)
            && let Err(e) = veil_sysproxy::nrpt_disable_fast()
        {
            tracing::error!("{e:#}");
        }
    }
}

/// Asks our resolver on [`DNS_ADDR`] for an A record, the way any program would, on the
/// schedule [`nrpt::PROBE_WAITS`]. True when the fake-IP answer came back.
#[cfg(windows)]
async fn probe_dns() -> bool {
    probe_dns_at(SocketAddr::new(IpAddr::V4(DNS_ADDR), 53), &nrpt::PROBE_WAITS).await
}

/// One query per entry of `waits`, each waiting that long for the answer (late answers
/// to an earlier query count too: same id).
#[cfg(any(windows, test))]
async fn probe_dns_at(server: SocketAddr, waits: &[Duration]) -> bool {
    let id = (std::process::id() as u16) ^ 0x5a5a;
    let query = nrpt::probe_query(id);
    let bind = if server.is_ipv4() { SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)) } else { SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)) };
    let Ok(sock) = tokio::net::UdpSocket::bind(bind).await else { return false };
    if sock.connect(server).await.is_err() {
        return false;
    }
    let mut buf = [0u8; 1500];
    for wait in waits {
        let deadline = tokio::time::Instant::now() + *wait;
        if sock.send(&query).await.is_err() {
            // The fresh adapter may not be ready yet: wait out this try, then send again.
            tokio::time::sleep_until(deadline).await;
            continue;
        }
        // A stray or failed read (e.g. ICMP unreachable) is not an answer: keep waiting.
        while let Ok(r) = tokio::time::timeout_at(deadline, sock.recv(&mut buf)).await {
            match r {
                Ok(n) if nrpt::probe_answered(id, &buf[..n]) => return true,
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    }
    false
}

/// Sets the flag when dropped while unwinding a panic (and only then).
struct DeadOnUnwind(Arc<AtomicBool>);

impl Drop for DeadOnUnwind {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.0.store(true, Ordering::SeqCst);
        }
    }
}

/// Runs a blocking call (PowerShell and friends) off the async workers.
fn cancelled() -> anyhow::Error {
    anyhow::anyhow!("cancelled: Veil is quitting")
}

fn check_not_quitting() -> Result<()> {
    if crate::engine::shutting_down() { Err(cancelled()) } else { Ok(()) }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f).await.context("blocking task failed")
}

async fn undo_routes(name: String, phys: String, scoped_default: bool) {
    let _ = blocking(move || {
        veil_sysproxy::remove_tun_routes(&name);
        if scoped_default {
            veil_sysproxy::remove_scoped_default(&phys);
        }
    })
    .await;
}

/// Adds host routes through `gw`; returns the ones added. Blocking.
fn add_host_routes(ips: Vec<IpAddr>, gw: IpAddr) -> Vec<IpAddr> {
    ips.into_iter()
        .filter(|&ip| {
            let ok = veil_sysproxy::add_host_route(ip, gw);
            if !ok && ip.is_ipv6() {
                tracing::warn!("IPv6 server {ip} has no host route: its connections are not protected from looping into the tunnel");
            }
            ok
        })
        .collect()
}

/// Polls the physical network every [`NET_POLL`] and moves the bypass (pinned sockets,
/// scoped default route, host routes to the servers) to a new interface or gateway once it
/// is stable. The split routes and the DNS setting point at the TUN and stay. Ends when
/// told to or when the sender is dropped (the `Tun` is gone).
fn spawn_net_watch(
    net: Arc<tokio::sync::Mutex<NetCfg>>,
    tun_name: String,
    routes: TunRoutes,
) -> (tokio::sync::oneshot::Sender<()>, JoinHandle<()>) {
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let mut debounce = NetDebounce::default();
        loop {
            tokio::select! {
                _ = &mut rx => break,
                _ = tokio::time::sleep(NET_POLL) => {}
            }
            let name = tun_name.clone();
            let seen = blocking(move || probe_network(&name)).await.ok().flatten();
            let mut cfg = net.lock().await;
            let Some(next) = debounce.feed(&cfg.state, seen) else { continue };
            if let Err(e) = reroute(&mut cfg, next, routes).await {
                tracing::warn!("network changed, but following it failed (will retry): {e:#}");
            }
        }
    });
    (tx, task)
}

/// Moves the bypass to the network `next`. On error nothing is recorded as changed, so
/// the watcher tries again.
async fn reroute(cfg: &mut NetCfg, next: NetState, routes: TunRoutes) -> Result<()> {
    let phys = next.phys.clone();
    let if_index = blocking(move || interface_index(&phys)).await??;
    let dns = with_fallbacks(next.dns.as_deref().unwrap_or_default());
    tracing::info!(
        "network changed: interface {} -> {}, gateway {:?} -> {:?}, direct DNS {dns:?}",
        cfg.state.phys,
        next.phys,
        cfg.state.gateway,
        next.gateway
    );
    dial::set_bypass(Some(Bypass { if_index, dns }));
    let (old_phys, old_gw, old_scoped) = (cfg.state.phys.clone(), cfg.state.gateway, cfg.scoped_default);
    let old_routes = cfg.host_routes.clone();
    let (new_phys, new_gw, servers) = (next.phys.clone(), next.gateway, cfg.servers.clone());
    let done = blocking(move || {
        for ip in old_routes {
            remove_host_route(ip, old_gw);
        }
        if old_scoped {
            veil_sysproxy::remove_scoped_default(&old_phys);
        }
        let scoped = match new_gw {
            Some(gw) if routes != TunRoutes::Domains => veil_sysproxy::add_scoped_default(&new_phys, gw),
            _ => false,
        };
        let added = new_gw.map(|gw| add_host_routes(servers, gw)).unwrap_or_default();
        (scoped, added)
    })
    .await?;
    (cfg.scoped_default, cfg.host_routes) = done;
    cfg.state = next;
    Ok(())
}

/// Removes a host route; on Windows only the one through `gateway` when it is known.
fn remove_host_route(ip: IpAddr, gateway: Option<IpAddr>) {
    #[cfg(windows)]
    veil_sysproxy::remove_host_route_via(ip, gateway);
    #[cfg(not(windows))]
    {
        let _ = gateway;
        veil_sysproxy::remove_host_route(ip);
    }
}

/// Maps a captured destination back to a domain when it is a fake address.
fn target(fake: &FakeIp, dst: SocketAddr) -> Option<Address> {
    if FakeIp::is_fake(dst.ip()) {
        // Unknown fake addresses come from DNS answers cached before a restart.
        fake.domain(dst.ip()).map(|d| Address::Domain(d, dst.port()))
    } else {
        Some(Address::Socket(dst))
    }
}

async fn handle_udp(shared: &Shared, fake: &FakeIp, mut udp: IpStackUdpStream) -> io::Result<()> {
    let dst = udp.peer_addr();
    let mut buf = vec![0u8; 64 * 1024];
    if dst.port() == 53 {
        loop {
            let n = tokio::time::timeout(UDP_IDLE, udp.read(&mut buf)).await.unwrap_or(Ok(0))?;
            if n == 0 {
                return Ok(());
            }
            if let Some(resp) = answer_dns(fake, &buf[..n]).await {
                udp.write_all(&resp).await?;
            }
        }
    }

    let Some(target) = target(fake, dst) else { return Ok(()) };
    let src = Some((crate::process::Proto::Udp, udp.local_addr()));
    match shared.router.decide(&target, src).await.action {
        RouteAction::Direct => {}
        // UDP through the proxy is not implemented yet; QUIC falls back to TCP.
        RouteAction::Proxy | RouteAction::Block => return Ok(()),
    }
    let remote = *dial::resolve(&target).await?.first().unwrap();
    let sock = dial::udp_socket_for(remote.ip()).await?;
    sock.connect(remote).await?;
    let mut rbuf = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE, udp.read(&mut buf)) => {
                let n = r.unwrap_or(Ok(0))?;
                if n == 0 { return Ok(()); }
                sock.send(&buf[..n]).await?;
            }
            r = sock.recv(&mut rbuf) => {
                let n = r?;
                udp.write_all(&rbuf[..n]).await?;
            }
        }
    }
}

async fn answer_dns(fake: &FakeIp, query: &[u8]) -> Option<Vec<u8>> {
    let q = dns::parse_question(query)?;
    match q.qtype {
        dns::TYPE_A => {
            let ip = fake.lookup_or_assign(&q.name);
            Some(dns::build_response(query, &q, &[IpAddr::V4(ip)], FAKE_TTL))
        }
        // No AAAA: keep clients on fake IPv4. HTTPS records could carry real IP hints.
        dns::TYPE_AAAA | dns::TYPE_HTTPS => Some(dns::build_response(query, &q, &[], FAKE_TTL)),
        _ => forward_dns(query).await,
    }
}

/// Sends other record types (MX, TXT, SRV, ...) to the real DNS server directly.
async fn forward_dns(query: &[u8]) -> Option<Vec<u8>> {
    let server = *dial::bypass_dns().first()?;
    let sock = dial::udp_socket_for(server).await.ok()?;
    sock.connect((server, 53)).await.ok()?;
    sock.send(query).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_pool() {
        let f = FakeIp::new();
        let a = f.lookup_or_assign("a.com");
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 3));
        assert_eq!(f.lookup_or_assign("a.com"), a);
        let b = f.lookup_or_assign("b.com");
        assert_ne!(a, b);
        assert_eq!(f.domain(a.into()).as_deref(), Some("a.com"));
        assert!(FakeIp::is_fake(b.into()));
        assert!(!FakeIp::is_fake(DNS_ADDR.into()));
        assert_eq!(
            target(&f, SocketAddr::new(a.into(), 443)),
            Some(Address::Domain("a.com".into(), 443))
        );
        assert_eq!(target(&f, SocketAddr::new(Ipv4Addr::new(198, 18, 9, 9).into(), 1)), None);
    }

    #[tokio::test]
    async fn nrpt_probe_and_decisions() {
        // The probe query, answered by our own resolver code, counts as an answer.
        let f = FakeIp::new();
        let q = nrpt::probe_query(0x1234);
        let resp = answer_dns(&f, &q).await.unwrap();
        assert!(nrpt::probe_answered(0x1234, &resp));
        // Wrong id, a query echoed back, garbage, an empty answer or a real address do not.
        assert!(!nrpt::probe_answered(0x1235, &resp));
        assert!(!nrpt::probe_answered(0x1234, &q));
        assert!(!nrpt::probe_answered(0x1234, b"junk"));
        assert!(!nrpt::probe_answered(0x1234, &[]));
        let parsed = dns::parse_question(&q).unwrap();
        let empty = dns::build_response(&q, &parsed, &[], 60);
        assert!(!nrpt::probe_answered(0x1234, &empty));
        let real = dns::build_response(&q, &parsed, &[IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], 60);
        assert!(!nrpt::probe_answered(0x1234, &real));
        // The schedule: growing pauses, 12-15 s in all.
        assert!(nrpt::PROBE_WAITS.windows(2).all(|w| w[0] <= w[1]));
        assert!(nrpt::PROBE_WAITS[0] < nrpt::PROBE_WAITS[nrpt::PROBE_WAITS.len() - 1]);
        let total = nrpt::probe_total();
        assert!(total >= Duration::from_secs(12) && total <= Duration::from_secs(15), "{total:?}");
    }

    /// A resolver that ignores the first `ignore` queries, then answers like ours; counts queries.
    async fn flaky_resolver(ignore: usize) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let sock = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = seen.clone();
        tokio::spawn(async move {
            let fake = FakeIp::new();
            let mut buf = [0u8; 1500];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if count.fetch_add(1, Ordering::SeqCst) < ignore {
                    continue;
                }
                if let Some(resp) = answer_dns(&fake, &buf[..n]).await {
                    let _ = sock.send_to(&resp, from).await;
                }
            }
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn probe_retries_until_answered() {
        let ms = Duration::from_millis;
        // Not ready for the first two tries: the third one gets through.
        let (addr, seen) = flaky_resolver(2).await;
        assert!(probe_dns_at(addr, &[ms(100), ms(150), ms(400), ms(400)]).await);
        assert_eq!(seen.load(Ordering::SeqCst), 3, "one query per try, none after the answer");
        // Never answers: false, after exactly one query per entry of the schedule.
        let (addr, seen) = flaky_resolver(usize::MAX).await;
        let started = tokio::time::Instant::now();
        assert!(!probe_dns_at(addr, &[ms(50), ms(100), ms(150)]).await);
        assert_eq!(seen.load(Ordering::SeqCst), 3);
        assert!(started.elapsed() >= ms(300), "the whole schedule is waited out");
    }

    #[test]
    fn dead_on_unwind_only() {
        let flag = Arc::new(AtomicBool::new(false));
        drop(DeadOnUnwind(flag.clone()));
        assert!(!flag.load(Ordering::SeqCst), "a normal drop (abort, stop) is not a death");
        let f = flag.clone();
        let r = std::thread::spawn(move || {
            let _g = DeadOnUnwind(f);
            panic!("test panic");
        })
        .join();
        assert!(r.is_err());
        assert!(flag.load(Ordering::SeqCst), "a panic marks the loop dead");
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// No `dns`: the system shows none of its own.
    fn net(phys: &str, gw: Option<&str>, dns: &[&str]) -> NetState {
        NetState::new(phys.into(), gw.map(ip), dns.iter().map(|s| ip(s)).collect())
    }

    #[test]
    fn system_dns_filtering_and_fallbacks() {
        let sys = filter_system_dns(vec![ip("127.0.0.1"), IpAddr::V4(DNS_ADDR), ip("198.18.0.9"), ip("192.168.1.1")]);
        assert_eq!(sys, vec![ip("192.168.1.1")]);
        assert_eq!(with_fallbacks(&sys), vec![ip("192.168.1.1"), ip("77.88.8.8"), ip("1.1.1.1"), ip("8.8.8.8")]);
        assert_eq!(with_fallbacks(&[ip("1.1.1.1")]), vec![ip("1.1.1.1"), ip("77.88.8.8"), ip("8.8.8.8")]);
        // Only our own resolver left (macOS, DNS overridden): unknown, not "no servers".
        assert_eq!(NetState::new("en0".into(), None, filter_system_dns(vec![IpAddr::V4(DNS_ADDR)])).dns, None);
    }

    #[test]
    fn network_change_detection() {
        let home = net("en0", Some("192.168.1.1"), &["192.168.1.1"]);
        assert!(!network_changed(&home, &home));
        // Same Wi-Fi interface, the iPhone hotspot's gateway.
        assert!(network_changed(&home, &net("en0", Some("172.20.10.1"), &[])));
        assert!(network_changed(&home, &net("en7", Some("192.168.1.1"), &[])));
        assert!(network_changed(&home, &net("en0", Some("192.168.1.1"), &["9.9.9.9"])));
        // DNS hidden by our override is no change.
        assert!(!network_changed(&home, &net("en0", Some("192.168.1.1"), &[])));
        // Only usable observations count: a gateway, a real interface, not our TUN.
        assert!(usable_observation(net("en0", None, &[]), "utun5").is_none());
        assert!(usable_observation(net("utun5", Some("10.0.0.1"), &[]), "utun5").is_none());
        assert!(usable_observation(net("", Some("10.0.0.1"), &[]), "utun5").is_none());
        assert!(usable_observation(net("en0", Some("10.0.0.1"), &[]), "utun5").is_some());
        // The next state keeps the DNS servers only on the same link.
        assert_eq!(next_state(&home, &net("en0", Some("172.20.10.1"), &[])), net("en0", Some("172.20.10.1"), &[]));
        assert_eq!(
            next_state(&home, &net("en0", Some("192.168.1.1"), &["9.9.9.9"])),
            net("en0", Some("192.168.1.1"), &["9.9.9.9"])
        );
        let no_dns = net("en0", Some("192.168.1.1"), &[]);
        assert_eq!(next_state(&no_dns, &net("en0", Some("192.168.1.1"), &[])), no_dns);
    }

    #[test]
    fn network_debounce() {
        let home = net("en0", Some("192.168.1.1"), &["192.168.1.1"]);
        let phone = net("en0", Some("172.20.10.1"), &[]);
        let mut d = NetDebounce::default();
        // Unchanged or offline: nothing, ever.
        for _ in 0..5 {
            assert_eq!(d.feed(&home, Some(home.clone())), None);
            assert_eq!(d.feed(&home, None), None);
        }
        // A new network has to be seen twice in a row.
        assert_eq!(d.feed(&home, Some(phone.clone())), None);
        assert_eq!(d.feed(&home, Some(phone.clone())), Some(phone.clone()));
        // Then it starts over (the caller has switched, or will retry after a failure).
        assert_eq!(d.feed(&home, Some(phone.clone())), None);
        assert_eq!(d.feed(&home, Some(phone.clone())), Some(phone.clone()));
        // Flapping between states, or a gap without network, never switches.
        let other = net("en7", Some("10.0.0.1"), &[]);
        let mut d = NetDebounce::default();
        for _ in 0..3 {
            assert_eq!(d.feed(&home, Some(phone.clone())), None);
            assert_eq!(d.feed(&home, Some(other.clone())), None);
        }
        assert_eq!(d.feed(&home, None), None);
        assert_eq!(d.feed(&home, Some(other.clone())), None);
        assert_eq!(d.feed(&home, Some(home.clone())), None);
        assert_eq!(d.feed(&home, Some(other.clone())), None);
        assert_eq!(d.feed(&home, Some(other.clone())), Some(other));
    }

    #[tokio::test]
    async fn dns_answers() {
        let f = FakeIp::new();
        let q = dns::build_query(7, "example.com", dns::TYPE_A);
        let r = answer_dns(&f, &q).await.unwrap();
        let (ips, _) = dns::parse_answers(&r, 7).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(f.lookup_or_assign("example.com"))]);
        let q = dns::build_query(8, "example.com", dns::TYPE_AAAA);
        let (ips, _) = dns::parse_answers(&answer_dns(&f, &q).await.unwrap(), 8).unwrap();
        assert!(ips.is_empty());
    }
}
