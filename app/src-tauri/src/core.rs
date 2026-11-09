//! Application state behind the UI: profiles, settings and the live connection.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use uuid::Uuid;
use veil_config::store::{AppState, ConnectionMode, Store};
use veil_config::{PRESETS, RoutingRule, Subscription, SubscriptionUsage, geodata, parse_links, subscription};
use veil_engine::rules::Rules;
use veil_engine::{Engine, EngineConfig};

/// `Tun` (through the privileged helper) exists on macOS only; Windows runs TUN inside the app.
#[cfg_attr(windows, allow(dead_code))]
enum Conn {
    Proxy { engine: Box<Engine>, sysproxy: bool },
    Tun,
}

pub struct Core {
    store: Store,
    pub state: AppState,
    conn: Option<Conn>,
    connected_at: Option<Instant>,
    last_error: Option<String>,
    /// Set after the app started an elevated copy of itself and should now quit.
    relaunch: bool,
    /// Started by `--connect-tun`: never ask for elevation again (no UAC loops).
    no_relaunch: bool,
    /// An elevated copy has been started and this one is on its way out: a second
    /// `connect` (double click, tray menu) must not show another UAC prompt.
    #[cfg_attr(not(windows), allow(dead_code))]
    elevated_started: bool,
}

#[derive(Serialize)]
pub struct UiProfile {
    id: Uuid,
    name: String,
    protocol: &'static str,
    security: &'static str,
    address: String,
    port: u16,
    subscription_id: Option<Uuid>,
    latency_ms: Option<u32>,
    pinned: bool,
}

#[derive(Serialize)]
pub struct UiSubscription {
    id: Uuid,
    name: String,
    url: String,
    usage: Option<SubscriptionUsage>,
    last_updated: Option<u64>,
}

#[derive(Serialize)]
pub struct UiState {
    profiles: Vec<UiProfile>,
    subscriptions: Vec<UiSubscription>,
    selected: Option<Uuid>,
    mode: ConnectionMode,
    preset: String,
    presets: Vec<(&'static str, &'static str)>,
    connected: bool,
    error: Option<String>,
    port: u16,
    /// `macos` or `windows`, for platform-specific texts in the UI.
    platform: &'static str,
    /// TUN mode: macOS (privileged helper) and Windows (elevated app + wintun.dll).
    tun_available: bool,
}

/// Snapshot of the state shown in the menu bar / tray menu.
pub struct TrayInfo {
    pub connected: bool,
    pub selected: Option<Uuid>,
    pub server_name: String,
    pub protocol: Option<&'static str>,
    pub mode: ConnectionMode,
    pub preset: String,
    pub tun_available: bool,
    /// Servers of the selected profile's subscription (all profiles when it has none).
    pub servers: Vec<(Uuid, String)>,
}

#[derive(Serialize)]
pub struct Traffic {
    upload: u64,
    download: u64,
    seconds: u64,
    connected: bool,
}

#[cfg_attr(windows, allow(dead_code))]
pub enum TrafficSource {
    Proxy(std::sync::Arc<veil_engine::Stats>, u64),
    Tun(u64),
    None,
}

impl TrafficSource {
    pub async fn read(self) -> Traffic {
        let (upload, download, seconds, connected) = match self {
            TrafficSource::Proxy(stats, secs) => {
                (stats.upload.load(Ordering::Relaxed), stats.download.load(Ordering::Relaxed), secs, true)
            }
            TrafficSource::Tun(secs) => {
                let s = tokio::task::spawn_blocking(veil_helper::status).await.ok().and_then(Result::ok);
                (s.as_ref().map_or(0, |s| s.upload), s.as_ref().map_or(0, |s| s.download), secs, true)
            }
            TrafficSource::None => (0, 0, 0, false),
        };
        Traffic { upload, download, seconds, connected }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl Core {
    pub fn open() -> Result<Self> {
        Self::open_store(Store::open_default()?)
    }

    fn open_store(store: Store) -> Result<Self> {
        let mut state = store.load()?;
        // Older versions offered more presets; map them onto the two we keep.
        if !PRESETS.iter().any(|(n, _)| *n == state.settings.routing_preset) {
            state.settings.routing_preset = "global".into();
            store.save(&state)?;
        }
        // Leftovers of a crash: put the user's proxy settings back.
        let _ = veil_sysproxy::restore(&store.dir().join("sysproxy-backup.json"));
        // Leftovers of a TUN session that died (Windows): above all the DNS (NRPT) rule,
        // which breaks name resolution for the whole system, this app's Proxy mode
        // included. Runs in a normal, non-elevated start too; a no-op elsewhere.
        // A cheap look first (journal file, registry): PowerShell only when there is a sign.
        let mut last_error = None;
        if veil_sysproxy::tun_leftovers_suspected()
            && let Some(report) = veil_sysproxy::tun_cleanup_if_orphaned()
            && !report.failed.is_empty()
        {
            tracing::warn!("TUN leftovers could not be removed (needs admin: {}): {:?}", report.needs_admin, report.failed);
            last_error = Some(tun_leftover_msg(report.needs_admin).to_string());
            // Ask for the rights right away: an elevated copy removes the rule and exits.
            #[cfg(windows)]
            if report.needs_admin {
                std::thread::spawn(|| {
                    if let Err(e) = win::run_elevated_cleanup() {
                        tracing::warn!("{e:#}");
                    }
                });
            }
        }
        Ok(Self { store, state, conn: None, connected_at: None, last_error, relaunch: false, no_relaunch: false, elevated_started: false })
    }

    fn save(&self) -> Result<()> {
        self.store.save(&self.state)
    }

    fn proxy_backup(&self) -> PathBuf {
        self.store.dir().join("sysproxy-backup.json")
    }

    pub fn snapshot(&self) -> UiState {
        let selected = self.state.selected_profile().map(|p| p.id);
        UiState {
            profiles: self
                .state
                .profiles
                .iter()
                .map(|p| UiProfile {
                    id: p.id,
                    name: p.name.clone(),
                    protocol: p.server.protocol.name(),
                    security: match p.server.security {
                        veil_config::Security::None => "",
                        veil_config::Security::Tls(_) => "tls",
                        veil_config::Security::Reality(_) => "reality",
                    },
                    address: p.server.address.clone(),
                    port: p.server.port,
                    subscription_id: p.subscription_id,
                    latency_ms: p.latency_ms,
                    pinned: p.pinned,
                })
                .collect(),
            subscriptions: self
                .state
                .subscriptions
                .iter()
                .map(|s| UiSubscription {
                    id: s.id,
                    name: s.name.clone(),
                    url: s.url.clone(),
                    usage: s.usage.clone(),
                    last_updated: s.last_updated,
                })
                .collect(),
            selected,
            mode: self.state.settings.mode,
            preset: self.state.settings.routing_preset.clone(),
            presets: PRESETS.to_vec(),
            connected: self.conn.is_some(),
            error: self.last_error.clone(),
            port: self.state.settings.mixed_port,
            platform: std::env::consts::OS,
            tun_available: TUN_AVAILABLE,
        }
    }

    /// True once (and only once) after `connect` started an elevated copy of the app:
    /// the caller must release its single-instance lock and quit.
    pub fn take_relaunch(&mut self) -> bool {
        std::mem::take(&mut self.relaunch)
    }

    /// Connect right after an elevated start (`--connect-tun`): TUN only if the saved
    /// mode is TUN, and never asks for elevation again.
    pub async fn connect_after_elevation(&mut self) -> Result<()> {
        self.no_relaunch = true;
        if self.state.settings.mode != ConnectionMode::Tun || self.conn.is_some() {
            return Ok(());
        }
        self.connect().await
    }

    pub fn is_connected(&self) -> bool {
        self.conn.is_some()
    }

    /// What the tray menu shows; cheap to build, no async.
    pub fn tray_info(&self) -> TrayInfo {
        let selected = self.state.selected_profile();
        let sub = selected.and_then(|p| p.subscription_id);
        let servers = self
            .state
            .profiles
            .iter()
            .filter(|p| sub.is_none() || p.subscription_id == sub)
            .map(|p| (p.id, p.name.clone()))
            .collect();
        TrayInfo {
            connected: self.conn.is_some(),
            selected: selected.map(|p| p.id),
            server_name: selected.map(|p| p.name.clone()).unwrap_or_default(),
            protocol: selected.map(|p| p.server.protocol.name()),
            mode: self.state.settings.mode,
            preset: self.state.settings.routing_preset.clone(),
            tun_available: TUN_AVAILABLE,
            servers,
        }
    }

    /// Adds share links, or a subscription when given an http(s) URL.
    pub async fn import(&mut self, input: &str) -> Result<String> {
        let input = input.trim();
        if input.starts_with("http://") || input.starts_with("https://") {
            if self.state.subscriptions.iter().any(|s| s.url == input) {
                bail!("this subscription is already added");
            }
            let sub = Subscription {
                id: Uuid::new_v4(),
                name: input.to_string(),
                url: input.to_string(),
                update_interval_hours: 12,
                last_updated: None,
                usage: None,
            };
            let id = sub.id;
            self.state.subscriptions.push(sub);
            match self.refresh_one(id).await {
                Ok((0, skipped)) => {
                    self.state.subscriptions.retain(|s| s.id != id);
                    bail!("the subscription has no supported servers ({skipped} unsupported)")
                }
                Ok((n, skipped)) => {
                    self.save()?;
                    Ok(format!("Subscription added: {n} servers{}", skipped_note(skipped)))
                }
                Err(e) => {
                    self.state.subscriptions.retain(|s| s.id != id);
                    Err(e)
                }
            }
        } else {
            let profiles = parse_links(input);
            if profiles.is_empty() {
                bail!("no supported links found");
            }
            let n = profiles.len();
            if self.state.selected.is_none() {
                self.state.selected = Some(profiles[0].id);
            }
            self.state.profiles.extend(profiles);
            self.save()?;
            Ok(format!("Added {n} server{}", if n == 1 { "" } else { "s" }))
        }
    }

    /// Returns (servers added, servers skipped as unsupported).
    async fn refresh_one(&mut self, id: Uuid) -> Result<(usize, usize)> {
        let sub = self.state.subscriptions.iter().find(|s| s.id == id).context("no such subscription")?.clone();
        let fetched = subscription::fetch(&sub).await?;
        let n = fetched.profiles.len();
        for reason in &fetched.skipped {
            tracing::info!("skipped server: {reason}");
        }
        let skipped = fetched.skipped.len();
        self.state.replace_subscription_profiles(id, fetched.profiles);
        if self.state.selected_profile().is_none() || self.state.selected.is_none() {
            self.state.selected = self.state.profiles.first().map(|p| p.id);
        }
        let s = self.state.subscriptions.iter_mut().find(|s| s.id == id).unwrap();
        s.last_updated = Some(now());
        s.usage = fetched.usage;
        if let Some(t) = fetched.title {
            s.name = t;
        }
        if let Some(h) = fetched.update_interval_hours {
            s.update_interval_hours = h;
        }
        Ok((n, skipped))
    }

    pub async fn refresh_subscriptions(&mut self, only_due: bool) -> Result<String> {
        let ids: Vec<Uuid> = self
            .state
            .subscriptions
            .iter()
            .filter(|s| !only_due || subscription::is_due(s))
            .map(|s| s.id)
            .collect();
        let mut errors = Vec::new();
        let mut total = 0;
        let mut skipped = 0;
        for id in ids {
            match self.refresh_one(id).await {
                Ok((n, s)) => {
                    total += n;
                    skipped += s;
                }
                Err(e) => errors.push(format!("{e:#}")),
            }
        }
        self.save()?;
        if errors.is_empty() {
            Ok(format!("Updated: {total} servers{}", skipped_note(skipped)))
        } else {
            bail!("{}", errors.join("; "))
        }
    }

    pub fn delete_subscription(&mut self, id: Uuid) -> Result<()> {
        self.state.subscriptions.retain(|s| s.id != id);
        self.state.profiles.retain(|p| p.subscription_id != Some(id));
        self.save()
    }

    /// Puts the geoip/geosite files bundled with the app in place, so rules
    /// never wait for a slow download.
    pub fn seed_geo(&self, bundled: &std::path::Path) {
        match geodata::seed_from(bundled, self.store.dir()) {
            Ok(true) => tracing::info!("geo data copied from {}", bundled.display()),
            Ok(false) => {}
            Err(e) => tracing::warn!("seeding geo data: {e:#}"),
        }
    }

    pub fn toggle_pin(&mut self, id: Uuid) -> Result<()> {
        let p = self.state.profiles.iter_mut().find(|p| p.id == id).context("no such profile")?;
        p.pinned = !p.pinned;
        self.save()
    }

    /// A geosite list with all domains of the service `domain` belongs to.
    pub async fn suggest_geosite(&self, domain: &str) -> Result<Option<String>> {
        let path = self.store.dir().join("geosite.dat");
        if !path.exists() {
            return Ok(None);
        }
        let domain = domain.to_string();
        tokio::task::spawn_blocking(move || veil_engine::geo::suggest_geosite(&path, &domain)).await?
    }

    pub fn delete_profile(&mut self, id: Uuid) -> Result<()> {
        self.state.profiles.retain(|p| p.id != id);
        if self.state.selected == Some(id) {
            self.state.selected = self.state.profiles.first().map(|p| p.id);
        }
        self.save()
    }

    pub async fn select(&mut self, id: Uuid) -> Result<()> {
        let profile = self.state.profiles.iter().find(|p| p.id == id).context("no such profile")?.clone();
        self.state.selected = Some(id);
        self.save()?;
        tracing::info!("switching to {}", profile.name);
        // Swap the server inside the running session; no reconnect.
        match &self.conn {
            Some(Conn::Proxy { engine, .. }) => engine.set_server(profile.server).await?,
            Some(Conn::Tun) => {
                let req = veil_helper::Request::Update {
                    server: Some(Box::new(profile.server)),
                    routing: None,
                    geo_dir: self.store.dir().to_path_buf(),
                };
                tokio::task::spawn_blocking(move || veil_helper::call(&req)).await??;
            }
            None => {}
        }
        Ok(())
    }

    pub async fn set_mode(&mut self, mode: ConnectionMode) -> Result<()> {
        let previous = self.state.settings.mode;
        let was_connected = self.conn.is_some();
        self.state.settings.mode = mode;
        self.save()?;
        let Err(e) = self.reconnect_if_connected().await else { return Ok(()) };
        // The new mode could not start (UAC declined, wintun.dll missing, ...): go back to the
        // old mode and its connection, so the user is not left offline with a mode that cannot work.
        if was_connected && self.conn.is_none() {
            self.state.settings.mode = previous;
            let _ = self.save();
            if self.connect().await.is_ok() {
                self.last_error = Some(format!("{e:#}"));
            }
        }
        Err(e)
    }

    pub async fn set_preset(&mut self, name: &str) -> Result<()> {
        if !PRESETS.iter().any(|(n, _)| *n == name) {
            bail!("unknown preset {name}");
        }
        self.state.settings.routing_preset = name.to_string();
        self.save()?;
        self.apply_routing().await
    }

    pub fn rules(&self) -> Vec<RoutingRule> {
        self.state.settings.custom_rules.clone()
    }

    /// Replaces the user's rules; they apply to the running session immediately.
    pub async fn set_rules(&mut self, rules: Vec<RoutingRule>) -> Result<()> {
        let mut settings = self.state.settings.clone();
        settings.custom_rules = rules;
        let routing = settings.routing();
        if routing.uses_geo_files() && !geodata::present(self.store.dir()) {
            bail!("geoip/geosite data missing in {}; reinstall Veil", self.store.dir().display());
        }
        // Reject bad entries (IP typos, unknown geosite codes) before saving.
        Rules::compile(&routing, self.store.dir()).context("invalid rule")?;
        self.state.settings = settings;
        self.save()?;
        self.apply_routing().await
    }

    async fn apply_routing(&mut self) -> Result<()> {
        if self.conn.is_none() {
            return Ok(());
        }
        let routing = self.state.settings.routing();
        if routing.uses_geo_files() && !geodata::present(self.store.dir()) {
            bail!("geoip/geosite data missing in {}; reinstall Veil", self.store.dir().display());
        }
        match &self.conn {
            Some(Conn::Proxy { engine, .. }) => engine.set_routing(&routing, self.store.dir())?,
            Some(Conn::Tun) => {
                let req = veil_helper::Request::Update {
                    server: None,
                    routing: Some(routing),
                    geo_dir: self.store.dir().to_path_buf(),
                };
                tokio::task::spawn_blocking(move || veil_helper::call(&req)).await??;
            }
            None => {}
        }
        Ok(())
    }

    async fn reconnect_if_connected(&mut self) -> Result<()> {
        if self.conn.is_some() {
            self.disconnect().await;
            self.connect().await?;
        }
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<()> {
        self.last_error = None;
        tracing::info!(
            "connecting: mode {:?}, server {:?}",
            self.state.settings.mode,
            self.state.selected_profile().map(|p| &p.name)
        );
        let result = self.connect_inner().await;
        match &result {
            Ok(()) if self.relaunch => tracing::info!("restarting as administrator"),
            Ok(()) => tracing::info!("connected"),
            Err(e) => tracing::error!("connect failed: {e:#}"),
        }
        if let Err(e) = &result {
            self.last_error = Some(format!("{e:#}"));
        }
        result
    }

    async fn connect_inner(&mut self) -> Result<()> {
        if self.conn.is_some() || self.elevated_started {
            return Ok(());
        }
        let profile = self.state.selected_profile().context("add a server first")?.clone();
        let routing = self.state.settings.routing();
        if routing.uses_geo_files() && !geodata::present(self.store.dir()) {
            bail!("geoip/geosite data missing in {}; reinstall Veil", self.store.dir().display());
        }
        let port = self.state.settings.mixed_port;
        match self.state.settings.mode {
            ConnectionMode::Proxy => {
                let engine = Engine::start(EngineConfig {
                    listen: SocketAddr::from(([127, 0, 0, 1], port)),
                    server: profile.server,
                    routing,
                    geo_dir: self.store.dir().to_path_buf(),
                    tun: None,
                })
                .await?;
                let sysproxy = self.state.settings.set_system_proxy;
                if sysproxy && let Err(e) = veil_sysproxy::enable("127.0.0.1", port, &self.proxy_backup()) {
                    let _ = veil_sysproxy::restore(&self.proxy_backup());
                    engine.stop().await;
                    return Err(e.context("could not enable the system proxy"));
                }
                self.conn = Some(Conn::Proxy { engine: Box::new(engine), sysproxy });
            }
            ConnectionMode::Tun => {
                if !TUN_AVAILABLE {
                    bail!("TUN mode is not available on this system yet; switch to Proxy mode");
                }
                // Windows: the engine runs inside this (elevated) process. The system proxy
                // stays off in TUN mode, as on macOS.
                #[cfg(windows)]
                {
                    use veil_engine::tun::{TunOptions, TunRoutes};
                    // Check first, so nobody sees a UAC prompt for a setup that cannot work.
                    win::check_wintun()?;
                    if !win::is_elevated() {
                        if self.no_relaunch {
                            bail!("TUN mode needs administrator rights; start Veil as administrator");
                        }
                        // The UAC prompt blocks until answered: keep it off the async workers.
                        tokio::task::spawn_blocking(win::relaunch_elevated).await??;
                        self.relaunch = true;
                        self.elevated_started = true;
                        return Ok(());
                    }
                    let engine = Engine::start(EngineConfig {
                        listen: SocketAddr::from(([127, 0, 0, 1], port)),
                        server: profile.server,
                        routing,
                        geo_dir: self.store.dir().to_path_buf(),
                        tun: Some(TunOptions {
                            mtu: 1500,
                            dns_backup: self.store.dir().join("dns-backup.json"),
                            routes: TunRoutes::All,
                        }),
                    })
                    .await?;
                    self.conn = Some(Conn::Proxy { engine: Box::new(engine), sysproxy: false });
                }
                #[cfg(not(windows))]
                {
                    let helper = helper_binary()?;
                    let shipped = helper.clone();
                    if !tokio::task::spawn_blocking(move || veil_helper::is_current(&shipped)).await? {
                        tracing::info!("installing helper from {}", helper.display());
                        tokio::task::spawn_blocking(move || veil_helper::install(&helper))
                            .await?
                            .context("could not install the helper")?;
                    }
                    let req = veil_helper::Request::Start {
                        server: Box::new(profile.server),
                        routing,
                        geo_dir: self.store.dir().to_path_buf(),
                        mixed_port: port,
                        routes: veil_helper::TunRoutes::All,
                    };
                    tokio::task::spawn_blocking(move || veil_helper::call(&req)).await??;
                    self.conn = Some(Conn::Tun);
                }
            }
        }
        self.connected_at = Some(Instant::now());
        Ok(())
    }

    pub async fn disconnect(&mut self) {
        if self.conn.is_some() {
            tracing::info!("disconnecting");
        }
        match self.conn.take() {
            Some(Conn::Proxy { engine, sysproxy }) => {
                if sysproxy && let Err(e) = veil_sysproxy::restore(&self.proxy_backup()) {
                    tracing::error!("restoring system proxy: {e:#}");
                }
                engine.stop().await;
            }
            Some(Conn::Tun) => {
                let r = tokio::task::spawn_blocking(|| veil_helper::call(&veil_helper::Request::Stop)).await;
                if let Ok(Err(e)) = r {
                    tracing::error!("stopping TUN: {e:#}");
                }
            }
            None => {}
        }
        self.connected_at = None;
        tracing::info!("disconnected");
    }

    /// Clears the "TUN leftovers" error once they are gone (removed by the elevated copy,
    /// by veil-rescue.ps1 or by hand). Cheap: no PowerShell. True when the error was cleared.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn recheck_tun_leftovers(&mut self) -> bool {
        let shown = self.last_error.as_deref().is_some_and(|e| e == tun_leftover_msg(true) || e == tun_leftover_msg(false));
        if shown && self.conn.is_none() && !veil_sysproxy::tun_leftovers_suspected() {
            tracing::info!("TUN leftovers are gone");
            self.last_error = None;
            return true;
        }
        false
    }

    /// Disconnects when the TUN packet loop has died on its own, so the UI stops showing
    /// a tunnel that carries nothing. True when that happened.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub async fn reap_dead_tun(&mut self) -> bool {
        let dead = matches!(&self.conn, Some(Conn::Proxy { engine, .. }) if engine.tun_failed());
        if dead {
            tracing::error!("the TUN tunnel stopped on its own: disconnecting");
            self.disconnect().await;
            self.last_error = Some("The TUN tunnel stopped unexpectedly and Veil disconnected. Connect again.".into());
        }
        dead
    }

    /// What `traffic()` needs, taken under the lock so the query runs without it.
    pub fn traffic_source(&self) -> TrafficSource {
        let seconds = self.connected_at.map_or(0, |t| t.elapsed().as_secs());
        match &self.conn {
            Some(Conn::Proxy { engine, .. }) => TrafficSource::Proxy(engine.stats().clone(), seconds),
            Some(Conn::Tun) => TrafficSource::Tun(seconds),
            None => TrafficSource::None,
        }
    }

    /// Measures one network round trip to every server, over the physical
    /// interface so that a running VPN (ours in TUN mode, or another one)
    /// neither fakes TCP handshakes nor detours UDP through its tunnel.
    pub async fn ping_all(&mut self) -> Result<()> {
        let pin = tokio::task::spawn_blocking(|| veil_engine::tun::physical_bypass().map(|(_, b)| b))
            .await?
            .ok();
        let targets: Vec<(Uuid, veil_config::ServerConfig)> =
            self.state.profiles.iter().map(|p| (p.id, p.server.clone())).collect();
        let mut set = tokio::task::JoinSet::new();
        for (id, server) in targets {
            let pin = pin.clone();
            set.spawn(async move { (id, ping(&server, pin).await) });
        }
        while let Some(r) = set.join_next().await {
            if let Ok((id, rtt)) = r
                && let Some(p) = self.state.profiles.iter_mut().find(|p| p.id == id)
            {
                // At least 1 ms: 0 is reserved for "unreachable".
                p.latency_ms = Some(rtt.map_or(0, |d| (d.as_millis() as u32).max(1)));
            }
        }
        self.save()
    }
}

/// One round trip to a server: the TCP handshake, or for Hysteria (UDP only)
/// the QUIC-measured RTT of an authenticated connection. DNS time is excluded.
async fn ping(server: &veil_config::ServerConfig, pin: Option<veil_proto::dial::Bypass>) -> Option<Duration> {
    // A server on this Mac is unreachable through the physical interface.
    let local = server.address.eq_ignore_ascii_case("localhost")
        || server.address.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
    let pin = if local { None } else { pin };
    if let veil_config::Protocol::Hysteria2 { .. } = server.protocol {
        let mut client = veil_proto::hysteria::HysteriaClient::new(server).ok()?;
        if let Some(pin) = pin {
            client = client.pinned(pin);
        }
        return tokio::time::timeout(Duration::from_secs(5), client.probe()).await.ok()?.ok();
    }
    let addr = veil_proto::Address::from_host(&server.address, server.port);
    let ips = veil_proto::dial::resolve_with(&addr, pin.as_ref()).await.ok()?;
    let target = veil_proto::Address::Socket(*ips.first()?);
    let start = Instant::now();
    let connect = veil_proto::dial::tcp_connect_with(&target, pin.as_ref());
    tokio::time::timeout(Duration::from_secs(3), connect).await.ok()?.ok()?;
    Some(start.elapsed())
}

fn skipped_note(skipped: usize) -> String {
    if skipped == 0 {
        String::new()
    } else {
        format!(" ({skipped} more use protocols Veil does not support yet)")
    }
}

const TUN_AVAILABLE: bool = cfg!(any(target_os = "macos", windows));

/// Windows: elevation check, UAC restart and the wintun.dll check.
#[cfg(windows)]
mod win {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use anyhow::{Context, Result, bail};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    /// Whether this process runs with an elevated (administrator) token.
    pub fn is_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut returned = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevation).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Starts this exe again through the UAC prompt, asking it to connect in TUN mode.
    pub fn relaunch_elevated() -> Result<()> {
        // The new copy waits for this process to exit before it opens its WebView
        // (the user data folder cannot be shared between elevation levels).
        let args = format!("{} {}={}", super::CONNECT_TUN_ARG, super::AFTER_PID_ARG, std::process::id());
        match run_as_admin(&args)? {
            c if c > 32 => Ok(()),
            // SE_ERR_ACCESSDENIED: the UAC prompt was declined.
            5 => bail!("Administrator permission was declined; TUN mode cannot start without it"),
            c => bail!("could not restart Veil as administrator (error {c})"),
        }
    }

    /// Starts an elevated copy of this exe that only removes what a dead TUN session
    /// left behind (`--tun-cleanup`) and exits. Blocks until the UAC prompt is answered.
    pub fn run_elevated_cleanup() -> Result<()> {
        match run_as_admin(super::TUN_CLEANUP_ARG)? {
            c if c > 32 => Ok(()),
            5 => bail!("Administrator permission was declined; the leftover DNS rule is still there"),
            c => bail!("could not start the cleanup as administrator (error {c})"),
        }
    }

    /// `ShellExecuteW` with the `runas` verb on this exe; returns its result code.
    fn run_as_admin(args: &str) -> Result<isize> {
        let exe = std::env::current_exe().context("cannot find Veil.exe")?;
        let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let verb = wide(std::ffi::OsStr::new("runas"));
        let file = wide(exe.as_os_str());
        let args = wide(std::ffi::OsStr::new(args));
        // An elevated start would otherwise use System32 as the working directory.
        let dir = exe.parent().map(|d| wide(d.as_os_str()));
        let dir_ptr = dir.as_ref().map_or(std::ptr::null(), |d| d.as_ptr());
        let code = unsafe {
            ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), args.as_ptr(), dir_ptr, SW_SHOWNORMAL)
        } as isize;
        Ok(code)
    }

    /// tun-rs loads wintun.dll from the folder of the exe.
    pub fn check_wintun() -> Result<()> {
        let exe = std::env::current_exe()?;
        if exe.parent().is_some_and(|d| d.join("wintun.dll").is_file()) {
            Ok(())
        } else {
            bail!("wintun.dll not found next to Veil.exe ({}); reinstall Veil", exe.display())
        }
    }
}

/// Command-line flag of the elevated copy: connect in TUN mode as soon as the UI is up.
pub const CONNECT_TUN_ARG: &str = "--connect-tun";

/// Command-line flag: remove what a dead TUN session left in the system, then exit.
/// Used for the elevated copy started when the normal one lacks the rights.
pub const TUN_CLEANUP_ARG: &str = "--tun-cleanup";

/// Shown when leftovers of a TUN session could not be removed: for lack of administrator
/// rights (`needs_admin`) or for another reason.
fn tun_leftover_msg(needs_admin: bool) -> &'static str {
    if needs_admin {
        "A DNS rule left by an earlier TUN session is still in Windows and can break name resolution. \
         Approve the administrator prompt to remove it, or run veil-rescue.ps1 from the Veil folder, then restart Veil."
    } else {
        "Settings left by an earlier TUN session could not be removed and can break name resolution. \
         Run veil-rescue.ps1 from the Veil folder (it writes a report to veil-rescue.txt), then restart Veil."
    }
}

/// Whether the command line (without the program name) asks for `--tun-cleanup`.
pub fn wants_tun_cleanup<I: IntoIterator<Item = String>>(args: I) -> bool {
    args.into_iter().any(|a| a == TUN_CLEANUP_ARG)
}

/// Command-line flag of the elevated copy: `--after-pid=N`, wait for process N (the copy
/// that started us) to exit before touching the WebView.
#[cfg_attr(not(windows), allow(dead_code))]
pub const AFTER_PID_ARG: &str = "--after-pid";

/// The pid given with `--after-pid=N`, if any.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn after_pid<I: IntoIterator<Item = String>>(args: I) -> Option<u32> {
    args.into_iter().find_map(|a| a.strip_prefix("--after-pid=")?.parse().ok())
}

/// Whether the command line (without the program name) asks for `--connect-tun`.
pub fn wants_connect_tun<I: IntoIterator<Item = String>>(args: I) -> bool {
    args.into_iter().any(|a| a == CONNECT_TUN_ARG)
}

/// The helper ships next to the app binary (Contents/MacOS in the bundle).
#[cfg(not(windows))]
fn helper_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("no exe dir")?;
    for candidate in [
        dir.join(format!("veil-helper{}", std::env::consts::EXE_SUFFIX)),
        // Dev-only fallback: never run a binary found via a relative path as root in release builds.
        #[cfg(debug_assertions)]
        dir.join("../../target/release/veil-helper"),
    ] {
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    bail!("veil-helper not found next to {}", exe.display())
}

#[cfg(test)]
mod arg_tests {
    use super::{after_pid, wants_connect_tun, wants_tun_cleanup};

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tun_cleanup_flag() {
        assert!(wants_tun_cleanup(args(&["--tun-cleanup"])));
        assert!(!wants_tun_cleanup(args(&[])));
        assert!(!wants_tun_cleanup(args(&["--connect-tun", "tun-cleanup", "--tun-cleanup=1"])));
    }

    #[test]
    fn connect_tun_flag() {
        assert!(wants_connect_tun(args(&["--connect-tun"])));
        assert!(wants_connect_tun(args(&["--x", "--connect-tun"])));
        assert!(!wants_connect_tun(args(&[])));
        assert!(!wants_connect_tun(args(&["--connect-tunnel", "connect-tun"])));
    }

    #[test]
    fn after_pid_flag() {
        assert_eq!(after_pid(args(&["--connect-tun", "--after-pid=1234"])), Some(1234));
        assert_eq!(after_pid(args(&["--after-pid=x"])), None);
        assert_eq!(after_pid(args(&["--after-pid"])), None);
        assert_eq!(after_pid(args(&[])), None);
    }
}

#[cfg(test)]
mod tests {
    //! Drives the same calls the UI buttons make, against a real Xray server.

    use std::process::{Command, Stdio};

    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[tokio::test]
    async fn ui_flow() {
        if Command::new("xray").arg("version").stdout(Stdio::null()).status().is_err() {
            eprintln!("xray not found, skipping");
            return;
        }
        let dir = std::env::temp_dir().join(format!("veil-app-{}", Uuid::new_v4()));
        let server_port = free_port();
        let config = serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": server_port, "protocol": "vless",
                "settings": {"clients": [{"id": UUID}], "decryption": "none"}}],
            "outbounds": [{"protocol": "freedom",
                "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}],
        });
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("xray.json"), config.to_string()).unwrap();
        let _xray = Kill(Command::new("xray").args(["run", "-c"]).arg(dir.join("xray.json")).spawn().unwrap());

        // Subscription endpoint serving one base64-encoded link.
        let link = format!("vless://{UUID}@127.0.0.1:{server_port}?type=tcp&security=none#Test%20server");
        let body = base64::engine::general_purpose::STANDARD.encode(&link);
        let sub_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sub_url = format!("http://{}/sub", sub_listener.local_addr().unwrap());
        tokio::spawn(async move {
            loop {
                let (mut s, _) = sub_listener.accept().await.unwrap();
                let mut req = [0u8; 1024];
                let _ = s.read(&mut req).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nsubscription-userinfo: upload=1; download=2; total=1000\r\nprofile-title: base64:0KLQtdGB0YI=\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            }
        });

        // Echo origin.
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = origin.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut core = Core::open_store(Store::open(&dir).unwrap()).unwrap();
        core.state.settings.set_system_proxy = false;
        core.state.settings.routing_preset = "proxy-all".into();
        let mixed = free_port();
        core.state.settings.mixed_port = mixed;

        assert!(core.import("not a link").await.is_err());
        let msg = core.import(&sub_url).await.unwrap();
        assert!(msg.contains('1'), "{msg}");
        let snap = core.snapshot();
        assert_eq!(snap.subscriptions[0].name, "Тест");
        assert_eq!(snap.profiles.len(), 1);
        assert_eq!(snap.selected, Some(snap.profiles[0].id));

        core.ping_all().await.unwrap();
        assert!(core.state.profiles[0].latency_ms.is_some_and(|ms| ms > 0), "server should answer ping");

        core.connect().await.unwrap();
        assert!(core.snapshot().connected);
        let mut s = TcpStream::connect(("127.0.0.1", mixed)).await.unwrap();
        s.write_all(format!("CONNECT {origin_addr} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        let mut head = [0u8; 39];
        s.read_exact(&mut head).await.unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        s.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        let t = core.traffic_source().read().await;
        assert!(t.connected && t.upload >= 4, "{} up", t.upload);

        // Switch servers mid-session: the open connection keeps working and
        // new connections use the new server, without reconnecting.
        let msg = core.import(&format!("vless://{UUID}@127.0.0.1:{server_port}?type=tcp#Second")).await.unwrap();
        assert!(msg.contains('1'), "{msg}");
        let second = core.state.profiles.iter().find(|p| p.name == "Second").unwrap().id;
        let t0 = Instant::now();
        core.select(second).await.unwrap();
        assert!(t0.elapsed() < Duration::from_millis(500), "switch took {:?}", t0.elapsed());
        assert!(core.snapshot().connected);
        s.write_all(b"pong").await.unwrap();
        s.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"pong");
        let mut s2 = TcpStream::connect(("127.0.0.1", mixed)).await.unwrap();
        s2.write_all(format!("CONNECT {origin_addr} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        s2.read_exact(&mut head).await.unwrap();
        assert!(head.starts_with(b"HTTP/1.1 200"));
        core.set_preset("global").await.unwrap();

        // Per-app rule applied to the live session: this test binary gets blocked.
        let me = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned();
        assert!(core.set_rules(vec![RoutingRule::ips(veil_config::RouteAction::Direct, &["10.0.0.0/33"])]).await.is_err());
        assert!(core.rules().is_empty(), "invalid rules must not be saved");
        core.set_rules(vec![RoutingRule::processes(veil_config::RouteAction::Block, &[&me])]).await.unwrap();
        let mut s3 = TcpStream::connect(("127.0.0.1", mixed)).await.unwrap();
        s3.write_all(format!("CONNECT {origin_addr} HTTP/1.1\r\n\r\n").as_bytes()).await.unwrap();
        s3.write_all(b"ping").await.unwrap();
        let mut got = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s3.read_to_end(&mut got)).await;
        assert!(!String::from_utf8_lossy(&got).contains("ping"), "blocked app got data through");
        core.set_rules(Vec::new()).await.unwrap();

        core.disconnect().await;
        assert!(!core.snapshot().connected);
        // Settings survive a restart.
        let reopened = Core::open_store(Store::open(&dir).unwrap()).unwrap();
        assert_eq!(reopened.snapshot().profiles.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
