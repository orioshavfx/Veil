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

/// `Tun` (through the privileged helper) exists on macOS and Linux; Windows runs TUN inside the app.
#[cfg_attr(windows, allow(dead_code))]
enum Conn {
    Proxy { engine: Box<Engine>, sysproxy: bool },
    Tun,
}

pub struct Core {
    store: Store,
    pub state: AppState,
    conn: Option<Conn>,
    /// `conn` is a TUN session on standby (kill switch): shown as disconnected, while the
    /// helper keeps the tunnel and refuses everything that would go through the VPN.
    /// Never saved: a fresh start of the app is plainly "disconnected".
    standby: bool,
    /// Bumped on every entry into standby, so a helper check that started before a
    /// reconnect and a new standby cannot end the new one.
    standby_epoch: u64,
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
    /// Disconnected, but the TUN stays on standby and blocks VPN traffic (kill switch).
    standby: bool,
    /// The kill switch setting, and whether this platform offers it (macOS TUN).
    kill_switch: bool,
    standby_available: bool,
    /// Settings → Updates: check GitHub for a new version at startup (macOS).
    check_updates: bool,
    auto_connect: bool,
    launch_at_login: bool,
    autostart_available: bool,
    error: Option<String>,
    port: u16,
    /// `macos`, `windows` or `linux`, for platform-specific texts in the UI.
    platform: &'static str,
    /// TUN mode: macOS (privileged helper) and Windows (elevated app + wintun.dll).
    tun_available: bool,
}

/// Snapshot of the state shown in the menu bar / tray menu.
pub struct TrayInfo {
    pub connected: bool,
    pub standby: bool,
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
        // Older versions offered geo presets (ru-direct, proxy-all); map any name
        // that is not one of the two base modes onto "global".
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
        Ok(Self {
            store,
            state,
            conn: None,
            standby: false,
            standby_epoch: 0,
            connected_at: None,
            last_error,
            relaunch: false,
            no_relaunch: false,
            elevated_started: false,
        })
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
            connected: self.is_connected(),
            standby: self.standby,
            kill_switch: self.state.settings.kill_switch,
            standby_available: STANDBY_AVAILABLE,
            check_updates: self.state.settings.check_updates,
            auto_connect: self.state.settings.auto_connect,
            launch_at_login: self.state.settings.launch_at_login,
            autostart_available: crate::autostart::AVAILABLE,
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

    /// Connected and carrying traffic (a session on standby is not).
    pub fn is_connected(&self) -> bool {
        self.conn.is_some() && !self.standby
    }

    /// Disconnected, with the TUN on standby blocking VPN traffic.
    pub fn is_standby(&self) -> bool {
        self.standby
    }

    fn session(&self) -> Session {
        match (&self.conn, self.standby) {
            (None, _) => Session::Off,
            (Some(_), false) => Session::Running,
            (Some(_), true) => Session::Standby,
        }
    }

    /// Whether "Disconnect" may put the session on standby: kill switch on, TUN mode, and
    /// the TUN runs in the helper (macOS), never the in-app engine (Windows).
    fn standby_allowed(&self) -> bool {
        STANDBY_AVAILABLE
            && self.state.settings.kill_switch
            && self.state.settings.mode == ConnectionMode::Tun
            && !matches!(self.conn, Some(Conn::Proxy { .. }))
    }

    /// The error of the last connection attempt (or of a TUN that died), if any.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Shows `msg` like a connection error (window, panel) until the next connection: an
    /// update that failed after it had turned the VPN off.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn set_error(&mut self, msg: String) {
        self.last_error = Some(msg);
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
            connected: self.is_connected(),
            standby: self.standby,
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

    pub fn toggle_pin(&mut self, id: Uuid) -> Result<()> {
        let p = self.state.profiles.iter_mut().find(|p| p.id == id).context("no such profile")?;
        p.pinned = !p.pinned;
        self.save()
    }

    /// A geosite list with all domains of the service `domain` belongs to, from
    /// the user's own geosite.dat; `None` when there is no such file.
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
        let was_connected = self.is_connected();
        self.state.settings.mode = mode;
        self.save()?;
        // A session on standby ends for good when the mode leaves TUN.
        self.settings_changed().await;
        if self.conn.is_none() {
            self.start_in_standby().await;
        }
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
            bail!("unknown routing mode {name}");
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
        geodata::ensure_available(&routing, self.store.dir())?;
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
        geodata::ensure_available(&routing, self.store.dir())?;
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

    /// Turns the kill switch on or off. Off while on standby: the tunnel is removed and the
    /// system is back to normal at once.
    pub async fn set_kill_switch(&mut self, on: bool) -> Result<()> {
        self.state.settings.kill_switch = on;
        self.save()?;
        self.settings_changed().await;
        // Nothing connected: the block starts now, not only after the first connection.
        if on && self.conn.is_none() {
            self.start_in_standby().await;
        }
        Ok(())
    }

    /// Settings → Startup: connect as soon as the app opens.
    pub fn set_auto_connect(&mut self, on: bool) -> Result<()> {
        self.state.settings.auto_connect = on;
        self.save()
    }

    /// Settings → Startup: start the app at login. The system entry is changed first and the
    /// setting follows only when that worked, so the switch never shows a state that is not real.
    pub fn set_launch_at_login(&mut self, on: bool) -> Result<()> {
        crate::autostart::set(on)?;
        self.state.settings.launch_at_login = on;
        self.save()
    }

    /// Start of the app: the autostart entry points at the app as it is now (it may have moved).
    pub fn refresh_autostart(&self) {
        if self.state.settings.launch_at_login
            && let Err(e) = crate::autostart::set(true)
        {
            tracing::warn!("autostart entry: {e:#}");
        }
    }

    /// Settings → Updates: the startup check on or off.
    pub fn set_check_updates(&mut self, on: bool) -> Result<()> {
        self.state.settings.check_updates = on;
        self.save()
    }

    /// After a change of mode or kill switch: a standby that is no longer allowed ends.
    async fn settings_changed(&mut self) {
        if plan(self.session(), UserEvent::SettingsChanged, self.standby_allowed()) == Step::Stop {
            tracing::info!("standby no longer allowed by the settings: stopping TUN");
            self.disconnect().await;
        }
    }

    async fn reconnect_if_connected(&mut self) -> Result<()> {
        if self.is_connected() {
            self.disconnect().await;
            self.connect().await?;
        }
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<()> {
        let _connecting = ConnectingFlag::raise();
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
        if self.elevated_started {
            return Ok(());
        }
        let profile = self.state.selected_profile().context("add a server first")?.clone();
        let routing = self.state.settings.routing();
        geodata::ensure_available(&routing, self.store.dir())?;
        match plan(self.session(), UserEvent::Connect, self.standby_allowed()) {
            Step::Nothing => return Ok(()),
            Step::Resume => match self.resume(&profile.server, &routing).await {
                Ok(()) => {
                    // The helper let VPN traffic through again: the app must not go on
                    // treating the session as standby (the standby watch would then call the
                    // helper's "no standby" a lost one and stop the TUN a second later).
                    self.standby = false;
                    self.connected_at = Some(Instant::now());
                    return Ok(());
                }
                // The helper lost the session (restarted, say): start from scratch.
                Err(e) => {
                    tracing::warn!("cannot leave standby ({e:#}): starting the tunnel again");
                    self.disconnect().await;
                }
            },
            Step::Restart => self.disconnect().await,
            Step::Start | Step::EnterStandby | Step::Stop => {}
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
                #[cfg(windows)]
                if sysproxy {
                    veil_sysproxy::spawn_proxy_guard("127.0.0.1", port, &self.proxy_backup());
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
                        standby: false,
                    };
                    tokio::task::spawn_blocking(move || veil_helper::call(&req)).await??;
                    self.conn = Some(Conn::Tun);
                }
            }
        }
        self.connected_at = Some(Instant::now());
        Ok(())
    }

    /// Kill switch on, TUN mode, nothing connected (app start, or the setting just changed):
    /// the tunnel comes up already on standby, so VPN traffic is blocked before the first
    /// connection as well. Quiet on purpose: it never asks for the helper password (without an
    /// installed, current helper nothing happens) and a failure only goes to the log.
    #[cfg(not(windows))]
    pub async fn start_in_standby(&mut self) {
        if !self.standby_allowed() || self.conn.is_some() {
            return;
        }
        let Some(profile) = self.state.selected_profile().cloned() else { return };
        let routing = self.state.settings.routing();
        if let Err(e) = geodata::ensure_available(&routing, self.store.dir()) {
            tracing::info!("no standby before the first connection: {e:#}");
            return;
        }
        let helper = match helper_binary() {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("no standby before the first connection: {e:#}");
                return;
            }
        };
        if !tokio::task::spawn_blocking(move || veil_helper::is_current(&helper)).await.unwrap_or(false) {
            tracing::info!("no standby before the first connection: the helper is not installed yet");
            return;
        }
        let req = veil_helper::Request::Start {
            server: Box::new(profile.server),
            routing,
            geo_dir: self.store.dir().to_path_buf(),
            mixed_port: self.state.settings.mixed_port,
            routes: veil_helper::TunRoutes::All,
            standby: true,
        };
        let r = tokio::task::spawn_blocking(move || helper_ok(veil_helper::call(&req)?))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|r| r);
        match r {
            Ok(()) => {
                self.conn = Some(Conn::Tun);
                self.standby = true;
                self.standby_epoch += 1;
                self.connected_at = None;
                tracing::info!("standby before the first connection: VPN traffic blocked");
            }
            Err(e) => tracing::warn!("no standby before the first connection: {e:#}"),
        }
    }

    /// Windows has no standby (the TUN runs inside the app).
    #[cfg(windows)]
    pub async fn start_in_standby(&mut self) {}

    /// Leaves standby: the current server and rules first (they may have changed while the
    /// VPN was off), then VPN connections are let through again.
    async fn resume(&self, server: &veil_config::ServerConfig, routing: &veil_config::RoutingConfig) -> Result<()> {
        let update = veil_helper::Request::Update {
            server: Some(Box::new(server.clone())),
            routing: Some(routing.clone()),
            geo_dir: self.store.dir().to_path_buf(),
        };
        tokio::task::spawn_blocking(move || {
            helper_ok(veil_helper::call(&update)?)?;
            helper_ok(veil_helper::call(&veil_helper::Request::Standby { on: false })?)
        })
        .await??;
        tracing::info!("standby off: connected");
        Ok(())
    }

    /// The app is quitting: everything stops, a session on standby included, and the
    /// system gets its normal network back.
    pub async fn quit(&mut self) {
        if plan(self.session(), UserEvent::Quit, self.standby_allowed()) == Step::Stop {
            self.disconnect().await;
        }
    }

    /// The user's "Disconnect" (button, tray, panel). With the kill switch on in TUN mode the
    /// tunnel goes on standby; if that fails, it is stopped completely, as without it:
    /// never a blocked system that the app does not know about.
    pub async fn turn_off(&mut self) {
        match plan(self.session(), UserEvent::Disconnect, self.standby_allowed()) {
            Step::EnterStandby => {
                tracing::info!("disconnecting to standby (kill switch)");
                let r = tokio::task::spawn_blocking(|| {
                    helper_ok(veil_helper::call(&veil_helper::Request::Standby { on: true })?)
                })
                .await
                .map_err(anyhow::Error::from)
                .and_then(|r| r);
                match r {
                    Ok(()) => {
                        self.standby = true;
                        self.standby_epoch += 1;
                        self.connected_at = None;
                        tracing::info!("standby: VPN traffic blocked");
                    }
                    Err(e) => {
                        tracing::error!("standby failed ({e:#}): stopping TUN instead");
                        self.disconnect().await;
                    }
                }
            }
            Step::Stop => self.disconnect().await,
            _ => {}
        }
    }

    /// Stops everything (also a session on standby) and restores the system: quitting,
    /// switching modes, or turning the kill switch off.
    pub async fn disconnect(&mut self) {
        if self.conn.is_some() {
            tracing::info!("disconnecting");
        }
        self.standby = false;
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

    /// The standby to watch (see [`standby_check`]), taken under the lock so the helper
    /// query runs without it: `None` when there is no standby (or none on this platform).
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn standby_token(&self) -> Option<u64> {
        (STANDBY_AVAILABLE && self.standby && matches!(self.conn, Some(Conn::Tun))).then_some(self.standby_epoch)
    }

    /// The helper no longer holds the standby that `token` names (it stopped, restarted or
    /// lost its TUN): stop what is left and say so instead of showing a block that is not
    /// there. False when that standby already ended some other way.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub async fn standby_lost(&mut self, token: u64) -> bool {
        if self.standby_token() != Some(token) {
            return false;
        }
        tracing::error!("the helper no longer holds the standby: stopping TUN");
        self.disconnect().await;
        self.last_error = Some(STANDBY_LOST_MSG.into());
        true
    }

    /// What `traffic()` needs, taken under the lock so the query runs without it.
    pub fn traffic_source(&self) -> TrafficSource {
        let seconds = self.connected_at.map_or(0, |t| t.elapsed().as_secs());
        if self.standby {
            return TrafficSource::None;
        }
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
        let targets = self.state.profiles.iter().map(|p| (p.id, p.server.clone())).collect();
        let results = measure(targets).await?;
        self.set_latencies(results);
        self.save()
    }

    /// The servers among `ids` to measure with [`measure`], without holding the lock.
    pub fn ping_targets(&self, ids: &[Uuid]) -> Vec<(Uuid, veil_config::ServerConfig)> {
        self.state.profiles.iter().filter(|p| ids.contains(&p.id)).map(|p| (p.id, p.server.clone())).collect()
    }

    /// Stores what [`measure`] found (in memory; saved with the next change of settings).
    pub fn set_latencies(&mut self, results: Vec<(Uuid, Option<Duration>)>) {
        for (id, rtt) in results {
            if let Some(p) = self.state.profiles.iter_mut().find(|p| p.id == id) {
                // At least 1 ms: 0 is reserved for "unreachable".
                p.latency_ms = Some(rtt.map_or(0, |d| (d.as_millis() as u32).max(1)));
            }
        }
    }
}

/// One round trip to each server, all at once (`None`: no answer).
pub async fn measure(targets: Vec<(Uuid, veil_config::ServerConfig)>) -> Result<Vec<(Uuid, Option<Duration>)>> {
    let pin = tokio::task::spawn_blocking(|| veil_engine::tun::physical_bypass().map(|(_, b)| b))
        .await?
        .ok();
    let mut set = tokio::task::JoinSet::new();
    for (id, server) in targets {
        let pin = pin.clone();
        set.spawn(async move { (id, ping(&server, pin).await) });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(found) = r {
            out.push(found);
        }
    }
    Ok(out)
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

/// A connection is being set up (`Core::connect` runs): an update does not start then.
pub static CONNECTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Raises [`CONNECTING`] for as long as it lives (errors and early returns included).
struct ConnectingFlag;

impl ConnectingFlag {
    fn raise() -> Self {
        CONNECTING.store(true, Ordering::SeqCst);
        Self
    }
}

impl Drop for ConnectingFlag {
    fn drop(&mut self) {
        CONNECTING.store(false, Ordering::SeqCst);
    }
}

pub const TUN_AVAILABLE: bool = cfg!(any(target_os = "macos", windows, target_os = "linux"));

/// Standby (kill switch) needs the TUN in the privileged helper: macOS only (not in the Linux beta).
pub const STANDBY_AVAILABLE: bool = cfg!(target_os = "macos");

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const STANDBY_LOST_MSG: &str = "Standby ended: the TUN helper stopped. Rule sites are no longer blocked.";

/// How often the app asks the helper whether the standby still holds.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const STANDBY_CHECK_EVERY: Duration = Duration::from_secs(3);

/// Failed helper queries in a row after which the standby counts as lost.
const STANDBY_MAX_FAILURES: u32 = 2;

/// The answer to one `Status` query while on standby.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandbyReply {
    /// The helper answered.
    Status { running: bool, standby: bool },
    /// No answer: not reachable, an error, a timeout.
    Failed,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandbyVerdict {
    Holds,
    Lost,
}

/// The standby watch, free of I/O: from one reply and the failures in a row before it,
/// the verdict and the new count. A plain answer that the session is gone ends the
/// standby at once; a single failed query does not, two in a row do.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn standby_check(reply: StandbyReply, failures: u32) -> (StandbyVerdict, u32) {
    match reply {
        StandbyReply::Status { running: true, standby: true } => (StandbyVerdict::Holds, 0),
        StandbyReply::Status { .. } => (StandbyVerdict::Lost, 0),
        StandbyReply::Failed => {
            let failures = failures.saturating_add(1);
            let verdict = if failures >= STANDBY_MAX_FAILURES { StandbyVerdict::Lost } else { StandbyVerdict::Holds };
            (verdict, failures)
        }
    }
}

/// An `Error` answer of the helper as an error.
fn helper_ok(resp: veil_helper::Response) -> Result<()> {
    match resp {
        veil_helper::Response::Error { message } => bail!("{message}"),
        _ => Ok(()),
    }
}

/// The connection as far as the kill switch is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Session {
    Off,
    Running,
    /// TUN up, VPN traffic refused.
    Standby,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UserEvent {
    Connect,
    /// The user's "Disconnect".
    Disconnect,
    /// The app is quitting.
    Quit,
    /// Mode or kill switch changed.
    SettingsChanged,
}

/// What to do with the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Nothing,
    /// A new session (`Start`).
    Start,
    /// `Standby { on: false }` (after an `Update`).
    Resume,
    /// `Standby { on: true }`; on failure a full stop.
    EnterStandby,
    /// Full `Stop`: tunnel, routes and DNS removed.
    Stop,
    /// `Stop`, then `Start`.
    Restart,
}

/// The kill switch decisions, free of I/O. `standby_allowed`: kill switch on, TUN mode,
/// TUN in the helper (see `Core::standby_allowed`).
fn plan(session: Session, event: UserEvent, standby_allowed: bool) -> Step {
    use {Session as S, Step as T, UserEvent as E};
    match (event, session) {
        (E::Connect, S::Off) => T::Start,
        (E::Connect, S::Running) => T::Nothing,
        (E::Connect, S::Standby) if standby_allowed => T::Resume,
        (E::Connect, S::Standby) => T::Restart,
        (E::Disconnect, S::Running) if standby_allowed => T::EnterStandby,
        (E::Disconnect, S::Running) => T::Stop,
        (E::Disconnect, S::Standby) if standby_allowed => T::Nothing,
        (E::Disconnect, S::Standby) => T::Stop,
        (E::Disconnect, S::Off) => T::Nothing,
        (E::Quit, S::Off) => T::Nothing,
        (E::Quit, _) => T::Stop,
        (E::SettingsChanged, S::Standby) if !standby_allowed => T::Stop,
        (E::SettingsChanged, _) => T::Nothing,
    }
}

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

/// Command-line flag of the autostart entry: start in the menu bar / tray, without a window.
pub const HIDDEN_ARG: &str = "--hidden";

/// Whether the command line (without the program name) asks for `--hidden`.
pub fn wants_hidden<I: IntoIterator<Item = String>>(args: I) -> bool {
    args.into_iter().any(|a| a == HIDDEN_ARG)
}

/// Whether "Connect when Veil opens" is on.
impl Core {
    pub fn auto_connect_enabled(&self) -> bool {
        self.state.settings.auto_connect
    }
}

/// Where the packaged helper lives on Linux (installed by the distribution package).
#[cfg(target_os = "linux")]
const LINUX_PACKAGED_HELPER: &str = "/usr/lib/veil/veil-helper";

/// Candidate locations of the shipped helper, best first. macOS: next to the app binary
/// (Contents/MacOS in the bundle). Linux: the package's /usr/lib/veil, then next to the app
/// (portable / AppImage-like layouts).
#[cfg(not(windows))]
fn helper_candidates(exe_dir: &std::path::Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(target_os = "linux")]
    v.push(PathBuf::from(LINUX_PACKAGED_HELPER));
    v.push(exe_dir.join(format!("veil-helper{}", std::env::consts::EXE_SUFFIX)));
    // Dev-only fallback: never run a binary found via a relative path as root in release builds.
    #[cfg(debug_assertions)]
    v.push(exe_dir.join("../../target/release/veil-helper"));
    v
}

#[cfg(not(windows))]
fn helper_binary() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().context("no exe dir")?;
    match helper_candidates(dir).into_iter().find(|c| c.exists()) {
        Some(c) => Ok(c),
        None => bail!("veil-helper not found next to {}", exe.display()),
    }
}

#[cfg(test)]
mod standby_tests {
    use super::{Session, Step, UserEvent, plan};

    #[test]
    fn disconnect_goes_to_standby_only_with_the_kill_switch() {
        assert_eq!(plan(Session::Running, UserEvent::Disconnect, true), Step::EnterStandby);
        assert_eq!(plan(Session::Running, UserEvent::Disconnect, false), Step::Stop);
        assert_eq!(plan(Session::Off, UserEvent::Disconnect, true), Step::Nothing);
        assert_eq!(plan(Session::Off, UserEvent::Disconnect, false), Step::Nothing);
        // Already off (standby): a second click changes nothing; without permission it stops.
        assert_eq!(plan(Session::Standby, UserEvent::Disconnect, true), Step::Nothing);
        assert_eq!(plan(Session::Standby, UserEvent::Disconnect, false), Step::Stop);
    }

    #[test]
    fn connect_resumes_from_standby() {
        assert_eq!(plan(Session::Off, UserEvent::Connect, true), Step::Start);
        assert_eq!(plan(Session::Off, UserEvent::Connect, false), Step::Start);
        assert_eq!(plan(Session::Running, UserEvent::Connect, true), Step::Nothing);
        assert_eq!(plan(Session::Standby, UserEvent::Connect, true), Step::Resume);
        assert_eq!(plan(Session::Standby, UserEvent::Connect, false), Step::Restart);
    }

    #[test]
    fn quit_always_stops() {
        for allowed in [true, false] {
            assert_eq!(plan(Session::Running, UserEvent::Quit, allowed), Step::Stop);
            assert_eq!(plan(Session::Standby, UserEvent::Quit, allowed), Step::Stop);
            assert_eq!(plan(Session::Off, UserEvent::Quit, allowed), Step::Nothing);
        }
    }

    #[test]
    fn settings_change_ends_a_standby_that_is_no_longer_allowed() {
        // Mode switched to Proxy, or the kill switch turned off.
        assert_eq!(plan(Session::Standby, UserEvent::SettingsChanged, false), Step::Stop);
        assert_eq!(plan(Session::Standby, UserEvent::SettingsChanged, true), Step::Nothing);
        // A running or stopped session is left to the mode switch itself.
        for allowed in [true, false] {
            assert_eq!(plan(Session::Running, UserEvent::SettingsChanged, allowed), Step::Nothing);
            assert_eq!(plan(Session::Off, UserEvent::SettingsChanged, allowed), Step::Nothing);
        }
    }

    #[test]
    fn standby_holds_while_the_helper_says_so() {
        use super::{StandbyReply as R, StandbyVerdict as V, standby_check};
        let ok = R::Status { running: true, standby: true };
        assert_eq!(standby_check(ok, 0), (V::Holds, 0));
        // A good answer clears an earlier failure.
        assert_eq!(standby_check(ok, 1), (V::Holds, 0));
    }

    #[test]
    fn standby_ends_on_a_plain_answer_that_it_is_gone() {
        use super::{StandbyReply as R, StandbyVerdict as V, standby_check};
        // Helper restarted or its TUN loop died: not running.
        assert_eq!(standby_check(R::Status { running: false, standby: false }, 0), (V::Lost, 0));
        assert_eq!(standby_check(R::Status { running: false, standby: true }, 0), (V::Lost, 0));
        // Running, but letting VPN traffic through: not the standby the UI shows.
        assert_eq!(standby_check(R::Status { running: true, standby: false }, 0), (V::Lost, 0));
    }

    #[test]
    fn standby_survives_one_failed_query_but_not_two() {
        use super::{StandbyReply as R, StandbyVerdict as V, standby_check};
        let (v, n) = standby_check(R::Failed, 0);
        assert_eq!((v, n), (V::Holds, 1));
        assert_eq!(standby_check(R::Failed, n), (V::Lost, 2));
        // Failure, answer, failure: never two in a row.
        let (_, n) = standby_check(R::Failed, 0);
        let (_, n) = standby_check(R::Status { running: true, standby: true }, n);
        assert_eq!(standby_check(R::Failed, n), (V::Holds, 1));
        assert_eq!(standby_check(R::Failed, u32::MAX), (V::Lost, u32::MAX));
    }

    /// A check that saw an old standby must not end a new one, nor a session not on standby.
    #[tokio::test]
    async fn standby_lost_needs_the_current_standby() {
        use veil_config::store::Store;
        let dir = std::env::temp_dir().join(format!("veil-standby-lost-{}", uuid::Uuid::new_v4()));
        let mut core = super::Core::open_store(Store::open(&dir).unwrap()).unwrap();
        assert_eq!(core.standby_token(), None);
        assert!(!core.standby_lost(0).await);
        assert!(core.last_error().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Old configs with a geo preset (or any unknown name) start as "global".
    #[test]
    fn unknown_routing_preset_falls_back_to_global() {
        use veil_config::store::Store;
        for old in ["ru-direct", "proxy-all", "no-such-mode"] {
            let dir = std::env::temp_dir().join(format!("veil-preset-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            let json = format!(
                r#"{{"settings":{{"mixed_port":2080,"mode":"proxy","set_system_proxy":true,"routing_preset":"{old}"}}}}"#
            );
            std::fs::write(dir.join("state.json"), json).unwrap();
            let core = super::Core::open_store(Store::open(&dir).unwrap()).unwrap();
            assert_eq!(core.state.settings.routing_preset, "global", "{old}");
            let snap = serde_json::to_value(core.snapshot()).unwrap();
            assert_eq!(snap["preset"], "global");
            assert_eq!(snap["presets"].as_array().unwrap().len(), 2);
            // The fix is saved, so the next start (and the CLI) sees "global" too.
            let reloaded = Store::open(&dir).unwrap().load().unwrap();
            assert_eq!(reloaded.settings.routing_preset, "global");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Geo rules without the user's own geo files: a clear error, nothing saved.
    #[tokio::test]
    async fn geo_rules_need_user_files() {
        use veil_config::store::Store;
        use veil_config::{RouteAction, RoutingRule};
        let dir = std::env::temp_dir().join(format!("veil-geo-rules-{}", uuid::Uuid::new_v4()));
        let mut core = super::Core::open_store(Store::open(&dir).unwrap()).unwrap();
        let err = core.set_rules(vec![RoutingRule::domains(RouteAction::Direct, &["geosite:example"])]).await.unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("geosite.dat not found"), "{err}");
        assert!(err.contains(&format!("put geoip.dat and geosite.dat into {}", dir.display())), "{err}");
        assert!(core.rules().is_empty(), "rejected rules must not be saved");
        // geoip:private is built in, CIDR rules need no files.
        core.set_rules(vec![RoutingRule::ips(RouteAction::Direct, &["geoip:private", "10.0.0.0/8"])]).await.unwrap();
        assert_eq!(core.rules().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The whole decision through `Core`: which sessions may go on standby.
    #[test]
    fn standby_allowed_needs_kill_switch_and_tun() {
        use veil_config::store::{ConnectionMode, Store};
        let dir = std::env::temp_dir().join(format!("veil-standby-{}", uuid::Uuid::new_v4()));
        let mut core = super::Core::open_store(Store::open(&dir).unwrap()).unwrap();
        assert!(!core.state.settings.kill_switch, "off by default");
        assert!(!core.standby_allowed());
        core.state.settings.mode = ConnectionMode::Tun;
        assert!(!core.standby_allowed());
        core.state.settings.kill_switch = true;
        assert_eq!(core.standby_allowed(), super::STANDBY_AVAILABLE);
        core.state.settings.mode = ConnectionMode::Proxy;
        assert!(!core.standby_allowed());
        // Nothing runs: not connected, not on standby, and the UI says so.
        assert_eq!(core.session(), Session::Off);
        let snap = serde_json::to_value(core.snapshot()).unwrap();
        assert_eq!(snap["connected"], false);
        assert_eq!(snap["standby"], false);
        assert_eq!(snap["kill_switch"], true);
        std::fs::remove_dir_all(&dir).unwrap();
    }
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
        // "global" sends local addresses direct; this test's servers are local, so
        // a user rule sends them through the proxy.
        core.state.settings.routing_preset = "global".into();
        core.state.settings.custom_rules = vec![RoutingRule::ips(veil_config::RouteAction::Proxy, &["127.0.0.0/8"])];
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
        let before = core.rules();
        assert!(core.set_rules(vec![RoutingRule::ips(veil_config::RouteAction::Direct, &["10.0.0.0/33"])]).await.is_err());
        assert_eq!(core.rules(), before, "invalid rules must not be saved");
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

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    #[test]
    fn packaged_helper_is_preferred_then_the_one_next_to_the_app() {
        let c = super::helper_candidates(std::path::Path::new("/opt/veil"));
        assert_eq!(c[0], std::path::PathBuf::from("/usr/lib/veil/veil-helper"));
        assert_eq!(c[1], std::path::PathBuf::from("/opt/veil/veil-helper"));
    }

    #[test]
    fn linux_has_tun_but_no_kill_switch() {
        assert!(super::TUN_AVAILABLE);
        assert!(!super::STANDBY_AVAILABLE);
    }
}
