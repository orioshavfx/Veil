use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use uuid::Uuid;
use veil_config::store::{AppState, Store};
use veil_config::{PRESETS, Profile, Subscription, geodata, parse_links, subscription, to_link};
use veil_engine::tun::TunOptions;
use veil_engine::{Engine, EngineConfig};

#[derive(Parser)]
#[command(name = "veil", version, about = "Proxy client (debug CLI)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Import share links or a subscription URL (http/https).
    Import { input: String },
    /// List profiles.
    List,
    /// Select a profile by its number in `list`.
    Select { index: usize },
    /// Print the share link of a profile.
    Link { index: usize },
    /// Remove a profile.
    Remove { index: usize },
    /// Refresh all subscriptions.
    Update,
    /// Show routing presets, or select one.
    Route { preset: Option<String> },
    /// Download fresh geoip.dat / geosite.dat.
    GeoUpdate,
    /// Restore proxy and DNS settings saved before `run` (after a crash), and remove
    /// what a dead TUN session left behind (a TUN in use by a running Veil stays).
    RestoreProxy,
    /// Remove what a TUN session left in the system (Windows: the DNS/NRPT rule, routes
    /// and DNS of the TUN adapter), even if a running Veil is using it. Safe to repeat;
    /// exits with 2 when it needs administrator rights.
    TunCleanup,
    /// Internal: wait for process PID to end, then do `tun-cleanup` (started by Veil in TUN mode).
    #[command(hide = true)]
    TunGuard {
        #[arg(long)]
        pid: u32,
    },
    /// Install or update the privileged TUN helper (asks for an admin password).
    HelperInstall,
    /// Run the local SOCKS5/HTTP proxy with the selected profile.
    Run {
        #[arg(short, long)]
        port: Option<u16>,
        /// Use this profile number instead of the selected one.
        #[arg(long)]
        profile: Option<usize>,
        /// Don't touch the system proxy settings.
        #[arg(long)]
        no_sysproxy: bool,
        /// Capture all traffic with a virtual interface (run with sudo).
        #[arg(long)]
        tun: bool,
    },
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn profile_at(state: &AppState, index: usize) -> Result<&Profile> {
    index
        .checked_sub(1)
        .and_then(|i| state.profiles.get(i))
        .with_context(|| format!("no profile #{index}, see `veil list`"))
}

async fn refresh(state: &mut AppState, sub_id: Uuid) -> Result<usize> {
    let sub = state.subscriptions.iter().find(|s| s.id == sub_id).unwrap().clone();
    let fetched = subscription::fetch(&sub).await?;
    let count = fetched.profiles.len();
    for reason in &fetched.skipped {
        eprintln!("skipped: {reason}");
    }
    state.replace_subscription_profiles(sub.id, fetched.profiles);
    let sub = state.subscriptions.iter_mut().find(|s| s.id == sub_id).unwrap();
    sub.last_updated = Some(now());
    sub.usage = fetched.usage;
    if let Some(title) = fetched.title {
        sub.name = title;
    }
    if let Some(h) = fetched.update_interval_hours {
        sub.update_interval_hours = h;
    }
    Ok(count)
}

fn dns_backup(store: &Store) -> std::path::PathBuf {
    store.dir().join("dns-backup.json")
}

fn proxy_backup(store: &Store) -> std::path::PathBuf {
    store.dir().join("sysproxy-backup.json")
}

/// Ctrl+C or SIGTERM (e.g. `kill`, logout).
#[cfg(unix)]
async fn wait_for_shutdown() -> Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r?,
        _ = term.recv() => {}
    }
    Ok(())
}

/// Ctrl+C, or the console window being closed.
#[cfg(windows)]
async fn wait_for_shutdown() -> Result<()> {
    let mut close = tokio::signal::windows::ctrl_close()?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r?,
        _ = close.recv() => {}
    }
    Ok(())
}

/// Prints what `tun_cleanup` did; true when everything of ours is gone.
fn print_cleanup(report: &veil_sysproxy::CleanupReport) -> bool {
    for item in &report.removed {
        println!("removed: {item}");
    }
    for item in &report.failed {
        eprintln!("NOT removed: {item}");
    }
    if report.needs_admin {
        eprintln!("administrator rights are needed: run this again from an elevated prompt (or run veil-rescue.ps1)");
    }
    report.failed.is_empty()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    // A panic must not leave the system pointing at a tunnel that is about to die. The hook
    // touches nothing itself: `run` sees the flag and stops the engine the normal way.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        veil_engine::note_panic();
        default_hook(info);
    }));
    let cli = Cli::parse();
    // The rescue commands come first: they must work even when the settings cannot be read.
    match cli.cmd {
        Cmd::TunCleanup => {
            let report = veil_sysproxy::tun_cleanup();
            let clean = print_cleanup(&report);
            if report.is_empty() {
                println!("nothing to clean up");
            }
            if !clean {
                std::process::exit(if report.needs_admin { 2 } else { 1 });
            }
            return Ok(());
        }
        Cmd::TunGuard { pid } => {
            #[cfg(windows)]
            let _ = veil_sysproxy::tun_guard(pid);
            #[cfg(not(windows))]
            let _ = pid;
            return Ok(());
        }
        _ => {}
    }
    let store = Store::open_default()?;
    let mut state = store.load()?;

    match cli.cmd {
        Cmd::Import { input } => {
            if input.starts_with("http://") || input.starts_with("https://") {
                let sub = Subscription {
                    id: Uuid::new_v4(),
                    name: input.clone(),
                    url: input,
                    update_interval_hours: 12,
                    last_updated: None,
                    usage: None,
                };
                let id = sub.id;
                state.subscriptions.push(sub);
                let n = refresh(&mut state, id).await?;
                println!("subscription added, {n} profiles");
            } else {
                let profiles = parse_links(&input);
                if profiles.is_empty() {
                    bail!("no valid links found");
                }
                println!("imported {} profiles", profiles.len());
                state.profiles.extend(profiles);
            }
            store.save(&state)?;
        }
        Cmd::List => {
            let selected = state.selected_profile().map(|p| p.id);
            for (i, p) in state.profiles.iter().enumerate() {
                let mark = if Some(p.id) == selected { "*" } else { " " };
                let s = &p.server;
                println!("{mark}{:>3}  {:<11} {}  ({}:{})", i + 1, s.protocol.name(), p.name, s.address, s.port);
            }
            for sub in &state.subscriptions {
                print!("subscription: {} ", sub.name);
                if let Some(u) = &sub.usage {
                    print!("[{:.2}/{:.2} GiB] ", (u.upload + u.download) as f64 / 1073741824.0, u.total as f64 / 1073741824.0);
                }
                println!();
            }
        }
        Cmd::Select { index } => {
            let p = profile_at(&state, index)?;
            println!("selected {}", p.name);
            state.selected = Some(p.id);
            store.save(&state)?;
        }
        Cmd::Link { index } => println!("{}", to_link(profile_at(&state, index)?)),
        Cmd::Remove { index } => {
            let id = profile_at(&state, index)?.id;
            state.profiles.retain(|p| p.id != id);
            store.save(&state)?;
        }
        Cmd::Update => {
            let ids: Vec<_> = state.subscriptions.iter().map(|s| s.id).collect();
            for id in ids {
                match refresh(&mut state, id).await {
                    Ok(n) => println!("updated: {n} profiles"),
                    Err(e) => eprintln!("update failed: {e:#}"),
                }
            }
            store.save(&state)?;
        }
        Cmd::Route { preset } => match preset {
            None => {
                for (name, desc) in PRESETS {
                    let mark = if *name == state.settings.routing_preset { "*" } else { " " };
                    println!("{mark} {name:<10} {desc}");
                }
                for r in &state.settings.custom_rules {
                    println!("  custom: {r:?}");
                }
            }
            Some(name) => {
                if !PRESETS.iter().any(|(n, _)| *n == name) {
                    bail!("unknown preset {name}, see `veil route`");
                }
                state.settings.routing_preset = name;
                store.save(&state)?;
            }
        },
        Cmd::GeoUpdate => {
            geodata::download(store.dir()).await?;
            println!("geo data updated in {}", store.dir().display());
        }
        Cmd::HelperInstall => {
            let exe = std::env::current_exe()?;
            let helper = exe.with_file_name("veil-helper");
            veil_helper::install(&helper)?;
            println!("helper {} installed", veil_helper::VERSION);
        }
        Cmd::RestoreProxy => {
            // Every step runs even if an earlier one failed, and a failure is never
            // reported as "nothing to restore".
            let proxy = veil_sysproxy::restore(&proxy_backup(&store));
            let dns = veil_sysproxy::dns_restore(&dns_backup(&store));
            // Only leftovers: a TUN that a running Veil is using stays (`tun-cleanup` forces it).
            let report = veil_sysproxy::tun_cleanup_if_orphaned().unwrap_or_else(|| {
                println!("TUN: in use by a running Veil, left alone");
                veil_sysproxy::CleanupReport::default()
            });
            let mut failed = !print_cleanup(&report);
            for (what, result) in [("proxy", &proxy), ("DNS", &dns)] {
                if let Err(e) = result {
                    eprintln!("restoring {what} failed: {e:#}");
                    failed = true;
                }
            }
            let (proxy, dns) = (proxy.unwrap_or(false), dns.unwrap_or(false));
            if proxy || dns {
                println!("restored:{}{}", if proxy { " proxy" } else { "" }, if dns { " DNS" } else { "" });
            } else if !failed && report.is_empty() {
                println!("nothing to restore");
            }
            if failed {
                std::process::exit(if report.needs_admin { 2 } else { 1 });
            }
        }
        Cmd::TunCleanup | Cmd::TunGuard { .. } => unreachable!("handled before the settings are opened"),
        Cmd::Run { port, profile, no_sysproxy, tun } => {
            let backup = proxy_backup(&store);
            if veil_sysproxy::restore(&backup)? {
                println!("restored system proxy left over from a previous run");
            }
            let p = match profile {
                Some(i) => profile_at(&state, i)?,
                None => state.selected_profile().context("no profiles, import some first")?,
            };
            let routing = state.settings.routing();
            let uses_geo = routing.uses_geo_files();
            if uses_geo && !geodata::present(store.dir()) {
                println!("downloading geoip/geosite data...");
                geodata::download(store.dir()).await?;
            }
            let port = port.unwrap_or(state.settings.mixed_port);
            let listen = SocketAddr::from(([127, 0, 0, 1], port));
            println!(
                "using {} ({}), routing: {}",
                p.name,
                p.server.protocol.name(),
                state.settings.routing_preset
            );
            let engine = Engine::start(EngineConfig {
                listen,
                server: p.server.clone(),
                routing,
                geo_dir: store.dir().to_path_buf(),
                tun: tun.then(|| TunOptions { mtu: 1500, dns_backup: dns_backup(&store), routes: veil_engine::tun::TunRoutes::All }),
            })
            .await?;
            if tun {
                println!("TUN mode: all traffic goes through the tunnel");
            }
            let sysproxy = !tun && state.settings.set_system_proxy && !no_sysproxy;
            if sysproxy {
                veil_sysproxy::enable("127.0.0.1", port, &backup)?;
                println!("system proxy enabled");
            }
            println!("SOCKS5/HTTP proxy on {listen}, Ctrl+C to stop");
            let tun_died = async {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    if engine.tun_failed() {
                        return;
                    }
                }
            };
            tokio::select! {
                r = wait_for_shutdown() => r?,
                _ = tun_died => eprintln!("the TUN tunnel stopped unexpectedly: shutting down"),
            }
            if sysproxy {
                veil_sysproxy::restore(&backup)?;
                println!("\nsystem proxy restored");
            }
            let stats = engine.stats();
            println!(
                "up {} KiB, down {} KiB",
                stats.upload.load(Ordering::Relaxed) / 1024,
                stats.download.load(Ordering::Relaxed) / 1024
            );
            engine.stop().await;
        }
    }
    Ok(())
}
