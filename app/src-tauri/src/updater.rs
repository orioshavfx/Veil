//! In-app updates from GitHub Releases: macOS only.
//!
//! The Windows build is a portable zip without an installer, so there the UI only points to
//! the releases page. On macOS the Rust API of `tauri-plugin-updater` is used directly: the
//! window gets no `updater:*` permissions, only the commands below. `latest.json` of the
//! latest GitHub release names the version, `Veil.app.tar.gz` and its minisign signature;
//! the download is checked against [`UPDATER_PUBKEY`] (and the version it was signed for)
//! before the VPN is stopped and anything is installed.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::sync::atomic::{AtomicU8, Ordering};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::Mutex;

use crate::core::Core;

/// Public key of the update signing key pair (the contents of `update.key.pub`, as printed by
/// `app/tools/gen-update-key.sh`). Empty: this build has no key, updates are off and nothing
/// is downloaded; the UI says "Updates are not configured in this build".
pub const UPDATER_PUBKEY: &str = "";

/// Only HTTPS, only github.com: `releases/latest` is the newest release that is neither a
/// draft nor a prerelease.
pub const UPDATE_ENDPOINT: &str = "https://github.com/orioshavfx/Veil/releases/latest/download/latest.json";
pub const RELEASES_PAGE: &str = "https://github.com/orioshavfx/Veil/releases";

const NOT_CONFIGURED: &str = "Updates are not configured in this build.";

/// Whether this build can update itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Not macOS: updates are downloaded by hand from the releases page.
    Unsupported,
    /// macOS, but built without a public key.
    NotConfigured,
    Ready,
}

pub fn availability(supported: bool, pubkey: &str) -> Availability {
    if !supported {
        Availability::Unsupported
    } else if pubkey.trim().is_empty() {
        Availability::NotConfigured
    } else {
        Availability::Ready
    }
}

pub fn this_build() -> Availability {
    availability(cfg!(target_os = "macos"), UPDATER_PUBKEY)
}

/// True when `remote` is a newer release than `current` (semver, a leading `v` allowed):
/// 1.0.0-beta.1 < 1.0.0-beta.2 < 1.0.0 < 1.0.1. Build metadata is ignored, and anything
/// that does not parse is never an update.
pub fn is_newer(current: &str, remote: &str) -> bool {
    let parse = |s: &str| {
        semver::Version::parse(s.trim().trim_start_matches('v')).ok().map(|mut v| {
            v.build = semver::BuildMetadata::EMPTY;
            v
        })
    };
    match (parse(current), parse(remote)) {
        (Some(c), Some(r)) => r > c,
        _ => false,
    }
}

/// Where an installation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum Phase {
    Idle = 0,
    /// Downloading and checking the signature; the VPN is untouched.
    Downloading = 1,
    /// Stopping the VPN the way Quit does.
    Stopping = 2,
    /// Replacing the app bundle.
    Installing = 3,
    /// Installed; the app restarts into the new version.
    Restarting = 4,
}

impl Phase {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Phase::Downloading,
            2 => Phase::Stopping,
            3 => Phase::Installing,
            4 => Phase::Restarting,
            _ => Phase::Idle,
        }
    }
}

/// One installation at a time.
pub struct InstallGate(AtomicU8);

impl InstallGate {
    pub const fn new() -> Self {
        Self(AtomicU8::new(Phase::Idle as u8))
    }

    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.0.load(Ordering::SeqCst))
    }

    /// Starts an installation; `None` while another one runs (or the app restarts after one).
    pub fn begin(&self) -> Option<Ticket<'_>> {
        self.0
            .compare_exchange(Phase::Idle as u8, Phase::Downloading as u8, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Ticket { gate: self, done: false })
    }
}

/// A running installation. Dropped before [`Ticket::finish`] (an error), the gate opens again.
pub struct Ticket<'a> {
    gate: &'a InstallGate,
    done: bool,
}

impl Ticket<'_> {
    pub fn set(&self, phase: Phase) {
        self.gate.0.store(phase as u8, Ordering::SeqCst);
    }

    /// Installed: the gate stays closed until the process is gone.
    pub fn finish(mut self) {
        self.set(Phase::Restarting);
        self.done = true;
    }
}

impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        if !self.done {
            self.set(Phase::Idle);
        }
    }
}

/// An update that the last check found.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Available {
    pub version: String,
    pub notes: Option<String>,
    /// `YYYY-MM-DD`.
    pub date: Option<String>,
}

#[derive(Default)]
struct LastCheck {
    checked: bool,
    available: Option<Available>,
    error: Option<String>,
}

/// What the UI shows in Settings → Updates.
#[derive(Debug, Clone, Serialize)]
pub struct UpdateStatus {
    availability: Availability,
    current_version: String,
    releases_page: &'static str,
    /// A check finished in this session.
    checked: bool,
    available: Option<Available>,
    /// The last check failed.
    error: Option<String>,
    phase: Phase,
}

/// Managed state: the last check and the installation gate.
pub struct Updates {
    last: std::sync::Mutex<LastCheck>,
    gate: InstallGate,
}

impl Default for InstallGate {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Updates {
    fn default() -> Self {
        Self::new()
    }
}

impl Updates {
    pub fn new() -> Self {
        Self { last: std::sync::Mutex::new(LastCheck::default()), gate: InstallGate::new() }
    }

    fn record(&self, result: &Result<Option<Available>, String>) {
        let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(found) => {
                last.checked = true;
                last.available = found.clone();
                last.error = None;
            }
            Err(e) => last.error = Some(e.clone()),
        }
    }

    /// A failed installation: shown in Settings → Updates until the next check.
    fn record_install_error(&self, e: &str) {
        self.last.lock().unwrap_or_else(|e| e.into_inner()).error = Some(e.to_string());
    }

    fn status(&self, app: &AppHandle) -> UpdateStatus {
        let last = self.last.lock().unwrap_or_else(|e| e.into_inner());
        UpdateStatus {
            availability: this_build(),
            current_version: app.package_info().version.to_string(),
            releases_page: RELEASES_PAGE,
            checked: last.checked,
            available: last.available.clone(),
            error: last.error.clone(),
            phase: self.gate.phase(),
        }
    }
}

/// Payload of the `update-progress` event.
#[derive(Clone, Serialize)]
struct Progress {
    phase: Phase,
    downloaded: u64,
    total: Option<u64>,
}

fn emit_progress(app: &AppHandle, phase: Phase, downloaded: u64, total: Option<u64>) {
    let _ = app.emit("update-progress", Progress { phase, downloaded, total });
}

/// The macOS plugin: needs `plugins.updater` in tauri.conf.json (its config does not
/// deserialize without one); the key and endpoint are set in code, see [`UPDATER_PUBKEY`].
pub fn register(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    #[cfg(target_os = "macos")]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build());
    builder
}

/// The last check, without a request.
#[tauri::command]
pub async fn update_status(app: AppHandle) -> Result<UpdateStatus, String> {
    Ok(app.state::<Updates>().status(&app))
}

/// Asks GitHub for the latest release. Not configured or not macOS: no request, only the status.
#[tauri::command]
pub async fn check_update(app: AppHandle) -> Result<UpdateStatus, String> {
    let updates = app.state::<Updates>();
    if this_build() != Availability::Ready {
        return Ok(updates.status(&app));
    }
    #[cfg(target_os = "macos")]
    {
        let result = mac::find(&app).await.map(|u| u.as_ref().map(mac::describe));
        updates.record(&result);
        result?;
    }
    Ok(updates.status(&app))
}

/// Downloads the update, checks its signature, stops the VPN like Quit, installs it and
/// restarts the app.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    if this_build() == Availability::Unsupported {
        return Err(format!("Download new versions of Veil from {RELEASES_PAGE}"));
    }
    if this_build() != Availability::Ready {
        return Err(NOT_CONFIGURED.into());
    }
    #[cfg(target_os = "macos")]
    {
        let updates = app.state::<Updates>();
        let ticket = updates.gate.begin().ok_or("An update is already being installed.")?;
        match mac::install(&app, &ticket).await {
            Ok(()) => {
                ticket.finish();
                Ok(())
            }
            Err(e) => {
                tracing::warn!("update not installed: {e}");
                // From `Stopping` on the VPN was stopped (`Core::quit`) under the core lock,
                // which `install` released when it returned.
                let vpn_stopped = matches!(updates.gate.phase(), Phase::Stopping | Phase::Installing);
                drop(ticket);
                emit_progress(&app, Phase::Idle, 0, None);
                // Settings → Updates keeps showing it (not only the toast).
                updates.record_install_error(&e);
                if vpn_stopped {
                    // The VPN is off now (a standby too): the tray, the window and the panel
                    // must say so, and the error stays until the next connection.
                    app.state::<Mutex<Core>>().lock().await.set_error(e.clone());
                    crate::update_tray(&app).await; // also emits `state-changed`
                }
                let _ = app.emit("update-status", ());
                Err(e)
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    Err(NOT_CONFIGURED.into())
}

#[tauri::command]
pub async fn set_check_updates(core: State<'_, Mutex<Core>>, enabled: bool) -> Result<(), String> {
    core.lock().await.set_check_updates(enabled).map_err(|e| format!("{e:#}"))
}

/// Once per start, quietly: the UI shows a small "Update available" in the header, nothing pops up.
#[cfg_attr(not(target_os = "macos"), allow(unused_variables))]
pub fn spawn_startup_check(app: &AppHandle) {
    if this_build() != Availability::Ready {
        return;
    }
    #[cfg(target_os = "macos")]
    {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(mac::STARTUP_CHECK_DELAY).await;
            if !app.state::<Mutex<Core>>().lock().await.state.settings.check_updates {
                return;
            }
            let result = mac::find(&app).await.map(|u| u.as_ref().map(mac::describe));
            match &result {
                Ok(Some(a)) => tracing::info!("update available: {}", a.version),
                Ok(None) => tracing::info!("no update available"),
                Err(e) => tracing::info!("update check failed: {e}"),
            }
            app.state::<Updates>().record(&result);
            let _ = app.emit("update-status", ());
        });
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use tauri::{AppHandle, Manager};
    use tauri_plugin_updater::{Error, Update, Updater, UpdaterExt};
    use tokio::sync::Mutex;

    use super::{Available, Phase, Ticket, UPDATE_ENDPOINT, UPDATER_PUBKEY, emit_progress, is_newer};
    use crate::core::Core;

    const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
    const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);
    pub const STARTUP_CHECK_DELAY: Duration = Duration::from_secs(10);
    /// How long the update waits for a running action (connecting, say) to finish.
    const CORE_WAIT: Duration = Duration::from_secs(10);
    const CONNECTING_MSG: &str = "Veil is connecting. Install the update when it has finished.";
    const BUSY: &str = "Veil is busy (connecting or updating). Try again when it has finished.";
    const PERMISSION_DENIED: &str = "Administrator permission was denied or the password prompt was cancelled, so the update was not installed. \
         Try again, or install the update by hand from the releases page.";

    fn updater(app: &AppHandle) -> Result<Updater, String> {
        let url: tauri::Url = UPDATE_ENDPOINT.parse().map_err(|e| format!("bad update URL: {e}"))?;
        app.updater_builder()
            .pubkey(UPDATER_PUBKEY)
            .endpoints(vec![url])
            .map_err(|e| explain(&e))?
            .timeout(CHECK_TIMEOUT)
            .version_comparator(|current, release| is_newer(&current.to_string(), &release.version.to_string()))
            .build()
            .map_err(|e| explain(&e))
    }

    /// The newer release, if there is one.
    pub async fn find(app: &AppHandle) -> Result<Option<Update>, String> {
        let updater = updater(app)?;
        match tokio::time::timeout(CHECK_TIMEOUT + Duration::from_secs(5), updater.check()).await {
            Ok(r) => r.map_err(|e| explain(&e)),
            Err(_) => Err("Checking for updates timed out. Check your internet connection and try again.".into()),
        }
    }

    pub fn describe(u: &Update) -> Available {
        Available {
            version: u.version.clone(),
            notes: u.body.clone().filter(|n| !n.trim().is_empty()),
            date: u.date.map(|d| d.date().to_string()),
        }
    }

    pub async fn install(app: &AppHandle, ticket: &Ticket<'_>) -> Result<(), String> {
        // Before anything is downloaded or stopped: can this copy of Veil be replaced at all?
        let exe = std::env::current_exe().map_err(|e| format!("Update failed: cannot find Veil's own path ({e})."))?;
        let bundle = replaceable_bundle(&exe)?;
        probe_volume(&bundle)?;
        let core = app.state::<Mutex<Core>>();
        // Never while a connection is being set up; other actions hold the core lock briefly.
        if crate::core::CONNECTING.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(CONNECTING_MSG.into());
        }
        drop(tokio::time::timeout(CORE_WAIT, core.lock()).await.map_err(|_| BUSY)?);

        let mut update = find(app).await?.ok_or("Veil is already up to date.")?;
        update.timeout = Some(DOWNLOAD_TIMEOUT);
        tracing::info!("downloading update {}", update.version);
        emit_progress(app, Phase::Downloading, 0, None);
        let mut downloaded = 0u64;
        let mut shown = 0u64;
        let bytes = tokio::time::timeout(
            DOWNLOAD_TIMEOUT,
            update.download(
                |chunk, total| {
                    downloaded += chunk as u64;
                    if downloaded - shown >= 256 * 1024 || Some(downloaded) == total {
                        shown = downloaded;
                        emit_progress(app, Phase::Downloading, downloaded, total);
                    }
                },
                || {},
            ),
        )
        .await
        .map_err(|_| "The download timed out. Check your internet connection and try again.".to_string())?
        .map_err(|e| explain(&e))?;

        // The package is here and its signature checked (`download` verifies it): only now
        // stop the VPN, the way Quit does (a standby included), and keep the core locked from
        // here to the restart, so nothing connects in between.
        let mut c = tokio::time::timeout(CORE_WAIT, core.lock()).await.map_err(|_| BUSY)?;
        // `Stopping` only once the lock is held: from here on the VPN is touched (see the
        // error arm of `install_update`).
        ticket.set(Phase::Stopping);
        emit_progress(app, Phase::Stopping, downloaded, None);
        let was_on = c.is_connected() || c.is_standby();
        tracing::info!("update {}: stopping the VPN", update.version);
        c.quit().await;
        let _ = tokio::task::spawn_blocking(veil_sysproxy::tun_cleanup_own).await;
        let after = |msg: String| if was_on { format!("{msg} The VPN was turned off; connect again.") } else { msg };
        if tun_still_up().await {
            return Err(after("The TUN helper still has a tunnel up, so the update was not installed. Quit Veil and try again.".into()));
        }

        ticket.set(Phase::Installing);
        emit_progress(app, Phase::Installing, downloaded, None);
        let version = update.version.clone();
        match tokio::task::spawn_blocking(move || update.install(bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(after(explain(&e))),
            Err(e) => return Err(after(format!("Update failed: {e}"))),
        }

        tracing::info!("update {version} installed: restarting");
        ticket.set(Phase::Restarting);
        emit_progress(app, Phase::Restarting, downloaded, None);
        // Stays locked until the process is gone (see the restart arm of `RunEvent::ExitRequested`).
        std::mem::forget(c);
        app.request_restart();
        Ok(())
    }

    const MOVE_TO_APPLICATIONS: &str =
        "Move Veil to the Applications folder (drag it there in Finder), open it from there and try again, \
         or install the update by hand from the releases page.";

    /// The `.app` bundle that `exe` (`current_exe`) runs from, if the updater can replace it:
    /// `<bundle>.app/Contents/MacOS/<exe>`, and not a copy that macOS runs from a randomized
    /// read-only location (App Translocation: an app opened from Downloads without moving it).
    pub fn replaceable_bundle(exe: &Path) -> Result<PathBuf, String> {
        if exe.components().any(|c| c.as_os_str() == "AppTranslocation") {
            return Err(format!(
                "macOS runs this copy of Veil from a temporary read-only location (App Translocation), so it cannot update itself. {MOVE_TO_APPLICATIONS}"
            ));
        }
        let macos = exe.parent().filter(|p| p.file_name().is_some_and(|n| n == "MacOS"));
        let contents = macos.and_then(Path::parent).filter(|p| p.file_name().is_some_and(|n| n == "Contents"));
        let bundle = contents
            .and_then(Path::parent)
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("app")))
            .filter(|p| p.parent().is_some());
        bundle.map(Path::to_path_buf).ok_or_else(|| {
            format!("This copy of Veil does not run from an app bundle ({}), so it cannot update itself.", exe.display())
        })
    }

    /// The folder that holds the bundle must not be on a read-only volume (a disk image, say).
    /// A folder that is only not writable for this user is fine: macOS then asks for an
    /// administrator password. Probed with a file that is removed right away.
    fn probe_volume(bundle: &Path) -> Result<(), String> {
        let Some(dir) = bundle.parent() else { return Ok(()) };
        let probe = dir.join(format!(".veil-update-probe-{}", std::process::id()));
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::ReadOnlyFilesystem => Err(format!(
                "Veil is on a read-only disk ({}), so it cannot update itself. {MOVE_TO_APPLICATIONS}",
                dir.display()
            )),
            // Not writable for this user (the installer asks for a password), or the probe
            // name is taken: the installation itself decides.
            Err(_) => Ok(()),
        }
    }

    /// The helper (if installed and running) still carries a TUN session.
    async fn tun_still_up() -> bool {
        let query = tokio::task::spawn_blocking(veil_helper::status);
        matches!(tokio::time::timeout(Duration::from_secs(10), query).await, Ok(Ok(Ok(s))) if s.running)
    }

    /// Plain-English errors for the UI.
    pub fn explain(e: &Error) -> String {
        match e {
            Error::Reqwest(_) | Error::Network(_) => {
                format!("Could not reach GitHub. Check your internet connection and try again. ({e})")
            }
            Error::ReleaseNotFound => "No update information was found on GitHub. Try again later.".into(),
            Error::TargetNotFound(_) | Error::TargetsNotFound(_) => "The latest release has no build for this Mac.".into(),
            Error::Minisign(_)
            | Error::Base64(_)
            | Error::SignatureUtf8(_)
            | Error::SignedVersionMismatch { .. }
            | Error::MissingSignedVersion => {
                "The update's signature is not valid, so it was not installed. Download Veil from the releases page instead.".into()
            }
            // On macOS a cancelled password prompt also ends up as `Io(PermissionDenied)`.
            Error::AuthenticationFailed => PERMISSION_DENIED.into(),
            Error::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => PERMISSION_DENIED.into(),
            Error::PreviousAppNotRestored(path) => format!(
                "The update failed and the previous Veil was left at {}. Move it back to Applications.",
                path.display()
            ),
            Error::TempDirNotOnSameMountPoint => {
                "Veil cannot update itself on this disk. Install the update by hand from the releases page.".into()
            }
            Error::Serialization(_) | Error::Semver(_) | Error::UrlParse(_) => {
                "The update information on GitHub is malformed. Try again later.".into()
            }
            other => format!("Update failed: {other}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_semver_with_prereleases() {
        assert!(is_newer("1.0.0-beta.1", "1.0.0-beta.2"));
        assert!(is_newer("1.0.0-beta.2", "1.0.0"));
        assert!(is_newer("1.0.0-beta.9", "1.0.0-beta.10"));
        assert!(is_newer("1.0.0", "1.0.1"));
        assert!(is_newer("1.0.0", "v1.1.0"));
        assert!(!is_newer("1.0.0-beta.2", "1.0.0-beta.1"));
        assert!(!is_newer("1.0.0", "1.0.0-beta.3"));
        assert!(!is_newer("1.0.0", "1.0.0"));
        assert!(!is_newer("1.0.0", "1.0.0+other-build"));
        assert!(!is_newer("1.0.0", "latest"));
        assert!(!is_newer("garbage", "2.0.0"));
    }

    #[test]
    fn availability_needs_macos_and_a_key() {
        assert_eq!(availability(false, "key"), Availability::Unsupported);
        assert_eq!(availability(true, ""), Availability::NotConfigured);
        assert_eq!(availability(true, "  \n"), Availability::NotConfigured);
        assert_eq!(availability(true, "RWQ..."), Availability::Ready);
        // This build has no key yet: no update request may go out.
        assert_ne!(this_build(), Availability::Ready);
        assert_eq!(serde_json::to_value(Availability::NotConfigured).unwrap(), "not_configured");
    }

    #[test]
    fn endpoint_is_https_github() {
        assert!(UPDATE_ENDPOINT.starts_with("https://github.com/orioshavfx/Veil/releases/latest/download/"));
        assert!(RELEASES_PAGE.starts_with("https://github.com/"));
    }

    #[test]
    fn one_installation_at_a_time() {
        let gate = InstallGate::new();
        assert_eq!(gate.phase(), Phase::Idle);
        let t = gate.begin().expect("first");
        assert_eq!(gate.phase(), Phase::Downloading);
        assert!(gate.begin().is_none(), "a second installation must not start");
        t.set(Phase::Installing);
        assert!(gate.begin().is_none());
        // A failure (the ticket dropped) opens the gate again.
        drop(t);
        assert_eq!(gate.phase(), Phase::Idle);
        let t = gate.begin().expect("after a failure");
        // Installed: closed for good, the app is restarting.
        t.finish();
        assert_eq!(gate.phase(), Phase::Restarting);
        assert!(gate.begin().is_none());
    }

    #[test]
    fn last_check_is_recorded() {
        let u = Updates::new();
        let found = Available { version: "1.0.0".into(), notes: None, date: None };
        u.record(&Ok(Some(found.clone())));
        {
            let l = u.last.lock().unwrap();
            assert!(l.checked && l.error.is_none());
            assert_eq!(l.available.as_ref(), Some(&found));
        }
        u.record(&Err("offline".into()));
        assert_eq!(u.last.lock().unwrap().error.as_deref(), Some("offline"));
        u.record(&Ok(None));
        let l = u.last.lock().unwrap();
        assert!(l.available.is_none() && l.error.is_none());
    }

    /// The manifest that app/tools/make-latest-json.py writes, read by the plugin's own parser.
    #[cfg(target_os = "macos")]
    #[test]
    fn latest_json_picks_the_apple_silicon_build() {
        use tauri_plugin_updater::RemoteRelease;
        let json = r#"{
          "version": "1.0.0-beta.2",
          "notes": "Fixes",
          "pub_date": "2026-11-14T12:00:00Z",
          "platforms": {
            "darwin-aarch64": {
              "signature": "dW50cnVzdGVkIGNvbW1lbnQ=",
              "url": "https://github.com/orioshavfx/Veil/releases/download/v1.0.0-beta.2/Veil.app.tar.gz"
            }
          }
        }"#;
        let r: RemoteRelease = serde_json::from_str(json).unwrap();
        assert!(is_newer("1.0.0-beta.1", &r.version.to_string()));
        assert_eq!(
            r.download_url("darwin-aarch64").unwrap().as_str(),
            "https://github.com/orioshavfx/Veil/releases/download/v1.0.0-beta.2/Veil.app.tar.gz"
        );
        assert_eq!(r.signature("darwin-aarch64").unwrap(), "dW50cnVzdGVkIGNvbW1lbnQ=");
        assert!(r.download_url("darwin-x86_64").is_err());
        assert!(r.pub_date.is_some());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn errors_are_explained() {
        use tauri_plugin_updater::Error;
        let perm = Error::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "x"));
        assert!(mac::explain(&perm).contains("password prompt was cancelled"));
        assert_eq!(mac::explain(&perm), mac::explain(&Error::AuthenticationFailed));
        assert!(mac::explain(&Error::MissingSignedVersion).contains("signature is not valid"));
        assert!(mac::explain(&Error::TargetsNotFound(vec!["darwin-aarch64".into()])).contains("no build"));
        assert!(mac::explain(&Error::ReleaseNotFound).contains("GitHub"));
        assert!(mac::explain(&Error::Network("503".into())).contains("internet connection"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_a_regular_app_bundle_is_replaced() {
        use std::path::Path;
        let ok = mac::replaceable_bundle(Path::new("/Applications/Veil.app/Contents/MacOS/veil-app")).unwrap();
        assert_eq!(ok, Path::new("/Applications/Veil.app"));
        let translocated = Path::new("/private/var/folders/x/T/AppTranslocation/ABC/d/Veil.app/Contents/MacOS/veil-app");
        assert!(mac::replaceable_bundle(translocated).unwrap_err().contains("App Translocation"));
        assert!(mac::replaceable_bundle(Path::new("/Users/me/target/release/veil-app")).unwrap_err().contains("app bundle"));
        assert!(mac::replaceable_bundle(Path::new("/x/Veil/Contents/MacOS/veil-app")).is_err());
    }
}
