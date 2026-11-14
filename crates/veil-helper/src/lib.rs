//! Privileged helper for TUN mode: protocol, client and installer.
//!
//! The helper runs as root under launchd and accepts JSON-line requests on a
//! Unix socket, only from the user it was installed for.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use veil_config::{RoutingConfig, ServerConfig};
pub use veil_engine::tun::TunRoutes;

pub const LABEL: &str = "dev.veil.helper";
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("VEIL_BUILD_ID"));

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Start {
        server: Box<ServerConfig>,
        routing: RoutingConfig,
        geo_dir: PathBuf,
        /// Local SOCKS/HTTP port that also runs alongside TUN.
        mixed_port: u16,
        #[serde(default)]
        routes: TunRoutes,
    },
    /// Switch server and/or rules of the running session without restarting TUN.
    Update {
        server: Option<Box<ServerConfig>>,
        routing: Option<RoutingConfig>,
        geo_dir: PathBuf,
    },
    Stop,
    Status,
    /// Kill switch: `on` keeps TUN, routes and DNS but refuses every connection that would go
    /// through the VPN (and closes those open through it); `off` lets them through again.
    Standby { on: bool },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    /// SHA-256 of the running helper executable; the app compares it with the
    /// helper it ships to decide whether to reinstall.
    #[serde(default)]
    pub binary_hash: String,
    pub running: bool,
    pub upload: u64,
    pub download: u64,
    /// The running session is on standby (see [`Request::Standby`]).
    #[serde(default)]
    pub standby: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status(Status),
    Error { message: String },
}

/// Prefix of the daemon's answer to a request it cannot parse (see `daemon_unix`).
pub const BAD_REQUEST: &str = "bad request:";

/// The helper's `Error` message as the app shows it. The app reinstalls a helper that is not
/// the one it ships before starting TUN, so a mismatch should not happen; if a helper from
/// another Veil build is still asked something it does not know, say what to do instead of
/// showing serde's "unknown variant" alone.
pub fn error_text(message: &str) -> String {
    if message.starts_with(BAD_REQUEST) {
        format!(
            "The installed TUN helper belongs to a different version of Veil and did not understand the request. \
             Disconnect and connect again to reinstall it (macOS asks for an administrator password). ({message})"
        )
    } else {
        message.to_string()
    }
}

pub fn status() -> Result<Status> {
    match call(&Request::Status)? {
        Response::Status(s) => Ok(s),
        other => bail!("unexpected response {other:?}"),
    }
}

pub fn file_hash(path: &Path) -> Result<String> {
    use sha2::Digest;
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect())
}

/// True when the running helper is exactly the binary at `shipped`.
pub fn is_current(shipped: &Path) -> bool {
    let Ok(want) = file_hash(shipped) else { return false };
    status().is_ok_and(|s| s.binary_hash == want)
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{INSTALL_PATH, PLIST_PATH, SOCKET_PATH, call, install, uninstall};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{call, install, uninstall};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standby_request_json() {
        let on = serde_json::to_string(&Request::Standby { on: true }).unwrap();
        assert_eq!(on, r#"{"cmd":"standby","on":true}"#);
        assert!(matches!(serde_json::from_str(&on).unwrap(), Request::Standby { on: true }));
        assert!(matches!(
            serde_json::from_str(r#"{"cmd":"standby","on":false}"#).unwrap(),
            Request::Standby { on: false }
        ));
        // What older clients send still reads the same.
        assert!(matches!(serde_json::from_str(r#"{"cmd":"stop"}"#).unwrap(), Request::Stop));
        assert!(matches!(serde_json::from_str(r#"{"cmd":"status"}"#).unwrap(), Request::Status));
        // `on` is required: a bare standby request must not silently mean "off".
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"standby"}"#).is_err());
    }

    #[test]
    fn unknown_requests_get_an_explained_error() {
        // What an older helper does with a request it does not know (daemon_unix): it
        // answers with an error, and the app turns that into advice.
        let e = serde_json::from_str::<Request>(r#"{"cmd":"something_newer","x":1}"#).unwrap_err();
        let answer = format!("{BAD_REQUEST} {e}");
        let shown = error_text(&answer);
        assert!(shown.contains("different version of Veil"), "{shown}");
        assert!(shown.contains("connect again"));
        assert!(shown.contains("something_newer"));
        // Other errors pass through unchanged.
        assert_eq!(error_text("not running"), "not running");
        // A `Status` from an older helper without `binary_hash` never matches the shipped
        // binary, so the app reinstalls it before starting TUN.
        let old: Status = serde_json::from_str(r#"{"version":"0.9.0+1","running":false,"upload":0,"download":0}"#).unwrap();
        assert!(old.binary_hash.is_empty());
    }

    #[test]
    fn status_without_standby_reads_as_off() {
        // A status from an older helper.
        let old = r#"{"version":"0.1.0+x","binary_hash":"ab","running":true,"upload":1,"download":2}"#;
        let s: Status = serde_json::from_str(old).unwrap();
        assert!(s.running && !s.standby);
        assert_eq!((s.upload, s.download), (1, 2));
        let new = Status { running: true, standby: true, ..Default::default() };
        let back: Status = serde_json::from_str(&serde_json::to_string(&new).unwrap()).unwrap();
        assert!(back.standby);
        // The new field goes over the wire with the response.
        let resp = serde_json::to_string(&Response::Status(new)).unwrap();
        assert!(resp.contains(r#""standby":true"#));
        assert!(matches!(serde_json::from_str(&resp).unwrap(), Response::Status(Status { standby: true, .. })));
    }
}
