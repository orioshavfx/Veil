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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status(Status),
    Error { message: String },
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
