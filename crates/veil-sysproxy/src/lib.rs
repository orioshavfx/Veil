//! System network settings: proxy, DNS and routes for TUN mode.
//!
//! The previous settings are written to a backup file before anything is
//! changed, so they can be restored after a crash.

use serde::{Deserialize, Serialize};

/// Which destinations a TUN device captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TunRoutes {
    /// Everything (`0/1` + `128/1`, and IPv6).
    #[default]
    All,
    /// Only `0/1`; leaves another VPN's `128/1` alone. For testing.
    LowerHalf,
    /// Nothing but the fake-IP range, i.e. traffic to domain names.
    Domains,
}

impl TunRoutes {
    #[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(dead_code))]
    fn v4(self) -> &'static [&'static str] {
        match self {
            TunRoutes::All => &["0.0.0.0/1", "128.0.0.0/1"],
            TunRoutes::LowerHalf => &["0.0.0.0/1"],
            TunRoutes::Domains => &[],
        }
    }
}

/// Name (interface alias) of the Windows TUN adapter. Cleanup touches only an adapter
/// with this alias that also has the TUN address 198.18.0.1.
pub const TUN_ADAPTER_NAME: &str = "Veil";

/// What [`tun_cleanup`] found and did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CleanupReport {
    /// Something of ours is still there and removing it takes administrator rights.
    pub needs_admin: bool,
    /// What was removed.
    pub removed: Vec<String>,
    /// What was found but could not be removed, with the reason.
    pub failed: Vec<String>,
}

impl CleanupReport {
    pub fn is_empty(&self) -> bool {
        self.removed.is_empty() && self.failed.is_empty()
    }
}

/// Nothing outlives the process here: the routes and DNS settings are tied to the TUN
/// device and restored by `dns_restore` (macOS, Linux).
#[cfg(not(windows))]
pub fn tun_cleanup() -> CleanupReport {
    CleanupReport::default()
}

/// See the Windows version; nothing to do elsewhere.
#[cfg(not(windows))]
pub fn tun_cleanup_if_orphaned() -> Option<CleanupReport> {
    None
}

/// See the Windows version; nothing to do elsewhere.
#[cfg(not(windows))]
pub fn tun_cleanup_own() -> Option<CleanupReport> {
    None
}

/// See the Windows version; nothing to do elsewhere.
#[cfg(not(windows))]
pub fn tun_leftovers_suspected() -> bool {
    false
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(any(windows, test))]
mod winnet;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
