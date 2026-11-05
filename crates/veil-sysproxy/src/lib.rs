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
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    fn v4(self) -> &'static [&'static str] {
        match self {
            TunRoutes::All => &["0.0.0.0/1", "128.0.0.0/1"],
            TunRoutes::LowerHalf => &["0.0.0.0/1"],
            TunRoutes::Domains => &[],
        }
    }
}

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;
