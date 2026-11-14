//! Optional, user-supplied geoip.dat / geosite.dat.
//!
//! Veil ships no geo lists and never downloads them. `geosite:` rules and
//! `geoip:` rules (except the built-in `geoip:private`) work only after the user
//! puts their own files into the data folder.

use std::path::Path;

use anyhow::{Result, bail};

use crate::routing::RoutingConfig;

pub const GEOIP: &str = "geoip.dat";
pub const GEOSITE: &str = "geosite.dat";

/// Geo files that `cfg` needs and `dir` does not have.
pub fn missing(cfg: &RoutingConfig, dir: &Path) -> Vec<&'static str> {
    [(GEOIP, cfg.uses_geoip()), (GEOSITE, cfg.uses_geosite())]
        .into_iter()
        .filter(|(name, needed)| *needed && !dir.join(name).is_file())
        .map(|(name, _)| name)
        .collect()
}

/// What to tell the user when geo rules cannot work.
pub fn missing_hint(dir: &Path) -> String {
    format!("put {GEOIP} and {GEOSITE} into {} or remove the geoip:/geosite: rules", dir.display())
}

/// An error naming the missing files and the folder when the rules need geo
/// files that are not there.
pub fn ensure_available(cfg: &RoutingConfig, dir: &Path) -> Result<()> {
    let missing = missing(cfg, dir);
    if missing.is_empty() {
        return Ok(());
    }
    bail!("{} not found: {}", missing.join(" and "), missing_hint(dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{RouteAction, RoutingRule};

    #[test]
    fn missing_files_are_named_with_the_folder() {
        let dir = std::env::temp_dir().join(format!("veil-geo-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = |rules| RoutingConfig { rules, final_action: RouteAction::Proxy };
        let both = cfg(vec![
            RoutingRule::domains(RouteAction::Direct, &["geosite:example"]),
            RoutingRule::ips(RouteAction::Direct, &["geoip:de"]),
        ]);
        assert_eq!(missing(&both, &dir), [GEOIP, GEOSITE]);
        let err = format!("{:#}", ensure_available(&both, &dir).unwrap_err());
        assert!(err.contains("geoip.dat and geosite.dat not found"), "{err}");
        assert!(err.contains(&dir.display().to_string()), "{err}");
        assert!(err.contains("remove the geoip:/geosite: rules"), "{err}");

        // Only the file a rule needs is required.
        std::fs::write(dir.join(GEOSITE), b"site").unwrap();
        assert_eq!(missing(&both, &dir), [GEOIP]);
        let site_only = cfg(vec![RoutingRule::domains(RouteAction::Proxy, &["geosite:example"])]);
        ensure_available(&site_only, &dir).unwrap();

        // The base modes and plain rules need no files at all.
        let empty = std::env::temp_dir().join(format!("veil-geo-none-{}", uuid::Uuid::new_v4()));
        for name in ["global", "selected-only"] {
            ensure_available(&RoutingConfig::preset(name).unwrap(), &empty).unwrap();
        }
        ensure_available(&cfg(vec![RoutingRule::ips(RouteAction::Direct, &["geoip:private", "10.0.0.0/8"])]), &empty)
            .unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }
}
