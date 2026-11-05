//! Downloading geoip.dat / geosite.dat.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::subscription::USER_AGENT;

/// Builds that include `category-ru` and `geoip:ru`.
pub const SOURCES: [(&str, &str); 2] = [
    ("geoip.dat", "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"),
    ("geosite.dat", "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"),
];

pub fn present(dir: &Path) -> bool {
    SOURCES.iter().all(|(name, _)| dir.join(name).exists())
}

/// Copies files shipped with the app into `dir` when they are missing there.
pub fn seed_from(bundled: &Path, dir: &Path) -> Result<bool> {
    let mut copied = false;
    for (name, _) in SOURCES {
        let (src, dst) = (bundled.join(name), dir.join(name));
        if !dst.exists() && src.exists() {
            std::fs::copy(&src, &dst).with_context(|| format!("copying {name}"))?;
            copied = true;
        }
    }
    Ok(copied)
}

/// Downloads both files, replacing the old ones only after a complete download.
pub async fn download(dir: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()?;
    for (name, url) in SOURCES {
        let bytes = client
            .get(url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("downloading {name}"))?
            .bytes()
            .await?;
        if bytes.len() < 64 * 1024 {
            bail!("{name}: suspiciously small download ({} bytes)", bytes.len());
        }
        let tmp = dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, &bytes)?;
        std::fs::rename(&tmp, dir.join(name))?;
        tracing::info!("{name}: {} KiB", bytes.len() / 1024);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_missing_files_only() {
        let root = std::env::temp_dir().join(format!("veil-geo-{}", uuid::Uuid::new_v4()));
        let (bundled, dir) = (root.join("bundled"), root.join("store"));
        std::fs::create_dir_all(&bundled).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(bundled.join("geoip.dat"), b"ip").unwrap();
        std::fs::write(bundled.join("geosite.dat"), b"site").unwrap();
        std::fs::write(dir.join("geosite.dat"), b"newer").unwrap();
        assert!(seed_from(&bundled, &dir).unwrap());
        assert!(present(&dir));
        // An existing (possibly updated) file is not overwritten.
        assert_eq!(std::fs::read(dir.join("geosite.dat")).unwrap(), b"newer");
        assert!(!seed_from(&bundled, &dir).unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }
}
