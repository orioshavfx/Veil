//! Persistent application state stored as JSON.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{Profile, Subscription};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionMode {
    #[default]
    Proxy,
    Tun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub mixed_port: u16,
    pub mode: ConnectionMode,
    pub set_system_proxy: bool,
    /// Name of a preset from [`crate::routing::PRESETS`].
    pub routing_preset: String,
    /// User rules, checked before the preset's rules.
    #[serde(default)]
    pub custom_rules: Vec<crate::routing::RoutingRule>,
    /// TUN mode (macOS): "Disconnect" puts the tunnel on standby instead of removing it, so
    /// connections that would go through the VPN are refused instead of leaking out directly.
    #[serde(default)]
    pub kill_switch: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mixed_port: 2080,
            mode: ConnectionMode::Proxy,
            set_system_proxy: true,
            routing_preset: "global".into(),
            custom_rules: Vec::new(),
            kill_switch: false,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppState {
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub selected: Option<Uuid>,
    #[serde(default)]
    pub settings: Settings,
}

impl Settings {
    /// Custom rules followed by the selected preset.
    pub fn routing(&self) -> crate::routing::RoutingConfig {
        let mut cfg = crate::routing::RoutingConfig::preset(&self.routing_preset)
            .unwrap_or_else(|| crate::routing::RoutingConfig::preset("global").unwrap());
        cfg.rules.splice(0..0, self.custom_rules.iter().cloned());
        cfg
    }
}

impl AppState {
    pub fn selected_profile(&self) -> Option<&Profile> {
        self.selected
            .and_then(|id| self.profiles.iter().find(|p| p.id == id))
            .or(self.profiles.first())
    }

    /// Replaces all profiles of a subscription, keeping the selection and pins
    /// of servers that survived (matched by server settings, then by name).
    pub fn replace_subscription_profiles(&mut self, sub_id: Uuid, mut fresh: Vec<Profile>) {
        let selected = self.selected_profile().filter(|p| p.subscription_id == Some(sub_id)).cloned();
        let old: Vec<Profile> =
            self.profiles.iter().filter(|p| p.subscription_id == Some(sub_id)).cloned().collect();
        let same = |a: &Profile, b: &Profile| a.server == b.server || a.name == b.name;
        for p in &mut fresh {
            p.pinned = old.iter().any(|o| o.pinned && same(o, p));
        }
        self.profiles.retain(|p| p.subscription_id != Some(sub_id));
        if let Some(sel) = selected {
            self.selected = fresh
                .iter()
                .find(|p| p.server == sel.server)
                .or_else(|| fresh.iter().find(|p| p.name == sel.name))
                .map(|p| p.id);
        }
        self.profiles.extend(fresh);
    }
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn open_default() -> Result<Self> {
        let dirs = directories::ProjectDirs::from("dev", "veil", "veil")
            .context("cannot determine application support directory")?;
        Self::open(dirs.data_dir())
    }

    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        // state.json holds links, UUIDs, passwords and subscription URLs: owner only.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(0o700)) {
                tracing::warn!("cannot restrict {}: {e}", dir.display());
            }
        }
        Ok(Self { path: dir.join("state.json") })
    }

    pub fn dir(&self) -> &Path {
        self.path.parent().unwrap()
    }

    pub fn load(&self) -> Result<AppState> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("corrupt state.json"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(AppState::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes atomically via a temporary file (mode 0600 on unix).
    pub fn save(&self, state: &AppState) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(state)?;
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            // A fresh file, so the mode applies even if a stale (wider) temp file was left.
            match fs::remove_file(&tmp) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_link;

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!("veil-test-{}", Uuid::new_v4()));
        let store = Store::open(&dir).unwrap();
        assert!(store.load().unwrap().profiles.is_empty());
        let mut state = AppState::default();
        state.profiles.push(parse_link("trojan://a@b.com:443#x").unwrap());
        store.save(&state).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.profiles, state.profiles);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let dir = std::env::temp_dir().join(format!("veil-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        // An older, world-readable state.json and a stale temp file.
        fs::write(dir.join("state.json"), b"{}").unwrap();
        fs::set_permissions(dir.join("state.json"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(dir.join("state.json.tmp"), b"x").unwrap();
        fs::set_permissions(dir.join("state.json.tmp"), fs::Permissions::from_mode(0o644)).unwrap();
        let store = Store::open(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        store.save(&AppState::default()).unwrap();
        assert_eq!(mode(&dir.join("state.json")), 0o600);
        assert!(!dir.join("state.json.tmp").exists());
        assert!(store.load().unwrap().profiles.is_empty());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn kill_switch_defaults_off_for_old_settings() {
        let old = r#"{"settings":{"mixed_port":2080,"mode":"tun","set_system_proxy":true,"routing_preset":"global"}}"#;
        let state: AppState = serde_json::from_str(old).unwrap();
        assert!(!state.settings.kill_switch);
        assert!(!Settings::default().kill_switch);
        let s = Settings { kill_switch: true, ..Settings::default() };
        let back: Settings = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(back.kill_switch);
    }

    #[test]
    fn selected_only_preset() {
        use crate::routing::{RouteAction, RoutingRule};
        let settings = Settings {
            routing_preset: "selected-only".into(),
            custom_rules: vec![RoutingRule::domains(RouteAction::Proxy, &["domain:youtube.com"])],
            ..Settings::default()
        };
        let r = settings.routing();
        assert_eq!(r.final_action, RouteAction::Direct);
        assert_eq!(r.rules.len(), 1);
        assert_eq!(r.rules[0].action, RouteAction::Proxy);
    }

    #[test]
    fn subscription_refresh_keeps_selection() {
        let sub = Uuid::new_v4();
        let mut p = parse_link("trojan://a@b.com:443#x").unwrap();
        p.subscription_id = Some(sub);
        let mut state = AppState { selected: Some(p.id), ..Default::default() };
        state.profiles.push(p.clone());
        let mut fresh = parse_link("trojan://a@b.com:443#renamed").unwrap();
        fresh.subscription_id = Some(sub);
        state.replace_subscription_profiles(sub, vec![fresh.clone()]);
        assert_eq!(state.selected, Some(fresh.id));
        assert_eq!(state.profiles.len(), 1);
    }

    #[test]
    fn subscription_refresh_keeps_pins() {
        let sub = Uuid::new_v4();
        let mk = |link: &str| {
            let mut p = parse_link(link).unwrap();
            p.subscription_id = Some(sub);
            p
        };
        let mut state = AppState::default();
        let mut a = mk("trojan://a@a.com:443#Germany");
        a.pinned = true;
        state.profiles = vec![a, mk("trojan://b@b.com:443#France")];
        // Germany got a new password (same name); France is unchanged.
        state.replace_subscription_profiles(sub, vec![mk("trojan://new@a.com:443#Germany"), mk("trojan://b@b.com:443#France")]);
        let pinned: Vec<_> = state.profiles.iter().filter(|p| p.pinned).map(|p| p.name.as_str()).collect();
        assert_eq!(pinned, ["Germany"]);
    }
}
