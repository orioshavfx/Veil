// Every command the frontend may call. Listing them makes tauri-build generate an
// `allow-<command>` permission for each and enforce the capabilities for app commands
// too: the main window gets all of them (capabilities/default.json), the macOS menu
// bar panel only what it uses (capabilities/popover.json).
const COMMANDS: &[&str] = &[
    "snapshot",
    "import",
    "refresh_subscriptions",
    "delete_subscription",
    "delete_profile",
    "select_profile",
    "set_mode",
    "set_preset",
    "toggle_pin",
    "suggest_geosite",
    "get_rules",
    "set_rules",
    "list_apps",
    "connect",
    "disconnect",
    "set_kill_switch",
    "traffic",
    "ping_all",
    "popover_state",
    "ping_servers",
    "hide_popover",
    "open_main_window",
    "quit_app",
    "update_status",
    "check_update",
    "install_update",
    "set_check_updates",
];

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    if let Err(e) = tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest)) {
        panic!("tauri-build: {e:#}");
    }
}
