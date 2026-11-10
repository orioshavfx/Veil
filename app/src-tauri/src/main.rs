#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;
mod popover;

use std::time::Duration;

use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, RunEvent, State, WindowEvent};
use tokio::sync::Mutex;
use uuid::Uuid;
use veil_config::RoutingRule;
use veil_config::store::ConnectionMode;

use crate::core::{Core, Traffic, TrayInfo, UiState};

type CoreState<'a> = State<'a, Mutex<Core>>;

/// Errors cross the IPC boundary as plain strings.
fn msg(e: anyhow::Error) -> String {
    let m = format!("{e:#}");
    tracing::warn!("{m}");
    m
}

#[tauri::command]
async fn snapshot(core: CoreState<'_>) -> Result<UiState, String> {
    Ok(core.lock().await.snapshot())
}

#[tauri::command]
async fn import(core: CoreState<'_>, input: String) -> Result<String, String> {
    core.lock().await.import(&input).await.map_err(msg)
}

#[tauri::command]
async fn refresh_subscriptions(core: CoreState<'_>) -> Result<String, String> {
    core.lock().await.refresh_subscriptions(false).await.map_err(msg)
}

#[tauri::command]
async fn delete_subscription(core: CoreState<'_>, id: Uuid) -> Result<(), String> {
    core.lock().await.delete_subscription(id).map_err(msg)
}

#[tauri::command]
async fn delete_profile(core: CoreState<'_>, id: Uuid) -> Result<(), String> {
    core.lock().await.delete_profile(id).map_err(msg)
}

#[tauri::command]
async fn select_profile(app: AppHandle, core: CoreState<'_>, id: Uuid) -> Result<(), String> {
    let r = core.lock().await.select(id).await.map_err(msg);
    update_tray(&app).await;
    r
}

#[tauri::command]
async fn set_mode(app: AppHandle, core: CoreState<'_>, mode: ConnectionMode) -> Result<(), String> {
    let (r, relaunch) = {
        let mut c = core.lock().await;
        let r = c.set_mode(mode).await.map_err(msg);
        (r, c.take_relaunch())
    };
    update_tray(&app).await;
    quit_for_relaunch(&app, relaunch);
    r
}

#[tauri::command]
async fn set_preset(core: CoreState<'_>, name: String) -> Result<(), String> {
    core.lock().await.set_preset(&name).await.map_err(msg)
}

#[tauri::command]
async fn toggle_pin(core: CoreState<'_>, id: Uuid) -> Result<(), String> {
    core.lock().await.toggle_pin(id).map_err(msg)
}

#[tauri::command]
async fn suggest_geosite(core: CoreState<'_>, domain: String) -> Result<Option<String>, String> {
    core.lock().await.suggest_geosite(&domain).await.map_err(msg)
}

#[tauri::command]
async fn get_rules(core: CoreState<'_>) -> Result<Vec<RoutingRule>, String> {
    Ok(core.lock().await.rules())
}

#[tauri::command]
async fn set_rules(core: CoreState<'_>, rules: Vec<RoutingRule>) -> Result<(), String> {
    core.lock().await.set_rules(rules).await.map_err(msg)
}

#[tauri::command]
async fn list_apps() -> Result<Vec<veil_engine::process::AppEntry>, String> {
    tokio::task::spawn_blocking(veil_engine::process::all_apps).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn connect(app: AppHandle, core: CoreState<'_>) -> Result<(), String> {
    let (r, relaunch) = {
        let mut c = core.lock().await;
        let r = c.connect().await.map_err(msg);
        (r, c.take_relaunch())
    };
    update_tray(&app).await;
    quit_for_relaunch(&app, relaunch);
    r
}

/// Windows TUN: an elevated copy of the app has been started through UAC. Free the
/// single-instance lock (the new copy waits for it) and quit; nothing is connected here.
fn quit_for_relaunch(app: &AppHandle, relaunch: bool) {
    if relaunch {
        #[cfg(windows)]
        single_instance::release();
        app.exit(0);
    }
}

#[tauri::command]
async fn disconnect(app: AppHandle, core: CoreState<'_>) -> Result<(), String> {
    core.lock().await.disconnect().await;
    update_tray(&app).await;
    Ok(())
}

#[tauri::command]
async fn traffic(core: CoreState<'_>) -> Result<Traffic, String> {
    let source = core.lock().await.traffic_source();
    Ok(source.read().await)
}

#[tauri::command]
async fn ping_all(core: CoreState<'_>) -> Result<(), String> {
    core.lock().await.ping_all().await.map_err(msg)
}

const TRAY_ID: &str = "main";
// SF Symbols "shield" / "shield.fill", rendered by app/tools/render-symbols.swift.
// macOS tints the black ones (template images); Windows gets white ones on a dark taskbar.
const TRAY_OFF: &[u8] = include_bytes!("../icons/tray-off.png");
const TRAY_ON: &[u8] = include_bytes!("../icons/tray-on.png");
#[cfg(windows)]
const TRAY_OFF_WHITE: &[u8] = include_bytes!("../icons/tray-off-white.png");
#[cfg(windows)]
const TRAY_ON_WHITE: &[u8] = include_bytes!("../icons/tray-on-white.png");

/// Whether the Windows taskbar is dark (the default), so the tray needs white icons.
#[cfg(windows)]
fn dark_taskbar() -> bool {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
    let name = wide("SystemUsesLightTheme");
    let mut value = 0u32;
    let mut size = 4u32;
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            (&raw mut value).cast(),
            &mut size,
        )
    };
    rc != 0 || value == 0
}

fn tray_icon(connected: bool) -> tauri::image::Image<'static> {
    #[cfg(windows)]
    let bytes = match (connected, dark_taskbar()) {
        (true, true) => TRAY_ON_WHITE,
        (false, true) => TRAY_OFF_WHITE,
        (true, false) => TRAY_ON,
        (false, false) => TRAY_OFF,
    };
    #[cfg(not(windows))]
    let bytes = if connected { TRAY_ON } else { TRAY_OFF };
    tauri::image::Image::from_bytes(bytes).expect("bundled tray icon")
}

async fn update_tray(app: &AppHandle) {
    let core = app.state::<Mutex<Core>>();
    let info = core.lock().await.tray_info();
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let tip = if info.connected { format!("Veil — Connected: {}", info.server_name) } else { "Veil — Disconnected".into() };
        let _ = tray.set_tooltip(Some(tip));
        let _ = tray.set_icon(Some(tray_icon(info.connected)));
        #[cfg(target_os = "macos")]
        let _ = tray.set_icon_as_template(true);
        match tray_menu(app, &info) {
            Ok(menu) => {
                let _ = tray.set_menu(Some(menu));
            }
            Err(e) => tracing::warn!("tray menu: {e}"),
        }
    }
    let _ = tauri::Emitter::emit(app, "state-changed", ());
}

/// Shortens long server names for the menu.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>().trim_end())
    }
}

const MENU_MAX_SERVERS: usize = 20;

fn tray_menu(app: &AppHandle, info: &TrayInfo) -> tauri::Result<Menu<tauri::Wry>> {
    let status = if info.connected {
        format!("Connected · {}", clip(&info.server_name, 40))
    } else {
        "Disconnected".to_string()
    };
    let header = MenuItem::with_id(app, "status", status, false, None::<&str>)?;
    let mode_name = match info.mode {
        ConnectionMode::Proxy => "Proxy",
        ConnectionMode::Tun => "TUN",
    };
    let proto = MenuItem::with_id(
        app,
        "info-proto",
        format!("{} · {mode_name}", info.protocol.unwrap_or("No server")),
        false,
        None::<&str>,
    )?;
    let preset_label = veil_config::PRESETS
        .iter()
        .find(|(n, _)| *n == info.preset)
        .map(|(_, l)| *l)
        .unwrap_or(info.preset.as_str());
    let preset = MenuItem::with_id(app, "info-preset", format!("Routing: {preset_label}"), false, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", if info.connected { "Disconnect" } else { "Connect" }, true, None::<&str>)?;

    // Server submenu.
    let mut server_items: Vec<Box<dyn IsMenuItem<tauri::Wry>>> = Vec::new();
    for (id, name) in info.servers.iter().take(MENU_MAX_SERVERS) {
        let item = CheckMenuItem::with_id(app, format!("srv:{id}"), clip(name, 40), true, info.selected == Some(*id), None::<&str>)?;
        server_items.push(Box::new(item));
    }
    if info.servers.is_empty() {
        server_items.push(Box::new(MenuItem::with_id(app, "srv-none", "No servers", false, None::<&str>)?));
    }
    if info.servers.len() > MENU_MAX_SERVERS {
        server_items.push(Box::new(PredefinedMenuItem::separator(app)?));
        server_items.push(Box::new(MenuItem::with_id(app, "show", "More in Veil…", true, None::<&str>)?));
    }
    let server_refs: Vec<&dyn IsMenuItem<tauri::Wry>> = server_items.iter().map(|b| b.as_ref()).collect();
    let servers = Submenu::with_items(app, "Server", true, &server_refs)?;

    // Mode submenu.
    let m_proxy = CheckMenuItem::with_id(app, "mode:proxy", "Proxy", true, info.mode == ConnectionMode::Proxy, None::<&str>)?;
    let m_tun = CheckMenuItem::with_id(
        app,
        "mode:tun",
        if info.tun_available { "TUN" } else { "TUN (unavailable)" },
        info.tun_available,
        info.mode == ConnectionMode::Tun,
        None::<&str>,
    )?;
    let mode = Submenu::with_items(app, "Mode", true, &[&m_proxy, &m_tun])?;

    // Routing presets submenu.
    let mut preset_items: Vec<CheckMenuItem<tauri::Wry>> = Vec::new();
    for (name, label) in veil_config::PRESETS.iter() {
        preset_items.push(CheckMenuItem::with_id(app, format!("preset:{name}"), *label, true, info.preset == *name, None::<&str>)?);
    }
    let preset_refs: Vec<&dyn IsMenuItem<tauri::Wry>> = preset_items.iter().map(|i| i as &dyn IsMenuItem<tauri::Wry>).collect();
    let routing = Submenu::with_items(app, "Routing", true, &preset_refs)?;

    let show = MenuItem::with_id(app, "show", "Open Veil", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Veil", true, None::<&str>)?;
    Menu::with_items(
        app,
        &[
            &header,
            &proto,
            &preset,
            &PredefinedMenuItem::separator(app)?,
            &toggle,
            &PredefinedMenuItem::separator(app)?,
            &servers,
            &mode,
            &routing,
            &PredefinedMenuItem::separator(app)?,
            &show,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ],
    )
}

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Where the log goes: ~/Library/Logs/Veil on macOS, %LOCALAPPDATA%\Veil on Windows.
fn log_dir() -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    return std::env::var_os("LOCALAPPDATA").map(|d| std::path::Path::new(&d).join("Veil"));
    #[cfg(not(windows))]
    return std::env::var_os("HOME").map(|h| std::path::Path::new(&h).join("Library/Logs/Veil"));
}

/// Log file for bug reports: veil.log in `log_dir()`.
fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let file = log_dir().and_then(|dir| {
        std::fs::create_dir_all(&dir).ok()?;
        open_log(&dir.join("veil.log")).ok()
    });
    match file {
        Some(f) => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(f))
            .init(),
        None => tracing_subscriber::fmt().with_env_filter(filter).init(),
    }
}

/// Opens the log for appending; on unix it is private (0600), also when it already existed,
/// since error messages may name servers and subscriptions.
fn open_log(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(all(test, unix))]
mod log_tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn log_file_is_private() {
        let dir = std::env::temp_dir().join(format!("veil-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let fresh = dir.join("veil.log");
        drop(super::open_log(&fresh).unwrap());
        assert_eq!(mode(&fresh), 0o600);
        // An existing world-readable log is tightened and appended to, not truncated.
        let old = dir.join("old.log");
        std::fs::write(&old, b"line\n").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
        {
            use std::io::Write;
            super::open_log(&old).unwrap().write_all(b"more\n").unwrap();
        }
        assert_eq!(mode(&old), 0o600);
        assert_eq!(std::fs::read(&old).unwrap(), b"line\nmore\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

/// Logoff / shutdown: restores the system proxy. Windows ends the session by terminating
/// processes after `WM_ENDSESSION`; whether tao turns that into `RunEvent::Exit` is not
/// something to rely on, and a leftover proxy on a dead port breaks the network until the
/// next start. A hidden top-level window (message-only windows get no session messages)
/// on its own thread handles the message and restores the settings synchronously.
#[cfg(windows)]
mod session_end {
    use std::path::PathBuf;
    use std::ptr::{null, null_mut};
    use std::sync::OnceLock;

    use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, MSG, RegisterClassW, TranslateMessage,
        WM_ENDSESSION, WNDCLASSW, WS_OVERLAPPED,
    };

    static BACKUP: OnceLock<PathBuf> = OnceLock::new();

    unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // wparam != 0: the session really ends (the query may have been vetoed by another app).
        if msg == WM_ENDSESSION && wparam != 0 {
            if let Some(path) = BACKUP.get() {
                let _ = veil_sysproxy::restore(path);
            }
            // TUN mode: the DNS (NRPT) rule would survive the reboot with nobody answering.
            // Straight from the registry: the session is ending, there is no time for PowerShell.
            veil_sysproxy::tun_cleanup_session_end();
            return 0;
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    pub fn start() {
        let Ok(store) = veil_config::store::Store::open_default() else { return };
        let _ = BACKUP.set(store.dir().join("sysproxy-backup.json"));
        let spawned = std::thread::Builder::new().name("session-end".into()).spawn(|| unsafe {
            let class: Vec<u16> = "VeilSessionEnd".encode_utf16().chain(std::iter::once(0)).collect();
            let hinstance = GetModuleHandleW(null());
            let mut wc: WNDCLASSW = std::mem::zeroed();
            wc.lpfnWndProc = Some(wndproc);
            wc.hInstance = hinstance;
            wc.lpszClassName = class.as_ptr();
            if RegisterClassW(&wc) == 0 {
                tracing::warn!("session-end window: RegisterClassW failed");
                return;
            }
            let hwnd = CreateWindowExW(0, class.as_ptr(), class.as_ptr(), WS_OVERLAPPED, 0, 0, 0, 0, null_mut(), null_mut(), hinstance, null());
            if hwnd.is_null() {
                tracing::warn!("session-end window: CreateWindowExW failed");
                return;
            }
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        });
        if let Err(e) = spawned {
            tracing::warn!("session-end thread: {e}");
        }
    }
}

/// Only one Veil per user session: a second launch brings the first window forward and exits,
/// instead of adding a second tray icon that fights over the system proxy.
#[cfg(windows)]
mod single_instance {
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicIsize, Ordering};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SW_RESTORE, SW_SHOW, SetForegroundWindow, ShowWindow};

    /// The mutex handle, kept open for the life of the process (until `release`).
    static HANDLE: AtomicIsize = AtomicIsize::new(0);

    /// Returns false when another Veil is already running. With `wait`, a copy that is
    /// about to quit (the non-elevated one that started us through UAC) gets that long
    /// to let go of the lock.
    pub fn acquire(wait: Duration) -> bool {
        let name: Vec<u16> = "Local\\dev.veil.app.single-instance".encode_utf16().chain(std::iter::once(0)).collect();
        let deadline = Instant::now() + wait;
        loop {
            unsafe {
                let handle = CreateMutexW(null_mut(), 0, name.as_ptr());
                let err = GetLastError();
                if handle.is_null() {
                    // An elevated copy owns it and we may not open it: it is running.
                    if err != ERROR_ACCESS_DENIED {
                        return true; // cannot tell: better two windows than none
                    }
                } else if err != ERROR_ALREADY_EXISTS {
                    HANDLE.store(handle as isize, Ordering::SeqCst);
                    return true;
                } else {
                    CloseHandle(handle);
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        unsafe {
            let title: Vec<u16> = "Veil".encode_utf16().chain(std::iter::once(0)).collect();
            let hwnd = FindWindowW(null_mut(), title.as_ptr());
            if !hwnd.is_null() {
                ShowWindow(hwnd, SW_SHOW);
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
            }
        }
        false
    }

    /// Lets go of the lock so that the elevated copy can take it.
    pub fn release() {
        let handle = HANDLE.swap(0, Ordering::SeqCst);
        if handle != 0 {
            unsafe { CloseHandle(handle as _) };
        }
    }
}

/// Waits for the process that started us through UAC to be gone: WebView2 refuses to share
/// a user data folder between a normal and an elevated process, and its browser process
/// lingers a moment after the host exits.
#[cfg(windows)]
fn wait_for_exit(pid: u32, timeout: Duration) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};
    unsafe {
        let process = OpenProcess(PROCESS_SYNCHRONIZE, 0, pid);
        if process.is_null() {
            return; // already gone
        }
        WaitForSingleObject(process, timeout.as_millis() as u32);
        CloseHandle(process);
    }
    std::thread::sleep(Duration::from_millis(300));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // An elevated copy started only to remove what a dead TUN session left behind:
    // no window, no single-instance lock (the normal copy is running and waiting for this).
    // Only leftovers: a TUN that a running Veil (veil-cli, say) is using stays.
    if core::wants_tun_cleanup(args.iter().cloned()) {
        init_logging();
        match veil_sysproxy::tun_cleanup_if_orphaned() {
            Some(report) => tracing::info!("--tun-cleanup: removed {:?}, left {:?}", report.removed, report.failed),
            None => tracing::info!("--tun-cleanup: the TUN is in use by a running Veil, left alone"),
        }
        return;
    }
    let connect_tun = core::wants_connect_tun(args.iter().cloned());
    #[cfg(windows)]
    if let Some(pid) = core::after_pid(args.iter().cloned()) {
        wait_for_exit(pid, Duration::from_secs(10));
    }
    #[cfg(windows)]
    if !single_instance::acquire(if connect_tun { Duration::from_secs(5) } else { Duration::ZERO }) {
        return;
    }
    init_logging();
    // A panic must not leave the system pointing at a tunnel that is about to die. The hook
    // itself touches nothing (any thread, any state): it raises a flag, and the TUN reaper
    // below disconnects the normal way and shows the error.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        veil_engine::note_panic();
        tracing::error!("panic: {info}");
        default_hook(info);
    }));
    #[cfg(windows)]
    session_end::start();
    tracing::info!("Veil {} starting", env!("CARGO_PKG_VERSION"));
    let core = Core::open().expect("cannot open settings");

    let app = tauri::Builder::default()
        .manage(Mutex::new(core))
        .invoke_handler(tauri::generate_handler![
            snapshot,
            import,
            refresh_subscriptions,
            delete_subscription,
            delete_profile,
            select_profile,
            set_mode,
            set_preset,
            toggle_pin,
            suggest_geosite,
            get_rules,
            set_rules,
            list_apps,
            connect,
            disconnect,
            traffic,
            ping_all,
            popover::popover_state,
            popover::ping_servers,
            popover::hide_popover,
            popover::open_main_window,
            popover::quit_app,
        ])
        .setup(move |app| {
            if let Ok(dir) = app.path().resource_dir() {
                let core = app.state::<Mutex<Core>>();
                tauri::async_runtime::block_on(async { core.lock().await.seed_geo(&dir.join("geo")) });
            }
            let handle = app.handle().clone();
            TrayIconBuilder::with_id(TRAY_ID)
                .icon(tray_icon(false))
                .icon_as_template(cfg!(target_os = "macos"))
                .tooltip("Veil — Disconnected")
                .menu(&tray_menu(&handle, &app.state::<Mutex<Core>>().blocking_lock().tray_info())?)
                // Right click: the menu. Left click: the menu bar panel on macOS, the window on Windows.
                .show_menu_on_left_click(false)
                .on_tray_icon_event(|tray, event| {
                    #[cfg(target_os = "macos")]
                    popover::mac::on_tray_event(tray, &event);
                    if cfg!(windows)
                        && let tauri::tray::TrayIconEvent::Click {
                            button: tauri::tray::MouseButton::Left,
                            button_state: tauri::tray::MouseButtonState::Up,
                            ..
                        } = event
                    {
                        show_window(tray.app_handle());
                    }
                })
                .on_menu_event(|app, event| {
                    let app = app.clone();
                    let id = event.id.as_ref().to_string();
                    match id.as_str() {
                        "toggle" => {
                            tauri::async_runtime::spawn(async move {
                                let core = app.state::<Mutex<Core>>();
                                let mut c = core.lock().await;
                                if c.is_connected() {
                                    c.disconnect().await;
                                } else if let Err(e) = c.connect().await {
                                    tracing::error!("{e:#}");
                                }
                                let relaunch = c.take_relaunch();
                                drop(c);
                                update_tray(&app).await;
                                quit_for_relaunch(&app, relaunch);
                            });
                        }
                        "show" => show_window(&app),
                        "quit" => app.exit(0),
                        "mode:proxy" | "mode:tun" => {
                            let mode = if id == "mode:tun" { ConnectionMode::Tun } else { ConnectionMode::Proxy };
                            tauri::async_runtime::spawn(async move {
                                let (r, relaunch) = {
                                    let core = app.state::<Mutex<Core>>();
                                    let mut c = core.lock().await;
                                    (c.set_mode(mode).await, c.take_relaunch())
                                };
                                if let Err(e) = r {
                                    tracing::error!("{e:#}");
                                }
                                update_tray(&app).await;
                                quit_for_relaunch(&app, relaunch);
                            });
                        }
                        other => {
                            if let Some(raw) = other.strip_prefix("srv:") {
                                if let Ok(sid) = Uuid::parse_str(raw) {
                                    tauri::async_runtime::spawn(async move {
                                        let r = app.state::<Mutex<Core>>().lock().await.select(sid).await;
                                        if let Err(e) = r {
                                            tracing::error!("{e:#}");
                                        }
                                        update_tray(&app).await;
                                    });
                                }
                            } else if let Some(name) = other.strip_prefix("preset:") {
                                let name = name.to_string();
                                tauri::async_runtime::spawn(async move {
                                    let r = app.state::<Mutex<Core>>().lock().await.set_preset(&name).await;
                                    if let Err(e) = r {
                                        tracing::error!("{e:#}");
                                    }
                                    update_tray(&app).await;
                                });
                            }
                        }
                    }
                })
                .build(app)?;

            // The menu bar panel, created hidden now so that the first click opens it at once.
            #[cfg(target_os = "macos")]
            let _ = popover::mac::window(app.handle());

            // Follow the taskbar's light/dark theme switches.
            #[cfg(windows)]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let mut dark = dark_taskbar();
                    loop {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        if dark_taskbar() != dark {
                            dark = !dark;
                            update_tray(&handle).await;
                        }
                    }
                });
            }

            // A TUN whose packet loop died (or a process that panicked) is not to be trusted:
            // disconnect the normal way and show "disconnected", not a lie.
            #[cfg(windows)]
            {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        let changed = {
                            let state = handle.state::<Mutex<Core>>();
                            let mut core = state.lock().await;
                            let reaped = core.reap_dead_tun().await;
                            core.recheck_tun_leftovers() || reaped
                        };
                        if changed {
                            update_tray(&handle).await;
                            let _ = tauri::Emitter::emit(&handle, "state-changed", ());
                        }
                    }
                });
            }

            // Started elevated by the app itself (Windows TUN): connect right away.
            if connect_tun {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    {
                        let core = handle.state::<Mutex<Core>>();
                        if let Err(e) = core.lock().await.connect_after_elevation().await {
                            tracing::error!("{e:#}");
                        }
                    }
                    update_tray(&handle).await;
                });
            }

            // Refresh subscriptions that are due, in the background.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    {
                        let core = handle.state::<Mutex<Core>>();
                        let mut c = core.lock().await;
                        if let Err(e) = c.refresh_subscriptions(true).await {
                            tracing::warn!("subscription update: {e}");
                        }
                    }
                    let _ = tauri::Emitter::emit(&handle, "state-changed", ());
                    tokio::time::sleep(Duration::from_secs(30 * 60)).await;
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window keeps the app running in the menu bar / tray.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
            // The menu bar panel closes when it loses focus, like a menu.
            #[cfg(target_os = "macos")]
            popover::mac::on_window_event(window, event);
        })
        .build(tauri::generate_context!())
        .expect("error while building Veil");

    // Set once the connection has been torn down, so the second exit request goes through.
    static CLEANED_UP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    app.run(|app, event| match event {
        RunEvent::ExitRequested { api, .. } => {
            if CLEANED_UP.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            // Never leave the system proxy or TUN pointing at a dead process, but
            // don't block the main thread while doing it.
            api.prevent_exit();
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                let core = app.state::<Mutex<Core>>();
                match tokio::time::timeout(Duration::from_secs(10), core.lock()).await {
                    Ok(mut c) => c.disconnect().await,
                    Err(_) => tracing::error!("exit: core busy for 10 s, quitting anyway"),
                }
                // Whatever happened above (a busy core, a teardown that failed half-way):
                // never quit with our TUN changes still in the system. Needs no core.
                let _ = tokio::task::spawn_blocking(veil_sysproxy::tun_cleanup_own).await;
                CLEANED_UP.store(true, std::sync::atomic::Ordering::SeqCst);
                app.exit(0);
            });
        }
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => show_window(app),
        _ => {}
    });
}
