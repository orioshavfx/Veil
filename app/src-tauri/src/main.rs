#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;

use std::time::Duration;

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, RunEvent, State, WindowEvent};
use tokio::sync::Mutex;
use uuid::Uuid;
use veil_config::RoutingRule;
use veil_config::store::ConnectionMode;

use crate::core::{Core, Traffic, UiState};

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
    let r = core.lock().await.set_mode(mode).await.map_err(msg);
    update_tray(&app).await;
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
    let r = core.lock().await.connect().await.map_err(msg);
    update_tray(&app).await;
    r
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
    let core = core.lock().await;
    let connected = core.is_connected();
    let server = core.state.selected_profile().map(|p| p.name.clone()).unwrap_or_default();
    drop(core);
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let tip = if connected { format!("Veil — connected: {server}") } else { "Veil — disconnected".into() };
        let _ = tray.set_tooltip(Some(tip));
        let _ = tray.set_icon(Some(tray_icon(connected)));
        #[cfg(target_os = "macos")]
        let _ = tray.set_icon_as_template(true);
        if let Ok(menu) = tray_menu(app, connected) {
            let _ = tray.set_menu(Some(menu));
        }
    }
    let _ = tauri::Emitter::emit(app, "state-changed", ());
}

fn tray_menu(app: &AppHandle, connected: bool) -> tauri::Result<Menu<tauri::Wry>> {
    let toggle = MenuItem::with_id(app, "toggle", if connected { "Disconnect" } else { "Connect" }, true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Open Veil", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Veil", true, None::<&str>)?;
    Menu::with_items(app, &[&toggle, &show, &PredefinedMenuItem::separator(app)?, &quit])
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
        std::fs::OpenOptions::new().create(true).append(true).open(dir.join("veil.log")).ok()
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

fn main() {
    init_logging();
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
        ])
        .setup(|app| {
            if let Ok(dir) = app.path().resource_dir() {
                let core = app.state::<Mutex<Core>>();
                tauri::async_runtime::block_on(async { core.lock().await.seed_geo(&dir.join("geo")) });
            }
            let handle = app.handle().clone();
            TrayIconBuilder::with_id(TRAY_ID)
                .icon(tray_icon(false))
                .icon_as_template(cfg!(target_os = "macos"))
                .tooltip("Veil — disconnected")
                .menu(&tray_menu(&handle, false)?)
                // macOS: menu on any click. Windows: left click opens the window, right click the menu.
                .show_menu_on_left_click(cfg!(target_os = "macos"))
                .on_tray_icon_event(|tray, event| {
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
                    match event.id.as_ref() {
                        "toggle" => {
                            tauri::async_runtime::spawn(async move {
                                let core = app.state::<Mutex<Core>>();
                                let mut c = core.lock().await;
                                if c.is_connected() {
                                    c.disconnect().await;
                                } else if let Err(e) = c.connect().await {
                                    tracing::error!("{e:#}");
                                }
                                drop(c);
                                update_tray(&app).await;
                            });
                        }
                        "show" => show_window(&app),
                        "quit" => app.exit(0),
                        _ => {}
                    }
                })
                .build(app)?;

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
                CLEANED_UP.store(true, std::sync::atomic::Ordering::SeqCst);
                app.exit(0);
            });
        }
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => show_window(app),
        _ => {}
    });
}
