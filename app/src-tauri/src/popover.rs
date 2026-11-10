//! The menu-bar panel (macOS): a small window under the tray icon with the power button,
//! the connection mode and the pinned servers. A left click on the icon opens it; a right
//! click (or control-click) still shows the native menu built in `main.rs`.
//!
//! The geometry, the server list and the latency colours are plain functions with tests;
//! the window handling lives in `mac` and only exists on macOS.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;
use uuid::Uuid;
use veil_config::store::ConnectionMode;

use crate::core::Core;

/// Window label of the panel.
pub const LABEL: &str = "popover";
/// Panel size in points.
pub const WIDTH: f64 = 264.0;
pub const HEIGHT: f64 = 320.0;
/// Servers shown (and pinged) when the user has pinned none.
pub const UNPINNED_LIMIT: usize = 2;
/// Gap between the menu bar icon and the panel, and the minimum distance to the screen edge.
const GAP: f64 = 4.0;
const MARGIN: f64 = 6.0;

/// A rectangle; top-left origin, y growing downwards (the convention of tao and tray-icon).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
}

impl Bounds {
    pub fn new(x: f64, y: f64, w: f64, h: f64) -> Self {
        Self { x, y, w, h }
    }

    fn right(&self) -> f64 {
        self.x + self.w
    }

    fn bottom(&self) -> f64 {
        self.y + self.h
    }

    fn scaled(&self, by: f64) -> Self {
        Self::new(self.x * by, self.y * by, self.w * by, self.h * by)
    }

    fn contains(&self, x: f64, y: f64) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }

    /// Distance from the point to the rectangle (0 inside).
    fn distance(&self, x: f64, y: f64) -> f64 {
        let dx = (self.x - x).max(0.0).max(x - self.right());
        let dy = (self.y - y).max(0.0).max(y - self.bottom());
        dx.hypot(dy)
    }
}

/// One display, in physical pixels as tao reports them, with its scale factor.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Screen {
    pub frame: Bounds,
    /// The part not covered by the menu bar and the Dock.
    pub work: Bounds,
    pub scale: f64,
}

/// Which screen the menu bar icon is on. tao and tray-icon give physical coordinates as
/// global points times the scale of the screen in question, so with a Retina screen next
/// to a non-Retina one a point can look as if it lies on both: then the screen on which
/// the icon has the height of a menu bar (16-44 points) wins.
pub fn pick_screen(icon: Bounds, screens: &[Screen]) -> Option<usize> {
    let cx = icon.x + icon.w / 2.0;
    let cy = icon.y + icon.h / 2.0;
    let height_miss = |s: &Screen| {
        let h = icon.h / s.scale;
        (16.0 - h).max(0.0) + (h - 44.0).max(0.0)
    };
    let logical = |s: &Screen| (s.frame.scaled(1.0 / s.scale), cx / s.scale, cy / s.scale);
    let containing = screens
        .iter()
        .enumerate()
        .filter(|(_, s)| s.scale > 0.0)
        .filter(|(_, s)| {
            let (frame, x, y) = logical(s);
            frame.contains(x, y)
        })
        .min_by(|(_, a), (_, b)| height_miss(a).total_cmp(&height_miss(b)))
        .map(|(i, _)| i);
    containing.or_else(|| {
        screens
            .iter()
            .enumerate()
            .filter(|(_, s)| s.scale > 0.0)
            .min_by(|(_, a), (_, b)| {
                let (fa, xa, ya) = logical(a);
                let (fb, xb, yb) = logical(b);
                fa.distance(xa, ya).total_cmp(&fb.distance(xb, yb))
            })
            .map(|(i, _)| i)
    })
}

/// Top-left corner of a `w` x `h` panel: centred under the icon, kept inside `work` (all in
/// points). If there is no room below the icon (a menu bar at the bottom), it goes above.
pub fn panel_origin(icon: Bounds, work: Bounds, w: f64, h: f64) -> (f64, f64) {
    let min_x = work.x + MARGIN;
    let max_x = work.right() - w - MARGIN;
    let centred = icon.x + icon.w / 2.0 - w / 2.0;
    // A screen narrower than the panel (should not happen): its left edge, or centred.
    let x = if max_x < min_x { work.x + ((work.w - w) / 2.0).max(0.0) } else { centred.clamp(min_x, max_x) };

    let below = icon.bottom() + GAP;
    let above = icon.y - GAP - h;
    let y = if below + h <= work.bottom() || above < work.y { below } else { above };
    let max_y = (work.bottom() - h).max(work.y);
    (x, y.clamp(work.y, max_y))
}

/// What a left click on the menu bar icon does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClickAction {
    Show,
    Hide,
    Ignore,
}

/// `hidden_ms_ago`: when the panel last closed because it lost focus. Clicking the icon
/// while the panel is open can take the focus away first, closing it; the click that
/// follows must not open it again right away.
pub fn left_click(visible: bool, hidden_ms_ago: Option<u128>, menu_shown: bool) -> ClickAction {
    if menu_shown {
        ClickAction::Ignore
    } else if visible {
        ClickAction::Hide
    } else if hidden_ms_ago.is_some_and(|ms| ms < 400) {
        ClickAction::Ignore
    } else {
        ClickAction::Show
    }
}

/// Indices of the servers the panel lists: the pinned ones in their order, or, when none is
/// pinned, the first few. The flag says whether any server is pinned.
pub fn shown_servers(pinned: &[bool]) -> (Vec<usize>, bool) {
    let chosen: Vec<usize> = pinned.iter().enumerate().filter(|(_, p)| **p).map(|(i, _)| i).collect();
    if chosen.is_empty() { ((0..pinned.len().min(UNPINNED_LIMIT)).collect(), false) } else { (chosen, true) }
}

/// Colour class of a latency: `None` not measured, `Some(0)` no answer (timeout).
pub fn ping_level(latency_ms: Option<u32>) -> &'static str {
    match latency_ms {
        None => "unknown",
        Some(0) => "bad",
        Some(ms) if ms < 150 => "good",
        Some(ms) if ms < 400 => "mid",
        Some(_) => "bad",
    }
}

#[derive(Serialize)]
pub struct PopoverServer {
    id: Uuid,
    name: String,
    latency_ms: Option<u32>,
    level: &'static str,
    selected: bool,
}

#[derive(Serialize)]
pub struct PopoverState {
    connected: bool,
    server_name: Option<String>,
    mode: ConnectionMode,
    tun_available: bool,
    error: Option<String>,
    /// Whether the list shows pinned servers (false: the first few, with a hint).
    pinned: bool,
    /// Whether there is any server at all.
    has_servers: bool,
    /// The selected server (shown under the status with its ping).
    current: Option<PopoverServer>,
    servers: Vec<PopoverServer>,
}

fn view(core: &Core) -> PopoverState {
    let state = &core.state;
    let selected = state.selected_profile();
    let flags: Vec<bool> = state.profiles.iter().map(|p| p.pinned).collect();
    let (shown, pinned) = shown_servers(&flags);
    let make = |p: &veil_config::model::Profile| PopoverServer {
        id: p.id,
        name: p.name.clone(),
        latency_ms: p.latency_ms,
        level: ping_level(p.latency_ms),
        selected: selected.is_some_and(|s| s.id == p.id),
    };
    let servers = shown.into_iter().filter_map(|i| state.profiles.get(i)).map(make).collect();
    let current = selected.map(make);
    PopoverState {
        connected: core.is_connected(),
        server_name: selected.map(|p| p.name.clone()),
        mode: state.settings.mode,
        tun_available: crate::core::TUN_AVAILABLE,
        error: core.last_error().map(str::to_string),
        pinned,
        has_servers: !state.profiles.is_empty(),
        current,
        servers,
    }
}

type CoreState<'a> = State<'a, Mutex<Core>>;

#[tauri::command]
pub async fn popover_state(core: CoreState<'_>) -> Result<PopoverState, String> {
    let guard = core.lock().await;
    let core_ref: &Core = &guard;
    Ok(view(core_ref))
}

/// Measures the given servers only. The settings are not locked while waiting for the
/// answers, so a click on Connect does not wait for a slow server.
#[tauri::command]
pub async fn ping_servers(app: AppHandle, core: CoreState<'_>, ids: Vec<Uuid>) -> Result<(), String> {
    let targets = core.lock().await.ping_targets(&ids);
    if targets.is_empty() {
        return Ok(());
    }
    let results = crate::core::measure(targets).await.map_err(|e| format!("{e:#}"))?;
    core.lock().await.set_latencies(results);
    let _ = app.emit("state-changed", ());
    Ok(())
}

#[tauri::command]
pub fn hide_popover(app: AppHandle) {
    #[cfg(target_os = "macos")]
    mac::hide(&app);
    #[cfg(not(target_os = "macos"))]
    let _ = app;
}

#[tauri::command]
pub fn open_main_window(app: AppHandle) {
    #[cfg(target_os = "macos")]
    mac::hide(&app);
    crate::show_window(&app);
}

#[tauri::command]
pub fn quit_app(app: AppHandle) {
    app.exit(0);
}

/// Window handling, macOS only.
#[cfg(target_os = "macos")]
pub mod mac {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconEvent};
    use tauri::{LogicalPosition, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent};

    use super::*;

    /// When the panel last closed because it lost focus.
    static HIDDEN_AT: StdMutex<Option<Instant>> = StdMutex::new(None);
    /// Mirrors the tray's "menu on left click" switch, turned on while Control is held.
    static MENU_ON_LEFT: AtomicBool = AtomicBool::new(false);

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGEventSourceFlagsState(state_id: i32) -> u64;
    }

    /// Whether the Control key is held right now.
    fn control_down() -> bool {
        const COMBINED_SESSION_STATE: i32 = 0;
        const FLAG_CONTROL: u64 = 0x0004_0000;
        unsafe { CGEventSourceFlagsState(COMBINED_SESSION_STATE) & FLAG_CONTROL != 0 }
    }

    /// Control-click is the Mac's right click. tray-icon only knows "menu on left click"
    /// as a setting decided before the click, so it follows the Control key while the
    /// pointer is over the icon.
    fn menu_on_left(tray: &TrayIcon, on: bool) {
        if MENU_ON_LEFT.swap(on, Ordering::SeqCst) != on {
            let _ = tray.set_show_menu_on_left_click(on);
        }
    }

    /// The panel window, created hidden on first use; one per app.
    pub fn window(app: &AppHandle) -> Option<WebviewWindow> {
        if let Some(w) = app.get_webview_window(LABEL) {
            return Some(w);
        }
        let built = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("popover.html".into()))
            .title("Veil")
            .inner_size(WIDTH, HEIGHT)
            .resizable(false)
            .maximizable(false)
            .minimizable(false)
            .decorations(false)
            .transparent(true)
            .always_on_top(true)
            .skip_taskbar(true)
            .visible_on_all_workspaces(true)
            .visible(false)
            .focused(false)
            .build();
        match built {
            Ok(w) => Some(w),
            Err(e) => {
                tracing::warn!("menu bar panel: {e}");
                None
            }
        }
    }

    pub fn on_tray_event(tray: &TrayIcon, event: &TrayIconEvent) {
        match event {
            TrayIconEvent::Enter { .. } | TrayIconEvent::Move { .. } => menu_on_left(tray, control_down()),
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Down,
                rect,
                position,
                ..
            } => {
                let control = control_down();
                let menu_shown = MENU_ON_LEFT.load(Ordering::SeqCst);
                menu_on_left(tray, control);
                if control {
                    return; // the menu's click, not the panel's
                }
                let app = tray.app_handle();
                let Some(w) = window(app) else { return };
                let visible = w.is_visible().unwrap_or(false);
                let hidden_ago = HIDDEN_AT.lock().ok().and_then(|t| *t).map(|t| t.elapsed().as_millis());
                match left_click(visible, hidden_ago, menu_shown) {
                    ClickAction::Show => show(app, &w, rect, *position),
                    ClickAction::Hide => hide(app),
                    ClickAction::Ignore => {}
                }
            }
            _ => {}
        }
    }

    fn show(app: &AppHandle, w: &WebviewWindow, rect: &tauri::Rect, click: tauri::PhysicalPosition<f64>) {
        let pos = rect.position.to_physical::<f64>(1.0);
        let size = rect.size.to_physical::<f64>(1.0);
        let icon = if size.width > 0.0 && size.height > 0.0 {
            Bounds::new(pos.x, pos.y, size.width, size.height)
        } else {
            Bounds::new(click.x, click.y, 0.0, 0.0)
        };
        let screens: Vec<Screen> = app
            .available_monitors()
            .unwrap_or_default()
            .iter()
            .map(|m| {
                let (p, s, wa) = (m.position(), m.size(), m.work_area());
                Screen {
                    frame: Bounds::new(p.x.into(), p.y.into(), s.width.into(), s.height.into()),
                    work: Bounds::new(
                        wa.position.x.into(),
                        wa.position.y.into(),
                        wa.size.width.into(),
                        wa.size.height.into(),
                    ),
                    scale: m.scale_factor(),
                }
            })
            .collect();
        // Points, which mean the same on every screen (physical pixels do not).
        if let Some(screen) = pick_screen(icon, &screens).and_then(|i| screens.get(i)) {
            let (x, y) =
                panel_origin(icon.scaled(1.0 / screen.scale), screen.work.scaled(1.0 / screen.scale), WIDTH, HEIGHT);
            let _ = w.set_position(LogicalPosition::new(x, y));
        }
        let _ = w.show();
        let _ = w.set_focus();
        let _ = app.emit_to(LABEL, "popover-opened", ());
    }

    /// The panel closes when it loses focus, like a menu.
    pub fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
        if let WindowEvent::Focused(false) = event
            && window.label() == LABEL
        {
            hide(window.app_handle());
        }
    }

    /// Hides the panel (lost focus, Escape, "Open Veil").
    pub fn hide(app: &AppHandle) {
        let Some(w) = app.get_webview_window(LABEL) else { return };
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
            if let Ok(mut t) = HIDDEN_AT.lock() {
                *t = Some(Instant::now());
            }
        }
        let _ = app.emit_to(LABEL, "popover-closed", ());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RETINA: f64 = 2.0;

    fn screen(x: f64, y: f64, w: f64, h: f64, menu: f64, scale: f64) -> Screen {
        Screen {
            frame: Bounds::new(x, y, w, h).scaled(scale),
            work: Bounds::new(x, y + menu, w, h - menu).scaled(scale),
            scale,
        }
    }

    #[test]
    fn panel_centred_under_icon() {
        let work = Bounds::new(0.0, 25.0, 1440.0, 875.0);
        let icon = Bounds::new(1000.0, 0.0, 30.0, 24.0);
        let (x, y) = panel_origin(icon, work, WIDTH, HEIGHT);
        assert_eq!(x, 1015.0 - WIDTH / 2.0);
        assert_eq!(y, 28.0);
    }

    #[test]
    fn panel_kept_inside_right_and_left_edges() {
        let work = Bounds::new(0.0, 25.0, 1440.0, 875.0);
        let (x, _) = panel_origin(Bounds::new(1420.0, 0.0, 20.0, 24.0), work, WIDTH, HEIGHT);
        assert_eq!(x, 1440.0 - WIDTH - MARGIN);
        let (x, _) = panel_origin(Bounds::new(2.0, 0.0, 20.0, 24.0), work, WIDTH, HEIGHT);
        assert_eq!(x, MARGIN);
    }

    #[test]
    fn panel_on_second_screen_and_with_notch() {
        // A screen to the left of the main one (negative x) with a tall (notch) menu bar.
        let work = Bounds::new(-1512.0, 38.0, 1512.0, 944.0);
        let icon = Bounds::new(-300.0, 0.0, 30.0, 37.0);
        let (x, y) = panel_origin(icon, work, WIDTH, HEIGHT);
        assert_eq!(x, -285.0 - WIDTH / 2.0);
        assert_eq!(y, 41.0);
        // An icon whose rect reports y = 0 height = 0 still lands under the menu bar.
        let (_, y) = panel_origin(Bounds::new(-300.0, 0.0, 0.0, 0.0), work, WIDTH, HEIGHT);
        assert_eq!(y, 38.0);
    }

    #[test]
    fn panel_goes_above_a_bottom_bar_and_fits_tiny_screens() {
        let work = Bounds::new(0.0, 0.0, 1280.0, 760.0);
        // Room above the icon: the panel ends just above it.
        let (_, y) = panel_origin(Bounds::new(600.0, 700.0, 24.0, 24.0), work, WIDTH, HEIGHT);
        assert_eq!(y, 700.0 - GAP - HEIGHT);
        // An icon below the work area: the panel stays inside it.
        let (_, y) = panel_origin(Bounds::new(600.0, 765.0, 24.0, 24.0), work, WIDTH, HEIGHT);
        assert_eq!(y, 760.0 - HEIGHT);
        let small = Bounds::new(0.0, 25.0, 200.0, 300.0);
        let (x, y) = panel_origin(Bounds::new(100.0, 0.0, 24.0, 24.0), small, WIDTH, HEIGHT);
        assert_eq!((x, y), (0.0, 25.0));
    }

    #[test]
    fn screen_of_the_icon() {
        // Main Retina screen 1440x900 pt, an external 1x screen to its right.
        let screens = [screen(0.0, 0.0, 1440.0, 900.0, 24.0, RETINA), screen(1440.0, 0.0, 1920.0, 1080.0, 24.0, 1.0)];
        // Icon on the Retina screen at x = 1000 pt.
        assert_eq!(pick_screen(Bounds::new(1000.0, 0.0, 30.0, 24.0).scaled(RETINA), &screens), Some(0));
        // Icon on the external screen at x = 2000 pt: in physical pixels (2000) it also looks
        // like it is on the Retina screen (0..2880), but there it would be 12 pt high.
        assert_eq!(pick_screen(Bounds::new(2000.0, 0.0, 30.0, 24.0), &screens), Some(1));
        // Nowhere: the nearest screen.
        assert_eq!(pick_screen(Bounds::new(3500.0, 0.0, 30.0, 24.0), &screens), Some(1));
        assert_eq!(pick_screen(Bounds::new(0.0, 0.0, 30.0, 24.0), &[]), None);
    }

    #[test]
    fn left_click_toggles() {
        assert_eq!(left_click(false, None, false), ClickAction::Show);
        assert_eq!(left_click(true, None, false), ClickAction::Hide);
        // The click that took the focus away (and so closed the panel) does not reopen it.
        assert_eq!(left_click(false, Some(50), false), ClickAction::Ignore);
        assert_eq!(left_click(false, Some(5_000), false), ClickAction::Show);
        // The native menu took this click.
        assert_eq!(left_click(false, None, true), ClickAction::Ignore);
    }

    #[test]
    fn pinned_or_first_two() {
        assert_eq!(shown_servers(&[]), (vec![], false));
        assert_eq!(shown_servers(&[false; 1]), (vec![0], false));
        assert_eq!(shown_servers(&[false; 70]), (vec![0, 1], false));
        let mut many = vec![false; 70];
        for i in [3, 10, 11, 40, 50, 60, 69] {
            many[i] = true;
        }
        assert_eq!(shown_servers(&many), (vec![3, 10, 11, 40, 50, 60, 69], true));
    }

    #[test]
    fn ping_colours() {
        assert_eq!(ping_level(None), "unknown");
        assert_eq!(ping_level(Some(0)), "bad");
        assert_eq!(ping_level(Some(1)), "good");
        assert_eq!(ping_level(Some(149)), "good");
        assert_eq!(ping_level(Some(150)), "mid");
        assert_eq!(ping_level(Some(399)), "mid");
        assert_eq!(ping_level(Some(400)), "bad");
    }
}
