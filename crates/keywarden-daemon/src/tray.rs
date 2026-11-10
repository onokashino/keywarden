//! Значок в трее: состояние базы и быстрые действия (открыть, поиск, блокировка, выход).
//! Linux: StatusNotifierItem по D-Bus (KDE, waybar, noctalia, GNOME с AppIndicator);
//! Windows: область уведомлений. Выключается в настройках.
//!
//! На macOS значка нет: строке меню нужен цикл NSApplication на главном потоке,
//! а там tokio. Делать вместе с переносом рантайма в фоновый поток.

use crate::state::Daemon;
use std::process::Child;
use std::sync::{Arc, mpsc};
use std::time::Duration;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

/// Что показывать: значок включён, база открыта.
type View = (bool, bool);

enum Action {
    Open,
    Launcher,
    Lock,
    Quit,
}

pub async fn run(d: Arc<Daemon>) {
    // у каждой базы свой демон; значок один, у основной
    if keywarden_core::ipc::profile().is_some() {
        return;
    }
    let (view_tx, view_rx) = mpsc::channel::<View>();
    let (act_tx, mut act_rx) = tokio::sync::mpsc::unbounded_channel();
    let tx = act_tx.clone();
    MenuEvent::set_event_handler(Some(move |e: MenuEvent| {
        let a = match e.id.0.as_str() {
            "open" => Action::Open,
            "launcher" => Action::Launcher,
            "lock" => Action::Lock,
            "quit" => Action::Quit,
            _ => return,
        };
        let _ = tx.send(a);
    }));
    TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = e
        {
            let _ = act_tx.send(Action::Open);
        }
    }));
    if let Err(e) = std::thread::Builder::new()
        .name("tray".into())
        .spawn(move || tray_thread(view_rx))
    {
        tracing::warn!("трей: {e}");
        return;
    }

    let mut window: Option<Child> = None;
    let mut shown = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                let view = (d.config().tray, d.is_unlocked());
                if shown != Some(view) {
                    shown = Some(view);
                    if view_tx.send(view).is_err() {
                        return;
                    }
                }
            }
            Some(a) = act_rx.recv() => match a {
                Action::Open => {
                    // уже открытое окно не плодим
                    if !window.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None))) {
                        window = spawn_ui(&[]);
                    }
                }
                Action::Launcher => {
                    spawn_ui(&["--launcher"]);
                }
                Action::Lock => d.lock("значок в трее").await,
                Action::Quit => {
                    d.lock("выход из трея").await;
                    std::process::exit(0);
                }
            },
        }
    }
}

fn spawn_ui(args: &[&str]) -> Option<Child> {
    let mut cmd = std::process::Command::new(crate::confirm::ui_binary());
    cmd.args(args);
    match cmd.spawn() {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::warn!("keywarden-ui не запустился: {e}");
            None
        }
    }
}

fn icon(png_bytes: &[u8]) -> Option<Icon> {
    let mut reader = png::Decoder::new(std::io::Cursor::new(png_bytes))
        .read_info()
        .ok()?;
    let mut buf = vec![0; reader.output_buffer_size()?];
    let info = reader.next_frame(&mut buf).ok()?;
    buf.truncate(info.buffer_size());
    Icon::from_rgba(buf, info.width, info.height).ok()
}

/// Значок и меню живут на своём потоке: в Windows им нужен цикл сообщений этого потока.
fn tray_thread(rx: mpsc::Receiver<View>) {
    let open_icon = icon(include_bytes!("../assets/tray.png"));
    let locked_icon = icon(include_bytes!("../assets/tray-locked.png"));
    let lock = MenuItem::with_id("lock", tr!("Заблокировать"), false, None);
    let menu = Menu::new();
    let built = menu.append_items(&[
        &MenuItem::with_id("open", tr!("Открыть Keywarden"), true, None),
        &MenuItem::with_id("launcher", tr!("Быстрый поиск"), true, None),
        &PredefinedMenuItem::separator(),
        &lock,
        &PredefinedMenuItem::separator(),
        &MenuItem::with_id("quit", tr!("Выход"), true, None),
    ]);
    if let Err(e) = built {
        tracing::warn!("трей: меню: {e}");
        return;
    }
    let mut tray = None;
    loop {
        #[cfg(windows)]
        let next = {
            pump_messages();
            match rx.recv_timeout(Duration::from_millis(50)) {
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                r => r.ok(),
            }
        };
        #[cfg(not(windows))]
        let next = rx.recv().ok();
        let Some((enabled, unlocked)) = next else {
            return;
        };
        if !enabled {
            // выключили в настройках: значок исчезает сразу
            tray = None;
            continue;
        }
        let tip = if unlocked {
            tr!("Keywarden: база открыта")
        } else {
            tr!("Keywarden: база заблокирована")
        };
        let img = if unlocked { &open_icon } else { &locked_icon };
        lock.set_enabled(unlocked);
        match &mut tray {
            Some(t) => {
                let t: &mut tray_icon::TrayIcon = t;
                let _ = t.set_icon(img.clone());
                let _ = t.set_tooltip(Some(tip));
            }
            None => {
                let mut b = TrayIconBuilder::new()
                    .with_id("keywarden")
                    .with_title("Keywarden")
                    .with_tooltip(tip)
                    .with_menu(Box::new(menu.clone()))
                    .with_menu_on_left_click(false);
                if let Some(i) = img.clone() {
                    b = b.with_icon(i);
                }
                match b.build() {
                    Ok(t) => tray = Some(t),
                    Err(e) => tracing::warn!("трей недоступен: {e}"),
                }
            }
        }
    }
}

#[cfg(windows)]
fn pump_messages() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, MSG, PM_REMOVE, PeekMessageW, TranslateMessage,
    };
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}
