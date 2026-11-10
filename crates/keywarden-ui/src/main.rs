//! keywarden-ui: главное окно и лаунчер на GPUI (gpui-kit).
//!
//! `keywarden-ui` открывает главное окно, `keywarden-ui --launcher` открывает лаунчер поверх
//! всего (layer-shell на Wayland, иначе всплывающее окно); его вешают на горячую клавишу
//! (niri, настройки клавиатуры GNOME и KDE, ярлык Windows, «Быстрые команды» macOS).

mod assets;
mod attachment_view;
mod brands;
mod client;
mod confirm;
mod editor;
mod generator;
mod launcher;
mod main_window;
mod otp_wizard;
mod seed_gen;
mod settings_page;
mod smooth_scroll;
mod ssh_migrate;
mod ssh_new;
mod theme;
mod ui;

use gpui_kit::*;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().collect();
    let launcher_mode = args.iter().any(|a| a == "--launcher");
    // --unlock [ПРИЧИНА]: окно разблокировки по запросу демона (SSH-агент), закрывается само
    let unlock_reason = args.iter().position(|a| a == "--unlock").map(|i| {
        args.get(i + 1)
            .filter(|a| !a.starts_with("--"))
            .cloned()
            .unwrap_or_default()
    });
    let confirm = args.iter().position(|a| a == "--confirm").map(|i| {
        args.get(i + 1)
            .and_then(|j| serde_json::from_str::<confirm::Prompt>(j).ok())
            .unwrap_or_else(|| {
                eprintln!("--confirm ждёт JSON {{\"title\",\"text\",\"allow_always\"}}");
                std::process::exit(2)
            })
    });

    let is_confirm = confirm.is_some();
    application().with_assets(assets::AppAssets).run(move |cx| {
        gpui_kit::init(cx);
        theme::init(cx);
        launcher::bind_keys(cx);
        confirm::bind_keys(cx);
        main_window::bind_keys(cx);
        settings_page::bind_keys(cx);
        editor::bind_keys(cx);
        if let Some(prompt) = confirm {
            cx.open_window(confirm::window_options(cx), |_, cx| {
                cx.new(|cx| confirm::ConfirmView::new(prompt, cx))
            })
            .expect("не удалось открыть окно подтверждения");
        } else if let Some(reason) = unlock_reason {
            cx.open_window(launcher::window_options(cx), |window, cx| {
                cx.new(|cx| launcher::Launcher::unlock_only(reason, window, cx))
            })
            .expect("не удалось открыть окно разблокировки");
        } else if launcher_mode {
            // без Root из gpui-kit: он заливает окно фоном темы, а у лаунчера прозрачные края с тенью
            cx.open_window(launcher::window_options(cx), |window, cx| {
                cx.new(|cx| launcher::Launcher::new(window, cx))
            })
            .expect("не удалось открыть лаунчер");
        } else {
            let opts = main_window::window_options(cx);
            open_window(opts, cx, |window, cx| {
                cx.new(|cx| main_window::MainWindow::new(window, cx))
            })
            .expect("не удалось открыть окно");
            cx.on_window_closed(|cx, _| cx.quit()).detach();
        }
        cx.activate(true);
    });
    std::process::exit(
        confirm::EXIT_CODE.load(std::sync::atomic::Ordering::SeqCst) * is_confirm as i32,
    );
}
