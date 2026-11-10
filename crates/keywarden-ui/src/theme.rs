//! Тема. По умолчанию встроенная «Keywarden» (графит + фиолетовый акцент).
//! Если подключён шаблон Noctalia (dist/noctalia/keywarden.json пишет
//! `$XDG_CONFIG_HOME/keywarden/themes/noctalia.json`), берём её цвета и перекрашиваемся
//! на лету, когда Noctalia меняет палитру.

use gpui_kit::component::{Theme, ThemeMode, ThemeRegistry};
use gpui_kit::{App, SharedString};
use std::path::PathBuf;

pub const NOCTALIA: &str = "Noctalia";
const BUILTIN: &str = "Keywarden";

pub fn themes_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("keywarden/themes")
}

pub fn init(cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    if let Err(e) =
        ThemeRegistry::global_mut(cx).load_themes_from_str(include_str!("keywarden-theme.json"))
    {
        tracing::warn!("встроенная тема не загрузилась: {e}");
    }
    // копия на случай, если перечитывание каталога сбросит реестр
    let builtin = ThemeRegistry::global(cx).themes().get(BUILTIN).cloned();
    if let Some(cfg) = &builtin {
        Theme::update(cx, |t| t.apply_config(cfg));
    }
    let dir = themes_dir();
    let _ = std::fs::create_dir_all(&dir);
    let wanted: SharedString = std::env::var("KEYWARDEN_THEME")
        .unwrap_or_else(|_| NOCTALIA.into())
        .into();
    let res = ThemeRegistry::watch_dir(dir, cx, move |cx| {
        let cfg = ThemeRegistry::global(cx)
            .themes()
            .get(&wanted)
            .cloned()
            .or_else(|| builtin.clone());
        if let Some(cfg) = cfg {
            Theme::update(cx, |t| t.apply_config(&cfg));
            cx.refresh_windows();
        }
    });
    if let Err(e) = res {
        tracing::warn!("каталог тем не отслеживается: {e}");
    }
}
