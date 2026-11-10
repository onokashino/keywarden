//! Мелкие общие элементы интерфейса.

use gpui_kit::component::kbd::Kbd;
use gpui_kit::component::{ActiveTheme as _, Sizable as _, h_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::model::EntryKind;
use keywarden_core::tr;

pub fn kind_icon(k: EntryKind) -> IconName {
    match k {
        EntryKind::Login => IconName::KeyRound,
        EntryKind::Card => IconName::CreditCard,
        EntryKind::Identity => IconName::IdCard,
        EntryKind::Note => IconName::StickyNote,
        EntryKind::SshKey => IconName::SquareTerminal,
        EntryKind::SshHost => IconName::Server,
        EntryKind::Passkey => IconName::FingerprintPattern,
        EntryKind::CryptoWallet => IconName::Wallet,
    }
}

/// Подсказка в подвале: [Ctrl+U] логин
/// Путь для показа: домашний каталог сокращается до «~».
pub fn tilde(path: &str) -> String {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default();
    tilde_in(path, &home)
}

fn tilde_in(path: &str, home: &str) -> String {
    match path.strip_prefix(home) {
        Some(rest) if !home.is_empty() && (rest.is_empty() || rest.starts_with(['/', '\\'])) => {
            format!("~{rest}")
        }
        _ => path.to_string(),
    }
}

pub fn kbd_hint(keys: &'static str, label: impl Into<SharedString>) -> impl IntoElement {
    h_flex()
        .gap_1()
        .child(Kbd::new(Keystroke::parse(keys).expect("валидная клавиша")))
        .child(label.into())
}

#[allow(dead_code)]
pub fn muted(text: impl Into<SharedString>, cx: &App) -> Div {
    div()
        .text_xs()
        .text_color(cx.theme().muted_foreground)
        .child(text.into())
}

/// Квадрат с иконкой, как плитки в референсе.
pub fn icon_tile(icon: IconName, size: f32, theme: &gpui_kit::component::Theme) -> Div {
    div()
        .size(px(size))
        .flex_shrink_0()
        .flex()
        .items_center()
        .justify_center()
        .rounded_lg()
        .border_1()
        .border_color(theme.border)
        .bg(theme.secondary)
        .child(gpui_kit::component::Icon::new(icon).text_color(theme.primary))
}

/// Сегментный переключатель: подложка и «таблетка» у выбранного пункта, иконка внутри неё.
/// Свой, потому что TabBar из gpui-kit рисует иконку вне таблетки.
pub fn segmented<V: 'static>(
    id: &'static str,
    items: Vec<(Option<IconName>, String)>,
    selected: usize,
    cx: &mut Context<V>,
    on_select: impl Fn(&mut V, usize, &mut Window, &mut Context<V>) + Clone + 'static,
) -> impl IntoElement {
    let theme = cx.theme().clone();
    h_flex()
        .id(id)
        .flex_shrink_0()
        .self_start()
        .p(px(3.))
        .gap(px(2.))
        .rounded_lg()
        .border_1()
        .border_color(theme.border)
        .bg(theme.tab_bar_segmented)
        .children(items.into_iter().enumerate().map(|(ix, (icon, label))| {
            let active = ix == selected;
            let on_select = on_select.clone();
            h_flex()
                .id((id, ix))
                .h(px(30.))
                .px_3()
                .gap_2()
                .rounded_md()
                .text_sm()
                .border_1()
                .border_color(transparent_black())
                .cursor_pointer()
                .when(active, |d| {
                    d.bg(theme.tab_active)
                        .border_color(theme.border)
                        .shadow_xs()
                        .text_color(theme.foreground)
                })
                .when(!active, |d| {
                    d.text_color(theme.muted_foreground)
                        .hover(|d| d.text_color(theme.foreground))
                })
                .on_click(cx.listener(move |v, _, w, cx| on_select(v, ix, w, cx)))
                .when_some(icon, |d, i| {
                    d.child(
                        gpui_kit::component::Icon::new(i)
                            .small()
                            .text_color(if active {
                                theme.primary
                            } else {
                                theme.muted_foreground
                            }),
                    )
                })
                .child(label)
        }))
}

// --- окна (диалоги) в одном стиле: шапка, линия, тело, линия, подвал ---

/// Шапка окна: чёткий заголовок и приглушённый подзаголовок, линия на всю ширину снизу.
pub fn sheet_header(
    title: impl Into<SharedString>,
    subtitle: Option<&'static str>,
    theme: &gpui_kit::component::Theme,
) -> Div {
    v_flex_div()
        .px_5()
        .pt_4()
        .pb_3()
        .gap_0p5()
        .border_b_1()
        .border_color(theme.border)
        .child(
            div()
                .text_base()
                .font_weight(FontWeight::SEMIBOLD)
                .child(title.into()),
        )
        .when_some(subtitle, |d, s| {
            d.child(div().text_xs().text_color(theme.muted_foreground).child(s))
        })
}

/// Тело окна с ровными отступами.
pub fn sheet_body() -> Div {
    v_flex_div().p_5().gap_4()
}

/// Подвал: слева подсказки клавиш, справа кнопки; линия на всю ширину сверху.
pub fn sheet_footer(theme: &gpui_kit::component::Theme) -> Div {
    h_flex()
        .px_5()
        .py_3()
        .gap_2()
        .border_t_1()
        .border_color(theme.border)
        .bg(theme.sidebar)
}

/// Подпись поля формы.
pub fn field_label(text: &'static str, theme: &gpui_kit::component::Theme) -> Div {
    div()
        .text_xs()
        .font_weight(FontWeight::MEDIUM)
        .text_color(theme.muted_foreground)
        .child(text)
}

fn v_flex_div() -> Div {
    div().flex().flex_col()
}

/// Плашка статуса: текст своим цветом на полупрозрачной подложке того же цвета.
/// Читается на тёмном фоне лучше, чем Tag с плотной заливкой.
pub fn badge(text: impl Into<SharedString>, color: Hsla) -> Div {
    div()
        .flex_shrink_0()
        .px_1p5()
        .py_0p5()
        .rounded(px(4.))
        .border_1()
        .border_color(color.opacity(0.35))
        .bg(color.opacity(0.12))
        .text_xs()
        .font_weight(FontWeight::MEDIUM)
        .text_color(color)
        .child(text.into())
}

/// Открыть системное окно выбора файла и записать путь в поле.
pub fn pick_file(
    state: gpui_kit::Entity<gpui_kit::component::input::InputState>,
    prompt: &'static str,
    window: &mut Window,
    cx: &mut App,
) {
    let rx = cx.prompt_for_paths(PathPromptOptions {
        files: true,
        directories: false,
        multiple: false,
        prompt: Some(prompt.into()),
    });
    window
        .spawn(cx, async move |cx| {
            if let Ok(Ok(Some(mut v))) = rx.await
                && !v.is_empty()
            {
                let f = v.remove(0).display().to_string();
                let _ = cx.update(|window, cx| {
                    state.update(cx, |i, cx| i.set_value(f, window, cx));
                    window.refresh();
                });
            }
        })
        .detach();
}

/// Поле файла без ручного ввода пути: пусто → «Выбрать файл…» (системное окно),
/// выбрано → имя файла, папка, «Сменить» и «Убрать». Значение хранится в обычном InputState.
pub fn file_field(
    id: &'static str,
    state: &gpui_kit::Entity<gpui_kit::component::input::InputState>,
    empty: &'static str,
    prompt: &'static str,
    icon: IconName,
    cx: &App,
) -> AnyElement {
    use gpui_kit::component::button::{Button, ButtonVariants as _};
    let theme = cx.theme();
    let value = state.read(cx).value().trim().to_string();
    let pick = {
        let st = state.clone();
        move |_: &ClickEvent, w: &mut Window, cx: &mut App| pick_file(st.clone(), prompt, w, cx)
    };
    if value.is_empty() {
        return h_flex()
            .id(id)
            .h(px(36.))
            .px_3()
            .gap_2()
            .rounded_md()
            .border_1()
            .border_color(theme.input)
            .text_sm()
            .text_color(theme.muted_foreground)
            .cursor_pointer()
            .hover(|d| d.bg(theme.secondary).text_color(theme.foreground))
            .on_click(pick)
            .child(gpui_kit::component::Icon::new(icon).small())
            .child(div().flex_1().child(empty))
            .child(div().text_xs().child(tr!("Выбрать файл…")))
            .into_any_element();
    }
    let path = std::path::Path::new(&value);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| value.clone());
    let mut dir = path
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if let Some(home) = std::env::var_os("HOME").map(|h| h.to_string_lossy().into_owned())
        && let Some(rest) = dir.strip_prefix(&home)
    {
        dir = format!("~{rest}");
    }
    let clear = state.clone();
    h_flex()
        .id(id)
        .h(px(44.))
        .pl_3()
        .pr_1()
        .gap_3()
        .rounded_md()
        .border_1()
        .border_color(theme.border)
        .bg(theme.secondary)
        .child(
            gpui_kit::component::Icon::new(icon)
                .small()
                .text_color(theme.primary),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w_0()
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::MEDIUM)
                        .truncate()
                        .child(name),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .truncate()
                        .child(dir),
                ),
        )
        .child(
            Button::new(SharedString::from(format!("{id}-change")))
                .ghost()
                .small()
                .label(tr!("Сменить"))
                .on_click(pick),
        )
        .child(
            Button::new(SharedString::from(format!("{id}-clear")))
                .ghost()
                .small()
                .icon(IconName::Close)
                .tooltip(tr!("Убрать"))
                .on_click(move |_, w, cx| {
                    clear.update(cx, |i, cx| i.set_value("", w, cx));
                    w.refresh();
                }),
        )
        .into_any_element()
}

/// Слот YubiKey кнопками вместо ввода: «Без YubiKey», «Слот 1», «Слот 2».
/// Значение ("", "1", "2") хранится в обычном InputState, как раньше.
pub fn yubikey_slots(
    id: &'static str,
    state: &gpui_kit::Entity<gpui_kit::component::input::InputState>,
    cx: &App,
) -> AnyElement {
    let theme = cx.theme();
    let cur = state.read(cx).value().trim().to_string();
    // "2:12345678" (слот с серийным номером) показываем как слот 2
    let slot = cur.split(':').next().unwrap_or_default().to_string();
    h_flex()
        .id(id)
        .p(px(3.))
        .gap(px(2.))
        .rounded_lg()
        .border_1()
        .border_color(theme.border)
        .bg(theme.tab_bar_segmented)
        .children(
            [
                ("", tr!("Без YubiKey")),
                ("1", tr!("Слот 1")),
                ("2", tr!("Слот 2")),
            ]
            .into_iter()
            .enumerate()
            .map(|(ix, (v, label))| {
                let active = slot == v;
                let st = state.clone();
                h_flex()
                    .id((id, ix))
                    .h(px(28.))
                    .px_3()
                    .rounded_md()
                    .text_sm()
                    .cursor_pointer()
                    .when(active, |d| {
                        d.bg(theme.tab_active)
                            .shadow_xs()
                            .text_color(theme.foreground)
                    })
                    .when(!active, |d| {
                        d.text_color(theme.muted_foreground)
                            .hover(|d| d.text_color(theme.foreground))
                    })
                    .on_click(move |_, w, cx| {
                        st.update(cx, |i, cx| i.set_value(v, w, cx));
                        w.refresh();
                    })
                    .child(label)
            }),
        )
        .into_any_element()
}

/// Окно поверх всех (лаунчер, подтверждение): layer-shell там, где он есть (Wayland: niri, Sway,
/// KDE), иначе всплывающее окно по центру экрана (Windows, macOS, X11, GNOME).
pub fn overlay_options(namespace: &'static str, w: f32, h: f32, cx: &App) -> WindowOptions {
    let sz = size(px(w), px(h));
    #[cfg(target_os = "linux")]
    if layer_shell_available() {
        use gpui_kit::layer_shell::{Anchor, KeyboardInteractivity, Layer, LayerShellOptions};
        return WindowOptions {
            titlebar: None,
            window_bounds: Some(WindowBounds::Windowed(Bounds {
                origin: point(px(0.), px(0.)),
                size: sz,
            })),
            kind: WindowKind::LayerShell(LayerShellOptions {
                namespace: namespace.into(),
                layer: Layer::Overlay,
                anchor: Anchor::empty(),
                keyboard_interactivity: KeyboardInteractivity::Exclusive,
                ..Default::default()
            }),
            window_background: WindowBackgroundAppearance::Transparent,
            focus: true,
            show: true,
            ..Default::default()
        };
    }
    let _ = namespace;
    WindowOptions {
        titlebar: None,
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(None, sz, cx))),
        kind: WindowKind::PopUp,
        is_resizable: false,
        window_background: WindowBackgroundAppearance::Transparent,
        focus: true,
        show: true,
        ..Default::default()
    }
}

/// Есть ли layer-shell: Wayland, но не GNOME (Mutter его не поддерживает).
#[cfg(target_os = "linux")]
fn layer_shell_available() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some()
        && !std::env::var("XDG_CURRENT_DESKTOP")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("gnome")
}

#[cfg(test)]
mod tilde_tests {
    // не `super::*`: вместе с gpui_kit::* приходит gpui-шный #[test]
    use super::tilde_in;

    #[test]
    fn only_whole_home() {
        assert_eq!(tilde_in("/home/a/Sync/v.kdbx", "/home/a"), "~/Sync/v.kdbx");
        assert_eq!(tilde_in("/home/ab/v.kdbx", "/home/a"), "/home/ab/v.kdbx");
        assert_eq!(tilde_in("/srv/v.kdbx", ""), "/srv/v.kdbx");
    }
}
