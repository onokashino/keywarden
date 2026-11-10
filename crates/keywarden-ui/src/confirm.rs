//! `keywarden-ui --confirm '{"title","text","allow_always"}'`: окно подтверждения поверх всего.
//! Его запускает демон (подключение расширения, пароль новому сайту, подпись SSH-ключом).
//! Код выхода: 11 разрешить всегда, 10 только сейчас, 1 отказ (и Esc, и закрытие).

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::tr;
use serde::Deserialize;
use std::sync::atomic::{AtomicI32, Ordering};

pub static EXIT_CODE: AtomicI32 = AtomicI32::new(1);

actions!(confirm, [AllowOnce, AllowAlways, Deny]);
const CONTEXT: &str = "Confirm";

#[derive(Deserialize, Clone)]
pub struct Prompt {
    pub title: String,
    pub text: String,
    #[serde(default)]
    pub allow_always: bool,
    /// «всегда» на самом деле на N минут (SSH-ключ): так и подписать кнопку
    #[serde(default)]
    pub always_minutes: Option<u32>,
}

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("enter", AllowOnce, Some(CONTEXT)),
        KeyBinding::new("ctrl-enter", AllowAlways, Some(CONTEXT)),
        KeyBinding::new("escape", Deny, Some(CONTEXT)),
    ]);
}

pub struct ConfirmView {
    prompt: Prompt,
    focus: FocusHandle,
}

impl ConfirmView {
    pub fn new(prompt: Prompt, cx: &mut Context<Self>) -> Self {
        Self {
            prompt,
            focus: cx.focus_handle(),
        }
    }
}

fn finish(code: i32, cx: &mut App) {
    EXIT_CODE.store(code, Ordering::SeqCst);
    cx.quit();
}

impl Render for ConfirmView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if !self.focus.is_focused(window) {
            window.focus(&self.focus, cx);
        }
        let theme = cx.theme().clone();
        window.set_rem_size(theme.font_size);
        div()
            .key_context(CONTEXT)
            .track_focus(&self.focus)
            .on_action(|_: &AllowOnce, _, cx| finish(10, cx))
            .on_action(|_: &AllowAlways, _, cx| finish(11, cx))
            .on_action(|_: &Deny, _, cx| finish(1, cx))
            .size_full()
            .p_3()
            .font_family(theme.font_family.clone())
            .child(
                v_flex()
                    .size_full()
                    .gap_3()
                    .p_5()
                    .bg(theme.background)
                    .text_color(theme.foreground)
                    .border_1()
                    .border_color(theme.border)
                    .rounded_xl()
                    .shadow_lg()
                    .child(
                        h_flex()
                            .gap_3()
                            .child(crate::ui::icon_tile(IconName::ShieldCheck, 36., &theme))
                            .child(
                                v_flex()
                                    .min_w_0()
                                    .child(
                                        div()
                                            .text_base()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .truncate()
                                            .child(self.prompt.title.clone()),
                                    )
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(theme.muted_foreground)
                                            .child(tr!("Keywarden спрашивает разрешение")),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .bg(theme.list_even)
                            .border_1()
                            .border_color(theme.border)
                            .text_sm()
                            .child(self.prompt.text.clone()),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                h_flex()
                                    .flex_1()
                                    .gap_3()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(crate::ui::kbd_hint("escape", tr!("нет")))
                                    .child(crate::ui::kbd_hint("enter", tr!("да")))
                                    .when(self.prompt.allow_always, |d| {
                                        d.child(crate::ui::kbd_hint(
                                            "ctrl-enter",
                                            match self.prompt.always_minutes {
                                                Some(n) => tr!("на {n} мин", n = n),
                                                None => tr!("всегда").to_string(),
                                            },
                                        ))
                                    }),
                            )
                            .child(
                                Button::new("deny")
                                    .outline()
                                    .label(tr!("Отказать"))
                                    .on_click(|_, _, cx| finish(1, cx)),
                            )
                            .child(
                                Button::new("once")
                                    .when(!self.prompt.allow_always, |b| b.primary())
                                    .when(self.prompt.allow_always, |b| b.outline())
                                    .label(tr!("Разрешить"))
                                    .on_click(|_, _, cx| finish(10, cx)),
                            )
                            .when(self.prompt.allow_always, |d| {
                                d.child(
                                    Button::new("always")
                                        .primary()
                                        .label(match self.prompt.always_minutes {
                                            Some(n) => tr!("Разрешить на {n} мин", n = n),
                                            None => tr!("Разрешить всегда").to_string(),
                                        })
                                        .on_click(|_, _, cx| finish(11, cx)),
                                )
                            }),
                    ),
            )
    }
}

pub fn window_options(cx: &App) -> WindowOptions {
    crate::ui::overlay_options("keywarden-confirm", 680., 250., cx)
}
