//! Генератор паролей и парольных фраз (окно по Ctrl+G и кнопка в редакторе).
//! Сама генерация в демоне (keywarden-core::generator), здесь только настройки и показ.

use crate::client;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::slider::{Slider, SliderEvent, SliderState};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::generator::{Generate, Generated, PassphraseOptions, PasswordOptions};
use keywarden_core::ipc::{Request, Response};
use keywarden_core::tr;
use serde::{Deserialize, Serialize};

/// Последние настройки генератора: открывается с теми же, что были.
#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct Saved {
    passphrase: bool,
    password: PasswordOptions,
    phrase: PassphraseOptions,
}

fn saved_path() -> std::path::PathBuf {
    keywarden_core::ipc::config_dir().join("generator.json")
}

/// Готовые наборы под типичные требования сайтов.
fn presets() -> [&'static str; 5] {
    [
        tr!("Надёжный"),
        tr!("Без символов"),
        tr!("PIN 6 цифр"),
        tr!("Фраза"),
        tr!("Максимум"),
    ]
}

pub struct GeneratorPanel {
    passphrase: bool,
    password: PasswordOptions,
    phrase: PassphraseOptions,
    length: Entity<SliderState>,
    words: Entity<SliderState>,
    current: Option<Generated>,
    status: Option<SharedString>,
    tasks: Vec<Task<()>>,
    _subs: Vec<Subscription>,
}

impl GeneratorPanel {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let saved: Saved = std::fs::read(saved_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let length = cx.new(|_| {
            SliderState::new()
                .min(4.)
                .max(64.)
                .step(1.)
                .default_value(saved.password.length.clamp(4, 64) as f32)
        });
        let words = cx.new(|_| {
            SliderState::new()
                .min(4.)
                .max(12.)
                .step(1.)
                .default_value(saved.phrase.words.clamp(4, 12) as f32)
        });
        let subs = vec![
            cx.subscribe_in(&length, window, |this, _, ev: &SliderEvent, _, cx| {
                if let SliderEvent::Change(v) = ev {
                    this.password.length = v.start() as usize;
                    this.generate(cx);
                }
            }),
            cx.subscribe_in(&words, window, |this, _, ev: &SliderEvent, _, cx| {
                if let SliderEvent::Change(v) = ev {
                    this.phrase.words = v.start() as usize;
                    this.generate(cx);
                }
            }),
        ];
        let mut this = Self {
            passphrase: saved.passphrase,
            password: saved.password,
            phrase: saved.phrase,
            length,
            words,
            current: None,
            status: None,
            tasks: vec![],
            _subs: subs,
        };
        this.generate(cx);
        this
    }

    fn options(&self) -> Generate {
        if self.passphrase {
            Generate::Passphrase(self.phrase.clone())
        } else {
            Generate::Password(self.password.clone())
        }
    }

    fn apply_preset(&mut self, ix: usize, window: &mut Window, cx: &mut Context<Self>) {
        let pw = |length, symbols, digits_only: bool| PasswordOptions {
            length,
            lower: !digits_only,
            upper: !digits_only,
            digits: true,
            symbols,
            exclude_ambiguous: !digits_only,
        };
        match ix {
            0 => (self.passphrase, self.password) = (false, pw(20, true, false)),
            1 => (self.passphrase, self.password) = (false, pw(16, false, false)),
            2 => (self.passphrase, self.password) = (false, pw(6, false, true)),
            3 => {
                self.passphrase = true;
                self.phrase = PassphraseOptions {
                    words: 5,
                    separator: "-".into(),
                    capitalize: true,
                    number: true,
                };
            }
            _ => (self.passphrase, self.password) = (false, pw(40, true, false)),
        }
        let (l, w) = (self.password.length as f32, self.phrase.words as f32);
        self.length.update(cx, |s, cx| s.set_value(l, window, cx));
        self.words.update(cx, |s, cx| s.set_value(w, window, cx));
        self.generate(cx);
    }

    fn preset_active(&self, ix: usize) -> bool {
        let p = &self.password;
        match ix {
            3 => self.passphrase,
            _ if self.passphrase => false,
            0 => p.length == 20 && p.symbols && p.upper && p.lower,
            1 => p.length == 16 && !p.symbols && p.upper && p.lower,
            2 => p.length == 6 && p.digits && !p.lower && !p.upper && !p.symbols,
            _ => p.length == 40 && p.symbols,
        }
    }

    pub fn generate(&mut self, cx: &mut Context<Self>) {
        let saved = Saved {
            passphrase: self.passphrase,
            password: self.password.clone(),
            phrase: self.phrase.clone(),
        };
        if let Ok(b) = serde_json::to_vec_pretty(&saved) {
            let _ = std::fs::create_dir_all(keywarden_core::ipc::config_dir());
            let _ = std::fs::write(saved_path(), b);
        }
        self.tasks.clear();
        self.tasks.push(client::call(
            cx,
            Request::Generate {
                options: self.options(),
            },
            |this, res, cx| {
                if let Ok(Response::Generated { generated }) = res {
                    this.current = Some(generated);
                    this.status = None;
                }
                cx.notify();
            },
        ));
    }

    fn copy(&mut self, cx: &mut Context<Self>) {
        let Some(g) = &self.current else { return };
        self.tasks.push(client::call(
            cx,
            Request::CopyText {
                value: g.value.clone(),
            },
            |this, res, cx| {
                this.status = Some(match res {
                    Ok(_) => tr!("Скопировано, буфер очистится сам").into(),
                    Err(e) => e.message().into(),
                });
                cx.notify();
            },
        ));
    }

    fn switch(
        &self,
        id: &'static str,
        label: &'static str,
        on: bool,
        cx: &mut Context<Self>,
        set: fn(&mut Self, bool),
    ) -> impl IntoElement {
        Switch::new(id)
            .label(label)
            .checked(on)
            .small()
            .on_change(cx.listener(move |this, v: &bool, _, cx| {
                set(this, *v);
                this.generate(cx);
            }))
    }
}

impl Render for GeneratorPanel {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let value = self
            .current
            .as_ref()
            .map(|g| g.value.expose().to_string())
            .unwrap_or_default();
        let bits = self.current.as_ref().map(|g| g.entropy_bits).unwrap_or(0.);
        let strength = match bits {
            b if b >= 100. => (tr!("отличный"), theme.success),
            b if b >= 70. => (tr!("надёжный"), theme.success),
            b if b >= 50. => (tr!("средний"), theme.warning),
            _ => (tr!("слабый"), theme.danger),
        };
        v_flex()
            .child(crate::ui::sheet_header(
                tr!("Генератор паролей"),
                Some(tr!("Случайный пароль или фраза из словаря EFF")),
                &theme,
            ))
            .child(
                crate::ui::sheet_body()
                    .child(h_flex().gap_1p5().flex_wrap().children(
                        presets().into_iter().enumerate().map(|(ix, name)| {
                            let active = self.preset_active(ix);
                            div()
                                .id(("preset", ix))
                                .px_2p5()
                                .py_1()
                                .rounded_md()
                                .border_1()
                                .text_xs()
                                .cursor_pointer()
                                .when(active, |d| {
                                    d.border_color(theme.ring)
                                        .bg(theme.list_active)
                                        .text_color(theme.foreground)
                                })
                                .when(!active, |d| {
                                    d.border_color(theme.border)
                                        .text_color(theme.muted_foreground)
                                        .hover(|d| {
                                            d.text_color(theme.foreground).bg(theme.secondary)
                                        })
                                })
                                .on_click(
                                    cx.listener(move |this, _, w, cx| this.apply_preset(ix, w, cx)),
                                )
                                .child(name)
                        }),
                    ))
                    .child(crate::ui::segmented(
                        "gen-mode",
                        vec![
                            (Some(IconName::Key), tr!("Пароль").into()),
                            (Some(IconName::StickyNote), tr!("Парольная фраза").into()),
                        ],
                        self.passphrase as usize,
                        cx,
                        |this, ix, _, cx| {
                            this.passphrase = ix == 1;
                            this.generate(cx);
                        },
                    ))
                    .child(
                        div()
                            .id("generated")
                            .p_3()
                            .rounded_lg()
                            .bg(theme.secondary)
                            .font_family(theme.mono_font_family.clone())
                            .text_base()
                            // высота постоянная: длинная фраза прокручивается, окно не прыгает
                            .h(px(108.))
                            .overflow_y_scroll()
                            .child(value),
                    )
                    .child(
                        h_flex()
                            .text_xs()
                            .gap_2()
                            .child(div().text_color(strength.1).child(strength.0))
                            .child(
                                div()
                                    .text_color(theme.muted_foreground)
                                    .child(tr!("{bits} бит энтропии", bits = format!("{bits:.0}"))),
                            ),
                    )
                    .when(!self.passphrase, |d| {
                        d.child(
                            v_flex()
                                .gap_2()
                                .child(
                                    div()
                                        .text_sm()
                                        .child(tr!("Длина: {n}", n = self.password.length)),
                                )
                                .child(Slider::new(&self.length)),
                        )
                        .child(
                            h_flex()
                                .gap_4()
                                .flex_wrap()
                                .child(self.switch(
                                    "upper",
                                    "A-Z",
                                    self.password.upper,
                                    cx,
                                    |t, v| t.password.upper = v,
                                ))
                                .child(self.switch(
                                    "lower",
                                    "a-z",
                                    self.password.lower,
                                    cx,
                                    |t, v| t.password.lower = v,
                                ))
                                .child(self.switch(
                                    "digits",
                                    "0-9",
                                    self.password.digits,
                                    cx,
                                    |t, v| t.password.digits = v,
                                ))
                                .child(self.switch(
                                    "symbols",
                                    "!@#",
                                    self.password.symbols,
                                    cx,
                                    |t, v| t.password.symbols = v,
                                ))
                                .child(self.switch(
                                    "ambiguous",
                                    tr!("без похожих (l1O0)"),
                                    self.password.exclude_ambiguous,
                                    cx,
                                    |t, v| t.password.exclude_ambiguous = v,
                                )),
                        )
                    })
                    .when(self.passphrase, |d| {
                        d.child(
                            v_flex()
                                .gap_2()
                                .child(
                                    div()
                                        .text_sm()
                                        .child(tr!("Слов: {n}", n = self.phrase.words)),
                                )
                                .child(Slider::new(&self.words)),
                        )
                        .child(
                            h_flex()
                                .gap_4()
                                .child(self.switch(
                                    "cap",
                                    tr!("С заглавной"),
                                    self.phrase.capitalize,
                                    cx,
                                    |t, v| t.phrase.capitalize = v,
                                ))
                                .child(self.switch(
                                    "num",
                                    tr!("Добавить цифру"),
                                    self.phrase.number,
                                    cx,
                                    |t, v| t.phrase.number = v,
                                )),
                        )
                    }),
            )
            .child(
                crate::ui::sheet_footer(&theme)
                    .child(
                        div()
                            .flex_1()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(self.status.clone().unwrap_or_else(|| {
                                tr!("Скопированное очистится из буфера само").into()
                            })),
                    )
                    .child(
                        Button::new("regen")
                            .icon(IconName::RotateCcwClock)
                            .label(tr!("Ещё вариант"))
                            .ghost()
                            .on_click(cx.listener(|this, _, _, cx| this.generate(cx))),
                    )
                    .child(
                        Button::new("copy")
                            .icon(IconName::Copy)
                            .label(tr!("Скопировать"))
                            .primary()
                            .on_click(cx.listener(|this, _, _, cx| this.copy(cx))),
                    ),
            )
    }
}
