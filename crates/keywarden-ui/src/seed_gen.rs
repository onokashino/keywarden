//! Новая сид-фраза BIP39: 12 или 24 слова, затем проверка «записали ли» по трём случайным словам.
//! Фраза уходит в редактор только после проверки.

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::secret::Secret;
use keywarden_core::tr;

pub enum SeedGenEvent {
    Done(Secret),
    Cancelled,
}

impl EventEmitter<SeedGenEvent> for SeedGen {}

enum Step {
    Choose,
    Show,
}

pub struct SeedGen {
    step: Step,
    words: Vec<String>,
    status: Option<SharedString>,
    error: Option<SharedString>,
    tasks: Vec<Task<()>>,
}

impl SeedGen {
    pub fn new() -> Self {
        Self {
            step: Step::Choose,
            words: vec![],
            status: None,
            error: None,
            tasks: vec![],
        }
    }

    fn generate(&mut self, n: usize, cx: &mut Context<Self>) {
        match keywarden_core::wallet::generate_bip39(n) {
            Ok(s) => {
                self.words = s.expose().split(' ').map(String::from).collect();
                self.step = Step::Show;
                self.error = None;
                self.status = None;
            }
            Err(e) => self.error = Some(e.into()),
        }
        cx.notify();
    }

    /// Скопировать через демон: буфер помечен для менеджеров истории и очистится сам.
    fn copy(&mut self, cx: &mut Context<Self>) {
        let value = Secret::new(self.words.join(" "));
        self.tasks.push(crate::client::call(
            cx,
            keywarden_core::ipc::Request::CopyText { value },
            |this, res, cx| {
                this.status = Some(match res {
                    Ok(_) => tr!("Скопировано, буфер очистится сам").into(),
                    Err(e) => e.message().into(),
                });
                cx.notify();
            },
        ));
    }
}

impl Drop for SeedGen {
    fn drop(&mut self) {
        // слова не держим в памяти дольше окна
        for w in self.words.iter_mut() {
            zeroize::Zeroize::zeroize(w);
        }
    }
}

/// Слова сеткой с номерами (три колонки сверху вниз), как на бумажной карточке.
pub fn word_grid(
    words: &[String],
    hidden: impl Fn(usize) -> bool,
    theme: &gpui_kit::component::Theme,
) -> Div {
    let rows = words.len().div_ceil(3).max(1);
    h_flex().gap_2().items_start().children((0..3).map(|col| {
        v_flex()
            .flex_1()
            .gap_1p5()
            .children((col * rows..((col + 1) * rows).min(words.len())).map(|i| {
                h_flex()
                    .h(px(34.))
                    .px_3()
                    .gap_2()
                    .rounded_md()
                    .bg(theme.secondary)
                    .child(
                        div()
                            .w(px(20.))
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(format!("{}.", i + 1)),
                    )
                    .child(
                        div()
                            .text_sm()
                            .font_family(theme.mono_font_family.clone())
                            .child(if hidden(i) {
                                "•••••".to_string()
                            } else {
                                words[i].clone()
                            }),
                    )
            }))
    }))
}

impl Render for SeedGen {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let (subtitle, body, footer): (&'static str, AnyElement, AnyElement) = match self.step {
            Step::Choose => (
                tr!("Из системного генератора случайных чисел, стандарт BIP39"),
                v_flex()
                    .gap_3()
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Сколько слов? 24 надёжнее, 12 удобнее записывать. Оба варианта понимают все кошельки.")),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                Button::new("gen12")
                                    .outline()
                                    .label(tr!("12 слов"))
                                    .on_click(cx.listener(|this, _, _, cx| this.generate(12, cx))),
                            )
                            .child(
                                Button::new("gen24")
                                    .primary()
                                    .label(tr!("24 слова"))
                                    .on_click(cx.listener(|this, _, _, cx| this.generate(24, cx))),
                            ),
                    )
                    .into_any_element(),
                h_flex()
                    .w_full()
                    .child(div().flex_1())
                    .child(
                        Button::new("cancel")
                            .outline()
                            .label(tr!("Отмена"))
                            .on_click(cx.listener(|_, _, _, cx| cx.emit(SeedGenEvent::Cancelled))),
                    )
                    .into_any_element(),
            ),
            Step::Show => (
                tr!("Фраза попадёт в запись и будет храниться в зашифрованной базе"),
                v_flex()
                    .gap_3()
                    .child(word_grid(&self.words, |_| false, &theme))
                    .into_any_element(),
                h_flex()
                    .w_full()
                    .gap_2()
                    .child(
                        Button::new("again")
                            .ghost()
                            .icon(IconName::RotateCcwClock)
                            .label(tr!("Другая фраза"))
                            .on_click(cx.listener(|this, _, _, cx| {
                                let n = this.words.len();
                                this.generate(n, cx)
                            })),
                    )
                    .when_some(self.status.clone(), |d, st| {
                        d.child(div().text_xs().text_color(theme.muted_foreground).child(st))
                    })
                    .child(div().flex_1())
                    .child(
                        Button::new("copy")
                            .outline()
                            .icon(IconName::Copy)
                            .label(tr!("Скопировать"))
                            .on_click(cx.listener(|this, _, _, cx| this.copy(cx))),
                    )
                    .child(
                        Button::new("use")
                            .primary()
                            .label(tr!("Вставить в запись"))
                            .on_click(cx.listener(|this, _, _, cx| {
                                cx.emit(SeedGenEvent::Done(Secret::new(this.words.join(" "))))
                            })),
                    )
                    .into_any_element(),
            ),
        };
        v_flex()
            .child(crate::ui::sheet_header(
                tr!("Новая сид-фраза"),
                Some(subtitle),
                &theme,
            ))
            .child(
                crate::ui::sheet_body()
                    .child(body)
                    .when_some(self.error.clone(), |d, e| {
                        d.child(div().text_sm().text_color(theme.danger_foreground).child(e))
                    }),
            )
            .child(crate::ui::sheet_footer(&theme).child(footer))
    }
}
