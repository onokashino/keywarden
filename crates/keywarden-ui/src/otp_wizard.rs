//! Мастер 2FA, как «Добавить сервис» в 2FAS: вставить секрет или ссылку, распознать QR из буфера
//! обмена (скриншот области) или с картинки, сразу увидеть живой код и сохранить: в новую запись
//! или в выбранную.

use crate::client::{self, CallError};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, Sizable as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::ipc::{Request, Response};
use keywarden_core::model::{EntryKind, EntryPatch, FieldSet};
use keywarden_core::secret::Secret;
use keywarden_core::totp::Code;
use keywarden_core::tr;
use std::time::Duration;

pub enum WizardEvent {
    /// сохранено; id записи
    Saved(String),
}

impl EventEmitter<WizardEvent> for OtpWizard {}

pub struct OtpWizard {
    /// запись, которой задаём 2FA; `None`: создать новую
    target: Option<String>,
    issuer: Entity<InputState>,
    account: Entity<InputState>,
    secret: Entity<InputState>,
    preview: Option<(Secret, Code)>,
    error: Option<SharedString>,
    busy: bool,
    preview_task: Option<Task<()>>,
    tasks: Vec<Task<()>>,
    _subs: Vec<Subscription>,
}

impl OtpWizard {
    pub fn new(
        target: Option<(String, String, String)>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let (id, title, user) = match target {
            Some((id, t, u)) => (Some(id), t, u),
            None => (None, String::new(), String::new()),
        };
        let issuer = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("Сервис, например GitHub"))
                .default_value(title)
        });
        let account = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("Аккаунт (необязательно)"))
                .default_value(user)
        });
        let secret = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("Секрет (JBSW Y3DP …) или ссылка otpauth://"))
                .masked(true)
        });
        let subs = [&issuer, &account, &secret]
            .into_iter()
            .map(|i| {
                cx.subscribe_in(i, window, |this, _, ev: &InputEvent, _, cx| {
                    if let InputEvent::Change = ev {
                        this.schedule_preview(cx);
                    }
                })
            })
            .collect();
        Self {
            target: id,
            issuer,
            account,
            secret,
            preview: None,
            error: None,
            busy: false,
            preview_task: None,
            tasks: vec![],
            _subs: subs,
        }
    }

    /// Фокус в поле секрета; вызывать после открытия диалога (он забирает фокус себе).
    pub fn focus(&self, window: &mut Window, cx: &mut Context<Self>) {
        let h = self.secret.read(cx).focus_handle(cx);
        window.focus(&h, cx);
    }

    fn val(&self, i: &Entity<InputState>, cx: &App) -> String {
        i.read(cx).value().trim().to_string()
    }

    fn schedule_preview(&mut self, cx: &mut Context<Self>) {
        let input = self.secret.read(cx).value().to_string();
        let (issuer, account) = (self.val(&self.issuer, cx), self.val(&self.account, cx));
        if input.trim().is_empty() {
            self.preview = None;
            self.error = None;
            cx.notify();
            return;
        }
        self.preview_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(120))
                .await;
            let req = Request::OtpPreview {
                input: Secret::new(input),
                issuer,
                account,
            };
            let res = cx
                .background_spawn(async move { client::blocking(&req) })
                .await;
            let _ = this.update(cx, |this, cx| {
                match res {
                    Ok(Response::OtpPreview { uri, code }) => {
                        this.preview = Some((uri, code));
                        this.error = None;
                    }
                    Err(e) => {
                        this.preview = None;
                        this.error = Some(e.message().into());
                    }
                    _ => {}
                }
                cx.notify();
            });
        }));
    }

    /// Текст из QR или буфера: ссылка otpauth:// заполняет и название с аккаунтом.
    fn apply_scanned(&mut self, text: Secret, window: &mut Window, cx: &mut Context<Self>) {
        let t = text.expose().trim().to_string();
        if let Ok(url) = url::Url::parse(&t)
            && url.scheme() == "otpauth"
        {
            let raw = url.path().trim_start_matches('/');
            let label = percent_decode(raw).unwrap_or_else(|| raw.to_string());
            let (mut issuer, account) = match label.split_once(':') {
                Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
                None => (String::new(), label.trim().to_string()),
            };
            if let Some((_, v)) = url.query_pairs().find(|(k, _)| k == "issuer") {
                issuer = v.into_owned();
            }
            if self.val(&self.issuer, cx).is_empty() && !issuer.is_empty() {
                self.issuer
                    .update(cx, |i, cx| i.set_value(issuer, window, cx));
            }
            if self.val(&self.account, cx).is_empty() && !account.is_empty() {
                self.account
                    .update(cx, |i, cx| i.set_value(account, window, cx));
            }
        }
        self.secret.update(cx, |i, cx| i.set_value(t, window, cx));
        self.schedule_preview(cx);
    }

    fn scan(&mut self, path: Option<String>, window: &mut Window, cx: &mut Context<Self>) {
        self.busy = true;
        self.error = None;
        cx.notify();
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::OtpScan { path },
            |this, res, window, cx| {
                this.busy = false;
                match res {
                    Ok(Response::OtpScanned { text }) => this.apply_scanned(text, window, cx),
                    Err(e) => this.error = Some(e.message().into()),
                    _ => {}
                }
                cx.notify();
            },
        ));
    }

    fn pick_image(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(tr!("Картинка с QR-кодом").into()),
        });
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(mut v))) = rx.await
                && !v.is_empty()
            {
                let p = v.remove(0).display().to_string();
                let _ = this.update_in(cx, |this, window, cx| this.scan(Some(p), window, cx));
            }
        }));
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let Some((uri, _)) = self.preview.clone() else {
            self.error = Some(tr!("Сначала вставьте секрет или QR-код").into());
            cx.notify();
            return;
        };
        let req = match &self.target {
            Some(id) => Request::SetOtp {
                id: id.clone(),
                value: uri,
            },
            None => {
                let title = self.val(&self.issuer, cx);
                if title.is_empty() {
                    self.error = Some(tr!("Укажите название сервиса").into());
                    cx.notify();
                    return;
                }
                Request::Add {
                    patch: EntryPatch {
                        kind: Some(EntryKind::Login),
                        set: vec![
                            FieldSet::new("Title", title),
                            FieldSet::new("UserName", self.val(&self.account, cx)),
                            FieldSet {
                                name: "otp".into(),
                                value: uri,
                                protected: Some(true),
                            },
                        ],
                        ..Default::default()
                    },
                }
            }
        };
        self.busy = true;
        cx.notify();
        let known = self.target.clone();
        self.tasks.push(client::call(cx, req, move |this, res, cx| {
            this.busy = false;
            match res {
                Ok(Response::Created { id }) => cx.emit(WizardEvent::Saved(id)),
                Ok(_) => cx.emit(WizardEvent::Saved(known.unwrap_or_default())),
                Err(CallError::Locked) => this.error = Some(tr!("База заблокирована").into()),
                Err(e) => this.error = Some(e.message().into()),
            }
            cx.notify();
        }));
    }
}

/// "%D0%AF%40x" -> "Я@x"; None, если после распаковки не UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%' && i + 2 < b.len())
            .then(|| std::str::from_utf8(&b[i + 1..i + 3]).ok())
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

impl Render for OtpWizard {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        use crate::ui::{field_label, sheet_body, sheet_footer, sheet_header};
        let theme = cx.theme().clone();
        let preview = match &self.preview {
            Some((_, c)) => {
                let (a, b) = c.code.split_at(c.code.len() / 2);
                h_flex()
                    .gap_3()
                    .child(Icon::new(IconName::CircleCheck).text_color(theme.success_foreground))
                    .child(
                        div()
                            .flex_1()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Сверьте с сайтом, если он просит подтвердить")),
                    )
                    .child(
                        div()
                            .text_2xl()
                            .font_weight(FontWeight::SEMIBOLD)
                            .font_family(theme.mono_font_family.clone())
                            .child(format!("{a} {b}")),
                    )
                    .into_any_element()
            }
            None => div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(tr!("Код появится, когда секрет распознается"))
                .into_any_element(),
        };
        v_flex()
            .child(sheet_header(
                tr!("Добавить 2FA"),
                Some(tr!("Секрет или QR-код со страницы, где включаете двухфакторную защиту")),
                &theme,
            ))
            .child(
                sheet_body()
                    .child(
                        v_flex()
                            .gap_1p5()
                            .child(field_label(tr!("Источник"), &theme))
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        Button::new("from-clipboard")
                                            .outline()
                                            .icon(IconName::Copy)
                                            .label(tr!("Из буфера: QR или текст"))
                                            .loading(self.busy)
                                            .on_click(
                                                cx.listener(|this, _, w, cx| {
                                                    this.scan(None, w, cx)
                                                }),
                                            ),
                                    )
                                    .child(
                                        Button::new("from-image")
                                            .outline()
                                            .icon(IconName::Image)
                                            .label(tr!("Картинка с QR…"))
                                            .on_click(
                                                cx.listener(|this, _, w, cx| {
                                                    this.pick_image(w, cx)
                                                }),
                                            ),
                                    ),
                            )
                            .child(div().text_xs().text_color(theme.muted_foreground).child(
                                if cfg!(windows) {
                                    tr!("QR на экране: Win+Shift+S, выделите код, затем «Из буфера»")
                                } else if cfg!(target_os = "macos") {
                                    tr!("QR на экране: Cmd+Ctrl+Shift+4, выделите код, затем «Из буфера»")
                                } else {
                                    tr!("QR на экране: скриншот области в буфер, затем «Из буфера»")
                                },
                            )),
                    )
                    .child(
                        v_flex()
                            .gap_1p5()
                            .child(field_label(tr!("Секрет или ссылка otpauth://"), &theme))
                            .child(Input::new(&self.secret).mask_toggle()),
                    )
                    .child(
                        h_flex()
                            .gap_3()
                            .child(
                                v_flex()
                                    .flex_1()
                                    .gap_1p5()
                                    .child(field_label(tr!("Сервис"), &theme))
                                    .child(
                                        Input::new(&self.issuer).disabled(self.target.is_some()),
                                    ),
                            )
                            .child(
                                v_flex()
                                    .flex_1()
                                    .gap_1p5()
                                    .child(field_label(tr!("Аккаунт"), &theme))
                                    .child(Input::new(&self.account)),
                            ),
                    )
                    .child(
                        // постоянная высота: окно не прыгает, когда появляется код
                        h_flex()
                            .h(px(64.))
                            .px_4()
                            .rounded_lg()
                            .border_1()
                            .border_color(if self.preview.is_some() {
                                theme.success.opacity(0.4)
                            } else {
                                theme.border
                            })
                            .when(self.preview.is_none(), |d| d.border_dashed())
                            .bg(theme.list_even)
                            .child(preview),
                    ),
            )
            .child(
                sheet_footer(&theme)
                    .child(match self.error.clone() {
                        Some(e) => h_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_2()
                            .text_xs()
                            .text_color(theme.danger_foreground)
                            .child(Icon::new(IconName::CircleAlert).small())
                            .child(div().truncate().child(e)),
                        None => h_flex()
                            .flex_1()
                            .gap_3()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(crate::ui::kbd_hint("escape", tr!("закрыть"))),
                    })
                    .child(
                        Button::new("cancel-otp")
                            .ghost()
                            .label(tr!("Отмена"))
                            .on_click(|_, w, cx| w.close_dialog(cx)),
                    )
                    .child(
                        Button::new("save-otp")
                            .primary()
                            .label(if self.target.is_some() {
                                tr!("Добавить в запись")
                            } else {
                                tr!("Создать запись")
                            })
                            .disabled(self.preview.is_none())
                            .loading(self.busy)
                            .on_click(cx.listener(|this, _, _, cx| this.save(cx))),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn percent_decode_label() {
        assert_eq!(
            super::percent_decode("GitHub:octo%40x.com").as_deref(),
            Some("GitHub:octo@x.com")
        );
        assert_eq!(super::percent_decode("%D0%AF").as_deref(), Some("Я"));
        assert_eq!(super::percent_decode("100%").as_deref(), Some("100%"));
    }
}
