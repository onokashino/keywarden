//! Новый ключ SSH, две вкладки: «Создать» (Ed25519, ECDSA P-256, RSA 4096) и «Добавить
//! существующий» (ключ из ~/.ssh одним щелчком, файл или вставленный текст). Ключ живёт в базе
//! и работает через SSH-агент Keywarden; хост задаёт, к какому серверу он подставляется.

use crate::client::{self, CallError};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputState, Textarea, TextareaState};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Icon, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::ipc::{LocalSshKey, Request, Response};
use keywarden_core::secret::Secret;
use keywarden_core::tr;
use std::path::PathBuf;

pub enum SshNewEvent {
    /// запись создана; id
    Saved(String),
}

impl EventEmitter<SshNewEvent> for SshNew {}

/// Алгоритмы вкладки «Создать»: имя для демона и подпись.
const ALGORITHMS: [(&str, &str); 3] = [
    ("ed25519", "Ed25519"),
    ("ecdsa", "ECDSA P-256"),
    ("rsa", "RSA 4096"),
];

pub struct SshNew {
    group: Option<String>,
    /// вкладка «Добавить существующий»
    adding: bool,
    algorithm: usize,
    title: Entity<InputState>,
    host: Entity<InputState>,
    passphrase: Entity<InputState>,
    /// вставленный текст ключа
    paste: Entity<TextareaState>,
    confirm: bool,
    /// выбранный файл ключа (из ~/.ssh или через окно выбора)
    file: Option<PathBuf>,
    /// ключи в ~/.ssh, которых ещё нет в базе (None: ещё ищем)
    found: Option<Vec<LocalSshKey>>,
    error: Option<SharedString>,
    busy: bool,
    tasks: Vec<Task<()>>,
}

impl SshNew {
    pub fn new(group: Option<String>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut this = Self {
            group,
            adding: false,
            algorithm: 0,
            title: cx.new(|cx| {
                InputState::new(window, cx).placeholder(tr!("Например, GitHub или рабочий сервер"))
            }),
            host: cx.new(|cx| {
                InputState::new(window, cx).placeholder("github.com, git@host, ssh://host:22")
            }),
            passphrase: cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(tr!("Пароль ключа"))
                    .masked(true)
            }),
            paste: cx.new(|cx| {
                TextareaState::new(window, cx)
                    .auto_grow(3, 8)
                    .placeholder("-----BEGIN OPENSSH PRIVATE KEY-----")
            }),
            confirm: false,
            file: None,
            found: None,
            error: None,
            busy: false,
            tasks: vec![],
        };
        this.tasks
            .push(client::call(cx, Request::SshLocalKeys, |this, res, cx| {
                this.found = Some(match res {
                    Ok(Response::SshLocalKeys { keys }) => {
                        keys.into_iter().filter(|k| !k.in_vault).collect()
                    }
                    _ => vec![],
                });
                cx.notify();
            }));
        this
    }

    pub fn focus(&self, window: &mut Window, cx: &mut Context<Self>) {
        let h = self.title.read(cx).focus_handle(cx);
        window.focus(&h, cx);
    }

    fn val(&self, i: &Entity<InputState>, cx: &App) -> String {
        i.read(cx).value().trim().to_string()
    }

    fn pick_file(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(tr!("Файл приватного ключа OpenSSH").into()),
        });
        let this = cx.entity();
        window
            .spawn(cx, async move |cx| {
                if let Ok(Ok(Some(mut v))) = rx.await
                    && !v.is_empty()
                {
                    let path = v.remove(0);
                    let _ = cx.update(|window, cx| {
                        this.update(cx, |this, cx| this.set_file(path, None, window, cx))
                    });
                }
            })
            .detach();
    }

    /// Выбран файл: название записи по умолчанию из комментария ключа или имени файла.
    fn set_file(
        &mut self,
        path: PathBuf,
        comment: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.val(&self.title, cx).is_empty() {
            let name = comment.filter(|c| !c.is_empty()).unwrap_or_else(|| {
                path.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            });
            self.title.update(cx, |i, cx| i.set_value(name, window, cx));
        }
        self.file = Some(path);
        self.error = None;
        cx.notify();
    }

    /// Текст ключа для «Добавить»: выбранный файл или вставка.
    fn key_text(&self, cx: &App) -> Result<Option<(Vec<u8>, String)>, String> {
        if let Some(path) = &self.file {
            let data =
                std::fs::read(path).map_err(|e| tr!("Не удалось прочитать файл: {e}", e = e))?;
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "id_key".into());
            return Ok(Some((data, name)));
        }
        let text = self.paste.read(cx).value().trim().to_string();
        Ok((!text.is_empty()).then(|| (format!("{text}\n").into_bytes(), "id_key".into())))
    }

    fn encrypted(&self, cx: &App) -> bool {
        self.adding
            && self
                .key_text(cx)
                .ok()
                .flatten()
                .is_some_and(|(d, _)| is_encrypted(&String::from_utf8_lossy(&d)))
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let title = self.val(&self.title, cx);
        if title.is_empty() {
            self.error = Some(tr!("Введите название").into());
            return cx.notify();
        }
        let host = Some(self.val(&self.host, cx)).filter(|h| !h.is_empty());
        let req = if !self.adding {
            Request::SshGenerate {
                title,
                comment: None,
                host,
                group: self.group.clone(),
                confirm: self.confirm,
                algorithm: Some(ALGORITHMS[self.algorithm].0.into()),
            }
        } else {
            let (data, file_name) = match self.key_text(cx) {
                Ok(Some(k)) => k,
                Ok(None) => {
                    self.error = Some(tr!("Выберите ключ, файл или вставьте текст ключа").into());
                    return cx.notify();
                }
                Err(e) => {
                    self.error = Some(e.into());
                    return cx.notify();
                }
            };
            let encrypted = is_encrypted(&String::from_utf8_lossy(&data));
            Request::SshImport {
                title,
                key: data_encoding::BASE64.encode(&data),
                file_name,
                passphrase: encrypted
                    .then(|| Secret::new(self.passphrase.read(cx).value().to_string())),
                group: self.group.clone(),
                confirm: self.confirm,
                host,
            }
        };
        self.busy = true;
        self.error = None;
        cx.notify();
        self.tasks.push(client::call(cx, req, |this, res, cx| {
            this.busy = false;
            match res {
                Ok(Response::Created { id }) => cx.emit(SshNewEvent::Saved(id)),
                Ok(_) => {}
                Err(CallError::Locked) => this.error = Some(tr!("База заблокирована").into()),
                Err(e) => this.error = Some(e.message().into()),
            }
            cx.notify();
        }));
    }
}

/// Ключ OpenSSH зашифрован: в двоичном заголовке имя шифра не «none».
fn is_encrypted(pem: &str) -> bool {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .concat();
    data_encoding::BASE64
        .decode(b64.as_bytes())
        .ok()
        .and_then(|raw| {
            // "openssh-key-v1\0" + u32 длина + имя шифра
            let rest = raw.get(15..)?;
            let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
            Some(rest.get(4..4 + len)? != b"none")
        })
        .unwrap_or(false)
}

impl SshNew {
    /// Вкладка «Создать»: выбор алгоритма и подсказка, какой брать.
    fn create_tab(&self, theme: &gpui_kit::component::Theme, cx: &mut Context<Self>) -> Div {
        let hint = match self.algorithm {
            0 => tr!("Рекомендуется: короткий, быстрый, его понимают все современные серверы"),
            1 => tr!("Для систем, где требуют ключи NIST"),
            _ => tr!("Для старых серверов и устройств без Ed25519"),
        };
        let items = ALGORITHMS
            .iter()
            .map(|(_, label)| (None, label.to_string()))
            .collect();
        v_flex()
            .gap_1p5()
            .child(crate::ui::field_label(tr!("Алгоритм"), theme))
            .child(crate::ui::segmented(
                "ssh-alg",
                items,
                self.algorithm,
                cx,
                |this, ix, _, cx| {
                    this.algorithm = ix;
                    cx.notify();
                },
            ))
            .child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(hint),
            )
    }

    /// Вкладка «Добавить существующий»: найденные ключи, файл, вставка, пароль ключа.
    fn add_tab(&self, theme: &gpui_kit::component::Theme, cx: &mut Context<Self>) -> Div {
        let chosen = self.file.clone();
        let found: Vec<AnyElement> = self
            .found
            .iter()
            .flatten()
            .enumerate()
            .map(|(ix, k)| {
                let path = PathBuf::from(&k.path);
                let active = chosen.as_ref() == Some(&path);
                let comment = Some(k.comment.clone());
                h_flex()
                    .id(("ssh-found", ix))
                    .gap_2()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .border_1()
                    .cursor_pointer()
                    .border_color(if active { theme.primary } else { theme.border })
                    .when(active, |d| d.bg(theme.primary.opacity(0.08)))
                    .hover(|d| d.bg(theme.secondary))
                    .child(
                        Icon::new(IconName::KeyRound)
                            .small()
                            .text_color(theme.muted_foreground),
                    )
                    .child(div().text_sm().child(crate::ui::tilde(&k.path)))
                    .child(crate::ui::badge(
                        k.algorithm.clone(),
                        theme.muted_foreground,
                    ))
                    .when(k.encrypted, |d| {
                        d.child(crate::ui::badge(tr!("с паролем"), theme.warning_foreground))
                    })
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(k.comment.clone()),
                    )
                    .on_click(cx.listener(move |this, _, w, cx| {
                        this.set_file(path.clone(), comment.clone(), w, cx)
                    }))
                    .into_any_element()
            })
            .collect();
        let picked_elsewhere = chosen.filter(|p| {
            !self
                .found
                .iter()
                .flatten()
                .any(|k| std::path::Path::new(&k.path) == p.as_path())
        });
        v_flex()
            .gap_3()
            .child(
                v_flex()
                    .gap_1p5()
                    .child(crate::ui::field_label(tr!("Найдено в ~/.ssh"), theme))
                    .map(|d| match &self.found {
                        None => d.child(
                            div()
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(tr!("Ищу ключи в ~/.ssh…")),
                        ),
                        Some(v) if v.is_empty() => d.child(
                            div()
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(tr!("Новых ключей нет: всё уже в базе или ~/.ssh пуст")),
                        ),
                        Some(_) => d.children(found),
                    }),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        Button::new("ssh-pick")
                            .outline()
                            .small()
                            .icon(IconName::FolderOpen)
                            .label(tr!("Выбрать файл…"))
                            .on_click(cx.listener(|this, _, w, cx| this.pick_file(w, cx))),
                    )
                    .when_some(picked_elsewhere, |d, p| {
                        d.child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_sm()
                                .child(crate::ui::tilde(&p.display().to_string())),
                        )
                        .child(
                            Button::new("ssh-file-clear")
                                .ghost()
                                .small()
                                .label(tr!("Убрать"))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.file = None;
                                    cx.notify();
                                })),
                        )
                    }),
            )
            .when(self.file.is_none(), |d| {
                d.child(
                    v_flex()
                        .gap_1p5()
                        .child(crate::ui::field_label(
                            tr!("Или вставьте приватный ключ"),
                            theme,
                        ))
                        .child(Textarea::new(&self.paste)),
                )
            })
            .when(self.encrypted(cx), |d| {
                d.child(
                    v_flex()
                        .gap_1p5()
                        .child(crate::ui::field_label(tr!("Пароль ключа"), theme))
                        .child(Input::new(&self.passphrase).mask_toggle()),
                )
            })
    }
}

impl SshNew {
    /// Клавиатура: Alt+1/Alt+2 вкладки, Alt+↑/↓ алгоритм или найденный ключ, Ctrl+Enter сохранить.
    fn on_key(&mut self, ev: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        let m = &ev.keystroke.modifiers;
        let key = ev.keystroke.key.as_str();
        if m.control && key == "enter" {
            return self.save(cx);
        }
        if !m.alt {
            return;
        }
        match key {
            "1" | "2" => {
                self.adding = key == "2";
                self.error = None;
            }
            "up" | "down" => {
                let step = if key == "down" { 1 } else { -1 };
                if !self.adding {
                    self.algorithm = (self.algorithm as isize + step)
                        .rem_euclid(ALGORITHMS.len() as isize)
                        as usize;
                } else if let Some(found) = self.found.clone().filter(|f| !f.is_empty()) {
                    let cur = self.file.as_ref().and_then(|p| {
                        found
                            .iter()
                            .position(|k| std::path::Path::new(&k.path) == p.as_path())
                    });
                    let next = match cur {
                        Some(i) => (i as isize + step).rem_euclid(found.len() as isize) as usize,
                        None => 0,
                    };
                    let k = &found[next];
                    return self.set_file(
                        PathBuf::from(&k.path),
                        Some(k.comment.clone()),
                        window,
                        cx,
                    );
                }
            }
            _ => return,
        }
        cx.stop_propagation();
        cx.notify();
    }
}

impl Render for SshNew {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        use crate::ui::{field_label, segmented, sheet_body, sheet_footer, sheet_header};
        let theme = cx.theme().clone();
        let tabs = vec![
            (Some(IconName::KeyRound), tr!("Создать").to_string()),
            (
                Some(IconName::Import),
                tr!("Добавить существующий").to_string(),
            ),
        ];
        v_flex()
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, w, cx| this.on_key(ev, w, cx)))
            .child(sheet_header(
                tr!("Новый ключ SSH"),
                Some(tr!("Ключ хранится в базе и работает через SSH-агент Keywarden: на диск он не попадает")),
                &theme,
            ))
            .child(
                sheet_body()
                    .child(segmented("ssh-mode", tabs, self.adding as usize, cx, |this, ix, _, cx| {
                        this.adding = ix == 1;
                        this.error = None;
                        cx.notify();
                    }))
                    .map(|d| {
                        if self.adding {
                            d.child(self.add_tab(&theme, cx))
                        } else {
                            d.child(self.create_tab(&theme, cx))
                        }
                    })
                    .child(
                        v_flex()
                            .gap_1p5()
                            .child(field_label(tr!("Название"), &theme))
                            .child(Input::new(&self.title)),
                    )
                    .child(
                        v_flex()
                            .gap_1p5()
                            .child(field_label(tr!("Хост, необязательно"), &theme))
                            .child(Input::new(&self.host))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(tr!("С «Ключом по хосту» ssh сразу возьмёт этот ключ для этих серверов")),
                            ),
                    )
                    .child(
                        Switch::new("ssh-new-confirm")
                            .checked(self.confirm)
                            .label(tr!("Спрашивать перед каждым использованием ключа"))
                            .on_change(cx.listener(|this, v: &bool, _, cx| {
                                this.confirm = *v;
                                cx.notify();
                            })),
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
                        None => h_flex().flex_1(),
                    })
                    .child(
                        Button::new("ssh-save")
                            .primary()
                            .icon(if self.adding { IconName::Import } else { IconName::KeyRound })
                            .label(if self.adding {
                                tr!("Добавить ключ")
                            } else {
                                tr!("Создать ключ")
                            })
                            .loading(self.busy)
                            .disabled(self.busy)
                            .on_click(cx.listener(|this, _, _, cx| this.save(cx))),
                    ),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::is_encrypted;

    #[test]
    fn detects_encrypted_key() {
        // заголовок незашифрованного ключа: openssh-key-v1\0, шифр "none"
        let mut raw = b"openssh-key-v1\0".to_vec();
        raw.extend_from_slice(&4u32.to_be_bytes());
        raw.extend_from_slice(b"none");
        let plain = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            data_encoding::BASE64.encode(&raw)
        );
        assert!(!is_encrypted(&plain));
        let mut raw = b"openssh-key-v1\0".to_vec();
        raw.extend_from_slice(&10u32.to_be_bytes());
        raw.extend_from_slice(b"aes256-ctr");
        let enc = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            data_encoding::BASE64.encode(&raw)
        );
        assert!(is_encrypted(&enc));
    }
}
