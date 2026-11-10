//! Окно «Перенести в базу»: ключи из ~/.ssh или серверы из ~/.ssh/config. Галочки у каждого,
//! внизу настройки переноса (удалить файлы с диска, включить «Серверы в ssh»).

use crate::client;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::switch::Switch;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, Sizable as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::ipc::{ConfigHostPreview, LocalSshKey, Request, Response};
use keywarden_core::tr;

pub enum MigrateEvent {
    /// перенос сделан: сообщение и включить ли «Серверы в ssh»
    Done { message: String, enable_hosts: bool },
}

impl EventEmitter<MigrateEvent> for SshMigrate {}

pub enum Source {
    Keys(Vec<LocalSshKey>),
    Hosts(Vec<ConfigHostPreview>),
}

struct Item {
    id: String,
    title: SharedString,
    subtitle: SharedString,
    /// (текст, «хорошо» или нет)
    badges: Vec<(SharedString, bool)>,
    /// почему нельзя выбрать
    blocked: Option<SharedString>,
}

pub struct SshMigrate {
    source: Source,
    items: Vec<Item>,
    checked: Vec<bool>,
    /// ключи: удалить файлы; серверы: включить «Серверы в ssh»
    option: bool,
    /// «Серверы в ssh» уже включены: переключатель не нужен
    hosts_on: bool,
    busy: bool,
    error: Option<SharedString>,
    focus: FocusHandle,
    tasks: Vec<Task<()>>,
}

impl SshMigrate {
    pub fn new(source: Source, hosts_on: bool, cx: &mut Context<Self>) -> Self {
        let items: Vec<Item> = match &source {
            Source::Keys(keys) => keys
                .iter()
                .filter(|k| !k.in_vault)
                .map(|k| Item {
                    id: k.path.clone(),
                    title: crate::ui::tilde(&k.path).into(),
                    subtitle: k.comment.clone().into(),
                    badges: vec![(k.algorithm.clone().into(), true)],
                    blocked: k
                        .encrypted
                        .then(|| tr!("с паролем: добавьте через «Новый ключ SSH»").into()),
                })
                .collect(),
            Source::Hosts(hosts) => hosts
                .iter()
                .map(|h| Item {
                    id: h.alias.clone(),
                    title: h.alias.clone().into(),
                    subtitle: h.address.clone().into(),
                    badges: {
                        let mut b = vec![(h.folder.clone().into(), true)];
                        match (&h.key, &h.identity) {
                            (Some(k), _) => b.push((tr!("ключ «{k}»", k = k).into(), true)),
                            (None, Some(_)) => b.push((tr!("ключ с диска").into(), false)),
                            (None, None) => {}
                        }
                        b
                    },
                    blocked: h.in_vault.then(|| tr!("уже в базе").into()),
                })
                .collect(),
        };
        let checked = items.iter().map(|i| i.blocked.is_none()).collect();
        Self {
            option: matches!(source, Source::Hosts(_)) && !hosts_on,
            source,
            items,
            checked,
            hosts_on,
            busy: false,
            error: None,
            focus: cx.focus_handle(),
            tasks: vec![],
        }
    }

    pub fn focus(&self, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus, cx);
    }

    fn selected(&self) -> Vec<String> {
        self.items
            .iter()
            .zip(&self.checked)
            .filter(|(i, c)| **c && i.blocked.is_none())
            .map(|(i, _)| i.id.clone())
            .collect()
    }

    fn set_all(&mut self, on: bool, cx: &mut Context<Self>) {
        for (c, i) in self.checked.iter_mut().zip(&self.items) {
            *c = on && i.blocked.is_none();
        }
        cx.notify();
    }

    fn run(&mut self, cx: &mut Context<Self>) {
        let picked = self.selected();
        if picked.is_empty() || self.busy {
            return;
        }
        self.busy = true;
        self.error = None;
        let option = self.option;
        let want = picked.clone();
        let req = match self.source {
            Source::Keys(_) => Request::SshMigrate {
                paths: picked.clone(),
                delete: option,
            },
            Source::Hosts(_) => Request::SshImportConfig { only: Some(picked) },
        };
        self.tasks.push(client::call(cx, req, move |this, res, cx| {
            this.busy = false;
            let message = match res {
                Ok(Response::SshLocalKeys { keys }) => {
                    let n = keys
                        .iter()
                        .filter(|k| k.in_vault && want.contains(&k.path))
                        .count();
                    if option {
                        tr!("Перенесено в базу: {n}, приватные файлы удалены", n = n)
                    } else {
                        tr!("Перенесено в базу: {n}", n = n)
                    }
                }
                Ok(Response::SshImported { added, .. }) => {
                    tr!("Серверов перенесено в базу: {n}", n = added)
                }
                Ok(_) => tr!("Готово").to_string(),
                Err(e) => {
                    this.error = Some(e.message().into());
                    cx.notify();
                    return;
                }
            };
            let enable_hosts = option && matches!(this.source, Source::Hosts(_));
            cx.emit(MigrateEvent::Done {
                message,
                enable_hosts,
            });
        }));
        cx.notify();
    }
}

impl Render for SshMigrate {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        use crate::ui::{sheet_body, sheet_footer, sheet_header};
        let theme = cx.theme().clone();
        let keys = matches!(self.source, Source::Keys(_));
        let n = self.selected().len();
        let total = self.items.iter().filter(|i| i.blocked.is_none()).count();
        let (title, subtitle) = if keys {
            (
                tr!("Перенести ключи в базу"),
                tr!("Ключи будут защищены мастер-паролем и заработают через SSH-агент Keywarden"),
            )
        } else {
            (
                tr!("Перенести серверы в базу"),
                tr!(
                    "Каждый Host станет записью «Сервер SSH» и поедет с базой на другие компьютеры"
                ),
            )
        };
        let rows = self.items.iter().enumerate().map(|(ix, it)| {
            let on = self.checked[ix] && it.blocked.is_none();
            let blocked = it.blocked.is_some();
            h_flex()
                .id(("migrate-row", ix))
                .gap_3()
                .px_3()
                .py_2()
                .rounded_md()
                .when(!blocked, |d| {
                    d.cursor_pointer()
                        .hover(|s| s.bg(theme.list_hover))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.checked[ix] = !this.checked[ix];
                            cx.notify();
                        }))
                })
                .when(blocked, |d| d.opacity(0.55))
                .child(
                    Checkbox::new(("migrate-check", ix))
                        .checked(on)
                        .disabled(blocked)
                        .on_click(cx.listener(move |this, v: &bool, _, cx| {
                            this.checked[ix] = *v;
                            cx.notify();
                        })),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .child(
                            div()
                                .text_sm()
                                .truncate()
                                .when(keys, |d| d.font_family(theme.mono_font_family.clone()))
                                .when(!keys, |d| d.font_weight(FontWeight::MEDIUM))
                                .child(it.title.clone()),
                        )
                        .child(
                            div()
                                .text_xs()
                                .truncate()
                                .text_color(theme.muted_foreground)
                                .child(it.blocked.clone().unwrap_or(it.subtitle.clone())),
                        ),
                )
                .children(it.badges.iter().map(|(t, good)| {
                    crate::ui::badge(
                        t.clone(),
                        if *good {
                            theme.muted_foreground
                        } else {
                            theme.warning_foreground
                        },
                    )
                }))
        });
        let (opt_label, opt_hint) = if keys {
            (
                tr!("Удалить приватные файлы с диска"),
                tr!("Файлы .pub останутся. Удаляется только то, что точно сохранилось в базе"),
            )
        } else {
            (
                tr!("Включить «Серверы в ssh»"),
                tr!(
                    "ssh, scp и git сразу увидят перенесённые серверы. Сам ~/.ssh/config не меняется"
                ),
            )
        };
        let show_option = keys || !self.hosts_on;
        v_flex()
            .track_focus(&self.focus)
            .on_key_down(cx.listener(|this, ev: &KeyDownEvent, _, cx| {
                let k = &ev.keystroke;
                if k.modifiers.control && k.key == "enter" {
                    this.run(cx);
                    cx.stop_propagation();
                }
            }))
            .child(sheet_header(title, Some(subtitle), &theme))
            .child(
                sheet_body()
                    .child(
                        h_flex()
                            .gap_2()
                            .child(
                                div()
                                    .flex_1()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(tr!("Выбрано {n} из {total}", n = n, total = total)),
                            )
                            .child(
                                Button::new("migrate-all")
                                    .ghost()
                                    .xsmall()
                                    .label(tr!("Все"))
                                    .on_click(cx.listener(|this, _, _, cx| this.set_all(true, cx))),
                            )
                            .child(
                                Button::new("migrate-none")
                                    .ghost()
                                    .xsmall()
                                    .label(tr!("Ничего"))
                                    .on_click(
                                        cx.listener(|this, _, _, cx| this.set_all(false, cx)),
                                    ),
                            ),
                    )
                    .child(
                        div()
                            .id("migrate-list")
                            .max_h(px(340.))
                            .overflow_y_scroll()
                            .rounded_lg()
                            .border_1()
                            .border_color(theme.border)
                            .p_1()
                            .child(v_flex().gap_0p5().children(rows)),
                    )
                    .when(show_option, |d| {
                        d.child(
                            v_flex()
                                .gap_1()
                                .child(
                                    Switch::new("migrate-option")
                                        .checked(self.option)
                                        .label(opt_label)
                                        .on_change(cx.listener(|this, v: &bool, _, cx| {
                                            this.option = *v;
                                            cx.notify();
                                        })),
                                )
                                .child(
                                    div()
                                        .pl(px(44.))
                                        .text_xs()
                                        .text_color(theme.muted_foreground)
                                        .child(opt_hint),
                                ),
                        )
                    }),
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
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child("Ctrl+Enter"),
                    })
                    .child(
                        Button::new("migrate-cancel")
                            .ghost()
                            .label(tr!("Отмена"))
                            .on_click(|_, w, cx| w.close_dialog(cx)),
                    )
                    .child(
                        Button::new("migrate-run")
                            .primary()
                            .icon(IconName::Import)
                            .label(tr!("Перенести: {n}", n = n))
                            .loading(self.busy)
                            .disabled(self.busy || n == 0)
                            .on_click(cx.listener(|this, _, _, cx| this.run(cx))),
                    ),
            )
    }
}
