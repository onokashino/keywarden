//! Лаунчер: окно поверх всего (layer-shell), открывается горячей клавишей niri.
//!
//! - база заблокирована → первым появляется поле мастер-пароля;
//! - нечёткий поиск по названию, логину, адресу; живые коды 2FA с таймером в списке;
//! - Enter копирует пароль, Ctrl+U логин, Ctrl+T код 2FA, Esc закрывает.
//!
//! После копирования окно закрывается сразу: буфер обслуживает демон, а не этот процесс.

use crate::client::{self, CallError};
use crate::ui::{kbd_hint, kind_icon};
use gpui_kit::component::input::{Escape, Input, InputEvent, InputState, MoveDown, MoveUp};
use gpui_kit::component::{ActiveTheme as _, Icon, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use keywarden_core::ipc::{Event, Request, Response};
use keywarden_core::model::EntrySummary;
use keywarden_core::secret::Secret;
use keywarden_core::totp::Code;
use keywarden_core::tr;
use std::collections::HashMap;
use std::time::Duration;

actions!(
    launcher,
    [
        CopyUsername,
        CopyTotp,
        CopyPassword,
        SelectNext,
        SelectPrev,
        Close
    ]
);

const CONTEXT: &str = "Launcher";
const LIMIT: usize = 8;

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("ctrl-u", CopyUsername, Some(CONTEXT)),
        KeyBinding::new("ctrl-t", CopyTotp, Some(CONTEXT)),
        KeyBinding::new("escape", Close, Some(CONTEXT)),
        KeyBinding::new("ctrl-n", SelectNext, Some(CONTEXT)),
        KeyBinding::new("ctrl-j", SelectNext, Some(CONTEXT)),
        KeyBinding::new("ctrl-p", SelectPrev, Some(CONTEXT)),
        KeyBinding::new("ctrl-k", SelectPrev, Some(CONTEXT)),
    ]);
}

#[derive(PartialEq)]
enum Mode {
    Connecting,
    Locked,
    Unlocking,
    Ready,
}

pub struct Launcher {
    mode: Mode,
    query: Entity<InputState>,
    password: Entity<InputState>,
    results: Vec<EntrySummary>,
    /// база каждой найденной записи: None текущая, иначе имя профиля
    origin: Vec<Option<String>>,
    codes: HashMap<String, Code>,
    /// иконки сайтов (favicon) по UUID картинки
    icons: HashMap<String, std::sync::Arc<Image>>,
    icons_requested: std::collections::HashSet<String>,
    selected: usize,
    /// результатов из всех открытых баз бывает больше, чем видно: список прокручивается к выбранному
    scroll: ScrollHandle,
    error: Option<SharedString>,
    db_path: Option<SharedString>,
    /// PIN сейчас действует: разблокировка PIN-ом вместо мастер-пароля
    use_pin: bool,
    /// `--unlock ПРИЧИНА`: только разблокировать и закрыться (например, ключ просит ssh)
    unlock_only: Option<SharedString>,
    /// Enter на ключе SSH с хостом открывает терминал с ssh (настройка), своя команда терминала
    ssh_connect: bool,
    terminal: Vec<String>,
    pin: Entity<InputState>,
    search: Option<Task<()>>,
    tasks: Vec<Task<()>>,
    _subs: Vec<Subscription>,
}

impl Launcher {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self::with_reason(None, window, cx)
    }

    /// Окно разблокировки по запросу (SSH-агент): после разблокировки закрывается само.
    pub fn unlock_only(reason: String, window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self::with_reason(Some(reason.into()), window, cx)
    }

    fn with_reason(
        unlock_only: Option<SharedString>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let query = cx.new(|cx| InputState::new(window, cx).placeholder(tr!("Найти запись…")));
        let password = cx.new(|cx| {
            InputState::new(window, cx)
                .masked(true)
                .placeholder(tr!("Мастер-пароль"))
        });
        let pin = cx.new(|cx| InputState::new(window, cx).masked(true).placeholder("PIN"));
        let subs = vec![
            cx.subscribe_in(&pin, window, |this, _, ev, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.unlock(window, cx);
                }
            }),
            cx.subscribe_in(&query, window, |this, state, ev, _, cx| match ev {
                InputEvent::Change => {
                    let q = state.read(cx).value().to_string();
                    this.run_search(q, cx);
                }
                InputEvent::PressEnter { .. } => this.copy("password", cx),
                _ => {}
            }),
            cx.subscribe_in(&password, window, |this, _, ev, window, cx| {
                tracing::debug!(
                    enter = matches!(ev, InputEvent::PressEnter { .. }),
                    "событие поля пароля"
                );
                if let InputEvent::PressEnter { .. } = ev {
                    this.unlock(window, cx);
                }
            }),
        ];
        let mut this = Self {
            mode: Mode::Connecting,
            query,
            password,
            results: vec![],
            origin: vec![],
            scroll: ScrollHandle::new(),
            icons: HashMap::new(),
            icons_requested: Default::default(),
            codes: HashMap::new(),
            selected: 0,
            error: None,
            db_path: None,
            use_pin: false,
            unlock_only,
            ssh_connect: false,
            terminal: vec![],
            pin,
            search: None,
            tasks: vec![],
            _subs: subs,
        };
        this.tasks
            .push(client::call(cx, Request::Status, |this, res, cx| {
                match res {
                    Ok(Response::Status(s)) => {
                        this.db_path = s.path.or(s.default_path).map(Into::into);
                        this.use_pin = s.quick_unlock;
                        if s.locked {
                            this.mode = Mode::Locked;
                        } else if this.unlock_only.is_some() {
                            cx.quit();
                        } else {
                            this.mode = Mode::Ready;
                            this.run_search(String::new(), cx);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => this.error = Some(e.message().into()),
                }
                cx.notify();
            }));
        this.tasks.push(client::call(
            cx,
            Request::Prefs { set: None },
            |this, res, cx| {
                if let Ok(Response::Prefs { prefs }) = res {
                    this.ssh_connect = prefs.ssh_agent && prefs.ssh_connect;
                    this.terminal = prefs.terminal;
                    cx.notify();
                }
            },
        ));
        this.tasks.push(client::subscribe(cx, |this, ev, cx| {
            if ev == Event::Locked {
                this.mode = Mode::Locked;
                this.results.clear();
                this.refresh_pin(cx);
                cx.notify();
            }
        }));
        this.tasks.push(Self::ticker(cx));
        this
    }

    /// Фокус в нужное поле после того, как окно показано (и после смены режима).
    fn focus_input(&self, window: &mut Window, cx: &mut Context<Self>) {
        let target = if self.mode == Mode::Ready {
            &self.query
        } else if self.use_pin {
            &self.pin
        } else {
            &self.password
        };
        let handle = target.read(cx).focus_handle(cx);
        if !handle.is_focused(window) {
            window.focus(&handle, cx);
        }
    }

    /// Действует ли PIN (после блокировки и после неверной попытки).
    fn refresh_pin(&mut self, cx: &mut Context<Self>) {
        self.tasks
            .push(client::call(cx, Request::Status, |this, res, cx| {
                if let Ok(Response::Status(s)) = res {
                    this.use_pin = s.quick_unlock;
                }
                cx.notify();
            }));
    }

    fn unlock(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.use_pin {
            let pin = Secret::new(self.pin.read(cx).value().to_string());
            self.pin.update(cx, |s, cx| s.set_value("", window, cx));
            self.mode = Mode::Unlocking;
            self.error = None;
            cx.notify();
            self.tasks.push(client::call(
                cx,
                Request::QuickUnlock { pin },
                |this, res, cx| {
                    match res {
                        Ok(_) if this.unlock_only.is_some() => cx.quit(),
                        Ok(_) => {
                            this.mode = Mode::Ready;
                            let q = this.query.read(cx).value().to_string();
                            this.run_search(q, cx);
                        }
                        Err(e) => {
                            this.mode = Mode::Locked;
                            this.error = Some(e.message().into());
                            this.refresh_pin(cx);
                        }
                    }
                    cx.notify();
                },
            ));
            return;
        }
        tracing::debug!(
            len = self.password.read(cx).value().len(),
            "разблокировка из лаунчера"
        );
        let pw = Secret::new(self.password.read(cx).value().to_string());
        self.password
            .update(cx, |s, cx| s.set_value("", window, cx));
        self.mode = Mode::Unlocking;
        self.error = None;
        cx.notify();
        self.tasks.push(client::call(
            cx,
            Request::Unlock {
                path: None,
                password: Some(pw),
                keyfile: None,
                yubikey: None,
            },
            |this, res, cx| {
                match res {
                    Ok(_) if this.unlock_only.is_some() => cx.quit(),
                    Ok(_) => {
                        this.mode = Mode::Ready;
                        let q = this.query.read(cx).value().to_string();
                        this.run_search(q, cx);
                    }
                    Err(e) => {
                        this.mode = Mode::Locked;
                        this.error = Some(e.message().into());
                    }
                }
                cx.notify();
            },
        ));
    }

    fn run_search(&mut self, query: String, cx: &mut Context<Self>) {
        if self.mode != Mode::Ready {
            return;
        }
        // старый запрос отменяется вместе с задачей
        self.search = Some(cx.spawn(async move |this, cx| {
            let found = cx
                .background_spawn(async move {
                    let req = Request::Search {
                        query,
                        limit: LIMIT,
                        filter: Default::default(),
                    };
                    let main = client::blocking(&req);
                    // остальные открытые базы: заблокированные и незапущенные пропускаются
                    let current =
                        keywarden_core::ipc::profile().unwrap_or_else(|| "default".into());
                    let mut more = vec![];
                    for p in keywarden_core::ipc::profiles() {
                        if p == current {
                            continue;
                        }
                        let name = (p != "default").then_some(p.as_str());
                        if let Ok(Response::Entries { entries }) = client::blocking_on(name, &req) {
                            more.extend(entries.into_iter().map(|e| (e, Some(p.clone()))));
                        }
                    }
                    (main, more)
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                let (main, more) = found;
                match main {
                    Ok(Response::Entries { entries }) => {
                        if this.results.is_empty() && !entries.is_empty() {
                            tracing::debug!("лаунчер готов");
                        }
                        this.origin = vec![None; entries.len()];
                        this.results = entries;
                        for (e, p) in more.into_iter().take(LIMIT) {
                            this.results.push(e);
                            this.origin.push(p);
                        }
                        this.selected = 0;
                        this.scroll.scroll_to_item(0);
                        this.error = None;
                        this.refresh_codes(cx);
                        this.load_icons(cx);
                    }
                    Ok(_) => {}
                    Err(CallError::Locked) => this.mode = Mode::Locked,
                    Err(e) => this.error = Some(e.message().into()),
                }
                cx.notify();
            });
        }));
    }

    fn refresh_codes(&mut self, cx: &mut Context<Self>) {
        let wanted: Vec<(String, Option<String>)> = self
            .results
            .iter()
            .zip(self.origin.iter())
            .filter(|(e, _)| e.has_otp)
            .filter(|(e, _)| !self.codes.get(&e.id).is_some_and(|c| c.remaining > 1))
            .map(|(e, o)| (e.id.clone(), o.clone()))
            .collect();
        for (id, origin) in wanted {
            self.tasks.push(client::call_on(
                cx,
                origin,
                Request::Totp { id: id.clone() },
                move |this, res, cx| {
                    if let Ok(Response::Totp { code }) = res {
                        this.codes.insert(id, code);
                        cx.notify();
                    }
                },
            ));
        }
    }

    fn load_icons(&mut self, cx: &mut Context<Self>) {
        let wanted: Vec<(String, Option<String>)> = self
            .results
            .iter()
            .zip(self.origin.iter())
            .filter_map(|(e, o)| Some((e.icon.clone()?, o.clone())))
            .filter(|(u, _)| !self.icons_requested.contains(u))
            .collect();
        for (uuid, origin) in wanted {
            self.icons_requested.insert(uuid.clone());
            let key = uuid.clone();
            self.tasks.push(client::call_on(
                cx,
                origin,
                Request::IconData { uuid },
                move |this, res, cx| {
                    if let Ok(Response::IconData { data }) = res
                        && let Ok(bytes) = data_encoding::BASE64.decode(data.as_bytes())
                    {
                        this.icons.insert(
                            key,
                            std::sync::Arc::new(Image::from_bytes(ImageFormat::Png, bytes)),
                        );
                        cx.notify();
                    }
                },
            ));
        }
    }

    /// Раз в секунду: обратный отсчёт кодов, новые коды на границе периода.
    fn ticker(cx: &mut Context<Self>) -> Task<()> {
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                let alive = this.update(cx, |this, cx| {
                    this.tasks.retain(|t| !t.is_ready());
                    for c in this.codes.values_mut() {
                        c.remaining = c.remaining.saturating_sub(1);
                    }
                    if this.mode == Mode::Ready {
                        this.refresh_codes(cx);
                    }
                    cx.notify();
                });
                if alive.is_err() {
                    return;
                }
            }
        })
    }

    /// Аргументы ssh, если Enter на этой записи должен подключаться к серверу.
    fn connect_args(&self, e: &EntrySummary) -> Option<Vec<String>> {
        (self.ssh_connect && e.kind == keywarden_core::model::EntryKind::SshKey)
            .then(|| keywarden_core::ssh_setup::ssh_args(&e.url))
            .flatten()
    }

    fn copy(&mut self, field: &'static str, cx: &mut Context<Self>) {
        let Some(entry) = self.results.get(self.selected) else {
            return;
        };
        // режим автоввода (kw autotype): Enter печатает запись в окно, из которого вызвали
        if field == "password" && std::env::args().any(|a| a == "--autotype") {
            let origin = self.origin.get(self.selected).cloned().flatten();
            let req = Request::AutoType {
                id: Some(entry.id.clone()),
                window: None,
                sequence: None,
            };
            match keywarden_core::ipc::send_to(origin.as_deref(), &req) {
                Ok(()) => cx.quit(),
                Err(e) => {
                    self.error = Some(tr!("автоввод: {e}", e = e).into());
                    cx.notify();
                }
            }
            return;
        }
        // ключ SSH с хостом: Enter открывает терминал с ssh
        if field == "password"
            && let Some(args) = self.connect_args(entry)
        {
            match keywarden_core::ssh_setup::terminal_command(&args, &self.terminal) {
                Some(mut c) => match c.spawn() {
                    Ok(_) => cx.quit(),
                    Err(e) => {
                        self.error = Some(tr!("Терминал не запустился: {e}", e = e).into());
                        cx.notify();
                    }
                },
                None => {
                    self.error = Some(
                        tr!("Терминал не найден: задайте terminal в config.toml, например [\"kitty\", \"-e\"]")
                            .into(),
                    );
                    cx.notify();
                }
            }
            return;
        }
        if field == "totp" && !entry.has_otp {
            self.error = Some(tr!("У «{title}» нет 2FA", title = entry.title).into());
            cx.notify();
            return;
        }
        let id = entry.id.clone();
        let origin = self.origin.get(self.selected).cloned().flatten();
        // кошелёк: Enter копирует первый адрес для получения (фраза в лаунчер не попадает)
        if entry.kind == keywarden_core::model::EntryKind::CryptoWallet {
            self.tasks.push(client::call_on(
                cx,
                origin.clone(),
                Request::Get { id, reveal: false },
                move |this, res, cx| {
                    let addr = match res {
                        Ok(Response::Entry { entry }) => entry
                            .fields
                            .iter()
                            .find(|f| f.name == keywarden_core::wallet::ADDRESSES)
                            .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
                            .and_then(|t| {
                                keywarden_core::wallet::parse_addresses(&t)
                                    .into_iter()
                                    .next()
                                    .map(|a| a.1)
                            }),
                        _ => None,
                    };
                    match addr {
                        Some(a) => this.tasks.push(client::call_on(
                            cx,
                            origin,
                            Request::CopyText { value: a.into() },
                            |this, res, cx| match res {
                                Ok(_) => cx.quit(),
                                Err(e) => {
                                    this.error = Some(e.message().into());
                                    cx.notify();
                                }
                            },
                        )),
                        None => {
                            this.error = Some(tr!("У кошелька нет сохранённых адресов").into());
                            cx.notify();
                        }
                    }
                },
            ));
            return;
        }
        self.tasks.push(client::call_on(
            cx,
            origin,
            Request::Copy {
                id,
                field: field.into(),
            },
            |this, res, cx| match res {
                Ok(_) => cx.quit(),
                Err(e) => {
                    this.error = Some(e.message().into());
                    cx.notify();
                }
            },
        ));
    }

    fn select(&mut self, delta: isize, cx: &mut Context<Self>) {
        if self.results.is_empty() {
            return;
        }
        let n = self.results.len() as isize;
        self.selected = ((self.selected as isize + delta).rem_euclid(n)) as usize;
        self.scroll.scroll_to_item(self.selected);
        cx.notify();
    }

    fn render_row(&self, ix: usize, e: &EntrySummary, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let selected = ix == self.selected;
        let origin = self.origin.get(ix).cloned().flatten();
        let subtitle = [
            origin.as_deref().unwrap_or_default(),
            e.username.as_str(),
            host(&e.url).as_str(),
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("  ·  ");
        let code = self.codes.get(&e.id).cloned();
        h_flex()
            .id(("row", ix))
            .px_3()
            .py_2()
            .gap_3()
            .rounded_lg()
            .when(selected, |d| d.bg(theme.list_active))
            .when(!selected, |d| d.hover(|d| d.bg(theme.secondary)))
            .cursor_pointer()
            .on_click(cx.listener(move |this, _, _, cx| {
                this.selected = ix;
                this.copy("password", cx);
            }))
            .child(crate::brands::tile(
                e,
                32.,
                kind_icon(e.kind),
                e.icon.as_ref().and_then(|u| self.icons.get(u)).cloned(),
                theme,
            ))
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::MEDIUM)
                            .truncate()
                            .child(e.title.clone()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .truncate()
                            .child(subtitle),
                    ),
            )
            .when(!e.group.is_empty(), |d| {
                d.child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(e.group.clone()),
                )
            })
            .when(selected && code.is_none(), |d| {
                d.child(
                    div()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(kbd_hint(
                            "enter",
                            if self.connect_args(e).is_some() {
                                tr!("подключиться")
                            } else if e.kind == keywarden_core::model::EntryKind::CryptoWallet {
                                tr!("адрес")
                            } else {
                                tr!("пароль")
                            },
                        )),
                )
            })
            .when_some(code, |d, c| {
                let urgent = c.remaining <= 5;
                d.child(
                    h_flex()
                        .gap_2()
                        .child(
                            div()
                                .font_family(theme.mono_font_family.clone())
                                .text_sm()
                                .text_color(if urgent {
                                    theme.danger
                                } else {
                                    theme.foreground
                                })
                                .child(spaced(&c.code)),
                        )
                        .child(countdown(c.remaining, c.period, urgent, cx)),
                )
            })
    }
}

impl Render for Launcher {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        self.focus_input(window, cx);
        let theme = cx.theme().clone();
        window.set_rem_size(theme.font_size); // обычно это делает Root, которого у лаунчера нет
        let ready = self.mode == Mode::Ready;

        let header = h_flex()
            .px_4()
            .py_3()
            .gap_3()
            .child(
                Icon::new(if ready {
                    gpui_kit_assets::IconName::Search
                } else {
                    gpui_kit_assets::IconName::Lock
                })
                .text_color(theme.muted_foreground),
            )
            .child(div().flex_1().text_lg().child(if ready {
                Input::new(&self.query).appearance(false).into_any_element()
            } else {
                Input::new(if self.use_pin {
                    &self.pin
                } else {
                    &self.password
                })
                .appearance(false)
                .mask_toggle()
                .into_any_element()
            }));

        let body = match self.mode {
            Mode::Ready if self.results.is_empty() => centered(
                &theme,
                if self.query.read(cx).value().is_empty() {
                    tr!("В базе пока нет записей")
                } else {
                    tr!("Ничего не найдено")
                },
            ),
            Mode::Ready => {
                let rows: Vec<_> = self
                    .results
                    .clone()
                    .iter()
                    .enumerate()
                    .map(|(i, e)| self.render_row(i, e, cx).into_any_element())
                    .collect();
                v_flex()
                    .id("results")
                    .size_full()
                    .overflow_y_scroll()
                    .track_scroll(&self.scroll)
                    .p_2()
                    .gap_0p5()
                    .children(rows)
                    .into_any_element()
            }
            Mode::Connecting => centered(&theme, tr!("Подключаюсь к keywardend…")),
            Mode::Unlocking => v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_3()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(gpui_kit::component::spinner::Spinner::new())
                .child(tr!("Расшифровка…"))
                .into_any_element(),
            Mode::Locked => v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_3()
                .child(crate::ui::icon_tile(
                    gpui_kit_assets::IconName::LockKeyhole,
                    52.,
                    &theme,
                ))
                .child(
                    div()
                        .text_base()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(tr!("Хранилище заблокировано")),
                )
                .when_some(self.unlock_only.clone(), |d, reason| {
                    d.child(div().max_w(px(520.)).text_center().text_sm().child(reason))
                })
                .child(div().text_sm().text_color(theme.muted_foreground).child(
                    match &self.db_path {
                        // только имя файла: полный путь здесь ничего не говорит
                        Some(p) => {
                            let file = std::path::Path::new(p.as_ref())
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_else(|| p.to_string());
                            if self.use_pin {
                                tr!("{file}: введите PIN и нажмите Enter", file = file)
                            } else {
                                tr!("{file}: введите мастер-пароль и нажмите Enter", file = file)
                            }
                        }
                        None => tr!("Введите мастер-пароль и нажмите Enter").into(),
                    },
                ))
                .with_animation(
                    "locked-in",
                    Animation::new(Duration::from_millis(220)).with_easing(ease_out_quint()),
                    |el, t| el.opacity(t).mt(px(8. * (1. - t))),
                )
                .into_any_element(),
        };

        let footer = h_flex()
            .px_4()
            .py_2()
            .gap_4()
            .border_t_1()
            .border_color(theme.border)
            .text_xs()
            .text_color(theme.muted_foreground)
            .when_some(self.error.clone(), |d, e| {
                d.child(div().flex_1().text_color(theme.danger).truncate().child(e))
            })
            .when(self.error.is_none(), |d| d.child(div().flex_1()))
            .when(ready, |d| {
                d.child(kbd_hint("enter", tr!("пароль")))
                    .child(kbd_hint("ctrl-u", tr!("логин")))
                    .child(kbd_hint("ctrl-t", "2FA"))
            })
            .when(!ready, |d| d.child(kbd_hint("enter", tr!("открыть"))))
            .child(kbd_hint("escape", tr!("закрыть")));

        div()
            .id("launcher")
            .key_context(CONTEXT)
            .size_full()
            .p_3()
            .font_family(theme.font_family.clone())
            .capture_action(cx.listener(|this, _: &MoveUp, _, cx| this.select(-1, cx)))
            .capture_action(cx.listener(|this, _: &MoveDown, _, cx| this.select(1, cx)))
            .on_action(cx.listener(|this, _: &SelectPrev, _, cx| this.select(-1, cx)))
            .on_action(cx.listener(|this, _: &SelectNext, _, cx| this.select(1, cx)))
            .on_action(cx.listener(|this, _: &CopyUsername, _, cx| this.copy("username", cx)))
            .on_action(cx.listener(|this, _: &CopyTotp, _, cx| this.copy("totp", cx)))
            .on_action(cx.listener(|this, _: &CopyPassword, _, cx| this.copy("password", cx)))
            .on_action(cx.listener(|_, _: &Close, _, cx| cx.quit()))
            .on_action(cx.listener(|_, _: &Escape, _, cx| cx.quit()))
            .child(
                v_flex()
                    .size_full()
                    .bg(theme.background)
                    .text_color(theme.foreground)
                    .border_1()
                    .border_color(theme.border)
                    .rounded_xl()
                    .shadow_lg()
                    .overflow_hidden()
                    .child(header)
                    .child(div().h_px().bg(theme.border))
                    .child(div().flex_1().min_h_0().overflow_hidden().child(body))
                    .child(footer),
            )
    }
}

fn centered(theme: &gpui_kit::component::Theme, text: &'static str) -> AnyElement {
    v_flex()
        .size_full()
        .items_center()
        .justify_center()
        .text_sm()
        .text_color(theme.muted_foreground)
        .child(text)
        .into_any_element()
}

/// Кольцо с остатком времени кода.
fn countdown(remaining: u64, period: u64, urgent: bool, cx: &App) -> impl IntoElement {
    let theme = cx.theme();
    let frac = remaining as f32 / period.max(1) as f32;
    div().w_8().h_1().rounded_full().bg(theme.secondary).child(
        div()
            .h_full()
            .rounded_full()
            .w(relative(frac))
            .bg(if urgent { theme.danger } else { theme.primary }),
    )
}

/// "123456" → "123 456"
fn spaced(code: &str) -> String {
    if code.len() == 6 || code.len() == 8 {
        let (a, b) = code.split_at(code.len() / 2);
        format!("{a} {b}")
    } else {
        code.to_string()
    }
}

fn host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

pub fn window_options(cx: &App) -> WindowOptions {
    // 8 строк результатов (LIMIT) + поиск и подсказки
    crate::ui::overlay_options("keywarden-launcher", 720., 600., cx)
}
