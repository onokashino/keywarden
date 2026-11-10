//! Страница «Настройки хранилища»: общие параметры, безопасность (смена ключа, шифрование)
//! и перенос (экспорт, копия, импорт, слияние). Всё делает демон; страница только собирает ввод.

use crate::client::{self, CallError};
use crate::ui::segmented;
use gpui_kit::component::button::{Button, ButtonVariants as _, DropdownButton};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, Sizable as _, WindowExt as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::ipc::{
    BackupInfo, ImportFormat, KeySpec, Prefs, Request, Response, SyncFolder, SyncHeld, SyncRecord,
};
use keywarden_core::secret::Secret;
use keywarden_core::settings::DbSettings;
use keywarden_core::tr;
use keywarden_core::vault::Cipher;
use std::path::PathBuf;

actions!(
    keywarden_settings,
    [
        TabGeneral,
        TabSecurity,
        TabTransfer,
        TabKeyring,
        TabDevice,
        TabSsh,
        TabSync
    ]
);

const CONTEXT: &str = "KeywardenSettings";

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("alt-1", TabGeneral, Some(CONTEXT)),
        KeyBinding::new("alt-2", TabSecurity, Some(CONTEXT)),
        KeyBinding::new("alt-3", TabTransfer, Some(CONTEXT)),
        KeyBinding::new("alt-4", TabKeyring, Some(CONTEXT)),
        KeyBinding::new("alt-5", TabDevice, Some(CONTEXT)),
        KeyBinding::new("alt-6", TabSsh, Some(CONTEXT)),
        KeyBinding::new("alt-7", TabSync, Some(CONTEXT)),
    ]);
}

pub enum SettingsEvent {
    /// база изменилась (импорт, слияние): обновить списки
    Changed,
}

impl EventEmitter<SettingsEvent> for SettingsPage {}

pub struct SettingsPage {
    focus: FocusHandle,
    tab: usize,
    /// SSH-агент для всех программ: состояние спрашивается у системы, поэтому кешируется
    ssh_setup: Option<keywarden_core::ssh_setup::Status>,
    /// запуск демона при входе в систему (читается из системы, а не из настроек)
    autostart: Option<bool>,
    /// приватные ключи в ~/.ssh (None: ещё не спрашивали) и «удалить после переноса»
    ssh_local: Option<Vec<keywarden_core::ipc::LocalSshKey>>,
    ssh_local_loading: bool,
    /// что перенесётся из ~/.ssh/config (None: ещё не спрашивали)
    ssh_config_hosts: Option<Vec<keywarden_core::ipc::ConfigHostPreview>>,
    ssh_config_loading: bool,
    ssh_migrate_sub: Option<Subscription>,
    /// сообщение вместо «Сохранено» после ближайшего сохранения настроек
    saved_note: Option<String>,
    settings: Option<DbSettings>,
    /// связка ключей: включено, кто держит имя, это мы, папка
    keyring: Option<(bool, Option<String>, bool, String)>,
    // общие
    name: Entity<InputState>,
    description: Entity<InputState>,
    history_items: Entity<InputState>,
    history_mib: Entity<InputState>,
    recycle_bin: bool,
    // шифрование
    cipher: Cipher,
    kdf_iter: Entity<InputState>,
    kdf_mem: Entity<InputState>,
    kdf_par: Entity<InputState>,
    // смена ключа
    cur_pw: Entity<InputState>,
    new_pw: Entity<InputState>,
    new_pw2: Entity<InputState>,
    new_keyfile: Entity<InputState>,
    new_yubikey: Entity<InputState>,
    cur_keyfile: Option<String>,
    cur_yubikey: Option<String>,
    // перенос
    copy_pw: Entity<InputState>,
    other_pw: Entity<InputState>,
    other_path: Option<PathBuf>,
    // этот компьютер
    prefs: Option<Prefs>,
    autolock: Entity<InputState>,
    clip_secs: Entity<InputState>,
    backups_keep: Entity<InputState>,
    pin_hours: Entity<InputState>,
    pin_new: Entity<InputState>,
    pin_master: Entity<InputState>,
    backups: Vec<BackupInfo>,
    /// копия, для которой показан вопрос «точно восстановить?»
    confirm_restore: Option<String>,
    /// обозреватели блоков: сеть и поле шаблона ссылки
    explorers: Vec<(String, Entity<InputState>)>,
    // синхронизация
    sync_records: Vec<SyncRecord>,
    sync_held: Option<SyncHeld>,
    sync_path: Option<String>,
    sync_folder: Option<SyncFolder>,
    /// строка журнала, для которой показан вопрос «точно отменить?»
    confirm_revert: Option<u64>,
    // состояние
    busy: Option<&'static str>,
    message: Option<(SharedString, bool)>,
    tasks: Vec<Task<()>>,
}

fn field(
    window: &mut Window,
    cx: &mut Context<SettingsPage>,
    placeholder: &'static str,
    masked: bool,
) -> Entity<InputState> {
    cx.new(|cx| {
        InputState::new(window, cx)
            .placeholder(placeholder)
            .masked(masked)
    })
}

impl SettingsPage {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let mut this = Self {
            focus: cx.focus_handle(),
            tab: 0,
            settings: None,
            keyring: None,
            name: field(window, cx, tr!("Например, Личное"), false),
            description: field(window, cx, tr!("Необязательно"), false),
            history_items: field(window, cx, "10", false),
            history_mib: field(window, cx, "6", false),
            recycle_bin: true,
            cipher: Cipher::Aes256,
            kdf_iter: field(window, cx, "", false),
            kdf_mem: field(window, cx, "", false),
            kdf_par: field(window, cx, "", false),
            cur_pw: field(window, cx, tr!("Текущий мастер-пароль"), true),
            new_pw: field(window, cx, tr!("Новый мастер-пароль"), true),
            new_pw2: field(window, cx, tr!("Ещё раз"), true),
            new_keyfile: field(window, cx, tr!("Путь к файлу-ключу (необязательно)"), false),
            new_yubikey: field(
                window,
                cx,
                tr!("Слот YubiKey, например 2 (необязательно)"),
                false,
            ),
            cur_keyfile: None,
            cur_yubikey: None,
            copy_pw: field(window, cx, tr!("Пароль копии"), true),
            other_pw: field(window, cx, tr!("Пароль той базы"), true),
            other_path: None,
            prefs: None,
            autolock: field(window, cx, "15", false),
            clip_secs: field(window, cx, "30", false),
            backups_keep: field(window, cx, "10", false),
            pin_hours: field(window, cx, "24", false),
            pin_new: field(window, cx, tr!("Новый PIN, от 4 символов"), true),
            pin_master: field(window, cx, tr!("Мастер-пароль для подтверждения"), true),
            backups: vec![],
            confirm_restore: None,
            ssh_setup: None,
            autostart: None,
            ssh_local: None,
            ssh_local_loading: false,
            ssh_config_hosts: None,
            ssh_config_loading: false,
            ssh_migrate_sub: None,
            saved_note: None,
            explorers: vec![],
            sync_records: vec![],
            sync_held: None,
            sync_path: None,
            sync_folder: None,
            confirm_revert: None,
            busy: None,
            message: None,
            tasks: vec![],
        };
        this.reload(window, cx);
        this
    }

    pub fn reload(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.set_keyring(None, cx);
        self.load_prefs(None, window, cx);
        self.load_backups(cx);
        self.load_sync(cx);
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::GetSettings,
            |this, res, window, cx| {
                if let Ok(Response::Settings { settings }) = res {
                    this.fill(settings, window, cx);
                }
                cx.notify();
            },
        ));
        self.tasks
            .push(client::call(cx, Request::Status, |this, res, cx| {
                if let Ok(Response::Status(s)) = res {
                    this.cur_keyfile = s.keyfile;
                    this.cur_yubikey = s.yubikey;
                }
                cx.notify();
            }));
    }

    fn fill(&mut self, s: DbSettings, window: &mut Window, cx: &mut Context<Self>) {
        let set =
            |i: &Entity<InputState>, v: String, window: &mut Window, cx: &mut Context<Self>| {
                i.update(cx, |i, cx| i.set_value(v, window, cx))
            };
        set(&self.name, s.name.clone(), window, cx);
        set(&self.description, s.description.clone(), window, cx);
        set(
            &self.history_items,
            s.history_max_items.to_string(),
            window,
            cx,
        );
        set(
            &self.history_mib,
            s.history_max_size_mib.to_string(),
            window,
            cx,
        );
        set(&self.kdf_iter, s.kdf_iterations.to_string(), window, cx);
        set(&self.kdf_mem, s.kdf_memory_mib.to_string(), window, cx);
        set(&self.kdf_par, s.kdf_parallelism.to_string(), window, cx);
        self.recycle_bin = s.recycle_bin;
        self.cipher = s.cipher;
        self.settings = Some(s);
    }

    /// Фокус внутрь страницы, чтобы работали её клавиши (Alt+1/2/3).
    pub fn focus(&self, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus, cx);
    }

    /// При смене вкладки поле с фокусом исчезает: фокус возвращается на страницу,
    /// иначе её клавиши перестают работать.
    fn set_keyring(&mut self, enable: Option<bool>, cx: &mut Context<Self>) {
        self.tasks.push(client::call(
            cx,
            Request::SecretService { enable },
            move |this, res, cx| {
                match res {
                    Ok(Response::SecretService {
                        enabled,
                        owner,
                        active,
                        group,
                    }) => {
                        this.keyring = Some((enabled, owner, active, group));
                        if let Some(on) = enable {
                            this.say(
                                if on {
                                    tr!("Включено. Вступит в силу после перезапуска: systemctl --user restart keywardend")
                                } else {
                                    tr!("Выключено. Вступит в силу после перезапуска keywardend")
                                },
                                false,
                                cx,
                            );
                        }
                    }
                    Err(e) => this.say(e.message(), true, cx),
                    _ => {}
                }
                cx.notify();
            },
        ));
    }

    fn migrate_keyring(&mut self, cx: &mut Context<Self>) {
        self.busy = Some(tr!("Переношу секреты из текущей связки ключей…"));
        cx.notify();
        self.tasks.push(client::call(
            cx,
            Request::SecretsMigrate,
            |this, res, cx| match res {
                Ok(Response::SecretsMigrated { items, skipped }) => {
                    cx.emit(SettingsEvent::Changed);
                    this.say(
                        tr!(
                            "Перенесено секретов: {items}, пропущено: {skipped}",
                            items = items,
                            skipped = skipped
                        ),
                        false,
                        cx,
                    )
                }
                Err(e) => this.say(e.message(), true, cx),
                _ => this.say(tr!("Готово"), false, cx),
            },
        ));
    }

    fn keyring_tab(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let Some((enabled, owner, active, group)) = self.keyring.clone() else {
            return div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(tr!("Загружаю…"))
                .into_any_element();
        };
        let busy = self.busy.is_some();
        panel(&theme)
            .child(section(
                tr!("Связка ключей (Secret Service)"),
                tr!("Сюда браузеры, git, NetworkManager и другие программы кладут свои пароли. Keywarden может заменить gnome-keyring: секреты будут в базе и синхронизируются вместе с ней"),
                &theme,
            ))
            .child(
                card(&theme)
                    .child(row(
                        tr!("Сейчас обслуживает"),
                        h_flex()
                            .gap_2()
                            .text_sm()
                            .child(owner.clone().unwrap_or_else(|| tr!("никто").into()))
                            .when(active, |d| {
                                d.child(gpui_kit::component::tag::Tag::success().xsmall().child("Keywarden"))
                            }),
                        &theme,
                    ))
                    .child(row(
                        tr!("Keywarden как связка"),
                        Switch::new("keyring")
                            .checked(enabled)
                            .label(if enabled { tr!("Включено") } else { tr!("Выключено") })
                            .on_change(cx.listener(|this, v: &bool, _, cx| this.set_keyring(Some(*v), cx))),
                        &theme,
                    ))
                    .child(row(
                        tr!("Папка в базе"),
                        div().text_sm().child(group.clone()),
                        &theme,
                    )),
            )
            .when(enabled && !active, |d| {
                d.child(
                    h_flex()
                        .gap_2()
                        .mx_4()
                        .mb_3()
                        .px_3()
                        .py_2()
                        .rounded_lg()
                        .border_1()
                        .border_color(theme.warning.opacity(0.35))
                        .bg(theme.warning.opacity(0.08))
                        .text_sm()
                        .child(Icon::new(IconName::TriangleAlert).small().text_color(theme.warning_foreground))
                        .child(div().flex_1().child(
                            tr!("Имя занято другой программой. Перенесите секреты кнопкой ниже, отключите у gnome-keyring компонент secrets и перезапустите keywardend"),
                        )),
                )
            })
            .child(
                footer(&theme)
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Связка (например gnome-keyring) может спросить свой пароль. Секреты появятся в папке базы, повторный перенос их обновит")),
                    )
                    .child(
                        Button::new("migrate-keyring")
                            .outline()
                            .icon(IconName::Import)
                            .label(tr!("Перенести из текущей связки"))
                            .disabled(active || owner.is_none())
                            .loading(busy)
                            .on_click(cx.listener(|this, _, _, cx| this.migrate_keyring(cx))),
                    ),
            )
            .into_any_element()
    }

    fn set_tab(&mut self, tab: usize, window: &mut Window, cx: &mut Context<Self>) {
        if !visible_tabs().contains(&tab) {
            return;
        }
        window.focus(&self.focus, cx);
        self.tab = tab;
        self.message = None;
        if tab == 6 {
            self.load_sync(cx);
        }
        cx.notify();
    }

    /// Язык интерфейса: хранится на этом компьютере, окна переключаются сразу.
    fn language_panel(
        &mut self,
        theme: &gpui_kit::component::Theme,
        cx: &mut Context<Self>,
    ) -> Div {
        use keywarden_core::i18n;
        let langs = i18n::languages();
        let saved = i18n::saved();
        let pick =
            |code: Option<&'static str>, this: &mut Self, cx: &mut Context<Self>| match i18n::save(
                code,
            ) {
                Ok(()) => {
                    this.message = None;
                    cx.refresh_windows();
                }
                Err(e) => this.say(tr!("Не удалось сохранить язык: {e}", e = e), true, cx),
            };
        // немного языков: переключатель, как у остальных настроек; много: выпадающий список
        let control = if langs.len() <= 3 {
            let mut items = vec![(None, tr!("Как в системе").to_string())];
            items.extend(langs.iter().map(|(_, n)| (None, n.to_string())));
            let selected = saved.map_or(0, |c| {
                1 + langs.iter().position(|(x, _)| *x == c).unwrap_or(0)
            });
            let codes: Vec<&'static str> = langs.iter().map(|(c, _)| *c).collect();
            segmented("language", items, selected, cx, move |this, ix, _, cx| {
                pick(ix.checked_sub(1).map(|i| codes[i]), this, cx)
            })
            .into_any_element()
        } else {
            let entity = cx.entity();
            let label = saved.map_or(tr!("Как в системе").to_string(), |c| {
                i18n::native_name(c).to_string()
            });
            DropdownButton::new("language")
                .button(Button::new("language-btn").outline().label(label))
                .dropdown_menu_with_anchor(Anchor::TopLeft, move |menu, _, _| {
                    let mut menu = menu.min_w(px(220.));
                    let options = std::iter::once((None, tr!("Как в системе").to_string()))
                        .chain(langs.iter().map(|(c, n)| (Some(*c), n.to_string())));
                    for (code, name) in options {
                        let e = entity.clone();
                        menu = menu.item(
                            gpui_kit::component::menu::PopupMenuItem::new(name)
                                .checked(code == saved)
                                .on_click(move |_, _, cx| {
                                    e.update(cx, |this, cx| pick(code, this, cx))
                                }),
                        );
                    }
                    menu
                })
                .into_any_element()
        };
        panel(theme)
            .child(section(
                tr!("Язык"),
                tr!("Хранится на этом компьютере, а не в базе"),
                theme,
            ))
            .child(card(theme).child(row(tr!("Язык интерфейса"), control, theme)))
            .child(
                div()
                    .px_4()
                    .pb_3()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(tr!(
                        "Сообщения фоновой службы сменят язык после её перезапуска"
                    )),
            )
    }

    /// Ключи в ~/.ssh, которых нет в базе, и кнопка переноса; None, если переносить нечего.
    fn ssh_local_view(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = cx.theme().clone();
        if self.ssh_local.is_none() && !self.ssh_local_loading {
            self.ssh_local_call(Request::SshLocalKeys, cx);
        }
        let keys: Vec<_> = self
            .ssh_local
            .clone()?
            .into_iter()
            .filter(|k| !k.in_vault)
            .collect();
        if keys.is_empty() {
            return None;
        }
        Some(
            v_flex()
                .gap_2()
                .children(keys.iter().map(|k| {
                    let text: SharedString = if k.encrypted {
                        tr!("с паролем: добавьте через «Новый ключ SSH»").into()
                    } else {
                        k.algorithm.clone().into()
                    };
                    let color = theme.muted_foreground;
                    h_flex()
                        .gap_2()
                        .min_w_0()
                        .child(
                            div()
                                .text_sm()
                                .font_family(theme.mono_font_family.clone())
                                .truncate()
                                .child(crate::ui::tilde(&k.path)),
                        )
                        .child(crate::ui::badge(text, color))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .truncate()
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child(k.comment.clone()),
                        )
                }))
                .into_any_element(),
        )
    }

    /// Вкладка SSH: агент и его состояние, ключи на диске, поведение.
    fn ssh_tab(&mut self, cx: &mut Context<Self>) -> AnyElement {
        use keywarden_core::ssh_setup::{self, Status};
        let theme = cx.theme().clone();
        let Some(p) = self.prefs.clone() else {
            return div().into_any_element();
        };
        let status = self.ssh_setup.get_or_insert_with(ssh_setup::status).clone();
        let all_set = matches!(status, Status::Active | Status::AfterRelogin) && p.ssh_host_config;
        let (dot, headline) = match (&status, p.ssh_agent) {
            (_, false) => (
                theme.muted_foreground,
                tr!("Выключен: ssh и git не видят ключи из базы").to_string(),
            ),
            (Status::Active, _) => (
                theme.success_foreground,
                tr!("Работает: ssh, git и другие программы берут ключи из базы").to_string(),
            ),
            (Status::AfterRelogin, _) => (
                theme.info_foreground,
                tr!("Подключён ко всем программам: заработает после перезахода в систему")
                    .to_string(),
            ),
            (Status::Overridden(path), _) => (
                theme.warning_foreground,
                tr!(
                    "SSH_AUTH_SOCK перехватывает другой агент: {path}",
                    path = crate::ui::tilde(path)
                ),
            ),
            (Status::Off, _) => (
                theme.warning_foreground,
                tr!("Работает только там, где задан SSH_AUTH_SOCK").to_string(),
            ),
        };
        let agent = panel(&theme)
            .child(
                h_flex()
                    .gap_4()
                    .px_4()
                    .py_3p5()
                    .child(
                        v_flex()
                            .flex_1()
                            .gap_0p5()
                            .child(div().text_sm().font_weight(FontWeight::SEMIBOLD).child(tr!("SSH-агент")))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(tr!("Ключи из записей «Ключ SSH» для ssh, git и любых программ. Приватный ключ не попадает на диск")),
                            ),
                    )
                    .child(Switch::new("ssh-agent").checked(p.ssh_agent).on_change(cx.listener(
                        |this, v: &bool, w, cx| {
                            let v = *v;
                            this.toggle_pref(|p| p.ssh_agent = v, w, cx)
                        },
                    ))),
            )
            .child(
                v_flex()
                    .gap_3()
                    .px_4()
                    .py_3p5()
                    .border_t_1()
                    .border_color(theme.table_row_border)
                    .child(
                        h_flex()
                            .gap_4()
                            .child(
                                v_flex()
                                    .flex_1()
                                    .min_w_0()
                                    .gap_0p5()
                                    .child(
                                        h_flex()
                                            .gap_2()
                                            .child(div().size_2().flex_shrink_0().rounded_full().bg(dot))
                                            .child(div().text_sm().child(headline)),
                                    )
                                    .when(p.ssh_agent && !all_set, |d| {
                                        d.child(
                                            div()
                                                .pl(px(16.))
                                                .text_xs()
                                                .text_color(theme.muted_foreground)
                                                .child(tr!("Пропишет агента для всех программ сессии и даст каждому серверу свой ключ. Выключается здесь же")),
                                        )
                                    }),
                            )
                            .when(p.ssh_agent && !all_set, |d| {
                                d.child(
                                    Button::new("ssh-setup-all")
                                        .outline()
                                        .icon(IconName::WandSparkles)
                                        .label(tr!("Подключить ко всем программам"))
                                        .on_click(cx.listener(|this, _, w, cx| {
                                            if let Err(e) = keywarden_core::ssh_setup::enable() {
                                                this.say(tr!("Не удалось: {e}", e = e), true, cx);
                                            }
                                            this.ssh_setup = None;
                                            this.toggle_pref(|p| p.ssh_host_config = true, w, cx);
                                        })),
                                )
                            }),
                    )
                    .when(p.ssh_agent && matches!(status, Status::Overridden(_)) && cfg!(target_os = "linux"), |d| {
                        d.child(
                            div()
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child(tr!("В GNOME это gcr-ssh-agent: systemctl --user disable --now gcr-ssh-agent.socket, затем перезайти")),
                        )
                    })
                    .when(p.ssh_agent && status != Status::Off, |d| {
                        d.child(
                            h_flex()
                                .gap_3()
                                .child(
                                    div()
                                        .flex_1()
                                        .text_xs()
                                        .text_color(theme.muted_foreground)
                                        .child(tr!("В уже открытых терминалах: eval \"$(kw ssh-env)\"")),
                                )
                                .child(
                                    Button::new("ssh-all-off")
                                        .ghost()
                                        .small()
                                        .label(tr!("Отключить от всех программ"))
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            if let Err(e) = keywarden_core::ssh_setup::disable() {
                                                this.say(tr!("Не удалось: {e}", e = e), true, cx);
                                            }
                                            this.ssh_setup = None;
                                            cx.notify();
                                        })),
                                ),
                        )
                    }),
            );
        if !p.ssh_agent {
            return v_flex().gap_6().child(agent).into_any_element();
        }
        let on_disk = self.ssh_local_view(cx);
        if self.ssh_config_hosts.is_none() && !self.ssh_config_loading {
            self.ssh_config_load(cx);
        }
        let servers = self
            .ssh_config_hosts
            .as_ref()
            .map(|h| {
                h.iter()
                    .filter(|h| !h.in_vault)
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .filter(|h| !h.is_empty());
        let terminals = keywarden_core::ssh_setup::installed_terminals();
        let entity = cx.entity();
        let current = p.terminal.first().cloned();
        let terminal_label = current.clone().unwrap_or_else(|| {
            terminals
                .first()
                .map_or(tr!("не найден").to_string(), |(t, _)| {
                    tr!("Автоматически ({t})", t = t)
                })
        });
        let behavior = panel(&theme)
            .child(section(tr!("Поведение"), tr!("Как агент и лаунчер работают с ключами"), &theme))
            .child(row(
                tr!("Серверы в ssh"),
                v_flex()
                    .gap_1()
                    .child(Switch::new("ssh-hosts").checked(p.ssh_host_config).label(tr!("ssh знает серверы из базы, каждому свой ключ")).on_change(cx.listener(|this, v: &bool, w, cx| {
                        let v = *v;
                        this.toggle_pref(|p| p.ssh_host_config = v, w, cx)
                    })))
                    .child(div().text_xs().text_color(theme.muted_foreground).child(tr!("Записи «Сервер SSH» и поле «Хост» ключей; Keywarden ведёт ~/.ssh/keywarden/config, port knocking тоже там"))),
                &theme,
            ))
            .child(row(
                tr!("База заблокирована"),
                Switch::new("ssh-unlock").checked(p.ssh_unlock_prompt).label(tr!("Показать окно разблокировки, когда ssh нужен ключ")).on_change(cx.listener(|this, v: &bool, w, cx| {
                    let v = *v;
                    this.toggle_pref(|p| p.ssh_unlock_prompt = v, w, cx)
                })),
                &theme,
            ))
            .child(row(
                tr!("Лаунчер"),
                Switch::new("ssh-connect").checked(p.ssh_connect).label(tr!("Enter на ключе с хостом открывает терминал с ssh")).on_change(cx.listener(|this, v: &bool, w, cx| {
                    let v = *v;
                    this.toggle_pref(|p| p.ssh_connect = v, w, cx)
                })),
                &theme,
            ))
            .when(p.ssh_connect && !terminals.is_empty(), |d| {
                d.child(row(
                    tr!("Терминал"),
                    h_flex().child(
                        DropdownButton::new("ssh-terminal")
                            .button(Button::new("ssh-terminal-btn").outline().label(terminal_label))
                            .dropdown_menu_with_anchor(Anchor::TopLeft, move |menu, _, _| {
                                let mut menu = menu.min_w(px(200.));
                                let options = std::iter::once((None, tr!("Автоматически").to_string()))
                                    .chain(terminals.iter().map(|(t, f)| (Some((*t, *f)), t.to_string())));
                                for (choice, name) in options {
                                    let e = entity.clone();
                                    let checked = choice.map(|(t, _)| t.to_string()) == current;
                                    menu = menu.item(
                                        gpui_kit::component::menu::PopupMenuItem::new(name)
                                            .checked(checked)
                                            .on_click(move |_, w, cx| {
                                                let cmd: Vec<String> = match choice {
                                                    None => vec![],
                                                    Some((t, "")) => vec![t.into()],
                                                    Some((t, f)) => vec![t.into(), f.into()],
                                                };
                                                e.update(cx, |this, cx| this.toggle_pref(move |p| p.terminal = cmd.clone(), w, cx))
                                            }),
                                    );
                                }
                                menu
                            }),
                    ),
                    &theme,
                ))
            });
        v_flex()
            .gap_6()
            .child(agent)
            .when_some(on_disk, |d, view| {
                let movable = self
                    .ssh_local
                    .as_ref()
                    .is_some_and(|k| k.iter().any(|k| !k.in_vault && !k.encrypted));
                d.child(
                    panel(&theme)
                        .child(section(
                            tr!("Ключи на диске"),
                            tr!("Эти ключи лежат в ~/.ssh открытым файлом. В базе они защищены мастер-паролем"),
                            &theme,
                        ))
                        .child(div().px_4().pb_3p5().child(view))
                        .when(movable, |d| {
                            d.child(footer(&theme).child(
                                Button::new("ssh-migrate")
                                    .outline()
                                    .icon(IconName::Import)
                                    .label(tr!("Перенести в базу…"))
                                    .on_click(cx.listener(|this, _, w, cx| {
                                        let keys = this.ssh_local.clone().unwrap_or_default();
                                        this.open_migrate(crate::ssh_migrate::Source::Keys(keys), w, cx)
                                    })),
                            ))
                        }),
                )
            })
            .when_some(servers, |d, fresh| {
                d.child(
                    panel(&theme)
                        .child(section(
                            tr!("Серверы из ~/.ssh/config"),
                            tr!("Перенесите их в базу: адреса, ключи, ProxyJump и прочие настройки поедут на другие компьютеры. Сам файл не меняется"),
                            &theme,
                        ))
                        .child(
                            v_flex()
                                .px_4()
                                .pb_3p5()
                                .gap_2()
                                .children(fresh.iter().take(5).map(|h| {
                                    h_flex()
                                        .gap_2()
                                        .min_w_0()
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_family(theme.mono_font_family.clone())
                                                .child(h.alias.clone()),
                                        )
                                        .child(crate::ui::badge(h.folder.clone(), theme.muted_foreground))
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .truncate()
                                                .text_xs()
                                                .text_color(theme.muted_foreground)
                                                .child(h.address.clone()),
                                        )
                                }))
                                .when(fresh.len() > 5, |d| {
                                    d.child(
                                        div()
                                            .text_xs()
                                            .text_color(theme.muted_foreground)
                                            .child(tr!("и ещё {n}", n = fresh.len() - 5)),
                                    )
                                }),
                        )
                        .child(footer(&theme).child(
                            Button::new("ssh-import-config")
                                .outline()
                                .icon(IconName::Import)
                                .label(tr!("Перенести в базу…"))
                                .on_click(cx.listener(|this, _, w, cx| {
                                    let hosts = this.ssh_config_hosts.clone().unwrap_or_default();
                                    this.open_migrate(crate::ssh_migrate::Source::Hosts(hosts), w, cx)
                                })),
                        )),
                )
            })
            .child(behavior)
            .into_any_element()
    }

    fn ssh_config_load(&mut self, cx: &mut Context<Self>) {
        self.ssh_config_loading = true;
        self.tasks.push(client::call(
            cx,
            Request::SshConfigHosts,
            |this, res, cx| {
                this.ssh_config_loading = false;
                // база заблокирована или файла нет: карточки просто не будет
                this.ssh_config_hosts = Some(match res {
                    Ok(Response::SshConfigHosts { hosts }) => hosts,
                    _ => vec![],
                });
                cx.notify();
            },
        ));
    }

    /// Окно переноса ключей или серверов; после него списки перечитываются.
    fn open_migrate(
        &mut self,
        source: crate::ssh_migrate::Source,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let hosts_on = self.prefs.as_ref().is_some_and(|p| p.ssh_host_config);
        let view = cx.new(|cx| crate::ssh_migrate::SshMigrate::new(source, hosts_on, cx));
        self.ssh_migrate_sub = Some(cx.subscribe_in(
            &view,
            window,
            |this, _, ev: &crate::ssh_migrate::MigrateEvent, window, cx| {
                let crate::ssh_migrate::MigrateEvent::Done {
                    message,
                    enable_hosts,
                } = ev;
                window.close_dialog(cx);
                this.say(message.clone(), false, cx);
                this.ssh_local = None;
                this.ssh_config_hosts = None;
                if *enable_hosts {
                    this.saved_note = Some(message.clone());
                    this.toggle_pref(|p| p.ssh_host_config = true, window, cx);
                }
            },
        ));
        let v2 = view.clone();
        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .w(px(600.))
                .child(view.clone())
        });
        window.defer(cx, move |window, cx| {
            v2.update(cx, |v, cx| v.focus(window, cx))
        });
    }

    /// Список ключей в ~/.ssh или перенос выбранных; ответ один и тот же: обновлённый список.
    fn ssh_local_call(&mut self, req: Request, cx: &mut Context<Self>) {
        let migrating = matches!(req, Request::SshMigrate { .. });
        let before = self
            .ssh_local
            .as_ref()
            .map_or(0, |v| v.iter().filter(|k| k.in_vault).count());
        self.ssh_local_loading = true;
        self.tasks.push(client::call(cx, req, move |this, res, cx| {
            this.ssh_local_loading = false;
            match res {
                Ok(Response::SshLocalKeys { keys }) => {
                    let moved = keys
                        .iter()
                        .filter(|k| k.in_vault)
                        .count()
                        .saturating_sub(before);
                    if migrating {
                        this.say(tr!("Перенесено в базу: {n}", n = moved), false, cx);
                    }
                    this.ssh_local = Some(keys);
                }
                Ok(_) => {}
                Err(e) => this.say(e.message(), true, cx),
            }
            cx.notify();
        }));
        cx.notify();
    }

    fn say(&mut self, text: impl Into<SharedString>, error: bool, cx: &mut Context<Self>) {
        self.busy = None;
        self.message = Some((text.into(), error));
        cx.notify();
    }

    fn val(&self, i: &Entity<InputState>, cx: &App) -> String {
        i.read(cx).value().trim().to_string()
    }

    fn clear(&self, inputs: &[&Entity<InputState>], window: &mut Window, cx: &mut Context<Self>) {
        for i in inputs {
            i.update(cx, |i, cx| i.set_value("", window, cx));
        }
    }

    // --- общие и шифрование ---

    fn save_settings(&mut self, cx: &mut Context<Self>) {
        let Some(mut s) = self.settings.clone() else {
            return;
        };
        let num = |t: String, what: &str| {
            t.parse::<i64>()
                .map_err(|_| tr!("{what}: нужно число", what = what))
        };
        let res = (|| -> Result<DbSettings, String> {
            s.name = self.val(&self.name, cx);
            s.description = self.val(&self.description, cx);
            s.recycle_bin = self.recycle_bin;
            s.history_max_items = num(self.val(&self.history_items, cx), tr!("версий истории"))?;
            s.history_max_size_mib = num(self.val(&self.history_mib, cx), tr!("размер истории"))?;
            s.cipher = self.cipher;
            if s.kdf != "aes" {
                s.kdf_iterations =
                    num(self.val(&self.kdf_iter, cx), tr!("итерации"))?.max(0) as u64;
                s.kdf_memory_mib = num(self.val(&self.kdf_mem, cx), tr!("память"))?.max(0) as u64;
                s.kdf_parallelism = num(self.val(&self.kdf_par, cx), tr!("потоки"))?.max(0) as u32;
            }
            Ok(s)
        })();
        let s = match res {
            Ok(s) => s,
            Err(e) => return self.say(e, true, cx),
        };
        self.busy = Some(tr!("Сохраняю настройки…"));
        cx.notify();
        self.tasks.push(client::call(
            cx,
            Request::SetSettings { settings: s },
            |this, res, cx| match res {
                Ok(Response::Settings { settings }) => {
                    this.settings = Some(settings);
                    this.say(tr!("Настройки сохранены"), false, cx)
                }
                Ok(_) => this.say(tr!("Настройки сохранены"), false, cx),
                Err(e) => this.say(e.message(), true, cx),
            },
        ));
    }

    fn tune(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.busy = Some(tr!("Замеряю скорость Argon2…"));
        cx.notify();
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::TuneKdf,
            |this, res, window, cx| match res {
                Ok(Response::Settings { settings }) => {
                    if let Some(s) = this.settings.as_mut() {
                        s.kdf = settings.kdf.clone();
                    }
                    for (i, v) in [
                        (this.kdf_iter.clone(), settings.kdf_iterations),
                        (this.kdf_mem.clone(), settings.kdf_memory_mib),
                        (this.kdf_par.clone(), settings.kdf_parallelism as u64),
                    ] {
                        i.update(cx, |i, cx| i.set_value(v.to_string(), window, cx));
                    }
                    this.say(
                        tr!("Подобрано под ~1 с на этом компьютере. Нажмите «Сохранить», чтобы применить"),
                        false,
                        cx,
                    )
                }
                Ok(_) => this.say("", false, cx),
                Err(e) => this.say(e.message(), true, cx),
            },
        ));
    }

    // --- смена ключа ---

    fn change_key(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let (p1, p2) = (self.val(&self.new_pw, cx), self.val(&self.new_pw2, cx));
        if p1 != p2 {
            return self.say(tr!("Новые пароли не совпадают"), true, cx);
        }
        let new_keyfile = Some(self.val(&self.new_keyfile, cx)).filter(|s| !s.is_empty());
        if p1.is_empty() && new_keyfile.is_none() {
            return self.say(tr!("Нужен новый пароль, файл-ключ или оба"), true, cx);
        }
        let current = KeySpec {
            password: Some(Secret::new(self.cur_pw.read(cx).value().to_string())),
            keyfile: self.cur_keyfile.clone(),
            yubikey: self.cur_yubikey.clone(),
        };
        let new = KeySpec {
            password: (!p1.is_empty()).then(|| Secret::new(p1)),
            keyfile: new_keyfile,
            yubikey: Some(self.val(&self.new_yubikey, cx)).filter(|s| !s.is_empty()),
        };
        self.clear(&[&self.cur_pw, &self.new_pw, &self.new_pw2], window, cx);
        self.busy = Some(tr!("Проверяю текущий ключ и перешифровываю базу…"));
        cx.notify();
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::ChangeKey { current, new },
            |this, res, window, cx| match res {
                Ok(_) => {
                    this.reload(window, cx);
                    this.say(
                        tr!("Ключ сменён. Бэкапы, сделанные до смены, открываются старым ключом"),
                        false,
                        cx,
                    )
                }
                Err(e) => this.say(e.message(), true, cx),
            },
        ));
    }

    fn create_keyfile(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let dir = home();
        let rx = cx.prompt_for_new_path(&dir, Some("keywarden.keyx"));
        let input = self.new_keyfile.clone();
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(path))) = rx.await else { return };
            let p = path.display().to_string();
            let res = cx
                .background_spawn({
                    let p = p.clone();
                    async move { client::blocking(&Request::GenerateKeyfile { path: p }) }
                })
                .await;
            let _ = this.update_in(cx, |this, window, cx| match res {
                Ok(_) => {
                    input.update(cx, |i, cx| i.set_value(p, window, cx));
                    this.say(
                        tr!("Файл-ключ создан. Сохраните его копию отдельно от базы: без него база не откроется"),
                        false,
                        cx,
                    )
                }
                Err(e) => this.say(e.message(), true, cx),
            });
        }));
    }

    // --- этот компьютер ---

    fn load_prefs(&mut self, set: Option<Prefs>, window: &mut Window, cx: &mut Context<Self>) {
        let saving = set.is_some();
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::Prefs { set },
            move |this, res, window, cx| {
                match res {
                    Ok(Response::Prefs { prefs }) => {
                        let put = |i: &Entity<InputState>,
                                   v: String,
                                   window: &mut Window,
                                   cx: &mut Context<Self>| {
                            i.update(cx, |i, cx| i.set_value(v, window, cx))
                        };
                        put(
                            &this.autolock,
                            prefs.autolock_minutes.to_string(),
                            window,
                            cx,
                        );
                        put(
                            &this.clip_secs,
                            prefs.clipboard_clear_seconds.to_string(),
                            window,
                            cx,
                        );
                        put(
                            &this.backups_keep,
                            prefs.backups_keep.to_string(),
                            window,
                            cx,
                        );
                        put(&this.pin_hours, prefs.pin_hours.to_string(), window, cx);
                        if this.explorers.is_empty() {
                            this.explorers = keywarden_core::wallet::NETWORK_IDS
                                .iter()
                                .map(|(id, _)| {
                                    (
                                        id.to_string(),
                                        cx.new(|cx| {
                                            InputState::new(window, cx)
                                                .placeholder("https://…/{address}")
                                        }),
                                    )
                                })
                                .collect();
                        }
                        for (id, inp) in &this.explorers {
                            let v = prefs.explorers.get(id).cloned().unwrap_or_default();
                            inp.update(cx, |i, cx| i.set_value(v, window, cx));
                        }
                        this.prefs = Some(*prefs);
                        if saving {
                            let note = this.saved_note.take();
                            this.say(note.unwrap_or_else(|| tr!("Сохранено").into()), false, cx);
                        }
                    }
                    Err(e) => this.say(e.message(), true, cx),
                    _ => {}
                }
                cx.notify();
            },
        ));
    }

    fn save_prefs(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(mut p) = self.prefs.clone() else {
            return;
        };
        let num = |this: &Self, i: &Entity<InputState>, cx: &mut Context<Self>| {
            this.val(i, cx).parse::<u64>().ok()
        };
        let (Some(a), Some(c), Some(k), Some(h)) = (
            num(self, &self.autolock, cx),
            num(self, &self.clip_secs, cx),
            num(self, &self.backups_keep, cx),
            num(self, &self.pin_hours, cx),
        ) else {
            return self.say(tr!("Числа должны быть целыми, без пробелов"), true, cx);
        };
        p.autolock_minutes = a;
        p.clipboard_clear_seconds = c;
        p.backups_keep = k as usize;
        p.pin_hours = h.max(1);
        // пустое поле: обозреватель по умолчанию
        p.explorers = self
            .explorers
            .iter()
            .map(|(id, inp)| (id.clone(), self.val(inp, cx)))
            .collect();
        self.load_prefs(Some(p), window, cx);
    }

    /// Переключатели сохраняются сразу.
    fn toggle_pref(
        &mut self,
        f: impl FnOnce(&mut Prefs),
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(mut p) = self.prefs.clone() {
            f(&mut p);
            self.prefs = Some(p.clone());
            self.load_prefs(Some(p), window, cx);
        }
    }

    fn set_pin(&mut self, remove: bool, window: &mut Window, cx: &mut Context<Self>) {
        let req = if remove {
            Request::SetPin {
                pin: None,
                key: None,
            }
        } else {
            let pin = self.val(&self.pin_new, cx);
            let pw = self.val(&self.pin_master, cx);
            if pin.chars().count() < 4 {
                return self.say(tr!("PIN не короче 4 символов"), true, cx);
            }
            if pw.is_empty() {
                return self.say(
                    tr!("Введите мастер-пароль: без него PIN не задать"),
                    true,
                    cx,
                );
            }
            Request::SetPin {
                pin: Some(pin.into()),
                key: Some(KeySpec {
                    password: Some(pw.into()),
                    keyfile: self.cur_keyfile.clone(),
                    yubikey: self.cur_yubikey.clone(),
                }),
            }
        };
        self.busy = Some(if remove {
            tr!("Убираю PIN…")
        } else {
            tr!("Проверяю мастер-пароль…")
        });
        cx.notify();
        self.tasks.push(client::call_in(window, cx, req, move |this, res, window, cx| {
            match res {
                Ok(_) => {
                    for i in [this.pin_new.clone(), this.pin_master.clone()] {
                        i.update(cx, |i, cx| i.set_value("", window, cx));
                    }
                    this.say(
                        if remove {
                            tr!("PIN убран: дальше только мастер-пароль")
                        } else {
                            tr!("PIN задан. После блокировки базу можно открыть им, пока не истечёт срок")
                        },
                        false,
                        cx,
                    );
                    this.load_prefs(None, window, cx);
                }
                Err(e) => this.say(e.message(), true, cx),
            }
        }));
    }

    fn load_sync(&mut self, cx: &mut Context<Self>) {
        self.tasks
            .push(client::call(cx, Request::SyncJournal, |this, res, cx| {
                if let Ok(Response::SyncJournal {
                    records,
                    held,
                    db_path,
                    folder,
                }) = res
                {
                    this.sync_records = records;
                    this.sync_held = held.map(|h| *h);
                    this.sync_path = db_path;
                    this.sync_folder = folder.map(|f| *f);
                }
                cx.notify();
            }));
    }

    fn sync_decide(&mut self, accept: bool, cx: &mut Context<Self>) {
        self.busy = Some(tr!("Сливаю…"));
        cx.notify();
        self.tasks.push(client::call(
            cx,
            Request::SyncDecide { accept },
            move |this, res, cx| {
                match res {
                    Ok(_) => {
                        cx.emit(SettingsEvent::Changed);
                        this.say(
                            if accept {
                                tr!("Удаления приняты")
                            } else {
                                tr!("Удаления отклонены: записи останутся и на других устройствах")
                            },
                            false,
                            cx,
                        );
                    }
                    Err(e) => this.say(e.message(), true, cx),
                }
                this.load_sync(cx);
                this.load_backups(cx);
            },
        ));
    }

    fn sync_revert(&mut self, id: u64, cx: &mut Context<Self>) {
        if self.confirm_revert != Some(id) {
            self.confirm_revert = Some(id);
            return cx.notify();
        }
        self.confirm_revert = None;
        self.busy = Some(tr!("Отменяю…"));
        cx.notify();
        self.tasks.push(client::call(
            cx,
            Request::SyncRevert { id },
            |this, res, cx| {
                match res {
                    Ok(_) => {
                        cx.emit(SettingsEvent::Changed);
                        this.say(
                            tr!("Отменено. Отмена тоже разойдётся по устройствам и сама есть в журнале"),
                            false,
                            cx,
                        );
                    }
                    Err(e) => this.say(e.message(), true, cx),
                }
                this.load_sync(cx);
            },
        ));
    }

    /// Переместить файл базы в выбранную папку (например, папку Syncthing).
    fn move_db(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some(tr!("Переместить сюда").into()),
        });
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            let dir = match rx.await {
                Ok(Ok(Some(mut v))) if !v.is_empty() => v.remove(0),
                _ => return,
            };
            let _ = this.update(cx, |this, cx| {
                this.busy = Some(tr!("Переношу базу…"));
                cx.notify();
            });
            let req = Request::MoveDatabase {
                dir: dir.display().to_string(),
            };
            let res = cx
                .background_spawn(async move { client::blocking(&req) })
                .await;
            let _ = this.update(cx, |this, cx| {
                match res {
                    Ok(_) => {
                        cx.emit(SettingsEvent::Changed);
                        this.say(
                            tr!("База перенесена. Старый файл лежит в резервных копиях"),
                            false,
                            cx,
                        );
                    }
                    Err(e) => this.say(e.message(), true, cx),
                }
                this.load_sync(cx);
                this.load_backups(cx);
            });
        }));
    }

    fn sync_tab(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let Some(p) = self.prefs.clone() else {
            return div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(tr!("Загружаю…"))
                .into_any_element();
        };
        let busy = self.busy.is_some();
        let switch = |id: &'static str,
                      on: bool,
                      label: &'static str,
                      f: fn(&mut Prefs, bool),
                      cx: &mut Context<Self>| {
            Switch::new(id)
                .checked(on)
                .label(label)
                .on_change(cx.listener(move |this, v: &bool, w, cx| {
                    let v = *v;
                    this.toggle_pref(|p| f(p, v), w, cx)
                }))
        };
        let held = self.sync_held.clone().map(|h| {
            v_flex()
                .gap_3()
                .p_4()
                .rounded_lg()
                .border_1()
                .border_color(theme.danger)
                .bg(theme.danger.opacity(0.08))
                .child(
                    h_flex()
                        .gap_2()
                        .child(Icon::new(IconName::TriangleAlert).text_color(theme.danger_foreground))
                        .child(
                            div()
                                .text_sm()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(tr!("{source}: убирает {removed} из {live} записей", source = capitalize(&h.source), removed = h.removed, live = h.live)),
                        ),
                )
                .child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child(tr!(
                            "Слияние на паузе, запись базы ждёт решения. Что придёт: {summary}. Если вы не удаляли столько записей, отклоните: записи останутся здесь и вернутся на другие устройства.",
                            summary = h.summary
                        )),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(div().flex_1())
                        .child(
                            Button::new("sync-accept")
                                .ghost()
                                .label(tr!("Принять удаления"))
                                .disabled(busy)
                                .on_click(cx.listener(|this, _, _, cx| this.sync_decide(true, cx))),
                        )
                        .child(
                            Button::new("sync-reject")
                                .primary()
                                .icon(IconName::Undo2)
                                .label(tr!("Отклонить удаления"))
                                .loading(busy)
                                .on_click(cx.listener(|this, _, _, cx| this.sync_decide(false, cx))),
                        ),
                )
        });
        let status = |s: &str| match s {
            "accepted" => (tr!("принято"), theme.warning_foreground),
            "rejected" => (tr!("удаления отклонены"), theme.info_foreground),
            "reverted" => (tr!("отменено"), theme.muted_foreground),
            _ => (tr!("слито"), theme.success_foreground),
        };
        let records: Vec<AnyElement> = self
            .sync_records
            .iter()
            .enumerate()
            .map(|(ix, r)| {
                let (label, color) = status(&r.status);
                let id = r.id;
                let confirm = self.confirm_revert == Some(id);
                let can = r.snapshot.is_some() && r.status != "reverted";
                h_flex()
                    .id(("sync-rec", ix))
                    .gap_3()
                    .px_4()
                    .py_2()
                    .border_t_1()
                    .border_color(theme.table_row_border)
                    .child(
                        div()
                            .w(px(120.))
                            .flex_shrink_0()
                            .text_sm()
                            .child(r.when.clone()),
                    )
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .child(div().text_sm().truncate().child(r.summary.clone()))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .truncate()
                                    .child(capitalize(&r.source)),
                            ),
                    )
                    .child(crate::ui::badge(label, color))
                    .when(can, |d| {
                        d.child(
                            Button::new(("sync-revert", ix))
                                .small()
                                .when(confirm, |b| b.danger().label(tr!("Точно отменить?")))
                                .when(!confirm, |b| {
                                    b.ghost().icon(IconName::Undo2).label(tr!("Отменить"))
                                })
                                .disabled(busy)
                                .on_click(
                                    cx.listener(move |this, _, _, cx| this.sync_revert(id, cx)),
                                ),
                        )
                    })
                    .into_any_element()
            })
            .collect();
        let found = self.sync_folder.clone().map(|f| {
            let name = match f.kind.as_str() {
                "syncthing" => "Syncthing",
                "nextcloud" => "Nextcloud",
                "dropbox" => "Dropbox",
                other => other,
            };
            (name.to_string(), f.root)
        });
        let step = |n: &'static str, text: &'static str| {
            h_flex()
                .gap_3()
                .items_start()
                .child(
                    div()
                        .size(px(20.))
                        .flex_shrink_0()
                        .rounded_full()
                        .bg(theme.secondary)
                        .text_xs()
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(n),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child(text),
                )
        };
        let setup = panel(&theme)
            .child(section(
                tr!("Как синхронизировать"),
                tr!("Файл базы лежит в папке, которую синхронизирует Syncthing, Nextcloud или Dropbox. Наружу уходит только зашифрованный файл"),
                &theme,
            ))
            .child(
                card(&theme)
                    .child(row(
                        tr!("Файл базы"),
                        div()
                            .text_sm()
                            .font_family(theme.mono_font_family.clone())
                            .truncate()
                            .child(crate::ui::tilde(&self.sync_path.clone().unwrap_or_default())),
                        &theme,
                    ))
                    .child(row(
                        tr!("Синхронизация"),
                        match &found {
                            Some((name, root)) => h_flex()
                                .gap_2()
                                .min_w_0()
                                .child(crate::ui::badge(tr!("{name}: работает", name = name), theme.success_foreground))
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(theme.muted_foreground)
                                        .truncate()
                                        .child(crate::ui::tilde(&root.to_string())),
                                )
                                .into_any_element(),
                            None => h_flex()
                                .child(crate::ui::badge(
                                    tr!("файл не в папке синхронизации"),
                                    theme.warning_foreground,
                                ))
                                .into_any_element(),
                        },
                        &theme,
                    )),
            )
            .when(found.is_none(), |d| {
                d.child(
                    v_flex()
                        .gap_2()
                        .px_4()
                        .py_3()
                        .border_t_1()
                        .border_color(theme.table_row_border)
                        .child(step("1", tr!("Установите Syncthing (или Nextcloud, Dropbox) на этот компьютер и на другие устройства, заведите общую папку")))
                        .child(step("2", tr!("Нажмите «Переместить в папку…» и выберите эту папку. Keywarden перенесёт базу и будет следить за ней")))
                        .child(step("3", tr!("На другом компьютере откройте этот же файл в Keywarden. На телефоне: KeePassDX (Android, с Syncthing-Fork) или KeePassium и Strongbox (iOS)"))),
                )
            })
            .child(
                footer(&theme)
                    .justify_between()
                    .gap_4()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Файл переносится тем же ключом и проверяется чтением, старый уходит в резервные копии. Вынос из папки синхронизации удалит файл на других устройствах")),
                    )
                    .child(
                        Button::new("move-db")
                            .outline()
                            .icon(IconName::FolderOpen)
                            .label(tr!("Переместить в папку…"))
                            .disabled(busy || self.sync_held.is_some())
                            .on_click(cx.listener(|this, _, w, cx| this.move_db(w, cx))),
                    ),
            );
        let soon = |title: &'static str, hint: &'static str| {
            panel(&theme).child(
                h_flex()
                    .px_4()
                    .py_3()
                    .gap_3()
                    .child(
                        v_flex()
                            .flex_1()
                            .gap_0p5()
                            .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(title))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(hint),
                            ),
                    )
                    .child(crate::ui::badge(tr!("скоро"), theme.muted_foreground)),
            )
        };
        v_flex()
            .gap_6()
            .children(held)
            .child(setup)
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Слежение и защита"),
                        tr!("Изменения с других устройств и их конфликтные копии сливаются в базу автоматически"),
                        &theme,
                    ))
                    .child(
                        card(&theme)
                            .child(row(
                                tr!("Слежение"),
                                switch("sync-watch", p.sync_watch, tr!("Сразу сливать изменения файла базы"), |p, v| p.sync_watch = v, cx),
                                &theme,
                            ))
                            .child(row(
                                tr!("Защита"),
                                switch("sync-guard", p.sync_guard, tr!("Спрашивать, если пришло удаление больше 5 записей или 10% базы"), |p, v| p.sync_guard = v, cx),
                                &theme,
                            )),
                    )
                    .child(
                        div()
                            .px_4()
                            .pb_3()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Ключ-файл и YubiKey не кладите в синхронизируемую папку: тогда копия на сервере бесполезна без них. Изменения при записи сливаются всегда, даже с выключенным слежением")),
                    ),
            )
            .child(soon(
                tr!("WebDAV: Nextcloud, Synology, любой сервер"),
                tr!("Keywarden сам скачивает и загружает базу, без отдельной программы синхронизации"),
            ))
            .child(soon(
                tr!("Напрямую между компьютерами"),
                tr!("По локальной сети, связь по коду из 6 слов, без облака"),
            ))
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Журнал"),
                        tr!("Каждое входящее изменение: откуда и что. Отмена возвращает записи как новую правку, поэтому она расходится по всем устройствам"),
                        &theme,
                    ))
                    .child(if records.is_empty() {
                        div()
                            .px_4()
                            .pb_3()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Пока ничего не приходило с других устройств"))
                            .into_any_element()
                    } else {
                        v_flex().children(records).into_any_element()
                    }),
            )
            .into_any_element()
    }

    fn load_backups(&mut self, cx: &mut Context<Self>) {
        self.tasks
            .push(client::call(cx, Request::Backups, |this, res, cx| {
                if let Ok(Response::Backups { backups }) = res {
                    this.backups = backups;
                }
                cx.notify();
            }));
    }

    fn restore(&mut self, name: String, cx: &mut Context<Self>) {
        if self.confirm_restore.as_deref() != Some(name.as_str()) {
            self.confirm_restore = Some(name);
            return cx.notify();
        }
        self.confirm_restore = None;
        self.busy = Some(tr!("Восстанавливаю…"));
        cx.notify();
        self.tasks.push(client::call(
            cx,
            Request::RestoreBackup { name },
            |this, res, cx| {
                match res {
                    Ok(_) => {
                        cx.emit(SettingsEvent::Changed);
                        this.say(
                            tr!("База восстановлена. Состояние до восстановления тоже лежит в копиях"),
                            false,
                            cx,
                        );
                    }
                    Err(e) => this.say(e.message(), true, cx),
                }
                this.load_backups(cx);
            },
        ));
    }

    fn device_tab(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let Some(p) = self.prefs.clone() else {
            return div()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(tr!("Загружаю…"))
                .into_any_element();
        };
        let busy = self.busy.is_some();
        let switch = |id: &'static str,
                      on: bool,
                      label: &'static str,
                      f: fn(&mut Prefs, bool),
                      cx: &mut Context<Self>| {
            Switch::new(id)
                .checked(on)
                .label(label)
                .on_change(cx.listener(move |this, v: &bool, w, cx| {
                    let v = *v;
                    this.toggle_pref(|p| f(p, v), w, cx)
                }))
        };
        let suffix = |input: &Entity<InputState>, unit: &'static str| {
            h_flex()
                .gap_2()
                .child(div().w(px(90.)).child(Input::new(input)))
                .child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child(unit),
                )
        };
        let kind = |k: &str| match k {
            "conflict" => (tr!("копия Syncthing"), theme.info_foreground),
            "unsaved" => (tr!("несохранённые правки"), theme.warning_foreground),
            "presync" => (tr!("до синхронизации"), theme.info_foreground),
            "moved" => (tr!("до переноса"), theme.info_foreground),
            _ => (tr!("перед сохранением"), theme.muted_foreground),
        };
        let backups: Vec<AnyElement> = self
            .backups
            .iter()
            .enumerate()
            .map(|(ix, b)| {
                let (label, color) = kind(&b.kind);
                let confirm = self.confirm_restore.as_deref() == Some(b.name.as_str());
                let name = b.name.clone();
                h_flex()
                    .id(("backup", ix))
                    .gap_3()
                    .px_4()
                    .min_h(px(44.))
                    .border_t_1()
                    .border_color(theme.table_row_border)
                    .child(
                        Icon::new(IconName::Database)
                            .small()
                            .text_color(theme.muted_foreground),
                    )
                    .child(div().w(px(130.)).text_sm().child(b.when.clone()))
                    .child(crate::ui::badge(label, color))
                    .child(div().flex_1())
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(tr!("{n} КБ", n = b.size.div_ceil(1024))),
                    )
                    .child(
                        Button::new(("restore", ix))
                            .small()
                            .when(confirm, |b| b.danger().label(tr!("Точно заменить базу?")))
                            .when(!confirm, |b| b.ghost().label(tr!("Восстановить")))
                            .disabled(busy)
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.restore(name.clone(), cx)),
                            ),
                    )
                    .into_any_element()
            })
            .collect();

        let caps = keywarden_core::platform::capabilities();
        v_flex()
            .gap_6()
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Система"),
                        tr!("Что умеет Keywarden на этом компьютере и как включить"),
                        &theme,
                    ))
                    .children(caps.into_iter().map(|(what, how)| {
                        row(
                            what,
                            div()
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(capitalize(&how)),
                            &theme,
                        )
                    })),
            )
            .child({
                let on = *self.autostart.get_or_insert_with(keywarden_core::autostart::enabled);
                panel(&theme).child(row(
                    tr!("Запуск при входе"),
                    Switch::new("autostart")
                        .checked(on)
                        .label(tr!("Работать в фоне сразу после входа в систему"))
                        .on_change(cx.listener(|this, on: &bool, _, cx| {
                            let res = if *on {
                                keywarden_core::autostart::enable()
                            } else {
                                keywarden_core::autostart::disable()
                            };
                            if let Err(e) = res {
                                this.say(tr!("Не удалось: {e}", e = e), true, cx);
                            }
                            this.autostart = None;
                            cx.notify();
                        })),
                    &theme,
                ))
                .when(cfg!(not(target_os = "macos")), |panel| {
                    panel.child(row(
                        tr!("Значок в трее"),
                        switch("tray", p.tray, tr!("Видно, открыта ли база; меню: открыть, поиск, блокировка, выход"), |p, v| p.tray = v, cx),
                        &theme,
                    ))
                })
            })
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Блокировка"),
                        tr!("Хранится на этом компьютере, а не в базе"),
                        &theme,
                    ))
                    .child(
                        card(&theme)
                            .child(row(tr!("После простоя"), suffix(&self.autolock, tr!("мин, 0 = никогда")), &theme))
                            .child(row(
                                tr!("Экран"),
                                switch("lock-screen", p.lock_on_screen_lock, tr!("Блокировать вместе с экраном"), |p, v| p.lock_on_screen_lock = v, cx),
                                &theme,
                            ))
                            .child(row(
                                tr!("Сон"),
                                switch("lock-sleep", p.lock_on_sleep, tr!("Блокировать перед сном"), |p, v| p.lock_on_sleep = v, cx),
                                &theme,
                            ))
                            .child(row(tr!("Буфер обмена"), suffix(&self.clip_secs, tr!("с до очистки")), &theme)),
                    ),
            )
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Быстрая разблокировка"),
                        tr!("PIN вместо мастер-пароля после блокировки. Три ошибки или истёкший срок: снова нужен мастер-пароль"),
                        &theme,
                    ))
                    .child(
                        card(&theme)
                            .child(row(
                                tr!("Состояние"),
                                h_flex()
                                    .gap_2()
                                    .child(if p.pin_set {
                                        crate::ui::badge(tr!("PIN задан"), theme.success_foreground)
                                    } else {
                                        crate::ui::badge(tr!("PIN не задан"), theme.muted_foreground)
                                    })
                                    .child(div().flex_1())
                                    .when(p.pin_set, |d| {
                                        d.child(
                                            Button::new("pin-remove")
                                                .ghost()
                                                .small()
                                                .label(tr!("Убрать PIN"))
                                                .disabled(busy)
                                                .on_click(cx.listener(|this, _, w, cx| this.set_pin(true, w, cx))),
                                        )
                                    }),
                                &theme,
                            ))
                            .child(row(
                                if p.pin_set { tr!("Новый PIN") } else { "PIN" },
                                Input::new(&self.pin_new).mask_toggle(),
                                &theme,
                            ))
                            .child(row(tr!("Мастер-пароль"), Input::new(&self.pin_master).mask_toggle(), &theme))
                            .child(row(tr!("Действует"), suffix(&self.pin_hours, tr!("ч после ввода мастер-пароля")), &theme)),
                    )
                    .child(
                        footer(&theme).child(
                            Button::new("pin-set")
                                .outline()
                                .icon(IconName::KeyRound)
                                .label(if p.pin_set { tr!("Сменить PIN") } else { tr!("Задать PIN") })
                                .loading(busy)
                                .on_click(cx.listener(|this, _, w, cx| this.set_pin(false, w, cx))),
                        ),
                    ),
            )
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Уведомления"),
                        tr!("Системные уведомления рабочего стола"),
                        &theme,
                    ))
                    .child(
                        card(&theme)
                            .child(row(
                                tr!("Срок действия"),
                                switch("n-expiry", p.notify_expiry, tr!("Записи с истёкшим сроком и истекающие за неделю"), |p, v| p.notify_expiry = v, cx),
                                &theme,
                            ))
                            .child(row(
                                tr!("Утечки"),
                                switch("n-breach", p.notify_breaches, tr!("Раз в неделю проверять в Have I Been Pwned"), |p, v| p.notify_breaches = v, cx),
                                &theme,
                            ))
                            .child(row(
                                tr!("Обновления"),
                                switch("n-updates", p.check_updates, tr!("Раз в сутки проверять новую версию на GitHub"), |p, v| p.check_updates = v, cx),
                                &theme,
                            ))
                            .when_some(p.update_available.clone(), |c, tag| {
                                let url = format!("https://github.com/onokashino/keywarden/releases/tag/{tag}");
                                c.child(row(
                                    tr!("Новая версия"),
                                    h_flex()
                                        .gap_3()
                                        .items_center()
                                        .child(crate::ui::badge(tr!("Доступна {version}", version = tag), theme.success_foreground))
                                        .child(
                                            Button::new("open-release")
                                                .ghost()
                                                .small()
                                                .label(tr!("Что нового"))
                                                .on_click(move |_, _, cx| cx.open_url(&url)),
                                        ),
                                    &theme,
                                ))
                            }),
                    ),
            )
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Обозреватели блоков"),
                        tr!("Куда ведёт кнопка у адреса кошелька. {address} заменяется адресом"),
                        &theme,
                    ))
                    .children(self.explorers.iter().map(|(id, inp)| {
                        let name = keywarden_core::wallet::NETWORK_IDS
                            .iter()
                            .find(|(n, _)| n == id)
                            .map(|(_, l)| *l)
                            .unwrap_or("");
                        row(name, Input::new(inp), &theme)
                    })),
            )
            .child(
                panel(&theme)
                    .child(section(
                        tr!("Резервные копии"),
                        tr!("Перед каждым сохранением база копируется в ~/.local/state/keywarden/backups"),
                        &theme,
                    ))
                    .child(card(&theme).child(row(tr!("Хранить"), suffix(&self.backups_keep, tr!("последних копий")), &theme)))
                    .child(if backups.is_empty() {
                        div()
                            .px_4()
                            .pb_3()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Копий пока нет: они появятся после первой правки"))
                            .into_any_element()
                    } else {
                        v_flex().children(backups).into_any_element()
                    }),
            )
            .child(
                h_flex().justify_end().child(
                    Button::new("save-prefs")
                        .primary()
                        .icon(IconName::Save)
                        .label(tr!("Сохранить"))
                        .loading(busy)
                        .on_click(cx.listener(|this, _, w, cx| this.save_prefs(w, cx))),
                ),
            )
            .into_any_element()
    }

    // --- перенос ---

    fn run_with_path(
        &mut self,
        save: Option<&'static str>,
        busy: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
        make: impl FnOnce(String) -> Request + 'static,
        done: impl FnOnce(&mut Self, Response, &mut Context<Self>) + 'static,
    ) {
        let rx = match save {
            Some(name) => {
                let rx = cx.prompt_for_new_path(&home(), Some(name));
                Either::Save(rx)
            }
            None => Either::Open(cx.prompt_for_paths(PathPromptOptions {
                files: true,
                directories: false,
                multiple: false,
                prompt: Some(tr!("Выбрать").into()),
            })),
        };
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            let path = match rx {
                Either::Save(rx) => match rx.await {
                    Ok(Ok(Some(p))) => p,
                    _ => return,
                },
                Either::Open(rx) => match rx.await {
                    Ok(Ok(Some(mut v))) if !v.is_empty() => v.remove(0),
                    _ => return,
                },
            };
            let _ = this.update(cx, |this, cx| {
                this.busy = Some(busy);
                cx.notify();
            });
            let req = make(path.display().to_string());
            let res = cx
                .background_spawn(async move { client::blocking(&req) })
                .await;
            let _ = this.update(cx, |this, cx| match res {
                Ok(r) => done(this, r, cx),
                Err(e) => this.say(e.message(), true, cx),
            });
        }));
    }

    fn export_csv(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.run_with_path(
            Some("keywarden-export.csv"),
            tr!("Выгружаю…"),
            window,
            cx,
            |path| Request::ExportCsv { path },
            |this, _, cx| {
                this.say(
                    tr!("Выгружено. В CSV пароли открытым текстом: удалите файл после переноса"),
                    false,
                    cx,
                )
            },
        );
    }

    fn save_copy(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let pw = self.copy_pw.read(cx).value().to_string();
        if pw.is_empty() {
            return self.say(tr!("Задайте пароль копии"), true, cx);
        }
        self.clear(&[&self.copy_pw], window, cx);
        self.run_with_path(
            Some("keywarden-copy.kdbx"),
            tr!("Сохраняю копию…"),
            window,
            cx,
            move |path| Request::SaveCopy {
                path,
                key: KeySpec {
                    password: Some(Secret::new(pw)),
                    ..Default::default()
                },
            },
            |this, _, cx| this.say(tr!("Копия сохранена и проверена расшифровкой"), false, cx),
        );
    }

    fn pick_other(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(tr!("Выбрать").into()),
        });
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(mut v))) = rx.await
                && !v.is_empty()
            {
                let p = v.remove(0);
                let _ = this.update(cx, |this, cx| {
                    this.other_path = Some(p);
                    this.message = None;
                    cx.notify();
                });
            }
        }));
    }

    fn import_or_merge(&mut self, merge: bool, window: &mut Window, cx: &mut Context<Self>) {
        let Some(path) = self.other_path.clone() else {
            return self.say(tr!("Сначала выберите файл"), true, cx);
        };
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let format = match ext.as_str() {
            "csv" => ImportFormat::Csv,
            "kdbx" | "kdb" => ImportFormat::Keepass,
            "json" => ImportFormat::Bitwarden,
            "2fas" => ImportFormat::TwoFas,
            _ => {
                return self.say(
                    tr!("Поддерживаются .csv, .kdbx, .kdb, .2fas и .json (Bitwarden)"),
                    true,
                    cx,
                );
            }
        };
        if merge && format != ImportFormat::Keepass {
            return self.say(
                tr!("Слить можно только с копией этой базы (.kdbx)"),
                true,
                cx,
            );
        }
        let key = KeySpec {
            password: Some(Secret::new(self.other_pw.read(cx).value().to_string())),
            ..Default::default()
        };
        self.clear(&[&self.other_pw], window, cx);
        let p = path.display().to_string();
        let req = if merge {
            Request::MergeFile { path: p, key }
        } else {
            Request::ImportFile {
                path: p,
                format,
                key: (format == ImportFormat::Keepass).then_some(key),
            }
        };
        self.busy = Some(if merge {
            tr!("Сливаю…")
        } else {
            tr!("Импортирую…")
        });
        cx.notify();
        self.tasks
            .push(client::call(cx, req, |this, res, cx| match res {
                Ok(Response::Imported { report: r }) => {
                    cx.emit(SettingsEvent::Changed);
                    let mut text = tr!(
                        "Перенесено записей: {total} (логины {logins}, карты {cards}, заметки {notes}, папок {folders})",
                        total = r.total(),
                        logins = r.logins,
                        cards = r.cards,
                        notes = r.notes,
                        folders = r.folders
                    );
                    if !r.review.is_empty() {
                        text.push_str(&tr!(". Проверить вручную: {n}", n = r.review.len()));
                    }
                    this.other_path = None;
                    this.say(text, false, cx)
                }
                Ok(Response::Merged { summary }) => {
                    cx.emit(SettingsEvent::Changed);
                    this.other_path = None;
                    this.say(tr!("Слияние: {summary}", summary = summary), false, cx)
                }
                Ok(_) => this.say(tr!("Готово"), false, cx),
                Err(CallError::WrongKey(m)) => {
                    this.say(tr!("Ключ той базы не подошёл: {m}", m = m), true, cx)
                }
                Err(e) => this.say(e.message(), true, cx),
            }));
    }
}

enum Either<A, B> {
    Save(A),
    Open(B),
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

// --- отрисовка ---

/// Раздел настроек одной карточкой: шапка, строки через линии, подвал с кнопками.
/// Вкладки этой системы: связка ключей Secret Service есть только в Linux.
fn visible_tabs() -> &'static [usize] {
    if cfg!(target_os = "linux") {
        &[0, 1, 2, 3, 4, 5, 6]
    } else {
        &[0, 1, 2, 4, 5, 6]
    }
}

fn panel(theme: &gpui_kit::component::Theme) -> Div {
    v_flex()
        .rounded_lg()
        .border_1()
        .border_color(theme.border)
        .bg(theme.list_even)
        .overflow_hidden()
}

/// Шапка карточки: название и одна строка пояснения.
fn section(title: &'static str, hint: &'static str, theme: &gpui_kit::component::Theme) -> Div {
    v_flex()
        .px_4()
        .pt_3p5()
        .pb_3()
        .gap_0p5()
        .child(
            div()
                .text_sm()
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        )
        .child(
            div()
                .text_xs()
                .text_color(theme.muted_foreground)
                .child(hint),
        )
}

/// Строка: подпись слева, управление справа; линия сверху отделяет от предыдущей.
fn row(label: &'static str, control: impl IntoElement, theme: &gpui_kit::component::Theme) -> Div {
    h_flex()
        .gap_4()
        .px_4()
        .min_h(px(52.))
        .py_2()
        .border_t_1()
        .border_color(theme.table_row_border)
        .child(div().w(px(180.)).flex_shrink_0().text_sm().child(label))
        .child(div().flex_1().min_w_0().child(control))
}

/// Подвал карточки: кнопки справа, приглушённый фон.
fn footer(theme: &gpui_kit::component::Theme) -> Div {
    h_flex()
        .justify_end()
        .gap_2()
        .px_4()
        .py_2p5()
        .border_t_1()
        .border_color(theme.border)
        .bg(theme.sidebar)
}

fn card(_theme: &gpui_kit::component::Theme) -> Div {
    v_flex()
}

impl Render for SettingsPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let busy = self.busy.is_some();
        let body: AnyElement = match self.tab {
            0 => v_flex()
                .gap_6()
                .child(self.language_panel(&theme, cx))
                .child(panel(&theme)
                .child(section(
                    tr!("Общие"),
                    tr!("Хранятся в самой базе: одинаковы на всех устройствах и в KeePassXC"),
                    &theme,
                ))
                .child(
                    card(&theme)
                        .child(row(tr!("Имя хранилища"), Input::new(&self.name), &theme))
                        .child(row(tr!("Описание"), Input::new(&self.description), &theme))
                        .child(row(
                            tr!("Корзина"),
                            Switch::new("recycle")
                                .checked(self.recycle_bin)
                                .label(if self.recycle_bin {
                                    tr!("Удалённое сначала попадает в корзину")
                                } else {
                                    tr!("Удаление сразу окончательное")
                                })
                                .on_change(cx.listener(|this, v: &bool, _, cx| {
                                    this.recycle_bin = *v;
                                    cx.notify();
                                })),
                            &theme,
                        ))
                        .child(row(
                            tr!("Версий в истории"),
                            Input::new(&self.history_items),
                            &theme,
                        ))
                        .child(row(
                            tr!("Предел истории, МиБ"),
                            Input::new(&self.history_mib),
                            &theme,
                        )),
                )
                .child(
                    footer(&theme).child(
                        Button::new("save-general")
                            .primary()
                            .icon(IconName::Save)
                            .label(tr!("Сохранить"))
                            .loading(busy)
                            .on_click(cx.listener(|this, _, _, cx| this.save_settings(cx))),
                    ),
                ))
                .into_any_element(),
            1 => v_flex()
                .gap_6()
                .child(
                    panel(&theme)
                        .child(section(
                            tr!("Мастер-ключ"),
                            tr!("Текущий пароль спрашивается заново, даже если база открыта"),
                            &theme,
                        ))
                        .child(
                            card(&theme)
                                .child(row(
                                    tr!("Текущий пароль"),
                                    Input::new(&self.cur_pw).mask_toggle(),
                                    &theme,
                                ))
                                .child(row(
                                    tr!("Новый пароль"),
                                    Input::new(&self.new_pw).mask_toggle(),
                                    &theme,
                                ))
                                .child(row(
                                    tr!("Ещё раз"),
                                    Input::new(&self.new_pw2).mask_toggle(),
                                    &theme,
                                ))
                                .child(row(
                                    tr!("Файл-ключ"),
                                    h_flex()
                                        .gap_2()
                                        .child(div().flex_1().child(crate::ui::file_field(
                                            "new-keyfile",
                                            &self.new_keyfile,
                                            tr!("Без файла-ключа"),
                                            tr!("Файл-ключ"),
                                            IconName::Key,
                                            cx,
                                        )))
                                        .child(
                                            Button::new("mk-keyfile")
                                                .outline()
                                                .icon(IconName::KeySquare)
                                                .label(tr!("Создать новый"))
                                                .on_click(cx.listener(|this, _, w, cx| {
                                                    this.create_keyfile(w, cx)
                                                })),
                                        ),
                                    &theme,
                                ))
                                .child(row("YubiKey", h_flex().child(crate::ui::yubikey_slots("new-yk", &self.new_yubikey, cx)), &theme)),
                        )
                        .child(
                            footer(&theme).child(
                                Button::new("change-key")
                                    .primary()
                                    .icon(IconName::Lock)
                                    .label(tr!("Сменить ключ"))
                                    .loading(busy)
                                    .on_click(cx.listener(|this, _, w, cx| this.change_key(w, cx))),
                            ),
                        ),
                )
                .child(
                    panel(&theme)
                        .child(section(
                            tr!("Шифрование"),
                            tr!("Argon2id: чем больше памяти и итераций, тем дороже подбор пароля и дольше разблокировка"),
                            &theme,
                        ))
                        .child(
                            card(&theme)
                                .child(row(
                                    tr!("Шифр"),
                                    segmented(
                                        "cipher",
                                        vec![(None, "AES-256".into()), (None, "ChaCha20".into())],
                                        (self.cipher == Cipher::ChaCha20) as usize,
                                        cx,
                                        |this, ix, _, cx| {
                                            this.cipher = if ix == 1 {
                                                Cipher::ChaCha20
                                            } else {
                                                Cipher::Aes256
                                            };
                                            cx.notify();
                                        },
                                    ),
                                    &theme,
                                ))
                                .map(|d| match self.settings.as_ref().filter(|s| s.kdf == "aes") {
                                    Some(s) => d.child(row(
                                        tr!("Функция ключа"),
                                        div()
                                            .text_sm()
                                            .child(tr!(
                                                "AES-KDF, {n} раундов: старый формат KeePass. «Подобрать под этот компьютер» переведёт базу на Argon2id",
                                                n = s.kdf_iterations
                                            )),
                                        &theme,
                                    )),
                                    None => d
                                        .child(row(tr!("Память, МиБ"), Input::new(&self.kdf_mem), &theme))
                                        .child(row(tr!("Итерации"), Input::new(&self.kdf_iter), &theme))
                                        .child(row(tr!("Потоки"), Input::new(&self.kdf_par), &theme)),
                                }),
                        )
                        .child(
                            footer(&theme)
                                .gap_2()
                                .child(
                                    Button::new("tune")
                                        .outline()
                                        .icon(IconName::WandSparkles)
                                        .label(tr!("Подобрать под этот компьютер"))
                                        .on_click(cx.listener(|this, _, w, cx| this.tune(w, cx))),
                                )
                                .child(
                                    Button::new("save-crypto")
                                        .primary()
                                        .icon(IconName::Save)
                                        .label(tr!("Сохранить"))
                                        .loading(busy)
                                        .on_click(cx.listener(|this, _, _, cx| this.save_settings(cx))),
                                ),
                        ),
                )
                .into_any_element(),
            3 => self.keyring_tab(cx),
            4 => self.device_tab(cx),
            5 => self.ssh_tab(cx),
            6 => self.sync_tab(cx),
            _ => {
                let other = self
                    .other_path
                    .as_ref()
                    .map(|p| p.display().to_string());
                let kdbx = other
                    .as_deref()
                    .is_some_and(|p| p.ends_with(".kdbx") || p.ends_with(".kdb"));
                v_flex()
                    .gap_6()
                    .child(
                        panel(&theme)
                            .child(section(
                                tr!("Выгрузить"),
                                tr!("Копия .kdbx переносит всё без потерь; CSV понимают Bitwarden, 1Password и Proton Pass"),
                                &theme,
                            ))
                            .child(
                                card(&theme)
                                    .child(row(
                                        tr!("Копия базы .kdbx"),
                                        h_flex()
                                            .gap_2()
                                            .child(div().flex_1().child(Input::new(&self.copy_pw).mask_toggle()))
                                            .child(
                                                Button::new("copy-kdbx")
                                                    .outline()
                                                    .icon(IconName::Database)
                                                    .label(tr!("Сохранить копию"))
                                                    .on_click(cx.listener(|this, _, w, cx| this.save_copy(w, cx))),
                                            ),
                                        &theme,
                                    ))
                                    .child(row(
                                        "CSV",
                                        h_flex()
                                            .gap_3()
                                            .child(
                                                Button::new("export-csv")
                                                    .outline()
                                                    .icon(IconName::FileDown)
                                                    .label(tr!("Выгрузить в CSV"))
                                                    .on_click(cx.listener(|this, _, w, cx| this.export_csv(w, cx))),
                                            )
                                            .child(
                                                h_flex()
                                                    .gap_1()
                                                    .text_xs()
                                                    .text_color(theme.warning_foreground)
                                                    .child(Icon::new(IconName::ShieldAlert).small())
                                                    .child(tr!("пароли открытым текстом")),
                                            ),
                                        &theme,
                                    )),
                            ),
                    )
                    .child(
                        panel(&theme)
                            .child(section(
                                tr!("Загрузить"),
                                tr!("Импорт кладёт записи в новую папку. Слияние объединяет с копией этой же базы по истории правок"),
                                &theme,
                            ))
                            .child(
                                card(&theme)
                                    .child(row(
                                        tr!("Файл"),
                                        h_flex()
                                            .gap_2()
                                            .child(
                                                div()
                                                    .flex_1()
                                                    .min_w_0()
                                                    .truncate()
                                                    .text_sm()
                                                    .text_color(if other.is_some() {
                                                        theme.foreground
                                                    } else {
                                                        theme.muted_foreground
                                                    })
                                                    .child(other.clone().unwrap_or_else(|| {
                                                        tr!("CSV, .kdbx, .kdb или JSON Bitwarden").into()
                                                    })),
                                            )
                                            .child(
                                                Button::new("pick")
                                                    .outline()
                                                    .icon(IconName::FileUp)
                                                    .label(tr!("Выбрать файл"))
                                                    .on_click(cx.listener(|this, _, w, cx| this.pick_other(w, cx))),
                                            ),
                                        &theme,
                                    ))
                                    .when(kdbx, |d| {
                                        d.child(row(
                                            tr!("Пароль той базы"),
                                            Input::new(&self.other_pw).mask_toggle(),
                                            &theme,
                                        ))
                                    }),
                            )
                            .child(
                                footer(&theme)
                                    .gap_2()
                                    .child(
                                        Button::new("import")
                                            .primary()
                                            .icon(IconName::Import)
                                            .label(tr!("Импортировать"))
                                            .loading(busy)
                                            .on_click(cx.listener(|this, _, w, cx| {
                                                this.import_or_merge(false, w, cx)
                                            })),
                                    )
                                    .when(kdbx, |d| {
                                        d.child(
                                            Button::new("merge")
                                                .outline()
                                                .icon(IconName::Merge)
                                                .label(tr!("Слить с этой базой"))
                                                .on_click(cx.listener(|this, _, w, cx| {
                                                    this.import_or_merge(true, w, cx)
                                                })),
                                        )
                                    }),
                            ),
                    )
                    .into_any_element()
            }
        };
        v_flex()
            .id("settings")
            .key_context(CONTEXT)
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &TabGeneral, w, cx| this.set_tab(0, w, cx)))
            .on_action(cx.listener(|this, _: &TabSecurity, w, cx| this.set_tab(1, w, cx)))
            .on_action(cx.listener(|this, _: &TabTransfer, w, cx| this.set_tab(2, w, cx)))
            .on_action(cx.listener(|this, _: &TabKeyring, w, cx| this.set_tab(3, w, cx)))
            .on_action(cx.listener(|this, _: &TabDevice, w, cx| this.set_tab(4, w, cx)))
            .on_action(cx.listener(|this, _: &TabSsh, w, cx| this.set_tab(5, w, cx)))
            .on_action(cx.listener(|this, _: &TabSync, w, cx| this.set_tab(6, w, cx)))
            .size_full()
            .child(
                h_flex()
                    .size_full()
                    .items_start()
                    // разделы слева: список не переносится на узком окне и растёт вниз
                    .child(
                        v_flex()
                            .w(px(220.))
                            .h_full()
                            .flex_shrink_0()
                            .p_3()
                            .gap_0p5()
                            .border_r_1()
                            .border_color(theme.border)
                            .children(visible_tabs().iter().map(|&t| {
                                let (icon, label) = tab_label(t);
                                let on = t == self.tab;
                                h_flex()
                                    .id(("settings-tab", t))
                                    .gap_2p5()
                                    .px_3()
                                    .py_2()
                                    .rounded_md()
                                    .text_sm()
                                    .cursor_pointer()
                                    .when(on, |d| {
                                        d.bg(theme.list_active)
                                            .text_color(theme.foreground)
                                            .font_weight(FontWeight::MEDIUM)
                                    })
                                    .when(!on, |d| {
                                        d.text_color(theme.muted_foreground).hover(|s| {
                                            s.bg(theme.list_hover).text_color(theme.foreground)
                                        })
                                    })
                                    .on_click(
                                        cx.listener(move |this, _, w, cx| this.set_tab(t, w, cx)),
                                    )
                                    .child(
                                        Icon::new(icon)
                                            .small()
                                            .when(on, |i| i.text_color(theme.primary)),
                                    )
                                    .child(label)
                            })),
                    )
                    .child(
                        div()
                            .id("settings-scroll")
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_y_scroll()
                            .child(
                                v_flex()
                                    .w_full()
                                    .max_w(px(780.))
                                    .mx_auto()
                                    .p_6()
                                    .gap_5()
                                    .child(
                                        div()
                                            .text_lg()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .child(tab_label(self.tab).1),
                                    )
                                    .when_some(self.busy, |d, b| {
                                        d.child(
                                            h_flex()
                                                .gap_2()
                                                .text_sm()
                                                .text_color(theme.muted_foreground)
                                                .child(
                                                    gpui_kit::component::spinner::Spinner::new()
                                                        .small(),
                                                )
                                                .child(b),
                                        )
                                    })
                                    .when_some(
                                        self.message.clone().filter(|_| !busy),
                                        |d, (m, err)| {
                                            d.child(
                                                h_flex()
                                                    .gap_2()
                                                    .px_3()
                                                    .py_2()
                                                    .rounded_lg()
                                                    .border_1()
                                                    .border_color(if err {
                                                        theme.danger.opacity(0.35)
                                                    } else {
                                                        theme.success.opacity(0.35)
                                                    })
                                                    .bg(if err {
                                                        theme.danger.opacity(0.1)
                                                    } else {
                                                        theme.success.opacity(0.1)
                                                    })
                                                    .text_sm()
                                                    .child(
                                                        Icon::new(if err {
                                                            IconName::CircleAlert
                                                        } else {
                                                            IconName::CircleCheck
                                                        })
                                                        .small()
                                                        .text_color(if err {
                                                            theme.danger_foreground
                                                        } else {
                                                            theme.success_foreground
                                                        }),
                                                    )
                                                    .child(div().flex_1().child(m)),
                                            )
                                        },
                                    )
                                    .child(
                                        div().child(body).with_animation(
                                            ("settings-tab", self.tab),
                                            Animation::new(std::time::Duration::from_millis(160))
                                                .with_easing(ease_out_quint()),
                                            |el, t| el.opacity(t).mt(px(4. * (1. - t))),
                                        ),
                                    )
                                    .child(div().h_6()),
                            ),
                    ),
            )
    }
}

fn tab_label(t: usize) -> (IconName, &'static str) {
    match t {
        0 => (IconName::SlidersHorizontal, tr!("Общие")),
        1 => (IconName::Shield, tr!("Безопасность")),
        2 => (IconName::ArrowLeftRight, tr!("Перенос")),
        3 => (IconName::KeySquare, tr!("Связка ключей")),
        4 => (IconName::Monitor, tr!("Этот компьютер")),
        5 => (IconName::SquareTerminal, "SSH"),
        _ => (IconName::RefreshCw, tr!("Синхронизация")),
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}
