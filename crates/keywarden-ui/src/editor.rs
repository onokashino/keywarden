//! Редактор записи: поля по шаблону типа, свои поля, заметки, группа.
//! Сохраняет только изменённое (EntryPatch), всё прочее в записи остаётся как было.

use crate::client;
use gpui_kit::component::button::{Button, ButtonVariants as _, DropdownButton};
use gpui_kit::component::input::{Input, InputEvent, InputState, Textarea, TextareaState};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::ipc::{Request, Response};
use keywarden_core::model::{
    AutotypeView, EntryDetail, EntryKind, EntryPatch, FieldSet, GroupView, PASSKEY_PREFIX,
};
use keywarden_core::secret::Secret;
use keywarden_core::tr;
use keywarden_core::wallet;
use std::collections::HashMap;

actions!(editor, [SaveEntry, CancelEdit]);
pub const CONTEXT: &str = "EntryEditor";

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("ctrl-s", SaveEntry, Some(CONTEXT)),
        KeyBinding::new("ctrl-enter", SaveEntry, Some(CONTEXT)),
        KeyBinding::new("escape", CancelEdit, Some(CONTEXT)),
    ]);
}

pub enum EditorEvent {
    Saved(String),
    Cancelled,
    /// новая запись: выбрали другой тип, форму надо собрать заново
    ChangeKind(EntryKind),
}

impl EventEmitter<EditorEvent> for EntryEditor {}

struct Row {
    /// имя поля в KDBX; для новых своих полей берётся из `name_input`
    name: String,
    label: SharedString,
    value: Entity<InputState>,
    protected: bool,
    custom: Option<Entity<InputState>>,
}

pub struct EntryEditor {
    id: Option<String>,
    kind: EntryKind,
    group: Option<String>,
    groups: Vec<GroupView>,
    title: Entity<InputState>,
    tags: Entity<InputState>,
    expires: Entity<InputState>,
    original_tags: String,
    original_expires: String,
    // автоввод
    at_enabled: bool,
    at_sequence: Entity<InputState>,
    at_windows: Vec<(Entity<InputState>, Entity<InputState>)>,
    original_autotype: AutotypeView,
    show_autotype: bool,
    rows: Vec<Row>,
    /// кошелёк: сид-фраза и адреса многострочные (доли SLIP-39 и адреса по строке)
    seed: Option<Entity<TextareaState>>,
    addresses: Option<Entity<TextareaState>>,
    /// кошелёк: что храним (0 фраза, 1 приватный ключ, 2 только адреса), passphrase, «Дополнительно»
    wallet_mode: u8,
    wallet_pass: bool,
    wallet_more: bool,
    notes: Entity<TextareaState>,
    original: HashMap<String, String>,
    removed: Vec<String>,
    error: Option<SharedString>,
    saving: bool,
    tasks: Vec<Task<()>>,
    _subs: Vec<Subscription>,
}

impl EntryEditor {
    /// `detail`: запись с раскрытыми значениями (reveal) или `None` для новой.
    pub fn new(
        kind: EntryKind,
        detail: Option<&EntryDetail>,
        group: Option<String>,
        groups: Vec<GroupView>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut original = HashMap::new();
        let mut values: Vec<(String, String, bool)> = vec![];
        if let Some(d) = detail {
            original.insert("Title".into(), d.summary.title.clone());
            original.insert("Notes".into(), d.notes.clone());
            for f in &d.fields {
                let v = f
                    .value
                    .as_ref()
                    .map(|s| s.expose().to_string())
                    .unwrap_or_default();
                original.insert(f.name.clone(), v.clone());
                values.push((f.name.clone(), v, f.protected));
            }
        }
        let title = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("Название"))
                .default_value(detail.map(|d| d.summary.title.clone()).unwrap_or_default())
        });
        let original_tags = detail
            .map(|d| d.summary.tags.join(", "))
            .unwrap_or_default();
        let original_expires = detail.and_then(|d| d.expires.clone()).unwrap_or_default();
        let tags = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("через запятую: работа, банк"))
                .default_value(original_tags.clone())
        });
        let expires = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("ГГГГ-ММ-ДД, пусто: бессрочно"))
                .default_value(original_expires.clone())
        });
        let original_autotype = detail.map(|d| d.autotype.clone()).unwrap_or_default();
        let at_sequence = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("{USERNAME}{TAB}{PASSWORD}{ENTER}")
                .default_value(original_autotype.sequence.clone().unwrap_or_default())
        });
        let at_windows = original_autotype
            .windows
            .iter()
            .map(|(w, seq)| Self::at_row(w, seq, window, cx))
            .collect();
        let notes = cx.new(|cx| {
            TextareaState::new(window, cx)
                .auto_grow(3, 12)
                .placeholder(tr!("Заметки"))
                .default_value(detail.map(|d| d.notes.clone()).unwrap_or_default())
        });

        let wallet = kind == EntryKind::CryptoWallet;
        let multiline = |name: &str| wallet && (name == wallet::SEED || name == wallet::ADDRESSES);
        let value_of = |name: &str| {
            values
                .iter()
                .find(|(n, _, _)| n == name)
                .map(|(_, v, _)| v.clone())
                .unwrap_or_default()
        };
        let mut subs = vec![];
        let mut area =
            |name: &str, placeholder: &'static str, window: &mut Window, cx: &mut Context<Self>| {
                let v = value_of(name);
                let st = cx.new(|cx| {
                    TextareaState::new(window, cx)
                        .auto_grow(2, 8)
                        .placeholder(placeholder)
                        .default_value(v)
                });
                // проверка фразы и сети адресов пересчитываются на каждую правку
                subs.push(cx.subscribe(&st, |_, _, _: &InputEvent, cx| cx.notify()));
                st
            };
        let seed = wallet.then(|| {
            area(
                wallet::SEED,
                tr!("слова через пробел; доли SLIP-39 по одной на строку"),
                window,
                cx,
            )
        });
        let addresses = wallet.then(|| {
            area(
                wallet::ADDRESSES,
                tr!("по адресу на строку, подпись через двоеточие: основной: bc1q…"),
                window,
                cx,
            )
        });
        let has = |n: &str| !value_of(n).trim().is_empty();
        let wallet_mode = if has(wallet::SEED)
            || !has(wallet::PRIVATE_KEY) && !has(wallet::ADDRESSES) && !has(wallet::XPUB)
        {
            0
        } else if has(wallet::PRIVATE_KEY) {
            1
        } else {
            2
        };
        let wallet_pass = has(wallet::PASSPHRASE);
        let mut rows = vec![];
        // сначала поля шаблона (в т.ч. пустые), потом остальные поля записи
        for spec in kind.template() {
            if multiline(spec.name) {
                continue;
            }
            let (value, protected) = values
                .iter()
                .find(|(n, _, _)| n == spec.name)
                .map(|(_, v, p)| (v.clone(), *p || spec.protected))
                .unwrap_or_default();
            rows.push(Self::row(
                spec.name,
                spec.label,
                spec.hint,
                value,
                protected || spec.protected,
                false,
                window,
                cx,
            ));
        }
        for (name, value, protected) in &values {
            if kind.template().iter().any(|s| s.name == name) {
                continue;
            }
            // KPEX_PASSKEY_*: правка сломала бы ключ доступа, показываем только в карточке
            if name.starts_with(PASSKEY_PREFIX) {
                continue;
            }
            // пустые стандартные поля KeePass, которых нет в шаблоне типа, не мешаются
            if value.is_empty() && matches!(name.as_str(), "UserName" | "URL" | "Password") {
                continue;
            }
            rows.push(Self::row(
                name,
                name,
                "",
                value.clone(),
                *protected,
                true,
                window,
                cx,
            ));
        }

        Self {
            id: detail.map(|d| d.summary.id.clone()),
            kind,
            group,
            groups,
            title,
            tags,
            expires,
            original_tags,
            original_expires,
            at_enabled: original_autotype.enabled,
            at_sequence,
            at_windows,
            show_autotype: original_autotype != AutotypeView::default(),
            original_autotype,
            rows,
            seed,
            addresses,
            wallet_mode,
            wallet_pass,
            wallet_more: false,
            _subs: subs,
            notes,
            original,
            removed: vec![],
            error: None,
            saving: false,
            tasks: vec![],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn row(
        name: &str,
        label: &str,
        hint: &str,
        value: String,
        protected: bool,
        custom: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Row {
        let hint = SharedString::from(hint.to_string());
        let v = cx.new(|cx| {
            InputState::new(window, cx)
                .masked(protected)
                .placeholder(hint)
                .default_value(value)
        });
        let n = custom.then(|| {
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(tr!("Имя поля"))
                    .default_value(name.to_string())
            })
        });
        Row {
            name: name.into(),
            label: SharedString::from(label.to_string()),
            value: v,
            protected,
            custom: n,
        }
    }

    /// Что уже введено в новую запись (при смене типа переносится в новую форму).
    pub fn draft(&self, cx: &App) -> (String, String, Option<String>) {
        (
            self.title.read(cx).value().to_string(),
            self.tags.read(cx).value().to_string(),
            self.group.clone(),
        )
    }

    pub fn set_draft(
        &mut self,
        title: &str,
        tags: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.title
            .update(cx, |s, cx| s.set_value(title.to_string(), window, cx));
        self.tags
            .update(cx, |s, cx| s.set_value(tags.to_string(), window, cx));
    }

    pub fn focus_handle(&self, cx: &App) -> FocusHandle {
        self.title.read(cx).focus_handle(cx)
    }

    fn add_field(&mut self, protected: bool, window: &mut Window, cx: &mut Context<Self>) {
        let row = Self::row("", "", "", String::new(), protected, true, window, cx);
        if let Some(n) = &row.custom {
            let h = n.read(cx).focus_handle(cx);
            window.focus(&h, cx);
        }
        self.rows.push(row);
        cx.notify();
    }

    fn remove_field(&mut self, ix: usize, cx: &mut Context<Self>) {
        let row = self.rows.remove(ix);
        if self.original.contains_key(&row.name) {
            self.removed.push(row.name);
        }
        cx.notify();
    }

    fn generate_into(&mut self, ix: usize, window: &mut Window, cx: &mut Context<Self>) {
        let target = self.rows[ix].value.clone();
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::Generate {
                options: Default::default(),
            },
            move |_, res, window, cx| {
                if let Ok(Response::Generated { generated }) = res {
                    target.update(cx, |s, cx| {
                        s.set_value(generated.value.expose().to_string(), window, cx)
                    });
                }
            },
        ));
    }

    fn patch(&self, cx: &App) -> Result<EntryPatch, String> {
        let mut set = vec![];
        let mut push = |name: String, value: String, protected: bool| {
            if self.original.get(&name) != Some(&value) {
                set.push(FieldSet {
                    name,
                    value: Secret::new(value),
                    protected: Some(protected),
                });
            }
        };
        let title = self.title.read(cx).value().to_string();
        if title.trim().is_empty() {
            return Err(tr!("Название не может быть пустым").into());
        }
        push("Title".into(), title, false);
        push(
            "Notes".into(),
            self.notes.read(cx).value().to_string(),
            false,
        );
        if let Some(s) = &self.seed {
            // лишние пробелы и пустые строки не меняют фразу
            let v: Vec<String> = s
                .read(cx)
                .value()
                .lines()
                .map(|l| {
                    l.split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .to_lowercase()
                })
                .filter(|l| !l.is_empty())
                .collect();
            push(wallet::SEED.into(), v.join("\n"), true);
        }
        if let Some(a) = &self.addresses {
            push(
                wallet::ADDRESSES.into(),
                a.read(cx).value().trim().to_string(),
                false,
            );
        }
        let mut removed = self.removed.clone();
        for r in &self.rows {
            let name = match &r.custom {
                Some(n) => n.read(cx).value().trim().to_string(),
                None => r.name.clone(),
            };
            let value = r.value.read(cx).value().to_string();
            if name.is_empty() {
                if !value.is_empty() {
                    return Err(tr!("У своего поля нет имени").into());
                }
                continue;
            }
            if matches!(name.as_str(), "Title" | "Notes") {
                return Err(tr!("Имя «{name}» зарезервировано", name = name));
            }
            // поле переименовали: старое имя удаляем
            if r.custom.is_some() && !r.name.is_empty() && r.name != name {
                removed.push(r.name.clone());
            }
            push(name, value, r.protected);
        }
        let tags_text = self.tags.read(cx).value().to_string();
        let tags = (tags_text.trim() != self.original_tags.trim()).then(|| {
            let mut v: Vec<String> = tags_text
                .split([',', ';'])
                .map(|t| t.trim().trim_start_matches('#').to_string())
                .filter(|t| !t.is_empty())
                .collect();
            v.dedup();
            v
        });
        let exp = self.expires.read(cx).value().trim().to_string();
        let expires = (exp != self.original_expires).then(|| (!exp.is_empty()).then_some(exp));
        let seq = self.at_sequence.read(cx).value().trim().to_string();
        let at = AutotypeView {
            enabled: self.at_enabled,
            sequence: (!seq.is_empty()).then_some(seq),
            windows: self
                .at_windows
                .iter()
                .map(|(w, s)| {
                    (
                        w.read(cx).value().trim().to_string(),
                        s.read(cx).value().trim().to_string(),
                    )
                })
                .filter(|(w, _)| !w.is_empty())
                .collect(),
        };
        let autotype = (at != self.original_autotype).then_some(at);
        Ok(EntryPatch {
            kind: Some(self.kind),
            group: self.group.clone(),
            tags,
            set,
            remove: removed,
            expires,
            autotype,
        })
    }

    fn at_row(
        window_pattern: &str,
        sequence: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> (Entity<InputState>, Entity<InputState>) {
        let (w, s) = (window_pattern.to_string(), sequence.to_string());
        (
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(tr!("*Банк* - Firefox"))
                    .default_value(w)
            }),
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(tr!("своя последовательность (необязательно)"))
                    .default_value(s)
            }),
        )
    }

    fn render_autotype(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let theme = cx.theme().clone();
        if !self.show_autotype {
            return None;
        }
        let label = |t: &'static str| {
            div()
                .w(px(150.))
                .flex_shrink_0()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(t)
        };
        let panel = v_flex()
            .gap_3()
            .p_4()
            .rounded_xl()
            .border_1()
            .border_color(theme.border)
            .bg(theme.list_even)
            .child(
                h_flex()
                    .gap_3()
                    .child(label(tr!("Автоввод")))
                    .child(
                        gpui_kit::component::switch::Switch::new("at-enabled")
                            .checked(self.at_enabled)
                            .label(if self.at_enabled { tr!("Разрешён (Mod+Shift+A)") } else { tr!("Выключен для этой записи") })
                            .on_change(cx.listener(|this, v: &bool, _, cx| {
                                this.at_enabled = *v;
                                cx.notify();
                            })),
                    ),
            )
            .child(
                h_flex()
                    .gap_3()
                    .child(label(tr!("Последовательность")))
                    .child(div().flex_1().child(Input::new(&self.at_sequence))),
            )
            .child(
                div()
                    .pl(px(162.))
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(tr!("{USERNAME} {PASSWORD} {TOTP} {S:Поле} {TAB} {ENTER} {DELAY 500}; пусто: логин, Tab, пароль, Enter")),
            )
            .children(self.at_windows.iter().enumerate().map(|(ix, (w, s))| {
                h_flex()
                    .gap_3()
                    .child(label(if ix == 0 { tr!("Окна") } else { "" }))
                    .child(div().flex_1().child(Input::new(w)))
                    .child(div().flex_1().child(Input::new(s)))
                    .child(
                        Button::new(("at-rm", ix))
                            .ghost()
                            .icon(IconName::Trash)
                            .tooltip(tr!("Убрать привязку"))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if ix < this.at_windows.len() {
                                    this.at_windows.remove(ix);
                                }
                                cx.notify();
                            })),
                    )
            }))
            .child(
                h_flex()
                    .pl(px(162.))
                    .gap_3()
                    .child(
                        Button::new("at-add")
                            .outline()
                            .icon(IconName::Plus)
                            .label(tr!("Привязать к окну"))
                            .on_click(cx.listener(|this, _, w, cx| {
                                let row = Self::at_row("", "", w, cx);
                                this.at_windows.push(row);
                                cx.notify();
                            })),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(tr!("заголовок окна, * любая часть: так запись найдётся и без адреса")),
                    ),
            )
            .into_any_element();
        Some(panel)
    }

    /// Кошелёк: что храним и быстрый выбор типа.
    fn render_wallet_head(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        v_flex()
            .gap_3()
            .child(
                h_flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(150.))
                            .flex_shrink_0()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Что храним")),
                    )
                    .child(crate::ui::segmented(
                        "wallet-mode",
                        vec![
                            (None, tr!("Сид-фраза").into()),
                            (None, tr!("Приватный ключ").into()),
                            (None, tr!("Только адреса").into()),
                        ],
                        self.wallet_mode as usize,
                        cx,
                        |this, ix, _, cx| {
                            this.wallet_mode = ix as u8;
                            cx.notify();
                        },
                    )),
            )
            .into_any_element()
    }

    /// Быстрый выбор под полем «Тип кошелька».
    fn render_wallet_presets(&self) -> Option<AnyElement> {
        let input = self
            .rows
            .iter()
            .find(|r| r.name == wallet::WALLET_TYPE)
            .map(|r| r.value.clone())?;
        let presets = [
            "MetaMask",
            "Trust Wallet",
            "Ledger",
            "Trezor",
            "Phantom",
            "Electrum",
            "Exodus",
            "TronLink",
        ];
        Some(
            h_flex()
                .pl(px(162.))
                .mt(px(-8.))
                .gap_1p5()
                .flex_wrap()
                .children(presets.into_iter().enumerate().map(|(i, p)| {
                    let input = input.clone();
                    Button::new(("wt", i))
                        .outline()
                        .xsmall()
                        .label(p)
                        .on_click(move |_, w, cx| input.update(cx, |s, cx| s.set_value(p, w, cx)))
                }))
                .into_any_element(),
        )
    }

    fn open_seed_gen(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let generator = cx.new(|_| crate::seed_gen::SeedGen::new());
        let seed = self.seed.clone();
        self._subs.push(
            cx.subscribe_in(&generator, window, move |_, _, ev, window, cx| {
                if let crate::seed_gen::SeedGenEvent::Done(phrase) = ev
                    && let Some(st) = &seed
                {
                    st.update(cx, |st, cx| {
                        st.set_value(phrase.expose().to_string(), window, cx)
                    });
                }
                window.close_dialog(cx);
            }),
        );
        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .w(px(620.))
                .child(generator.clone())
        });
    }

    /// Блок кошелька: фраза с проверкой и подсказками слов, адреса с сетями.
    fn render_wallet(&mut self, cx: &mut Context<Self>) -> Option<(AnyElement, AnyElement)> {
        let (seed, addrs) = (self.seed.clone()?, self.addresses.clone()?);
        let theme = cx.theme().clone();
        let text = seed.read(cx).value().to_string();
        let check = wallet::check_seed(&text);
        // подсказка для слова, которое сейчас набирают
        let partial = (!text.ends_with(char::is_whitespace))
            .then(|| {
                text.split_whitespace()
                    .last()
                    .unwrap_or_default()
                    .to_string()
            })
            .filter(|w| !w.is_empty() && !wallet::is_bip39_word(w));
        let suggestions = partial
            .as_deref()
            .map(|p| wallet::suggest(p, 6))
            .unwrap_or_default();
        let status = if text.trim().is_empty() {
            None
        } else {
            let color = if check.valid && check.complete {
                theme.success_foreground
            } else if check.valid {
                theme.warning_foreground
            } else {
                theme.danger_foreground
            };
            Some(
                h_flex()
                    .gap_2()
                    .text_xs()
                    .child(crate::ui::badge(check.label.clone(), color))
                    .child(div().text_color(color).child(check.message.clone())),
            )
        };
        let label = |t: &'static str| {
            div()
                .w(px(150.))
                .flex_shrink_0()
                .pt_1p5()
                .text_sm()
                .text_color(theme.muted_foreground)
                .child(t)
        };
        let addr_list: Vec<(String, String)> = wallet::parse_addresses(&addrs.read(cx).value());
        Some((
            h_flex()
                .gap_3()
                .items_start()
                .child(label(tr!("Сид-фраза")))
                .child(
                    v_flex()
                        .flex_1()
                        .gap_2()
                        .child(Textarea::new(&seed))
                        .when(!suggestions.is_empty(), |d| {
                            d.child(h_flex().gap_1p5().flex_wrap().children(
                                suggestions.into_iter().enumerate().map(|(i, w)| {
                                    let seed = seed.clone();
                                    Button::new(("sug", i))
                                        .outline()
                                        .xsmall()
                                        .label(w)
                                        .on_click(move |_, window, cx| {
                                            // дописать слово вместо начатого
                                            let cur = seed.read(cx).value().to_string();
                                            let cut = cur
                                                .rfind(char::is_whitespace)
                                                .map(|i| i + 1)
                                                .unwrap_or(0);
                                            let next = format!("{}{w} ", &cur[..cut]);
                                            seed.update(cx, |s, cx| s.set_value(next, window, cx));
                                        })
                                }),
                            ))
                        })
                        .children(status)
                        .child(
                            h_flex().child(
                                Button::new("seed-gen")
                                    .ghost()
                                    .small()
                                    .icon(IconName::WandSparkles)
                                    .label(tr!("Сгенерировать новую фразу"))
                                    .on_click(
                                        cx.listener(|this, _, w, cx| this.open_seed_gen(w, cx)),
                                    ),
                            ),
                        ),
                )
                .into_any_element(),
            h_flex()
                .gap_3()
                .items_start()
                .child(label(tr!("Адреса")))
                .child(
                    v_flex()
                        .flex_1()
                        .gap_1p5()
                        .child(Textarea::new(&addrs))
                        .children(addr_list.into_iter().map(|(l, a)| {
                            let nets = wallet::address_networks(&a);
                            h_flex()
                                .gap_2()
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child(if nets.is_empty() {
                                    crate::ui::badge(
                                        tr!("сеть не распознана"),
                                        theme.warning_foreground,
                                    )
                                } else {
                                    crate::ui::badge(
                                        nets.join(" · ").to_uppercase(),
                                        theme.info_foreground,
                                    )
                                })
                                .when(!l.is_empty(), |d| d.child(l))
                                .child(div().truncate().child(a))
                        })),
                )
                .into_any_element(),
        ))
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        if self.saving {
            return;
        }
        let patch = match self.patch(cx) {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(e.into());
                cx.notify();
                return;
            }
        };
        self.saving = true;
        self.error = None;
        let req = match &self.id {
            Some(id) => Request::Update {
                id: id.clone(),
                patch,
            },
            None => Request::Add { patch },
        };
        let known = self.id.clone();
        self.tasks.push(client::call(cx, req, move |this, res, cx| {
            this.saving = false;
            match res {
                Ok(Response::Created { id }) => cx.emit(EditorEvent::Saved(id)),
                Ok(_) => cx.emit(EditorEvent::Saved(known.unwrap_or_default())),
                Err(e) => this.error = Some(e.message().into()),
            }
            cx.notify();
        }));
        cx.notify();
    }
}

impl Render for EntryEditor {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let group_label: SharedString = self
            .group
            .as_ref()
            .and_then(|g| self.groups.iter().find(|v| &v.id == g))
            .map(|g| {
                if g.path.is_empty() {
                    tr!("Корень").to_string()
                } else {
                    g.path.clone()
                }
            })
            .unwrap_or_else(|| tr!("Корень").into())
            .into();
        let groups = self.groups.clone();
        let cur_group = self.group.clone();
        let entity = cx.entity();

        let (wallet_seed, wallet_addr) = match self.render_wallet(cx) {
            Some((a, b)) => (Some(a), Some(b)),
            None => (None, None),
        };
        let wallet_kind = self.kind == EntryKind::CryptoWallet;
        let names: Vec<String> = self.rows.iter().map(|r| r.name.clone()).collect();
        let rows: Vec<AnyElement> = self
            .rows
            .iter()
            .enumerate()
            .map(|(ix, r)| {
                let is_password = r.name == "Password";
                let label = match &r.custom {
                    // своё имя правится на месте, но выглядит как подпись
                    Some(n) => div()
                        // внутренний отступ поля: текст на одной линии с подписями
                        .ml(px(-10.))
                        .child(Input::new(n).appearance(false))
                        .into_any_element(),
                    None => div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child(r.label.clone())
                        .into_any_element(),
                };
                h_flex()
                    .gap_3()
                    .items_center()
                    .child(div().w(px(150.)).flex_shrink_0().child(label))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_1()
                            .child(
                                Input::new(&r.value)
                                    .when(r.protected, |i| i.mask_toggle())
                                    // корзина внутри поля: правый край как у остальных
                                    .when(r.custom.is_some(), |i| {
                                        i.suffix(
                                            Button::new(("rm", ix))
                                                .ghost()
                                                .xsmall()
                                                .icon(IconName::Trash)
                                                .tooltip(tr!("Удалить поле"))
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.remove_field(ix, cx)
                                                })),
                                        )
                                    })
                                    .when(is_password, |i| {
                                        i.suffix(
                                            Button::new(("gen", ix))
                                                .ghost()
                                                .xsmall()
                                                .icon(IconName::WandSparkles)
                                                .tooltip(tr!("Сгенерировать"))
                                                .on_click(cx.listener(move |this, _, w, cx| {
                                                    this.generate_into(ix, w, cx)
                                                })),
                                        )
                                    }),
                            )
                            // подсказка под полем, а не сбоку: поле не сжимается
                            .when_some(
                                (r.name == wallet::PRIVATE_KEY || r.name == wallet::XPUB)
                                    .then(|| r.value.read(cx).value().to_string())
                                    .filter(|v| !v.trim().is_empty()),
                                |d, v| {
                                    let hint = if r.name == wallet::XPUB {
                                        xpub_hint(&v)
                                    } else {
                                        wallet::private_key_format(&v)
                                            .unwrap_or_else(|| tr!("формат не распознан").into())
                                    };
                                    d.child(
                                        div()
                                            .text_xs()
                                            .text_color(theme.muted_foreground)
                                            .child(hint),
                                    )
                                },
                            ),
                    )
            })
            .map(|e| e.into_any_element())
            .collect();
        // кошелёк: строки по группам; у остальных типов всё как было
        let custom: Vec<bool> = self.rows.iter().map(|r| r.custom.is_some()).collect();
        let (mut type_row, mut main_rows, mut more_rows) = (vec![], vec![], vec![]);
        let mut custom_rows = vec![];
        for ((name, el), is_custom) in names.into_iter().zip(rows).zip(custom) {
            if !wallet_kind && is_custom {
                custom_rows.push(el);
            } else if !wallet_kind {
                main_rows.push(el);
            } else if name == wallet::WALLET_TYPE {
                type_row.push(el);
            } else if (name == wallet::PASSPHRASE && self.wallet_mode == 0 && self.wallet_pass)
                || (name == wallet::PRIVATE_KEY && self.wallet_mode == 1)
                || (name == wallet::XPUB && self.wallet_mode == 2)
            {
                main_rows.push(el);
            } else if name != wallet::PASSPHRASE && name != wallet::PRIVATE_KEY {
                more_rows.push(el);
            }
        }
        let show_extras = !wallet_kind || self.wallet_more;
        let wallet_head = wallet_kind.then(|| self.render_wallet_head(cx));

        let form = v_flex()
            .key_context(CONTEXT)
            .on_action(cx.listener(|this, _: &SaveEntry, _, cx| this.save(cx)))
            .on_action(cx.listener(|_, _: &CancelEdit, _, cx| cx.emit(EditorEvent::Cancelled)))
            .gap_4()
            .p_6()
            .child(
                h_flex()
                    .gap_3()
                    .child(crate::ui::icon_tile(
                        crate::ui::kind_icon(self.kind),
                        44.,
                        &theme,
                    ))
                    .child(div().flex_1().child(Input::new(&self.title).large()))
                    .when(self.id.is_some(), |d| {
                        d.child(
                            gpui_kit::component::tag::Tag::secondary()
                                .small()
                                .child(self.kind.label()),
                        )
                    }),
            )
            // у новой записи тип можно сменить, пока она не сохранена
            .when(self.id.is_none(), |d| {
                let e = entity.clone();
                let current = self.kind;
                d.child(
                    h_flex()
                        .gap_3()
                        .child(
                            div()
                                .w(px(150.))
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(tr!("Тип")),
                        )
                        .child(
                            DropdownButton::new("kind")
                                .button(
                                    Button::new("kind-btn")
                                        .outline()
                                        .icon(crate::ui::kind_icon(self.kind))
                                        .label(self.kind.label()),
                                )
                                .dropdown_menu_with_anchor(Anchor::TopLeft, move |menu, _, _| {
                                    let mut menu = menu.min_w(px(240.));
                                    // ключ доступа создаёт сайт, вручную его не завести
                                    for k in EntryKind::ALL
                                        .into_iter()
                                        .filter(|k| *k != EntryKind::Passkey)
                                    {
                                        let e = e.clone();
                                        menu =
                                            menu.item(
                                                gpui_kit::component::menu::PopupMenuItem::new(
                                                    k.label(),
                                                )
                                                .icon(crate::ui::kind_icon(k))
                                                .checked(k == current)
                                                .on_click(move |_, _, cx| {
                                                    e.update(cx, |_, cx| {
                                                        cx.emit(EditorEvent::ChangeKind(k))
                                                    });
                                                }),
                                            );
                                    }
                                    menu
                                }),
                        ),
                )
            })
            .child(
                h_flex()
                    .gap_3()
                    .child(
                        div()
                            .w(px(150.))
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Папка")),
                    )
                    .child(
                        DropdownButton::new("group")
                            .button(
                                Button::new("group-btn")
                                    .outline()
                                    .icon(IconName::FolderOpen)
                                    .label(group_label),
                            )
                            .dropdown_menu_with_anchor(Anchor::TopLeft, move |menu, _, _| {
                                let mut menu = menu.min_w(px(240.));
                                for g in groups.iter().filter(|g| !g.is_recycle_bin) {
                                    let id = (g.depth > 0).then(|| g.id.clone());
                                    let label = if g.depth == 0 {
                                        tr!("Корень").to_string()
                                    } else {
                                        format!("{}{}", "  ".repeat(g.depth - 1), g.name)
                                    };
                                    let e = entity.clone();
                                    let checked = id == cur_group;
                                    menu = menu.item(
                                        gpui_kit::component::menu::PopupMenuItem::new(label)
                                            .checked(checked)
                                            .on_click(move |_, _, cx| {
                                                e.update(cx, |this, cx| {
                                                    this.group = id.clone();
                                                    cx.notify();
                                                });
                                            }),
                                    );
                                }
                                menu
                            }),
                    ),
            )
            .children(wallet_head)
            .children(type_row)
            .children(wallet_kind.then(|| self.render_wallet_presets()).flatten())
            .when(!wallet_kind || self.wallet_mode == 0, |d| {
                d.children(wallet_seed)
            })
            .when(
                wallet_kind && self.wallet_mode == 0 && !self.wallet_pass,
                |d| {
                    d.child(
                        h_flex().pl(px(162.)).child(
                            Button::new("add-pass")
                                .ghost()
                                .small()
                                .icon(IconName::Plus)
                                .label(tr!("Есть passphrase (25-е слово)"))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.wallet_pass = true;
                                    cx.notify();
                                })),
                        ),
                    )
                },
            )
            .children(main_rows)
            .children(wallet_addr)
            .when(wallet_kind, |d| {
                d.child(
                    h_flex().child(
                        Button::new("more")
                            .ghost()
                            .small()
                            .icon(if self.wallet_more {
                                IconName::ChevronDown
                            } else {
                                IconName::ChevronRight
                            })
                            .label(if self.wallet_mode == 2 {
                                tr!("Дополнительно: сети, путь, пароль приложения, теги")
                            } else {
                                tr!("Дополнительно: сети, путь, xpub, пароль приложения, теги")
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.wallet_more = !this.wallet_more;
                                cx.notify();
                            })),
                    ),
                )
            })
            .when(wallet_kind && self.wallet_more, |d| d.children(more_rows))
            .when(show_extras, |d| {
                d.child(
                    h_flex()
                        .gap_3()
                        .child(
                            div()
                                .w(px(150.))
                                .flex_shrink_0()
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(tr!("Теги")),
                        )
                        .child(div().flex_1().child(Input::new(&self.tags))),
                )
            })
            .when(show_extras, |d| {
                d.child(
                    h_flex()
                        .gap_3()
                        .child(
                            div()
                                .w(px(150.))
                                .flex_shrink_0()
                                .text_sm()
                                .text_color(theme.muted_foreground)
                                .child(tr!("Срок действия")),
                        )
                        .child(div().flex_1().child(Input::new(&self.expires)))
                        .child(
                            Button::new("exp-year")
                                .outline()
                                .label(tr!("+1 год"))
                                .tooltip(tr!("Через год от сегодня"))
                                .on_click(cx.listener(|this, _, w, cx| {
                                    let d =
                                        chrono::Local::now().date_naive() + chrono::Days::new(365);
                                    this.expires.update(cx, |i, cx| {
                                        i.set_value(d.format("%Y-%m-%d").to_string(), w, cx)
                                    });
                                })),
                        ),
                )
            })
            // свои поля отдельно от полей типа
            .when(!custom_rows.is_empty(), |d| {
                d.child(
                    v_flex()
                        .gap_4()
                        .pt_3()
                        .border_t_1()
                        .border_color(theme.border.opacity(0.6))
                        .child(
                            div()
                                .text_xs()
                                .font_weight(FontWeight::MEDIUM)
                                .text_color(theme.muted_foreground)
                                .child(tr!("СВОИ ПОЛЯ")),
                        )
                        .children(custom_rows),
                )
            })
            // дополнительные действия: тихий ряд под полями, отделённый линией
            .when(show_extras || (!wallet_kind && !self.show_autotype), |d| {
                d.child(
                    h_flex()
                        .pt_3()
                        .pl(px(160.))
                        .gap_1()
                        .flex_wrap()
                        .border_t_1()
                        .border_color(theme.border.opacity(0.6))
                        .when(show_extras, |d| {
                            d.child(
                                Button::new("add-field")
                                    .ghost()
                                    .small()
                                    .icon(IconName::Plus)
                                    .label(tr!("Поле"))
                                    .on_click(
                                        cx.listener(|this, _, w, cx| this.add_field(false, w, cx)),
                                    ),
                            )
                            .child(
                                Button::new("add-secret")
                                    .ghost()
                                    .small()
                                    .icon(IconName::Lock)
                                    .label(tr!("Скрытое поле"))
                                    .on_click(
                                        cx.listener(|this, _, w, cx| this.add_field(true, w, cx)),
                                    ),
                            )
                        })
                        .when(!wallet_kind && !self.show_autotype, |d| {
                            d.child(
                                Button::new("at-open")
                                    .ghost()
                                    .small()
                                    .icon(IconName::Keyboard)
                                    .label(tr!("Автоввод"))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.show_autotype = true;
                                        cx.notify();
                                    })),
                            )
                        }),
                )
            })
            .when(!wallet_kind, |d| d.children(self.render_autotype(cx)))
            .child(
                v_flex()
                    .gap_1()
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Заметки")),
                    )
                    .child(Textarea::new(&self.notes)),
            );
        // кнопки всегда видны внизу, форма прокручивается над ними
        // подсказка и ошибка слева, кнопки справа, главная крайняя (как в диалогах)
        let footer = h_flex()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(tr!("Ctrl+S сохранить · Esc отмена")),
            )
            .when_some(self.error.clone(), |d, e| {
                d.child(div().text_sm().text_color(theme.danger).child(e))
            })
            .child(
                Button::new("cancel")
                    .ghost()
                    .label(tr!("Отмена"))
                    .on_click(cx.listener(|_, _, _, cx| cx.emit(EditorEvent::Cancelled))),
            )
            .child(
                Button::new("save")
                    .primary()
                    .icon(IconName::Save)
                    .loading(self.saving)
                    .label(if self.saving {
                        tr!("Сохраняю…")
                    } else {
                        tr!("Сохранить")
                    })
                    .on_click(cx.listener(|this, _, _, cx| this.save(cx))),
            );
        v_flex()
            .size_full()
            .child(
                div()
                    .id("editor-body")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .child(form),
            )
            .child(
                footer
                    .flex_shrink_0()
                    .px_6()
                    .py_3()
                    .border_t_1()
                    .border_color(theme.border)
                    .bg(theme.background),
            )
    }
}

/// Подсказка под полем xpub: какая сеть и вид адресов, или почему не читается.
fn xpub_hint(text: &str) -> String {
    match keywarden_core::wallet_derive::parse_xpub(text) {
        Ok(x) => match x.script {
            Some(sc) => tr!(
                "{coin} {script}, адреса покажутся в записи",
                coin = x.coin.label(),
                script = format!("{sc:?}")
            ),
            None => tr!("xpub: вид адреса выберете в записи").into(),
        },
        Err(e) => e,
    }
}
