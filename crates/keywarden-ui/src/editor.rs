//! Редактор записи: поля по шаблону типа, свои поля, заметки, группа.
//! Сохраняет только изменённое (EntryPatch), всё прочее в записи остаётся как было.

use crate::client;
use gpui_kit::component::button::{Button, ButtonVariants as _, DropdownButton};
use gpui_kit::component::calendar::Date;
use gpui_kit::component::date_picker::{DatePicker, DatePickerEvent, DatePickerState};
use gpui_kit::component::input::{Input, InputEvent, InputState, Textarea, TextareaState};
use gpui_kit::component::tag::Tag;
use gpui_kit::component::{ActiveTheme as _, Sizable as _, WindowExt as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::card;
use keywarden_core::ipc::{Request, Response};
use keywarden_core::model::{
    self, AutotypeView, EntryDetail, EntryKind, EntryPatch, FieldSet, GroupView, PASSKEY_PREFIX,
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
    /// поле для нового тега: Enter или запятая превращают набранное в плашку
    tags: Entity<InputState>,
    tag_list: Vec<String>,
    /// теги, которые уже есть в базе: подсказки под полем
    known_tags: Vec<String>,
    original_tags: Vec<String>,
    expires: Entity<DatePickerState>,
    original_expires: String,
    /// правило совпадения адреса для браузера (`model::URL_MATCH`); пусто: весь домен
    url_match: String,
    /// карта: тип следует за номером, пока его не выбрали вручную
    auto_brand: bool,
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
        known_tags: Vec<String>,
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
        let original_tags: Vec<String> = detail.map(|d| d.summary.tags.clone()).unwrap_or_default();
        let original_expires = detail.and_then(|d| d.expires.clone()).unwrap_or_default();
        let tags = cx.new(|cx| InputState::new(window, cx).placeholder(tr!("Новый тег и Enter")));
        let expires = cx.new(|cx| {
            let ru = keywarden_core::i18n::current() == "ru";
            DatePickerState::new(window, cx)
                .date_format(if ru { "%d.%m.%Y" } else { "%Y-%m-%d" })
                .first_day_of_week(if ru {
                    chrono::Weekday::Mon
                } else {
                    chrono::Weekday::Sun
                })
        });
        if let Ok(d) = chrono::NaiveDate::parse_from_str(&original_expires, "%Y-%m-%d") {
            expires.update(cx, |s, cx| s.set_date(d, window, cx));
        }
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
        let mut subs = vec![
            cx.subscribe_in(
                &tags,
                window,
                |this, _, ev: &InputEvent, window, cx| match ev {
                    InputEvent::Change => this.commit_tags(false, window, cx),
                    InputEvent::PressEnter { .. } => this.commit_tags(true, window, cx),
                    _ => {}
                },
            ),
            cx.subscribe(&expires, |_, _, _: &DatePickerEvent, cx| cx.notify()),
        ];
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
            // правило совпадения адреса правится своим списком, а не строкой
            if name == model::URL_MATCH {
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

        let url_match = value_of(model::URL_MATCH).trim().to_lowercase();
        let auto_brand = {
            let b = value_of("Brand");
            b.trim().is_empty() || card::brand(&value_of("Card Number")) == Some(b.trim())
        };
        if kind == EntryKind::Card {
            // тип карты и подсказки под номером и сроком следуют за вводом
            for r in rows
                .iter()
                .filter(|r: &&Row| matches!(r.name.as_str(), "Card Number" | "Expiry"))
            {
                subs.push(cx.subscribe_in(
                    &r.value,
                    window,
                    |this, _, ev: &InputEvent, window, cx| {
                        if matches!(ev, InputEvent::Change) {
                            this.follow_card_number(window, cx);
                        }
                    },
                ));
            }
        }

        Self {
            id: detail.map(|d| d.summary.id.clone()),
            kind,
            group,
            groups,
            title,
            tags,
            tag_list: original_tags.clone(),
            known_tags,
            expires,
            original_tags,
            original_expires,
            url_match,
            auto_brand,
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
    pub fn draft(&self, cx: &App) -> (String, Vec<String>, Option<String>) {
        (
            self.title.read(cx).value().to_string(),
            self.final_tags(cx),
            self.group.clone(),
        )
    }

    pub fn set_draft(
        &mut self,
        title: &str,
        tags: &[String],
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.title
            .update(cx, |s, cx| s.set_value(title.to_string(), window, cx));
        self.tag_list = tags.to_vec();
    }

    fn add_tag(&mut self, tag: &str) {
        let tag = tag.trim().trim_start_matches('#').trim();
        if !tag.is_empty()
            && !self
                .tag_list
                .iter()
                .any(|t| t.to_lowercase() == tag.to_lowercase())
        {
            self.tag_list.push(tag.to_string());
        }
    }

    /// Набранное в поле тегов становится плашками. `all`: Enter, уходит всё; иначе только то,
    /// что уже отделено запятой, а недописанный хвост остаётся в поле.
    fn commit_tags(&mut self, all: bool, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.tags.read(cx).value().to_string();
        if all || text.contains([',', ';']) {
            let mut parts: Vec<&str> = text.split([',', ';']).collect();
            let rest = if all {
                ""
            } else {
                parts.pop().unwrap_or_default()
            };
            for p in parts {
                self.add_tag(p);
            }
            let rest = rest.trim_start().to_string();
            self.tags.update(cx, |s, cx| s.set_value(rest, window, cx));
        }
        // подсказки под полем фильтруются по набранному
        cx.notify();
    }

    /// Плашки и то, что осталось недописанным в поле.
    fn final_tags(&self, cx: &App) -> Vec<String> {
        let mut out = self.tag_list.clone();
        for p in self.tags.read(cx).value().split([',', ';']) {
            let p = p.trim().trim_start_matches('#').trim();
            if !p.is_empty() && !out.iter().any(|t| t.to_lowercase() == p.to_lowercase()) {
                out.push(p.to_string());
            }
        }
        out
    }

    fn row_value(&self, name: &str, cx: &App) -> String {
        self.rows
            .iter()
            .find(|r| r.name == name && r.custom.is_none())
            .map(|r| r.value.read(cx).value().to_string())
            .unwrap_or_default()
    }

    fn set_brand(&mut self, brand: &str, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(r) = self.rows.iter().find(|r| r.name == "Brand") {
            let brand = brand.to_string();
            r.value.update(cx, |s, cx| s.set_value(brand, window, cx));
        }
        cx.notify();
    }

    fn follow_card_number(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.auto_brand {
            let b = card::brand(&self.row_value("Card Number", cx)).unwrap_or_default();
            if self.row_value("Brand", cx) != b {
                return self.set_brand(b, window, cx);
            }
        }
        cx.notify();
    }

    /// Замечание под полем карты: (текст, это предупреждение).
    fn card_note(&self, name: &str, cx: &App) -> Option<(SharedString, bool)> {
        if self.kind != EntryKind::Card {
            return None;
        }
        let v = self.row_value(name, cx);
        if v.trim().is_empty() {
            return None;
        }
        match name {
            "Card Number" if !card::luhn(&v) => Some((
                tr!("Проверьте номер: контрольная цифра не сходится").into(),
                true,
            )),
            "Expiry" => match card::parse_expiry(&v) {
                None => Some((tr!("Нужен вид ММ/ГГ, например 04/29").into(), true)),
                Some((m, y)) => {
                    use chrono::Datelike as _;
                    let now = chrono::Local::now().date_naive();
                    ((y, m) < (now.year() as u32, now.month()))
                        .then(|| (tr!("Срок карты истёк").into(), true))
                }
            },
            _ => None,
        }
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
            // срок карты сохраняется в одном виде, как бы его ни набрали
            let value = match card::parse_expiry(&value) {
                Some((m, y))
                    if self.kind == EntryKind::Card && name == "Expiry" && r.custom.is_none() =>
                {
                    card::format_expiry(m, y)
                }
                _ => value,
            };
            // тип карты, который не выбирали вручную, берётся по номеру на момент сохранения
            let value = match card::brand(&self.row_value("Card Number", cx)) {
                Some(b)
                    if self.kind == EntryKind::Card
                        && self.auto_brand
                        && name == "Brand"
                        && r.custom.is_none() =>
                {
                    b.to_string()
                }
                _ => value,
            };
            push(name, value, r.protected);
        }
        if self.url_match.is_empty() || self.url_match == "domain" {
            if self.original.contains_key(model::URL_MATCH) {
                removed.push(model::URL_MATCH.into());
            }
        } else {
            push(model::URL_MATCH.into(), self.url_match.clone(), false);
        }
        let tag_list = self.final_tags(cx);
        let tags = (tag_list != self.original_tags).then_some(tag_list);
        let exp = match self.expires.read(cx).date() {
            Date::Single(Some(d)) => d.format("%Y-%m-%d").to_string(),
            _ => String::new(),
        };
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

    /// Тип карты: список платёжных систем; «по номеру» возвращает автоматическое определение.
    fn render_brand(&self, r: &Row, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let current = r.value.read(cx).value().trim().to_string();
        let auto = self.auto_brand;
        let entity = cx.entity();
        // пока тип следует за номером, показываем то, что по номеру видно уже сейчас
        let detected = card::brand(&self.row_value("Card Number", cx));
        let label: SharedString = match (auto, detected) {
            (true, Some(b)) => b.into(),
            _ if current.is_empty() => tr!("Определится по номеру").into(),
            _ => current.clone().into(),
        };
        h_flex()
            .gap_3()
            .items_center()
            .child(
                div()
                    .w(px(150.))
                    .flex_shrink_0()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(r.label.clone()),
            )
            .child(
                DropdownButton::new("brand")
                    .button(
                        Button::new("brand-btn")
                            .outline()
                            .icon(IconName::CreditCard)
                            .label(label),
                    )
                    .dropdown_menu_with_anchor(Anchor::TopLeft, move |menu, _, _| {
                        use gpui_kit::component::menu::PopupMenuItem;
                        let e = entity.clone();
                        let mut menu = menu.min_w(px(220.)).item(
                            PopupMenuItem::new(tr!("По номеру карты"))
                                .checked(auto)
                                .on_click(move |_, w, cx| {
                                    e.update(cx, |this, cx| {
                                        this.auto_brand = true;
                                        let b = card::brand(&this.row_value("Card Number", cx))
                                            .unwrap_or_default();
                                        this.set_brand(b, w, cx);
                                    });
                                }),
                        );
                        menu = menu.separator();
                        // тип из чужого менеджера, которого нет в списке, остаётся выбранным пунктом
                        let other = (!current.is_empty()
                            && !card::BRANDS.contains(&current.as_str()))
                        .then(|| current.clone());
                        for b in card::BRANDS.iter().map(|b| b.to_string()).chain(other) {
                            let e = entity.clone();
                            let checked = !auto && b == current;
                            let name = b.clone();
                            menu = menu.item(PopupMenuItem::new(b).checked(checked).on_click(
                                move |_, w, cx| {
                                    e.update(cx, |this, cx| {
                                        this.auto_brand = false;
                                        this.set_brand(&name, w, cx);
                                    });
                                },
                            ));
                        }
                        menu
                    }),
            )
            .into_any_element()
    }

    /// Теги: плашки с крестиком, поле для нового и теги базы, которых у записи ещё нет.
    fn render_tags(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let typed = self.tags.read(cx).value().trim().to_lowercase();
        let has = |t: &str| {
            self.tag_list
                .iter()
                .any(|x| x.to_lowercase() == t.to_lowercase())
        };
        let suggestions: Vec<String> = self
            .known_tags
            .iter()
            .filter(|t| !has(t) && (typed.is_empty() || t.to_lowercase().contains(&typed)))
            .take(8)
            .cloned()
            .collect();
        v_flex()
            .flex_1()
            .min_w_0()
            .gap_2()
            .when(!self.tag_list.is_empty(), |d| {
                d.child(h_flex().flex_wrap().gap_1p5().children(
                    self.tag_list.iter().enumerate().map(|(ix, t)| {
                        Tag::secondary().child(
                            h_flex().gap_1().items_center().child(t.clone()).child(
                                Button::new(("tag-rm", ix))
                                    .ghost()
                                    .xsmall()
                                    .icon(IconName::Close)
                                    .tooltip(tr!("Убрать тег"))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        if ix < this.tag_list.len() {
                                            this.tag_list.remove(ix);
                                        }
                                        cx.notify();
                                    })),
                            ),
                        )
                    }),
                ))
            })
            .child(Input::new(&self.tags))
            .when(!suggestions.is_empty(), |d| {
                d.child(
                    h_flex()
                        .flex_wrap()
                        .gap_1()
                        .items_center()
                        .child(
                            div()
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child(tr!("Уже есть в базе:")),
                        )
                        .children(suggestions.into_iter().enumerate().map(|(ix, t)| {
                            let tag = t.clone();
                            Button::new(("tag-add", ix))
                                .ghost()
                                .xsmall()
                                .icon(IconName::Plus)
                                .label(t)
                                .on_click(cx.listener(move |this, _, w, cx| {
                                    this.add_tag(&tag);
                                    this.tags.update(cx, |s, cx| s.set_value("", w, cx));
                                    cx.notify();
                                }))
                        })),
                )
            })
            .into_any_element()
    }

    /// На каких страницах браузер предлагает эту запись.
    fn render_url_match(&self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let options: [(&str, &str, &str); 5] = [
            (
                "domain",
                tr!("Весь сайт с поддоменами"),
                tr!("example.com и login.example.com"),
            ),
            (
                "host",
                tr!("Только этот адрес сайта"),
                tr!("Поддомены и соседние сайты хостинга не подходят"),
            ),
            (
                "starts",
                tr!("Адрес начинается так же"),
                tr!("Для сайтов, где у каждого свой путь: host.io/team/"),
            ),
            (
                "exact",
                tr!("Точно эта страница"),
                tr!("Адрес страницы должен совпасть целиком"),
            ),
            (
                "never",
                tr!("Не предлагать в браузере"),
                tr!("Запись остаётся только в приложении"),
            ),
        ];
        let current = if self.url_match.is_empty() {
            "domain".to_string()
        } else {
            self.url_match.clone()
        };
        let (label, hint) = options
            .iter()
            .find(|o| o.0 == current)
            .map(|o| (o.1, o.2))
            .unwrap_or((options[0].1, options[0].2));
        let entity = cx.entity();
        h_flex()
            .gap_3()
            .items_start()
            .child(
                div()
                    .w(px(150.))
                    .flex_shrink_0()
                    .pt_1p5()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(tr!("В браузере")),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_1()
                    .items_start()
                    .child(
                        DropdownButton::new("url-match")
                            .button(
                                Button::new("url-match-btn")
                                    .outline()
                                    .icon(IconName::Globe)
                                    .label(label),
                            )
                            .dropdown_menu_with_anchor(Anchor::TopLeft, move |menu, _, _| {
                                let mut menu = menu.min_w(px(260.));
                                for (value, label, _) in options {
                                    let e = entity.clone();
                                    menu = menu.item(
                                        gpui_kit::component::menu::PopupMenuItem::new(label)
                                            .checked(value == current)
                                            .on_click(move |_, _, cx| {
                                                e.update(cx, |this, cx| {
                                                    this.url_match = value.to_string();
                                                    cx.notify();
                                                });
                                            }),
                                    );
                                }
                                menu
                            }),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(hint),
                    ),
            )
            .into_any_element()
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
                let note = r
                    .custom
                    .is_none()
                    .then(|| self.card_note(&r.name, cx))
                    .flatten();
                if self.kind == EntryKind::Card && r.name == "Brand" && r.custom.is_none() {
                    return self.render_brand(r, cx);
                }
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
                            .when_some(note, |d, (text, warn)| {
                                d.child(
                                    div()
                                        .text_xs()
                                        .text_color(if warn {
                                            theme.warning_foreground
                                        } else {
                                            theme.muted_foreground
                                        })
                                        .child(text),
                                )
                            })
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
                    .into_any_element()
            })
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
        let url_match_row = (self.kind == EntryKind::Login
            || self.original.contains_key(model::URL_MATCH))
        .then(|| self.render_url_match(cx));
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
            .children(url_match_row)
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
                        .child(self.render_tags(cx)),
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
                        .child(
                            div().flex_1().child(
                                DatePicker::new(&self.expires)
                                    .cleanable(true)
                                    .placeholder(tr!("Бессрочно")),
                            ),
                        )
                        .child(
                            Button::new("exp-year")
                                .outline()
                                .label(tr!("+1 год"))
                                .tooltip(tr!("Через год от сегодня"))
                                .on_click(cx.listener(|this, _, w, cx| {
                                    let d =
                                        chrono::Local::now().date_naive() + chrono::Days::new(365);
                                    this.expires.update(cx, |s, cx| s.set_date(d, w, cx));
                                    cx.notify();
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
