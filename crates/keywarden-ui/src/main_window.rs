//! Главное окно: папки и типы слева, список записей, карточка или редактор справа.
//! Всё управляется с клавиатуры: Ctrl+F поиск, ↑↓ выбор, Enter пароль, Ctrl+U логин,
//! Ctrl+T 2FA, Ctrl+N новая запись, Ctrl+E правка, Shift+Delete удалить, Ctrl+G генератор,
//! Ctrl+L заблокировать, Alt+↑/↓ папки и типы.

use crate::client::{self, CallError};
use crate::editor::{EditorEvent, EntryEditor};
use crate::generator::GeneratorPanel;
use crate::ui::{badge, icon_tile, kbd_hint, kind_icon};
use gpui_kit::component::Disableable as _;
use gpui_kit::component::button::{Button, ButtonVariants as _, DropdownButton};
use gpui_kit::component::input::{Input, InputEvent, InputState, MoveDown, MoveUp};
use gpui_kit::component::menu::DropdownMenu as _;
use gpui_kit::component::skeleton::Skeleton;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::tag::Tag;
use gpui_kit::component::{ActiveTheme as _, Icon, Sizable as _, WindowExt as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::ipc::{Event, Request, Response};
use keywarden_core::model::{EntryDetail, EntryKind, EntrySummary, FieldView, GroupView};
use keywarden_core::search::Filter;
use keywarden_core::secret::Secret;
use keywarden_core::totp::Code;
use keywarden_core::tr;
use keywarden_core::vault::Cipher;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Сколько показанный секрет остаётся на экране.
const REVEAL_TTL: Duration = Duration::from_secs(30);
/// Сколько держится сообщение в строке состояния.
const STATUS_TTL: Duration = Duration::from_secs(5);

actions!(
    keywarden,
    [
        UnlockOptions,
        ToggleCreateVault,
        FocusSearch,
        NewLogin,
        NewCard,
        NewIdentity,
        NewNote,
        NewSshKey,
        NewSshHost,
        NewWallet,
        RevealWallet,
        EditEntry,
        DeleteEntry,
        LockDatabase,
        OpenGenerator,
        CopyPassword,
        CopyUsername,
        CopyTotp,
        PrevFilter,
        NextFilter,
        OpenSettings,
        DuplicateEntry,
        NextProfile,
        TabFields,
        TabAttachments,
        TabHistory,
        OpenAttachment,
        NudgeUp,
        NudgeDown
    ]
);

const CONTEXT: &str = "Keywarden";

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("ctrl-f", FocusSearch, Some(CONTEXT)),
        KeyBinding::new("ctrl-n", NewLogin, Some(CONTEXT)),
        KeyBinding::new("ctrl-e", EditEntry, Some(CONTEXT)),
        KeyBinding::new("shift-delete", DeleteEntry, Some(CONTEXT)),
        KeyBinding::new("ctrl-l", LockDatabase, Some(CONTEXT)),
        KeyBinding::new("ctrl-g", OpenGenerator, Some(CONTEXT)),
        KeyBinding::new("ctrl-u", CopyUsername, Some(CONTEXT)),
        KeyBinding::new("ctrl-t", CopyTotp, Some(CONTEXT)),
        KeyBinding::new("ctrl-shift-c", CopyPassword, Some(CONTEXT)),
        KeyBinding::new("alt-up", PrevFilter, Some(CONTEXT)),
        KeyBinding::new("alt-down", NextFilter, Some(CONTEXT)),
        KeyBinding::new("alt-shift-up", NudgeUp, Some(CONTEXT)),
        KeyBinding::new("ctrl-shift-r", RevealWallet, Some(CONTEXT)),
        KeyBinding::new("alt-shift-down", NudgeDown, Some(CONTEXT)),
        KeyBinding::new("ctrl-,", OpenSettings, Some(CONTEXT)),
        KeyBinding::new("ctrl-d", DuplicateEntry, Some(CONTEXT)),
        KeyBinding::new("ctrl-tab", NextProfile, Some(CONTEXT)),
        KeyBinding::new("alt-1", TabFields, Some(CONTEXT)),
        KeyBinding::new("alt-2", TabAttachments, Some(CONTEXT)),
        KeyBinding::new("alt-3", TabHistory, Some(CONTEXT)),
        KeyBinding::new("ctrl-o", OpenAttachment, Some(CONTEXT)),
    ]);
}

#[derive(Clone, PartialEq)]
enum Nav {
    All,
    /// записи с 2FA
    Otp,
    /// настройки хранилища (не фильтр, а отдельная страница)
    Settings,
    /// проверка паролей (отдельная страница)
    Health,
    Tag(String),
    Kind(EntryKind),
    Group(String),
}

/// Перетаскиваемая запись или папка (значение drag-and-drop в GPUI).
#[derive(Clone)]
struct EntryDrag {
    id: String,
    title: SharedString,
}

/// Перетаскивание типа в боковой панели (ручной порядок типов).
#[derive(Clone)]
struct KindDrag {
    kind: EntryKind,
}

impl Render for KindDrag {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        div()
    }
}

#[derive(Clone)]
struct GroupDrag {
    id: String,
    name: SharedString,
}

/// Что видно под курсором при перетаскивании.
struct DragChip {
    icon: IconName,
    label: SharedString,
    /// где схватили элемент: превью рисуется от этой точки, сдвигаем его под курсор
    grab: Point<Pixels>,
}

impl Render for DragChip {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let chip = h_flex()
            .gap_2()
            .px_3()
            .py_1p5()
            .rounded_lg()
            .border_1()
            .border_color(theme.primary.opacity(0.5))
            .bg(theme.popover)
            .shadow_lg()
            .text_sm()
            // превью рисуется вне корня окна: цвет и шрифт не наследуются
            .text_color(theme.foreground)
            .font_family(theme.font_family.clone())
            .child(Icon::new(self.icon).small().text_color(theme.primary))
            .child(self.label.clone());
        div()
            .pl(self.grab.x + px(14.))
            .pt(self.grab.y + px(10.))
            .child(chip.with_animation(
                "chip-in",
                Animation::new(Duration::from_millis(140)).with_easing(ease_out_quint()),
                |el, t| el.opacity(t).mt(px(4. * (1. - t))),
            ))
    }
}

/// Выведенный адрес: подпись (номер или сеть), путь, адрес или ошибка, сеть и имя для сохранения.
#[derive(Clone)]
struct DerivedRow {
    label: String,
    path: String,
    addr: Result<String, String>,
    coin: keywarden_core::wallet_derive::Coin,
    name: String,
}

impl DerivedRow {
    fn error(e: String, coin: keywarden_core::wallet_derive::Coin) -> Self {
        Self {
            label: String::new(),
            path: String::new(),
            addr: Err(e),
            coin,
            name: String::new(),
        }
    }
}

/// Значок сети: цвет и тикер, как в кошельках.
fn coin_color(id: &str) -> Hsla {
    let c = match id {
        "btc" => 0xF7931A,
        "ltc" => 0x5A8FD6,
        "doge" => 0xC2A633,
        "eth" => 0x7B8FF0,
        "bnb" => 0xF3BA2F,
        "sol" => 0xA66BFF,
        "tron" => 0xFF3B4E,
        _ => 0x8E8E98,
    };
    rgb(c).into()
}

fn coin_avatar(id: &str, size: f32) -> Div {
    let color = coin_color(id);
    div()
        .size(px(size))
        .flex_shrink_0()
        .rounded_md()
        .bg(color.opacity(0.14))
        .border_1()
        .border_color(color.opacity(0.4))
        .text_color(color)
        .text_size(px(if id.len() > 3 { 9. } else { 10.5 }))
        .font_weight(FontWeight::BOLD)
        .flex()
        .items_center()
        .justify_center()
        .child(if id.is_empty() {
            "?".to_string()
        } else {
            id.to_uppercase()
        })
}

/// Адрес покороче: начало и конец, середина многоточием.
/// `{USERNAME}{TAB}{PASSWORD}{ENTER}` -> «логин, Tab, пароль, Enter»; текст как есть в кавычках.
fn human_sequence(seq: &str) -> String {
    let mut out: Vec<String> = vec![];
    let mut rest = seq;
    while !rest.is_empty() {
        if let Some(body) = rest.strip_prefix('{')
            && let Some(end) = body.find('}')
        {
            let tok = &body[..end];
            out.push(match tok.to_ascii_uppercase().as_str() {
                "USERNAME" => tr!("логин").into(),
                "PASSWORD" => tr!("пароль").into(),
                "TOTP" => tr!("код 2FA").into(),
                "URL" => tr!("адрес").into(),
                "TAB" => "Tab".into(),
                "ENTER" => "Enter".into(),
                _ => format!("{{{tok}}}"),
            });
            rest = &body[end + 1..];
        } else {
            let end = rest[1..].find('{').map_or(rest.len(), |i| i + 1);
            out.push(format!("«{}»", &rest[..end]));
            rest = &rest[end..];
        }
    }
    out.join(", ")
}

/// Где сейчас щель под бросок и где была до этого. Прежняя схлопывается, пока новая
/// раскрывается: сумма высот постоянна, и строки ниже не прыгают.
struct Gaps<K> {
    cur: Option<K>,
    prev: Option<K>,
    generation: u64,
}

impl<K> Default for Gaps<K> {
    fn default() -> Self {
        Self {
            cur: None,
            prev: None,
            generation: 0,
        }
    }
}

impl<K: PartialEq + Clone> Gaps<K> {
    fn observe(&mut self, now: Option<K>) {
        if now == self.cur {
            return;
        }
        if now.is_none() {
            // бросили или увели курсор: щели убираем сразу
            self.prev = None;
        } else {
            self.prev = self.cur.take();
        }
        self.cur = now;
        self.generation += 1;
    }

    /// Щель в этом месте: Some(true) раскрывается, Some(false) схлопывается.
    fn at(&self, k: &K) -> Option<bool> {
        if self.cur.as_ref() == Some(k) {
            Some(true)
        } else if self.prev.as_ref() == Some(k) {
            Some(false)
        } else {
            None
        }
    }
}

/// Раскрыть или схлопнуть щель высотой `h` (анимация с новым ключом на каждую смену щели).
fn gap_anim(el: Stateful<Div>, tag: &str, opening: bool, generation: u64, h: f32) -> AnyElement {
    el.with_animation(
        SharedString::from(format!("{tag}-{generation}-{opening}")),
        Animation::new(Duration::from_millis(220)).with_easing(ease_out_quint()),
        move |el, t| {
            let k = if opening { t } else { 1. - t };
            el.h(px(h * k))
                .opacity(0.85 * k)
                .when(k < 0.05, |el| el.border_0())
        },
    )
    .into_any_element()
}

/// Вместо текста на миг «✓ Скопировано».
fn copied_or(copied: bool, text: String, theme: &gpui_kit::component::Theme) -> AnyElement {
    if copied {
        h_flex()
            .gap_1()
            .text_color(theme.success)
            .child(Icon::new(IconName::Check).xsmall())
            .child(tr!("Скопировано"))
            .into_any_element()
    } else {
        text.into_any_element()
    }
}

fn short_addr(a: &str) -> String {
    mid_addr(a, 12, 8)
}

fn mid_addr(a: &str, head: usize, tail: usize) -> String {
    let n = a.chars().count();
    if n <= head + tail + 4 {
        return a.to_string();
    }
    let h: String = a.chars().take(head).collect();
    let t: String = a.chars().skip(n - tail).collect();
    format!("{h}…{t}")
}

fn script_name(s: keywarden_core::wallet_derive::Script) -> &'static str {
    use keywarden_core::wallet_derive::Script;
    match s {
        Script::Segwit => "SegWit",
        Script::Nested => "Nested",
        Script::Legacy => "Legacy",
    }
}

/// Правый клик в боковой панели: по папке или по тегу.
#[derive(Clone)]
enum CtxTarget {
    Group {
        id: String,
        name: String,
        entries: usize,
    },
    Tag {
        name: String,
        count: usize,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum ProfileState {
    Open,
    Locked,
    Stopped,
}

fn profile_label(name: &str) -> String {
    if name == "default" {
        tr!("Основная").into()
    } else {
        name.into()
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Sort {
    /// порядок, как в базе: его меняют перетаскиванием и Alt+Shift+стрелками (общий с KeePassXC)
    Manual,
    /// по совпадению с запросом, без запроса: недавно использованные
    Relevance,
    Title,
    Modified,
    Created,
}

impl Sort {
    fn label(self) -> &'static str {
        match self {
            Sort::Manual => tr!("Вручную"),
            Sort::Relevance => tr!("Недавно открытые"),
            Sort::Title => tr!("По названию"),
            Sort::Modified => tr!("Недавно изменённые"),
            Sort::Created => tr!("Недавно созданные"),
        }
    }
}

#[derive(PartialEq)]
enum Mode {
    Connecting,
    Locked,
    Busy,
    Ready,
}

pub struct MainWindow {
    mode: Mode,
    creating: bool,
    // разблокировка / создание
    db_path: Entity<InputState>,
    keyfile: Entity<InputState>,
    yubikey: Entity<InputState>,
    password: Entity<InputState>,
    pin: Entity<InputState>,
    password2: Entity<InputState>,
    // база
    search: Entity<InputState>,
    groups: Vec<GroupView>,
    tags: Vec<(String, usize)>,
    /// созданные в панели теги без записей: в KDBX тег живёт только на записях, до первой
    /// записи он есть только здесь
    pending_tags: Vec<String>,
    /// демон уже пробовали запустить сами (нет systemd на Windows и macOS)
    daemon_autostarted: bool,
    sort: Sort,
    health: Option<keywarden_core::health::Report>,
    /// собственные иконки записей по UUID (favicon), загружаются по мере надобности
    icons: HashMap<String, std::sync::Arc<Image>>,
    icons_requested: HashSet<String>,
    health_busy: bool,
    /// выделить эту запись, когда придёт список (переход со страницы проверки)
    pending_select: Option<String>,
    /// ключ, которым git подписывает коммиты (None: ещё не спрашивали git)
    git_signing: Option<Option<String>>,
    nav: Nav,
    entries: Vec<EntrySummary>,
    selected: Option<usize>,
    detail: Option<EntryDetail>,
    revealed: Option<EntryDetail>,
    shown: HashSet<String>,
    code: Option<Code>,
    /// живые коды на странице «Коды 2FA», по id записи
    otp_codes: HashMap<String, Code>,
    editor: Option<Entity<EntryEditor>>,
    settings: Option<Entity<crate::settings_page::SettingsPage>>,
    list_scroll: ScrollHandle,
    status: Option<(SharedString, bool)>,
    status_at: Option<Instant>,
    revealed_at: Option<Instant>,
    /// повторное подтверждение для кошельков: когда прошло (демон держит его 2 минуты)
    elevated_at: Option<Instant>,
    /// задан ли PIN (тогда подтверждение PIN-ом, иначе мастер-паролем)
    pin_set: bool,
    /// обозреватели блоков: сеть -> шаблон ссылки
    explorers: std::collections::BTreeMap<String, String>,
    /// слова фразы, открытые по одному (сквозные номера)
    seed_open: HashSet<usize>,
    seed_all: bool,
    /// вывод адресов из фразы: сеть, вид адреса, аккаунт, сколько, свой путь, кэш
    dv_coin: keywarden_core::wallet_derive::Coin,
    dv_script: keywarden_core::wallet_derive::Script,
    dv_account: u32,
    dv_count: u32,
    dv_path: Entity<InputState>,
    dv_cache: Option<(String, Vec<DerivedRow>)>,
    /// своё поле пути раскрыто
    dv_custom: bool,
    /// вкладка адресов: 0 сохранённые, 1 вывод; None: сама по содержимому
    addr_tab: Option<usize>,
    /// переименование сохранённого адреса прямо в строке
    addr_edit: Option<(usize, Entity<InputState>, Subscription)>,
    addr_confirm_rm: Option<usize>,
    show_advanced: bool,
    /// разблокировка PIN-кодом (демон говорит, что PIN сейчас действует)
    use_pin: bool,
    /// растёт при смене раздела: строки списка появляются лесенкой заново
    rows_anim: u64,
    /// неудачные попытки разблокировки: карточка встряхивается на каждую
    unlock_fails: u64,
    /// перетаскивание записи над строкой списка: (индекс строки, после неё)
    /// перетаскивание записи над списком: номер щели между строками (0 = перед первой)
    entry_drop: Option<usize>,
    /// куда только что встала запись или папка (id, номер): короткая вспышка
    landed: Option<(String, u64)>,
    /// контекстное меню папки или тега и где его открыли
    ctx_menu: Option<(CtxTarget, Point<Pixels>)>,
    /// перетаскивание папки над папкой: (id, -1 перед, 0 внутрь, 1 после)
    group_drop: Option<(String, i8)>,
    /// порядок типов в боковой панели (настройка этого компьютера)
    kind_order: Vec<EntryKind>,
    /// куда встанет перетаскиваемый тип: перед ним или после (true)
    kind_drop: Option<(EntryKind, bool)>,
    /// щели под бросок: новая раскрывается, прежняя схлопывается одновременно
    entry_gaps: Gaps<usize>,
    group_gaps: Gaps<String>,
    kind_gaps: Gaps<usize>,
    loading_list: bool,
    loading_detail: bool,
    detail_tab: usize,
    /// раздел «История» в карточке раскрыт
    history_open: bool,
    total: usize,
    open_path: Option<String>,
    debounce_task: Option<Task<()>>,
    /// подписка на события демона текущей базы
    sub_task: Option<Task<()>>,
    /// базы и их состояние (меню в шапке)
    profiles: Vec<(String, ProfileState)>,
    profile_menu: bool,
    /// что только что скопировано: на кнопке ненадолго галочка
    copied: Option<String>,
    copied_task: Option<Task<()>>,
    tasks: Vec<Task<()>>,
    search_task: Option<Task<()>>,
    detail_task: Option<Task<()>>,
    _subs: Vec<Subscription>,
}

impl MainWindow {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let input = |placeholder: &'static str,
                     masked: bool,
                     window: &mut Window,
                     cx: &mut Context<Self>| {
            cx.new(|cx| {
                InputState::new(window, cx)
                    .placeholder(placeholder)
                    .masked(masked)
            })
        };
        let db_path = input(tr!("Путь к базе .kdbx"), false, window, cx);
        let keyfile = input(tr!("Файл-ключ (необязательно)"), false, window, cx);
        let yubikey = input(
            tr!("YubiKey: слот, например 2 (необязательно)"),
            false,
            window,
            cx,
        );
        let password = input(tr!("Мастер-пароль"), true, window, cx);
        let pin = input("PIN", true, window, cx);
        let password2 = input(tr!("Мастер-пароль ещё раз"), true, window, cx);
        let search = input(
            tr!("Поиск: слова, #тег, user:, url:, is:expired"),
            false,
            window,
            cx,
        );
        let dv_path = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("свой путь без номера адреса, например m/84'/0'/1'/0"))
        });
        let subs = vec![
            cx.subscribe(&dv_path, |_, _, _: &InputEvent, cx| cx.notify()),
            cx.subscribe_in(&password, window, |this, _, ev, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit_unlock(window, cx);
                }
            }),
            cx.subscribe_in(&pin, window, |this, _, ev, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit_unlock(window, cx);
                }
            }),
            cx.subscribe_in(&password2, window, |this, _, ev, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    this.submit_unlock(window, cx);
                }
            }),
            cx.subscribe_in(&search, window, |this, _, ev, _, cx| match ev {
                InputEvent::Change => this.reload_list_debounced(cx),
                InputEvent::PressEnter { .. } => {
                    let field = if this.nav == Nav::Otp {
                        "totp"
                    } else {
                        "password"
                    };
                    this.copy(field, cx)
                }
                _ => {}
            }),
        ];
        let mut this = Self {
            mode: Mode::Connecting,
            creating: false,
            db_path,
            keyfile,
            yubikey,
            password,
            pin,
            password2,
            search,
            groups: vec![],
            tags: vec![],
            pending_tags: vec![],
            daemon_autostarted: false,
            sort: Sort::Manual,
            health: None,
            icons: HashMap::new(),
            icons_requested: HashSet::new(),
            health_busy: false,
            pending_select: None,
            git_signing: None,
            nav: Nav::All,
            entries: vec![],
            selected: None,
            detail: None,
            revealed: None,
            shown: HashSet::new(),
            code: None,
            otp_codes: HashMap::new(),
            editor: None,
            settings: None,
            list_scroll: ScrollHandle::new(),
            status: None,
            status_at: None,
            revealed_at: None,
            elevated_at: None,
            pin_set: false,
            explorers: keywarden_core::wallet::default_explorers(),
            seed_open: HashSet::new(),
            seed_all: false,
            dv_coin: keywarden_core::wallet_derive::Coin::Btc,
            dv_script: keywarden_core::wallet_derive::Script::Segwit,
            dv_account: 0,
            dv_count: 5,
            dv_path,
            dv_cache: None,
            dv_custom: false,
            addr_tab: None,
            addr_edit: None,
            addr_confirm_rm: None,
            show_advanced: false,
            use_pin: false,
            rows_anim: 0,
            unlock_fails: 0,
            entry_drop: None,
            landed: None,
            ctx_menu: None,
            group_drop: None,
            kind_order: EntryKind::ALL.to_vec(),
            kind_drop: None,
            entry_gaps: Gaps::default(),
            group_gaps: Gaps::default(),
            kind_gaps: Gaps::default(),
            loading_list: false,
            loading_detail: false,
            detail_tab: 0,
            history_open: false,
            total: 0,
            open_path: None,
            debounce_task: None,
            copied: None,
            copied_task: None,
            tasks: vec![],
            search_task: None,
            detail_task: None,
            _subs: subs,
            sub_task: None,
            profiles: vec![],
            profile_menu: false,
        };
        this.connect(window, cx);
        this.tasks.push(Self::ticker(cx));
        this
    }

    // --- состояние ---
    /// Подключиться к демону текущей базы: состояние и подписка на его события.
    fn connect(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.mode = Mode::Connecting;
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::Status,
            |this, res, window, cx| {
                match res {
                    Ok(Response::Status(s)) => {
                        let path = s
                            .path
                            .clone()
                            .or(s.default_path.clone())
                            .unwrap_or_default();
                        // путь, файл-ключ и YubiKey прячутся, если всё уже известно из конфига
                        this.show_advanced = path.is_empty();
                        this.use_pin = s.quick_unlock;
                        this.db_path
                            .update(cx, |i, cx| i.set_value(path, window, cx));
                        this.keyfile.update(cx, |i, cx| {
                            i.set_value(s.keyfile.clone().unwrap_or_default(), window, cx)
                        });
                        this.yubikey.update(cx, |i, cx| {
                            i.set_value(s.yubikey.clone().unwrap_or_default(), window, cx)
                        });
                        this.total = s.entries;
                        if s.locked {
                            this.set_locked(window, cx);
                        } else {
                            this.open_path = s.path;
                            this.set_ready(window, cx);
                        }
                    }
                    Ok(_) => {}
                    // демона нет: запустить один раз и подключиться снова
                    Err(client::CallError::Unavailable(_)) if !this.daemon_autostarted => {
                        this.daemon_autostarted = true;
                        let profile =
                            keywarden_core::ipc::profile().unwrap_or_else(|| "default".into());
                        this.tasks.push(cx.spawn_in(window, async move |this, cx| {
                            let started = cx
                                .background_spawn(async move { client::start_daemon(&profile) })
                                .await;
                            let _ = this.update_in(cx, |this, window, cx| match started {
                                Ok(()) => this.connect(window, cx),
                                Err(e) => {
                                    this.mode = Mode::Locked;
                                    this.flash(e, true, cx);
                                }
                            });
                        }));
                    }
                    Err(e) => {
                        this.mode = Mode::Locked;
                        this.flash(e.message(), true, cx)
                    }
                }
                cx.notify();
            },
        ));
        // подписка старой базы отменяется вместе со своей задачей
        self.sub_task = Some(client::subscribe(cx, |this, ev, cx| this.on_event(ev, cx)));
    }

    fn refresh_profiles(&mut self, cx: &mut Context<Self>) {
        self.tasks.push(cx.spawn(async move |this, cx| {
            let list = cx
                .background_spawn(async move {
                    keywarden_core::ipc::profiles()
                        .into_iter()
                        .map(|p| {
                            let name = (p != "default").then_some(p.as_str());
                            let state = match client::blocking_on(name, &Request::Status) {
                                Ok(Response::Status(s)) if !s.locked => ProfileState::Open,
                                Ok(_) | Err(CallError::Locked) => ProfileState::Locked,
                                Err(_) => ProfileState::Stopped,
                            };
                            (p, state)
                        })
                        .collect::<Vec<_>>()
                })
                .await;
            let _ = this.update(cx, |this, cx| {
                this.profiles = list;
                cx.notify();
            });
        }));
    }

    fn switch_profile(&mut self, name: String, window: &mut Window, cx: &mut Context<Self>) {
        self.profile_menu = false;
        let current = keywarden_core::ipc::profile().unwrap_or_else(|| "default".into());
        if current == name {
            cx.notify();
            return;
        }
        self.flash(
            tr!("Открываю базу «{name}»…", name = profile_label(&name)),
            false,
            cx,
        );
        let n = name.clone();
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            let started = if n == "default" {
                Ok(())
            } else {
                let n = n.clone();
                cx.background_spawn(async move { client::start_daemon(&n) })
                    .await
            };
            let _ = this.update_in(cx, |this, window, cx| match started {
                Ok(()) => {
                    let _ = keywarden_core::ipc::set_profile(Some(&n));
                    this.forget_session(Some(window), cx);
                    this.icons.clear();
                    this.icons_requested.clear();
                    this.status = None;
                    this.connect(window, cx);
                    this.refresh_profiles(cx);
                }
                Err(e) => this.flash(e, true, cx),
            });
        }));
        cx.notify();
    }

    fn add_profile_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.profile_menu = false;
        let name = cx.new(|cx| InputState::new(window, cx).placeholder("work, family, …"));
        let path = cx.new(|cx| InputState::new(window, cx).placeholder(tr!("/путь/к/базе.kdbx")));
        let this = cx.entity();
        let focus = name.read(cx).focus_handle(cx);
        window.open_dialog(cx, move |dialog, _, cx| {
            let dialog = dialog.centered().entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
            let (this, name, path) = (this.clone(), name.clone(), path.clone());
            let theme = cx.theme().clone();
            let label = |t: &'static str| {
                div()
                    .text_xs()
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(theme.muted_foreground)
                    .child(t)
            };
            dialog
                .p_0()
                .w(px(540.))
                .child(crate::ui::sheet_header(
                    tr!("Добавить базу"),
                    Some(tr!("Каждая база открывается и блокируется отдельно; лаунчер ищет по всем открытым")),
                    &theme,
                ))
                .child(
                    crate::ui::sheet_body()
                        .child(v_flex().gap_1p5().child(label(tr!("Короткое имя"))).child(Input::new(&name)))
                        .child(
                            v_flex().gap_1p5().child(label(tr!("Файл .kdbx"))).child(crate::ui::file_field(
                                "pick-db",
                                &path,
                                tr!("Файл базы не выбран"),
                                tr!("База .kdbx"),
                                IconName::Database,
                                cx,
                            )),
                        ),
                )
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(div().flex_1())
                        .child(
                            Button::new("cancel")
                                .outline()
                                .label(tr!("Отмена"))
                                .on_click(|_, w, cx| w.close_dialog(cx)),
                        )
                        .child(Button::new("ok").primary().label(tr!("Добавить и открыть")).on_click(
                            move |_, window, cx| {
                                let n = name.read(cx).value().trim().to_string();
                                let p = path.read(cx).value().trim().to_string();
                                let res = if p.is_empty() {
                                    Err(tr!("укажите файл базы").to_string())
                                } else {
                                    keywarden_core::ipc::add_profile(&n, std::path::Path::new(&p))
                                };
                                this.update(cx, |this, cx| match res {
                                    Ok(_) => {
                                        window.close_dialog(cx);
                                        this.switch_profile(n.clone(), window, cx);
                                    }
                                    Err(e) => this.flash(e, true, cx),
                                });
                            },
                        )),
                )
        });
        window.focus(&focus, cx);
    }

    /// Меню баз под шапкой боковой панели.
    fn render_profile_menu(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let current = keywarden_core::ipc::profile().unwrap_or_else(|| "default".into());
        v_flex()
            .id("profile-menu")
            .absolute()
            .top(px(68.))
            .left(px(12.))
            .w(px(240.))
            .p_1()
            .gap_0p5()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .shadow_lg()
            .child(
                div()
                    .px_2()
                    .pt_1()
                    .pb_1p5()
                    .text_xs()
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(theme.muted_foreground)
                    .child(tr!("Базы")),
            )
            .children(self.profiles.clone().into_iter().map(|(name, state)| {
                let active = name == current;
                let n = name.clone();
                h_flex()
                    .id(SharedString::from(format!("prof-{name}")))
                    .gap_2()
                    .px_2()
                    .py_1p5()
                    .rounded_md()
                    .cursor_pointer()
                    .when(active, |d| d.bg(theme.list_active))
                    .hover(|d| d.bg(theme.secondary_active))
                    .on_click(
                        cx.listener(move |this, _, w, cx| this.switch_profile(n.clone(), w, cx)),
                    )
                    .child(Icon::new(IconName::Database).small().text_color(if active {
                        theme.primary
                    } else {
                        theme.muted_foreground
                    }))
                    .child(
                        div()
                            .flex_1()
                            .text_sm()
                            .truncate()
                            .child(profile_label(&name)),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(match state {
                                ProfileState::Open => tr!("открыта"),
                                ProfileState::Locked => tr!("закрыта"),
                                ProfileState::Stopped => tr!("не запущена"),
                            }),
                    )
            }))
            .child(div().h(px(1.)).my_1().bg(theme.border))
            .child(
                h_flex()
                    .id("prof-add")
                    .gap_2()
                    .px_2()
                    .py_1p5()
                    .rounded_md()
                    .cursor_pointer()
                    .text_sm()
                    .hover(|d| d.bg(theme.secondary_active))
                    .on_click(cx.listener(|this, _, w, cx| this.add_profile_dialog(w, cx)))
                    .child(
                        Icon::new(IconName::Plus)
                            .small()
                            .text_color(theme.muted_foreground),
                    )
                    .child(tr!("Добавить базу…")),
            )
            .child(div().h(px(1.)).my_1().bg(theme.border))
            .child(
                h_flex()
                    .px_2()
                    .py_1()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(kbd_hint("ctrl-tab", tr!("следующая база"))),
            )
            .with_animation(
                "profile-menu-in",
                Animation::new(Duration::from_millis(120)).with_easing(ease_out_quint()),
                |el, t| el.opacity(t).top(px(60. + 8. * t)),
            )
            .into_any_element()
    }

    /// Всё, что видно после разблокировки, забывается: записи, раскрытые секреты, запрос поиска.
    fn forget_session(&mut self, window: Option<&mut Window>, cx: &mut Context<Self>) {
        self.mode = Mode::Locked;
        self.entries.clear();
        self.groups.clear();
        self.tags.clear();
        self.health = None;
        self.selected = None;
        self.detail = None;
        self.revealed = None;
        self.revealed_at = None;
        self.shown.clear();
        self.code = None;
        self.otp_codes.clear();
        self.editor = None;
        self.settings = None;
        self.nav = Nav::All;
        self.total = 0;
        self.debounce_task = None;
        if let Some(window) = window {
            self.search.update(cx, |s, cx| s.set_value("", window, cx));
        }
    }

    /// Действует ли PIN: меняется при блокировке и после неверных попыток.
    fn refresh_quick(&mut self, cx: &mut Context<Self>) {
        self.tasks
            .push(client::call(cx, Request::Status, |this, res, cx| {
                if let Ok(Response::Status(s)) = res {
                    this.use_pin = s.quick_unlock && !this.creating;
                }
                cx.notify();
            }));
    }

    fn set_locked(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.refresh_quick(cx);
        self.forget_session(Some(window), cx);
        let h = if self.use_pin && !self.creating {
            self.pin.read(cx).focus_handle(cx)
        } else {
            self.password.read(cx).focus_handle(cx)
        };
        window.focus(&h, cx);
        cx.notify();
    }

    fn set_ready(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.mode = Mode::Ready;
        let h = self.search.read(cx).focus_handle(cx);
        window.focus(&h, cx);
        self.reload_all(cx);
        self.load_prefs(cx);
    }

    /// PIN задан ли и какие обозреватели: для кошельков.
    fn load_prefs(&mut self, cx: &mut Context<Self>) {
        self.tasks.push(client::call(
            cx,
            Request::Prefs { set: None },
            |this, res, cx| {
                if let Ok(Response::Prefs { prefs }) = res {
                    this.pin_set = prefs.pin_set;
                    this.explorers = prefs.explorers;
                    this.kind_order = ordered_kinds(&prefs.kind_order);
                }
                cx.notify();
            },
        ));
    }

    // --- криптокошельки: повторное подтверждение, фраза, карточка, адреса ---

    fn elevated_ui(&self) -> bool {
        // чуть меньше двух минут демона: не упереться в отказ на границе
        self.elevated_at
            .is_some_and(|t| t.elapsed() < Duration::from_secs(110))
    }

    /// Выполнить действие с фразой кошелька: если подтверждение истекло, сначала спросить PIN
    /// или мастер-пароль. Проверяет демон; здесь только окно и повтор действия.
    fn with_auth(
        &mut self,
        then: impl FnOnce(&mut Self, &mut Window, &mut Context<Self>) + 'static,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.elevated_ui() {
            return then(self, window, cx);
        }
        let use_pin = self.pin_set;
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .masked(true)
                .placeholder(if use_pin {
                    "PIN"
                } else {
                    tr!("Мастер-пароль")
                })
        });
        let keyfile =
            Some(self.keyfile.read(cx).value().trim().to_string()).filter(|k| !k.is_empty());
        let yubikey =
            Some(self.yubikey.read(cx).value().trim().to_string()).filter(|y| !y.is_empty());
        let this = cx.entity();
        type Then = Box<dyn FnOnce(&mut MainWindow, &mut Window, &mut Context<MainWindow>)>;
        let then = std::rc::Rc::new(std::cell::RefCell::new(Some(Box::new(then) as Then)));
        let submit = {
            let (input, this) = (input.clone(), this.clone());
            std::rc::Rc::new(move |window: &mut Window, cx: &mut App| {
                let v = input.read(cx).value().to_string();
                if v.is_empty() {
                    return;
                }
                let req = if use_pin {
                    Request::Elevate {
                        pin: Some(v.into()),
                        key: None,
                    }
                } else {
                    Request::Elevate {
                        pin: None,
                        key: Some(keywarden_core::ipc::KeySpec {
                            password: Some(v.into()),
                            keyfile: keyfile.clone(),
                            yubikey: yubikey.clone(),
                        }),
                    }
                };
                window.close_dialog(cx);
                let then = then.clone();
                this.update(cx, |this, cx| {
                    this.tasks.push(client::call_in(
                        window,
                        cx,
                        req,
                        move |this, res, window, cx| {
                            match res {
                                Ok(_) => {
                                    this.elevated_at = Some(Instant::now());
                                    // раскрытое без подтверждения было без фразы: перечитать
                                    this.revealed = None;
                                    if let Some(f) = then.borrow_mut().take() {
                                        f(this, window, cx)
                                    }
                                }
                                Err(e) => this.flash(e.message(), true, cx),
                            }
                        },
                    ));
                });
            })
        };
        let s2 = submit.clone();
        self._subs.push(
            cx.subscribe_in(&input, window, move |_, _, ev, window, cx| {
                if let InputEvent::PressEnter { .. } = ev {
                    // мы внутри обновления окна: отправку откладываем, иначе повторное update упадёт
                    let s2 = s2.clone();
                    window.defer(cx, move |window, cx| s2(window, cx));
                }
            }),
        );
        let focus = input.read(cx).focus_handle(cx);
        window.open_dialog(cx, move |dialog, _, cx| {
            let theme = cx.theme().clone();
            let (input, submit) = (input.clone(), submit.clone());
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .w(px(420.))
                .child(crate::ui::sheet_header(
                    tr!("Подтвердите, что это вы"),
                    Some(tr!("Фраза и ключи кошельков откроются на 2 минуты")),
                    &theme,
                ))
                .child(
                    crate::ui::sheet_body()
                        .child(Input::new(&input).prefix(Icon::new(IconName::LockKeyhole).small())),
                )
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(div().flex_1())
                        .child(
                            Button::new("cancel")
                                .outline()
                                .label(tr!("Отмена"))
                                .on_click(|_, w, cx| w.close_dialog(cx)),
                        )
                        .child(
                            Button::new("ok")
                                .primary()
                                .label(tr!("Подтвердить"))
                                .on_click(move |_, w, cx| submit(w, cx)),
                        ),
                )
        });
        window.focus(&focus, cx);
    }

    /// Раскрыть фразу кошелька (после подтверждения): перечитать запись со значениями.
    fn reveal_seed(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        self.seed_all = false;
        self.seed_open.clear();
        self.detail_task = Some(client::call(
            cx,
            Request::Get { id, reveal: true },
            |this, res, cx| {
                if let Ok(Response::Entry { entry }) = res {
                    this.revealed = Some(*entry);
                    this.revealed_at = Some(Instant::now());
                }
                cx.notify();
            },
        ));
    }

    fn revealed_field(&self, name: &str) -> Option<String> {
        self.revealed
            .as_ref()?
            .fields
            .iter()
            .find(|f| f.name == name)?
            .value
            .as_ref()
            .map(|v| v.expose().to_string())
            .filter(|v| !v.trim().is_empty())
    }

    /// Карточка для печати: PDF в $XDG_RUNTIME_DIR (в памяти, 0600), открывается и через
    /// 10 минут удаляется. Для SLIP-39 своя карточка на каждую долю.
    fn print_card(&mut self, with_qr: bool, cx: &mut Context<Self>) {
        use std::io::Write as _;
        let Some(seed) = self.revealed_field(keywarden_core::wallet::SEED) else {
            return self.flash(tr!("Сначала откройте фразу"), true, cx);
        };
        let title = self
            .detail
            .as_ref()
            .map(|d| d.summary.title.clone())
            .unwrap_or_default();
        let check = keywarden_core::wallet::check_seed(&seed);
        let lines: Vec<&str> = seed.lines().filter(|l| !l.trim().is_empty()).collect();
        let n = lines.len();
        let date = chrono::Local::now().format("%Y-%m-%d").to_string();
        let dir = keywarden_core::ipc::runtime_dir();
        let _ = keywarden_core::platform::create_private_dir(&dir);
        for (i, line) in lines.iter().enumerate() {
            let card = keywarden_core::wallet_card::Card {
                title: title.clone(),
                format: if check.format == "slip39" {
                    tr!("SLIP-39, доля {i} из {n}", i = i + 1, n = n)
                } else {
                    check.label.clone()
                },
                words: line.split_whitespace().map(String::from).collect(),
                qr: (with_qr && check.format == "bip39")
                    .then(|| keywarden_core::wallet::seedqr(line, false))
                    .flatten(),
                date: date.clone(),
            };
            let pdf = match keywarden_core::wallet_card::card_pdf(&card) {
                Ok(p) => p,
                Err(e) => return self.flash(e, true, cx),
            };
            let path = dir.join(format!(
                "keywarden-card-{}.pdf",
                data_encoding::HEXLOWER.encode(&rand::random::<[u8; 6]>())
            ));
            let written = keywarden_core::platform::create_private_file(&path)
                .and_then(|mut f| f.write_all(&pdf));
            if let Err(e) = written {
                return self.flash(tr!("Карточку не записать: {e}", e = e), true, cx);
            }
            cx.open_with_system(&path);
            self.tasks.push(cx.spawn(async move |_, cx| {
                cx.background_executor()
                    .timer(Duration::from_secs(600))
                    .await;
                let _ = std::fs::remove_file(&path);
            }));
        }
        self.flash(
            tr!("Карточка открыта для печати. Файл в памяти, удалится сам через 10 минут"),
            false,
            cx,
        );
    }

    fn show_seedqr(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(seed) = self.revealed_field(keywarden_core::wallet::SEED) else {
            return self.flash(tr!("Сначала откройте фразу"), true, cx);
        };
        let compact = std::rc::Rc::new(std::cell::Cell::new(false));
        let seed = std::rc::Rc::new(zeroize::Zeroizing::new(seed));
        window.open_dialog(cx, move |dialog, _, cx| {
            let theme = cx.theme().clone();
            let (c1, c2) = (compact.clone(), compact.clone());
            let matrix = keywarden_core::wallet::seedqr(&seed, compact.get());
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .child(crate::ui::sheet_header(
                    "SeedQR",
                    Some(tr!(
                        "Для SeedSigner и аппаратных кошельков, которые его понимают"
                    )),
                    &theme,
                ))
                .child(
                    v_flex()
                        .p_5()
                        .items_center()
                        .gap_4()
                        .child(match matrix {
                            Some((w, cells)) => qr_cells(w, &cells, 7.),
                            None => div()
                                .child(tr!("SeedQR только для BIP39"))
                                .into_any_element(),
                        })
                        .child(
                            h_flex()
                                .gap_2()
                                .text_sm()
                                .text_color(theme.warning_foreground)
                                .child(Icon::new(IconName::ShieldAlert).small())
                                .child(tr!(
                                    "Это вся фраза целиком: не фотографируйте и закройте окно"
                                )),
                        ),
                )
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(Button::new("std").ghost().label(tr!("Обычный")).on_click(
                            move |_, w, _| {
                                c1.set(false);
                                w.refresh();
                            },
                        ))
                        .child(
                            Button::new("cmp")
                                .ghost()
                                .label(tr!("Компактный"))
                                .on_click(move |_, w, _| {
                                    c2.set(true);
                                    w.refresh();
                                }),
                        )
                        .child(div().flex_1())
                        .child(
                            Button::new("qr-close")
                                .primary()
                                .label(tr!("Готово"))
                                .on_click(|_, w, cx| w.close_dialog(cx)),
                        ),
                )
        });
    }

    fn show_address_qr(&mut self, address: String, window: &mut Window, cx: &mut Context<Self>) {
        window.open_dialog(cx, move |dialog, _, cx| {
            let theme = cx.theme().clone();
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .child(crate::ui::sheet_header(
                    tr!("Адрес для получения"),
                    Some(tr!("Публичный: его можно показывать отправителю")),
                    &theme,
                ))
                .child(
                    v_flex()
                        .p_5()
                        .items_center()
                        .gap_3()
                        .child(qr_element(&address))
                        .child(
                            div()
                                .text_sm()
                                .font_family(theme.mono_font_family.clone())
                                .child(address.clone()),
                        ),
                )
                .child(
                    crate::ui::sheet_footer(&theme).child(div().flex_1()).child(
                        Button::new("qr-close")
                            .primary()
                            .label(tr!("Готово"))
                            .on_click(|_, w, cx| w.close_dialog(cx)),
                    ),
                )
        });
    }

    fn copy_text(&mut self, text: String, label: &'static str, cx: &mut Context<Self>) {
        self.tasks.push(client::call(
            cx,
            Request::CopyText {
                value: text.clone().into(),
            },
            move |this, res, cx| match res {
                Ok(_) => {
                    this.mark_copied(format!("text:{text}"), cx);
                    this.flash(tr!("{label} скопирован", label = label), false, cx)
                }
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    /// Отметка «скопировано» у элемента на 1.4 с.
    fn mark_copied(&mut self, key: String, cx: &mut Context<Self>) {
        self.copied = Some(key);
        self.copied_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(1400))
                .await;
            let _ = this.update(cx, |this, cx| {
                this.copied = None;
                cx.notify();
            });
        }));
        cx.notify();
    }

    fn text_copied(&self, text: &str) -> bool {
        self.copied.as_deref().and_then(|k| k.strip_prefix("text:")) == Some(text)
    }

    /// Пересчитать адреса из фразы или ключа, если поменялись параметры (вывод не на каждый кадр).
    fn derived_rows(
        &mut self,
        d: &EntryDetail,
        xpub: Option<&str>,
        cx: &mut Context<Self>,
    ) -> Option<Vec<DerivedRow>> {
        use keywarden_core::wallet;
        use keywarden_core::wallet_derive::{self as wd, Coin, Script};
        let seed = self.revealed_field(wallet::SEED);
        let key = self.revealed_field(wallet::PRIVATE_KEY);
        if seed.is_none() && key.is_none() && xpub.is_none() {
            return None;
        }
        let pass = self.revealed_field(wallet::PASSPHRASE).unwrap_or_default();
        let custom = self.dv_path.read(cx).value().trim().to_string();
        let cache_key = format!(
            "{}|{:?}|{:?}|{}|{}|{}|{:?}|{xpub:?}",
            d.summary.id,
            self.dv_coin,
            self.dv_script,
            self.dv_account,
            self.dv_count,
            custom,
            self.revealed_at
        );
        if let Some((k, rows)) = &self.dv_cache
            && *k == cache_key
        {
            return Some(rows.clone());
        }
        let mut rows = vec![];
        if let Some(phrase) = &seed {
            let check = wallet::check_seed(phrase);
            match wd::seed_bytes(phrase, &pass) {
                Err(e) => rows.push(DerivedRow::error(e, self.dv_coin)),
                Ok(sb) => {
                    let electrum = check.format == "electrum";
                    for i in 0..self.dv_count {
                        let (label, path) = if electrum {
                            (
                                format!("#{i}"),
                                wd::electrum_path(check.label.contains("segwit"), i),
                            )
                        } else if self.dv_coin == Coin::Sol {
                            (
                                tr!("аккаунт {i}", i = i),
                                wd::default_path(Coin::Sol, self.dv_script, i, 0),
                            )
                        } else if !custom.is_empty() {
                            (
                                format!("#{i}"),
                                format!("{}/{i}", custom.trim_end_matches('/')),
                            )
                        } else {
                            (
                                format!("#{i}"),
                                wd::default_path(self.dv_coin, self.dv_script, self.dv_account, i),
                            )
                        };
                        let coin = if electrum { Coin::Btc } else { self.dv_coin };
                        let script = if electrum && !check.label.contains("segwit") {
                            Script::Legacy
                        } else {
                            self.dv_script
                        };
                        let addr = wd::derive(&sb, coin, script, &path);
                        let tick = coin.id().to_uppercase();
                        let name = if electrum {
                            format!("{tick} Electrum #{i}")
                        } else if coin == Coin::Sol {
                            tr!("{tick} аккаунт {i}", tick = tick, i = i)
                        } else if !custom.is_empty() {
                            format!("{tick} {path}")
                        } else {
                            let sc = if coin.has_scripts() {
                                format!(" {}", script_name(script))
                            } else {
                                String::new()
                            };
                            let acc = if self.dv_account > 0 {
                                tr!(" акк {n}", n = self.dv_account)
                            } else {
                                String::new()
                            };
                            format!("{tick}{sc}{acc} #{i}")
                        };
                        rows.push(DerivedRow {
                            label,
                            path,
                            addr,
                            coin,
                            name,
                        });
                    }
                }
            }
        } else if let Some(x) = xpub {
            match wd::parse_xpub(x) {
                Err(e) => rows.push(DerivedRow::error(e, self.dv_coin)),
                Ok(xp) => {
                    let coin = if self.dv_coin == Coin::Sol {
                        xp.coin
                    } else {
                        self.dv_coin
                    };
                    for i in 0..self.dv_count {
                        rows.push(DerivedRow {
                            label: format!("#{i}"),
                            path: format!("xpub/0/{i}"),
                            addr: xp.address(coin, self.dv_script, 0, i),
                            coin,
                            name: format!("{} xpub #{i}", coin.id().to_uppercase()),
                        });
                    }
                }
            }
        } else if let Some(k) = &key {
            for coin in wd::key_coins(k) {
                let scripts: &[Script] = if coin.has_scripts() {
                    &[Script::Segwit, Script::Nested, Script::Legacy]
                } else {
                    &[Script::Legacy]
                };
                for sc in scripts {
                    let (label, name) = if coin.has_scripts() {
                        (
                            format!("{} {}", coin.label(), script_name(*sc)),
                            format!("{} {}", coin.id().to_uppercase(), script_name(*sc)),
                        )
                    } else {
                        (coin.label().to_string(), coin.id().to_uppercase())
                    };
                    rows.push(DerivedRow {
                        label,
                        path: String::new(),
                        addr: wd::address_from_private_key(k, coin, *sc),
                        coin,
                        name,
                    });
                }
            }
        }
        self.dv_cache = Some((cache_key, rows.clone()));
        Some(rows)
    }

    /// Вывод адресов из фразы, ключа или xpub: подпись вкладки и её содержимое.
    fn render_derived(
        &mut self,
        d: &EntryDetail,
        saved: &[(String, String)],
        cx: &mut Context<Self>,
    ) -> Option<(&'static str, AnyElement)> {
        use keywarden_core::wallet;
        use keywarden_core::wallet_derive::{Coin, Script};
        let theme = cx.theme().clone();
        let secret_field = |name: &str| {
            d.fields
                .iter()
                .any(|f| f.name == name && f.value.as_ref().is_none_or(|v| !v.is_empty()))
        };
        let has_seed = secret_field(wallet::SEED);
        let has_key = secret_field(wallet::PRIVATE_KEY);
        // xpub публичный: адреса без подтверждения, если в записи нет фразы и ключа
        let xpub = (!has_seed && !has_key)
            .then(|| {
                d.fields
                    .iter()
                    .find(|f| f.name == wallet::XPUB)
                    .and_then(|f| f.value.as_ref())
                    .map(|v| v.expose().trim().to_string())
                    .or_else(|| self.revealed_field(wallet::XPUB))
            })
            .flatten()
            .filter(|v| !v.is_empty());
        let has_xpub = xpub.is_some();
        if !has_seed && !has_key && !has_xpub {
            return None;
        }
        let tab = if has_seed {
            tr!("Из фразы")
        } else if has_key {
            tr!("Из ключа")
        } else {
            tr!("Из xpub")
        };
        let xp = xpub
            .as_deref()
            .and_then(|x| keywarden_core::wallet_derive::parse_xpub(x).ok());
        let Some(rows) = self.derived_rows(d, xpub.as_deref(), cx) else {
            return Some((
                tab,
                v_flex()
                    .items_center()
                    .gap_3()
                    .px_4()
                    .py_6()
                    .child(Icon::new(IconName::Wallet).text_color(theme.muted_foreground))
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .text_center()
                            .child(tr!("Публичные адреса всех сетей считаются из фразы прямо здесь, без интернета")),
                    )
                    .child(
                        Button::new("dv-show")
                            .primary()
                            .icon(IconName::Eye)
                            .label(tr!("Показать адреса"))
                            .on_click(cx.listener(|this, _, w, cx| {
                                this.with_auth(|this, _, cx| this.reveal_seed(cx), w, cx)
                            })),
                    )
                    .into_any_element(),
            ));
        };
        let electrum = self
            .revealed_field(wallet::SEED)
            .is_some_and(|s| wallet::check_seed(&s).format == "electrum");
        let controls = (has_seed && !electrum) || has_xpub;
        let eff_coin = match &xp {
            Some(x) if self.dv_coin == Coin::Sol => x.coin,
            _ => self.dv_coin,
        };
        // чипы сетей с цветной точкой
        let chips = h_flex().gap_1p5().flex_wrap().children(
            Coin::ALL
                .into_iter()
                .enumerate()
                .filter(|(_, c)| !(has_xpub && *c == Coin::Sol))
                .map(|(i, c)| {
                    let on = eff_coin == c;
                    let color = coin_color(c.id());
                    h_flex()
                        .id(("dv-coin", i))
                        .h(px(28.))
                        .px_2p5()
                        .gap_1p5()
                        .rounded_full()
                        .border_1()
                        .cursor_pointer()
                        .text_xs()
                        .font_weight(FontWeight::MEDIUM)
                        .when(on, |d| {
                            d.bg(color.opacity(0.16)).border_color(color.opacity(0.6))
                        })
                        .when(!on, |d| {
                            d.border_color(theme.border)
                                .text_color(theme.muted_foreground)
                                .hover(|s| s.bg(theme.secondary_hover))
                        })
                        .child(div().size(px(7.)).rounded_full().bg(color))
                        .child(c.id().to_uppercase())
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.dv_coin = c;
                            cx.notify();
                        }))
                }),
        );
        let fixed_script = xp.as_ref().is_some_and(|x| x.script.is_some());
        let script_seg = (eff_coin.has_scripts() && !fixed_script).then(|| {
            crate::ui::segmented(
                "dv-script",
                vec![
                    (None, "SegWit".into()),
                    (None, "Nested".into()),
                    (None, "Legacy".into()),
                ],
                match self.dv_script {
                    Script::Segwit => 0,
                    Script::Nested => 1,
                    Script::Legacy => 2,
                },
                cx,
                |this, ix, _, cx| {
                    this.dv_script = [Script::Segwit, Script::Nested, Script::Legacy][ix];
                    cx.notify();
                },
            )
            .into_any_element()
        });
        let seed_paths = has_seed && !electrum && self.dv_coin != Coin::Sol;
        let account = seed_paths.then(|| {
            h_flex()
                .gap_1()
                .items_center()
                .text_sm()
                .child(
                    div()
                        .text_color(theme.muted_foreground)
                        .child(tr!("Аккаунт")),
                )
                .child(
                    Button::new("dv-acc-")
                        .ghost()
                        .small()
                        .icon(IconName::Minus)
                        .disabled(self.dv_account == 0)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.dv_account = this.dv_account.saturating_sub(1);
                            cx.notify();
                        })),
                )
                .child(
                    div()
                        .min_w(px(20.))
                        .text_center()
                        .font_weight(FontWeight::MEDIUM)
                        .child(self.dv_account.to_string()),
                )
                .child(
                    Button::new("dv-acc+")
                        .ghost()
                        .small()
                        .icon(IconName::Plus)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.dv_account += 1;
                            cx.notify();
                        })),
                )
        });
        let custom_btn = seed_paths.then(|| {
            Button::new("dv-custom")
                .small()
                .when(self.dv_custom, |b| b.outline())
                .when(!self.dv_custom, |b| b.ghost())
                .icon(IconName::SlidersHorizontal)
                .label(tr!("Свой путь"))
                .on_click(cx.listener(|this, _, w, cx| {
                    this.dv_custom = !this.dv_custom;
                    if !this.dv_custom {
                        this.dv_path.update(cx, |i, cx| i.set_value("", w, cx));
                    }
                    cx.notify();
                }))
        });
        let list: Vec<AnyElement> = rows
            .into_iter()
            .enumerate()
            .map(|(ix, row)| {
                let base = h_flex()
                    .gap_3()
                    .px_4()
                    .py_2()
                    .min_h(px(52.))
                    .when(ix > 0, |d| {
                        d.border_t_1().border_color(theme.table_row_border)
                    });
                let a = match row.addr {
                    Err(e) => {
                        return base
                            .child(
                                Icon::new(IconName::TriangleAlert)
                                    .small()
                                    .text_color(theme.danger_foreground),
                            )
                            .child(div().text_sm().text_color(theme.danger_foreground).child(e))
                            .into_any_element();
                    }
                    Ok(a) => a,
                };
                let coin = row.coin;
                let dv_copied = self.text_copied(&a);
                let saved_as =
                    saved
                        .iter()
                        .find(|(_, s)| s.eq_ignore_ascii_case(&a))
                        .map(|(l, _)| {
                            if l.is_empty() {
                                tr!("сохранён").to_string()
                            } else {
                                l.clone()
                            }
                        });
                let explorer = self
                    .explorers
                    .get(coin.id())
                    .map(|t| wallet::explorer_url(t, &a));
                let (a1, a2, a3) = (a.clone(), a.clone(), a.clone());
                let name = row.name.clone();
                let key_rows = !controls;
                base.child(if key_rows {
                    coin_avatar(coin.id(), 30.).into_any_element()
                } else {
                    div()
                        .w(px(30.))
                        .flex_shrink_0()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(row.label.clone())
                        .into_any_element()
                })
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_0p5()
                        .when(key_rows, |d| {
                            d.child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(row.label.clone()),
                            )
                        })
                        .child(
                            div()
                                .id(("dv-addr", ix))
                                .text_sm()
                                .font_family(theme.mono_font_family.clone())
                                .truncate()
                                .cursor_pointer()
                                .hover(|s| s.text_color(theme.primary))
                                .child(copied_or(dv_copied, mid_addr(&a, 18, 10), &theme))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.copy_text(a1.clone(), tr!("Адрес"), cx)
                                })),
                        )
                        .when(!row.path.is_empty(), |d| {
                            d.child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .font_family(theme.mono_font_family.clone())
                                    .child(row.path.clone()),
                            )
                        }),
                )
                .child(
                    Button::new(("dv-qr", ix))
                        .ghost()
                        .small()
                        .icon(IconName::QrCode)
                        .tooltip(tr!("QR-код"))
                        .on_click(cx.listener(move |this, _, w, cx| {
                            this.show_address_qr(a2.clone(), w, cx)
                        })),
                )
                .children(explorer.map(|url| {
                    Button::new(("dv-exp", ix))
                        .ghost()
                        .small()
                        .icon(IconName::ExternalLink)
                        .tooltip(tr!("Открыть в обозревателе"))
                        .on_click(move |_, _, cx| cx.open_url(&url))
                }))
                .child(match saved_as {
                    Some(l) => div()
                        .w(px(124.))
                        .flex()
                        .justify_end()
                        .child(badge(l, theme.success_foreground))
                        .into_any_element(),
                    None => div()
                        .w(px(124.))
                        .flex()
                        .justify_end()
                        .child(
                            Button::new(("dv-save", ix))
                                .outline()
                                .small()
                                .icon(IconName::Plus)
                                .label(tr!("Сохранить"))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.add_address(name.clone(), a3.clone(), cx)
                                })),
                        )
                        .into_any_element(),
                })
                .into_any_element()
            })
            .collect();
        let body = v_flex()
            .when(controls, |d| {
                d.child(
                    v_flex()
                        .gap_3()
                        .px_4()
                        .py_3()
                        .child(chips)
                        .child(
                            h_flex()
                                .gap_4()
                                .flex_wrap()
                                .items_center()
                                .children(script_seg)
                                .children(account)
                                .child(div().flex_1())
                                .children(custom_btn),
                        )
                        .when(self.dv_custom && seed_paths, |d| {
                            d.child(
                                v_flex()
                                    .gap_1()
                                    .child(Input::new(&self.dv_path))
                                    .child(
                                        div()
                                            .text_xs()
                                            .text_color(theme.muted_foreground)
                                            .child(tr!("Путь без номера адреса, номер допишется сам. Например m/84'/0'/1'/0 для аккаунта 1")),
                                    ),
                            )
                        }),
                )
            })
            .when(electrum, |d| {
                d.child(
                    div()
                        .px_4()
                        .py_2()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .child(tr!("Фраза Electrum: адреса Bitcoin по путям Electrum")),
                )
            })
            .child(
                v_flex()
                    .mx_4()
                    .mt(px(if controls { 4. } else { 12. }))
                    .mb_2()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .overflow_hidden()
                    .children(list),
            )
            .when(has_seed || has_xpub, |d| {
                d.child(
                    h_flex()
                        .px_4()
                        .pb_2()
                        .gap_3()
                        .child(
                            Button::new("dv-more")
                                .ghost()
                                .small()
                                .icon(IconName::ChevronDown)
                                .label(tr!("Ещё 5 адресов"))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.dv_count += 5;
                                    cx.notify();
                                })),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(theme.muted_foreground)
                                .child(tr!("Считаются здесь, без интернета. Щелчок по адресу копирует")),
                        ),
                )
            })
            .into_any_element();
        Some((tab, body))
    }

    /// Записать список адресов в поле «Адреса»: строка «подпись: адрес».
    fn set_addresses(
        &mut self,
        list: Vec<(String, String)>,
        done: &'static str,
        cx: &mut Context<Self>,
    ) {
        let Some(id) = self.selected_id() else { return };
        let text = list
            .iter()
            .map(|(l, a)| {
                if l.trim().is_empty() {
                    a.clone()
                } else {
                    format!("{}: {a}", l.trim())
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        self.tasks.push(client::call(
            cx,
            Request::Update {
                id,
                patch: keywarden_core::model::EntryPatch {
                    set: vec![keywarden_core::model::FieldSet::new(
                        keywarden_core::wallet::ADDRESSES,
                        text,
                    )],
                    ..Default::default()
                },
            },
            move |this, res, cx| match res {
                Ok(_) => this.flash(done, false, cx),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn saved_addresses(&self) -> Vec<(String, String)> {
        let text = self
            .detail
            .as_ref()
            .and_then(|d| {
                d.fields
                    .iter()
                    .find(|f| f.name == keywarden_core::wallet::ADDRESSES)
            })
            .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
            .unwrap_or_default();
        keywarden_core::wallet::parse_addresses(&text)
    }

    fn add_address(&mut self, label: String, addr: String, cx: &mut Context<Self>) {
        let mut list = self.saved_addresses();
        if list.iter().any(|(_, a)| a.eq_ignore_ascii_case(&addr)) {
            return;
        }
        list.push((label, addr));
        self.set_addresses(list, tr!("Адрес сохранён"), cx);
    }

    fn remove_address(&mut self, ix: usize, cx: &mut Context<Self>) {
        if self.addr_confirm_rm != Some(ix) {
            self.addr_confirm_rm = Some(ix);
            return cx.notify();
        }
        self.addr_confirm_rm = None;
        let mut list = self.saved_addresses();
        if ix < list.len() {
            list.remove(ix);
            self.set_addresses(list, tr!("Адрес удалён"), cx);
        }
    }

    /// Переименование прямо в строке: Enter сохраняет, уход фокуса отменяет.
    fn start_rename(&mut self, ix: usize, window: &mut Window, cx: &mut Context<Self>) {
        let label = self
            .saved_addresses()
            .get(ix)
            .map(|(l, _)| l.clone())
            .unwrap_or_default();
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("Название, например «Биржа» или «Холодный»"))
                .default_value(label)
        });
        input.update(cx, |i, cx| i.focus(window, cx));
        let sub = cx.subscribe_in(&input, window, move |this, inp, ev, _, cx| match ev {
            InputEvent::PressEnter { .. } => {
                let v = inp.read(cx).value().to_string();
                this.addr_edit = None;
                let mut list = this.saved_addresses();
                if let Some(item) = list.get_mut(ix) {
                    // двоеточие отделяет подпись от адреса в поле
                    item.0 = v.replace(':', " ").trim().to_string();
                    this.set_addresses(list, tr!("Название сохранено"), cx);
                }
                cx.notify();
            }
            InputEvent::Blur => {
                this.addr_edit = None;
                cx.notify();
            }
            _ => {}
        });
        self.addr_edit = Some((ix, input, sub));
        cx.notify();
    }

    /// Сохранённые адреса карточками: значок сети, название, короткий адрес, действия.
    fn render_saved(
        &mut self,
        saved: &[(String, String)],
        hint: &'static str,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        use keywarden_core::wallet;
        let theme = cx.theme().clone();
        if saved.is_empty() {
            return v_flex()
                .items_center()
                .gap_2()
                .px_4()
                .py_6()
                .child(Icon::new(IconName::Wallet).text_color(theme.muted_foreground))
                .child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .text_center()
                        .child(hint),
                )
                .into_any_element();
        }
        let rows: Vec<AnyElement> = saved
            .iter()
            .enumerate()
            .map(|(ix, (label, addr))| {
                let nets = wallet::address_networks(addr);
                let net = nets.first().copied().unwrap_or("");
                let title = if !label.is_empty() {
                    label.clone()
                } else if net.is_empty() {
                    tr!("Адрес").to_string()
                } else {
                    net.to_uppercase()
                };
                let explorer = nets
                    .first()
                    .and_then(|n| self.explorers.get(*n))
                    .map(|t| wallet::explorer_url(t, addr));
                let (a1, a2) = (addr.clone(), addr.clone());
                let editing = self
                    .addr_edit
                    .as_ref()
                    .filter(|(i, _, _)| *i == ix)
                    .map(|(_, inp, _)| inp.clone());
                let confirm = self.addr_confirm_rm == Some(ix);
                let copied = self.text_copied(addr);
                h_flex()
                    .id(("saved-addr", ix))
                    .gap_3()
                    .px_3()
                    .py_2p5()
                    .when(ix > 0, |d| {
                        d.border_t_1().border_color(theme.table_row_border)
                    })
                    .hover(|s| s.bg(theme.secondary))
                    .child(coin_avatar(net, 34.))
                    .child(
                        v_flex()
                            .id(("saved-copy", ix))
                            .group("saved-copy")
                            .flex_1()
                            .min_w_0()
                            .gap_0p5()
                            .when(editing.is_none(), |d| {
                                d.cursor_pointer()
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.copy_text(a1.clone(), tr!("Адрес"), cx)
                                    }))
                            })
                            .child(match editing {
                                Some(inp) => Input::new(&inp).into_any_element(),
                                None => h_flex()
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(FontWeight::MEDIUM)
                                            .truncate()
                                            .child(title),
                                    )
                                    .when(nets.len() > 1, |d| {
                                        d.child(badge(
                                            nets.join(" · ").to_uppercase(),
                                            theme.muted_foreground,
                                        ))
                                    })
                                    .into_any_element(),
                            })
                            .child(
                                div()
                                    .text_xs()
                                    .font_family(theme.mono_font_family.clone())
                                    .text_color(theme.muted_foreground)
                                    .group_hover("saved-copy", |s| s.text_color(theme.primary))
                                    .child(copied_or(copied, short_addr(addr), &theme)),
                            ),
                    )
                    .child(
                        Button::new(("saved-qr", ix))
                            .ghost()
                            .small()
                            .icon(IconName::QrCode)
                            .tooltip(tr!("QR-код"))
                            .on_click(cx.listener(move |this, _, w, cx| {
                                this.show_address_qr(a2.clone(), w, cx)
                            })),
                    )
                    .children(explorer.map(|url| {
                        Button::new(("saved-exp", ix))
                            .ghost()
                            .small()
                            .icon(IconName::ExternalLink)
                            .tooltip(tr!("Открыть в обозревателе"))
                            .on_click(move |_, _, cx| cx.open_url(&url))
                    }))
                    .child(
                        Button::new(("saved-rename", ix))
                            .ghost()
                            .small()
                            .icon(IconName::Pencil)
                            .tooltip(tr!("Переименовать"))
                            .on_click(
                                cx.listener(move |this, _, w, cx| this.start_rename(ix, w, cx)),
                            ),
                    )
                    .child(
                        Button::new(("saved-rm", ix))
                            .small()
                            .when(confirm, |b| b.danger().label(tr!("Удалить?")))
                            .when(!confirm, |b| {
                                b.ghost()
                                    .icon(IconName::Trash)
                                    .tooltip(tr!("Убрать из записи"))
                            })
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.remove_address(ix, cx)),
                            ),
                    )
                    .into_any_element()
            })
            .collect();
        v_flex()
            .m_4()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .overflow_hidden()
            .children(rows)
            .into_any_element()
    }

    /// Блоки «Сид-фраза» и «Адреса» в карточке кошелька.
    /// Ключ SSH: открытый ключ, куда его добавить и подпись коммитов git.
    fn render_ssh(&mut self, d: &EntryDetail, cx: &mut Context<Self>) -> AnyElement {
        use keywarden_core::git_signing;
        let theme = cx.theme().clone();
        let Some(public) = d
            .notes
            .lines()
            .find(|l| git_signing::key_body(l).is_some())
            .map(str::to_string)
        else {
            return div().into_any_element();
        };
        let signing = self
            .git_signing
            .get_or_insert_with(git_signing::current)
            .clone();
        let ours = git_signing::key_body(&public) == signing;
        let link = |id: &'static str, label: &'static str, url: &'static str| {
            Button::new(id)
                .ghost()
                .small()
                .icon(IconName::ExternalLink)
                .label(label)
                .on_click(move |_, _, cx| cx.open_url(url))
        };
        let copy_pub = public.clone();
        let sign_pub = public.clone();
        v_flex()
            .child(section_head(tr!("Открытый ключ"), None, None, &theme))
            .child(
                v_flex()
                    .rounded_lg()
                    .overflow_hidden()
                    .border_1()
                    .border_color(theme.border)
                    .child(
                        v_flex()
                            .gap_3()
                            .px_4()
                            .py_3()
                            .child(
                                div()
                                    .text_xs()
                                    .font_family(theme.mono_font_family.clone())
                                    .text_color(theme.muted_foreground)
                                    .line_clamp(2)
                                    .child(public.clone()),
                            )
                            .child(
                                h_flex()
                                    .gap_1()
                                    .flex_wrap()
                                    .child(
                                        Button::new("ssh-copy-pub")
                                            .outline()
                                            .small()
                                            .icon(IconName::Copy)
                                            .label(tr!("Скопировать"))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                cx.write_to_clipboard(ClipboardItem::new_string(
                                                    copy_pub.clone(),
                                                ));
                                                this.flash(
                                                    tr!("Открытый ключ скопирован"),
                                                    false,
                                                    cx,
                                                );
                                            })),
                                    )
                                    .child(link(
                                        "ssh-gh",
                                        tr!("Добавить на GitHub"),
                                        "https://github.com/settings/ssh/new",
                                    ))
                                    .child(link(
                                        "ssh-gl",
                                        tr!("GitLab"),
                                        "https://gitlab.com/-/user_settings/ssh_keys",
                                    )),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_3()
                            .px_4()
                            .py_3()
                            .border_t_1()
                            .border_color(theme.border)
                            .child(
                                gpui_kit::component::switch::Switch::new("ssh-git")
                                    .checked(ours)
                                    .label(tr!("Подписывать этим ключом коммиты и теги git"))
                                    .on_change(cx.listener(move |this, on: &bool, _, cx| {
                                        let res = if *on {
                                            git_signing::enable(&sign_pub)
                                        } else {
                                            git_signing::disable()
                                        };
                                        match res {
                                            Ok(()) if *on => this.flash(
                                                tr!("git подписывает коммиты и теги этим ключом"),
                                                false,
                                                cx,
                                            ),
                                            Ok(()) => {}
                                            Err(e) => this.flash(e, true, cx),
                                        }
                                        this.git_signing = None;
                                        cx.notify();
                                    })),
                            )
                            .when(ours, |d| {
                                d.child(div().flex_1()).child(crate::ui::badge(
                                    tr!("подписывает коммиты git"),
                                    theme.success_foreground,
                                ))
                            }),
                    ),
            )
            .into_any_element()
    }

    fn render_wallet(&mut self, d: &EntryDetail, cx: &mut Context<Self>) -> AnyElement {
        use keywarden_core::wallet;
        let theme = cx.theme().clone();
        // фраза есть, если поле скрыто (значит непустое) или раскрыто непустым
        let has_seed = d
            .fields
            .iter()
            .any(|f| f.name == wallet::SEED && f.value.as_ref().is_none_or(|v| !v.is_empty()));
        let seed = self.revealed_field(wallet::SEED);
        let seed_card: AnyElement = match &seed {
            None => h_flex()
                .gap_3()
                .px_4()
                .py_3()
                .text_sm()
                .child(
                    Icon::new(IconName::LockKeyhole)
                        .small()
                        .text_color(theme.muted_foreground),
                )
                .child(
                    div()
                        .flex_1()
                        .text_color(theme.muted_foreground)
                        .child(tr!("Фраза скрыта: откроется после PIN или мастер-пароля")),
                )
                .child(
                    Button::new("seed-show")
                        .outline()
                        .small()
                        .icon(IconName::Eye)
                        .label(tr!("Показать"))
                        .on_click(cx.listener(|this, _, w, cx| {
                            this.with_auth(|this, _, cx| this.reveal_seed(cx), w, cx)
                        })),
                )
                .into_any_element(),
            Some(text) => {
                let check = wallet::check_seed(text);
                let color = if check.valid && check.complete {
                    theme.success_foreground
                } else if check.valid {
                    theme.warning_foreground
                } else {
                    theme.danger_foreground
                };
                let mut global = 0usize;
                let shares: Vec<Vec<String>> = text
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.split_whitespace().map(String::from).collect())
                    .collect();
                let many = shares.len() > 1;
                let mut blocks: Vec<AnyElement> = vec![];
                for (si, words) in shares.iter().enumerate() {
                    let rows = words.len().div_ceil(3).max(1);
                    let base = global;
                    global += words.len();
                    let grid = h_flex().gap_2().items_start().children((0..3).map(|col| {
                        v_flex().flex_1().gap_1p5().children(
                            (col * rows..((col + 1) * rows).min(words.len())).map(|i| {
                                let g = base + i;
                                let open = self.seed_all || self.seed_open.contains(&g);
                                h_flex()
                                    .id(("seed-w", g))
                                    .h(px(34.))
                                    .px_3()
                                    .gap_2()
                                    .rounded_md()
                                    .bg(theme.secondary)
                                    .cursor_pointer()
                                    .hover(|d| d.bg(theme.secondary_active))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        if !this.seed_open.remove(&g) {
                                            this.seed_open.insert(g);
                                        }
                                        cx.notify();
                                    }))
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
                                            .text_color(if open {
                                                theme.foreground
                                            } else {
                                                theme.muted_foreground
                                            })
                                            .child(if open {
                                                words[i].clone()
                                            } else {
                                                "•••••".to_string()
                                            }),
                                    )
                            }),
                        )
                    }));
                    blocks.push(
                        v_flex()
                            .gap_2()
                            .when(many, |d| {
                                d.child(
                                    div()
                                        .text_xs()
                                        .text_color(theme.muted_foreground)
                                        .child(tr!("Доля {n}", n = si + 1)),
                                )
                            })
                            .child(grid)
                            .into_any_element(),
                    );
                }
                let bip39 = check.format == "bip39" && check.valid;
                v_flex()
                    .gap_3()
                    .px_4()
                    .py_3()
                    .child(
                        h_flex()
                            .gap_2()
                            .text_xs()
                            .child(badge(check.label.clone(), color))
                            .child(div().text_color(color).child(check.message.clone())),
                    )
                    .children(blocks)
                    .child(
                        h_flex()
                            .gap_1()
                            .flex_wrap()
                            .child(
                                Button::new("seed-all")
                                    .ghost()
                                    .small()
                                    .icon(if self.seed_all {
                                        IconName::EyeOff
                                    } else {
                                        IconName::Eye
                                    })
                                    .label(if self.seed_all {
                                        tr!("Скрыть слова")
                                    } else {
                                        tr!("Показать все")
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.seed_all = !this.seed_all;
                                        this.seed_open.clear();
                                        cx.notify();
                                    })),
                            )
                            .child(
                                Button::new("seed-copy")
                                    .ghost()
                                    .small()
                                    .icon(IconName::Copy)
                                    .label(tr!("Скопировать"))
                                    .tooltip(tr!("Буфер очистится через 10 секунд"))
                                    .on_click(cx.listener(|this, _, w, cx| {
                                        this.with_auth(
                                            |this, _, cx| {
                                                this.copy(keywarden_core::wallet::SEED, cx)
                                            },
                                            w,
                                            cx,
                                        )
                                    })),
                            )
                            .child(
                                Button::new("seed-card")
                                    .ghost()
                                    .small()
                                    .icon(IconName::FileDown)
                                    .label(tr!("Карточка для печати"))
                                    .on_click(cx.listener(|this, _, w, cx| {
                                        this.with_auth(
                                            |this, _, cx| this.print_card(false, cx),
                                            w,
                                            cx,
                                        )
                                    })),
                            )
                            .when(bip39, |d| {
                                d.child(
                                    Button::new("seed-card-qr")
                                        .ghost()
                                        .small()
                                        .icon(IconName::QrCode)
                                        .label(tr!("Карточка с SeedQR"))
                                        .on_click(cx.listener(|this, _, w, cx| {
                                            this.with_auth(
                                                |this, _, cx| this.print_card(true, cx),
                                                w,
                                                cx,
                                            )
                                        })),
                                )
                                .child(
                                    Button::new("seed-qr")
                                        .ghost()
                                        .small()
                                        .icon(IconName::QrCode)
                                        .label("SeedQR")
                                        .on_click(cx.listener(|this, _, w, cx| {
                                            this.with_auth(
                                                |this, w, cx| this.show_seedqr(w, cx),
                                                w,
                                                cx,
                                            )
                                        })),
                                )
                            }),
                    )
                    .into_any_element()
            }
        };
        let saved = wallet::parse_addresses(
            &d.fields
                .iter()
                .find(|f| f.name == wallet::ADDRESSES)
                .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
                .unwrap_or_default(),
        );
        let derived = self.render_derived(d, &saved, cx);
        let derive_tab = derived.as_ref().map(|(t, _)| *t);
        // вкладка по умолчанию: сохранённые, если они есть
        let tab = self.addr_tab.filter(|_| derive_tab.is_some()).unwrap_or(
            if saved.is_empty() && derive_tab.is_some() {
                1
            } else {
                0
            },
        );
        let hint = if derive_tab.is_some() {
            tr!(
                "Пока ничего не сохранено. На соседней вкладке нажмите «Сохранить» у нужного адреса"
            )
        } else {
            tr!(
                "Адресов нет. Добавьте их в правке записи или сохраните xpub, тогда адреса посчитаются сами"
            )
        };
        let tabs = derive_tab.map(|dt| {
            crate::ui::segmented(
                "addr-tabs",
                vec![
                    (
                        None,
                        if saved.is_empty() {
                            tr!("Сохранённые").to_string()
                        } else {
                            tr!("Сохранённые · {n}", n = saved.len())
                        },
                    ),
                    (None, dt.to_string()),
                ],
                tab,
                cx,
                |this, ix, _, cx| {
                    this.addr_tab = Some(ix);
                    cx.notify();
                },
            )
            .into_any_element()
        });
        let body = if tab == 1 {
            derived.map(|(_, b)| b)
        } else {
            Some(self.render_saved(&saved, hint, cx))
        };
        let show_addresses = derive_tab.is_some() || !saved.is_empty();
        v_flex()
            .gap_5()
            .when(has_seed, |d| {
                d.child(
                    v_flex()
                        .child(section_head(tr!("Сид-фраза"), None, None, &theme))
                        .child(v_flex().rounded_lg().child(seed_card)),
                )
            })
            .when(show_addresses, |d| {
                d.child(
                    v_flex()
                        .child(section_head(
                            tr!("Адреса"),
                            if derive_tab.is_none() {
                                Some(saved.len())
                            } else {
                                None
                            },
                            None,
                            &theme,
                        ))
                        .children(tabs.map(|t| h_flex().px_4().pt_3().child(t)))
                        .children(body),
                )
            })
            .into_any_element()
    }

    fn on_event(&mut self, ev: Event, cx: &mut Context<Self>) {
        match ev {
            Event::Locked => {
                self.refresh_quick(cx);
                self.forget_session(None, cx);
                self.flash(tr!("База заблокирована"), false, cx);
            }
            Event::Unlocked if self.mode != Mode::Ready => {
                self.mode = Mode::Ready;
                self.reload_all(cx);
            }
            Event::Changed => self.reload_all(cx),
            Event::Saved => self.flash(tr!("Сохранено"), false, cx),
            Event::SaveFailed { message } => {
                self.flash(tr!("Не сохранено: {message}", message = message), true, cx)
            }
            Event::Merged { message } => {
                self.flash(message, false, cx);
                self.reload_all(cx);
            }
            Event::SyncHeld { message } => self.flash(message, true, cx),
            _ => {}
        }
        cx.notify();
    }

    /// Окно переноса серверов из ~/.ssh/config (то же, что в настройках, вкладка SSH).
    fn open_ssh_import(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::Prefs { set: None },
            |this, res, window, cx| {
                let prefs = match res {
                    Ok(Response::Prefs { prefs }) => *prefs,
                    Ok(_) => return,
                    Err(e) => return this.flash(e.message(), true, cx),
                };
                this.tasks.push(client::call_in(
                    window,
                    cx,
                    Request::SshConfigHosts,
                    move |this, res, window, cx| {
                        let hosts = match res {
                            Ok(Response::SshConfigHosts { hosts }) => hosts,
                            Ok(_) => return,
                            Err(e) => return this.flash(e.message(), true, cx),
                        };
                        if !hosts.iter().any(|h| !h.in_vault) {
                            return this.flash(
                                tr!("В ~/.ssh/config нет новых серверов"),
                                false,
                                cx,
                            );
                        }
                        this.show_ssh_import(hosts, prefs.clone(), window, cx);
                    },
                ));
            },
        ));
    }

    fn show_ssh_import(
        &mut self,
        hosts: Vec<keywarden_core::ipc::ConfigHostPreview>,
        prefs: keywarden_core::ipc::Prefs,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let on = prefs.ssh_host_config;
        let view = cx.new(|cx| {
            crate::ssh_migrate::SshMigrate::new(crate::ssh_migrate::Source::Hosts(hosts), on, cx)
        });
        self._subs.push(cx.subscribe_in(
            &view,
            window,
            move |this, _, ev: &crate::ssh_migrate::MigrateEvent, window, cx| {
                let crate::ssh_migrate::MigrateEvent::Done {
                    message,
                    enable_hosts,
                } = ev;
                window.close_dialog(cx);
                this.flash(message.clone(), false, cx);
                if *enable_hosts {
                    let mut p = prefs.clone();
                    p.ssh_host_config = true;
                    this.tasks.push(client::call(
                        cx,
                        Request::Prefs { set: Some(p) },
                        |this, res, cx| {
                            if let Err(e) = res {
                                this.flash(e.message(), true, cx);
                            }
                        },
                    ));
                }
                this.reload_all(cx);
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

    fn flash(&mut self, text: impl Into<SharedString>, error: bool, cx: &mut Context<Self>) {
        self.status = Some((text.into(), error));
        self.status_at = Some(Instant::now());
        cx.notify();
    }

    fn reload_all(&mut self, cx: &mut Context<Self>) {
        self.tasks
            .push(client::call(cx, Request::Status, |this, res, cx| {
                if let Ok(Response::Status(s)) = res {
                    this.open_path = s.path;
                    this.total = s.entries;
                }
                cx.notify();
            }));
        self.tasks
            .push(client::call(cx, Request::Tags, |this, res, cx| {
                if let Ok(Response::Tags { tags }) = res {
                    this.tags = tags;
                    if let Nav::Tag(t) = &this.nav
                        && !this.tags.iter().any(|(x, _)| x == t)
                    {
                        this.nav = Nav::All;
                    }
                }
                cx.notify();
            }));
        self.tasks
            .push(client::call(cx, Request::Groups, |this, res, cx| {
                if let Ok(Response::Groups { groups }) = res {
                    this.groups = groups;
                    if let Nav::Group(g) = &this.nav
                        && !this.groups.iter().any(|v| &v.id == g)
                    {
                        this.nav = Nav::All;
                    }
                }
                cx.notify();
            }));
        self.reload_list(false, cx);
    }

    fn filter(&self) -> Filter {
        let mut f = match &self.nav {
            Nav::All | Nav::Otp | Nav::Settings | Nav::Health => Filter::default(),
            Nav::Kind(k) => Filter {
                kind: Some(*k),
                ..Default::default()
            },
            Nav::Group(g) => Filter {
                group: Some(g.clone()),
                ..Default::default()
            },
            Nav::Tag(t) => Filter {
                tag: Some(t.clone()),
                ..Default::default()
            },
        };
        f.manual = self.sort == Sort::Manual;
        f
    }

    /// Поиск на каждую клавишу, но не чаще, чем раз в 60 мс: быстрый набор не копит запросы.
    fn reload_list_debounced(&mut self, cx: &mut Context<Self>) {
        self.debounce_task = Some(cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(60))
                .await;
            let _ = this.update(cx, |this, cx| this.reload_list(true, cx));
        }));
    }

    /// `reset`: выделить первую запись (новый запрос), иначе сохранить выбранную.
    fn reload_list(&mut self, reset: bool, cx: &mut Context<Self>) {
        self.loading_list = true;
        let query = self.search.read(cx).value().to_string();
        let keep = if reset { None } else { self.selected_id() };
        let req = Request::Search {
            query,
            limit: 500,
            filter: self.filter(),
        };
        self.search_task = Some(client::call(cx, req, move |this, res, cx| {
            this.loading_list = false;
            match res {
                Ok(Response::Entries { mut entries }) => {
                    match this.sort {
                        Sort::Manual | Sort::Relevance => {}
                        Sort::Title => entries.sort_by_key(|e| e.title.to_lowercase()),
                        Sort::Modified => entries.sort_by(|a, b| b.modified.cmp(&a.modified)),
                        Sort::Created => entries.sort_by(|a, b| b.created.cmp(&a.created)),
                    }
                    if this.nav == Nav::Otp {
                        entries.retain(|e| e.has_otp);
                        for e in &entries {
                            if !this.otp_codes.contains_key(&e.id) {
                                this.fetch_otp(e.id.clone(), cx);
                            }
                        }
                    }
                    this.entries = entries;
                    if reset {
                        this.rows_anim += 1;
                    }
                    this.load_icons(cx);
                    let keep = this.pending_select.take().or(keep);
                    let pos = keep.and_then(|id| this.entries.iter().position(|e| e.id == id));
                    this.select(
                        pos.or(if this.entries.is_empty() {
                            None
                        } else {
                            Some(0)
                        }),
                        cx,
                    );
                }
                Err(CallError::Locked) => this.mode = Mode::Locked,
                Err(e) => this.flash(e.message(), true, cx),
                Ok(_) => {}
            }
            cx.notify();
        }));
    }

    fn selected_id(&self) -> Option<String> {
        self.selected
            .and_then(|i| self.entries.get(i))
            .map(|e| e.id.clone())
    }

    fn select(&mut self, ix: Option<usize>, cx: &mut Context<Self>) {
        let changed = ix.and_then(|i| self.entries.get(i)).map(|e| &e.id)
            != self.detail.as_ref().map(|d| &d.summary.id);
        self.selected = ix;
        if let Some(i) = ix {
            self.list_scroll.scroll_to_item(i);
        }
        if changed {
            self.revealed = None;
            self.revealed_at = None;
            self.shown.clear();
            self.code = None;
            self.detail_tab = 0;
            self.history_open = false;
            self.addr_tab = None;
            self.addr_edit = None;
            self.addr_confirm_rm = None;
        }
        let Some(id) = self.selected_id() else {
            self.detail = None;
            self.loading_detail = false;
            cx.notify();
            return;
        };
        if self.nav == Nav::Otp {
            cx.notify();
            return;
        }
        // код 2FA запрашивается сразу, вместе с карточкой, а не после неё: без второго сдвига
        let has_otp = self
            .selected
            .and_then(|i| self.entries.get(i))
            .is_some_and(|e| e.has_otp);
        if changed && has_otp {
            self.fetch_code(id.clone(), cx);
        }
        // старая карточка остаётся на месте, пока не придёт новая: без пустого кадра
        self.loading_detail = changed;
        self.detail_task = Some(client::call(
            cx,
            Request::Get { id, reveal: false },
            |this, res, cx| {
                this.loading_detail = false;
                if let Ok(Response::Entry { entry }) = res {
                    this.detail = Some(*entry);
                }
                cx.notify();
            },
        ));
        cx.notify();
    }

    fn move_selection(&mut self, delta: isize, cx: &mut Context<Self>) {
        if self.entries.is_empty() || self.editor.is_some() {
            return;
        }
        let n = self.entries.len() as isize;
        let cur = self.selected.map(|s| s as isize).unwrap_or(-1);
        self.select(Some((cur + delta).clamp(0, n - 1) as usize), cx);
    }

    fn navs(&self) -> Vec<Nav> {
        let mut v = vec![Nav::All, Nav::Otp, Nav::Health];
        v.extend(EntryKind::ALL.into_iter().map(Nav::Kind));
        v.extend(self.groups.iter().skip(1).map(|g| Nav::Group(g.id.clone())));
        v
    }

    fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let page = cx.new(|cx| crate::settings_page::SettingsPage::new(window, cx));
        self._subs
            .push(cx.subscribe(&page, |this, _, ev, cx| match ev {
                crate::settings_page::SettingsEvent::Changed => this.reload_all(cx),
            }));
        page.update(cx, |p, cx| p.focus(window, cx));
        self.settings = Some(page);
        self.nav = Nav::Settings;
        self.editor = None;
        cx.notify();
    }

    fn set_nav(&mut self, nav: Nav, cx: &mut Context<Self>) {
        self.settings = None;
        if nav == Nav::Health {
            self.nav = nav;
            self.editor = None;
            return self.load_health(false, cx);
        }
        self.nav = nav;
        self.editor = None;
        self.reload_list(true, cx);
    }

    fn step_nav(&mut self, delta: isize, cx: &mut Context<Self>) {
        let navs = self.navs();
        let cur = navs.iter().position(|n| *n == self.nav).unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(navs.len() as isize) as usize;
        self.set_nav(navs[next].clone(), cx);
    }

    fn fetch_code(&mut self, id: String, cx: &mut Context<Self>) {
        let want = id.clone();
        self.tasks.push(client::call(
            cx,
            Request::Totp { id },
            move |this, res, cx| {
                // ответ мог прийти, когда уже выбрана другая запись
                if let Ok(Response::Totp { code }) = res
                    && this.selected_id().as_deref() == Some(want.as_str())
                {
                    this.code = Some(code);
                    cx.notify();
                }
            },
        ));
    }

    fn fetch_otp(&mut self, id: String, cx: &mut Context<Self>) {
        let key = id.clone();
        self.tasks.push(client::call(
            cx,
            Request::Totp { id },
            move |this, res, cx| {
                if let Ok(Response::Totp { code }) = res {
                    this.otp_codes.insert(key, code);
                    cx.notify();
                }
            },
        ));
    }

    fn ticker(cx: &mut Context<Self>) -> Task<()> {
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(Duration::from_secs(1)).await;
                let alive = this.update(cx, |this, cx| {
                    this.tasks.retain(|t| !t.is_ready());
                    let now = Instant::now();
                    if this.status_at.is_some_and(|t| now - t > STATUS_TTL) {
                        this.status = None;
                        this.status_at = None;
                        cx.notify();
                    }
                    if this.revealed_at.is_some_and(|t| now - t > REVEAL_TTL) {
                        this.revealed = None;
                        this.revealed_at = None;
                        this.shown.clear();
                        cx.notify();
                    }
                    if this.nav == Nav::Otp && !this.otp_codes.is_empty() {
                        let mut stale = vec![];
                        for (id, c) in this.otp_codes.iter_mut() {
                            c.remaining = c.remaining.saturating_sub(1);
                            if c.remaining == 0 {
                                stale.push(id.clone());
                            }
                        }
                        for id in stale {
                            this.fetch_otp(id, cx);
                        }
                        cx.notify();
                    }
                    if let Some(c) = this.code.as_mut() {
                        c.remaining = c.remaining.saturating_sub(1);
                        if c.remaining == 0
                            && let Some(d) = &this.detail
                        {
                            let id = d.summary.id.clone();
                            this.fetch_code(id, cx);
                        }
                        cx.notify();
                    }
                });
                if alive.is_err() {
                    return;
                }
            }
        })
    }

    // --- действия ---

    fn submit_unlock(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let path = self.db_path.read(cx).value().trim().to_string();
        let keyfile =
            Some(self.keyfile.read(cx).value().trim().to_string()).filter(|k| !k.is_empty());
        let pw = self.password.read(cx).value().to_string();
        if self.use_pin && !self.creating {
            let pw = self.pin.read(cx).value().to_string();
            if pw.is_empty() {
                return self.flash(tr!("Введите PIN"), true, cx);
            }
            self.pin.update(cx, |s, cx| s.set_value("", window, cx));
            self.mode = Mode::Busy;
            cx.notify();
            self.tasks.push(client::call_in(
                window,
                cx,
                Request::QuickUnlock { pin: pw.into() },
                |this, res, window, cx| match res {
                    Ok(_) => {
                        this.status = None;
                        this.set_ready(window, cx);
                    }
                    Err(e) => {
                        this.unlock_fails += 1;
                        this.set_locked(window, cx);
                        this.flash(e.message(), true, cx);
                    }
                },
            ));
            return;
        }
        let yubikey =
            Some(self.yubikey.read(cx).value().trim().to_string()).filter(|y| !y.is_empty());
        if path.is_empty() {
            return self.flash(tr!("Укажите путь к базе"), true, cx);
        }
        if self.creating && pw != self.password2.read(cx).value().as_ref() {
            return self.flash(tr!("Пароли не совпадают"), true, cx);
        }
        let password = (!pw.is_empty()).then(|| Secret::new(pw));
        if password.is_none() && keyfile.is_none() {
            return self.flash(tr!("Нужен пароль, файл-ключ или оба"), true, cx);
        }
        for i in [&self.password, &self.password2] {
            i.update(cx, |s, cx| s.set_value("", window, cx));
        }
        let req = if self.creating {
            self.flash(
                tr!("Подбираю параметры Argon2id (около секунды)…"),
                false,
                cx,
            );
            Request::Create {
                path,
                password,
                keyfile,
                yubikey,
                cipher: Cipher::Aes256,
            }
        } else {
            Request::Unlock {
                path: Some(path),
                password,
                keyfile,
                yubikey,
            }
        };
        self.mode = Mode::Busy;
        cx.notify();
        self.tasks.push(client::call_in(
            window,
            cx,
            req,
            |this, res, window, cx| match res {
                Ok(_) => {
                    this.creating = false;
                    this.status = None;
                    this.set_ready(window, cx);
                }
                Err(e) => {
                    this.unlock_fails += 1;
                    this.set_locked(window, cx);
                    this.flash(e.message(), true, cx);
                }
            },
        ));
    }

    fn copy(&mut self, field: &str, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        let key = field.to_string();
        let label = match field {
            "password" => tr!("Пароль").to_string(),
            "username" => tr!("поле§Логин").to_string(),
            "totp" => tr!("Код 2FA").to_string(),
            other => format!("«{other}»"),
        };
        self.tasks.push(client::call(
            cx,
            Request::Copy {
                id,
                field: field.to_string(),
            },
            move |this, res, cx| match res {
                Ok(_) => {
                    this.mark_copied(key, cx);
                    this.flash(
                        tr!("{label} скопирован, буфер очистится сам", label = label),
                        false,
                        cx,
                    )
                }
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    /// Тип новой записи по открытому разделу: в «Ключ SSH» создаётся ключ SSH и т.д.
    /// Ключи доступа создают сайты, вручную их не заводят: там обычный логин.
    fn default_kind(&self) -> EntryKind {
        match &self.nav {
            Nav::Kind(k) if *k != EntryKind::Passkey => *k,
            _ => EntryKind::Login,
        }
    }

    fn new_entry(&mut self, kind: EntryKind, window: &mut Window, cx: &mut Context<Self>) {
        if self.mode != Mode::Ready {
            return;
        }
        if self.nav == Nav::Otp {
            return self.open_otp_wizard(false, window, cx);
        }
        let group = match &self.nav {
            Nav::Group(g) if !self.groups.iter().any(|v| &v.id == g && v.is_recycle_bin) => {
                Some(g.clone())
            }
            _ => None,
        };
        // ключ SSH без самого ключа бесполезен: сразу создать или импортировать
        if kind == EntryKind::SshKey {
            return self.open_ssh_new(group, window, cx);
        }
        self.open_editor(kind, None, group, window, cx);
        // создаём на странице тега: тег сразу в записи
        if let (Nav::Tag(t), Some(e)) = (&self.nav, &self.editor) {
            let t = t.clone();
            e.update(cx, |e, cx| e.set_draft("", &t, window, cx));
        }
    }

    fn edit_selected(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        let wallet = self
            .detail
            .as_ref()
            .is_some_and(|d| d.summary.id == id && d.summary.kind == EntryKind::CryptoWallet);
        if wallet && !self.elevated_ui() {
            // в редакторе фраза видна целиком: сначала подтверждение
            return self.with_auth(|this, w, cx| this.edit_selected(w, cx), window, cx);
        }
        // правка идёт по раскрытым значениям: в редакторе секреты маскированы, но не потеряны
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::Get { id, reveal: true },
            |this, res, window, cx| match res {
                Ok(Response::Entry { entry }) => {
                    let group = this
                        .groups
                        .iter()
                        .find(|g| g.path == entry.summary.group)
                        .map(|g| g.id.clone())
                        .filter(|_| !entry.summary.group.is_empty());
                    this.open_editor(entry.summary.kind, Some(&entry), group, window, cx)
                }
                Err(e) => this.flash(e.message(), true, cx),
                _ => {}
            },
        ));
    }

    fn open_editor(
        &mut self,
        kind: EntryKind,
        detail: Option<&EntryDetail>,
        group: Option<String>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let groups = self.groups.clone();
        let editor = cx.new(|cx| EntryEditor::new(kind, detail, group, groups, window, cx));
        self._subs.push(cx.subscribe_in(
            &editor,
            window,
            |this, _, ev: &EditorEvent, window, cx| {
                match ev {
                    EditorEvent::Saved(id) => {
                        this.editor = None;
                        this.flash(tr!("Сохранено"), false, cx);
                        // показать сохранённую запись
                        let id = id.clone();
                        this.search_task = Some(client::call(
                            cx,
                            Request::Search {
                                query: String::new(),
                                limit: 500,
                                filter: this.filter(),
                            },
                            move |this, res, cx| {
                                if let Ok(Response::Entries { entries }) = res {
                                    this.entries = entries;
                                    let pos = this.entries.iter().position(|e| e.id == id);
                                    this.select(pos, cx);
                                }
                            },
                        ));
                        this.search.update(cx, |s, cx| s.set_value("", window, cx));
                    }
                    EditorEvent::Cancelled => this.editor = None,
                    EditorEvent::ChangeKind(kind) => {
                        let Some(old) = this.editor.take() else {
                            return;
                        };
                        let (title, tags, group) = old.read(cx).draft(cx);
                        this.open_editor(*kind, None, group, window, cx);
                        if let Some(e) = &this.editor {
                            e.update(cx, |e, cx| e.set_draft(&title, &tags, window, cx));
                        }
                        cx.notify();
                        return;
                    }
                }
                let h = this.search.read(cx).focus_handle(cx);
                window.focus(&h, cx);
                cx.notify();
            },
        ));
        let title_focus = editor.read(cx).focus_handle(cx);
        window.focus(&title_focus, cx);
        self.editor = Some(editor);
        cx.notify();
    }

    fn open_ssh_new(&mut self, group: Option<String>, window: &mut Window, cx: &mut Context<Self>) {
        let view = cx.new(|cx| crate::ssh_new::SshNew::new(group, window, cx));
        self._subs.push(cx.subscribe_in(
            &view,
            window,
            |this, _, ev: &crate::ssh_new::SshNewEvent, window, cx| {
                let crate::ssh_new::SshNewEvent::Saved(id) = ev;
                window.close_dialog(cx);
                this.flash(tr!("Ключ SSH сохранён в базе"), false, cx);
                // ключ создают из «Ключей SSH» или из папки: там он и появится, раздел не меняем
                if matches!(
                    this.nav,
                    Nav::All | Nav::Kind(EntryKind::SshKey) | Nav::Group(_)
                ) {
                    this.search.update(cx, |s, cx| s.set_value("", window, cx));
                    this.pending_select = Some(id.clone());
                } else {
                    this.open_entry(id.clone(), window, cx);
                }
                this.reload_all(cx);
            },
        ));
        let v2 = view.clone();
        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .w(px(560.))
                .child(view.clone())
        });
        window.defer(cx, move |window, cx| {
            v2.update(cx, |v, cx| v.focus(window, cx))
        });
    }

    fn open_otp_wizard(&mut self, for_selected: bool, window: &mut Window, cx: &mut Context<Self>) {
        let target = if for_selected {
            self.detail.as_ref().map(|d| {
                (
                    d.summary.id.clone(),
                    d.summary.title.clone(),
                    d.summary.username.clone(),
                )
            })
        } else {
            None
        };
        let wizard = cx.new(|cx| crate::otp_wizard::OtpWizard::new(target, window, cx));
        self._subs.push(cx.subscribe_in(
            &wizard,
            window,
            |this, _, ev: &crate::otp_wizard::WizardEvent, window, cx| {
                let crate::otp_wizard::WizardEvent::Saved(id) = ev;
                window.close_dialog(cx);
                this.flash(tr!("2FA добавлена"), false, cx);
                this.otp_codes.remove(id);
                this.code = None;
                this.reload_all(cx);
            },
        ));
        let w2 = wizard.clone();
        window.open_dialog(cx, move |dialog, _, _| {
            let dialog = dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
            dialog.p_0().w(px(580.)).child(wizard.clone())
        });
        window.defer(cx, move |window, cx| {
            w2.update(cx, |w, cx| w.focus(window, cx))
        });
    }

    fn show_qr(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        let title = self
            .detail
            .as_ref()
            .map(|d| d.summary.title.clone())
            .unwrap_or_default();
        self.tasks.push(client::call_in(
            window,
            cx,
            Request::OtpUri { id },
            move |this, res, window, cx| match res {
                Ok(Response::OtpUri { uri }) => {
                    let qr = uri.expose().to_string();
                    let title = title.clone();
                    window.open_dialog(cx, move |dialog, _, cx| {
                        let dialog = dialog
                            .centered()
                            .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
                        let theme = cx.theme().clone();
                        dialog
                            .p_0()
                            .child(crate::ui::sheet_header(
                                tr!("2FA «{title}» на телефон", title = title),
                                Some(tr!("Отсканируйте в 2FAS или другом приложении-аутентификаторе")),
                                &theme,
                            ))
                            .child(
                            v_flex()
                                .p_5()
                                .items_center()
                                .gap_4()
                                .child(qr_element(&qr))
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .text_sm()
                                        .text_color(theme.warning_foreground)
                                        .child(Icon::new(IconName::ShieldAlert).small())
                                        .child(
                                            tr!("В QR-коде секрет: отсканируйте в 2FAS и закройте окно"),
                                        ),
                                ),
                        )
                            .child(
                                crate::ui::sheet_footer(&theme).child(div().flex_1()).child(
                                    Button::new("qr-close")
                                        .primary()
                                        .label(tr!("Готово"))
                                        .on_click(|_, w, cx| w.close_dialog(cx)),
                                ),
                            )
                    });
                }
                Err(e) => this.flash(e.message(), true, cx),
                _ => {}
            },
        ));
    }

    fn import_twofas(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(tr!("Бэкап 2FAS (.2fas)").into()),
        });
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(mut v))) = rx.await else {
                return;
            };
            if v.is_empty() {
                return;
            }
            let req = Request::ImportFile {
                path: v.remove(0).display().to_string(),
                format: keywarden_core::ipc::ImportFormat::TwoFas,
                key: None,
            };
            let res = cx
                .background_spawn(async move { client::blocking(&req) })
                .await;
            let _ = this.update(cx, |this, cx| match res {
                Ok(Response::Imported { report }) => {
                    let mut m = tr!("Из 2FAS перенесено кодов: {n}", n = report.total());
                    if !report.review.is_empty() {
                        m.push_str(&tr!(", пропущено: {n}", n = report.review.len()));
                    }
                    this.flash(m, false, cx);
                    this.reload_all(cx);
                }
                Err(e) => this.flash(e.message(), true, cx),
                _ => {}
            });
        }));
    }

    fn export_twofas(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let dir = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        let rx = cx.prompt_for_new_path(&dir, Some("keywarden.2fas"));
        self.tasks.push(cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(path))) = rx.await else { return };
            let req = Request::ExportTwoFas {
                path: path.display().to_string(),
            };
            let res = cx
                .background_spawn(async move { client::blocking(&req) })
                .await;
            let _ = this.update(cx, |this, cx| match res {
                Ok(_) => this.flash(
                    tr!("Выгружено. Откройте файл в 2FAS, затем удалите его: в нём секреты"),
                    false,
                    cx,
                ),
                Err(e) => this.flash(e.message(), true, cx),
            });
        }));
    }

    fn icon_for(&self, e: &EntrySummary) -> Option<std::sync::Arc<Image>> {
        e.icon.as_ref().and_then(|u| self.icons.get(u)).cloned()
    }

    /// Собственные иконки записей из списка, которых ещё нет в кэше.
    fn load_icons(&mut self, cx: &mut Context<Self>) {
        let wanted: Vec<String> = self
            .entries
            .iter()
            .filter_map(|e| e.icon.clone())
            .filter(|u| !self.icons_requested.contains(u))
            .collect();
        for uuid in wanted {
            self.icons_requested.insert(uuid.clone());
            let key = uuid.clone();
            self.tasks.push(client::call(
                cx,
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

    fn fetch_favicon(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        self.flash(tr!("Загружаю иконку сайта…"), false, cx);
        self.tasks.push(client::call(
            cx,
            Request::FetchFavicon { id },
            |this, res, cx| match res {
                Ok(_) => this.flash(tr!("Иконка сохранена в базе"), false, cx),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn clear_icon(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        self.tasks.push(client::call(
            cx,
            Request::ClearIcon { id },
            |this, res, cx| match res {
                Ok(_) => this.flash(tr!("Иконка убрана"), false, cx),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn load_health(&mut self, breaches: bool, cx: &mut Context<Self>) {
        self.health_busy = true;
        cx.notify();
        self.tasks.push(client::call(
            cx,
            Request::Health { breaches },
            |this, res, cx| {
                this.health_busy = false;
                match res {
                    Ok(Response::Health { report }) => this.health = Some(report),
                    Err(e) => this.flash(e.message(), true, cx),
                    _ => {}
                }
                cx.notify();
            },
        ));
    }

    /// Открыть запись в общем списке (со страницы проверки).
    fn open_entry(&mut self, id: String, window: &mut Window, cx: &mut Context<Self>) {
        self.search.update(cx, |s, cx| s.set_value("", window, cx));
        self.pending_select = Some(id);
        self.set_nav(Nav::All, cx);
    }

    fn exclude_from_health(&mut self, id: String, cx: &mut Context<Self>) {
        self.tasks.push(client::call(
            cx,
            Request::HealthExclude { id, exclude: true },
            |this, res, cx| match res {
                Ok(_) => {
                    this.flash(tr!("Запись больше не попадает в отчёт"), false, cx);
                    // утечки заново не запрашиваем: сеть только по кнопке
                    this.load_health(false, cx);
                }
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn render_health(&mut self, cx: &mut Context<Self>) -> AnyElement {
        use keywarden_core::health::Issue;
        let theme = cx.theme().clone();
        let Some(r) = self.health.clone() else {
            return v_flex()
                .flex_1()
                .p_6()
                .gap_4()
                .child(Skeleton::new().h(px(72.)).rounded_lg())
                .child(Skeleton::new().h(px(36.)).w(px(240.)).rounded_md())
                .child(Skeleton::new().h(px(160.)).rounded_lg())
                .into_any_element();
        };
        let stat = |label: &'static str, value: String, bad: bool, last: bool| {
            v_flex()
                .flex_1()
                .min_w(px(110.))
                .px_4()
                .py_3()
                .gap_1()
                .when(!last, |d| d.border_r_1().border_color(theme.border))
                .child(
                    h_flex()
                        .gap_1p5()
                        .text_xs()
                        .text_color(theme.muted_foreground)
                        .when(bad, |d| {
                            d.child(div().size(px(6.)).rounded_full().bg(theme.danger))
                        })
                        .child(label),
                )
                .child(
                    div()
                        .text_2xl()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(if bad {
                            theme.danger_foreground
                        } else {
                            theme.foreground
                        })
                        .child(value),
                )
        };
        let breached = if r.breaches_checked {
            r.breached.to_string()
        } else {
            "?".to_string()
        };
        let rows: Vec<AnyElement> = r
            .items
            .iter()
            .enumerate()
            .map(|(ix, i)| {
                let (open_id, skip_id) = (i.id.clone(), i.id.clone());
                h_flex()
                    .id(("health", ix))
                    .gap_3()
                    .px_2()
                    .py_3()
                    .border_b_1()
                    .border_color(theme.table_row_border)
                    .hover(|d| d.bg(theme.secondary))
                    .child(crate::brands::tile(
                        &keywarden_core::model::EntrySummary {
                            id: i.id.clone(),
                            kind: i.kind,
                            title: i.title.clone(),
                            username: i.username.clone(),
                            url: i.url.clone(),
                            group: i.group.clone(),
                            tags: vec![],
                            has_otp: false,
                            expires: None,
                            expired: false,
                            modified: String::new(),
                            created: String::new(),
                            icon: None,
                            detail: String::new(),
                        },
                        32.,
                        kind_icon(i.kind),
                        None,
                        &theme,
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
                                    .child(i.title.clone()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .truncate()
                                    .child(if i.group.is_empty() {
                                        i.username.clone()
                                    } else {
                                        format!("{}  •  {}", i.username, i.group)
                                    }),
                            ),
                    )
                    .child(h_flex().gap_1().children(i.issues.iter().map(|x| {
                        let (text, color) = match x {
                            Issue::Breached { count } => (
                                tr!("в утечках: {count}", count = count),
                                theme.danger_foreground,
                            ),
                            Issue::Weak { score } => (
                                tr!("слабый {score}/4", score = score),
                                theme.warning_foreground,
                            ),
                            Issue::Reused { count } => {
                                (tr!("повтор ×{count}", count = count), theme.info_foreground)
                            }
                            Issue::Old { days } => (
                                tr!("{n} мес. без смены", n = days / 30),
                                theme.muted_foreground,
                            ),
                            Issue::Expired => (tr!("срок истёк").into(), theme.danger_foreground),
                            Issue::Insecure => {
                                (tr!("http без шифрования").into(), theme.warning_foreground)
                            }
                            Issue::NoTwoFactor { .. } => {
                                (tr!("можно включить 2FA").into(), theme.info_foreground)
                            }
                            Issue::PasskeyReady { .. } => {
                                (tr!("можно ключ доступа").into(), theme.muted_foreground)
                            }
                            Issue::BadSeed { message } => (
                                tr!("фраза: {message}", message = message),
                                theme.danger_foreground,
                            ),
                            Issue::AddressMismatch { addresses } => (
                                tr!("чужие адреса: {n}", n = addresses.len()),
                                theme.danger_foreground,
                            ),
                        };
                        badge(text, color)
                    })))
                    .when_some(
                        i.issues.iter().find_map(|x| match x {
                            Issue::NoTwoFactor { doc } if doc.starts_with("https://") => {
                                Some(doc.clone())
                            }
                            _ => None,
                        }),
                        |d, doc| {
                            d.child(
                                Button::new(("h-doc", ix))
                                    .ghost()
                                    .small()
                                    .label(tr!("Как включить 2FA"))
                                    .on_click(move |_, _, cx| cx.open_url(&doc)),
                            )
                        },
                    )
                    .child(
                        Button::new(("h-open", ix))
                            .outline()
                            .small()
                            .label(tr!("Открыть"))
                            .on_click(cx.listener(move |this, _, w, cx| {
                                this.open_entry(open_id.clone(), w, cx)
                            })),
                    )
                    .child(
                        Button::new(("h-skip", ix))
                            .ghost()
                            .small()
                            .icon(IconName::EyeOff)
                            .tooltip(tr!(
                                "Не показывать в отчёте (как «исключить из отчётов» в KeePassXC)"
                            ))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.exclude_from_health(skip_id.clone(), cx)
                            })),
                    )
                    .with_animation(
                        ("health-in", ix),
                        Animation::new(Duration::from_millis(160 + 30 * ix.min(10) as u64))
                            .with_easing(ease_out_quint()),
                        |el, t| el.opacity(t),
                    )
                    .into_any_element()
            })
            .collect();
        v_flex()
            .id("health-page")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .p_6()
            .gap_5()
            .child(
                h_flex()
                    .flex_wrap()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .child(stat(tr!("Слабые"), r.weak.to_string(), r.weak > 0, false))
                    .child(stat(tr!("Повторяются"), r.reused.to_string(), r.reused > 0, false))
                    .child(stat(tr!("Старше года"), r.old.to_string(), false, false))
                    .child(stat(tr!("Срок истёк"), r.expired.to_string(), r.expired > 0, false))
                    .child(stat(tr!("В утечках"), breached, r.breached > 0, false))
                    .child(stat(tr!("Без https"), r.insecure.to_string(), r.insecure > 0, false))
                    .when(r.wallets > 0, |d| {
                        d.child(stat(tr!("Кошельки"), r.wallets.to_string(), true, false))
                    })
                    .child(stat(
                        tr!("Можно 2FA"),
                        if r.sites_checked { r.no_2fa.to_string() } else { "?".into() },
                        false,
                        true,
                    )),
            )
            .child(
                v_flex()
                    .child(section_head(
                        tr!("Требуют внимания"),
                        Some(rows.len()),
                        Some(
                            Button::new("hibp")
                                .ghost()
                                .small()
                                .icon(IconName::Search)
                                .label(if r.breaches_checked {
                                    tr!("Проверить онлайн ещё раз")
                                } else {
                                    tr!("Проверить онлайн")
                                })
                                .tooltip(tr!("Утечки в Have I Been Pwned и поддержка 2FA и ключей доступа по 2fa.directory"))
                                .loading(self.health_busy)
                                .on_click(cx.listener(|this, _, _, cx| this.load_health(true, cx)))
                                .into_any_element(),
                        ),
                        &theme,
                    ))
                    .child(if rows.is_empty() {
                        h_flex()
                            .gap_2()
                            .py_4()
                            .text_sm()
                            .child(
                                Icon::new(IconName::CircleCheck)
                                    .small()
                                    .text_color(theme.success_foreground),
                            )
                            .child(tr!("Проверено {n}: проблем не найдено", n = r.checked))
                            .into_any_element()
                    } else {
                        v_flex().children(rows).into_any_element()
                    }),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(tr!("Проверено паролей: {checked}, исключено из отчёта: {excluded}. При онлайн-проверке в Have I Been Pwned уходят только первые 5 символов SHA-1 хэша, а списки 2fa.directory скачиваются целиком: пароли и адреса не покидают компьютер.", checked = r.checked, excluded = r.excluded)),
            )
            .into_any_element()
    }

    fn duplicate(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id().filter(|_| self.editor.is_none()) else {
            return;
        };
        self.tasks.push(client::call(
            cx,
            Request::Duplicate { id },
            |this, res, cx| match res {
                Ok(Response::Created { id }) => {
                    this.flash(tr!("Создана копия"), false, cx);
                    // выделить копию после обновления списка
                    this.search_task = Some(client::call(
                        cx,
                        Request::Search {
                            query: String::new(),
                            limit: 500,
                            filter: this.filter(),
                        },
                        move |this, res, cx| {
                            if let Ok(Response::Entries { entries }) = res {
                                this.entries = entries;
                                let pos = this.entries.iter().position(|e| e.id == id);
                                this.select(pos, cx);
                            }
                        },
                    ));
                }
                Ok(_) => {}
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn move_entry(&mut self, id: String, group: String, cx: &mut Context<Self>) {
        let name = self
            .groups
            .iter()
            .find(|g| g.id == group)
            .map(|g| {
                if g.depth == 0 {
                    tr!("корень").to_string()
                } else {
                    g.name.clone()
                }
            })
            .unwrap_or_default();
        self.tasks.push(client::call(
            cx,
            Request::MoveEntry { id, group },
            move |this, res, cx| match res {
                Ok(_) => this.flash(tr!("Перемещено в «{name}»", name = name), false, cx),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    /// Ручной порядок имеет смысл только в сортировке «Вручную» и без поискового запроса.
    fn manual_order(&mut self, cx: &mut Context<Self>) -> bool {
        let ok = self.sort == Sort::Manual && self.search.read(cx).value().trim().is_empty();
        if !ok {
            self.flash(
                tr!("Порядок меняется в сортировке «Вручную» без поиска"),
                true,
                cx,
            );
        }
        ok
    }

    fn reorder_entry(&mut self, id: String, target: String, after: bool, cx: &mut Context<Self>) {
        if id == target || !self.manual_order(cx) {
            return;
        }
        self.pending_select = Some(id.clone());
        self.land(&id);
        self.tasks.push(client::call(
            cx,
            Request::ReorderEntry { id, target, after },
            |this, res, cx| {
                if let Err(e) = res {
                    this.flash(e.message(), true, cx)
                }
            },
        ));
    }

    /// Поставить тип перед или после другого и запомнить порядок в настройках.
    fn reorder_kind(
        &mut self,
        kind: EntryKind,
        target: EntryKind,
        after: bool,
        cx: &mut Context<Self>,
    ) {
        if kind == target {
            return;
        }
        let mut order = self.kind_order.clone();
        order.retain(|k| *k != kind);
        let at = order
            .iter()
            .position(|k| *k == target)
            .unwrap_or(order.len());
        order.insert(if after { at + 1 } else { at }, kind);
        self.kind_order = order.clone();
        cx.notify();
        // свежие настройки с демона, иначе затёрли бы правки из окна настроек
        self.tasks.push(client::call(
            cx,
            Request::Prefs { set: None },
            move |this, res, cx| {
                if let Ok(Response::Prefs { mut prefs }) = res {
                    prefs.kind_order = order.iter().map(|k| k.as_str().to_string()).collect();
                    this.tasks.push(client::call(
                        cx,
                        Request::Prefs { set: Some(*prefs) },
                        |this, res, cx| {
                            if let Err(e) = res {
                                this.flash(e.message(), true, cx)
                            }
                        },
                    ));
                }
            },
        ));
    }

    fn reorder_group(&mut self, id: String, target: String, after: bool, cx: &mut Context<Self>) {
        tracing::info!(id, target, after, "папка: поставить рядом");
        if id == target {
            return;
        }
        self.land(&id);
        self.tasks.push(client::call(
            cx,
            Request::ReorderGroup { id, target, after },
            |this, res, cx| {
                if let Err(e) = res {
                    this.flash(e.message(), true, cx)
                }
            },
        ));
    }

    /// Alt+Shift+стрелки: сдвинуть выбранную запись внутри её папки.
    fn nudge(&mut self, delta: isize, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id().filter(|_| self.editor.is_none()) else {
            return;
        };
        if !self.manual_order(cx) {
            return;
        }
        self.pending_select = Some(id.clone());
        self.tasks.push(client::call(
            cx,
            Request::NudgeEntry { id, delta },
            |this, res, cx| {
                if let Err(e) = res {
                    this.flash(e.message(), true, cx)
                }
            },
        ));
    }

    fn land(&mut self, id: &str) {
        let n = self.landed.as_ref().map(|l| l.1 + 1).unwrap_or(1);
        self.landed = Some((id.to_string(), n));
    }

    fn move_group(&mut self, id: String, parent: String, cx: &mut Context<Self>) {
        tracing::info!(id, parent, "папка: переместить внутрь");
        if id == parent {
            return;
        }
        // уже там: перенос поставил бы папку в конец списка
        if self
            .groups
            .iter()
            .any(|g| g.id == id && g.parent.as_deref() == Some(parent.as_str()))
        {
            return;
        }
        self.land(&id);
        self.tasks.push(client::call(
            cx,
            Request::MoveGroup { id, parent },
            |this, res, cx| match res {
                Ok(_) => this.flash(tr!("Папка перемещена"), false, cx),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn delete_selected(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(e) = self.selected.and_then(|i| self.entries.get(i)).cloned() else {
            return;
        };
        let in_bin = self.groups.iter().any(|g| {
            g.is_recycle_bin && (e.group == g.path || e.group.starts_with(&format!("{}/", g.path)))
        });
        let this = cx.entity();
        let title = e.title.clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let dialog = dialog.centered().entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
            let theme = cx.theme().clone();
            let this = this.clone();
            let id = e.id.clone();
            dialog
                .p_0()
                .w(px(480.))
                .child(crate::ui::sheet_header(
                    if in_bin { tr!("Удалить навсегда?") } else { tr!("Переместить в корзину?") },
                    None,
                    &theme,
                ))
                .child(crate::ui::sheet_body().text_sm().child(if in_bin {
                    tr!("«{title}» будет удалена без возможности восстановления. Удаление дойдёт и до других копий базы.", title = title)
                } else {
                    tr!("«{title}» окажется в корзине, оттуда её можно вернуть.", title = title)
                }))
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(div().flex_1())
                        .child(Button::new("cancel").ghost().label(tr!("Отмена")).on_click(|_, window, cx| window.close_dialog(cx)))
                        .child(Button::new("ok").danger().label(tr!("Удалить")).on_click(move |_, window, cx| {
                            let id = id.clone();
                            this.update(cx, |this, cx| {
                                this.tasks.push(client::call(cx, Request::Delete { id }, |this, res, cx| match res {
                                    Ok(_) => this.flash(tr!("Удалено"), false, cx),
                                    Err(e) => this.flash(e.message(), true, cx),
                                }));
                            });
                            window.close_dialog(cx);
                        })),
                )
        });
    }

    fn open_generator(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let panel = cx.new(|cx| GeneratorPanel::new(window, cx));
        window.open_dialog(cx, move |dialog, _, _| {
            let dialog = dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
            dialog.p_0().w(px(580.)).child(panel.clone())
        });
    }

    fn lock(&mut self, cx: &mut Context<Self>) {
        self.tasks
            .push(client::call(cx, Request::Lock, |_, _, _| {}));
    }

    fn reveal(&mut self, field: String, cx: &mut Context<Self>) {
        if !self.shown.remove(&field) {
            self.shown.insert(field);
        }
        if self.revealed.is_none()
            && let Some(id) = self.selected_id()
        {
            self.detail_task = Some(client::call(
                cx,
                Request::Get { id, reveal: true },
                |this, res, cx| {
                    if let Ok(Response::Entry { entry }) = res {
                        this.revealed = Some(*entry);
                        this.revealed_at = Some(Instant::now());
                    }
                    cx.notify();
                },
            ));
        }
        cx.notify();
    }

    fn save_attachment(&mut self, name: String, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        let dir = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/"));
        let rx = cx.prompt_for_new_path(&dir, Some(&name));
        self.tasks.push(cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(path))) = rx.await else { return };
            let res = cx
                .background_spawn(async move {
                    match client::blocking(&Request::AttachmentGet { id, name }) {
                        Ok(Response::Attachment { data }) => {
                            let bytes = data_encoding::BASE64
                                .decode(data.as_bytes())
                                .map_err(|e| e.to_string())?;
                            keywarden_core::vault::write_atomic(&path, &bytes)
                                .map_err(|e| e.to_string())?;
                            Ok(path)
                        }
                        Ok(_) => Err(tr!("нет ответа").to_string()),
                        Err(e) => Err(e.message()),
                    }
                })
                .await;
            let _ = this.update(cx, |this, cx| match res {
                Ok(p) => this.flash(tr!("Сохранено в {path}", path = p.display()), false, cx),
                Err(e) => this.flash(e, true, cx),
            });
        }));
    }

    /// Просмотр вложения по типу файла (код с подсветкой, Markdown, картинка, hex).
    fn view_attachment(&mut self, name: String, window: &mut Window, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        let req = Request::AttachmentGet {
            id,
            name: name.clone(),
        };
        self.tasks.push(client::call_in(
            window,
            cx,
            req,
            move |this, res, window, cx| {
                let data = match res {
                    Ok(Response::Attachment { data }) => {
                        data_encoding::BASE64.decode(data.as_bytes())
                    }
                    Err(e) => return this.flash(e.message(), true, cx),
                    _ => return,
                };
                let Ok(data) = data else {
                    return this.flash(tr!("вложение повреждено"), true, cx);
                };
                let me = cx.entity();
                let n = name.clone();
                let on_save: crate::attachment_view::SaveFn = std::rc::Rc::new(move |_, cx| {
                    me.update(cx, |t, cx| t.save_attachment(n.clone(), cx))
                });
                let view = cx.new(|cx| {
                    crate::attachment_view::AttachmentView::new(
                        name.clone(),
                        data,
                        on_save,
                        window,
                        cx,
                    )
                });
                window.open_dialog(cx, move |dialog, _, _| {
                    let dialog = dialog
                        .centered()
                        .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
                    dialog.w(px(960.)).child(view.clone())
                });
            },
        ));
    }

    fn add_attachment(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        let rx = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some(tr!("Приложить").into()),
        });
        self.tasks.push(cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(paths))) = rx.await else {
                return;
            };
            let _ = this.update(cx, |this, cx| this.attach_paths(id, paths, cx));
        }));
    }

    /// Приложить файлы к записи: из окна выбора или перетаскиванием из файлового менеджера.
    fn attach_paths(&mut self, id: String, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        // папки не прикладываем: их перетаскивают по ошибке
        let paths: Vec<PathBuf> = paths.into_iter().filter(|p| p.is_file()).collect();
        if paths.is_empty() {
            return self.flash(tr!("Приложить можно только файлы, не папки"), true, cx);
        }
        self.tasks.push(cx.spawn(async move |this, cx| {
            let res = cx
                .background_spawn(async move {
                    for p in &paths {
                        let data = std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?;
                        let name = p
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned();
                        client::blocking(&Request::AttachmentAdd {
                            id: id.clone(),
                            name,
                            data: data_encoding::BASE64.encode(&data),
                        })
                        .map_err(|e| e.message())?;
                    }
                    Ok::<_, String>(paths.len())
                })
                .await;
            let _ = this.update(cx, |this, cx| match res {
                Ok(n) => this.flash(tr!("Приложено файлов: {n}", n = n), false, cx),
                Err(e) => this.flash(e, true, cx),
            });
        }));
    }

    fn remove_attachment(&mut self, name: String, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        self.tasks.push(client::call(
            cx,
            Request::AttachmentRemove { id, name },
            |this, res, cx| match res {
                Ok(_) => this.flash(
                    tr!("Вложение удалено (старая версия осталась в истории)"),
                    false,
                    cx,
                ),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn restore(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(id) = self.selected_id() else { return };
        self.tasks.push(client::call(
            cx,
            Request::RestoreHistory { id, index },
            |this, res, cx| match res {
                Ok(_) => this.flash(
                    tr!("Версия восстановлена, текущая ушла в историю"),
                    false,
                    cx,
                ),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    fn new_group(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let parent = match &self.nav {
            Nav::Group(g) => Some(g.clone()),
            _ => None,
        };
        let name = cx.new(|cx| InputState::new(window, cx).placeholder(tr!("Название папки")));
        let this = cx.entity();
        let focus = name.read(cx).focus_handle(cx);
        window.open_dialog(cx, move |dialog, _, cx| {
            let dialog = dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
            let theme = cx.theme().clone();
            let (this, name, parent) = (this.clone(), name.clone(), parent.clone());
            dialog
                .p_0()
                .w(px(440.))
                .child(crate::ui::sheet_header(tr!("Новая папка"), None, &theme))
                .child(crate::ui::sheet_body().child(Input::new(&name)))
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(div().flex_1())
                        .child(
                            Button::new("cancel")
                                .outline()
                                .label(tr!("Отмена"))
                                .on_click(|_, w, cx| w.close_dialog(cx)),
                        )
                        .child(Button::new("ok").primary().label(tr!("Создать")).on_click(
                            move |_, window, cx| {
                                let n = name.read(cx).value().trim().to_string();
                                if !n.is_empty() {
                                    let parent = parent.clone();
                                    this.update(cx, |this, cx| {
                                        this.tasks.push(client::call(
                                            cx,
                                            Request::AddGroup { parent, name: n },
                                            |this, res, cx| match res {
                                                Ok(_) => {
                                                    this.flash(tr!("Папка создана"), false, cx)
                                                }
                                                Err(e) => this.flash(e.message(), true, cx),
                                            },
                                        ));
                                    });
                                }
                                window.close_dialog(cx);
                            },
                        )),
                )
        });
        window.focus(&focus, cx);
    }

    fn new_tag(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let name = cx.new(|cx| InputState::new(window, cx).placeholder(tr!("Название тега")));
        let this = cx.entity();
        let focus = name.read(cx).focus_handle(cx);
        window.open_dialog(cx, move |dialog, _, cx| {
            let dialog = dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide);
            let theme = cx.theme().clone();
            let (this, name) = (this.clone(), name.clone());
            dialog
                .p_0()
                .w(px(440.))
                .child(crate::ui::sheet_header(
                    tr!("Новый тег"),
                    Some(tr!("Потом перетащите на него записи из списка")),
                    &theme,
                ))
                .child(crate::ui::sheet_body().child(Input::new(&name)))
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(div().flex_1())
                        .child(
                            Button::new("cancel")
                                .ghost()
                                .label(tr!("Отмена"))
                                .on_click(|_, w, cx| w.close_dialog(cx)),
                        )
                        .child(Button::new("ok").primary().label(tr!("Создать")).on_click(
                            move |_, window, cx| {
                                // без # и запятых: один тег
                                let n = name
                                    .read(cx)
                                    .value()
                                    .trim()
                                    .trim_start_matches('#')
                                    .replace([',', ';'], " ")
                                    .trim()
                                    .to_string();
                                if !n.is_empty() {
                                    this.update(cx, |this, cx| {
                                        if !this.tags.iter().any(|(t, _)| *t == n)
                                            && !this.pending_tags.contains(&n)
                                        {
                                            this.pending_tags.push(n.clone());
                                        }
                                        this.flash(
                                            tr!("Тег #{n}: перетащите на него записи", n = n),
                                            false,
                                            cx,
                                        );
                                    });
                                }
                                window.close_dialog(cx);
                            },
                        )),
                )
        });
        window.focus(&focus, cx);
    }

    /// Запись брошена на тег: добавить его к тегам записи.
    fn tag_entry(&mut self, id: String, tag: String, cx: &mut Context<Self>) {
        let Some(mut tags) = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.tags.clone())
        else {
            return;
        };
        if tags.contains(&tag) {
            self.flash(tr!("У записи уже есть #{tag}", tag = tag), false, cx);
            return;
        }
        tags.push(tag.clone());
        self.tasks.push(client::call(
            cx,
            Request::Update {
                id,
                patch: keywarden_core::model::EntryPatch {
                    tags: Some(tags),
                    ..Default::default()
                },
            },
            move |this, res, cx| match res {
                Ok(_) => this.flash(tr!("Добавлен тег #{tag}", tag = tag), false, cx),
                Err(e) => this.flash(e.message(), true, cx),
            },
        ));
    }

    // --- контекстное меню папок и тегов ---

    fn render_ctx_menu(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let (target, pos) = self.ctx_menu.clone()?;
        let theme = cx.theme().clone();
        let close = |this: &mut Self, cx: &mut Context<Self>| {
            this.ctx_menu = None;
            cx.notify();
        };
        let row = |id: &'static str, icon: IconName, label: &'static str, danger: bool| {
            h_flex()
                .id(id)
                .h(px(30.))
                .px_2()
                .gap_2()
                .rounded_md()
                .text_sm()
                .cursor_pointer()
                .text_color(if danger {
                    theme.danger_foreground
                } else {
                    theme.foreground
                })
                .hover(|d| {
                    d.bg(if danger {
                        theme.danger.opacity(0.18)
                    } else {
                        theme.secondary_active
                    })
                })
                .child(Icon::new(icon).small().text_color(if danger {
                    theme.danger_foreground
                } else {
                    theme.muted_foreground
                }))
                .child(label)
        };
        let title: SharedString = match &target {
            CtxTarget::Group { name, .. } => name.clone().into(),
            CtxTarget::Tag { name, .. } => format!("#{name}").into(),
        };
        let mut menu = v_flex()
            .id("ctx-menu")
            .w(px(220.))
            .p_1()
            .rounded_lg()
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .shadow_lg()
            .occlude()
            .child(
                div()
                    .px_2()
                    .pt_1()
                    .pb_1p5()
                    .text_xs()
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(theme.muted_foreground)
                    .truncate()
                    .child(title),
            );
        match target {
            CtxTarget::Group { id, name, entries } => {
                let (i1, i2, i3, n1, n2) = (id.clone(), id.clone(), id, name.clone(), name);
                menu = menu
                    .child(row("ctx-rename", IconName::Pencil, tr!("Переименовать"), false).on_click(
                        cx.listener(move |this, _, w, cx| {
                            close(this, cx);
                            let id = i1.clone();
                            this.text_dialog(
                                tr!("Переименовать папку"),
                                n1.clone(),
                                tr!("Переименовать"),
                                move |name| Request::RenameGroup { id: id.clone(), name },
                                tr!("Папка переименована"),
                                w,
                                cx,
                            );
                        }),
                    ))
                    .child(row("ctx-sub", IconName::FolderPlus, tr!("Новая подпапка"), false).on_click(
                        cx.listener(move |this, _, w, cx| {
                            close(this, cx);
                            let parent = i2.clone();
                            this.text_dialog(
                                tr!("Новая подпапка"),
                                String::new(),
                                tr!("Создать"),
                                move |name| Request::AddGroup {
                                    parent: Some(parent.clone()),
                                    name,
                                },
                                tr!("Папка создана"),
                                w,
                                cx,
                            );
                        }),
                    ))
                    .child(div().h(px(1.)).my_1().bg(theme.border))
                    .child(row("ctx-del", IconName::Trash, tr!("Удалить"), true).on_click(cx.listener(
                        move |this, _, w, cx| {
                            close(this, cx);
                            let text = if entries > 0 {
                                tr!("Папка «{n2}» вместе с записями ({entries}) и подпапками уйдёт в корзину. Вернуть можно из корзины.", n2 = n2, entries = entries)
                            } else {
                                tr!("Папка «{n2}» уйдёт в корзину. Вернуть можно из корзины.", n2 = n2)
                            };
                            if this.nav == Nav::Group(i3.clone()) {
                                this.set_nav(Nav::All, cx);
                            }
                            this.confirm_dialog(
                                tr!("Удалить папку?"),
                                text,
                                tr!("Удалить"),
                                Request::DeleteGroup { id: i3.clone() },
                                tr!("Папка в корзине"),
                                w,
                                cx,
                            );
                        },
                    )));
            }
            CtxTarget::Tag { name, count } => {
                let (t1, t2) = (name.clone(), name);
                menu = menu
                    .child(
                        row("ctx-rename", IconName::Pencil, tr!("Переименовать"), false).on_click(
                            cx.listener(move |this, _, w, cx| {
                                close(this, cx);
                                let from = t1.clone();
                                this.text_dialog(
                                    tr!("Переименовать тег"),
                                    from.clone(),
                                    tr!("Переименовать"),
                                    move |to| Request::RenameTag {
                                        from: from.clone(),
                                        to,
                                    },
                                    tr!("Тег переименован во всех записях"),
                                    w,
                                    cx,
                                );
                            }),
                        ),
                    )
                    .child(div().h(px(1.)).my_1().bg(theme.border))
                    .child(
                        row("ctx-del", IconName::Trash, tr!("Удалить тег"), true).on_click(cx.listener(
                            move |this, _, w, cx| {
                                close(this, cx);
                                if this.nav == Nav::Tag(t2.clone()) {
                                    this.set_nav(Nav::All, cx);
                                }
                                // пустой тег из панели: в базе его нет, просто убрать
                                if count == 0 {
                                    this.pending_tags.retain(|t| *t != t2);
                                    cx.notify();
                                    return;
                                }
                                this.confirm_dialog(
                                tr!("Удалить тег?"),
                                tr!("Тег #{t2} снимется с записей ({count}). Сами записи останутся.", t2 = t2, count = count),
                                tr!("Удалить тег"),
                                Request::DeleteTag { tag: t2.clone() },
                                tr!("Тег удалён"),
                                w,
                                cx,
                            );
                            },
                        )),
                    );
            }
        }
        Some(
            deferred(
                div()
                    .id("ctx-backdrop")
                    .absolute()
                    .top_0()
                    .left_0()
                    .size_full()
                    .occlude()
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| close(this, cx)),
                    )
                    .on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, _, _, cx| close(this, cx)),
                    )
                    .on_key_down(cx.listener(move |this, ev: &KeyDownEvent, _, cx| {
                        if ev.keystroke.key == "escape" {
                            close(this, cx)
                        }
                    }))
                    .child(
                        anchored().position(pos).snap_to_window().child(
                            menu.with_animation(
                                "ctx-in",
                                Animation::new(Duration::from_millis(120))
                                    .with_easing(ease_out_quint()),
                                |el, t| el.opacity(t).mt(px(4. * (1. - t))),
                            ),
                        ),
                    ),
            )
            .with_priority(1)
            .into_any_element(),
        )
    }

    /// Окно с одним полем: переименование папки или тега, новая подпапка.
    #[allow(clippy::too_many_arguments)]
    fn text_dialog(
        &mut self,
        title: &'static str,
        initial: String,
        ok: &'static str,
        make: impl Fn(String) -> Request + 'static,
        done: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder(tr!("Название"))
                .default_value(initial)
        });
        let this = cx.entity();
        let focus = input.read(cx).focus_handle(cx);
        let make = std::rc::Rc::new(make);
        window.open_dialog(cx, move |dialog, _, cx| {
            let theme = cx.theme().clone();
            let (this, input, make) = (this.clone(), input.clone(), make.clone());
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .w(px(440.))
                .child(crate::ui::sheet_header(title, None, &theme))
                .child(crate::ui::sheet_body().child(Input::new(&input)))
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(div().flex_1())
                        .child(
                            Button::new("cancel")
                                .outline()
                                .label(tr!("Отмена"))
                                .on_click(|_, w, cx| w.close_dialog(cx)),
                        )
                        .child(Button::new("ok").primary().label(ok).on_click(
                            move |_, window, cx| {
                                let v = input.read(cx).value().trim().to_string();
                                if !v.is_empty() {
                                    let req = make(v);
                                    this.update(cx, |this, cx| {
                                        this.tasks.push(client::call(
                                            cx,
                                            req,
                                            move |this, res, cx| match res {
                                                Ok(_) => this.flash(done, false, cx),
                                                Err(e) => this.flash(e.message(), true, cx),
                                            },
                                        ));
                                    });
                                }
                                window.close_dialog(cx);
                            },
                        )),
                )
        });
        window.focus(&focus, cx);
    }

    /// Подтверждение опасного действия.
    #[allow(clippy::too_many_arguments)]
    fn confirm_dialog(
        &mut self,
        title: &'static str,
        text: String,
        ok: &'static str,
        req: Request,
        done: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let this = cx.entity();
        // запрос не клонируется: кнопка забирает его один раз
        let req = std::rc::Rc::new(std::cell::RefCell::new(Some(req)));
        window.open_dialog(cx, move |dialog, _, cx| {
            let theme = cx.theme().clone();
            let (this, req) = (this.clone(), req.clone());
            dialog
                .centered()
                .entrance(gpui_kit::component::dialog::DialogEntrance::FadeSlide)
                .p_0()
                .w(px(440.))
                .child(crate::ui::sheet_header(title, None, &theme))
                .child(
                    crate::ui::sheet_body().child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(text.clone()),
                    ),
                )
                .child(
                    crate::ui::sheet_footer(&theme)
                        .child(div().flex_1())
                        .child(
                            Button::new("cancel")
                                .outline()
                                .label(tr!("Отмена"))
                                .on_click(|_, w, cx| w.close_dialog(cx)),
                        )
                        .child(Button::new("ok").danger().label(ok).on_click(
                            move |_, window, cx| {
                                let Some(req) = req.borrow_mut().take() else {
                                    return window.close_dialog(cx);
                                };
                                this.update(cx, |this, cx| {
                                    this.tasks.push(client::call(cx, req, move |this, res, cx| {
                                        match res {
                                            Ok(_) => this.flash(done, false, cx),
                                            Err(e) => this.flash(e.message(), true, cx),
                                        }
                                    }));
                                });
                                window.close_dialog(cx);
                            },
                        )),
                )
        });
    }

    // --- отрисовка ---

    fn nav_title(&self) -> (IconName, String) {
        match &self.nav {
            Nav::All => (IconName::Inbox, tr!("Все записи").into()),
            Nav::Otp => (IconName::Timer, tr!("Коды 2FA").into()),
            Nav::Settings => (IconName::Settings, tr!("Настройки хранилища").into()),
            Nav::Tag(t) => (IconName::Hash, format!("#{t}")),
            Nav::Health => (IconName::ShieldCheck, tr!("Проверка паролей").into()),
            Nav::Kind(k) => (kind_icon(*k), k.label().into()),
            Nav::Group(g) => self
                .groups
                .iter()
                .find(|v| &v.id == g)
                .map(|v| {
                    if v.is_recycle_bin {
                        (IconName::Trash, tr!("Корзина").to_string())
                    } else {
                        (IconName::Folder, v.name.clone())
                    }
                })
                .unwrap_or((IconName::Folder, tr!("Папка").into())),
        }
    }

    fn render_unlock(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let busy = matches!(self.mode, Mode::Busy | Mode::Connecting);
        let path = self.db_path.read(cx).value().to_string();
        let error = self.status.clone().filter(|s| s.1).map(|s| s.0);
        let pin = self.use_pin && !self.creating;
        let advanced = (self.show_advanced && !pin) || self.creating;
        let first_run = path.is_empty();
        let label = |t: &'static str| {
            div()
                .text_xs()
                .font_weight(FontWeight::MEDIUM)
                .text_color(theme.muted_foreground)
                .child(t)
        };
        let field =
            |t: &'static str, input: AnyElement| v_flex().gap_1p5().child(label(t)).child(input);
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .bg(theme.sidebar)
            .child(
                v_flex()
                    .w(px(420.))
                    .gap_5()
                    .p_8()
                    .rounded(px(16.))
                    .border_1()
                    .border_color(theme.border)
                    .bg(theme.background)
                    .shadow_lg()
                    .child(
                        h_flex()
                            .gap_3()
                            .child(icon_tile(IconName::LockKeyhole, 44., &theme))
                            .child(
                                v_flex()
                                    .min_w_0()
                                    .child(div().text_lg().font_weight(FontWeight::SEMIBOLD).child(
                                        if self.creating {
                                            tr!("Новое хранилище")
                                        } else {
                                            tr!("Разблокировать хранилище")
                                        },
                                    ))
                                    .child(
                                        div()
                                            .text_sm()
                                            .truncate()
                                            .text_color(theme.muted_foreground)
                                            .child(if self.creating {
                                                tr!("KDBX 4 · AES-256 · Argon2id 256 МиБ")
                                                    .to_string()
                                            } else if path.is_empty() {
                                                tr!("Укажите файл базы .kdbx").to_string()
                                            } else {
                                                file_name(&path)
                                            }),
                                    ),
                            )
                            // редкие действия убраны в меню, чтобы экран был о главном: пароль
                            .when(!pin && !first_run, |d| {
                                let options = if advanced && !self.creating {
                                    tr!("Скрыть параметры входа")
                                } else {
                                    tr!("Файл-ключ, YubiKey, другой файл")
                                };
                                let create = if self.creating {
                                    tr!("Открыть существующую базу")
                                } else {
                                    tr!("Создать новую базу")
                                };
                                let creating = self.creating;
                                d.child(div().flex_1()).child(
                                    Button::new("unlock-more")
                                        .ghost()
                                        .small()
                                        .icon(IconName::Ellipsis)
                                        .dropdown_menu_with_anchor(
                                            Anchor::TopRight,
                                            move |menu, _, _| {
                                                let menu = if creating {
                                                    menu
                                                } else {
                                                    menu.menu(options, Box::new(UnlockOptions))
                                                };
                                                menu.menu(create, Box::new(ToggleCreateVault))
                                            },
                                        ),
                                )
                            }),
                    )
                    // подпись не нужна: что вводить, сказано в самом поле
                    .child(
                        Input::new(if pin { &self.pin } else { &self.password })
                            .large()
                            .prefix(Icon::new(IconName::Lock).small())
                            .mask_toggle(),
                    )
                    .when(self.creating, |d| {
                        d.child(field(
                            tr!("Ещё раз"),
                            Input::new(&self.password2)
                                .large()
                                .prefix(Icon::new(IconName::Lock).small())
                                .mask_toggle()
                                .into_any_element(),
                        ))
                    })
                    .when(advanced, |d| {
                        d.child(field(
                            tr!("Файл базы"),
                            crate::ui::file_field(
                                "unlock-db",
                                &self.db_path,
                                tr!("Файл базы не выбран"),
                                tr!("База .kdbx"),
                                IconName::Database,
                                cx,
                            ),
                        ))
                        .child(field(
                            tr!("Файл-ключ (если есть)"),
                            crate::ui::file_field(
                                "unlock-keyfile",
                                &self.keyfile,
                                tr!("Без файла-ключа"),
                                tr!("Файл-ключ"),
                                IconName::Key,
                                cx,
                            ),
                        ))
                        .child(field(
                            "YubiKey",
                            h_flex()
                                .child(crate::ui::yubikey_slots("unlock-yk", &self.yubikey, cx))
                                .into_any_element(),
                        ))
                    })
                    .when_some(error, |d, e| {
                        d.child(
                            h_flex()
                                .gap_2()
                                .px_3()
                                .py_2()
                                .rounded_lg()
                                .bg(theme.danger.opacity(0.12))
                                .border_1()
                                .border_color(theme.danger.opacity(0.35))
                                .text_sm()
                                .text_color(theme.danger_foreground)
                                .child(Icon::new(IconName::CircleAlert).small())
                                .child(div().flex_1().child(e))
                                .with_animation(
                                    "unlock-error",
                                    Animation::new(Duration::from_millis(180))
                                        .with_easing(ease_out_quint()),
                                    |el, t| el.opacity(t),
                                ),
                        )
                    })
                    .child(
                        Button::new("unlock")
                            .primary()
                            .large()
                            .w_full()
                            .loading(busy)
                            .label(match (busy, self.creating) {
                                (true, true) => tr!("Создаю базу…"),
                                (true, false) => tr!("Расшифровка…"),
                                (false, true) => tr!("Создать базу"),
                                (false, false) => tr!("Открыть"),
                            })
                            .on_click(cx.listener(|this, _, w, cx| this.submit_unlock(w, cx))),
                    )
                    .when(busy && self.mode == Mode::Busy, |d| {
                        d.child(
                            div()
                                .text_xs()
                                .text_center()
                                .text_color(theme.muted_foreground)
                                .child(tr!(
                                    "Argon2id медленный нарочно: так подбор пароля стоит дорого"
                                )),
                        )
                    })
                    .when(pin, |d| {
                        d.child(
                            h_flex().justify_center().child(
                                Button::new("use-master")
                                    .ghost()
                                    .small()
                                    .label(tr!("Ввести мастер-пароль"))
                                    .on_click(cx.listener(|this, _, w, cx| {
                                        this.use_pin = false;
                                        let h = this.password.read(cx).focus_handle(cx);
                                        w.focus(&h, cx);
                                        cx.notify();
                                    })),
                            ),
                        )
                    })
                    // первый запуск: базы ещё нет, выбор «открыть или создать» нужен на виду
                    .when(first_run && !pin, |d| {
                        d.child(
                            h_flex().justify_center().child(
                                Button::new("toggle-create")
                                    .ghost()
                                    .small()
                                    .label(if self.creating {
                                        tr!("У меня уже есть база")
                                    } else {
                                        tr!("Создать новую базу")
                                    })
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.creating = !this.creating;
                                        this.status = None;
                                        cx.notify();
                                    })),
                            ),
                        )
                    })
                    .with_animation(
                        SharedString::from(format!("unlock-card-{}", self.unlock_fails)),
                        Animation::new(Duration::from_millis(if self.unlock_fails == 0 {
                            260
                        } else {
                            420
                        }))
                        .with_easing(ease_out_quint()),
                        {
                            let shake = self.unlock_fails > 0;
                            move |el, t| {
                                if shake {
                                    // неверный ключ: короткое затухающее покачивание
                                    let x = (t * std::f32::consts::PI * 6.).sin() * 9. * (1. - t);
                                    el.relative().left(px(x))
                                } else {
                                    el.opacity(t).relative().top(px(10. * (1. - t)))
                                }
                            }
                        },
                    ),
            )
            .into_any_element()
    }

    fn render_sidebar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        // во время перетаскивания: папки и «Все записи» (корень) это цели, остальное бледнеет
        // has_active_drag срабатывает и на ползунки (они тоже тянутся через drag): берём только свои
        if !cx.has_active_drag() {
            OUR_DRAG.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        let dragging = cx.has_active_drag() && OUR_DRAG.load(std::sync::atomic::Ordering::Relaxed);
        // тип тянут только среди типов: папки и «в корень» при этом не цели
        let kind_drag = dragging && dragged_id().is_some_and(|d| d.starts_with("kind:"));
        let dragging = dragging && !kind_drag;
        if !kind_drag && self.kind_drop.is_some() {
            self.kind_drop = None;
        }
        // цели остаются как есть (подсветка только у той, над которой курсор), остальное плавно бледнеет
        let target = |el: Stateful<Div>| el;
        let epoch = DRAG_EPOCH.load(std::sync::atomic::Ordering::Relaxed);
        let not_target = move |el: Stateful<Div>| -> AnyElement {
            if dragging {
                el.with_animation(
                    ("dim", epoch as usize),
                    Animation::new(Duration::from_millis(180)).with_easing(ease_out_quint()),
                    |el, t| el.opacity(1. - 0.65 * t),
                )
                .into_any_element()
            } else {
                el.into_any_element()
            }
        };
        let item = |id: SharedString,
                    icon: IconName,
                    label: String,
                    count: Option<usize>,
                    depth: usize,
                    nav: Nav,
                    active: bool,
                    cx: &mut Context<Self>| {
            h_flex()
                .id(id)
                .relative()
                .h(px(34.))
                // панель прокручивается: строки не сжимаются, когда их много
                .flex_shrink_0()
                .gap_3()
                .px_3()
                .pl(px(12. + depth as f32 * 14.))
                .rounded_lg()
                .text_sm()
                .cursor_pointer()
                .border_1()
                .border_color(gpui_kit::transparent_black())
                .text_color(if active {
                    theme.sidebar_accent_foreground
                } else {
                    theme.sidebar_foreground
                })
                .when(active, |d| d.bg(theme.sidebar_accent))
                .when(!active, |d| d.hover(|d| d.bg(theme.secondary)))
                .on_click(cx.listener(move |this, _, _, cx| this.set_nav(nav.clone(), cx)))
                // акцентная полоска у края панели, как в референсе
                .when(active, |d| {
                    d.child(
                        div()
                            .absolute()
                            .left(px(-13.))
                            .top(px(7.))
                            .w(px(3.))
                            .h(px(18.))
                            .rounded_full()
                            .bg(theme.primary),
                    )
                })
                .child(Icon::new(icon).small().text_color(if active {
                    theme.primary
                } else {
                    theme.muted_foreground
                }))
                .child(div().flex_1().truncate().child(label))
                .when_some(count.filter(|c| *c > 0), |d, c| {
                    d.child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(theme.muted_foreground)
                            .child(c.to_string()),
                    )
                })
        };
        let section = |title: &'static str| {
            div()
                .flex_shrink_0()
                .pt_5()
                .pb_1p5()
                .px_3()
                .text_xs()
                .font_weight(FontWeight::MEDIUM)
                .text_color(theme.muted_foreground)
                .child(title)
        };
        let mut col = v_flex()
            .id("nav")
            .flex_1()
            .min_h_0()
            .px_3()
            .pb_3()
            .gap_0p5()
            .overflow_y_scroll()
            .child(section(tr!("ХРАНИЛИЩЕ")))
            .child({
                let root = self
                    .groups
                    .first()
                    .map(|g| g.id.clone())
                    .unwrap_or_default();
                let r2 = root.clone();
                target(item(
                    "all".into(),
                    IconName::Inbox,
                    tr!("Все записи").into(),
                    Some(self.total),
                    0,
                    Nav::All,
                    self.nav == Nav::All,
                    cx,
                ))
                .drag_over::<EntryDrag>(drop_style(&theme))
                .drag_over::<GroupDrag>(drop_style(&theme))
                .on_drop(cx.listener(move |this, d: &EntryDrag, _, cx| {
                    this.move_entry(d.id.clone(), root.clone(), cx)
                }))
                .on_drop(cx.listener(move |this, d: &GroupDrag, _, cx| {
                    this.move_group(d.id.clone(), r2.clone(), cx)
                }))
            })
            .child(not_target(item(
                "otp".into(),
                IconName::Timer,
                tr!("Коды 2FA").into(),
                None,
                0,
                Nav::Otp,
                self.nav == Nav::Otp,
                cx,
            )))
            .child(not_target(item(
                "health".into(),
                IconName::ShieldCheck,
                tr!("Проверка паролей").into(),
                self.health.as_ref().map(|h| h.items.len()),
                0,
                Nav::Health,
                self.nav == Nav::Health,
                cx,
            )));
        // корзина не папка: живёт в разделе хранилища, её подпапки в списке папок не видны
        if let Some(bin) = self.groups.iter().find(|g| g.is_recycle_bin).cloned() {
            let nav = Nav::Group(bin.id.clone());
            let bid = bin.id.clone();
            col = col.child(
                target(item(
                    "bin".into(),
                    IconName::Trash,
                    tr!("Корзина").into(),
                    Some(bin.entries),
                    0,
                    nav.clone(),
                    self.nav == nav,
                    cx,
                ))
                .drag_over::<EntryDrag>(drop_style(&theme))
                .on_drop(cx.listener(move |this, d: &EntryDrag, _, cx| {
                    this.move_entry(d.id.clone(), bid.clone(), cx)
                })),
            );
        }
        col = col.child(section(tr!("ТИПЫ")));
        let dragged_kind = kind_drag
            .then(dragged_id)
            .flatten()
            .and_then(|d| d.strip_prefix("kind:").map(str::to_string))
            .and_then(|s| EntryKind::ALL.iter().copied().find(|k| k.as_str() == s));
        let slot = self
            .kind_drop
            .filter(|(t, _)| dragged_kind.is_some_and(|d| d != *t))
            .and_then(|(t, after)| {
                let i = self.kind_order.iter().position(|k| *k == t)?;
                Some(i + after as usize)
            });
        self.kind_gaps.observe(slot);
        let kgen = self.kind_gaps.generation;
        let kind_ghost = |k: EntryKind, slot: usize, opening: bool, cx: &mut Context<Self>| {
            let el = h_flex()
                .id(SharedString::from(format!("kghost-{slot}")))
                .gap_3()
                .px_3()
                .rounded_lg()
                .border_1()
                .border_dashed()
                .border_color(theme.primary.opacity(0.5))
                .bg(theme.primary.opacity(0.06))
                .text_sm()
                .overflow_hidden()
                .on_drop(cx.listener(|this, d: &KindDrag, _, cx| {
                    if let Some((target, after)) = this.kind_drop.take() {
                        this.reorder_kind(d.kind, target, after, cx)
                    }
                }))
                .child(Icon::new(kind_icon(k)).small().text_color(theme.primary))
                .child(div().flex_1().truncate().child(k.label()));
            gap_anim(el, "kgap", opening, kgen, 34.)
        };
        let kinds = self.kind_order.clone();
        for (i, k) in kinds.iter().copied().enumerate() {
            let nav = Nav::Kind(k);
            if let (Some(opening), Some(dk)) = (self.kind_gaps.at(&i), dragged_kind) {
                col = col.child(kind_ghost(dk, i, opening, cx));
            }
            let row = item(
                format!("kind-{}", k.as_str()).into(),
                kind_icon(k),
                k.label().into(),
                None,
                0,
                nav.clone(),
                self.nav == nav,
                cx,
            )
            .on_drag_move(
                cx.listener(move |this, ev: &DragMoveEvent<KindDrag>, _, cx| {
                    if !ev.bounds.contains(&ev.event.position) {
                        return;
                    }
                    let after =
                        ev.event.position.y > ev.bounds.origin.y + ev.bounds.size.height * 0.5;
                    if this.kind_drop != Some((k, after)) {
                        this.kind_drop = Some((k, after));
                        cx.notify();
                    }
                }),
            )
            .on_drop(cx.listener(move |this, d: &KindDrag, _, cx| {
                let after = this.kind_drop.take().is_some_and(|(_, a)| a);
                this.reorder_kind(d.kind, k, after, cx)
            }))
            .when(kind_drag && dragged_kind == Some(k), |d| d.opacity(0.4))
            .on_drag(KindDrag { kind: k }, |d, grab, _, cx| {
                drag_started(&format!("kind:{}", d.kind.as_str()));
                cx.new(|_| DragChip {
                    icon: kind_icon(d.kind),
                    label: d.kind.label().into(),
                    grab,
                })
            });
            col = col.child(not_target(row));
        }
        if let (Some(opening), Some(dk)) = (self.kind_gaps.at(&kinds.len()), dragged_kind) {
            col = col.child(kind_ghost(dk, kinds.len(), opening, cx));
        }
        let root_id = self
            .groups
            .first()
            .map(|g| g.id.clone())
            .unwrap_or_default();
        let (r1, r2) = (root_id.clone(), root_id);
        // заголовок «ПАПКИ» во время перетаскивания: цель «в корень» (вынуть из папки).
        // Рамка есть всегда (прозрачная), поэтому при начале перетаскивания ничего не сдвигается.
        col = col.child(
            div().flex_shrink_0().pt_3().child(
                h_flex()
                    .id("folders-head")
                    .h(px(30.))
                    .pl_3()
                    .pr_1()
                    .rounded_lg()
                    .border_1()
                    .border_dashed()
                    .border_color(if dragging {
                        theme.primary.opacity(0.45)
                    } else {
                        transparent_black()
                    })
                    .drag_over::<EntryDrag>(drop_style(&theme))
                    .drag_over::<GroupDrag>(drop_style(&theme))
                    .on_drop(cx.listener(move |this, d: &EntryDrag, _, cx| {
                        this.move_entry(d.id.clone(), r1.clone(), cx)
                    }))
                    .on_drop(cx.listener(move |this, d: &GroupDrag, _, cx| {
                        this.move_group(d.id.clone(), r2.clone(), cx)
                    }))
                    .child(
                        div()
                            .flex_1()
                            .text_xs()
                            .font_weight(FontWeight::MEDIUM)
                            .text_color(if dragging {
                                theme.foreground
                            } else {
                                theme.muted_foreground
                            })
                            .child(if dragging {
                                tr!("В КОРЕНЬ: БРОСЬТЕ СЮДА")
                            } else {
                                tr!("ПАПКИ")
                            }),
                    )
                    .when(!dragging, |d| {
                        d.child(
                            Button::new("new-group")
                                .ghost()
                                .xsmall()
                                .icon(IconName::Plus)
                                .tooltip(tr!("Новая папка"))
                                .on_click(cx.listener(|this, _, w, cx| this.new_group(w, cx))),
                        )
                    }),
            ),
        );
        let bin_path = self
            .groups
            .iter()
            .find(|g| g.is_recycle_bin)
            .map(|g| g.path.clone());
        let in_bin = |g: &GroupView| {
            bin_path
                .as_ref()
                .is_some_and(|b| &g.path == b || g.path.starts_with(&format!("{b}/")))
        };
        // порядок папок как в базе; его меняют перетаскиванием
        let ordered: Vec<GroupView> = self
            .groups
            .iter()
            .skip(1)
            .filter(|g| !in_bin(g))
            .cloned()
            .collect();
        // копия перетаскиваемой папки в щели: перед папкой или после неё со всем поддеревом
        let dragged_group = dragging
            .then(dragged_id)
            .flatten()
            .and_then(|id| self.groups.iter().find(|g| g.id == id).cloned());
        // щель: «id:-1» перед папкой, «id:1» после неё со всем поддеревом
        let slot = self
            .group_drop
            .as_ref()
            .filter(|(id, z)| {
                dragging && *z != 0 && dragged_group.as_ref().is_some_and(|d| &d.id != id)
            })
            .map(|(id, z)| format!("{id}:{z}"));
        self.group_gaps.observe(slot);
        // щели «после», которые ждут конца поддерева (вложенные лежат сверху)
        let mut pending: Vec<(String, usize, String, bool)> = vec![];
        for g in ordered {
            while let Some((path, ..)) = pending.last()
                && !g.path.starts_with(&format!("{path}/"))
            {
                let (_, depth, key, opening) = pending.pop().expect("есть");
                if let Some(dg) = &dragged_group {
                    col = col.child(self.render_group_ghost(dg, depth, &key, opening, &theme, cx));
                }
            }
            let nav = Nav::Group(g.id.clone());
            let (gid, gid2, gid3) = (g.id.clone(), g.id.clone(), g.id.clone());
            let drag = GroupDrag {
                id: g.id.clone(),
                name: g.name.clone().into(),
            };
            // строка подсвечивается как «внутрь», только если курсор не на её краях
            let zone = self
                .group_drop
                .as_ref()
                .filter(|(id, _)| id == &g.id && dragging)
                .map(|(_, z)| *z);
            let before = format!("{}:-1", g.id);
            if let (Some(opening), Some(dg)) = (self.group_gaps.at(&before), &dragged_group) {
                col = col.child(self.render_group_ghost(
                    dg,
                    g.depth - 1,
                    &before,
                    opening,
                    &theme,
                    cx,
                ));
            }
            let after = format!("{}:1", g.id);
            if let Some(opening) = self.group_gaps.at(&after) {
                pending.push((g.path.clone(), g.depth - 1, after, opening));
            }
            let ctx = CtxTarget::Group {
                id: g.id.clone(),
                name: g.name.clone(),
                entries: g.entries,
            };
            col = col.child(
                target(item(
                    format!("g-{}", g.id).into(),
                    IconName::Folder,
                    g.name.clone(),
                    Some(g.entries),
                    g.depth - 1,
                    nav.clone(),
                    self.nav == nav,
                    cx,
                ))
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, ev: &MouseDownEvent, _, cx| {
                        this.ctx_menu = Some((ctx.clone(), ev.position));
                        cx.notify();
                    }),
                )
                .relative()
                .drag_over::<EntryDrag>(drop_style(&theme))
                .when(zone != Some(-1) && zone != Some(1), |d| {
                    d.drag_over::<GroupDrag>(drop_style(&theme))
                })
                // верхняя четверть строки: поставить перед, нижняя: после, середина: внутрь
                .on_drag_move(
                    cx.listener(move |this, ev: &DragMoveEvent<GroupDrag>, _, cx| {
                        if !ev.bounds.contains(&ev.event.position) {
                            return;
                        }
                        let h = ev.bounds.size.height;
                        let y = ev.event.position.y - ev.bounds.origin.y;
                        let z = if y < h * 0.25 {
                            -1
                        } else if y > h * 0.75 {
                            1
                        } else {
                            0
                        };
                        let hint = Some((gid3.clone(), z));
                        if this.group_drop != hint {
                            this.group_drop = hint;
                            cx.notify();
                        }
                    }),
                )
                .on_drop(cx.listener(move |this, d: &EntryDrag, _, cx| {
                    this.move_entry(d.id.clone(), gid.clone(), cx)
                }))
                .on_drop(cx.listener(move |this, d: &GroupDrag, _, cx| {
                    let z = this.group_drop.take().map(|(_, z)| z).unwrap_or(0);
                    if z == 0 {
                        this.move_group(d.id.clone(), gid2.clone(), cx)
                    } else {
                        this.reorder_group(d.id.clone(), gid2.clone(), z > 0, cx)
                    }
                }))
                .when(dragging && is_dragged(&g.id), |d| d.opacity(0.4))
                .when_some(
                    self.landed
                        .as_ref()
                        .filter(|(id, _)| id == &g.id)
                        .map(|l| l.1),
                    |d, n| d.child(landed_flash(n, theme.primary)),
                )
                .on_drag(drag, |d, grab, _, cx| {
                    drag_started(&d.id);
                    cx.new(|_| DragChip {
                        icon: IconName::Folder,
                        label: d.name.clone(),
                        grab,
                    })
                }),
            );
        }
        while let Some((_, depth, key, opening)) = pending.pop() {
            if let Some(dg) = &dragged_group {
                col = col.child(self.render_group_ghost(dg, depth, &key, opening, &theme, cx));
            }
        }
        // заметная строка в конце списка папок (значок в заголовке легко не увидеть)
        if !dragging && !kind_drag {
            col = col.child(
                h_flex()
                    .id("new-group-row")
                    .h(px(34.))
                    .flex_shrink_0()
                    .px_3()
                    .gap_3()
                    .rounded_lg()
                    .border_1()
                    .border_color(gpui_kit::transparent_black())
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .cursor_pointer()
                    .hover(|d| d.bg(theme.secondary).text_color(theme.sidebar_foreground))
                    .child(Icon::new(IconName::FolderPlus).small())
                    .child(tr!("Новая папка"))
                    .on_click(cx.listener(|this, _, w, cx| this.new_group(w, cx))),
            );
        }
        // тег, получивший записи, уже в общем списке
        let known: Vec<String> = self.tags.iter().map(|(t, _)| t.clone()).collect();
        self.pending_tags.retain(|t| !known.contains(t));
        let entry_drag = dragging && dragged_group.is_none();
        {
            col = col.child(section(tr!("ТЕГИ")));
            let all: Vec<(String, usize)> = self
                .tags
                .iter()
                .cloned()
                .chain(self.pending_tags.iter().map(|t| (t.clone(), 0)))
                .collect();
            for (t, n) in all {
                let nav = Nav::Tag(t.clone());
                let ctx = CtxTarget::Tag {
                    name: t.clone(),
                    count: n,
                };
                let t2 = t.clone();
                let row = item(
                    format!("t-{t}").into(),
                    IconName::Hash,
                    t,
                    Some(n),
                    0,
                    nav.clone(),
                    self.nav == nav,
                    cx,
                )
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, ev: &MouseDownEvent, _, cx| {
                        this.ctx_menu = Some((ctx.clone(), ev.position));
                        cx.notify();
                    }),
                )
                // запись, брошенная на тег, получает его
                .drag_over::<EntryDrag>(drop_style(&theme))
                .on_drop(cx.listener(move |this, d: &EntryDrag, _, cx| {
                    this.tag_entry(d.id.clone(), t2.clone(), cx)
                }));
                col = col.child(if entry_drag {
                    row.into_any_element()
                } else {
                    not_target(row)
                });
            }
            if !dragging && !kind_drag {
                col = col.child(
                    h_flex()
                        .id("new-tag-row")
                        .h(px(34.))
                        .flex_shrink_0()
                        .px_3()
                        .gap_3()
                        .rounded_lg()
                        .border_1()
                        .border_color(gpui_kit::transparent_black())
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .cursor_pointer()
                        .hover(|d| d.bg(theme.secondary).text_color(theme.sidebar_foreground))
                        .child(Icon::new(IconName::Plus).small())
                        .child(tr!("Новый тег"))
                        .on_click(cx.listener(|this, _, w, cx| this.new_tag(w, cx))),
                );
            }
        }
        let db = self.open_path.as_deref().map(file_name).unwrap_or_default();
        let profile =
            profile_label(&keywarden_core::ipc::profile().unwrap_or_else(|| "default".into()));
        let menu = self.profile_menu.then(|| self.render_profile_menu(cx));
        v_flex()
            .relative()
            .w(px(264.))
            .h_full()
            .flex_shrink_0()
            .bg(theme.sidebar)
            .border_r_1()
            .border_color(theme.sidebar_border)
            .child(
                // шапка: текущая база, щелчок открывает список баз
                h_flex()
                    .id("profile-switch")
                    .h(px(72.))
                    .flex_shrink_0()
                    .px_4()
                    .gap_3()
                    .border_b_1()
                    .border_color(theme.sidebar_border)
                    .cursor_pointer()
                    .hover(|d| d.bg(theme.secondary))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.profile_menu = !this.profile_menu;
                        if this.profile_menu {
                            this.refresh_profiles(cx);
                        }
                        cx.notify();
                    }))
                    .child(icon_tile(IconName::ShieldCheck, 40., &theme))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .text_base()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .truncate()
                                    .child(if profile == tr!("Основная") {
                                        "Keywarden".to_string()
                                    } else {
                                        profile.clone()
                                    }),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .truncate()
                                    .text_color(theme.muted_foreground)
                                    .child(db),
                            ),
                    )
                    .child(
                        Icon::new(IconName::ChevronsUpDown)
                            .small()
                            .text_color(theme.muted_foreground),
                    ),
            )
            .child(col)
            .child(
                h_flex()
                    .flex_shrink_0()
                    .p_3()
                    .gap_2()
                    .border_t_1()
                    .border_color(theme.sidebar_border)
                    .child(
                        Button::new("settings")
                            .ghost()
                            .icon(IconName::Settings)
                            .tooltip(tr!("Настройки хранилища"))
                            .on_click(cx.listener(|this, _, w, cx| this.open_settings(w, cx))),
                    )
                    .child(
                        Button::new("gen")
                            .ghost()
                            .flex_1()
                            .icon(IconName::WandSparkles)
                            .label(tr!("Генератор"))
                            .tooltip("Ctrl+G")
                            .on_click(cx.listener(|this, _, w, cx| this.open_generator(w, cx))),
                    )
                    .child(
                        Button::new("lock")
                            .ghost()
                            .icon(IconName::Lock)
                            .tooltip(tr!("Заблокировать (Ctrl+L)"))
                            .on_click(cx.listener(|this, _, _, cx| this.lock(cx))),
                    ),
            )
            .children(menu)
    }

    fn render_header(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let (icon, title) = self.nav_title();
        // в разделе типа кнопка создаёт запись этого типа: «+ Ключ SSH», «+ Карта»
        let kind = self.default_kind();
        let new_menu = DropdownButton::new("new")
            .button(
                Button::new("new-btn")
                    .primary()
                    .icon(IconName::Plus)
                    .label(if kind == EntryKind::Login {
                        tr!("Новая запись")
                    } else {
                        kind.label()
                    })
                    .on_click(cx.listener(move |this, _, w, cx| this.new_entry(kind, w, cx))),
            )
            .dropdown_menu(|menu, _, _| {
                menu.menu(tr!("Логин   Ctrl+N"), Box::new(NewLogin))
                    .menu(tr!("Карта"), Box::new(NewCard))
                    .menu(tr!("Личная информация"), Box::new(NewIdentity))
                    .menu(tr!("Заметка"), Box::new(NewNote))
                    .menu(tr!("Ключ SSH"), Box::new(NewSshKey))
                    .menu(tr!("Сервер SSH"), Box::new(NewSshHost))
                    .menu(tr!("Криптокошелёк"), Box::new(NewWallet))
            });
        let n = self.entries.len();
        v_flex()
            .flex_shrink_0()
            .child(
                // хлебные крошки и действия
                h_flex()
                    .h(px(56.))
                    .px_6()
                    .gap_2()
                    .border_b_1()
                    .border_color(theme.border)
                    .text_sm()
                    .child(
                        Icon::new(IconName::ShieldCheck)
                            .small()
                            .text_color(theme.muted_foreground),
                    )
                    .child(
                        div()
                            .text_color(theme.muted_foreground)
                            .child(tr!("Хранилище")),
                    )
                    .child(
                        Icon::new(IconName::ChevronRight)
                            .xsmall()
                            .text_color(theme.muted_foreground),
                    )
                    .child(div().child(title.clone()))
                    .child(div().flex_1())
                    .child(
                        div().w(px(300.)).child(
                            Input::new(&self.search)
                                .prefix(Icon::new(IconName::Search).small())
                                .cleanable(true),
                        ),
                    )
                    .when(
                        !matches!(self.nav, Nav::Otp | Nav::Settings | Nav::Health),
                        |d| {
                            d.child(
                                Button::new("sort")
                                    .ghost()
                                    .icon(IconName::ArrowUpDown)
                                    .label(self.sort.label())
                                    .tooltip(tr!("Порядок списка: щелчок переключает"))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.sort = match this.sort {
                                            Sort::Manual => Sort::Relevance,
                                            Sort::Relevance => Sort::Title,
                                            Sort::Title => Sort::Modified,
                                            Sort::Modified => Sort::Created,
                                            Sort::Created => Sort::Manual,
                                        };
                                        this.reload_list(false, cx);
                                    })),
                            )
                        },
                    )
                    .child(new_menu),
            )
            .child(
                h_flex()
                    .px_6()
                    .py_5()
                    .gap_3()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(icon_tile(icon, 40., &theme))
                    .child(
                        v_flex()
                            .flex_1()
                            .child(
                                div()
                                    .text_xl()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(title),
                            )
                            .child(
                                div().text_sm().text_color(theme.muted_foreground).child(
                                    match self.nav {
                                        Nav::Otp => tr!(
                                            "{entries}  ·  щёлкните по коду, чтобы скопировать",
                                            entries = plural_entries(n)
                                        ),
                                        Nav::Settings => {
                                            tr!("Параметры базы, мастер-ключ, импорт и экспорт")
                                                .to_string()
                                        }
                                        Nav::Health => {
                                            tr!("Слабые, повторяющиеся, старые и утёкшие пароли")
                                                .to_string()
                                        }
                                        _ => plural_entries(n),
                                    },
                                ),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_4()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .when(self.nav == Nav::Otp, |d| {
                                d.child(kbd_hint("enter", tr!("код")))
                            })
                            .when(
                                !matches!(self.nav, Nav::Otp | Nav::Settings | Nav::Health),
                                |d| {
                                    d.child(kbd_hint("enter", tr!("пароль")))
                                        .child(kbd_hint("ctrl-u", tr!("логин")))
                                        .child(kbd_hint("ctrl-t", "2FA"))
                                        .child(kbd_hint("ctrl-e", tr!("правка")))
                                },
                            ),
                    )
                    .when(self.loading_list, |d| {
                        d.child(Spinner::new().small().color(theme.muted_foreground))
                    }),
            )
    }

    /// Бросили запись в щель списка: встать перед записью, что сейчас за щелью (или в конец).
    fn drop_at_gap(&mut self, id: String, cx: &mut Context<Self>) {
        let Some(gap) = self.entry_drop.take() else {
            return;
        };
        match self.entries.get(gap) {
            Some(next) => {
                let target = next.id.clone();
                self.reorder_entry(id, target, false, cx)
            }
            None => {
                if let Some(last) = self.entries.last() {
                    let target = last.id.clone();
                    self.reorder_entry(id, target, true, cx)
                }
            }
        }
    }

    /// Копия перетаскиваемой папки в щели боковой панели. Бросок на неё равен броску на ту
    /// половину строки, что её открыла (`group_drop` хранит цель и сторону).
    fn render_group_ghost(
        &self,
        g: &GroupView,
        depth: usize,
        key: &str,
        opening: bool,
        theme: &gpui_kit::component::Theme,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let el = h_flex()
            .id(SharedString::from(format!("gghost-{key}")))
            .gap_3()
            .px_3()
            .pl(px(12. + depth as f32 * 14.))
            .rounded_lg()
            .border_1()
            .border_dashed()
            .border_color(theme.primary.opacity(0.5))
            .bg(theme.primary.opacity(0.06))
            .text_sm()
            .text_color(theme.sidebar_foreground)
            .overflow_hidden()
            .on_drop(cx.listener(|this, d: &GroupDrag, _, cx| {
                if let Some((target, z)) = this.group_drop.take() {
                    this.reorder_group(d.id.clone(), target, z > 0, cx)
                }
            }))
            .child(
                Icon::new(IconName::Folder)
                    .small()
                    .text_color(theme.primary),
            )
            .child(div().flex_1().truncate().child(g.name.clone()));
        gap_anim(el, "ggap", opening, self.group_gaps.generation, 34.)
    }

    /// Копия перетаскиваемой записи в раздвинутой щели: так видно, куда она встанет.
    fn render_ghost(
        &self,
        e: &EntrySummary,
        gap: usize,
        opening: bool,
        theme: &gpui_kit::component::Theme,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let el = h_flex()
            .id(("ghost", gap))
            .mx_2()
            .px_3()
            .gap_3()
            .rounded_lg()
            .border_1()
            .border_dashed()
            .border_color(theme.primary.opacity(0.5))
            .bg(theme.primary.opacity(0.06))
            .overflow_hidden()
            .on_drop(cx.listener(|this, d: &EntryDrag, _, cx| this.drop_at_gap(d.id.clone(), cx)))
            .child(crate::brands::tile(
                e,
                32.,
                kind_icon(e.kind),
                self.icon_for(e),
                theme,
            ))
            .child(
                v_flex()
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
                            .child(tr!("встанет сюда")),
                    ),
            );
        gap_anim(el, "egap", opening, self.entry_gaps.generation, 50.)
    }

    fn render_list(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        if !cx.has_active_drag() {
            self.entry_drop = None;
            self.group_drop = None;
        }
        let mut rows: Vec<AnyElement> = Vec::with_capacity(self.entries.len() + 1);
        // место для записи раздвигается там, куда она встанет (кроме её же места)
        let src = cx
            .has_active_drag()
            .then(dragged_id)
            .flatten()
            .and_then(|id| self.entries.iter().position(|e| e.id == id));
        let slot = src
            .zip(self.entry_drop)
            .filter(|(src, gap)| *gap != *src && *gap != src + 1)
            .map(|(_, gap)| gap);
        self.entry_gaps.observe(slot);
        let dragged = src.map(|i| self.entries[i].clone());
        for (ix, e) in self.entries.iter().enumerate() {
            if let (Some(g), Some(opening)) = (&dragged, self.entry_gaps.at(&ix)) {
                rows.push(self.render_ghost(g, ix, opening, &theme, cx));
            }
            let active = Some(ix) == self.selected;
            let who = if e.username.is_empty() {
                &e.detail
            } else {
                &e.username
            };
            let mut sub = match (who.is_empty(), e.group.is_empty()) {
                (false, false) => format!("{}  •  {}", who, e.group),
                (false, true) => who.clone(),
                (true, _) => e.group.clone(),
            };
            for t in e.tags.iter().take(3) {
                sub.push_str(&format!("  #{t}"));
            }
            let drag = EntryDrag {
                id: e.id.clone(),
                title: e.title.clone().into(),
            };
            let kind = e.kind;
            rows.push(
                h_flex()
                    .id(("entry", ix))
                    .on_drag(drag, move |d, grab, _, cx| {
                        drag_started(&d.id);
                        cx.new(|_| DragChip {
                            icon: kind_icon(kind),
                            label: d.title.clone(),
                            grab,
                        })
                    })
                    .on_drag_move(
                        cx.listener(move |this, ev: &DragMoveEvent<EntryDrag>, _, cx| {
                            if !ev.bounds.contains(&ev.event.position) {
                                return;
                            }
                            // щель, а не «до/после строки»: «после 3» и «перед 4» одно и то же место,
                            // поэтому раздвинутый список не заставляет указатель прыгать
                            let lower = ev.event.position.y > ev.bounds.center().y;
                            let hint = Some(if lower { ix + 1 } else { ix });
                            if this.entry_drop != hint {
                                this.entry_drop = hint;
                                cx.notify();
                            }
                        }),
                    )
                    .on_drop(
                        cx.listener(|this, d: &EntryDrag, _, cx| {
                            this.drop_at_gap(d.id.clone(), cx)
                        }),
                    )
                    .when(cx.has_active_drag() && is_dragged(&e.id), |d| {
                        d.opacity(0.4)
                    })
                    .when_some(
                        self.landed
                            .as_ref()
                            .filter(|(id, _)| id == &e.id)
                            .map(|l| l.1),
                        |d, n| d.child(landed_flash(n, theme.primary)),
                    )
                    .relative()
                    .gap_3()
                    .mx_2()
                    .px_3()
                    .py_2()
                    .rounded_lg()
                    .cursor_pointer()
                    .when(active, |d| d.bg(theme.list_active))
                    .when(!active, |d| d.hover(|d| d.bg(theme.secondary)))
                    .on_click(cx.listener(move |this, ev: &ClickEvent, w, cx| {
                        this.select(Some(ix), cx);
                        if ev.click_count() >= 2 {
                            this.edit_selected(w, cx);
                        }
                    }))
                    .child(crate::brands::tile(
                        e,
                        32.,
                        kind_icon(e.kind),
                        self.icon_for(e),
                        &theme,
                    ))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_0p5()
                            .child(
                                h_flex()
                                    .gap_2()
                                    .child(
                                        div()
                                            .text_sm()
                                            .font_weight(FontWeight::MEDIUM)
                                            .truncate()
                                            .child(if e.title.is_empty() {
                                                tr!("(без названия)").to_string()
                                            } else {
                                                e.title.clone()
                                            }),
                                    )
                                    .when(e.has_otp, |d| {
                                        d.child(badge("2FA", theme.success_foreground))
                                    })
                                    .when(e.expired, |d| {
                                        d.child(badge(tr!("истекла"), theme.danger_foreground))
                                    }),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .truncate()
                                    .child(sub),
                            ),
                    )
                    .with_animation(
                        (SharedString::from(format!("row-in-{}", self.rows_anim)), ix),
                        Animation::new(Duration::from_millis(if ix < 14 {
                            180 + 22 * ix as u64
                        } else {
                            1
                        }))
                        .with_easing(ease_out_quint()),
                        move |el, t| {
                            // задержка лесенкой: строка стоит, пока не дошла её очередь
                            let start = if ix < 14 {
                                (22. * ix as f32) / (180. + 22. * ix as f32)
                            } else {
                                0.
                            };
                            let k = ((t - start) / (1. - start)).clamp(0., 1.);
                            el.opacity(k).mt(px(4. * (1. - k)))
                        },
                    )
                    .into_any_element(),
            );
        }
        let end = self.entries.len();
        if let (Some(g), Some(opening)) = (&dragged, self.entry_gaps.at(&end)) {
            rows.push(self.render_ghost(g, end, opening, &theme, cx));
        }
        let body = if rows.is_empty() && self.loading_list {
            // скелетон только при первой загрузке, дальше старый список держится до ответа
            v_flex()
                .py_2()
                .children((0..7).map(|i| {
                    h_flex()
                        .gap_3()
                        .mx_2()
                        .px_3()
                        .py_2()
                        .child(Skeleton::new().size(px(32.)).rounded_lg())
                        .child(
                            v_flex()
                                .flex_1()
                                .gap_1p5()
                                .child(
                                    Skeleton::new()
                                        .h_3()
                                        .w(relative(0.45 + (i % 3) as f32 * 0.12))
                                        .rounded_md(),
                                )
                                .child(
                                    Skeleton::new()
                                        .secondary()
                                        .h_2p5()
                                        .w(relative(0.3))
                                        .rounded_md(),
                                ),
                        )
                }))
                .into_any_element()
        } else if rows.is_empty() {
            v_flex()
                .p_8()
                .gap_2()
                .items_center()
                .text_color(theme.muted_foreground)
                .child(Icon::new(IconName::Inbox).large())
                .child(
                    div()
                        .text_sm()
                        .child(if self.search.read(cx).value().is_empty() {
                            tr!("Здесь пока пусто. Ctrl+N: новая запись")
                        } else {
                            tr!("Ничего не найдено")
                        }),
                )
                // серверы обычно уже описаны в ~/.ssh/config: перенос прямо отсюда
                .when(
                    self.nav == Nav::Kind(EntryKind::SshHost)
                        && self.search.read(cx).value().is_empty(),
                    |d| {
                        d.child(
                            div().pt_2().child(
                                Button::new("ssh-import-config")
                                    .outline()
                                    .icon(IconName::Import)
                                    .label(tr!("Перенести из ~/.ssh/config…"))
                                    .on_click(
                                        cx.listener(|this, _, w, cx| this.open_ssh_import(w, cx)),
                                    ),
                            ),
                        )
                    },
                )
                .into_any_element()
        } else {
            v_flex().py_2().gap_0p5().children(rows).into_any_element()
        };
        div()
            .id("entries")
            .w(px(380.))
            .h_full()
            .flex_shrink_0()
            .border_r_1()
            .border_color(theme.border)
            .overflow_y_scroll()
            .track_scroll(&self.list_scroll)
            .child(body)
    }

    /// Страница «Коды 2FA»: все коды сразу, как в приложении-аутентификаторе.
    fn render_otp_grid(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        if self.entries.is_empty() {
            return v_flex()
                .flex_1()
                .items_center()
                .justify_center()
                .gap_3()
                .text_color(theme.muted_foreground)
                .child(icon_tile(IconName::Timer, 48., &theme))
                .child(div().text_sm().child(if self.loading_list {
                    tr!("Загружаю…")
                } else {
                    tr!("Кодов 2FA пока нет")
                }))
                .child(self.otp_toolbar(cx))
                .into_any_element();
        }
        let mut cards: Vec<AnyElement> = vec![];
        for (ix, e) in self.entries.iter().enumerate() {
            let active = Some(ix) == self.selected;
            let code = self.otp_codes.get(&e.id).cloned();
            let copied = active && self.copied.as_deref() == Some("totp");
            let sub = if e.username.is_empty() {
                e.group.clone()
            } else {
                e.username.clone()
            };
            cards.push(
                v_flex()
                    .id(("otp", ix))
                    .w(px(300.))
                    .h(px(150.))
                    .p_4()
                    .gap_2()
                    .rounded_lg()
                    .border_1()
                    .border_color(if active { theme.ring } else { theme.border })
                    .bg(if active {
                        theme.list_active
                    } else {
                        theme.background
                    })
                    .cursor_pointer()
                    .hover(|d| d.bg(theme.list_active))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.select(Some(ix), cx);
                        this.copy("totp", cx);
                    }))
                    .child(
                        h_flex()
                            .gap_3()
                            .child(crate::brands::tile(
                                e,
                                32.,
                                kind_icon(e.kind),
                                self.icon_for(e),
                                &theme,
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
                                            .child(sub),
                                    ),
                            )
                            .child(copy_icon(copied, &theme).small().text_color(if copied {
                                theme.success_foreground
                            } else {
                                theme.muted_foreground
                            })),
                    )
                    .child(match &code {
                        Some(c) => {
                            let (a, b) = c.code.split_at(c.code.len() / 2);
                            div()
                                .text_3xl()
                                .font_weight(FontWeight::SEMIBOLD)
                                .font_family(theme.mono_font_family.clone())
                                .child(format!("{a} {b}"))
                                .into_any_element()
                        }
                        None => Skeleton::new()
                            .h_8()
                            .w(px(170.))
                            .rounded_md()
                            .into_any_element(),
                    })
                    .child(match &code {
                        Some(c) => {
                            let urgent = c.remaining <= 5;
                            h_flex()
                                .gap_2()
                                .child(div().flex_1().child(countdown_bar(c, &theme)))
                                .child(
                                    div()
                                        .min_w(px(36.))
                                        .text_xs()
                                        .text_right()
                                        .text_color(if urgent {
                                            theme.danger_foreground
                                        } else {
                                            theme.muted_foreground
                                        })
                                        .child(if c.remaining <= 7 && !c.next.is_empty() {
                                            tr!(
                                                "{s} с · далее {next}",
                                                s = c.remaining,
                                                next = c.next
                                            )
                                        } else {
                                            tr!("{s} с", s = c.remaining)
                                        }),
                                )
                                .into_any_element()
                        }
                        None => Skeleton::new()
                            .secondary()
                            .h_1()
                            .rounded_full()
                            .into_any_element(),
                    })
                    .with_animation(
                        ("otp-in", ix),
                        Animation::new(Duration::from_millis(180 + 40 * ix.min(8) as u64))
                            .with_easing(ease_out_quint()),
                        |el, t| el.opacity(t).mt(px(6. * (1. - t))),
                    )
                    .into_any_element(),
            );
        }
        div()
            .id("otp-grid")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .child(div().px_6().pt_5().child(self.otp_toolbar(cx)))
            .child(div().flex().flex_wrap().gap_4().p_6().children(cards))
            .into_any_element()
    }

    fn otp_toolbar(&mut self, cx: &mut Context<Self>) -> impl IntoElement {
        h_flex()
            .gap_2()
            .child(
                Button::new("otp-add")
                    .primary()
                    .icon(IconName::Plus)
                    .label(tr!("Добавить 2FA"))
                    .tooltip("Ctrl+N")
                    .on_click(cx.listener(|this, _, w, cx| this.open_otp_wizard(false, w, cx))),
            )
            .child(
                Button::new("otp-import")
                    .outline()
                    .icon(IconName::Import)
                    .label(tr!("Из 2FAS"))
                    .on_click(cx.listener(|this, _, w, cx| this.import_twofas(w, cx))),
            )
            .child(
                Button::new("otp-export")
                    .outline()
                    .icon(IconName::FileDown)
                    .label(tr!("В 2FAS"))
                    .on_click(cx.listener(|this, _, w, cx| this.export_twofas(w, cx))),
            )
    }

    fn field_value(&self, f: &FieldView) -> (String, bool) {
        if !f.protected {
            return (
                f.value
                    .as_ref()
                    .map(|v| v.expose().to_string())
                    .unwrap_or_default(),
                true,
            );
        }
        if self.shown.contains(&f.name)
            && let Some(v) = self
                .revealed
                .as_ref()
                .and_then(|r| r.fields.iter().find(|x| x.name == f.name))
                .and_then(|x| x.value.as_ref())
        {
            return (v.expose().to_string(), true);
        }
        ("••••••••••".into(), false)
    }

    fn render_detail(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let theme = cx.theme().clone();
        let Some(d) = self.detail.clone() else {
            if self.loading_detail || (self.loading_list && self.entries.is_empty()) {
                return v_flex()
                    .p_6()
                    .gap_4()
                    .child(
                        h_flex()
                            .gap_3()
                            .child(Skeleton::new().size(px(44.)).rounded_lg())
                            .child(
                                v_flex()
                                    .flex_1()
                                    .gap_2()
                                    .child(Skeleton::new().h_5().w(relative(0.4)).rounded_md())
                                    .child(
                                        Skeleton::new()
                                            .secondary()
                                            .h_3()
                                            .w(relative(0.25))
                                            .rounded_md(),
                                    ),
                            ),
                    )
                    .child(Skeleton::new().h(px(96.)).rounded_xl())
                    .child(Skeleton::new().h(px(160.)).rounded_xl())
                    .into_any_element();
            }
            return v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_3()
                .text_color(theme.muted_foreground)
                .child(icon_tile(IconName::ShieldCheck, 48., &theme))
                .child(
                    div()
                        .text_sm()
                        .child(tr!("Выберите запись или создайте новую (Ctrl+N)")),
                )
                .into_any_element();
        };
        let wallet_body = if d.summary.kind == EntryKind::CryptoWallet {
            self.render_wallet(&d, cx)
        } else {
            div().into_any_element()
        };
        let ssh_body = if d.summary.kind == EntryKind::SshKey {
            self.render_ssh(&d, cx)
        } else {
            div().into_any_element()
        };
        let label_of = |name: &str| -> String {
            d.summary
                .kind
                .template()
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.label.to_string())
                .unwrap_or_else(|| match name {
                    "otp" => "2FA".into(),
                    "Password" => tr!("Пароль").into(),
                    "UserName" => tr!("поле§Логин").into(),
                    "URL" => tr!("Адрес").into(),
                    // доп. адреса KeePassDX/KeePass2Android и KeePassXC
                    other => match other
                        .strip_prefix("KP2A_URL_")
                        .or_else(|| other.strip_prefix("KP2A_URL"))
                    {
                        Some(n) if n.is_empty() || n.chars().all(|c| c.is_ascii_digit()) => {
                            tr!("Ещё адрес").into()
                        }
                        _ => other.into(),
                    },
                })
        };
        let visible_fields: Vec<&FieldView> = d
            .fields
            .iter()
            .filter(|f| !(f.name == "otp" || f.name == "TOTP Seed" || f.name == "TOTP Settings"))
            .filter(|f| {
                !(d.summary.kind == EntryKind::CryptoWallet
                    && (f.name == keywarden_core::wallet::SEED
                        || f.name == keywarden_core::wallet::ADDRESSES))
            })
            // скрытое (value None) показываем точками, пустое не показываем вовсе
            .filter(|f| f.value.as_ref().is_none_or(|v| !v.is_empty()))
            .collect();
        let last = visible_fields.len().saturating_sub(1);
        let fields: Vec<AnyElement> = visible_fields
            .into_iter()
            .enumerate()
            .map(|(ix, f)| {
                let (value, visible) = self.field_value(f);
                let name = f.name.clone();
                let guarded = d.summary.kind == EntryKind::CryptoWallet
                    && keywarden_core::wallet::is_guarded(&f.name);
                let copy_field = match f.name.as_str() {
                    "Password" => "password".to_string(),
                    "UserName" => "username".to_string(),
                    other => other.to_string(),
                };
                h_flex()
                    .gap_3()
                    .px_4()
                    .py_3()
                    .when(ix < last, |d| {
                        d.border_b_1().border_color(theme.table_row_border)
                    })
                    .hover(|d| d.bg(theme.secondary))
                    .child(
                        div()
                            .w(px(150.))
                            .flex_shrink_0()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(label_of(&f.name)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_sm()
                            .truncate()
                            .when(f.protected, |d| {
                                d.font_family(theme.mono_font_family.clone())
                            })
                            .when(!visible, |d| d.text_color(theme.muted_foreground))
                            .child(value),
                    )
                    .when(f.reference, |d| {
                        d.child(badge(tr!("ссылка"), theme.info_foreground))
                    })
                    .when(f.protected, |d| {
                        d.child(
                            Button::new(("eye", ix))
                                .ghost()
                                .xsmall()
                                .icon(if self.shown.contains(&f.name) {
                                    IconName::EyeOff
                                } else {
                                    IconName::Eye
                                })
                                .tooltip(tr!("Показать на 30 с"))
                                .on_click(cx.listener(move |this, _, w, cx| {
                                    let name = name.clone();
                                    if guarded && !this.elevated_ui() {
                                        this.with_auth(
                                            move |this, _, cx| {
                                                this.shown.remove(&name);
                                                this.reveal(name, cx)
                                            },
                                            w,
                                            cx,
                                        )
                                    } else {
                                        this.reveal(name, cx)
                                    }
                                })),
                        )
                    })
                    .child(
                        Button::new(("copy", ix))
                            .ghost()
                            .small()
                            .icon(copy_icon(
                                self.copied.as_deref() == Some(copy_field.as_str()),
                                &theme,
                            ))
                            .tooltip(tr!("Скопировать"))
                            .on_click(cx.listener(move |this, _, w, cx| {
                                let f = copy_field.clone();
                                if guarded {
                                    this.with_auth(move |this, _, cx| this.copy(&f, cx), w, cx)
                                } else {
                                    this.copy(&f, cx)
                                }
                            })),
                    )
                    .into_any_element()
            })
            .collect();

        let card = || v_flex().rounded_lg().overflow_hidden();
        let attachments = d.attachments.clone();
        let history = d.history.clone();
        let att_body: AnyElement = v_flex()
            .gap_3()
            .child(if attachments.is_empty() {
                muted_box(
                    tr!("Вложений нет: перетащите файл сюда из файлового менеджера"),
                    &theme,
                )
            } else {
                let n = attachments.len();
                card()
                    .children(attachments.into_iter().enumerate().map(|(ix, a)| {
                        let (n1, n2) = (a.name.clone(), a.name.clone());
                        let (n3, n4) = (a.name.clone(), a.name.clone());
                        h_flex()
                            .id(("att-row", ix))
                            .gap_3()
                            .px_4()
                            .py_3()
                            .cursor_pointer()
                            .hover(|d| d.bg(theme.secondary))
                            .on_click(cx.listener(move |this, _, w, cx| {
                                this.view_attachment(n3.clone(), w, cx)
                            }))
                            .when(ix + 1 < n, |d| {
                                d.border_b_1().border_color(theme.table_row_border)
                            })
                            .child(
                                Icon::new(crate::attachment_view::icon_for_name(&a.name))
                                    .small()
                                    .text_color(theme.muted_foreground),
                            )
                            .child(div().flex_1().text_sm().truncate().child(a.name.clone()))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(human_size(a.size)),
                            )
                            .child(
                                Button::new(("view-att", ix))
                                    .ghost()
                                    .small()
                                    .icon(IconName::Eye)
                                    .tooltip(tr!("Просмотр"))
                                    .on_click(cx.listener(move |this, _, w, cx| {
                                        this.view_attachment(n4.clone(), w, cx)
                                    })),
                            )
                            .child(
                                Button::new(("save-att", ix))
                                    .ghost()
                                    .small()
                                    .icon(IconName::Download)
                                    .tooltip(tr!("Сохранить на диск"))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.save_attachment(n1.clone(), cx)
                                    })),
                            )
                            .child(
                                Button::new(("rm-att", ix))
                                    .ghost()
                                    .small()
                                    .icon(IconName::Trash)
                                    .tooltip(tr!("Удалить"))
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.remove_attachment(n2.clone(), cx)
                                    })),
                            )
                    }))
                    .into_any_element()
            })
            .into_any_element();
        let hist_body: AnyElement = {
            if history.is_empty() {
                muted_box(tr!("Прошлых версий нет"), &theme)
            } else {
                let n = history.len();
                card()
                    .children(history.into_iter().enumerate().map(|(i, h)| {
                        let index = h.index;
                        h_flex()
                            .gap_3()
                            .px_4()
                            .py_3()
                            .when(i + 1 < n, |d| {
                                d.border_b_1().border_color(theme.table_row_border)
                            })
                            .child(
                                Icon::new(IconName::RotateCcwClock)
                                    .small()
                                    .text_color(theme.muted_foreground),
                            )
                            .child(div().text_sm().child(h.modified.unwrap_or_default()))
                            .child(
                                div()
                                    .flex_1()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .truncate()
                                    .child(h.title),
                            )
                            .child(
                                Button::new(("restore", index))
                                    .outline()
                                    .small()
                                    .label(tr!("Вернуть"))
                                    .on_click(
                                        cx.listener(move |this, _, _, cx| this.restore(index, cx)),
                                    ),
                            )
                    }))
                    .into_any_element()
            }
        };
        let fields_body: AnyElement = v_flex()
            .gap_4()
            .child(if fields.is_empty() {
                muted_box(tr!("Полей нет"), &theme)
            } else {
                card().children(fields).into_any_element()
            })
            // у ключа SSH открытый ключ уже показан выше
            .when(
                !d.notes.is_empty()
                    && !(d.summary.kind == EntryKind::SshKey
                        && keywarden_core::git_signing::key_body(d.notes.trim()).is_some()
                        && d.notes.trim().lines().count() == 1),
                |el| {
                    el.child(
                        v_flex()
                            .gap_2()
                            .child(section_head(tr!("Заметки"), None, None, &theme))
                            .child(card().px_4().py_3().text_sm().child(d.notes.clone())),
                    )
                },
            )
            .into_any_element();

        let code = self.code.clone();
        let anim_key = SharedString::from(format!("detail-{}", d.summary.id));
        let drop_id = d.summary.id.clone();
        v_flex()
            .id("detail")
            .size_full()
            .overflow_y_scroll()
            .drag_over::<ExternalPaths>(|st, _, _, cx| {
                st.bg(cx.theme().drop_target)
                    .border_2()
                    .border_color(cx.theme().drag_border)
            })
            .on_drop(cx.listener(move |this, paths: &ExternalPaths, _, cx| {
                this.attach_paths(drop_id.clone(), paths.paths().to_vec(), cx)
            }))
            .p_6()
            .gap_5()
            .child(
                h_flex()
                    .gap_3()
                    .child(crate::brands::tile(
                        &d.summary,
                        44.,
                        kind_icon(d.summary.kind),
                        self.icon_for(&d.summary),
                        &theme,
                    ))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .child(
                                h_flex().gap_2().child(
                                    div()
                                        .text_xl()
                                        .font_weight(FontWeight::SEMIBOLD)
                                        .truncate()
                                        .child(d.summary.title.clone()),
                                ),
                            )
                            .child(
                                h_flex()
                                    .gap_2()
                                    .text_sm()
                                    .text_color(theme.muted_foreground)
                                    .child(Tag::secondary().xsmall().child(d.summary.kind.label()))
                                    .when(!d.summary.group.is_empty(), |el| {
                                        el.child(div().truncate().child(d.summary.group.clone()))
                                    })
                                    .children(d.summary.tags.iter().map(|t| {
                                        let nav = Nav::Tag(t.clone());
                                        div()
                                            .id(SharedString::from(format!("dtag-{t}")))
                                            .px_1p5()
                                            .rounded_md()
                                            .text_xs()
                                            .text_color(theme.primary)
                                            .bg(theme.primary.opacity(0.1))
                                            .cursor_pointer()
                                            .hover(|d| d.bg(theme.primary.opacity(0.2)))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.set_nav(nav.clone(), cx)
                                            }))
                                            .child(format!("#{t}"))
                                    })),
                            ),
                    )
                    .map(|el| {
                        let has_custom = d.summary.icon.is_some();
                        let can_fetch = !d.summary.url.is_empty()
                            && crate::brands::find(&d.summary.title, &d.summary.url).is_none();
                        if has_custom {
                            el.child(
                                Button::new("clear-icon")
                                    .ghost()
                                    .icon(IconName::ImageOff)
                                    .tooltip(tr!("Убрать иконку сайта"))
                                    .on_click(cx.listener(|this, _, _, cx| this.clear_icon(cx))),
                            )
                        } else if can_fetch {
                            el.child(
                                Button::new("fetch-icon")
                                    .ghost()
                                    .icon(IconName::ImageDown)
                                    .tooltip(tr!(
                                        "Загрузить иконку сайта (один запрос к этому сайту)"
                                    ))
                                    .on_click(cx.listener(|this, _, _, cx| this.fetch_favicon(cx))),
                            )
                        } else {
                            el
                        }
                    })
                    .child(
                        Button::new("duplicate")
                            .outline()
                            .icon(IconName::CopyPlus)
                            .tooltip(tr!("Дублировать (Ctrl+D)"))
                            .on_click(cx.listener(|this, _, _, cx| this.duplicate(cx))),
                    )
                    .child(
                        Button::new("edit")
                            .outline()
                            .icon(IconName::Pencil)
                            .label(tr!("Изменить"))
                            .tooltip("Ctrl+E")
                            .on_click(cx.listener(|this, _, w, cx| this.edit_selected(w, cx))),
                    )
                    .child(
                        Button::new("delete")
                            .outline()
                            .icon(IconName::Trash)
                            .tooltip(tr!("Удалить (Shift+Delete)"))
                            .on_click(cx.listener(|this, _, w, cx| this.delete_selected(w, cx))),
                    ),
            )
            .when_some(d.expires.clone(), |el, date| {
                let expired = d.summary.expired;
                el.child(
                    h_flex()
                        .gap_2()
                        .px_3()
                        .py_2()
                        .rounded_lg()
                        .border_1()
                        .border_color(if expired {
                            theme.danger.opacity(0.35)
                        } else {
                            theme.border
                        })
                        .bg(if expired {
                            theme.danger.opacity(0.1)
                        } else {
                            theme.list_even
                        })
                        .text_sm()
                        .child(
                            Icon::new(if expired {
                                IconName::CalendarX
                            } else {
                                IconName::CalendarClock
                            })
                            .small()
                            .text_color(if expired {
                                theme.danger_foreground
                            } else {
                                theme.muted_foreground
                            }),
                        )
                        .child(if expired {
                            tr!(
                                "Срок действия истёк {date}: пора сменить пароль",
                                date = date
                            )
                        } else {
                            tr!("Действует до {date}", date = date)
                        }),
                )
            })
            .when(
                d.autotype != keywarden_core::model::AutotypeView::default(),
                |el| {
                    let at = &d.autotype;
                    let text = if !at.enabled {
                        tr!("Автоввод выключен для этой записи").to_string()
                    } else {
                        let mut t = tr!(
                            "Автоввод: {sequence}",
                            sequence = at
                                .sequence
                                .as_deref()
                                .map_or(tr!("логин, Tab, пароль, Enter").into(), human_sequence)
                        );
                        if !at.windows.is_empty() {
                            t.push_str(&tr!(" · окон: {n}", n = at.windows.len()));
                        }
                        t
                    };
                    el.child(
                        h_flex()
                            .gap_2()
                            .px_3()
                            .py_2()
                            .rounded_lg()
                            .border_1()
                            .border_color(theme.border)
                            .bg(theme.list_even)
                            .text_sm()
                            .child(
                                Icon::new(IconName::Keyboard)
                                    .small()
                                    .text_color(theme.muted_foreground),
                            )
                            .child(div().truncate().child(text)),
                    )
                },
            )
            .when(code.is_none() && d.summary.has_otp, |el| {
                el.child(code_placeholder(&theme))
            })
            .when(
                !d.summary.has_otp && matches!(d.summary.kind, EntryKind::Login),
                |el| {
                    el.child(
                        h_flex()
                            .id("add-otp")
                            .gap_2()
                            .px_4()
                            .py_3()
                            .rounded_xl()
                            .border_1()
                            .border_dashed()
                            .border_color(theme.border)
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .cursor_pointer()
                            .hover(|d| {
                                d.border_color(theme.primary.opacity(0.5))
                                    .text_color(theme.foreground)
                            })
                            .on_click(
                                cx.listener(|this, _, w, cx| this.open_otp_wizard(true, w, cx)),
                            )
                            .child(Icon::new(IconName::Timer).small())
                            .child(tr!("Добавить 2FA: секрет или QR-код с сайта")),
                    )
                },
            )
            .when_some(code, |el, c| {
                el.child(render_code(
                    &c,
                    self.copied.as_deref() == Some("totp"),
                    &theme,
                    cx,
                ))
            })
            .when(d.summary.kind == EntryKind::CryptoWallet, |el| {
                el.child(wallet_body)
            })
            .when(d.summary.kind == EntryKind::SshKey, |el| el.child(ssh_body))
            .child(section_head(tr!("Свойства"), None, None, &theme))
            .child(fields_body)
            .child(section_head(
                tr!("Вложения"),
                Some(d.attachments.len()),
                Some(
                    Button::new("attach")
                        .ghost()
                        .small()
                        .icon(IconName::Plus)
                        .label(tr!("Приложить"))
                        .on_click(cx.listener(|this, _, _, cx| this.add_attachment(cx)))
                        .into_any_element(),
                ),
                &theme,
            ))
            .child(att_body)
            .child(
                div()
                    .id("hist-head")
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.history_open = !this.history_open;
                        cx.notify();
                    }))
                    .child(section_head(
                        tr!("История"),
                        Some(d.history.len()),
                        Some(
                            Icon::new(if self.history_open {
                                IconName::ChevronDown
                            } else {
                                IconName::ChevronRight
                            })
                            .small()
                            .text_color(theme.muted_foreground)
                            .into_any_element(),
                        ),
                        &theme,
                    )),
            )
            .when(self.history_open, |el| {
                el.child(div().child(hist_body).with_animation(
                    "hist-open",
                    Animation::new(Duration::from_millis(160)).with_easing(ease_out_quint()),
                    |el, t| el.opacity(t),
                ))
            })
            .child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(tr!(
                        "Создана {created}  ·  изменена {modified}",
                        created = d.created.clone().unwrap_or_default(),
                        modified = d.modified.clone().unwrap_or_default()
                    )),
            )
            // мягкое проявление при смене записи: меняется только прозрачность, размеры не скачут
            .with_animation(
                ElementId::Name(anim_key),
                Animation::new(Duration::from_millis(140)).with_easing(ease_out_quint()),
                |el, t| el.opacity(0.55 + 0.45 * t),
            )
            .into_any_element()
    }
}

/// Карточка кода 2FA: крупные цифры, полоса оставшегося времени, копирование.
/// Полоса оставшегося времени кода: за секунду плавно убывает до следующего значения.
fn countdown_bar(c: &Code, theme: &gpui_kit::component::Theme) -> AnyElement {
    let period = c.period.max(1) as f32;
    let from = c.remaining as f32 / period;
    let color = if c.remaining <= 5 {
        theme.danger
    } else {
        theme.primary
    };
    div()
        .w_full()
        .h(px(4.))
        .rounded_full()
        .bg(theme.border)
        .child(
            div()
                .h_full()
                .rounded_full()
                .bg(color)
                .w(relative(from))
                .with_animation(
                    ElementId::Name(format!("cd-{}-{}", c.code, c.remaining).into()),
                    Animation::new(Duration::from_secs(1)),
                    move |el, t| el.w(relative((from - t / period).max(0.))),
                ),
        )
        .into_any_element()
}

/// Заголовок раздела карточки: название, число, справа действие; линия на всю ширину снизу.
fn section_head(
    title: &'static str,
    count: Option<usize>,
    right: Option<AnyElement>,
    theme: &gpui_kit::component::Theme,
) -> Div {
    h_flex()
        .w_full()
        .h(px(36.))
        .gap_2()
        .border_b_1()
        .border_color(theme.border)
        .child(
            div()
                .text_sm()
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        )
        .when_some(count.filter(|n| *n > 0), |d, n| {
            d.child(
                div()
                    .text_xs()
                    .text_color(theme.muted_foreground)
                    .child(n.to_string()),
            )
        })
        .child(div().flex_1())
        .children(right)
}

/// Высота карточки кода: одинаковая с заглушкой, чтобы при загрузке ничего не прыгало.
const CODE_CARD_H: f32 = 112.;

fn code_placeholder(theme: &gpui_kit::component::Theme) -> impl IntoElement {
    v_flex()
        .h(px(CODE_CARD_H))
        .gap_3()
        .p_4()
        .rounded_xl()
        .border_1()
        .border_color(theme.border)
        .bg(theme.list_even)
        .child(Skeleton::new().h_3().w(px(70.)).rounded_md())
        .child(Skeleton::new().h_8().w(px(180.)).rounded_md())
        .child(Skeleton::new().secondary().h_1().w(px(120.)).rounded_full())
}

/// Подсветка папки, над которой держат запись или папку.
fn drop_style<T>(
    theme: &gpui_kit::component::Theme,
) -> impl Fn(StyleRefinement, &T, &mut Window, &mut App) -> StyleRefinement + 'static {
    let (bg, border) = (theme.primary.opacity(0.12), theme.primary.opacity(0.4));
    move |s, _, _, _| s.bg(bg).border_color(border)
}

/// Копировать или галочка «скопировано».
fn copy_icon(done: bool, theme: &gpui_kit::component::Theme) -> Icon {
    if done {
        Icon::new(IconName::Check).text_color(theme.success_foreground)
    } else {
        Icon::new(IconName::Copy)
    }
}

fn render_code(
    c: &Code,
    copied: bool,
    theme: &gpui_kit::component::Theme,
    cx: &mut Context<MainWindow>,
) -> impl IntoElement {
    let urgent = c.remaining <= 5;
    let (a, b) = c.code.split_at(c.code.len() / 2);
    h_flex()
        .h(px(CODE_CARD_H))
        .gap_4()
        .p_4()
        .rounded_xl()
        .border_1()
        .border_color(theme.border)
        .bg(theme.list_even)
        .child(
            v_flex()
                .flex_1()
                .gap_1()
                .child(
                    div()
                        .text_sm()
                        .text_color(theme.muted_foreground)
                        .child(tr!("Код 2FA")),
                )
                .child(
                    div()
                        .text_3xl()
                        .font_weight(FontWeight::SEMIBOLD)
                        .font_family(theme.mono_font_family.clone())
                        .child(format!("{a} {b}")),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(div().w(px(120.)).child(countdown_bar(c, theme)))
                        .child(
                            div()
                                .text_xs()
                                .text_color(if urgent {
                                    theme.danger_foreground
                                } else {
                                    theme.muted_foreground
                                })
                                .child(tr!("ещё {s} с", s = c.remaining)),
                        )
                        .when(c.remaining <= 7 && !c.next.is_empty(), |d| {
                            d.child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .font_family(theme.mono_font_family.clone())
                                    .child(tr!("далее {next}", next = c.next)),
                            )
                        }),
                ),
        )
        .child(
            Button::new("qr-totp")
                .ghost()
                .icon(IconName::QrCode)
                .tooltip(tr!("QR-код для телефона"))
                .on_click(cx.listener(|this, _, w, cx| this.show_qr(w, cx))),
        )
        .child(
            Button::new("copy-totp")
                .outline()
                .icon(copy_icon(copied, theme))
                .tooltip(tr!("Скопировать (Ctrl+T)"))
                .on_click(cx.listener(|this, _, _, cx| this.copy("totp", cx))),
        )
}

/// QR-код клетками: светлая подложка с полями, как требуют сканеры.
fn qr_element(text: &str) -> AnyElement {
    let Some((w, cells)) = keywarden_core::totp::qr_matrix(text) else {
        return div()
            .child(tr!("ссылка слишком длинная для QR"))
            .into_any_element();
    };
    qr_cells(w, &cells, 6.)
}

fn qr_cells(w: usize, cells: &[bool], size: f32) -> AnyElement {
    let cell = px(size);
    v_flex()
        .p(px(24.))
        .bg(gpui_kit::white())
        .rounded_lg()
        .children((0..w).map(|y| {
            h_flex().children((0..w).map(|x| {
                div()
                    .size(cell)
                    .when(cells[y * w + x], |d| d.bg(gpui_kit::black()))
            }))
        }))
        .into_any_element()
}

/// Пустой раздел: одна приглушённая строка, без рамок.
fn muted_box(text: &'static str, theme: &gpui_kit::component::Theme) -> AnyElement {
    div()
        .px_4()
        .py_3()
        .text_sm()
        .text_color(theme.muted_foreground)
        .child(text)
        .into_any_element()
}

fn file_name(path: &str) -> String {
    std::path::Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.to_string())
}

fn plural_entries(n: usize) -> String {
    let w = keywarden_core::i18n::plural(n as u64, "запись", "записи", "записей");
    format!("{n} {w}")
}

fn human_size(n: usize) -> String {
    match n {
        n if n >= 1 << 20 => tr!("{n} МБ", n = format!("{:.1}", n as f64 / (1 << 20) as f64)),
        n if n >= 1 << 10 => tr!("{n} КБ", n = format!("{:.1}", n as f64 / 1024.)),
        n => tr!("{n} Б", n = n),
    }
}

/// Типы в сохранённом порядке; новые или незнакомые в конце по умолчанию.
fn ordered_kinds(saved: &[String]) -> Vec<EntryKind> {
    let mut out: Vec<EntryKind> = saved
        .iter()
        .filter_map(|s| EntryKind::ALL.iter().copied().find(|k| k.as_str() == s))
        .collect();
    for k in EntryKind::ALL {
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

/// Идёт перетаскивание записи или папки (а не ползунка из диалога).
static OUR_DRAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Номер перетаскивания: анимации «приглушить остальное» стартуют заново на каждое.
static DRAG_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Что тащат: строка-источник остаётся на месте полупрозрачной.
static DRAGGED: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

fn drag_started(id: &str) {
    OUR_DRAG.store(true, std::sync::atomic::Ordering::Relaxed);
    DRAG_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    *DRAGGED.lock().unwrap_or_else(|p| p.into_inner()) = Some(id.to_string());
}

fn dragged_id() -> Option<String> {
    OUR_DRAG
        .load(std::sync::atomic::Ordering::Relaxed)
        .then(|| DRAGGED.lock().unwrap_or_else(|p| p.into_inner()).clone())
        .flatten()
}

fn is_dragged(id: &str) -> bool {
    OUR_DRAG.load(std::sync::atomic::Ordering::Relaxed)
        && DRAGGED.lock().unwrap_or_else(|p| p.into_inner()).as_deref() == Some(id)
}

/// Вспышка на месте, куда встала запись или папка после перетаскивания.
fn landed_flash(n: u64, color: Hsla) -> impl IntoElement {
    div().absolute().inset_0().rounded_lg().with_animation(
        ("landed", n as usize),
        Animation::new(Duration::from_millis(700)).with_easing(ease_out_quint()),
        move |el, t| el.bg(color.opacity(0.22 * (1. - t))),
    )
}

impl Render for MainWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let ready = self.mode == Mode::Ready;
        // после блокировки событием демона фокус никуда не попадает: ставим его в поле ключа
        if self.mode == Mode::Locked && window.focused(cx).is_none() {
            let h = if self.use_pin && !self.creating {
                self.pin.read(cx).focus_handle(cx)
            } else {
                self.password.read(cx).focus_handle(cx)
            };
            window.focus(&h, cx);
        }
        let body = if ready {
            let right = match &self.editor {
                Some(e) => div().size_full().child(e.clone()).into_any_element(),
                None => self.render_detail(cx),
            };
            h_flex()
                .size_full()
                .child(self.render_sidebar(cx))
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .h_full()
                        .child(self.render_header(cx))
                        .child(
                            if let Some(page) =
                                self.settings.clone().filter(|_| self.nav == Nav::Settings)
                            {
                                div().flex_1().min_h_0().child(page).into_any_element()
                            } else if self.nav == Nav::Health {
                                self.render_health(cx)
                            } else if self.nav == Nav::Otp && self.editor.is_none() {
                                self.render_otp_grid(cx)
                            } else {
                                h_flex()
                                    .flex_1()
                                    .min_h_0()
                                    .child(self.render_list(cx))
                                    .child(div().flex_1().h_full().min_w_0().child(right))
                                    .into_any_element()
                            },
                        ),
                )
                .into_any_element()
        } else {
            self.render_unlock(cx)
        };
        // уведомление в углу; ошибки разблокировки показываются в самой форме
        let toast = self.status.clone().filter(|_| ready).map(|(msg, err)| {
            let n = self.status_at.map(|t| t.elapsed().as_nanos()).unwrap_or(0);
            h_flex()
                .absolute()
                .bottom(px(20.))
                .right(px(20.))
                .max_w(px(420.))
                .gap_2()
                .px_4()
                .py_2p5()
                .rounded_lg()
                .border_1()
                .border_color(if err {
                    theme.danger.opacity(0.4)
                } else {
                    theme.border
                })
                .bg(theme.popover)
                .shadow_lg()
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
                .child(div().truncate().child(msg))
                .with_animation(
                    ElementId::Name(format!("toast-{n}").into()),
                    Animation::new(Duration::from_millis(180)).with_easing(ease_out_quint()),
                    |el, t| el.opacity(t).bottom(px(12. + 8. * t)),
                )
        });

        v_flex()
            .id("main")
            .key_context(CONTEXT)
            .relative()
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .font_family(theme.font_family.clone())
            .capture_action(cx.listener(|this, _: &MoveUp, _, cx| {
                if this.mode == Mode::Ready && this.editor.is_none() {
                    this.move_selection(-1, cx);
                } else {
                    cx.propagate();
                }
            }))
            .capture_action(cx.listener(|this, _: &MoveDown, _, cx| {
                if this.mode == Mode::Ready && this.editor.is_none() {
                    this.move_selection(1, cx);
                } else {
                    cx.propagate();
                }
            }))
            .on_action(cx.listener(|this, _: &FocusSearch, w, cx| {
                this.editor = None;
                let h = this.search.read(cx).focus_handle(cx);
                w.focus(&h, cx);
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &UnlockOptions, _, cx| {
                this.show_advanced = !this.show_advanced;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &ToggleCreateVault, _, cx| {
                this.creating = !this.creating;
                this.status = None;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &NewLogin, w, cx| {
                let kind = this.default_kind();
                this.new_entry(kind, w, cx)
            }))
            .on_action(
                cx.listener(|this, _: &NewCard, w, cx| this.new_entry(EntryKind::Card, w, cx)),
            )
            .on_action(cx.listener(|this, _: &NewIdentity, w, cx| {
                this.new_entry(EntryKind::Identity, w, cx)
            }))
            .on_action(
                cx.listener(|this, _: &NewNote, w, cx| this.new_entry(EntryKind::Note, w, cx)),
            )
            .on_action(
                cx.listener(|this, _: &NewSshKey, w, cx| this.new_entry(EntryKind::SshKey, w, cx)),
            )
            .on_action(
                cx.listener(|this, _: &NewSshHost, w, cx| {
                    this.new_entry(EntryKind::SshHost, w, cx)
                }),
            )
            .on_action(cx.listener(|this, _: &NewWallet, w, cx| {
                this.new_entry(EntryKind::CryptoWallet, w, cx)
            }))
            .on_action(cx.listener(|this, _: &EditEntry, w, cx| this.edit_selected(w, cx)))
            .on_action(cx.listener(|this, _: &DeleteEntry, w, cx| this.delete_selected(w, cx)))
            .on_action(cx.listener(|this, _: &LockDatabase, _, cx| this.lock(cx)))
            .on_action(cx.listener(|this, _: &OpenGenerator, w, cx| this.open_generator(w, cx)))
            .on_action(cx.listener(|this, _: &CopyPassword, _, cx| this.copy("password", cx)))
            .on_action(cx.listener(|this, _: &CopyUsername, _, cx| this.copy("username", cx)))
            .on_action(cx.listener(|this, _: &CopyTotp, _, cx| this.copy("totp", cx)))
            .on_action(cx.listener(|this, _: &PrevFilter, _, cx| this.step_nav(-1, cx)))
            .on_action(cx.listener(|this, _: &NextFilter, _, cx| this.step_nav(1, cx)))
            .on_action(cx.listener(|this, _: &NudgeUp, _, cx| this.nudge(-1, cx)))
            .on_action(cx.listener(|this, _: &RevealWallet, w, cx| {
                if this
                    .detail
                    .as_ref()
                    .is_some_and(|d| d.summary.kind == EntryKind::CryptoWallet)
                {
                    this.with_auth(|this, _, cx| this.reveal_seed(cx), w, cx)
                }
            }))
            .on_action(cx.listener(|this, _: &NudgeDown, _, cx| this.nudge(1, cx)))
            .on_action(cx.listener(|this, _: &DuplicateEntry, _, cx| this.duplicate(cx)))
            .on_action(cx.listener(|this, _: &TabFields, _, cx| {
                this.detail_tab = 0;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &TabAttachments, _, cx| {
                this.detail_tab = 1;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &TabHistory, _, cx| {
                this.history_open = !this.history_open;
                cx.notify();
            }))
            .on_action(cx.listener(|this, _: &OpenAttachment, w, cx| {
                // первое вложение записи; остальные открываются щелчком
                if let Some(a) = this.detail.as_ref().and_then(|d| d.attachments.first()) {
                    let name = a.name.clone();
                    this.detail_tab = 1;
                    this.view_attachment(name, w, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &NextProfile, w, cx| {
                // следующая база по кругу, как вкладки баз в KeePassXC
                let all = keywarden_core::ipc::profiles();
                let current = keywarden_core::ipc::profile().unwrap_or_else(|| "default".into());
                let i = all.iter().position(|p| *p == current).unwrap_or(0);
                if let Some(next) = all.get((i + 1) % all.len()).cloned() {
                    this.switch_profile(next, w, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &OpenSettings, w, cx| {
                if this.mode == Mode::Ready {
                    this.open_settings(w, cx)
                }
            }))
            .child(div().flex_1().min_h_0().child(body))
            .child(crate::smooth_scroll::listener())
            .children(toast)
            .children(self.render_ctx_menu(cx))
    }
}

pub fn window_options(cx: &App) -> WindowOptions {
    let bounds = Bounds::centered(None, size(px(1200.), px(760.)), cx);
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(bounds)),
        titlebar: Some(TitlebarOptions {
            title: Some("Keywarden".into()),
            ..Default::default()
        }),
        app_id: Some("keywarden".into()),
        window_min_size: Some(size(px(860.), px(520.))),
        ..Default::default()
    }
}

#[cfg(test)]
mod sequence_tests {
    #[test]
    fn sequence_reads_like_words() {
        assert_eq!(
            super::human_sequence("{USERNAME}{TAB}{PASSWORD}{ENTER}"),
            "логин, Tab, пароль, Enter"
        );
        assert_eq!(
            super::human_sequence("ab{TOTP}{DELAY 5}"),
            "«ab», код 2FA, {DELAY 5}"
        );
    }
}
