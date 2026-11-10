//! Типы записей поверх обычных записей KDBX.
//!
//! Тип хранится в custom data (`keywarden.type`), поля шаблона хранятся как обычные пользовательские
//! поля KDBX, секретные с флагом защиты. В KeePassXC такая запись выглядит как обычная запись
//! с дополнительными полями. Записи без метки получают тип по содержимому
//! (KPEX_PASSKEY_* → passkey, вложение KeeAgent.settings → SSH-ключ).

use crate::secret::Secret;
use keepass::Database;
use keepass::db::{
    CustomDataItem, CustomDataValue, EntryId, EntryRef, GroupId, GroupRef, Times, Value, fields,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub const TYPE_KEY: &str = "keywarden.type";
pub const KEEAGENT_SETTINGS: &str = "KeeAgent.settings";
pub const PASSKEY_PREFIX: &str = "KPEX_PASSKEY_";
pub const PASSKEY_PRIVATE_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const LEGACY_TOTP_SEED: &str = "TOTP Seed";
pub const LEGACY_TOTP_SETTINGS: &str = "TOTP Settings";

#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    #[error("{}", crate::tr!("запись не найдена"))]
    EntryNotFound,
    #[error("{}", crate::tr!("группа не найдена"))]
    GroupNotFound,
    #[error("{}", crate::tr!("неверный идентификатор: {e}", e = .0))]
    BadId(String),
    #[error("{}", crate::tr!("вложение не найдено: {e}", e = .0))]
    AttachmentNotFound(String),
}

pub type Result<T> = std::result::Result<T, ModelError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Login,
    Card,
    Identity,
    Note,
    SshKey,
    SshHost,
    Passkey,
    CryptoWallet,
}

impl EntryKind {
    pub const ALL: [EntryKind; 8] = [
        Self::Login,
        Self::Card,
        Self::Identity,
        Self::Note,
        Self::SshKey,
        Self::SshHost,
        Self::Passkey,
        Self::CryptoWallet,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Card => "card",
            Self::Identity => "identity",
            Self::Note => "note",
            Self::SshKey => "ssh_key",
            Self::SshHost => "ssh_host",
            Self::Passkey => "passkey",
            Self::CryptoWallet => "crypto_wallet",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Login => crate::tr!("Логин"),
            Self::Card => crate::tr!("Карта"),
            Self::Identity => crate::tr!("Личная информация"),
            Self::Note => crate::tr!("Заметка"),
            Self::SshKey => crate::tr!("Ключ SSH"),
            Self::SshHost => crate::tr!("Сервер SSH"),
            Self::Passkey => crate::tr!("Ключ доступа"),
            Self::CryptoWallet => crate::tr!("Криптокошелёк"),
        }
    }

    /// Поля шаблона в порядке показа. Имена английские: так их видят KeePassXC и мобильные клиенты.
    pub fn template(self) -> Vec<FieldSpec> {
        match self {
            Self::Login => t_login(),
            Self::Card => t_card(),
            Self::Identity => t_identity(),
            Self::Note => t_note(),
            Self::SshKey => t_ssh_key(),
            Self::SshHost => t_ssh_host(),
            Self::Passkey => t_passkey(),
            Self::CryptoWallet => t_wallet(),
        }
    }
}

// Поля шаблонов. Имена английские: так их видят KeePassXC и мобильные клиенты.
fn t_login() -> Vec<FieldSpec> {
    vec![
        FieldSpec::new(fields::USERNAME, crate::tr!("поле§Логин"), false),
        FieldSpec::new(fields::PASSWORD, crate::tr!("Пароль"), true),
        FieldSpec::new(fields::URL, crate::tr!("сайт§Адрес"), false).hint("https://example.com"),
        FieldSpec::new(fields::OTP, "2FA", true).hint("otpauth://totp/…"),
    ]
}
fn t_card() -> Vec<FieldSpec> {
    vec![
        FieldSpec::new("Cardholder", crate::tr!("Владелец"), false),
        FieldSpec::new("Card Number", crate::tr!("Номер карты"), true),
        FieldSpec::new("Expiry", crate::tr!("Срок"), false).hint(crate::tr!("ММ/ГГ")),
        FieldSpec::new("CVV", "CVV", true),
        FieldSpec::new("PIN", "PIN", true),
        FieldSpec::new("Brand", crate::tr!("Платёжная система"), false),
    ]
}
fn t_identity() -> Vec<FieldSpec> {
    vec![
        FieldSpec::new("First Name", crate::tr!("Имя"), false),
        FieldSpec::new("Middle Name", crate::tr!("Отчество"), false),
        FieldSpec::new("Last Name", crate::tr!("Фамилия"), false),
        FieldSpec::new("Email", crate::tr!("Почта"), false),
        FieldSpec::new("Phone", crate::tr!("Телефон"), false),
        FieldSpec::new("Company", crate::tr!("Компания"), false),
        FieldSpec::new("Address", crate::tr!("Адрес"), false),
        FieldSpec::new("City", crate::tr!("Город"), false),
        FieldSpec::new("Postal Code", crate::tr!("Индекс"), false),
        FieldSpec::new("Country", crate::tr!("Страна"), false),
        FieldSpec::new("Passport Number", crate::tr!("Номер паспорта"), true),
        FieldSpec::new("License Number", crate::tr!("Номер прав"), true),
        FieldSpec::new("SSN", crate::tr!("СНИЛС / SSN"), true),
    ]
}
fn t_note() -> Vec<FieldSpec> {
    vec![]
}
fn t_wallet() -> Vec<FieldSpec> {
    vec![
        FieldSpec::new(
            crate::wallet::WALLET_TYPE,
            crate::tr!("Тип кошелька"),
            false,
        ),
        FieldSpec::new(crate::wallet::NETWORKS, crate::tr!("Сети"), false),
        FieldSpec::new(crate::wallet::SEED, crate::tr!("Сид-фраза"), true),
        FieldSpec::new(crate::wallet::PASSPHRASE, "Passphrase", true)
            .hint(crate::tr!("25-е слово, если задано")),
        FieldSpec::new(
            crate::wallet::PRIVATE_KEY,
            crate::tr!("Приватный ключ"),
            true,
        ),
        FieldSpec::new(fields::PASSWORD, crate::tr!("Пароль приложения"), true),
        FieldSpec::new(
            crate::wallet::DERIVATION,
            crate::tr!("Путь деривации"),
            false,
        )
        .hint("m/84'/0'/0'/0/0"),
        FieldSpec::new(crate::wallet::ADDRESSES, crate::tr!("Адреса"), false)
            .hint(crate::tr!("по одному на строку")),
        FieldSpec::new(crate::wallet::XPUB, "xpub", false),
    ]
}
fn t_ssh_key() -> Vec<FieldSpec> {
    vec![
        FieldSpec::new(fields::USERNAME, crate::tr!("Пользователь"), false),
        FieldSpec::new(fields::PASSWORD, crate::tr!("Пароль ключа"), true),
        FieldSpec::new(fields::URL, crate::tr!("Хост"), false)
            .hint(crate::tr!("github.com, git@host, ssh://user@host:2222")),
    ]
}
fn t_ssh_host() -> Vec<FieldSpec> {
    use crate::ssh_hosts as h;
    vec![
        FieldSpec::new(fields::URL, crate::tr!("Адрес"), false).hint("user@host:port"),
        FieldSpec::new(h::KEY, crate::tr!("Ключ"), false).hint(crate::tr!(
            "название записи «Ключ SSH»; пусто: любой ключ агента"
        )),
        FieldSpec::new(h::PROXY, crate::tr!("Через хост"), false)
            .hint(crate::tr!("ProxyJump: bastion или user@bastion:2222")),
        FieldSpec::new(h::FORWARD, crate::tr!("Проброс портов"), false)
            .hint(crate::tr!("8080, 5432:db:5432 (локальный:хост:удалённый)")),
        FieldSpec::new(h::OPTIONS, crate::tr!("Другие настройки"), false).hint(crate::tr!(
            "строки ssh_config через ; например ServerAliveInterval 30"
        )),
        FieldSpec::new(h::KNOCK, "Port knocking", true)
            .hint(crate::tr!("порты по порядку: 7000 8000:udp 9000")),
    ]
}
fn t_passkey() -> Vec<FieldSpec> {
    vec![
        FieldSpec::new(fields::USERNAME, crate::tr!("поле§Логин"), false),
        FieldSpec::new(fields::URL, crate::tr!("Сайт"), false),
        FieldSpec::new("KPEX_PASSKEY_RELYING_PARTY", "Relying party", false),
    ]
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct FieldSpec {
    pub name: &'static str,
    pub label: &'static str,
    pub protected: bool,
    /// подсказка в пустом поле (формат, пример)
    pub hint: &'static str,
}

impl FieldSpec {
    const fn new(name: &'static str, label: &'static str, protected: bool) -> Self {
        Self {
            name,
            label,
            protected,
            hint: "",
        }
    }

    const fn hint(mut self, hint: &'static str) -> Self {
        self.hint = hint;
        self
    }
}

// --- Представления для IPC и UI ---

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntrySummary {
    pub id: String,
    pub kind: EntryKind,
    pub title: String,
    pub username: String,
    pub url: String,
    /// путь группы без корня, через "/"
    pub group: String,
    pub tags: Vec<String>,
    pub has_otp: bool,
    /// срок действия "YYYY-MM-DD", если задан
    #[serde(default)]
    pub expires: Option<String>,
    #[serde(default)]
    pub expired: bool,
    /// ISO-время для сортировки списка
    #[serde(default)]
    pub modified: String,
    #[serde(default)]
    pub created: String,
    /// UUID собственной иконки записи (favicon), если есть
    #[serde(default)]
    pub icon: Option<String>,
    /// вторая строка в списке, когда логина нет (у кошелька: тип и что хранится)
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldView {
    pub name: String,
    /// `None`, если поле защищено и не запрошено раскрытие
    pub value: Option<Secret>,
    pub protected: bool,
    /// значение ссылается на другую запись или поле ({REF:...}, {USERNAME}): при просмотре без
    /// раскрытия показано уже подставленное значение, при раскрытии (правке) сырое
    #[serde(default)]
    pub reference: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttachmentView {
    pub name: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryView {
    pub index: usize,
    pub modified: Option<String>,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EntryDetail {
    pub summary: EntrySummary,
    pub notes: String,
    /// все поля кроме Title и Notes: сначала по шаблону, потом остальные по алфавиту
    pub fields: Vec<FieldView>,
    pub attachments: Vec<AttachmentView>,
    pub history: Vec<HistoryView>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub expires: Option<String>,
    #[serde(default)]
    pub autotype: AutotypeView,
}

/// Настройки автоввода записи (как вкладка Auto-Type в KeePassXC).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AutotypeView {
    pub enabled: bool,
    /// своя последовательность; `None`: по умолчанию ({USERNAME}{TAB}{PASSWORD}{ENTER})
    #[serde(default)]
    pub sequence: Option<String>,
    /// привязки: шаблон заголовка окна (`*` любая подстрока) и последовательность (пусто: общая)
    #[serde(default)]
    pub windows: Vec<(String, String)>,
}

impl Default for AutotypeView {
    fn default() -> Self {
        Self {
            enabled: true,
            sequence: None,
            windows: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub path: String,
    pub parent: Option<String>,
    pub depth: usize,
    pub entries: usize,
    pub is_recycle_bin: bool,
}

/// Изменения записи. Неупомянутые поля, вложения, история и custom data не трогаются.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryPatch {
    pub kind: Option<EntryKind>,
    pub group: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub set: Vec<FieldSet>,
    #[serde(default)]
    pub remove: Vec<String>,
    /// срок действия: `Some(Some("2027-01-31"))` задать, `Some(None)` снять, `None` не трогать
    #[serde(default)]
    pub expires: Option<Option<String>>,
    /// автоввод: `None` не трогать
    #[serde(default)]
    pub autotype: Option<AutotypeView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSet {
    pub name: String,
    pub value: Secret,
    /// `None`: как у существующего поля, иначе по шаблону (Password и otp всегда защищены)
    pub protected: Option<bool>,
}

impl FieldSet {
    pub fn new(name: impl Into<String>, value: impl Into<Secret>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            protected: None,
        }
    }
}

// --- Чтение ---

pub fn parse_entry_id(s: &str) -> Result<EntryId> {
    Uuid::parse_str(s)
        .map(EntryId::from)
        .map_err(|_| ModelError::BadId(s.into()))
}

pub fn parse_group_id(s: &str) -> Result<GroupId> {
    Uuid::parse_str(s)
        .map(GroupId::from)
        .map_err(|_| ModelError::BadId(s.into()))
}

pub fn kind_of(e: &EntryRef<'_>) -> EntryKind {
    if let Some(CustomDataItem {
        value: Some(CustomDataValue::String(s)),
        ..
    }) = e.custom_data.get(TYPE_KEY)
        && let Some(k) = EntryKind::parse(s)
    {
        return k;
    }
    if e.fields.contains_key(PASSKEY_PRIVATE_KEY) {
        return EntryKind::Passkey;
    }
    if e.attachment_by_name(KEEAGENT_SETTINGS).is_some() {
        return EntryKind::SshKey;
    }
    let empty = |k| e.get(k).is_none_or(str::is_empty);
    if empty(fields::USERNAME)
        && empty(fields::PASSWORD)
        && empty(fields::URL)
        && !empty(fields::NOTES)
    {
        return EntryKind::Note;
    }
    EntryKind::Login
}

pub fn has_otp(e: &EntryRef<'_>) -> bool {
    e.get(fields::OTP).is_some_and(|s| !s.is_empty())
        || e.get(LEGACY_TOTP_SEED).is_some_and(|s| !s.is_empty())
}

/// Цепочка от группы до корня включительно.
fn ancestors(db: &Database, id: GroupId) -> Vec<GroupId> {
    let mut out = vec![id];
    while let Some(p) = db
        .group(*out.last().unwrap())
        .and_then(|g| g.parent().map(|p| p.id()))
    {
        out.push(p);
    }
    out
}

/// Лежит ли группа `g` внутри `ancestor` (или это она сама).
pub fn is_descendant(db: &Database, g: GroupId, ancestor: GroupId) -> bool {
    ancestors(db, g).contains(&ancestor)
}

/// Путь группы без корня: "Finance/Cards".
pub fn group_path(db: &Database, id: GroupId) -> String {
    let mut chain = ancestors(db, id);
    chain.pop(); // корень не показываем
    chain
        .iter()
        .rev()
        .filter_map(|g| db.group(*g).map(|g| g.name.clone()))
        .collect::<Vec<_>>()
        .join("/")
}

/// Лежит ли группа (или её предок) в корзине.
pub fn in_recycle_bin(db: &Database, id: GroupId) -> bool {
    db.meta
        .recyclebin_uuid
        .is_some_and(|bin| ancestors(db, id).iter().any(|g| g.uuid() == bin))
}

/// Отключён ли поиск в группе (EnableSearching=false у неё или у ближайшего предка, как в KeePassXC).
pub fn searching_disabled(db: &Database, id: GroupId) -> bool {
    ancestors(db, id)
        .iter()
        .find_map(|g| db.group(*g).and_then(|g| g.enable_searching))
        .is_some_and(|on| !on)
}

pub fn summary(e: &EntryRef<'_>) -> EntrySummary {
    let s = |k| e.get(k).unwrap_or_default().to_string();
    EntrySummary {
        id: e.id().uuid().to_string(),
        kind: kind_of(e),
        title: s(fields::TITLE),
        username: s(fields::USERNAME),
        url: s(fields::URL),
        group: group_path(e.database(), e.parent().id()),
        tags: e.tags.clone(),
        has_otp: has_otp(e),
        expires: (e.times.expires == Some(true))
            .then(|| e.times.expiry.format("%Y-%m-%d").to_string()),
        expired: is_expired(e),
        modified: iso(e.times.last_modification),
        created: iso(e.times.creation),
        icon: e.custom_icon().map(|i| i.id().uuid().to_string()),
        detail: wallet_detail(e),
    }
}

/// «MetaMask · сид-фраза»: без раскрытия самих секретов, только что из них заполнено.
fn wallet_detail(e: &EntryRef<'_>) -> String {
    use crate::wallet::*;
    if kind_of(e) != EntryKind::CryptoWallet {
        return String::new();
    }
    let has = |k| e.get(k).is_some_and(|v| !v.trim().is_empty());
    let what = if has(SEED) {
        crate::tr!("сид-фраза")
    } else if has(PRIVATE_KEY) {
        crate::tr!("приватный ключ")
    } else if has(XPUB) {
        crate::tr!("только просмотр (xpub)")
    } else {
        ""
    };
    [e.get(WALLET_TYPE).unwrap_or_default().trim(), what]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("  •  ")
}

fn iso(t: Option<chrono::NaiveDateTime>) -> String {
    t.map(|t| t.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_default()
}

/// Срок действия прошёл (время в KDBX хранится в UTC).
pub fn is_expired(e: &EntryRef<'_>) -> bool {
    e.times.expires == Some(true) && e.times.expiry <= Times::now()
}

/// "2027-01-31" -> конец этого дня.
fn parse_expiry(s: &str) -> Result<chrono::NaiveDateTime> {
    chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(23, 59, 59))
        .ok_or_else(|| {
            ModelError::BadId(crate::tr!(
                "дата срока действия: ГГГГ-ММ-ДД, а не «{s}»",
                s = s
            ))
        })
}

pub fn detail(db: &Database, id: &str, reveal: bool) -> Result<EntryDetail> {
    let e = db
        .entry(parse_entry_id(id)?)
        .ok_or(ModelError::EntryNotFound)?;
    let kind = kind_of(&e);
    let mut names: Vec<&String> = e
        .fields
        .keys()
        .filter(|k| *k != fields::TITLE && *k != fields::NOTES)
        .collect();
    let order = |n: &str| {
        kind.template()
            .iter()
            .position(|f| f.name == n)
            .unwrap_or(usize::MAX)
    };
    names.sort_by(|a, b| order(a).cmp(&order(b)).then(a.cmp(b)));
    let fields_view = names
        .into_iter()
        .map(|name| {
            let v = &e.fields[name];
            let raw = v.get();
            let reference = raw.contains('{') && resolve(db, &e, raw) != *raw;
            FieldView {
                name: name.clone(),
                value: if reveal {
                    Some(Secret::new(raw.clone()))
                } else if v.is_protected() && !raw.is_empty() {
                    // пустое защищённое поле отдаём пустым: «пусто» не секрет, а окну
                    // не нужно рисовать строку с точками там, где ничего нет
                    None
                } else {
                    Some(Secret::new(resolve(db, &e, raw)))
                },
                protected: v.is_protected(),
                reference,
            }
        })
        .collect();
    let fmt =
        |t: Option<chrono::NaiveDateTime>| t.map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string());
    let history = e
        .history
        .as_ref()
        .map(|h| {
            h.get_entries()
                .iter()
                .enumerate()
                .map(|(index, old)| HistoryView {
                    index,
                    modified: fmt(old.times.last_modification),
                    title: old.get_title().unwrap_or_default().to_string(),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(EntryDetail {
        summary: summary(&e),
        notes: e.get(fields::NOTES).unwrap_or_default().to_string(),
        fields: fields_view,
        attachments: e
            .attachments_named()
            .map(|(name, a)| AttachmentView {
                name: name.to_string(),
                size: a.data.len(),
            })
            .collect(),
        history,
        created: fmt(e.times.creation),
        modified: fmt(e.times.last_modification),
        expires: (e.times.expires == Some(true))
            .then(|| e.times.expiry.format("%Y-%m-%d").to_string()),
        autotype: e
            .autotype
            .as_ref()
            .map(|a| AutotypeView {
                enabled: a.enabled,
                sequence: a.default_sequence.clone().filter(|s| !s.trim().is_empty()),
                windows: a
                    .associations
                    .iter()
                    .map(|x| (x.window.clone(), x.sequence.clone()))
                    .collect(),
            })
            .unwrap_or_default(),
    })
}

/// Копия записи в той же папке: поля, теги, вложения, тип; история не копируется (как в KeePassXC
/// по умолчанию). К названию добавляется « (копия)».
pub fn duplicate_entry(db: &mut Database, id: &str) -> Result<String> {
    let src = db
        .entry(parse_entry_id(id)?)
        .ok_or(ModelError::EntryNotFound)?;
    let group = src.parent().id();
    let mut fields = src.fields.clone();
    let tags = src.tags.clone();
    let custom = src.custom_data.clone();
    let autotype = src.autotype.clone();
    let icon = src.icon().cloned();
    let attachments: Vec<(String, Value<Vec<u8>>)> = src
        .attachments_named()
        .map(|(n, a)| (n.to_string(), a.data.clone()))
        .collect();
    let title = crate::tr!(
        "{title} (копия)",
        title = src.get(fields::TITLE).unwrap_or_default()
    );
    fields.insert(fields::TITLE.into(), Value::unprotected(title));
    let now = Times::now();
    let mut g = db.group_mut(group).ok_or(ModelError::GroupNotFound)?;
    let mut e = g.add_entry();
    e.fields = fields;
    e.tags = tags;
    e.custom_data = custom;
    e.autotype = autotype;
    match icon {
        Some(keepass::db::Icon::BuiltIn(i)) => e.set_icon_builtin(i),
        Some(keepass::db::Icon::Custom(c)) => {
            let _ = e.set_icon_custom(c);
        }
        _ => {}
    }
    for (n, d) in attachments {
        e.add_attachment(n, d);
    }
    e.times.creation = Some(now);
    e.times.last_modification = Some(now);
    e.times.last_access = Some(now);
    Ok(e.id().uuid().to_string())
}

/// Собственная иконка записи (PNG), как «Загрузить favicon» в KeePassXC. Одинаковые картинки
/// хранятся в базе один раз, ставшие ненужными удаляются.
pub fn set_custom_icon(db: &mut Database, id: &str, png: Vec<u8>) -> Result<()> {
    let eid = parse_entry_id(id)?;
    let existing = db
        .iter_all_custom_icons()
        .find(|i| i.data == png)
        .map(|i| i.id());
    let mut e = db.entry_mut(eid).ok_or(ModelError::EntryNotFound)?;
    match existing {
        Some(icon) => e
            .set_icon_custom(icon)
            .map_err(|_| ModelError::EntryNotFound)?,
        None => {
            e.set_icon_custom_new(png);
        }
    }
    e.times.last_modification = Some(Times::now());
    drop_unused_icons(db);
    Ok(())
}

pub fn clear_icon(db: &mut Database, id: &str) -> Result<()> {
    let mut e = db
        .entry_mut(parse_entry_id(id)?)
        .ok_or(ModelError::EntryNotFound)?;
    e.set_icon_none();
    e.times.last_modification = Some(Times::now());
    drop_unused_icons(db);
    Ok(())
}

/// Данные собственной иконки по UUID.
pub fn icon_data(db: &Database, uuid: &str) -> Option<Vec<u8>> {
    db.iter_all_custom_icons()
        .find(|i| i.id().uuid().to_string() == uuid)
        .map(|i| i.data.clone())
}

fn drop_unused_icons(db: &mut Database) {
    db.rebuild_custom_icon_refs();
    let unused: Vec<_> = db
        .iter_all_custom_icons()
        .filter(|i| i.entries(true).next().is_none() && i.groups().next().is_none())
        .map(|i| i.id())
        .collect();
    for id in unused {
        if let Some(i) = db.custom_icon_mut(id) {
            i.remove();
        }
    }
}

/// Переместить запись в папку (перетаскивание): без новой версии в истории, как в KeePassXC.
pub fn move_entry(db: &mut Database, id: &str, group: &str) -> Result<()> {
    let g = parse_group_id(group)?;
    db.group(g).ok_or(ModelError::GroupNotFound)?;
    let mut e = db
        .entry_mut(parse_entry_id(id)?)
        .ok_or(ModelError::EntryNotFound)?;
    if e.as_ref().parent().id() == g {
        return Ok(());
    }
    e.move_to(g).map_err(|_| ModelError::GroupNotFound)?;
    e.times.location_changed = Some(Times::now());
    Ok(())
}

/// Переместить папку в другую; в саму себя, в свою подпапку и корень двигать нельзя.
pub fn move_group(db: &mut Database, id: &str, parent: &str) -> Result<()> {
    let (g, p) = (parse_group_id(id)?, parse_group_id(parent)?);
    db.group(p).ok_or(ModelError::GroupNotFound)?;
    if g == db.root().id() || is_descendant(db, p, g) {
        return Err(ModelError::BadId(
            crate::tr!("папку нельзя переместить в саму себя или в её подпапку").into(),
        ));
    }
    let mut gm = db.group_mut(g).ok_or(ModelError::GroupNotFound)?;
    gm.move_to(p).map_err(|_| ModelError::GroupNotFound)?;
    gm.times.location_changed = Some(Times::now());
    Ok(())
}

/// Поставить запись перед или после другой (ручной порядок, как в KeePassXC).
/// Если цель в другой папке, запись сначала переезжает туда.
pub fn reorder_entry(db: &mut Database, id: &str, target: &str, after: bool) -> Result<()> {
    let (e, t) = (parse_entry_id(id)?, parse_entry_id(target)?);
    if e == t {
        return Ok(());
    }
    let tg = db.entry(t).ok_or(ModelError::EntryNotFound)?.parent().id();
    move_entry(db, id, &tg.uuid().to_string())?;
    let mut g = db.group_mut(tg).ok_or(ModelError::GroupNotFound)?;
    let ti = g.entry_index(t).ok_or(ModelError::EntryNotFound)?;
    let ei = g.entry_index(e).ok_or(ModelError::EntryNotFound)?;
    g.reorder_entry(e, place(ei, ti, after));
    Ok(())
}

/// То же для папок: перед или после другой папки, при необходимости с переездом к её родителю.
pub fn reorder_group(db: &mut Database, id: &str, target: &str, after: bool) -> Result<()> {
    let (g, t) = (parse_group_id(id)?, parse_group_id(target)?);
    if g == t {
        return Ok(());
    }
    let parent = db
        .group(t)
        .ok_or(ModelError::GroupNotFound)?
        .parent()
        .map(|p| p.id())
        .ok_or_else(|| ModelError::BadId(crate::tr!("рядом с корнем папку не поставить").into()))?;
    move_group(db, id, &parent.uuid().to_string())?;
    let mut p = db.group_mut(parent).ok_or(ModelError::GroupNotFound)?;
    let ti = p.group_index(t).ok_or(ModelError::GroupNotFound)?;
    let gi = p.group_index(g).ok_or(ModelError::GroupNotFound)?;
    p.reorder_group(g, place(gi, ti, after));
    Ok(())
}

/// Сдвинуть запись на `delta` позиций внутри её папки (Alt+Shift+стрелки).
pub fn nudge_entry(db: &mut Database, id: &str, delta: isize) -> Result<()> {
    let e = parse_entry_id(id)?;
    let gid = db.entry(e).ok_or(ModelError::EntryNotFound)?.parent().id();
    let mut g = db.group_mut(gid).ok_or(ModelError::GroupNotFound)?;
    let i = g.entry_index(e).ok_or(ModelError::EntryNotFound)? as isize;
    g.reorder_entry(e, (i + delta).max(0) as usize);
    Ok(())
}

/// Куда встать элементу с позиции `from`, чтобы оказаться перед (или после) элемента на `target`:
/// после изъятия элемента всё правее него сдвигается на одну позицию влево.
fn place(from: usize, target: usize, after: bool) -> usize {
    let to = if after { target + 1 } else { target };
    if from < to { to - 1 } else { to }
}

/// Порядок записей как в базе: записи папки по порядку, затем её подпапки по порядку.
pub fn tree_order(db: &Database) -> HashMap<EntryId, usize> {
    fn walk(g: GroupRef<'_>, out: &mut HashMap<EntryId, usize>) {
        for e in g.entries() {
            let n = out.len();
            out.insert(e.id(), n);
        }
        for c in g.groups() {
            walk(c, out);
        }
    }
    let mut out = HashMap::new();
    walk(db.root(), &mut out);
    out
}

/// Переименовать тег во всех записях (если новый уже есть, теги сольются). Возвращает число записей.
pub fn rename_tag(db: &mut Database, from: &str, to: &str) -> Result<usize> {
    let to = to.trim();
    if to.is_empty() || to.contains([',', ';']) {
        return Err(ModelError::BadId(
            crate::tr!("тег не может быть пустым или содержать , и ;").into(),
        ));
    }
    retag(db, from, Some(to))
}

/// Снять тег со всех записей. Возвращает число записей.
pub fn remove_tag(db: &mut Database, tag: &str) -> Result<usize> {
    retag(db, tag, None)
}

fn retag(db: &mut Database, from: &str, to: Option<&str>) -> Result<usize> {
    let ids: Vec<EntryId> = db
        .iter_all_entries()
        .filter(|e| e.tags.iter().any(|t| t == from))
        .map(|e| e.id())
        .collect();
    for id in &ids {
        let mut e = db.entry_mut(*id).ok_or(ModelError::EntryNotFound)?;
        e.tags.retain(|t| t != from);
        if let Some(to) = to
            && !e.tags.iter().any(|t| t == to)
        {
            e.tags.push(to.to_string());
        }
        // время правки: слияние с другими устройствами подхватит изменение
        e.times.last_modification = Some(Times::now());
    }
    Ok(ids.len())
}

/// Все теги вне корзины с числом записей, по алфавиту.
pub fn tags(db: &Database) -> Vec<(String, usize)> {
    let mut m: std::collections::BTreeMap<String, usize> = Default::default();
    for e in db.iter_all_entries() {
        if in_recycle_bin(db, e.parent().id()) {
            continue;
        }
        for t in &e.tags {
            *m.entry(t.clone()).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by_key(|(t, _)| t.to_lowercase());
    v
}

/// Подстановки KeePass в значении поля: `{REF:P@I:<uuid>}` (поле другой записи по UUID или
/// по тексту поля: `{REF:U@T:GitHub}`) и `{TITLE}`, `{USERNAME}`, `{URL}`, `{PASSWORD}`, `{NOTES}`
/// своей записи. Глубина ограничена, чтобы циклические ссылки не зациклили.
pub fn resolve(db: &Database, e: &EntryRef<'_>, value: &str) -> String {
    resolve_depth(db, e, value, 0)
}

fn resolve_depth(db: &Database, e: &EntryRef<'_>, value: &str, depth: usize) -> String {
    if depth > 8 || !value.contains('{') {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let tail = &rest[start..];
        let Some(end) = tail.find('}') else {
            out.push_str(tail);
            return out;
        };
        let token = &tail[1..end];
        match placeholder(db, e, token) {
            Some(v) => out.push_str(&resolve_depth(db, e, &v, depth + 1)),
            None => out.push_str(&tail[..=end]),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

fn field_by_code(c: char) -> Option<&'static str> {
    Some(match c.to_ascii_uppercase() {
        'T' => fields::TITLE,
        'U' => fields::USERNAME,
        'P' => fields::PASSWORD,
        'A' => fields::URL,
        'N' => fields::NOTES,
        _ => return None,
    })
}

fn placeholder(db: &Database, e: &EntryRef<'_>, token: &str) -> Option<String> {
    let own = |f: &str| e.get(f).map(str::to_string);
    match token.to_ascii_uppercase().as_str() {
        "TITLE" => return own(fields::TITLE),
        "USERNAME" => return own(fields::USERNAME),
        "URL" => return own(fields::URL),
        "PASSWORD" => return own(fields::PASSWORD),
        "NOTES" => return own(fields::NOTES),
        _ => {}
    }
    // REF:<что>@<где>:<значение>
    let spec = token
        .strip_prefix("REF:")
        .or_else(|| token.strip_prefix("ref:"))?;
    let (want, rest) = spec.split_once('@')?;
    let (by, needle) = rest.split_once(':')?;
    let want = field_by_code(want.chars().next()?)?;
    let by = by.chars().next()?.to_ascii_uppercase();
    let target = db.iter_all_entries().find(|x| match by {
        'I' => x
            .id()
            .uuid()
            .simple()
            .to_string()
            .eq_ignore_ascii_case(&needle.replace('-', "")),
        c => field_by_code(c).is_some_and(|f| {
            x.get(f)
                .is_some_and(|v| v.to_lowercase().contains(&needle.to_lowercase()))
        }),
    })?;
    target.get(want).map(str::to_string)
}

/// Значение поля целиком (для копирования). Пароль ключа, номер карты и т.д.
pub fn field_value(db: &Database, id: &str, field: &str) -> Result<Option<Secret>> {
    let e = db
        .entry(parse_entry_id(id)?)
        .ok_or(ModelError::EntryNotFound)?;
    Ok(e.get(field).map(|v| Secret::new(resolve(db, &e, v))))
}

pub fn attachment(db: &Database, id: &str, name: &str) -> Result<Vec<u8>> {
    let e = db
        .entry(parse_entry_id(id)?)
        .ok_or(ModelError::EntryNotFound)?;
    let a = e
        .attachment_by_name(name)
        .ok_or_else(|| ModelError::AttachmentNotFound(name.into()))?;
    Ok(a.data.get().clone())
}

pub fn groups(db: &Database) -> Vec<GroupView> {
    fn walk(db: &Database, g: GroupRef<'_>, depth: usize, out: &mut Vec<GroupView>) {
        out.push(GroupView {
            id: g.id().uuid().to_string(),
            name: g.name.clone(),
            path: group_path(db, g.id()),
            parent: g.parent().map(|p| p.id().uuid().to_string()),
            depth,
            entries: g.entries().count(),
            is_recycle_bin: db.meta.recyclebin_uuid == Some(g.id().uuid()),
        });
        // порядок папок как в базе: его задаёт пользователь перетаскиванием
        for c in g.groups() {
            walk(db, c, depth + 1, out);
        }
    }
    let mut out = Vec::new();
    walk(db, db.root(), 0, &mut out);
    out
}

// --- Изменение ---

/// Новая запись по шаблону типа. Возвращает её id.
pub fn create_entry(db: &mut Database, patch: &EntryPatch) -> Result<String> {
    let group = match &patch.group {
        Some(g) => parse_group_id(g)?,
        None => db.root().id(),
    };
    let kind = patch.kind.unwrap_or(EntryKind::Login);
    let id = {
        let mut g = db.group_mut(group).ok_or(ModelError::GroupNotFound)?;
        let mut e = g.add_entry();
        e.set_unprotected(fields::TITLE, "");
        for f in [fields::USERNAME, fields::URL, fields::NOTES] {
            e.set_unprotected(f, "");
        }
        e.set_protected(fields::PASSWORD, "");
        for spec in kind.template() {
            if !e.fields.contains_key(spec.name) && spec.name != fields::OTP {
                e.set(spec.name, value(spec.protected, String::new()));
            }
        }
        e.id()
    };
    apply(
        db,
        id,
        &EntryPatch {
            group: None,
            ..patch.clone()
        },
        kind,
        false,
    )?;
    Ok(id.uuid().to_string())
}

/// Изменить запись; прежняя версия уходит в историю, как в KeePassXC.
pub fn update_entry(db: &mut Database, id: &str, patch: &EntryPatch) -> Result<()> {
    let id = parse_entry_id(id)?;
    let kind = match patch.kind {
        Some(k) => k,
        None => kind_of(&db.entry(id).ok_or(ModelError::EntryNotFound)?),
    };
    apply(db, id, patch, kind, true)
}

fn apply(
    db: &mut Database,
    id: EntryId,
    patch: &EntryPatch,
    kind: EntryKind,
    track: bool,
) -> Result<()> {
    let target_group = patch.group.as_deref().map(parse_group_id).transpose()?;
    if let Some(g) = target_group {
        db.group(g).ok_or(ModelError::GroupNotFound)?;
    }
    let max_history = db.meta.history_max_items.unwrap_or(10);
    let now = Times::now();
    let expiry = match &patch.expires {
        Some(Some(d)) => Some(Some(parse_expiry(d)?)),
        Some(None) => Some(None),
        None => None,
    };
    let mut e = db.entry_mut(id).ok_or(ModelError::EntryNotFound)?;
    let edit = |e: &mut keepass::db::EntryMut<'_>| {
        if let Some(a) = &patch.autotype {
            e.autotype = Some(keepass::db::AutoType {
                enabled: a.enabled,
                default_sequence: a.sequence.clone().filter(|s| !s.trim().is_empty()),
                associations: a
                    .windows
                    .iter()
                    .filter(|(w, _)| !w.trim().is_empty())
                    .map(|(w, seq)| keepass::db::AutoTypeAssociation {
                        window: w.trim().to_string(),
                        sequence: seq.trim().to_string(),
                    })
                    .collect(),
                ..e.autotype.clone().unwrap_or_default()
            });
        }
        match expiry {
            Some(Some(t)) => {
                e.times.expires = Some(true);
                e.times.expiry = t;
            }
            Some(None) => e.times.expires = Some(false),
            None => {}
        }
        if let Some(k) = patch.kind {
            e.custom_data.insert(
                TYPE_KEY.into(),
                CustomDataItem {
                    value: Some(CustomDataValue::String(k.as_str().into())),
                    last_modification_time: Some(now),
                },
            );
        }
        if let Some(tags) = &patch.tags {
            e.tags = tags.clone();
        }
        for f in &patch.set {
            let protected = f.protected.unwrap_or_else(|| {
                e.fields
                    .get(&f.name)
                    .map(Value::is_protected)
                    .unwrap_or_else(|| default_protected(kind, &f.name))
            });
            e.set(
                f.name.clone(),
                value(protected, f.value.expose().to_string()),
            );
        }
        for name in &patch.remove {
            e.fields.remove(name);
        }
        e.times.last_modification = Some(now);
        e.times.last_access = Some(now);
    };
    if track {
        e.edit_tracking(|t| edit(&mut t.as_mut()));
    } else {
        e.edit(edit);
    }
    if let Some(g) = target_group
        && e.as_ref().parent().id() != g
    {
        e.move_to(g).map_err(|_| ModelError::GroupNotFound)?;
        e.times.location_changed = Some(now);
    }
    if track {
        trim_history(&mut e, max_history);
        db.remove_unused_attachments();
    }
    Ok(())
}

fn trim_history(e: &mut keepass::db::EntryMut<'_>, max: isize) {
    if max < 0 {
        return;
    }
    if let Some(h) = &e.history
        && h.get_entries().len() > max as usize
    {
        let keep: Vec<_> = h.get_entries()[..max as usize].to_vec();
        let mut new = keepass::db::History::default();
        for old in keep.into_iter().rev() {
            new.add_entry(old); // add_entry вставляет в начало
        }
        e.history = Some(new);
    }
}

fn default_protected(kind: EntryKind, name: &str) -> bool {
    name == fields::PASSWORD
        || name == fields::OTP
        || name == LEGACY_TOTP_SEED
        || name.starts_with(PASSKEY_PREFIX)
            && name != "KPEX_PASSKEY_USERNAME"
            && name != "KPEX_PASSKEY_RELYING_PARTY"
        || kind
            .template()
            .iter()
            .any(|f| f.name == name && f.protected)
}

fn value(protected: bool, s: String) -> Value<String> {
    if protected {
        Value::protected(s)
    } else {
        Value::unprotected(s)
    }
}

/// Удаление как в KeePassXC: сначала в корзину; из корзины насовсем с записью в DeletedObjects,
/// чтобы удаление доехало до других копий базы при слиянии.
pub fn delete_entry(db: &mut Database, id: &str) -> Result<()> {
    let id = parse_entry_id(id)?;
    let parent = db.entry(id).ok_or(ModelError::EntryNotFound)?.parent().id();
    let already_in_bin = in_recycle_bin(db, parent);
    if db.meta.recyclebin_enabled != Some(false) && !already_in_bin {
        let bin = ensure_recycle_bin(db);
        let mut e = db.entry_mut(id).ok_or(ModelError::EntryNotFound)?;
        e.move_to(bin).map_err(|_| ModelError::GroupNotFound)?;
        e.times.location_changed = Some(Times::now());
    } else {
        db.entry_mut(id).ok_or(ModelError::EntryNotFound)?.remove();
        db.deleted_objects.insert(id.uuid(), Some(Times::now()));
        db.remove_unused_attachments();
    }
    Ok(())
}

fn ensure_recycle_bin(db: &mut Database) -> GroupId {
    if let Some(bin) = db.recycle_bin() {
        return bin.id();
    }
    let mut root = db.root_mut();
    let mut bin = root.add_group();
    bin.name = "Recycle Bin".into();
    bin.set_icon_builtin(43);
    bin.enable_autotype = Some(false);
    bin.enable_searching = Some(false);
    let id = bin.id();
    db.meta.recyclebin_enabled = Some(true);
    db.meta.recyclebin_uuid = Some(id.uuid());
    db.meta.recyclebin_changed = Some(Times::now());
    id
}

pub fn add_group(db: &mut Database, parent: Option<&str>, name: &str) -> Result<String> {
    let parent = match parent {
        Some(p) => parse_group_id(p)?,
        None => db.root().id(),
    };
    let mut g = db.group_mut(parent).ok_or(ModelError::GroupNotFound)?;
    let mut child = g.add_group();
    child.name = name.to_string();
    child.set_icon_builtin(48);
    Ok(child.id().uuid().to_string())
}

pub fn rename_group(db: &mut Database, id: &str, name: &str) -> Result<()> {
    let mut g = db
        .group_mut(parse_group_id(id)?)
        .ok_or(ModelError::GroupNotFound)?;
    g.name = name.to_string();
    g.times.last_modification = Some(Times::now());
    Ok(())
}

/// Как с записями: группа уходит в корзину, из корзины удаляется насовсем вместе с содержимым,
/// а все UUID попадают в DeletedObjects.
pub fn delete_group(db: &mut Database, id: &str) -> Result<()> {
    let gid = parse_group_id(id)?;
    let g = db.group(gid).ok_or(ModelError::GroupNotFound)?;
    if g.parent().is_none() {
        return Err(ModelError::BadId(
            crate::tr!("корневую группу удалить нельзя").into(),
        ));
    }
    let is_bin = db.meta.recyclebin_uuid == Some(gid.uuid());
    if db.meta.recyclebin_enabled != Some(false) && !in_recycle_bin(db, gid) {
        let bin = ensure_recycle_bin(db);
        let mut g = db.group_mut(gid).ok_or(ModelError::GroupNotFound)?;
        g.move_to(bin).map_err(|_| ModelError::GroupNotFound)?;
        g.times.location_changed = Some(Times::now());
        return Ok(());
    }
    let mut uuids = Vec::new();
    collect_uuids(&db.group(gid).ok_or(ModelError::GroupNotFound)?, &mut uuids);
    db.group_mut(gid).ok_or(ModelError::GroupNotFound)?.remove();
    let now = Times::now();
    for u in uuids {
        db.deleted_objects.insert(u, Some(now));
    }
    if is_bin {
        db.meta.recyclebin_uuid = None;
        db.meta.recyclebin_changed = Some(now);
    }
    db.remove_unused_attachments();
    Ok(())
}

fn collect_uuids(g: &GroupRef<'_>, out: &mut Vec<Uuid>) {
    out.push(g.id().uuid());
    out.extend(g.entries().map(|e| e.id().uuid()));
    for child in g.groups() {
        collect_uuids(&child, out);
    }
}

/// Снимок текущей версии в историю до изменения вложений. Если менять вложения внутри
/// edit_tracking, keepass-rs удаляет файл из базы раньше, чем снимок со ссылкой на него попадёт в историю.
fn snapshot(db: &mut Database, id: EntryId) -> Result<()> {
    let max_history = db.meta.history_max_items.unwrap_or(10);
    let mut e = db.entry_mut(id).ok_or(ModelError::EntryNotFound)?;
    e.edit_tracking(|t| {
        let now = Times::now();
        t.times.last_modification = Some(now);
        t.times.last_access = Some(now);
    });
    trim_history(&mut e, max_history);
    db.remove_unused_attachments(); // заодно регистрирует ссылки из истории
    Ok(())
}

pub fn add_attachment(db: &mut Database, id: &str, name: &str, data: Vec<u8>) -> Result<()> {
    let id = parse_entry_id(id)?;
    snapshot(db, id)?;
    let mut e = db.entry_mut(id).ok_or(ModelError::EntryNotFound)?;
    e.remove_attachment_by_name(name);
    e.add_attachment(name.to_string(), Value::protected(data));
    db.remove_unused_attachments();
    Ok(())
}

pub fn remove_attachment(db: &mut Database, id: &str, name: &str) -> Result<()> {
    let id = parse_entry_id(id)?;
    if db
        .entry(id)
        .ok_or(ModelError::EntryNotFound)?
        .attachment_by_name(name)
        .is_none()
    {
        return Err(ModelError::AttachmentNotFound(name.into()));
    }
    snapshot(db, id)?;
    db.entry_mut(id)
        .ok_or(ModelError::EntryNotFound)?
        .remove_attachment_by_name(name);
    db.remove_unused_attachments();
    Ok(())
}

/// Вернуть версию из истории: текущая уходит в историю, как в KeePassXC.
pub fn restore_history(db: &mut Database, id: &str, index: usize) -> Result<()> {
    let eid = parse_entry_id(id)?;
    let old = {
        let e = db.entry(eid).ok_or(ModelError::EntryNotFound)?;
        let h = e.history.as_ref().ok_or(ModelError::EntryNotFound)?;
        h.get_entries()
            .get(index)
            .cloned()
            .ok_or(ModelError::EntryNotFound)?
    };
    let patch = EntryPatch {
        set: old
            .fields
            .iter()
            .map(|(k, v)| FieldSet {
                name: k.clone(),
                value: Secret::new(v.get().clone()),
                protected: Some(v.is_protected()),
            })
            .collect(),
        remove: db
            .entry(eid)
            .unwrap()
            .fields
            .keys()
            .filter(|k| !old.fields.contains_key(*k))
            .cloned()
            .collect(),
        tags: Some(old.tags.clone()),
        ..Default::default()
    };
    update_entry(db, id, &patch)
}

/// Отметить использование записи (как KeePassXC при копировании пароля).
pub fn touch(db: &mut Database, id: &str) {
    if let Ok(eid) = parse_entry_id(id)
        && let Some(mut e) = db.entry_mut(eid)
    {
        e.times.last_access = Some(Times::now());
        e.times.usage_count = Some(e.times.usage_count.unwrap_or(0) + 1);
    }
}

#[cfg(test)]
mod reorder_tests {
    use super::*;

    fn names(db: &Database) -> Vec<String> {
        groups(db).into_iter().skip(1).map(|g| g.name).collect()
    }

    #[test]
    fn group_order_survives_save() {
        let mut db = Database::new();
        let a = add_group(&mut db, None, "A").unwrap();
        let _b = add_group(&mut db, None, "B").unwrap();
        let c = add_group(&mut db, None, "C").unwrap();
        reorder_group(&mut db, &c, &a, false).unwrap();
        assert_eq!(names(&db), ["C", "A", "B"]);
        let key = keepass::DatabaseKey::new().with_password("p");
        db.config.kdf_config = crate::vault::test_kdf();
        let mut buf = vec![];
        db.save(&mut buf, key.clone()).unwrap();
        let back = Database::parse(&buf, key).unwrap();
        assert_eq!(names(&back), ["C", "A", "B"], "порядок папок после записи");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Database {
        let mut db = Database::new();
        db.root_mut().name = "Root".into();
        db.root_mut().add_group().name = "Finance".into();
        db
    }

    fn finance(db: &Database) -> String {
        db.root()
            .group_by_name("Finance")
            .unwrap()
            .id()
            .uuid()
            .to_string()
    }

    #[test]
    fn card_template_protects_secrets() {
        let mut db = db();
        let patch = EntryPatch {
            kind: Some(EntryKind::Card),
            group: Some(finance(&db)),
            set: vec![
                FieldSet::new("Title", "Visa"),
                FieldSet::new("Card Number", "4111"),
                FieldSet::new("Cardholder", "IVAN"),
            ],
            ..Default::default()
        };
        let id = create_entry(&mut db, &patch).unwrap();
        let d = detail(&db, &id, false).unwrap();
        assert_eq!(d.summary.kind, EntryKind::Card);
        assert_eq!(d.summary.group, "Finance");
        let num = d.fields.iter().find(|f| f.name == "Card Number").unwrap();
        assert!(
            num.protected && num.value.is_none(),
            "секрет скрыт без reveal"
        );
        let holder = d.fields.iter().find(|f| f.name == "Cardholder").unwrap();
        assert_eq!(holder.value.as_ref().unwrap().expose(), "IVAN");
        assert_eq!(d.fields[0].name, "Cardholder", "порядок по шаблону");
        assert!(d.history.is_empty(), "создание не пишет историю");
    }

    #[test]
    fn update_keeps_history_and_unknown_fields() {
        let mut db = db();
        let id = create_entry(
            &mut db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Password", "old"),
                    FieldSet::new("Custom", "x"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        update_entry(
            &mut db,
            &id,
            &EntryPatch {
                set: vec![FieldSet::new("Password", "new")],
                ..Default::default()
            },
        )
        .unwrap();
        let d = detail(&db, &id, true).unwrap();
        let get = |n: &str| {
            d.fields
                .iter()
                .find(|f| f.name == n)
                .and_then(|f| f.value.clone())
                .unwrap()
        };
        assert_eq!(get("Password").expose(), "new");
        assert_eq!(get("Custom").expose(), "x");
        assert_eq!(d.history.len(), 1);

        restore_history(&mut db, &id, 0).unwrap();
        assert_eq!(
            field_value(&db, &id, "Password").unwrap().unwrap().expose(),
            "old"
        );
        assert_eq!(detail(&db, &id, false).unwrap().history.len(), 2);
    }

    #[test]
    fn history_is_trimmed() {
        let mut db = db();
        db.meta.history_max_items = Some(3);
        let id = create_entry(&mut db, &EntryPatch::default()).unwrap();
        for i in 0..6 {
            update_entry(
                &mut db,
                &id,
                &EntryPatch {
                    set: vec![FieldSet::new("Password", format!("p{i}"))],
                    ..Default::default()
                },
            )
            .unwrap();
        }
        assert_eq!(detail(&db, &id, false).unwrap().history.len(), 3);
    }

    #[test]
    fn delete_goes_through_recycle_bin() {
        let mut db = db();
        let id = create_entry(&mut db, &EntryPatch::default()).unwrap();
        delete_entry(&mut db, &id).unwrap();
        let d = detail(&db, &id, false).unwrap();
        assert_eq!(d.summary.group, "Recycle Bin");
        assert!(db.deleted_objects.is_empty());

        delete_entry(&mut db, &id).unwrap();
        assert!(detail(&db, &id, false).is_err());
        assert!(
            db.deleted_objects
                .contains_key(&parse_entry_id(&id).unwrap().uuid())
        );
    }

    #[test]
    fn groups_lifecycle() {
        let mut db = db();
        let g = add_group(&mut db, None, "Work").unwrap();
        let e = create_entry(
            &mut db,
            &EntryPatch {
                group: Some(g.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        rename_group(&mut db, &g, "Job").unwrap();
        assert!(
            groups(&db)
                .iter()
                .any(|v| v.path == "Job" && v.entries == 1)
        );
        delete_group(&mut db, &g).unwrap();
        assert!(groups(&db).iter().any(|v| v.path == "Recycle Bin/Job"));
        delete_group(&mut db, &g).unwrap();
        assert!(!groups(&db).iter().any(|v| v.name == "Job"));
        assert!(
            db.deleted_objects
                .contains_key(&parse_entry_id(&e).unwrap().uuid())
        );
        assert!(
            db.deleted_objects
                .contains_key(&parse_group_id(&g).unwrap().uuid())
        );
    }

    #[test]
    fn attachments_roundtrip() {
        let mut db = db();
        let id = create_entry(&mut db, &EntryPatch::default()).unwrap();
        add_attachment(&mut db, &id, "a.txt", b"hello".to_vec()).unwrap();
        assert_eq!(attachment(&db, &id, "a.txt").unwrap(), b"hello");
        remove_attachment(&mut db, &id, "a.txt").unwrap();
        assert!(attachment(&db, &id, "a.txt").is_err());
        // старая версия с вложением осталась в истории, значит и само вложение в базе
        assert_eq!(db.num_attachments(), 1);
        let d = detail(&db, &id, false).unwrap();
        assert_eq!(d.history.len(), 2);
        let eid = parse_entry_id(&id).unwrap();
        let e = db.entry(eid).unwrap();
        let old = e.historical(0).unwrap();
        assert_eq!(
            old.attachment_by_name("a.txt").unwrap().data.get(),
            b"hello"
        );
    }

    #[test]
    fn kind_survives_save() {
        let mut db = db();
        db.config.kdf_config = crate::vault::test_kdf();
        let mut ids = vec![];
        for k in EntryKind::ALL {
            ids.push((
                k,
                create_entry(
                    &mut db,
                    &EntryPatch {
                        kind: Some(k),
                        ..Default::default()
                    },
                )
                .unwrap(),
            ));
        }
        let key = keepass::DatabaseKey::new().with_password("p");
        let mut buf = Vec::new();
        db.save(&mut buf, key.clone()).unwrap();
        let back = Database::parse(&buf, key).unwrap();
        for (k, id) in ids {
            assert_eq!(detail(&back, &id, false).unwrap().summary.kind, k);
        }
    }

    #[test]
    fn kind_detection_for_foreign_entries() {
        let mut db = db();
        let note = db
            .root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected("Notes", "text"))
            .id();
        let pk = db
            .root_mut()
            .add_entry()
            .edit(|e| e.set_protected(PASSKEY_PRIVATE_KEY, "pem"))
            .id();
        assert_eq!(kind_of(&db.entry(note).unwrap()), EntryKind::Note);
        assert_eq!(kind_of(&db.entry(pk).unwrap()), EntryKind::Passkey);
    }

    #[test]
    fn expiry_duplicate_move_tags_refs() {
        let mut db = Database::new();
        let work = add_group(&mut db, None, "Work").unwrap();
        let sub = add_group(&mut db, Some(&work), "Sub").unwrap();
        let id = create_entry(
            &mut db,
            &EntryPatch {
                tags: Some(vec!["dev".into(), "git".into()]),
                expires: Some(Some("2000-01-01".into())),
                set: vec![
                    FieldSet::new("Title", "GitHub"),
                    FieldSet::new("UserName", "octo"),
                    FieldSet::new("Password", "s3cret"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        let e = db.entry(parse_entry_id(&id).unwrap()).unwrap();
        let s = summary(&e);
        assert!(s.expired);
        assert_eq!(s.expires.as_deref(), Some("2000-01-01"));
        assert!(
            create_entry(
                &mut db,
                &EntryPatch {
                    expires: Some(Some("31.01.2027".into())),
                    ..Default::default()
                }
            )
            .is_err()
        );
        update_entry(
            &mut db,
            &id,
            &EntryPatch {
                expires: Some(None),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!summary(&db.entry(parse_entry_id(&id).unwrap()).unwrap()).expired);

        let copy = duplicate_entry(&mut db, &id).unwrap();
        let c = db.entry(parse_entry_id(&copy).unwrap()).unwrap();
        assert_eq!(c.get_title(), Some("GitHub (копия)"));
        assert_eq!(c.get_password(), Some("s3cret"));
        assert_eq!(tags(&db), [("dev".to_string(), 2), ("git".to_string(), 2)]);

        let history_before = db
            .entry(parse_entry_id(&id).unwrap())
            .unwrap()
            .history
            .as_ref()
            .map(|h| h.get_entries().len())
            .unwrap_or(0);
        move_entry(&mut db, &id, &sub).unwrap();
        let e = db.entry(parse_entry_id(&id).unwrap()).unwrap();
        assert_eq!(group_path(&db, e.parent().id()), "Work/Sub");
        assert_eq!(
            e.history
                .as_ref()
                .map(|h| h.get_entries().len())
                .unwrap_or(0),
            history_before,
            "перемещение не плодит версии"
        );
        assert!(
            move_group(&mut db, &work, &sub).is_err(),
            "в свою подпапку нельзя"
        );
        let other = add_group(&mut db, None, "Other").unwrap();
        move_group(&mut db, &sub, &other).unwrap();

        // ссылки
        let uuid = parse_entry_id(&id)
            .unwrap()
            .uuid()
            .simple()
            .to_string()
            .to_uppercase();
        let r = create_entry(
            &mut db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Title", "Ref"),
                    FieldSet::new("UserName", format!("{{REF:U@I:{uuid}}}")),
                    FieldSet::new("Password", "{REF:P@T:GitHub (копия)}"),
                    FieldSet::new("URL", "https://x/{USERNAME}"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            field_value(&db, &r, "UserName").unwrap().unwrap().expose(),
            "octo"
        );
        assert_eq!(
            field_value(&db, &r, "Password").unwrap().unwrap().expose(),
            "s3cret"
        );
        assert_eq!(
            field_value(&db, &r, "URL").unwrap().unwrap().expose(),
            "https://x/octo"
        );
        let d = detail(&db, &r, false).unwrap();
        let user = d.fields.iter().find(|f| f.name == "UserName").unwrap();
        assert!(user.reference);
        assert_eq!(user.value.as_ref().unwrap().expose(), "octo");
        let raw = detail(&db, &r, true).unwrap();
        assert!(
            raw.fields
                .iter()
                .any(|f| f.value.as_ref().unwrap().expose().starts_with("{REF:U@I:"))
        );
        // цикл не зацикливает
        let loop_id = create_entry(
            &mut db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Title", "Loop"),
                    FieldSet::new("UserName", "{USERNAME}"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            field_value(&db, &loop_id, "UserName")
                .unwrap()
                .unwrap()
                .expose(),
            "{USERNAME}"
        );
    }

    #[test]
    fn custom_icons_are_shared_and_cleaned() {
        let mut db = Database::new();
        let a = create_entry(&mut db, &EntryPatch::default()).unwrap();
        let b = create_entry(&mut db, &EntryPatch::default()).unwrap();
        let png = vec![1, 2, 3];
        set_custom_icon(&mut db, &a, png.clone()).unwrap();
        set_custom_icon(&mut db, &b, png.clone()).unwrap();
        assert_eq!(db.num_custom_icons(), 1, "одна картинка на две записи");
        let uuid = summary(&db.entry(parse_entry_id(&a).unwrap()).unwrap())
            .icon
            .unwrap();
        assert_eq!(icon_data(&db, &uuid).unwrap(), png);
        clear_icon(&mut db, &a).unwrap();
        assert_eq!(db.num_custom_icons(), 1, "у второй записи осталась");
        clear_icon(&mut db, &b).unwrap();
        assert_eq!(db.num_custom_icons(), 0, "ненужная удалена");
    }

    #[test]
    fn autotype_settings_roundtrip() {
        let mut db = Database::new();
        let id = create_entry(&mut db, &EntryPatch::default()).unwrap();
        assert_eq!(
            detail(&db, &id, false).unwrap().autotype,
            AutotypeView::default()
        );
        let want = AutotypeView {
            enabled: true,
            sequence: Some("{PASSWORD}{ENTER}".into()),
            windows: vec![("*Банк*".into(), String::new())],
        };
        update_entry(
            &mut db,
            &id,
            &EntryPatch {
                autotype: Some(want.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(detail(&db, &id, false).unwrap().autotype, want);
        assert_eq!(
            crate::autotype::candidates(&db, "Мой Банк - Firefox"),
            [(id.clone(), "{PASSWORD}{ENTER}".to_string())],
            "пустая последовательность привязки берёт свою последовательность записи"
        );
    }

    #[test]
    fn manual_order_reorder_and_tree_order() {
        let mut db = Database::new();
        let id = |db: &mut Database, t: &str| {
            create_entry(
                db,
                &EntryPatch {
                    set: vec![FieldSet::new("Title", t)],
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let (a, b, c) = (id(&mut db, "A"), id(&mut db, "B"), id(&mut db, "C"));
        let titles = |db: &Database| {
            let order = tree_order(db);
            let mut v: Vec<_> = db.iter_all_entries().collect();
            v.sort_by_key(|e| order[&e.id()]);
            v.iter()
                .map(|e| e.get(fields::TITLE).unwrap_or_default().to_string())
                .collect::<Vec<_>>()
                .join("")
        };
        assert_eq!(titles(&db), "ABC");
        reorder_entry(&mut db, &c, &a, false).unwrap();
        assert_eq!(titles(&db), "CAB");
        reorder_entry(&mut db, &c, &b, true).unwrap();
        assert_eq!(titles(&db), "ABC");
        reorder_entry(&mut db, &a, &b, true).unwrap();
        assert_eq!(titles(&db), "BAC");
        nudge_entry(&mut db, &a, -1).unwrap();
        assert_eq!(titles(&db), "ABC");
        nudge_entry(&mut db, &a, -5).unwrap();
        assert_eq!(titles(&db), "ABC");
    }

    #[test]
    fn rename_and_remove_tag_everywhere() {
        let mut db = Database::new();
        for (t, tags) in [
            ("A", vec!["work", "x"]),
            ("B", vec!["work"]),
            ("C", vec!["job"]),
        ] {
            let id = create_entry(
                &mut db,
                &EntryPatch {
                    set: vec![FieldSet::new("Title", t)],
                    ..Default::default()
                },
            )
            .unwrap();
            db.entry_mut(parse_entry_id(&id).unwrap()).unwrap().tags =
                tags.into_iter().map(String::from).collect();
        }
        assert_eq!(rename_tag(&mut db, "work", "job").unwrap(), 2);
        assert_eq!(
            tags(&db),
            vec![("job".to_string(), 3), ("x".to_string(), 1)]
        );
        assert!(rename_tag(&mut db, "job", "a,b").is_err());
        assert_eq!(remove_tag(&mut db, "job").unwrap(), 3);
        assert_eq!(tags(&db), vec![("x".to_string(), 1)]);
    }
}
