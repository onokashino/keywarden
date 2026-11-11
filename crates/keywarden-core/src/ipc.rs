//! Протокол между keywardend и клиентами (kw, UI, host).
//! Транспорт: UNIX-сокет (Linux, macOS) или именованный канал (Windows), см. `platform`;
//! одна строка JSON на запрос и одна на ответ.
//! После `Subscribe` соединение получает поток `Response::Event`.

use crate::generator::{Generate, Generated};
use crate::model::{EntryDetail, EntryPatch, EntrySummary, GroupView};
use crate::platform::{self, Conn};
use crate::secret::Secret;
use crate::totp::Code;
use crate::vault::Cipher;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Status,
    Unlock {
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        password: Option<Secret>,
        #[serde(default)]
        keyfile: Option<String>,
        /// YubiKey challenge-response: "слот" или "слот:серийный", как `keepassxc-cli -y`
        #[serde(default)]
        yubikey: Option<String>,
    },
    Lock,
    /// Создать новую базу и сразу открыть её
    Create {
        path: String,
        #[serde(default)]
        password: Option<Secret>,
        #[serde(default)]
        keyfile: Option<String>,
        #[serde(default)]
        yubikey: Option<String>,
        #[serde(default)]
        cipher: Cipher,
    },
    Search {
        query: String,
        #[serde(default = "default_limit")]
        limit: usize,
        #[serde(default)]
        filter: crate::search::Filter,
    },
    Get {
        id: String,
        #[serde(default)]
        reveal: bool,
    },
    /// Скопировать поле в буфер с автоочисткой. `field`: password, username, url, totp или имя поля.
    Copy {
        id: String,
        field: String,
    },
    /// Скопировать произвольный секрет (например, сгенерированный пароль)
    CopyText {
        value: Secret,
    },
    Totp {
        id: String,
    },
    Add {
        patch: EntryPatch,
    },
    Update {
        id: String,
        patch: EntryPatch,
    },
    Delete {
        id: String,
    },
    RestoreHistory {
        id: String,
        index: usize,
    },
    Groups,
    AddGroup {
        #[serde(default)]
        parent: Option<String>,
        name: String,
    },
    RenameGroup {
        id: String,
        name: String,
    },
    DeleteGroup {
        id: String,
    },
    AttachmentGet {
        id: String,
        name: String,
    },
    /// `data` в base64
    AttachmentAdd {
        id: String,
        name: String,
        data: String,
    },
    AttachmentRemove {
        id: String,
        name: String,
    },
    Generate {
        #[serde(default)]
        options: Generate,
    },
    /// Подписка на события: дальше по этому соединению идут только `Response::Event`
    Subscribe,
    /// Импорт приватного ключа OpenSSH в новую запись «Ключ SSH» (вложение + KeeAgent.settings)
    SshImport {
        title: String,
        /// содержимое файла ключа, base64
        key: String,
        file_name: String,
        #[serde(default)]
        passphrase: Option<Secret>,
        #[serde(default)]
        group: Option<String>,
        /// спрашивать подтверждение при каждом использовании
        #[serde(default)]
        confirm: bool,
        /// хосты для поля «Хост» (ключ под каждый хост)
        #[serde(default)]
        host: Option<String>,
    },
    /// Приватные ключи в ~/.ssh: что можно перенести в базу
    SshLocalKeys,
    /// Перенести ключи из ~/.ssh в базу (зашифрованные пропускаются); `delete`: потом удалить
    /// приватный файл с диска (.pub остаётся). Ответ: обновлённый `SshLocalKeys`.
    SshMigrate {
        paths: Vec<String>,
        #[serde(default)]
        delete: bool,
    },
    /// Новый ключ ed25519 в новой записи «Ключ SSH»; ответ `Created`, открытый ключ в заметке
    SshGenerate {
        title: String,
        /// комментарий ключа (по умолчанию название записи)
        #[serde(default)]
        comment: Option<String>,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        group: Option<String>,
        #[serde(default)]
        confirm: bool,
        /// ed25519 (по умолчанию), ecdsa (P-256) или rsa (4096)
        #[serde(default)]
        algorithm: Option<String>,
    },
    /// Записи «Сервер SSH» для `kw ssh`: адрес, ключ, готовые аргументы ssh
    SshHosts,
    /// Постучать по портам записи «Сервер SSH» с этим именем (`kw knock`, `Match exec`)
    SshKnock {
        host: String,
    },
    /// Что перенесётся из ~/.ssh/config: хосты, папки, ключи
    SshConfigHosts,
    /// Хосты из ~/.ssh/config в записи «Сервер SSH» (уже перенесённые пропускаются);
    /// `only`: только эти имена
    SshImportConfig {
        #[serde(default)]
        only: Option<Vec<String>>,
    },
    /// Импорт незашифрованного JSON-экспорта Bitwarden
    ImportBitwarden {
        json: String,
    },
    /// Сообщение расширения браузера (keywarden-ext::protocol::Outer), host передаёт его как есть
    Browser {
        message: serde_json::Value,
    },
    /// Сменить мастер-пароль, файл-ключ или YubiKey. Текущий ключ подтверждается заново:
    /// открытая база на оставленном без присмотра экране не должна позволять её перехватить.
    ChangeKey {
        current: KeySpec,
        new: KeySpec,
    },
    /// Новый файл-ключ (формат KeePassXC 2.0); существующий файл не затирается
    GenerateKeyfile {
        path: String,
    },
    GetSettings,
    SetSettings {
        settings: crate::settings::DbSettings,
    },
    /// Параметры Argon2id под ~1 с на этом компьютере (не применяются, только расчёт)
    TuneKdf,
    /// Копия базы другим ключом в новый файл
    SaveCopy {
        path: String,
        key: KeySpec,
    },
    /// Экспорт в CSV (формат KeePassXC): пароли открытым текстом, файл получает права 0600
    ExportCsv {
        path: String,
    },
    /// Импорт файла в новую папку
    ImportFile {
        path: String,
        format: ImportFormat,
        /// для KeePass: ключ той базы
        #[serde(default)]
        key: Option<KeySpec>,
    },
    /// Слить с другой копией этой же базы (например, старой с телефона): по UUID и времени правки
    MergeFile {
        path: String,
        key: KeySpec,
    },
    /// Копия записи рядом, « (копия)» в названии
    Duplicate {
        id: String,
    },
    /// Переместить запись в папку (без новой версии в истории)
    MoveEntry {
        id: String,
        group: String,
    },
    /// Переместить папку внутрь другой
    MoveGroup {
        id: String,
        parent: String,
    },
    /// Все теги с числом записей
    Tags,
    /// Мастер 2FA: что получится из введённого (секрет, otpauth://, KeeOtp), без сохранения
    OtpPreview {
        input: Secret,
        #[serde(default)]
        issuer: String,
        #[serde(default)]
        account: String,
    },
    /// Задать 2FA записи (старые поля TOTP Seed/Settings убираются)
    SetOtp {
        id: String,
        value: Secret,
    },
    /// Ссылка otpauth:// записи для QR-кода (перенос на телефон); содержит секрет
    OtpUri {
        id: String,
    },
    /// Распознать QR-код: из картинки по пути или из буфера обмена (скриншот области)
    OtpScan {
        #[serde(default)]
        path: Option<String>,
    },
    /// Все коды 2FA в бэкап 2FAS (.2fas): секреты открытым текстом, файл 0600
    ExportTwoFas {
        path: String,
    },
    /// Отчёт о паролях; `breaches`: проверить утечки в Have I Been Pwned (сеть, k-анонимность)
    Health {
        #[serde(default)]
        breaches: bool,
    },
    /// Исключить запись из отчётов (или вернуть), как в KeePassXC
    HealthExclude {
        id: String,
        exclude: bool,
    },
    /// Скачать favicon сайта записи (https, по нажатию) и сохранить как иконку записи
    FetchFavicon {
        id: String,
    },
    /// Убрать собственную иконку записи
    ClearIcon {
        id: String,
    },
    /// PNG собственной иконки (base64)
    IconData {
        uuid: String,
    },
    /// Перенести секреты из текущей связки ключей (gnome-keyring, KeePassXC) в папку Secret Service
    SecretsMigrate,
    /// Состояние связки ключей; `enable`: включить или выключить Keywarden как связку
    /// (запоминается в конфиге, действует после перезапуска keywardend)
    SecretService {
        #[serde(default)]
        enable: Option<bool>,
    },
    /// Автоввод в активное окно niri: `id` выбранная запись (иначе подбор по заголовку окна);
    /// `window` заголовок вместо niri (проверка), `sequence` своя последовательность
    AutoType {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        window: Option<String>,
        #[serde(default)]
        sequence: Option<String>,
    },
    /// Разблокировать PIN-кодом: работает, если PIN задан и после полной разблокировки
    /// не прошёл срок; три неверных PIN подряд требуют полного ключа
    QuickUnlock {
        pin: Secret,
    },
    /// Задать PIN (`pin`: Some) или убрать его. Задать можно только с полным ключом базы.
    SetPin {
        #[serde(default)]
        pin: Option<Secret>,
        #[serde(default)]
        key: Option<KeySpec>,
    },
    /// Настройки этого компьютера (конфиг демона); `set`: сохранить
    Prefs {
        #[serde(default)]
        set: Option<Prefs>,
    },
    /// Ручной порядок: поставить запись перед/после другой (при необходимости с переездом в её папку)
    ReorderEntry {
        id: String,
        target: String,
        #[serde(default)]
        after: bool,
    },
    /// То же для папок
    ReorderGroup {
        id: String,
        target: String,
        #[serde(default)]
        after: bool,
    },
    /// Переименовать тег во всех записях
    RenameTag {
        from: String,
        to: String,
    },
    /// Снять тег со всех записей
    DeleteTag {
        tag: String,
    },
    /// Сдвинуть запись внутри её папки на delta позиций
    NudgeEntry {
        id: String,
        delta: isize,
    },
    /// Повторное подтверждение при открытой базе: PIN или мастер-пароль открывают
    /// поля криптокошельков на 2 минуты
    Elevate {
        #[serde(default)]
        pin: Option<Secret>,
        #[serde(default)]
        key: Option<KeySpec>,
    },
    /// Резервные копии базы, новые сверху
    Backups,
    /// Заменить содержимое базы копией (текущее состояние перед этим само уходит в копии)
    RestoreBackup {
        name: String,
    },
    /// Журнал синхронизаций и входящая версия, которая ждёт решения
    SyncJournal,
    /// Решение по входящей версии с массовым удалением: принять или отклонить удаления
    SyncDecide {
        accept: bool,
    },
    /// Отменить слияние из журнала: затронутые записи возвращаются как новая правка
    SyncRevert {
        id: u64,
    },
    /// Переместить файл открытой базы в каталог (например, папку Syncthing)
    MoveDatabase {
        dir: String,
    },
}

/// Программа синхронизации, в чьей папке лежит база.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncFolder {
    /// syncthing, nextcloud, dropbox
    pub kind: String,
    pub root: String,
}

/// Строка журнала синхронизаций.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncRecord {
    pub id: u64,
    /// «2026-11-09 14:03»
    pub when: String,
    /// откуда пришло: «файл базы», «конфликтная копия …»
    pub source: String,
    pub summary: String,
    /// applied, accepted, rejected, reverted
    pub status: String,
    /// зашифрованный снимок базы до слияния (имя в каталоге копий): по нему делается отмена
    #[serde(default)]
    pub snapshot: Option<String>,
}

/// Входящая версия на паузе: она убирает слишком много записей.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncHeld {
    pub source: String,
    pub summary: String,
    pub removed: usize,
    pub live: usize,
}

/// Приватный ключ в ~/.ssh (перенос в базу).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalSshKey {
    pub path: String,
    /// комментарий ключа (часто почта или user@host)
    pub comment: String,
    pub fingerprint: String,
    /// «ed25519», «ecdsa», «rsa 3072»
    #[serde(default)]
    pub algorithm: String,
    /// такой ключ уже есть в базе
    pub in_vault: bool,
    /// зашифрован паролем: переносится только вручную (Новый ключ SSH, Импортировать)
    pub encrypted: bool,
}

/// Хост из ~/.ssh/config перед переносом в базу.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfigHostPreview {
    pub alias: String,
    /// user@host:port
    pub address: String,
    /// папка в базе: SSH/prod
    pub folder: String,
    /// IdentityFile как записан
    pub identity: Option<String>,
    /// запись ключа в базе, которой он станет
    pub key: Option<String>,
    pub in_vault: bool,
}

/// Запись «Сервер SSH» для выбора в `kw ssh`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshHost {
    pub id: String,
    pub title: String,
    /// имя для `ssh имя`
    pub alias: String,
    /// путь группы без корня, через "/"
    pub group: String,
    /// user@host:port
    pub address: String,
    /// название записи ключа
    pub key: Option<String>,
    pub proxy: Option<String>,
    /// «8080 → localhost:80»
    pub forwards: Vec<String>,
    pub knock: bool,
    /// аргументы ssh: `[имя]`, когда хосты базы прописаны в ~/.ssh/keywarden/config,
    /// иначе всё явно (-p, -J, -L, -o)
    pub args: Vec<String>,
    /// стучать перед ssh самим: конфиг Keywarden выключен и `Match exec` не сработает
    pub knock_first: bool,
}

/// Настройки этого компьютера: не в базе, а в конфиге демона.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Prefs {
    /// блокировка после N минут простоя, 0 = выключено
    pub autolock_minutes: u64,
    pub lock_on_screen_lock: bool,
    pub lock_on_sleep: bool,
    pub clipboard_clear_seconds: u64,
    pub backups_keep: usize,
    /// задан ли PIN (меняется через `SetPin`, при сохранении игнорируется)
    pub pin_set: bool,
    /// сколько часов после полной разблокировки работает PIN
    pub pin_hours: u64,
    /// уведомлять об истёкших и истекающих записях
    pub notify_expiry: bool,
    /// раз в неделю проверять пароли в Have I Been Pwned и уведомлять о новых утечках
    pub notify_breaches: bool,
    /// обозреватели блоков: сеть (btc, eth…) -> шаблон ссылки с {address}
    pub explorers: std::collections::BTreeMap<String, String>,
    /// следить за файлом базы и сразу сливать изменения от Syncthing, Nextcloud, Dropbox
    pub sync_watch: bool,
    /// входящая версия, которая убирает больше 5 записей или 10% базы, ждёт подтверждения
    pub sync_guard: bool,
    /// порядок типов в боковой панели (login, card…); пусто: стандартный
    pub kind_order: Vec<String>,
    /// SSH-агент отдаёт ключи из записей
    pub ssh_agent: bool,
    /// база заблокирована, а ssh просит ключ: показать окно разблокировки
    pub ssh_unlock_prompt: bool,
    /// ключ под каждый хост через ~/.ssh/keywarden/config
    pub ssh_host_config: bool,
    /// лаунчер: Enter на ключе SSH с хостом открывает терминал с ssh
    pub ssh_connect: bool,
    /// значок в трее
    pub tray: bool,
    /// свой терминал (ssh дописывается в конец); пусто: найти самим
    pub terminal: Vec<String>,
    /// раз в сутки спрашивать GitHub Releases о новой версии (наружу уходит только этот запрос)
    pub check_updates: bool,
    /// вышедшая новая версия, если есть (тег vX.Y.Z; при сохранении игнорируется)
    pub update_available: Option<String>,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            autolock_minutes: 15,
            lock_on_screen_lock: true,
            lock_on_sleep: true,
            clipboard_clear_seconds: 30,
            backups_keep: 10,
            pin_set: false,
            pin_hours: 24,
            notify_expiry: true,
            notify_breaches: false,
            explorers: crate::wallet::default_explorers(),
            sync_watch: true,
            sync_guard: true,
            kind_order: vec![],
            ssh_agent: true,
            ssh_unlock_prompt: true,
            ssh_host_config: false,
            ssh_connect: true,
            tray: true,
            terminal: vec![],
            check_updates: false,
            update_available: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BackupInfo {
    pub name: String,
    /// «2026-11-09 14:03»
    pub when: String,
    pub size: u64,
    /// backup, conflict (копия Syncthing), unsaved (несохранённые правки при блокировке)
    pub kind: String,
}

/// Ключ базы в запросе: пароль, файл-ключ, YubiKey ("2" или "2:серийный").
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeySpec {
    #[serde(default)]
    pub password: Option<Secret>,
    #[serde(default)]
    pub keyfile: Option<String>,
    #[serde(default)]
    pub yubikey: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    /// CSV KeePassXC, Chrome, Firefox, Bitwarden, 1Password, Proton Pass
    Csv,
    /// другая база .kdbx или старая .kdb
    Keepass,
    /// JSON-экспорт Bitwarden
    Bitwarden,
    /// бэкап 2FAS (.2fas) без пароля
    TwoFas,
}

fn default_limit() -> usize {
    50
}

impl Request {
    /// Имя команды для логов: сам запрос может содержать секреты.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Status => "status",
            Self::Unlock { .. } => "unlock",
            Self::Lock => "lock",
            Self::Create { .. } => "create",
            Self::Search { .. } => "search",
            Self::Get { .. } => "get",
            Self::Copy { .. } => "copy",
            Self::CopyText { .. } => "copy_text",
            Self::Totp { .. } => "totp",
            Self::Add { .. } => "add",
            Self::Update { .. } => "update",
            Self::Delete { .. } => "delete",
            Self::RestoreHistory { .. } => "restore_history",
            Self::Groups => "groups",
            Self::AddGroup { .. } => "add_group",
            Self::RenameGroup { .. } => "rename_group",
            Self::DeleteGroup { .. } => "delete_group",
            Self::AttachmentGet { .. } => "attachment_get",
            Self::AttachmentAdd { .. } => "attachment_add",
            Self::AttachmentRemove { .. } => "attachment_remove",
            Self::Generate { .. } => "generate",
            Self::Subscribe => "subscribe",
            Self::Browser { .. } => "browser",
            Self::SshImport { .. } => "ssh_import",
            Self::SshGenerate { .. } => "ssh_generate",
            Self::SshLocalKeys => "ssh_local_keys",
            Self::SshMigrate { .. } => "ssh_migrate",
            Self::SshHosts => "ssh_hosts",
            Self::SshKnock { .. } => "ssh_knock",
            Self::SshConfigHosts => "ssh_config_hosts",
            Self::SshImportConfig { .. } => "ssh_import_config",
            Self::ImportBitwarden { .. } => "import_bitwarden",
            Self::ChangeKey { .. } => "change_key",
            Self::GenerateKeyfile { .. } => "generate_keyfile",
            Self::GetSettings => "get_settings",
            Self::SetSettings { .. } => "set_settings",
            Self::TuneKdf => "tune_kdf",
            Self::SaveCopy { .. } => "save_copy",
            Self::ExportCsv { .. } => "export_csv",
            Self::ImportFile { .. } => "import_file",
            Self::MergeFile { .. } => "merge_file",
            Self::Duplicate { .. } => "duplicate",
            Self::MoveEntry { .. } => "move_entry",
            Self::MoveGroup { .. } => "move_group",
            Self::Tags => "tags",
            Self::OtpPreview { .. } => "otp_preview",
            Self::SetOtp { .. } => "set_otp",
            Self::OtpUri { .. } => "otp_uri",
            Self::OtpScan { .. } => "otp_scan",
            Self::ExportTwoFas { .. } => "export_2fas",
            Self::Health { .. } => "health",
            Self::HealthExclude { .. } => "health_exclude",
            Self::FetchFavicon { .. } => "fetch_favicon",
            Self::ClearIcon { .. } => "clear_icon",
            Self::IconData { .. } => "icon_data",
            Self::SecretsMigrate => "secrets_migrate",
            Self::SecretService { .. } => "secret_service",
            Self::AutoType { .. } => "autotype",
            Self::QuickUnlock { .. } => "quick_unlock",
            Self::SetPin { .. } => "set_pin",
            Self::Prefs { .. } => "prefs",
            Self::Backups => "backups",
            Self::Elevate { .. } => "elevate",
            Self::ReorderEntry { .. } => "reorder_entry",
            Self::ReorderGroup { .. } => "reorder_group",
            Self::NudgeEntry { .. } => "nudge_entry",
            Self::RenameTag { .. } => "rename_tag",
            Self::DeleteTag { .. } => "delete_tag",
            Self::RestoreBackup { .. } => "restore_backup",
            Self::SyncJournal => "sync_journal",
            Self::SyncDecide { .. } => "sync_decide",
            Self::SyncRevert { .. } => "sync_revert",
            Self::MoveDatabase { .. } => "move_database",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusInfo {
    pub locked: bool,
    pub path: Option<String>,
    pub entries: usize,
    /// база из конфига, которую предложат открыть
    pub default_path: Option<String>,
    pub keyfile: Option<String>,
    #[serde(default)]
    pub yubikey: Option<String>,
    /// можно разблокировать PIN-кодом прямо сейчас
    #[serde(default)]
    pub quick_unlock: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Locked,
    WrongKey,
    NotFound,
    Conflict,
    Invalid,
    Internal,
    /// нужно повторное подтверждение (PIN или мастер-пароль): поля криптокошелька, экспорт
    NeedsAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Locked,
    Unlocked,
    /// записи изменились (правка, слияние с диска)
    Changed,
    Saved,
    SaveFailed {
        message: String,
    },
    /// файл слит с изменениями снаружи (Syncthing)
    Merged {
        message: String,
    },
    /// входящая версия убирает слишком много записей и ждёт решения
    SyncHeld {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Pong {
        version: String,
    },
    Status(StatusInfo),
    Ok,
    Entries {
        entries: Vec<EntrySummary>,
    },
    Entry {
        entry: Box<EntryDetail>,
    },
    Totp {
        code: Code,
    },
    Created {
        id: String,
    },
    Groups {
        groups: Vec<GroupView>,
    },
    Attachment {
        data: String,
    },
    Generated {
        generated: Generated,
    },
    Event(Event),
    Imported {
        report: crate::bitwarden::ImportReport,
    },
    Settings {
        settings: crate::settings::DbSettings,
    },
    Merged {
        summary: String,
    },
    Tags {
        tags: Vec<(String, usize)>,
    },
    OtpPreview {
        uri: Secret,
        code: Code,
    },
    OtpUri {
        uri: Secret,
    },
    OtpScanned {
        text: Secret,
    },
    Health {
        report: crate::health::Report,
    },
    SshLocalKeys {
        keys: Vec<LocalSshKey>,
    },
    SshHosts {
        hosts: Vec<SshHost>,
    },
    SshConfigHosts {
        hosts: Vec<ConfigHostPreview>,
    },
    SshImported {
        added: usize,
        skipped: usize,
    },
    Prefs {
        // в коробке: иначе Response разрастается, а он лежит в каждом Result демона
        prefs: Box<Prefs>,
    },
    Backups {
        backups: Vec<BackupInfo>,
    },
    SyncJournal {
        records: Vec<SyncRecord>,
        held: Option<Box<SyncHeld>>,
        #[serde(default)]
        db_path: Option<String>,
        #[serde(default)]
        folder: Option<Box<SyncFolder>>,
    },
    IconData {
        data: String,
    },
    SecretsMigrated {
        items: usize,
        skipped: usize,
    },
    /// к окну подходит несколько записей: выбрать в лаунчере
    AutoTypeChoices {
        window: String,
        entries: Vec<EntrySummary>,
    },
    SecretService {
        /// включено в конфиге
        enabled: bool,
        /// кто сейчас держит org.freedesktop.secrets (путь к программе), если кто-то держит
        owner: Option<String>,
        /// это сам keywardend
        active: bool,
        group: String,
    },
    /// ответ для расширения (keywarden-ext::protocol::OuterReply)
    Browser {
        reply: serde_json::Value,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

impl Response {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Каталог демона: сокеты (кроме Windows) и короткоживущие файлы, см. `platform::runtime_base`.
pub fn runtime_dir() -> PathBuf {
    runtime_dir_for(profile().as_deref())
}

// --- профили: несколько баз, по демону на каждую ---

/// Текущий профиль процесса (переключатель баз в окне); `None`: основная база.
static PROFILE: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Имя профиля: латиница, цифры, `-` и `_`, до 32 символов; "default" значит основную базу.
pub fn valid_profile(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn set_profile(name: Option<&str>) -> Result<(), String> {
    let name = name.filter(|n| *n != "default");
    if let Some(n) = name
        && !valid_profile(n)
    {
        return Err(crate::tr!("имя базы «{n}»: латиница, цифры, - и _", n = n));
    }
    *PROFILE.write().unwrap_or_else(|e| e.into_inner()) = name.map(str::to_string);
    Ok(())
}

/// Профиль процесса: заданный `set_profile`, иначе из `KEYWARDEN_PROFILE`.
pub fn profile() -> Option<String> {
    PROFILE
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
        .or_else(|| std::env::var("KEYWARDEN_PROFILE").ok())
        .filter(|p| !p.is_empty() && p != "default" && valid_profile(p))
}

pub fn runtime_dir_for(profile: Option<&str>) -> PathBuf {
    let base = platform::runtime_base();
    match profile.filter(|p| *p != "default") {
        Some(p) => base.join("profiles").join(p),
        None => base,
    }
}

pub fn config_dir() -> PathBuf {
    platform::config_dir()
}

/// Конфиг базы: основная в `config.toml`, остальные в `profiles/<имя>.toml`.
pub fn config_file_for(profile: Option<&str>) -> PathBuf {
    match profile.filter(|p| *p != "default") {
        Some(p) => config_dir().join("profiles").join(format!("{p}.toml")),
        None => config_dir().join("config.toml"),
    }
}

/// Добавить базу: конфиг `profiles/<имя>.toml` с путём к файлу. Существующий не затирается.
pub fn add_profile(name: &str, db: &std::path::Path) -> Result<PathBuf, String> {
    if !valid_profile(name) || name == "default" {
        return Err(crate::tr!("имя базы: латиница, цифры, - и _ (не default)").into());
    }
    let file = config_file_for(Some(name));
    if file.exists() {
        return Err(crate::tr!("база «{name}» уже есть", name = name));
    }
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let db = std::path::absolute(db).unwrap_or_else(|_| db.to_path_buf());
    let line = format!("database = {:?}\n", db.display().to_string());
    std::fs::write(&file, line).map_err(|e| e.to_string())?;
    Ok(file)
}

/// Все базы: основная ("default") и профили из `profiles/*.toml`.
pub fn profiles() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(config_dir().join("profiles"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let p = e.path();
            (p.extension()? == "toml")
                .then(|| p.file_stem()?.to_str().map(str::to_string))
                .flatten()
        })
        .filter(|n| valid_profile(n) && n != "default")
        .collect();
    v.sort();
    v.insert(0, "default".into());
    v
}

/// Точка подключения `name` ("daemon", "api", "ssh") демона базы `profile`.
pub fn endpoint_for(profile: Option<&str>, name: &str) -> PathBuf {
    let profile = profile.filter(|p| *p != "default");
    platform::endpoint(&runtime_dir_for(profile), profile, name)
}

pub fn endpoint(name: &str) -> PathBuf {
    endpoint_for(profile().as_deref(), name)
}

pub fn daemon_socket() -> PathBuf {
    endpoint("daemon")
}

/// Синхронный клиент. Одно соединение можно использовать для нескольких запросов.
pub struct Client {
    reader: BufReader<Conn>,
}

impl Client {
    pub fn connect() -> io::Result<Self> {
        Self::connect_path(&daemon_socket())
    }

    /// Демон другой базы (лаунчер ищет по всем открытым).
    pub fn connect_to(profile: Option<&str>) -> io::Result<Self> {
        Self::connect_path(&endpoint_for(profile, "daemon"))
    }

    fn connect_path(path: &std::path::Path) -> io::Result<Self> {
        Ok(Self {
            reader: BufReader::new(platform::connect(path)?),
        })
    }

    pub fn call(&mut self, req: &Request) -> io::Result<Response> {
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        self.reader.get_mut().write_all(line.as_bytes())?;
        self.read()
    }

    /// Следующий ответ или событие (после Subscribe).
    pub fn read(&mut self) -> io::Result<Response> {
        let mut buf = String::new();
        if self.reader.read_line(&mut buf)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                crate::tr!("keywardend закрыл соединение"),
            ));
        }
        Ok(serde_json::from_str(&buf)?)
    }

    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        platform::set_read_timeout(self.reader.get_ref(), t)
    }
}

/// Один запрос по новому соединению.
pub fn call(req: &Request) -> io::Result<Response> {
    Client::connect()?.call(req)
}

/// Отправить и не ждать ответа (лаунчер просит автоввод и сразу закрывается).
pub fn send_to(profile: Option<&str>, req: &Request) -> io::Result<()> {
    let mut c = match profile {
        Some(p) => Client::connect_to(Some(p))?,
        None => Client::connect()?,
    };
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    c.reader.get_mut().write_all(line.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_is_stable() {
        assert_eq!(
            serde_json::to_string(&Request::Ping).unwrap(),
            r#"{"cmd":"ping"}"#
        );
        let r: Request = serde_json::from_str(r#"{"cmd":"search","query":"git"}"#).unwrap();
        assert!(matches!(r, Request::Search { limit: 50, .. }));
        let e = serde_json::to_string(&Response::Event(Event::Locked)).unwrap();
        assert_eq!(e, r#"{"kind":"event","event":"locked"}"#);
    }

    #[test]
    fn secrets_not_in_debug() {
        let r = Request::Unlock {
            path: None,
            password: Some("hunter2".into()),
            keyfile: None,
            yubikey: None,
        };
        assert!(!format!("{r:?}").contains("hunter2"));
    }

    #[test]
    fn profile_paths() {
        assert!(valid_profile("work-2"));
        assert!(!valid_profile("../etc"));
        assert!(!valid_profile(""));
        let run = platform::runtime_base();
        assert_eq!(
            runtime_dir_for(Some("work")),
            run.join("profiles").join("work")
        );
        assert_eq!(runtime_dir_for(Some("default")), run);
        let conf = config_dir();
        assert_eq!(
            config_file_for(Some("work")),
            conf.join("profiles").join("work.toml")
        );
        assert_eq!(config_file_for(None), conf.join("config.toml"));
        assert!(set_profile(Some("../x")).is_err());
    }
}
