//! kw: командная строка Keywarden. Всё делает keywardend, kw только спрашивает и печатает.

mod browser;
mod ssh_tui;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand, ValueEnum};
use data_encoding::BASE64;
use keywarden_core::generator::{Generate, PassphraseOptions, PasswordOptions};
use keywarden_core::ipc::{Client, ErrorCode, ImportFormat, KeySpec, Request, Response};
use keywarden_core::model::{
    EntryDetail, EntryKind, EntryPatch, EntrySummary, FieldSet, GroupView,
};
use keywarden_core::secret::Secret;
use keywarden_core::vault::Cipher;
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;

use keywarden_core::tr;

#[derive(Parser)]
#[command(
    name = "kw",
    version,
    about = tr!("Keywarden: менеджер паролей поверх KeePass")
)]
struct Cli {
    #[arg(help = tr!("база (профиль): по умолчанию основная; также KEYWARDEN_PROFILE"))]
    #[arg(long, global = true)]
    profile: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum WalletCmd {
    #[command(about = tr!("Сохранённые адреса: название, подпись, сеть, адрес (через табуляцию)"))]
    Addresses {
        #[arg(default_value = "")]
        query: String,
    },
}

#[derive(Subcommand)]
enum SyncCmd {
    #[command(about = tr!("Журнал синхронизаций и версия, которая ждёт решения"))]
    Status,
    #[command(about = tr!("Принять удаления из версии на паузе"))]
    Accept,
    #[command(about = tr!("Отклонить удаления: записи останутся и вернутся на другие устройства"))]
    Reject,
    #[command(about = tr!("Отменить слияние по номеру из журнала"))]
    Revert { id: u64 },
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = tr!("Все базы (профили) и их состояние"))]
    Profiles,
    #[command(about = tr!("Добавить базу: профиль ИМЯ с файлом ПУТЬ; запуск: systemctl --user start keywardend@ИМЯ"))]
    ProfileAdd { name: String, db: PathBuf },
    #[command(about = tr!("Открыть базу (по умолчанию из конфига)"))]
    Unlock {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, short = 'k')]
        keyfile: Option<PathBuf>,
        #[arg(help = tr!("база открывается только файлом-ключом"))]
        #[arg(long)]
        no_password: bool,
        #[arg(help = tr!("пароль одной строкой со stdin (для скриптов)"))]
        #[arg(long)]
        password_stdin: bool,
        #[arg(help = tr!("YubiKey challenge-response: слот[:серийный], как keepassxc-cli -y"))]
        #[arg(long, short = 'y', value_name = "SLOT[:SERIAL]")]
        yubikey: Option<String>,
        #[arg(help = tr!("PIN вместо мастер-пароля (если задан через `kw pin` и не истёк срок)"))]
        #[arg(long, conflicts_with_all = ["no_password", "keyfile", "yubikey"])]
        pin: bool,
    },
    #[command(about = tr!("Задать PIN быстрой разблокировки (нужен мастер-пароль) или убрать его"))]
    Pin {
        #[arg(long)]
        remove: bool,
        #[arg(help = tr!("две строки со stdin: мастер-пароль, затем PIN"))]
        #[arg(long)]
        stdin: bool,
    },
    #[command(about = tr!("Заблокировать базу"))]
    Lock,
    #[command(about = tr!("Состояние демона"))]
    Status,
    #[command(about = tr!("Проверить, что демон отвечает"))]
    Ping,
    #[command(about = tr!("Создать новую базу KDBX 4 (Argon2id, 256 МиБ, ~1 с на разблокировку)"))]
    New {
        path: PathBuf,
        #[arg(long, short = 'k')]
        keyfile: Option<PathBuf>,
        #[arg(long, value_enum, default_value = "aes256")]
        cipher: CipherArg,
        #[arg(long)]
        no_password: bool,
        #[arg(help = tr!("YubiKey challenge-response: слот[:серийный]"))]
        #[arg(long, short = 'y', value_name = "SLOT[:SERIAL]")]
        yubikey: Option<String>,
    },
    #[command(about = tr!("Подключённые YubiKey"))]
    Yubikeys,
    #[command(about = tr!("Найти записи (нечёткий поиск по названию, логину, адресу)"))]
    Search {
        #[arg(default_value = "")]
        query: String,
        #[arg(long, short = 'n', default_value_t = 30)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    #[command(about = tr!("Синхронизация: журнал, решение по массовому удалению, отмена слияния"))]
    Sync {
        #[command(subcommand)]
        cmd: SyncCmd,
    },
    #[command(about = tr!("Адреса криптокошельков (публичные; фразы и ключи из терминала не выдаются)"))]
    Wallet {
        #[command(subcommand)]
        cmd: WalletCmd,
    },
    #[command(about = tr!("Показать запись"))]
    Show {
        query: String,
        #[arg(help = tr!("показать значения защищённых полей"))]
        #[arg(long, short = 'r')]
        reveal: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Скопировать поле в буфер (очистится через 30 с)"))]
    Copy {
        query: String,
        #[arg(help = tr!("password, username, url, totp, notes или имя своего поля"))]
        #[arg(long, short = 'f', default_value = "password")]
        field: String,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Код 2FA"))]
    Totp {
        query: String,
        #[arg(long, short = 'c')]
        copy: bool,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Добавить запись"))]
    Add {
        #[arg(long = "type", short = 't', value_enum, default_value = "login")]
        kind: KindArg,
        #[arg(long)]
        title: String,
        #[command(flatten)]
        edit: EditArgs,
    },
    #[command(about = tr!("Изменить запись (старая версия уходит в историю)"))]
    Edit {
        query: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long = "type", value_enum)]
        kind: Option<KindArg>,
        #[command(flatten)]
        edit: EditArgs,
        #[arg(help = tr!("удалить поле"))]
        #[arg(long = "remove-field", value_name = "NAME")]
        remove: Vec<String>,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Проверка паролей: слабые, повторы, старые, истёкшие; --breaches: утечки (Have I Been Pwned)"))]
    Health {
        #[arg(help = tr!("проверить утечки: уходят только первые 5 символов SHA-1 каждого пароля"))]
        #[arg(long)]
        breaches: bool,
    },
    #[command(about = tr!("2FA: задать, распознать QR, показать QR для телефона"))]
    #[command(subcommand)]
    Otp(OtpCmd),
    #[command(about = tr!("Автоввод в активное окно niri (горячая клавиша): запись подбирается по заголовку окна, при нескольких открывается лаунчер для выбора"))]
    Autotype {
        #[arg(help = tr!("конкретная запись вместо подбора"))]
        query: Option<String>,
        #[arg(help = tr!("заголовок окна вместо niri (проверка)"))]
        #[arg(long)]
        window: Option<String>,
        #[arg(help = tr!("своя последовательность, например \"{USERNAME}{TAB}{PASSWORD}{ENTER}\""))]
        #[arg(long)]
        sequence: Option<String>,
    },
    #[command(about = tr!("Перенести секреты из текущей связки ключей (gnome-keyring) в Keywarden"))]
    SecretsImport,
    #[command(about = tr!("Иконка сайта записи: скачать favicon (один запрос к сайту) или убрать (--clear)"))]
    Icon {
        query: String,
        #[arg(long)]
        clear: bool,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Дублировать запись (копия рядом, « (копия)» в названии)"))]
    Dup {
        query: String,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Переместить запись в группу (путь Finance/Cards, / для корня)"))]
    Mv {
        query: String,
        group: String,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Все теги с числом записей"))]
    Tags,
    #[command(about = tr!("Удалить запись (сначала в корзину, из корзины насовсем)"))]
    Rm {
        query: String,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Группы (папки)"))]
    Groups,
    #[command(about = tr!("Создать группу: kw mkgroup Finance/Cards"))]
    Mkgroup { path: String },
    #[command(about = tr!("Сгенерировать пароль или парольную фразу"))]
    Generate {
        #[arg(long, short = 'l', default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(help = tr!("парольная фраза из словаря EFF"))]
        #[arg(long, short = 'p')]
        passphrase: bool,
        #[arg(long, short = 'w', default_value_t = 6)]
        words: usize,
        #[arg(long, short = 'c')]
        copy: bool,
    },
    #[command(about = tr!("Приложить файл к записи"))]
    Attach {
        query: String,
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Сохранить вложение на диск"))]
    Attachment {
        query: String,
        name: String,
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Импортировать приватный ключ OpenSSH в запись «Ключ SSH» (пароль ключа спросит, если он есть)"))]
    SshImport {
        file: PathBuf,
        #[arg(long)]
        title: Option<String>,
        #[arg(long, short = 'g')]
        group: Option<String>,
        #[arg(help = tr!("спрашивать подтверждение при каждом использовании ключа"))]
        #[arg(long)]
        confirm: bool,
        #[arg(help = tr!("пароль ключа одной строкой со stdin (для скриптов)"))]
        #[arg(long)]
        passphrase_stdin: bool,
        #[arg(long, help = tr!("хосты для этого ключа: github.com, git@host, ssh://host:22"))]
        host: Option<String>,
    },
    #[command(about = tr!("Подписывать коммиты и теги git SSH-ключом из записи (через агент Keywarden)"))]
    SshGitSign {
        #[arg(help = tr!("запись «Ключ SSH»; не нужна с --off"))]
        query: Option<String>,
        #[arg(long, help = tr!("перестать подписывать"))]
        off: bool,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Ключи из ~/.ssh: показать и перенести в базу"))]
    SshMigrate {
        #[arg(long, help = tr!("перенести все новые незашифрованные ключи в базу"))]
        import: bool,
        #[arg(long, requires = "import", help = tr!("после переноса удалить приватные файлы с диска (.pub остаются)"))]
        delete: bool,
    },
    #[command(about = tr!("Создать новый ключ в записи «Ключ SSH» и показать открытый ключ"))]
    SshGenerate {
        #[arg(long)]
        title: String,
        #[arg(long = "type", short = 't', default_value = "ed25519", value_parser = ["ed25519", "ecdsa", "rsa"], help = tr!("алгоритм: ed25519 (рекомендуется), ecdsa (P-256) или rsa (4096, для старых серверов)"))]
        algorithm: String,
        #[arg(long, help = tr!("хосты для этого ключа: github.com, git@host, ssh://host:22"))]
        host: Option<String>,
        #[arg(long, help = tr!("комментарий ключа (по умолчанию название)"))]
        comment: Option<String>,
        #[arg(long, short = 'g')]
        group: Option<String>,
        #[arg(long, help = tr!("спрашивать подтверждение при каждом использовании ключа"))]
        confirm: bool,
    },
    #[command(about = tr!("Импорт из Bitwarden (незашифрованный JSON-экспорт) в группу «Bitwarden»"))]
    ImportBitwarden { file: PathBuf },
    #[command(about = tr!("Сменить мастер-пароль, файл-ключ или YubiKey (текущий ключ спрашивается заново)"))]
    Passwd {
        #[arg(help = tr!("новый файл-ключ (создать: kw keyfile ПУТЬ)"))]
        #[arg(long, short = 'k')]
        keyfile: Option<PathBuf>,
        #[arg(help = tr!("новый YubiKey: слот[:серийный]"))]
        #[arg(long, short = 'y', value_name = "SLOT[:SERIAL]")]
        yubikey: Option<String>,
        #[arg(help = tr!("без пароля, только файл-ключ"))]
        #[arg(long)]
        no_password: bool,
        #[arg(help = tr!("текущий файл-ключ, если он не из конфига"))]
        #[arg(long)]
        current_keyfile: Option<PathBuf>,
        #[arg(help = tr!("текущий YubiKey, если он не из конфига"))]
        #[arg(long)]
        current_yubikey: Option<String>,
        #[arg(help = tr!("две строки со stdin: текущий пароль и новый (для скриптов)"))]
        #[arg(long)]
        password_stdin: bool,
    },
    #[command(about = tr!("Создать файл-ключ (формат KeePassXC); существующий файл не затирается"))]
    Keyfile { path: PathBuf },
    #[command(about = tr!("Настройки базы: без параметров показать, с параметрами изменить"))]
    DbSettings {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(help = tr!("корзина: on или off"))]
        #[arg(long, value_parser = parse_on_off)]
        recycle_bin: Option<bool>,
        #[arg(help = tr!("сколько версий истории хранить (-1 без ограничения)"))]
        #[arg(long, allow_negative_numbers = true)]
        history: Option<i64>,
        #[arg(help = tr!("предел истории одной записи, МиБ (-1 без ограничения)"))]
        #[arg(long, allow_negative_numbers = true)]
        history_size: Option<i64>,
        #[arg(long, value_enum)]
        cipher: Option<CipherArg>,
        #[arg(help = tr!("память Argon2, МиБ"))]
        #[arg(long)]
        memory: Option<u64>,
        #[arg(long)]
        iterations: Option<u64>,
        #[arg(long)]
        parallelism: Option<u32>,
        #[arg(help = tr!("подобрать Argon2id под ~1 с на этом компьютере"))]
        #[arg(long)]
        tune: bool,
    },
    #[command(about = tr!("Экспорт: csv (пароли открытым текстом) или kdbx (копия базы с другим паролем)"))]
    Export {
        path: PathBuf,
        #[arg(long, short = 'f', value_enum, default_value = "csv")]
        format: ExportArg,
        #[arg(help = tr!("для kdbx: файл-ключ копии"))]
        #[arg(long, short = 'k')]
        keyfile: Option<PathBuf>,
        #[arg(help = tr!("для kdbx: пароль копии одной строкой со stdin"))]
        #[arg(long)]
        password_stdin: bool,
    },
    #[command(about = tr!("Импорт в новую папку: CSV (KeePassXC, Chrome, Firefox, Bitwarden, 1Password, Proton Pass), другая база KeePass (.kdbx, .kdb) или JSON Bitwarden. Формат по расширению, если не указан."))]
    Import {
        file: PathBuf,
        #[arg(long, short = 'f', value_enum)]
        format: Option<ImportArg>,
        #[arg(help = tr!("для KeePass: файл-ключ той базы"))]
        #[arg(long, short = 'k')]
        keyfile: Option<PathBuf>,
        #[arg(help = tr!("для KeePass: пароль той базы одной строкой со stdin"))]
        #[arg(long)]
        password_stdin: bool,
    },
    #[command(about = tr!("Слить с другой копией этой базы (по UUID и времени правки, как Merge в KeePassXC)"))]
    Merge {
        file: PathBuf,
        #[arg(long, short = 'k')]
        keyfile: Option<PathBuf>,
        #[arg(long)]
        password_stdin: bool,
    },
    #[command(about = tr!("Выбрать сервер и подключиться: хосты ключей SSH по папкам и из ~/.ssh/config"))]
    Ssh {
        #[arg(long, help = tr!("только вывести хосты: папка, название, адрес"))]
        list: bool,
        #[arg(help = tr!("сразу отфильтровать; единственное совпадение подключается без списка"))]
        query: Vec<String>,
    },
    #[command(about = tr!("Перенести хосты ~/.ssh/config в записи «Сервер SSH» (едут с базой на другие компьютеры)"))]
    SshImportConfig,
    #[command(about = tr!("Port knocking для сервера SSH из базы (его вызывает ssh через Match exec)"))]
    Knock {
        #[arg(help = tr!("имя сервера, как в ssh имя"))]
        host: String,
    },
    #[command(about = tr!("Строка для оболочки: export SSH_AUTH_SOCK=… (агент Keywarden)"))]
    SshEnv,
    #[command(about = tr!("Агент Keywarden для всех программ (SSH_AUTH_SOCK в окружении сессии)"))]
    SshSetup {
        #[arg(long, help = tr!("выключить"))]
        off: bool,
        #[arg(long, help = tr!("только показать состояние"))]
        status: bool,
        #[arg(long, help = tr!("ключ под каждый хост: ~/.ssh/keywarden/config и Include в ~/.ssh/config"))]
        hosts: bool,
        #[arg(long, conflicts_with = "hosts", help = tr!("выключить ключ под каждый хост"))]
        no_hosts: bool,
    },
    #[command(about = tr!("Связать расширение браузера с Keywarden (native messaging) для Firefox, Chrome, Edge, Brave"))]
    BrowserSetup {
        #[arg(help = tr!("id расширения в Chromium-браузерах (chrome://extensions)"))]
        #[arg(long)]
        chrome_id: Option<String>,
    },
    #[command(about = tr!("Печатать события демона (отладка)"))]
    Watch,
}

#[derive(Args, Default)]
struct Pick {
    #[arg(help = tr!("при нескольких совпадениях взять первое"))]
    #[arg(long)]
    first: bool,
}

#[derive(Args)]
struct EditArgs {
    #[arg(long, short = 'u')]
    username: Option<String>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    notes: Option<String>,
    #[arg(help = tr!("путь группы: Finance/Cards"))]
    #[arg(long, short = 'g')]
    group: Option<String>,
    #[arg(help = tr!("спросить пароль"))]
    #[arg(long, short = 'p')]
    password_prompt: bool,
    #[arg(help = tr!("сгенерировать пароль"))]
    #[arg(long)]
    generate: bool,
    #[arg(help = tr!("otpauth://... для 2FA"))]
    #[arg(long)]
    otp: Option<String>,
    #[arg(help = tr!("своё поле: --field \"Card Number=4111...\""))]
    #[arg(long = "field", value_name = "NAME=VALUE")]
    fields: Vec<String>,
    #[arg(help = tr!("защищённое поле, значение спросить: --secret-field CVV"))]
    #[arg(long = "secret-field", value_name = "NAME")]
    secret_fields: Vec<String>,
    #[arg(long = "tag")]
    tags: Vec<String>,
    #[arg(help = tr!("срок действия ГГГГ-ММ-ДД или none (снять)"))]
    #[arg(long)]
    expires: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Login,
    Card,
    Identity,
    Note,
    SshKey,
    SshHost,
    Wallet,
}

impl From<KindArg> for EntryKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Login => EntryKind::Login,
            KindArg::Card => EntryKind::Card,
            KindArg::Identity => EntryKind::Identity,
            KindArg::Note => EntryKind::Note,
            KindArg::SshKey => EntryKind::SshKey,
            KindArg::SshHost => EntryKind::SshHost,
            KindArg::Wallet => EntryKind::CryptoWallet,
        }
    }
}

#[derive(Subcommand)]
enum OtpCmd {
    #[command(about = tr!("Задать 2FA записи: секрет base32, otpauth:// или KeeOtp"))]
    Set {
        query: String,
        value: String,
        #[command(flatten)]
        pick: Pick,
    },
    #[command(about = tr!("Распознать QR-код с картинки или из буфера обмена (без файла)"))]
    Scan { file: Option<PathBuf> },
    #[command(about = tr!("QR-код записи в терминале, чтобы отсканировать телефоном (показывает секрет)"))]
    Qr {
        query: String,
        #[command(flatten)]
        pick: Pick,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportArg {
    Csv,
    Kdbx,
    #[value(help = tr!("бэкап 2FAS: все коды 2FA"))]
    #[value(name = "2fas")]
    TwoFas,
}

#[derive(Clone, Copy, ValueEnum)]
enum ImportArg {
    Csv,
    Keepass,
    Bitwarden,
    #[value(name = "2fas")]
    TwoFas,
}

fn parse_on_off(s: &str) -> Result<bool, String> {
    match s {
        "on" | "yes" | "true" | "1" => Ok(true),
        "off" | "no" | "false" | "0" => Ok(false),
        _ => Err(tr!("on или off").into()),
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum CipherArg {
    Aes256,
    Chacha20,
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("kw: {e:#}");
        std::process::exit(1);
    }
}

fn connect() -> Result<Client> {
    Client::connect().context(if cfg!(target_os = "linux") {
        tr!("keywardend не запущен (systemctl --user start keywardend)")
    } else {
        tr!("keywardend не запущен: откройте Keywarden или запустите keywardend")
    })
}

/// Запрос с разбором ошибки демона.
fn call(c: &mut Client, req: Request) -> Result<Response> {
    match c.call(&req)? {
        Response::Error {
            code: ErrorCode::Locked,
            ..
        } => bail!(tr!("база заблокирована, выполните kw unlock")),
        Response::Error { message, .. } => Err(anyhow!(message)),
        r => Ok(r),
    }
}

fn run(cli: Cli) -> Result<()> {
    use keywarden_core::ipc;
    ipc::set_profile(cli.profile.as_deref()).map_err(|e| anyhow!(e))?;
    match &cli.cmd {
        Cmd::Profiles => {
            for p in ipc::profiles() {
                let name = (p != "default").then_some(p.as_str());
                let state =
                    match Client::connect_to(name).and_then(|mut c| c.call(&Request::Status)) {
                        Ok(Response::Status(s)) if !s.locked => {
                            tr!(
                                "открыта: {path} ({n} {entries})",
                                path = s.path.unwrap_or_default(),
                                n = s.entries,
                                entries = keywarden_core::i18n::plural(
                                    s.entries as u64,
                                    "запись",
                                    "записи",
                                    "записей"
                                )
                            )
                        }
                        Ok(Response::Status(s)) => format!(
                            "{}{}",
                            tr!("заблокирована"),
                            s.default_path.map(|p| format!(": {p}")).unwrap_or_default()
                        ),
                        _ => tr!("демон не запущен").into(),
                    };
                println!("{p}  {state}");
            }
            return Ok(());
        }
        Cmd::BrowserSetup { chrome_id } => return browser::setup(chrome_id.as_deref()),
        Cmd::ProfileAdd { name, db } => {
            ipc::add_profile(name, db).map_err(|e| anyhow!(e))?;
            if cfg!(target_os = "linux") {
                println!(
                    "{}",
                    tr!(
                        "База «{name}» добавлена. Запуск: systemctl --user start keywardend@{name} (или keywardend --profile {name})",
                        name = name
                    )
                );
            } else {
                println!(
                    "{}",
                    tr!(
                        "База «{name}» добавлена. Запуск: keywardend --profile {name}",
                        name = name
                    )
                );
            }
            return Ok(());
        }
        Cmd::SshSetup {
            off,
            status,
            hosts,
            no_hosts,
        } if !*hosts && !*no_hosts => {
            use keywarden_core::ssh_setup::{self, Status};
            if !*status {
                if *off {
                    ssh_setup::disable()
                } else {
                    ssh_setup::enable()
                }
                .map_err(|e| anyhow!(tr!("не удалось: {e}", e = e)))?;
            }
            println!(
                "{}",
                match ssh_setup::status() {
                    Status::Off => tr!("Агент Keywarden для всех программ выключен").to_string(),
                    Status::Active =>
                        tr!("Агент Keywarden работает для всех новых программ").to_string(),
                    Status::AfterRelogin =>
                        tr!("Включено: заработает после перезахода в систему").to_string(),
                    Status::Overridden(v) => tr!(
                        "Включено, но SSH_AUTH_SOCK сейчас указывает на другой агент: {path}",
                        path = v
                    ),
                }
            );
            return Ok(());
        }
        _ => {}
    }
    let mut c = connect()?;
    match cli.cmd {
        Cmd::Profiles | Cmd::ProfileAdd { .. } | Cmd::BrowserSetup { .. } => unreachable!(),
        Cmd::SshSetup { hosts, .. } => {
            let Response::Prefs { mut prefs } = call(&mut c, Request::Prefs { set: None })? else {
                bail!(tr!("неожиданный ответ демона"));
            };
            prefs.ssh_host_config = hosts;
            call(&mut c, Request::Prefs { set: Some(*prefs) })?;
            println!(
                "{}",
                if hosts {
                    tr!("Ключ под каждый хост включён: ~/.ssh/keywarden/config")
                } else {
                    tr!("Ключ под каждый хост выключен")
                }
            );
        }
        Cmd::Ping => {
            if let Response::Pong { version } = call(&mut c, Request::Ping)? {
                println!("keywardend {version}");
            }
        }
        Cmd::Status => {
            if let Response::Status(s) = call(&mut c, Request::Status)? {
                if s.locked {
                    println!("{}", tr!("заблокирована"));
                    if let Some(p) = s.default_path {
                        println!("{}", tr!("база по умолчанию: {p}", p = p));
                    }
                } else {
                    println!(
                        "{}",
                        tr!(
                            "открыта: {path} ({n} {entries})",
                            path = s.path.unwrap_or_default(),
                            n = s.entries,
                            entries = keywarden_core::i18n::plural(
                                s.entries as u64,
                                "запись",
                                "записи",
                                "записей"
                            )
                        )
                    );
                }
            }
        }
        Cmd::Yubikeys => {
            let keys = keywarden_core::vault::yubikeys().map_err(|e| anyhow!(e))?;
            if keys.is_empty() {
                println!("{}", tr!("YubiKey не найден"));
            }
            for (serial, name) in keys {
                println!("{serial}  {}", name.unwrap_or_default());
            }
        }
        Cmd::Unlock {
            db,
            keyfile,
            no_password,
            password_stdin,
            yubikey,
            pin,
        } => {
            if pin {
                let pin = if password_stdin {
                    read_stdin_line()?
                } else {
                    prompt("PIN: ")?
                };
                call(&mut c, Request::QuickUnlock { pin })?;
                eprintln!("{}", tr!("база открыта"));
                return Ok(());
            }
            let password = if no_password {
                None
            } else if password_stdin {
                Some(read_stdin_line()?)
            } else {
                Some(prompt(tr!("Мастер-пароль: "))?)
            };
            let req = Request::Unlock {
                path: db.map(abs),
                password,
                keyfile: keyfile.map(abs),
                yubikey,
            };
            call(&mut c, req)?;
            eprintln!("{}", tr!("база открыта"));
        }
        Cmd::Pin { remove, stdin } => {
            if remove {
                call(
                    &mut c,
                    Request::SetPin {
                        pin: None,
                        key: None,
                    },
                )?;
                eprintln!("{}", tr!("PIN убран"));
                return Ok(());
            }
            let (pw, pin) = if stdin {
                let mut l = read_stdin_lines()?.into_iter();
                match (l.next(), l.next()) {
                    (Some(pw), Some(pin)) => (pw, pin),
                    _ => anyhow::bail!(tr!("ожидались две строки: мастер-пароль и PIN")),
                }
            } else {
                (prompt(tr!("Мастер-пароль: "))?, prompt(tr!("Новый PIN: "))?)
            };
            call(
                &mut c,
                Request::SetPin {
                    pin: Some(pin),
                    key: Some(keywarden_core::ipc::KeySpec {
                        password: Some(pw),
                        ..Default::default()
                    }),
                },
            )?;
            eprintln!("{}", tr!("PIN задан"));
        }
        Cmd::Lock => {
            call(&mut c, Request::Lock)?;
            eprintln!("{}", tr!("база заблокирована"));
        }
        Cmd::New {
            path,
            keyfile,
            cipher,
            no_password,
            yubikey,
        } => {
            let password = if no_password {
                None
            } else {
                let p = prompt(tr!("Новый мастер-пароль: "))?;
                if prompt(tr!("Ещё раз: "))? != p {
                    bail!(tr!("пароли не совпали"));
                }
                Some(p)
            };
            let cipher = match cipher {
                CipherArg::Aes256 => Cipher::Aes256,
                CipherArg::Chacha20 => Cipher::ChaCha20,
            };
            eprintln!("{}", tr!("подбираю параметры Argon2id (~1 с)…"));
            call(
                &mut c,
                Request::Create {
                    path: abs(path),
                    password,
                    keyfile: keyfile.map(abs),
                    yubikey,
                    cipher,
                },
            )?;
            eprintln!("{}", tr!("база создана и открыта"));
        }
        Cmd::Sync { cmd } => match cmd {
            SyncCmd::Status => {
                let Response::SyncJournal { records, held, .. } =
                    call(&mut c, Request::SyncJournal)?
                else {
                    bail!(tr!("нет ответа"))
                };
                if let Some(h) = held {
                    println!(
                        "{}",
                        tr!(
                            "НА ПАУЗЕ: {source} убирает {removed} из {live} записей ({summary}). kw sync reject или kw sync accept",
                            source = h.source,
                            removed = h.removed,
                            live = h.live,
                            summary = h.summary
                        )
                    );
                }
                for r in records {
                    println!(
                        "{}\t{}\t{}\t{}\t{}{}",
                        r.id,
                        r.when,
                        r.status,
                        r.source,
                        r.summary,
                        if r.snapshot.is_some() && r.status != "reverted" {
                            String::new()
                        } else {
                            format!("\t{}", tr!("(без отмены)"))
                        }
                    );
                }
            }
            SyncCmd::Accept | SyncCmd::Reject => {
                let accept = matches!(cmd, SyncCmd::Accept);
                call(&mut c, Request::SyncDecide { accept })?;
                eprintln!(
                    "{}",
                    if accept {
                        tr!("Удаления приняты")
                    } else {
                        tr!("Удаления отклонены")
                    }
                );
            }
            SyncCmd::Revert { id } => {
                call(&mut c, Request::SyncRevert { id })?;
                eprintln!("{}", tr!("Слияние {id} отменено", id = id));
            }
        },
        Cmd::Wallet {
            cmd: WalletCmd::Addresses { query },
        } => {
            use keywarden_core::model::EntryKind;
            let entries = search(&mut c, &query, 500)?;
            let mut found = false;
            for e in entries
                .into_iter()
                .filter(|e| e.kind == EntryKind::CryptoWallet)
            {
                let Response::Entry { entry } = call(
                    &mut c,
                    Request::Get {
                        id: e.id.clone(),
                        reveal: false,
                    },
                )?
                else {
                    continue;
                };
                let text = entry
                    .fields
                    .iter()
                    .find(|f| f.name == keywarden_core::wallet::ADDRESSES)
                    .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string()))
                    .unwrap_or_default();
                for (label, addr) in keywarden_core::wallet::parse_addresses(&text) {
                    found = true;
                    let nets = keywarden_core::wallet::address_networks(&addr).join(",");
                    println!(
                        "{}\t{}\t{}\t{}",
                        e.title,
                        if label.is_empty() { "-" } else { &label },
                        if nets.is_empty() { "?" } else { &nets },
                        addr
                    );
                }
            }
            if !found {
                bail!(tr!("адресов кошельков не найдено"));
            }
        }
        Cmd::Search { query, limit, json } => {
            let entries = search(&mut c, &query, limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                print_table(&entries);
            }
        }
        Cmd::Show {
            query,
            reveal,
            json,
            pick,
        } => {
            let e = resolve(&mut c, &query, &pick)?;
            let Response::Entry { entry } = call(&mut c, Request::Get { id: e.id, reveal })? else {
                bail!(tr!("нет ответа"))
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else {
                print_entry(&entry);
            }
        }
        Cmd::Copy { query, field, pick } => {
            let e = resolve(&mut c, &query, &pick)?;
            call(
                &mut c,
                Request::Copy {
                    id: e.id,
                    field: field.clone(),
                },
            )?;
            eprintln!(
                "{}",
                tr!(
                    "{field} из «{title}» скопирован, буфер очистится сам",
                    field = field,
                    title = e.title
                )
            );
        }
        Cmd::Totp { query, copy, pick } => {
            let e = resolve(&mut c, &query, &pick)?;
            if copy {
                call(
                    &mut c,
                    Request::Copy {
                        id: e.id.clone(),
                        field: "totp".into(),
                    },
                )?;
            }
            if let Response::Totp { code } = call(&mut c, Request::Totp { id: e.id })? {
                println!(
                    "{}",
                    tr!("{code}  ({s} с)", code = code.code, s = code.remaining)
                );
            }
        }
        Cmd::Add { kind, title, edit } => {
            let kind: EntryKind = kind.into();
            let mut patch = edit_patch(&mut c, &edit)?;
            patch.kind = Some(kind);
            patch.set.insert(0, FieldSet::new("Title", title.clone()));
            let Response::Created { id } = call(&mut c, Request::Add { patch })? else {
                bail!(tr!("нет ответа"))
            };
            eprintln!(
                "{}",
                tr!("добавлено «{title}» ({id})", title = title, id = id)
            );
        }
        Cmd::Edit {
            query,
            title,
            kind,
            edit,
            remove,
            pick,
        } => {
            let e = resolve(&mut c, &query, &pick)?;
            let mut patch = edit_patch(&mut c, &edit)?;
            patch.kind = kind.map(Into::into);
            patch.remove = remove;
            if let Some(t) = title {
                patch.set.push(FieldSet::new("Title", t));
            }
            call(&mut c, Request::Update { id: e.id, patch })?;
            eprintln!("{}", tr!("«{title}» изменено", title = e.title));
        }
        Cmd::Health { breaches } => {
            use keywarden_core::health::Issue;
            let Response::Health { report: r } = call(&mut c, Request::Health { breaches })? else {
                bail!(tr!("нет ответа"))
            };
            println!(
                "{}",
                tr!(
                    "Проверено {checked}, исключено из отчётов {excluded}: слабых {weak}, повторов {reused}, старше года {old}, истёкших {expired}{breached}",
                    checked = r.checked,
                    excluded = r.excluded,
                    weak = r.weak,
                    reused = r.reused,
                    old = r.old,
                    expired = r.expired,
                    breached = if r.breaches_checked {
                        tr!(", в утечках {n}", n = r.breached)
                    } else {
                        String::new()
                    }
                )
            );
            for i in &r.items {
                let what: Vec<String> = i
                    .issues
                    .iter()
                    .map(|x| match x {
                        Issue::Breached { count } => tr!("в утечках {count} раз", count = count),
                        Issue::Weak { score } => tr!("слабый ({score}/4)", score = score),
                        Issue::Reused { count } => {
                            tr!("повторяется в {count} записях", count = count)
                        }
                        Issue::Old { days } => tr!("не менялся {days} дн.", days = days),
                        Issue::Expired => tr!("срок истёк").into(),
                        Issue::Insecure => tr!("адрес без шифрования (http)").into(),
                        Issue::NoTwoFactor { doc } => tr!("сайт умеет 2FA: {doc}", doc = doc),
                        Issue::PasskeyReady { doc } => {
                            tr!("сайт принимает ключ доступа: {doc}", doc = doc)
                        }
                        Issue::BadSeed { message } => {
                            tr!("сид-фраза: {message}", message = message)
                        }
                        Issue::AddressMismatch { addresses } => {
                            tr!(
                                "адреса не из этой фразы или ключа: {list}",
                                list = addresses.join(", ")
                            )
                        }
                    })
                    .collect();
                println!("  {}  {}  {}", i.title, i.username, what.join(", "));
            }
        }
        Cmd::Otp(OtpCmd::Set { query, value, pick }) => {
            let e = resolve(&mut c, &query, &pick)?;
            call(
                &mut c,
                Request::SetOtp {
                    id: e.id,
                    value: Secret::new(value),
                },
            )?;
            eprintln!("{}", tr!("2FA для «{title}» задана", title = e.title));
        }
        Cmd::Otp(OtpCmd::Scan { file }) => {
            let Response::OtpScanned { text } = call(
                &mut c,
                Request::OtpScan {
                    path: file.map(abs),
                },
            )?
            else {
                bail!(tr!("нет ответа"))
            };
            println!("{}", text.expose());
        }
        Cmd::Otp(OtpCmd::Qr { query, pick }) => {
            let e = resolve(&mut c, &query, &pick)?;
            let Response::OtpUri { uri } = call(&mut c, Request::OtpUri { id: e.id })? else {
                bail!(tr!("нет ответа"))
            };
            let (w, cells) = keywarden_core::totp::qr_matrix(uri.expose())
                .ok_or_else(|| anyhow!(tr!("ссылка слишком длинная для QR")))?;
            // светлые клетки блоками: на тёмном терминале QR читается как обычный
            let dark = |x: isize, y: isize| {
                x >= 0
                    && y >= 0
                    && (x as usize) < w
                    && (y as usize) < w
                    && cells[y as usize * w + x as usize]
            };
            let q = 2isize;
            let mut y = -q;
            while y < w as isize + q {
                let line: String = (-q..w as isize + q)
                    .map(|x| match (!dark(x, y), !dark(x, y + 1)) {
                        (true, true) => '█',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (false, false) => ' ',
                    })
                    .collect();
                println!("{line}");
                y += 2;
            }
            eprintln!(
                "{}",
                tr!(
                    "Отсканируйте в 2FAS или другом приложении. В QR секрет: не показывайте экран другим."
                )
            );
        }
        Cmd::Autotype {
            query,
            window,
            sequence,
        } => {
            let id = match query {
                Some(q) => Some(resolve(&mut c, &q, &Pick { first: false })?.id),
                None => None,
            };
            if let Response::AutoTypeChoices { window, entries } = call(
                &mut c,
                Request::AutoType {
                    id,
                    window,
                    sequence,
                },
            )? {
                {
                    eprintln!(
                        "{}",
                        tr!(
                            "к окну «{window}» подходит записей: {n}; выберите в лаунчере",
                            window = window,
                            n = entries.len()
                        )
                    );
                    let ui = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.parent().map(|d| d.join("keywarden-ui")))
                        .filter(|p| p.exists())
                        .unwrap_or_else(|| "keywarden-ui".into());
                    std::process::Command::new(ui)
                        .args(["--launcher", "--autotype"])
                        .spawn()
                        .context(tr!("лаунчер не запустился"))?;
                }
            }
        }
        Cmd::SecretsImport => {
            let Response::SecretsMigrated { items, skipped } =
                call(&mut c, Request::SecretsMigrate)?
            else {
                bail!(tr!("нет ответа"))
            };
            println!(
                "{}",
                tr!(
                    "Перенесено секретов: {items}, пропущено: {skipped}",
                    items = items,
                    skipped = skipped
                )
            );
        }
        Cmd::Icon { query, clear, pick } => {
            let e = resolve(&mut c, &query, &pick)?;
            if clear {
                call(&mut c, Request::ClearIcon { id: e.id })?;
                eprintln!("{}", tr!("иконка «{title}» убрана", title = e.title));
            } else {
                call(&mut c, Request::FetchFavicon { id: e.id })?;
                eprintln!(
                    "{}",
                    tr!("иконка «{title}» сохранена в базе", title = e.title)
                );
            }
        }
        Cmd::Dup { query, pick } => {
            let e = resolve(&mut c, &query, &pick)?;
            let Response::Created { id } = call(&mut c, Request::Duplicate { id: e.id })? else {
                bail!(tr!("нет ответа"))
            };
            println!("{id}");
        }
        Cmd::Mv { query, group, pick } => {
            let e = resolve(&mut c, &query, &pick)?;
            let all = groups(&mut c)?;
            let path = group.trim_matches('/');
            let g = if path.is_empty() {
                all.first().cloned()
            } else {
                all.into_iter().find(|g| g.path.eq_ignore_ascii_case(path))
            }
            .ok_or_else(|| {
                anyhow!(tr!(
                    "нет группы «{group}» (создать: kw mkgroup {group})",
                    group = group
                ))
            })?;
            call(
                &mut c,
                Request::MoveEntry {
                    id: e.id,
                    group: g.id,
                },
            )?;
            eprintln!(
                "{}",
                tr!(
                    "«{title}» перемещено в «{group}»",
                    title = e.title,
                    group = if path.is_empty() { "/" } else { path }
                )
            );
        }
        Cmd::Tags => {
            let Response::Tags { tags } = call(&mut c, Request::Tags)? else {
                bail!(tr!("нет ответа"))
            };
            for (t, n) in tags {
                println!("#{t}  [{n}]");
            }
        }
        Cmd::Rm { query, pick } => {
            let e = resolve(&mut c, &query, &pick)?;
            call(&mut c, Request::Delete { id: e.id })?;
            eprintln!("{}", tr!("«{title}» удалено", title = e.title));
        }
        Cmd::Groups => {
            for g in groups(&mut c)?.iter().skip(1) {
                let bin = if g.is_recycle_bin {
                    tr!("  (корзина)")
                } else {
                    ""
                };
                println!(
                    "{}{}  [{}]{bin}",
                    "  ".repeat(g.depth - 1),
                    g.name,
                    g.entries
                );
            }
        }
        Cmd::Mkgroup { path } => {
            let mut parent: Option<String> = None;
            let mut done = String::new();
            for part in path.split('/').filter(|p| !p.is_empty()) {
                done = if done.is_empty() {
                    part.to_string()
                } else {
                    format!("{done}/{part}")
                };
                let existing = groups(&mut c)?
                    .into_iter()
                    .find(|g| g.path.eq_ignore_ascii_case(&done));
                parent = Some(match existing {
                    Some(g) => g.id,
                    None => match call(
                        &mut c,
                        Request::AddGroup {
                            parent: parent.clone(),
                            name: part.into(),
                        },
                    )? {
                        Response::Created { id } => id,
                        _ => bail!(tr!("нет ответа")),
                    },
                });
            }
            eprintln!("{}", tr!("группа {path} есть", path = path));
        }
        Cmd::Generate {
            length,
            no_symbols,
            no_digits,
            passphrase,
            words,
            copy,
        } => {
            let options = if passphrase {
                Generate::Passphrase(PassphraseOptions {
                    words,
                    ..Default::default()
                })
            } else {
                Generate::Password(PasswordOptions {
                    length,
                    symbols: !no_symbols,
                    digits: !no_digits,
                    ..Default::default()
                })
            };
            let Response::Generated { generated } = call(&mut c, Request::Generate { options })?
            else {
                bail!(tr!("нет ответа"))
            };
            if copy {
                call(
                    &mut c,
                    Request::CopyText {
                        value: generated.value.clone(),
                    },
                )?;
                eprintln!(
                    "{}",
                    tr!(
                        "скопировано ({bits} бит)",
                        bits = format!("{:.0}", generated.entropy_bits)
                    )
                );
            } else {
                println!("{}", generated.value.expose());
                if std::io::stderr().is_terminal() {
                    eprintln!(
                        "{}",
                        tr!(
                            "{bits} бит энтропии",
                            bits = format!("{:.0}", generated.entropy_bits)
                        )
                    );
                }
            }
        }
        Cmd::Attach {
            query,
            file,
            name,
            pick,
        } => {
            let e = resolve(&mut c, &query, &pick)?;
            let data = std::fs::read(&file).with_context(|| file.display().to_string())?;
            let name = name.unwrap_or_else(|| {
                file.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            });
            call(
                &mut c,
                Request::AttachmentAdd {
                    id: e.id,
                    name: name.clone(),
                    data: BASE64.encode(&data),
                },
            )?;
            eprintln!(
                "{}",
                tr!(
                    "«{name}» приложен к «{title}»",
                    name = name,
                    title = e.title
                )
            );
        }
        Cmd::Attachment {
            query,
            name,
            output,
            pick,
        } => {
            let e = resolve(&mut c, &query, &pick)?;
            let Response::Attachment { data } = call(
                &mut c,
                Request::AttachmentGet {
                    id: e.id,
                    name: name.clone(),
                },
            )?
            else {
                bail!(tr!("нет ответа"))
            };
            let bytes = BASE64.decode(data.as_bytes())?;
            match output {
                Some(p) => {
                    keywarden_core::vault::write_atomic(&p, &bytes)?;
                    eprintln!("{}", tr!("сохранено в {path}", path = p.display()));
                }
                None => std::io::stdout().write_all(&bytes)?,
            }
        }
        Cmd::SshImport {
            file,
            title,
            group,
            confirm,
            passphrase_stdin,
            host,
        } => {
            let data = std::fs::read(&file).with_context(|| file.display().to_string())?;
            let encrypted = String::from_utf8_lossy(&data).contains("BEGIN OPENSSH PRIVATE KEY")
                && is_encrypted_openssh(&data);
            let passphrase = match (encrypted, passphrase_stdin) {
                (false, _) => None,
                (true, true) => Some(read_stdin_line()?),
                (true, false) => Some(prompt(tr!("Пароль ключа: "))?),
            };
            let file_name = file
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let title = title.unwrap_or_else(|| format!("SSH {file_name}"));
            let group = match group {
                None => None,
                Some(path) => Some(
                    groups(&mut c)?
                        .into_iter()
                        .find(|g| g.path.eq_ignore_ascii_case(path.trim_matches('/')))
                        .ok_or_else(|| anyhow!(tr!("нет группы «{path}»", path = path)))?
                        .id,
                ),
            };
            let req = Request::SshImport {
                title: title.clone(),
                key: BASE64.encode(&data),
                file_name,
                passphrase,
                group,
                confirm,
                host,
            };
            call(&mut c, req)?;
            eprintln!(
                "{}",
                tr!(
                    "ключ импортирован в «{title}»; он доступен через kw ssh-env, пока база открыта",
                    title = title
                )
            );
        }
        Cmd::SshMigrate { import, delete } => {
            let Response::SshLocalKeys { keys } = call(&mut c, Request::SshLocalKeys)? else {
                bail!(tr!("неожиданный ответ демона"));
            };
            let keys = if import {
                let paths = keys
                    .iter()
                    .filter(|k| !k.in_vault && !k.encrypted)
                    .map(|k| k.path.clone())
                    .collect();
                let Response::SshLocalKeys { keys } =
                    call(&mut c, Request::SshMigrate { paths, delete })?
                else {
                    bail!(tr!("неожиданный ответ демона"));
                };
                keys
            } else {
                keys
            };
            if keys.is_empty() {
                println!("{}", tr!("В ~/.ssh нет приватных ключей OpenSSH"));
            }
            for k in keys {
                let state = if k.in_vault {
                    tr!("в базе")
                } else if k.encrypted {
                    tr!("зашифрован: перенесите через kw ssh-import")
                } else {
                    tr!("можно перенести: kw ssh-migrate --import")
                };
                println!("{}  {}  {}  {state}", k.path, k.comment, k.fingerprint);
            }
        }
        Cmd::SshImportConfig => match call(&mut c, Request::SshImportConfig { only: None })? {
            Response::SshImported { added, skipped } => {
                println!(
                    "{}",
                    tr!(
                        "Перенесено в базу: {added}, уже были: {skipped}. Папка «SSH».",
                        added = added,
                        skipped = skipped
                    )
                );
                if !matches!(call(&mut c, Request::Prefs { set: None })?, Response::Prefs { prefs } if prefs.ssh_host_config)
                {
                    println!(
                        "{}",
                        tr!("Чтобы ssh видел серверы из базы: kw ssh-setup --hosts")
                    );
                }
            }
            _ => bail!(tr!("нет ответа")),
        },
        Cmd::Knock { host } => knock(&mut c, &host)?,
        Cmd::Ssh { list, query } => {
            // база заблокирована: спросить пароль здесь же, в терминале
            if let Err(e) = search_kind(&mut c, EntryKind::SshKey) {
                if list || !std::io::stdin().is_terminal() {
                    return Err(e);
                }
                let password = prompt(tr!("Мастер-пароль: "))?;
                call(
                    &mut c,
                    Request::Unlock {
                        path: None,
                        password: Some(password),
                        keyfile: None,
                        yubikey: None,
                    },
                )?;
            }
            let config =
                std::fs::read_to_string(keywarden_core::platform::home().join(".ssh/config"))
                    .unwrap_or_default();
            let q = query.join(" ");
            if list || !q.is_empty() {
                let keys = search_kind(&mut c, EntryKind::SshKey)?;
                let mut hosts = ssh_tui::all_hosts(&keys, &ssh_servers(&mut c)?, &config);
                hosts.retain(|h| ssh_tui::matches(h, &q));
                if list {
                    for h in &hosts {
                        println!("{}\t{}\t{}", h.folder.join("/"), h.name, h.target);
                    }
                    return Ok(());
                }
                if let [one] = hosts.as_slice() {
                    if let ssh_tui::Source::Server {
                        alias,
                        knock_first: true,
                        ..
                    } = &one.source
                    {
                        knock(&mut c, alias)?;
                    }
                    return exec("ssh", &one.args, None);
                }
            }
            if !std::io::stdout().is_terminal() {
                bail!(tr!("нужен терминал; список: kw ssh --list"));
            }
            match ssh_tui::pick(&mut TuiBackend(&mut c), config)? {
                ssh_tui::Exit::Quit => {}
                ssh_tui::Exit::Exec {
                    program,
                    args,
                    note,
                } => return exec(program, &args, note),
            }
        }
        Cmd::SshGenerate {
            title,
            algorithm,
            host,
            comment,
            group,
            confirm,
        } => {
            let group = match group {
                None => None,
                Some(path) => Some(
                    groups(&mut c)?
                        .into_iter()
                        .find(|g| g.path.eq_ignore_ascii_case(path.trim_matches('/')))
                        .ok_or_else(|| anyhow!(tr!("нет группы «{path}»", path = path)))?
                        .id,
                ),
            };
            let Response::Created { id } = call(
                &mut c,
                Request::SshGenerate {
                    title,
                    comment,
                    host,
                    group,
                    confirm,
                    algorithm: Some(algorithm),
                },
            )?
            else {
                bail!(tr!("неожиданный ответ демона"));
            };
            let Response::Entry { entry } = call(&mut c, Request::Get { id, reveal: false })?
            else {
                bail!(tr!("неожиданный ответ демона"));
            };
            // stdout: только открытый ключ, чтобы его можно было передать дальше (| wl-copy)
            println!("{}", entry.notes.trim());
            eprintln!(
                "{}",
                tr!("Открытый ключ выше: добавьте его на сервер или в GitHub")
            );
        }
        Cmd::SshGitSign { query, off, pick } => {
            use keywarden_core::git_signing;
            if off {
                git_signing::disable().map_err(|e| anyhow!(e))?;
                println!(
                    "{}",
                    tr!("git больше не подписывает коммиты ключом Keywarden")
                );
                return Ok(());
            }
            let query = query.ok_or_else(|| anyhow!(tr!("укажите запись с ключом SSH")))?;
            let e = resolve(&mut c, &query, &pick)?;
            let Response::Entry { entry } = call(
                &mut c,
                Request::Get {
                    id: e.id,
                    reveal: false,
                },
            )?
            else {
                bail!(tr!("нет ответа"))
            };
            let public = entry
                .notes
                .lines()
                .find(|l| git_signing::key_body(l).is_some())
                .ok_or_else(|| anyhow!(tr!("в записи нет открытого ключа SSH")))?;
            git_signing::enable(public).map_err(|e| anyhow!(e))?;
            println!(
                "{}",
                tr!(
                    "git подписывает коммиты и теги ключом «{title}». Проверка: git log --show-signature",
                    title = entry.summary.title
                )
            );
        }
        Cmd::ImportBitwarden { file } => {
            let json =
                std::fs::read_to_string(&file).with_context(|| file.display().to_string())?;
            let Response::Imported { report: r } = call(&mut c, Request::ImportBitwarden { json })?
            else {
                bail!(tr!("нет ответа"))
            };
            println!(
                "{}",
                tr!(
                    "Перенесено {n} записей в группу «Bitwarden»:",
                    n = r.total()
                )
            );
            println!(
                "{}",
                tr!(
                    "  логины {logins}, карты {cards}, личные данные {identities}, заметки {notes}, ключи SSH {ssh}; папок {folders}",
                    logins = r.logins,
                    cards = r.cards,
                    identities = r.identities,
                    notes = r.notes,
                    ssh = r.ssh_keys,
                    folders = r.folders
                )
            );
            if r.skipped_deleted > 0 {
                println!(
                    "{}",
                    tr!(
                        "  пропущено из корзины Bitwarden: {n}",
                        n = r.skipped_deleted
                    )
                );
            }
            if r.review.is_empty() {
                println!("{}", tr!("Ручная проверка не нужна."));
            } else {
                println!("{}", tr!("Проверьте вручную:"));
                for x in &r.review {
                    println!("  - {x}");
                }
            }
        }
        Cmd::Passwd {
            keyfile,
            yubikey,
            no_password,
            current_keyfile,
            current_yubikey,
            password_stdin,
        } => {
            let Response::Status(st) = call(&mut c, Request::Status)? else {
                bail!(tr!("нет ответа"))
            };
            let (cur_pw, new_pw) = if password_stdin {
                let mut lines = read_stdin_lines()?.into_iter();
                (lines.next(), if no_password { None } else { lines.next() })
            } else {
                let cur = prompt(tr!("Текущий мастер-пароль (пусто, если его нет): "))?;
                let new = if no_password {
                    None
                } else {
                    let a = prompt(tr!("Новый мастер-пароль: "))?;
                    if a.expose() != prompt(tr!("Ещё раз: "))?.expose() {
                        bail!(tr!("пароли не совпадают"));
                    }
                    Some(a)
                };
                (Some(cur), new)
            };
            let current = KeySpec {
                password: cur_pw,
                keyfile: current_keyfile.map(abs).or(st.keyfile),
                yubikey: current_yubikey.or(st.yubikey),
            };
            let new = KeySpec {
                password: new_pw,
                keyfile: keyfile.map(abs),
                yubikey,
            };
            call(&mut c, Request::ChangeKey { current, new })?;
            println!(
                "{}",
                tr!("Ключ сменён. Бэкапы до смены по-прежнему открываются старым ключом.")
            );
        }
        Cmd::Keyfile { path } => {
            call(
                &mut c,
                Request::GenerateKeyfile {
                    path: abs(path.clone()),
                },
            )?;
            println!(
                "{}",
                tr!(
                    "Создан {path}. Без него база не откроется: сохраните копию отдельно от базы.",
                    path = path.display()
                )
            );
        }
        Cmd::DbSettings {
            name,
            description,
            recycle_bin,
            history,
            history_size,
            cipher,
            memory,
            iterations,
            parallelism,
            tune,
        } => {
            let Response::Settings { settings: mut s } = call(
                &mut c,
                if tune {
                    Request::TuneKdf
                } else {
                    Request::GetSettings
                },
            )?
            else {
                bail!(tr!("нет ответа"))
            };
            let changed = tune
                || name.is_some()
                || description.is_some()
                || recycle_bin.is_some()
                || history.is_some()
                || history_size.is_some()
                || cipher.is_some()
                || memory.is_some()
                || iterations.is_some()
                || parallelism.is_some();
            if let Some(v) = name {
                s.name = v;
            }
            if let Some(v) = description {
                s.description = v;
            }
            if let Some(v) = recycle_bin {
                s.recycle_bin = v;
            }
            if let Some(v) = history {
                s.history_max_items = v;
            }
            if let Some(v) = history_size {
                s.history_max_size_mib = v;
            }
            if let Some(v) = cipher {
                s.cipher = match v {
                    CipherArg::Aes256 => Cipher::Aes256,
                    CipherArg::Chacha20 => Cipher::ChaCha20,
                };
            }
            // параметры Argon2 у базы со старым AES-KDF значат переход на Argon2id
            if s.kdf == "aes" && (memory.is_some() || iterations.is_some() || parallelism.is_some())
            {
                s.kdf = "argon2id".into();
                s.kdf_memory_mib = 64;
                s.kdf_iterations = 10;
                s.kdf_parallelism = 2;
            }
            if let Some(v) = memory {
                s.kdf_memory_mib = v;
            }
            if let Some(v) = iterations {
                s.kdf_iterations = v;
            }
            if let Some(v) = parallelism {
                s.kdf_parallelism = v;
            }
            if changed {
                let Response::Settings { settings } =
                    call(&mut c, Request::SetSettings { settings: s })?
                else {
                    bail!(tr!("нет ответа"))
                };
                s = settings;
                println!("{}", tr!("Сохранено."));
            }
            println!("{}", tr!("Имя:        {name}", name = s.name));
            println!("{}", tr!("Описание:   {text}", text = s.description));
            println!(
                "{}",
                if s.recycle_bin {
                    tr!("Корзина:    включена")
                } else {
                    tr!("Корзина:    выключена")
                }
            );
            println!(
                "{}",
                tr!(
                    "История:    {items} версий, до {mib} МиБ на запись",
                    items = s.history_max_items,
                    mib = s.history_max_size_mib
                )
            );
            println!(
                "{}",
                tr!(
                    "Шифр:       {cipher}, сжатие {gzip}",
                    cipher = format!("{:?}", s.cipher),
                    gzip = if s.compression { "gzip" } else { tr!("нет") }
                )
            );
            println!(
                "{}",
                tr!(
                    "KDF:        {kdf} {iterations} итераций, {mib} МиБ, {threads} потоков",
                    kdf = s.kdf,
                    iterations = s.kdf_iterations,
                    mib = s.kdf_memory_mib,
                    threads = s.kdf_parallelism
                )
            );
        }
        Cmd::Export {
            path,
            format,
            keyfile,
            password_stdin,
        } => match format {
            ExportArg::Csv => {
                call(
                    &mut c,
                    Request::ExportCsv {
                        path: abs(path.clone()),
                    },
                )?;
                println!(
                    "{}",
                    tr!(
                        "Выгружено в {path}. В файле пароли открытым текстом: удалите его после переноса.",
                        path = path.display()
                    )
                );
            }
            ExportArg::TwoFas => {
                call(
                    &mut c,
                    Request::ExportTwoFas {
                        path: abs(path.clone()),
                    },
                )?;
                println!(
                    "{}",
                    tr!(
                        "Коды 2FA выгружены в {path}. В файле секреты открытым текстом: удалите после импорта в 2FAS.",
                        path = path.display()
                    )
                );
            }
            ExportArg::Kdbx => {
                let password = if password_stdin {
                    Some(read_stdin_line()?)
                } else {
                    let a = prompt(tr!("Пароль копии: "))?;
                    if a.expose() != prompt(tr!("Ещё раз: "))?.expose() {
                        bail!(tr!("пароли не совпадают"));
                    }
                    Some(a)
                };
                call(
                    &mut c,
                    Request::SaveCopy {
                        path: abs(path.clone()),
                        key: KeySpec {
                            password,
                            keyfile: keyfile.map(abs),
                            yubikey: None,
                        },
                    },
                )?;
                println!(
                    "{}",
                    tr!("Копия сохранена в {path}.", path = path.display())
                );
            }
        },
        Cmd::Import {
            file,
            format,
            keyfile,
            password_stdin,
        } => {
            let ext = file
                .extension()
                .map(|e| e.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            let format = match format {
                Some(ImportArg::Csv) => ImportFormat::Csv,
                Some(ImportArg::Keepass) => ImportFormat::Keepass,
                Some(ImportArg::Bitwarden) => ImportFormat::Bitwarden,
                Some(ImportArg::TwoFas) => ImportFormat::TwoFas,
                None => match ext.as_str() {
                    "csv" => ImportFormat::Csv,
                    "kdbx" | "kdb" => ImportFormat::Keepass,
                    "json" => ImportFormat::Bitwarden,
                    "2fas" => ImportFormat::TwoFas,
                    _ => bail!(tr!("формат не понятен по расширению, укажите --format")),
                },
            };
            let key = (format == ImportFormat::Keepass)
                .then(|| -> Result<KeySpec> {
                    Ok(KeySpec {
                        password: Some(if password_stdin {
                            read_stdin_line()?
                        } else {
                            prompt(tr!("Пароль импортируемой базы: "))?
                        }),
                        keyfile: keyfile.map(abs),
                        yubikey: None,
                    })
                })
                .transpose()?;
            let Response::Imported { report: r } = call(
                &mut c,
                Request::ImportFile {
                    path: abs(file.clone()),
                    format,
                    key,
                },
            )?
            else {
                bail!(tr!("нет ответа"))
            };
            println!(
                "{}",
                tr!(
                    "Перенесено {n} записей в папку «Импорт {name}»: логины {logins}, карты {cards}, личные данные {identities}, заметки {notes}, ключи SSH {ssh}; папок {folders}",
                    n = r.total(),
                    name = file.file_stem().unwrap_or_default().to_string_lossy(),
                    logins = r.logins,
                    cards = r.cards,
                    identities = r.identities,
                    notes = r.notes,
                    ssh = r.ssh_keys,
                    folders = r.folders
                )
            );
            for x in &r.review {
                println!("{}", tr!("  проверить: {x}", x = x));
            }
        }
        Cmd::Merge {
            file,
            keyfile,
            password_stdin,
        } => {
            let password = if password_stdin {
                read_stdin_line()?
            } else {
                prompt(tr!("Пароль той копии: "))?
            };
            let Response::Merged { summary } = call(
                &mut c,
                Request::MergeFile {
                    path: abs(file),
                    key: KeySpec {
                        password: Some(password),
                        keyfile: keyfile.map(abs),
                        yubikey: None,
                    },
                },
            )?
            else {
                bail!(tr!("нет ответа"))
            };
            println!("{}", tr!("Слияние: {summary}", summary = summary));
        }
        Cmd::SshEnv => {
            let sock = keywarden_core::ipc::endpoint("ssh");
            if cfg!(windows) {
                // PowerShell; встроенный OpenSSH Windows понимает канал в SSH_AUTH_SOCK
                println!("$env:SSH_AUTH_SOCK = '{}'", sock.display());
            } else {
                println!("export SSH_AUTH_SOCK={}", sock.display());
            }
        }
        Cmd::Watch => {
            call(&mut c, Request::Subscribe)?;
            c.set_read_timeout(None)?;
            loop {
                if let Response::Event(e) = c.read()? {
                    println!("{}", serde_json::to_string(&e)?);
                }
            }
        }
    }
    Ok(())
}

/// Зашифрован ли ключ OpenSSH: имя шифра в заголовке не "none".
fn is_encrypted_openssh(pem: &[u8]) -> bool {
    let text = String::from_utf8_lossy(pem);
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let Ok(raw) = BASE64.decode(b64.trim().as_bytes()) else {
        return false;
    };
    // "openssh-key-v1\0" + u32 длина + имя шифра
    let rest = raw.strip_prefix(b"openssh-key-v1\0").unwrap_or_default();
    let len = rest
        .get(..4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .unwrap_or(0);
    rest.get(4..4 + len).is_some_and(|name| name != b"none")
}

fn search(c: &mut Client, query: &str, limit: usize) -> Result<Vec<EntrySummary>> {
    match call(
        c,
        Request::Search {
            query: query.into(),
            limit,
            filter: Default::default(),
        },
    )? {
        Response::Entries { entries } => Ok(entries),
        _ => bail!(tr!("нет ответа")),
    }
}

fn ssh_servers(c: &mut Client) -> Result<Vec<keywarden_core::ipc::SshHost>> {
    match call(c, Request::SshHosts)? {
        Response::SshHosts { hosts } => Ok(hosts),
        _ => bail!(tr!("нет ответа")),
    }
}

fn knock(c: &mut Client, alias: &str) -> Result<()> {
    call(c, Request::SshKnock { host: alias.into() }).map(|_| ())
}

/// База для экрана kw ssh: записи, правка поля «Хост», терминал из настроек.
struct TuiBackend<'a>(&'a mut Client);

impl ssh_tui::Backend for TuiBackend<'_> {
    fn entries(&mut self) -> Result<Vec<EntrySummary>> {
        search_kind(self.0, EntryKind::SshKey)
    }

    fn servers(&mut self) -> Result<Vec<keywarden_core::ipc::SshHost>> {
        ssh_servers(self.0)
    }

    fn knock(&mut self, alias: &str) -> Result<()> {
        knock(self.0, alias)
    }

    fn set_url(&mut self, id: &str, url: String) -> Result<()> {
        let patch = EntryPatch {
            set: vec![FieldSet::new("URL", url)],
            ..Default::default()
        };
        call(
            self.0,
            Request::Update {
                id: id.into(),
                patch,
            },
        )
        .map(|_| ())
    }

    fn terminal(&mut self) -> Vec<String> {
        match call(self.0, Request::Prefs { set: None }) {
            Ok(Response::Prefs { prefs }) => prefs.terminal,
            _ => vec![],
        }
    }
}

/// Заменить kw программой (ssh, sftp): тот же терминал, тот же код выхода.
fn exec(program: &str, args: &[String], note: Option<String>) -> Result<()> {
    if let Some(n) = note {
        eprintln!("{n}");
    }
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        Err(anyhow!(cmd.exec()).context(program.to_string()))
    }
    #[cfg(not(unix))]
    std::process::exit(
        cmd.status()
            .context(program.to_string())?
            .code()
            .unwrap_or(1),
    );
}

fn search_kind(c: &mut Client, kind: EntryKind) -> Result<Vec<EntrySummary>> {
    match call(
        c,
        Request::Search {
            query: String::new(),
            limit: 10_000,
            filter: keywarden_core::search::Filter {
                kind: Some(kind),
                ..Default::default()
            },
        },
    )? {
        Response::Entries { entries } => Ok(entries),
        _ => bail!(tr!("нет ответа")),
    }
}

fn groups(c: &mut Client) -> Result<Vec<GroupView>> {
    match call(c, Request::Groups)? {
        Response::Groups { groups } => Ok(groups),
        _ => bail!(tr!("нет ответа")),
    }
}

/// Запрос → одна запись: id, точное название, единственное совпадение или --first.
fn resolve(c: &mut Client, query: &str, pick: &Pick) -> Result<EntrySummary> {
    if uuid::Uuid::parse_str(query).is_ok()
        && let Response::Entry { entry } = call(
            c,
            Request::Get {
                id: query.into(),
                reveal: false,
            },
        )?
    {
        return Ok(entry.summary);
    }
    let hits = search(c, query, 20)?;
    let exact: Vec<_> = hits
        .iter()
        .filter(|e| e.title.eq_ignore_ascii_case(query))
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0].clone());
    }
    match hits.len() {
        0 => bail!(tr!("ничего не найдено по «{query}»", query = query)),
        1 => Ok(hits[0].clone()),
        _ if pick.first => Ok(hits[0].clone()),
        _ => {
            print_table(&hits);
            bail!(tr!(
                "несколько совпадений: уточните запрос, укажите id или добавьте --first"
            ))
        }
    }
}

fn edit_patch(c: &mut Client, a: &EditArgs) -> Result<EntryPatch> {
    let mut set = Vec::new();
    for (name, v) in [
        ("UserName", &a.username),
        ("URL", &a.url),
        ("Notes", &a.notes),
        ("otp", &a.otp),
    ] {
        if let Some(v) = v {
            set.push(FieldSet::new(name, v.as_str()));
        }
    }
    if a.password_prompt {
        set.push(FieldSet::new("Password", prompt(tr!("Пароль записи: "))?));
    } else if a.generate {
        let Response::Generated { generated } = call(
            c,
            Request::Generate {
                options: Generate::default(),
            },
        )?
        else {
            bail!(tr!("нет ответа"))
        };
        set.push(FieldSet::new("Password", generated.value));
    }
    for f in &a.fields {
        let (k, v) = f
            .split_once('=')
            .ok_or_else(|| anyhow!(tr!("--field ждёт ИМЯ=ЗНАЧЕНИЕ: {f}", f = f)))?;
        set.push(FieldSet::new(k.trim(), v));
    }
    for name in &a.secret_fields {
        set.push(FieldSet {
            name: name.clone(),
            value: prompt(&format!("{name}: "))?,
            protected: Some(true),
        });
    }
    let group = match &a.group {
        None => None,
        Some(path) => Some(
            groups(c)?
                .into_iter()
                .find(|g| g.path.eq_ignore_ascii_case(path.trim_matches('/')))
                .ok_or_else(|| {
                    anyhow!(tr!(
                        "нет группы «{path}» (создать: kw mkgroup {path})",
                        path = path
                    ))
                })?
                .id,
        ),
    };
    Ok(EntryPatch {
        kind: None,
        group,
        tags: (!a.tags.is_empty()).then(|| a.tags.clone()),
        set,
        remove: vec![],
        expires: a
            .expires
            .as_ref()
            .map(|v| (!v.is_empty() && v != "none").then(|| v.clone())),
        autotype: None,
    })
}

fn prompt(text: &str) -> Result<Secret> {
    Ok(Secret::new(
        rpassword::prompt_password(text).context(tr!("нужен терминал (или --password-stdin)"))?,
    ))
}

/// Все строки stdin (пароли для скриптов), исходный буфер обнуляется.
fn read_stdin_lines() -> Result<Vec<Secret>> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    let lines = s.lines().map(|l| Secret::new(l.to_string())).collect();
    drop(Secret::new(s));
    Ok(lines)
}

fn read_stdin_line() -> Result<Secret> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    let line = s.lines().next().unwrap_or_default().to_string();
    // обнуляем копию со всем stdin
    let secret = Secret::new(line);
    drop(Secret::new(s));
    Ok(secret)
}

fn abs(p: PathBuf) -> String {
    std::path::absolute(&p).unwrap_or(p).display().to_string()
}

fn print_table(entries: &[EntrySummary]) {
    let w = |f: fn(&EntrySummary) -> &str| {
        entries
            .iter()
            .map(|e| f(e).chars().count())
            .max()
            .unwrap_or(0)
            .min(32)
    };
    let (wt, wu, wg) = (w(|e| &e.title), w(|e| &e.username), w(|e| &e.group));
    for e in entries {
        let otp = if e.has_otp { "2FA" } else { "   " };
        println!(
            "{:<wt$}  {:<wu$}  {:<wg$}  {otp}  {}  {}",
            clip(&e.title, wt),
            clip(&e.username, wu),
            clip(&e.group, wg),
            &e.id[..8],
            e.url
        );
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        s.chars().take(n.saturating_sub(1)).chain(['…']).collect()
    }
}

fn print_entry(e: &EntryDetail) {
    println!("{}  [{}]", e.summary.title, e.summary.kind.label());
    if !e.summary.group.is_empty() {
        println!("{}", tr!("  группа: {group}", group = e.summary.group));
    }
    for f in &e.fields {
        let v = match &f.value {
            Some(v) => v.expose().to_string(),
            None => "••••••  (kw show -r)".into(),
        };
        println!("  {}: {v}", f.name);
    }
    if !e.notes.is_empty() {
        println!(
            "{}",
            tr!(
                "  заметки:\n    {notes}",
                notes = e.notes.replace('\n', "\n    ")
            )
        );
    }
    for a in &e.attachments {
        println!(
            "{}",
            tr!(
                "  вложение: {name} ({size} байт)",
                name = a.name,
                size = a.size
            )
        );
    }
    if !e.history.is_empty() {
        println!("{}", tr!("  версий в истории: {n}", n = e.history.len()));
    }
    println!("  id: {}", e.summary.id);
}
