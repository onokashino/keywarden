//! Открытая база: чтение, безопасное сохранение, создание.
//!
//! Правила записи:
//! - перед записью копия текущего файла в бэкапы (храним последние N);
//! - запись атомарная: временный файл рядом, fsync, rename, fsync каталога;
//! - сериализованный результат сначала расшифровывается обратно и сравнивается с памятью;
//! - если файл на диске изменился после открытия (Syncthing), не затираем его.

use crate::secret::Secret;
use keepass::config::{
    CompressionConfig, DatabaseConfig, InnerCipherConfig, KdfConfig, OuterCipherConfig,
};
use keepass::db::DatabaseOpenError;
use keepass::{Database, DatabaseKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("{}", crate::tr!("ошибка ввода-вывода: {e}", e = .0))]
    Io(#[from] io::Error),
    #[error("{}", crate::tr!("неверный пароль или файл-ключ"))]
    WrongKey,
    #[error("{}", crate::tr!("не задан ни пароль, ни файл-ключ"))]
    EmptyKey,
    #[error("YubiKey: {0}")]
    YubiKey(String),
    #[error("{}", crate::tr!("не удалось открыть базу: {e}", e = .0))]
    Open(String),
    #[error("{}", crate::tr!("не удалось сохранить базу: {e}", e = .0))]
    Save(String),
    #[error("{}", crate::tr!("сохранённая копия не совпала с базой в памяти, запись отменена"))]
    VerifyFailed,
    #[error("{}", crate::tr!("файл базы изменился на диске после открытия, нужно слияние"))]
    ChangedOnDisk,
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// Чем открывается база. Пароль, файл-ключ и YubiKey можно сочетать
/// (YubiKey только вместе с паролем или файлом-ключом, как требует keepass-rs).
#[derive(Clone, Default)]
pub struct Credentials {
    pub password: Option<Secret>,
    pub keyfile: Option<PathBuf>,
    pub challenge: Option<Challenge>,
}

/// Challenge-response HMAC-SHA1, как в KeePassXC.
#[derive(Clone, Debug, PartialEq)]
pub enum Challenge {
    /// слот 1 или 2; без серийного номера берётся первый найденный ключ
    YubiKey { slot: u8, serial: Option<u32> },
    /// секрет HMAC в hex вместо железа: для тестов и восстановления по сохранённому секрету
    Secret(String),
}

impl Challenge {
    /// "2" или "2:12345678", как `keepassxc-cli --yubikey`.
    pub fn parse_yubikey(s: &str) -> std::result::Result<Self, String> {
        let (slot, serial) = s
            .split_once(':')
            .map(|(a, b)| (a, Some(b)))
            .unwrap_or((s, None));
        let slot: u8 = slot
            .trim()
            .parse()
            .ok()
            .filter(|n| matches!(n, 1 | 2))
            .ok_or_else(|| crate::tr!("слот YubiKey 1 или 2, а не «{slot}»", slot = slot))?;
        let serial = serial
            .map(|s| {
                s.trim()
                    .parse::<u32>()
                    .map_err(|_| crate::tr!("серийный номер YubiKey не число: «{s}»", s = s))
            })
            .transpose()?;
        Ok(Self::YubiKey { slot, serial })
    }
}

/// Подключённые YubiKey (серийный номер и имя).
pub fn yubikeys() -> std::result::Result<Vec<(u32, Option<String>)>, String> {
    #[cfg(target_os = "linux")]
    return keepass::ChallengeResponseKey::get_available_yubikeys()
        .map(|v| {
            v.into_iter()
                .map(|y| (y.serial_number, y.name.clone()))
                .collect()
        })
        .map_err(|e| e.to_string());
    #[cfg(not(target_os = "linux"))]
    crate::yubikey::list()
}

/// Linux: USB-путь библиотеки keepass (ключ выбирается по серийному номеру).
#[cfg(target_os = "linux")]
fn yubikey_key(slot: u8, serial: Option<u32>) -> Result<keepass::ChallengeResponseKey> {
    let serial = match serial {
        Some(s) => s,
        None => yubikeys()
            .map_err(VaultError::YubiKey)?
            .first()
            .map(|y| y.0)
            .ok_or_else(|| {
                VaultError::YubiKey(crate::tr!("YubiKey не найден: вставьте ключ").into())
            })?,
    };
    let yk = keepass::Yubikey {
        serial_number: serial,
        name: None,
    };
    Ok(keepass::ChallengeResponseKey::YubikeyChallenge(
        yk,
        slot.to_string(),
    ))
}

/// Windows и macOS: системный HID (`crate::yubikey`), ключ опрашивается при открытии и сохранении.
#[cfg(not(target_os = "linux"))]
fn yubikey_key(slot: u8, serial: Option<u32>) -> Result<keepass::ChallengeResponseKey> {
    Ok(keepass::ChallengeResponseKey::External(
        keepass::ExternalChallenge(std::sync::Arc::new(move |c: &[u8]| {
            crate::yubikey::challenge(serial, slot, c)
        })),
    ))
}

impl Credentials {
    /// Открывают ли эти ключи файл базы (Argon2, секунда: вызывать вне блокировки демона).
    pub fn verify(&self, path: &Path) -> Result<()> {
        parse(&fs::read(path)?, &self.key()?).map(|_| ())
    }

    fn key(&self) -> Result<DatabaseKey> {
        let mut key = DatabaseKey::new();
        if let Some(p) = &self.password {
            key = key.with_password(p.expose());
        }
        if let Some(kf) = &self.keyfile {
            key = key.with_keyfile(&mut File::open(kf)?)?;
        }
        if key.is_empty() {
            return Err(VaultError::EmptyKey);
        }
        match &self.challenge {
            None => {}
            Some(Challenge::Secret(hex)) => {
                key = key.with_challenge_response_key(
                    keepass::ChallengeResponseKey::LocalChallenge(hex.clone()),
                );
            }
            Some(Challenge::YubiKey { slot, serial }) => {
                key = key.with_challenge_response_key(yubikey_key(*slot, *serial)?);
            }
        }
        Ok(key)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cipher {
    #[default]
    Aes256,
    ChaCha20,
}

pub struct Vault {
    pub db: Database,
    key: DatabaseKey,
    path: PathBuf,
    /// sha256 файла, каким мы его последний раз читали или писали
    disk_hash: [u8; 32],
    pub backups: Backups,
}

#[derive(Debug, Clone)]
pub struct Backups {
    pub dir: PathBuf,
    pub keep: usize,
}

impl Backups {
    /// `$XDG_STATE_HOME/keywarden/backups/<имя>-<хэш пути>`: вне папки Syncthing, чтобы бэкапы не синхронизировались.
    pub fn default_for(db_path: &Path) -> Self {
        let state = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let canon = fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf());
        let tag = hex8(&Sha256::digest(canon.as_os_str().as_encoded_bytes()));
        let stem = db_path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            dir: state
                .join("keywarden/backups")
                .join(format!("{stem}-{tag}")),
            keep: 10,
        }
    }
}

impl Vault {
    pub fn open(path: impl Into<PathBuf>, creds: &Credentials) -> Result<Self> {
        let path = path.into();
        let key = creds.key()?;
        let bytes = fs::read(&path)?;
        let db = parse(&bytes, &key)?;
        Ok(Self {
            backups: Backups::default_for(&path),
            db,
            key,
            disk_hash: Sha256::digest(&bytes).into(),
            path,
        })
    }

    /// Новая база KDBX 4: Argon2id, внутренний шифр ChaCha20. Файл не должен существовать.
    pub fn create(
        path: impl Into<PathBuf>,
        creds: &Credentials,
        cipher: Cipher,
        kdf: KdfConfig,
    ) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            return Err(VaultError::Io(io::Error::new(
                io::ErrorKind::AlreadyExists,
                path.display().to_string(),
            )));
        }
        let mut config = DatabaseConfig::default();
        config.outer_cipher_config = match cipher {
            Cipher::Aes256 => OuterCipherConfig::AES256,
            Cipher::ChaCha20 => OuterCipherConfig::ChaCha20,
        };
        config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        config.compression_config = CompressionConfig::GZip;
        config.kdf_config = kdf;
        let mut db = Database::with_config(config);
        db.root_mut().name = "Root".into();
        db.meta.generator = Some("Keywarden".into());

        let bytes = serialize(&db, &creds.key()?)?;
        write_atomic(&path, &bytes)?;
        Self::open(path, creds)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Изменился ли файл на диске с момента открытия или последнего сохранения.
    pub fn changed_on_disk(&self) -> Result<bool> {
        Ok(Sha256::digest(fs::read(&self.path)?).as_slice() != self.disk_hash)
    }

    pub fn save(&mut self) -> Result<()> {
        let hash = self.save_job().run()?;
        self.disk_hash = hash;
        Ok(())
    }

    /// Снимок для сохранения вне блокировки: Argon2 при записи и проверке занимает секунды,
    /// и демон в это время продолжает отвечать на поиск.
    pub fn save_job(&self) -> SaveJob {
        SaveJob {
            db: self.db.clone(),
            key: self.key.clone(),
            path: self.path.clone(),
            expected_disk_hash: self.disk_hash,
            backups: self.backups.clone(),
        }
    }

    /// Последний шанс не потерять правки (блокировка при неудавшемся сохранении): та же база тем же
    /// ключом рядом с бэкапами, `<имя>.unsaved-<время>.kdbx`. Открывается в KeePassXC как обычная база.
    pub fn write_recovery(&self) -> Result<PathBuf> {
        crate::platform::create_private_dir(&self.backups.dir)?;
        let stem = self.path.file_stem().unwrap_or_default().to_string_lossy();
        let dst = self.backups.dir.join(format!(
            "{stem}.unsaved-{}.kdbx",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        write_atomic(&dst, &serialize(&self.db, &self.key)?)?;
        Ok(dst)
    }

    /// Отметить, что на диске теперь файл с этим хэшем (после `SaveJob::run`).
    pub fn mark_saved(&mut self, disk_hash: [u8; 32]) {
        self.disk_hash = disk_hash;
    }

    /// Чтение файла с диска тем же ключом вне блокировки демона (Argon2 занимает время).
    pub fn reader(&self) -> DiskReader {
        DiskReader {
            key: self.key.clone(),
            path: self.path.clone(),
        }
    }

    pub fn disk_hash(&self) -> [u8; 32] {
        self.disk_hash
    }

    /// Файл базы теперь в другом месте (после `DiskReader::write_verified`).
    pub fn set_location(&mut self, path: PathBuf, disk_hash: [u8; 32]) {
        self.path = path;
        self.disk_hash = disk_hash;
    }

    /// Новый ключ для следующих сохранений. Возвращает старый, чтобы откатиться,
    /// если запись с новым ключом не удалась: тогда на диске по-прежнему старый.
    pub fn replace_key(&mut self, creds: &Credentials) -> Result<DatabaseKey> {
        let key = creds.key()?;
        self.db.meta.master_key_changed = Some(keepass::db::Times::now());
        Ok(std::mem::replace(&mut self.key, key))
    }

    pub fn restore_key(&mut self, key: DatabaseKey) {
        self.key = key;
    }

    /// Копия базы другим ключом в другой файл (перенос, резервная копия): та же проверка
    /// расшифровкой, что и при обычном сохранении. Существующий файл не затирается.
    pub fn save_copy(&self, path: &Path, creds: &Credentials) -> Result<()> {
        save_copy_of(&self.db, path, creds)
    }
}

/// Другая база (.kdbx или старая .kdb) для импорта или слияния.
pub fn open_other(path: &Path, creds: &Credentials) -> Result<Database> {
    parse(&fs::read(path)?, &creds.key()?)
}

/// То же, что `Vault::save_copy`, по снимку базы: Argon2 идёт без блокировки демона.
pub fn save_copy_of(db: &Database, path: &Path, creds: &Credentials) -> Result<()> {
    if path.exists() {
        return Err(VaultError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            path.display().to_string(),
        )));
    }
    let key = creds.key()?;
    let bytes = serialize(db, &key)?;
    let back = parse(&bytes, &key)?;
    let mut mine = db.clone();
    mine.remove_unused_attachments();
    mine.rebuild_custom_icon_refs();
    if back != mine {
        return Err(VaultError::VerifyFailed);
    }
    write_atomic(path, &bytes)?;
    Ok(())
}

/// Файл-ключ в формате KeePassXC (XML 2.0): 32 случайных байта и контрольная сумма.
/// Существующий файл не затирается: потерять файл-ключ значит потерять базу.
pub fn generate_keyfile(path: &Path) -> io::Result<()> {
    use rand_core06::RngCore;
    let mut key = [0u8; 32];
    rand_core06::OsRng.fill_bytes(&mut key);
    let hex = data_encoding::HEXUPPER.encode(&key);
    let check = data_encoding::HEXUPPER.encode(&Sha256::digest(key)[..4]);
    let groups: Vec<&str> = (0..hex.len()).step_by(8).map(|i| &hex[i..i + 8]).collect();
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<KeyFile>\n    <Meta>\n        <Version>2.0</Version>\n    </Meta>\n    <Key>\n        <Data Hash=\"{check}\">\n            {}\n            {}\n        </Data>\n    </Key>\n</KeyFile>\n",
        groups[..4].join(" "),
        groups[4..].join(" "),
    );
    key.fill(0);
    let mut f = open_new(path, 0o600)?;
    f.write_all(xml.as_bytes())?;
    f.sync_all()
}

#[derive(Clone)]
pub struct DiskReader {
    key: DatabaseKey,
    path: PathBuf,
}

impl DiskReader {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Текущий файл базы и его sha256.
    pub fn read(&self) -> Result<(Database, [u8; 32])> {
        let bytes = fs::read(&self.path)?;
        Ok((parse(&bytes, &self.key)?, Sha256::digest(&bytes).into()))
    }

    pub fn hash_on_disk(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(fs::read(&self.path)?).into())
    }

    /// Записать базу тем же ключом в новый файл и проверить чтением. Возвращает sha256 файла.
    pub fn write_verified(&self, db: &Database, path: &Path) -> Result<[u8; 32]> {
        let bytes = serialize(db, &self.key)?;
        parse(&bytes, &self.key)?;
        write_atomic(path, &bytes)?;
        if Sha256::digest(fs::read(path)?).as_slice() != Sha256::digest(&bytes).as_slice() {
            return Err(VaultError::VerifyFailed);
        }
        Ok(Sha256::digest(&bytes).into())
    }

    /// Зашифрованный тем же ключом снимок базы в каталоге копий: `<имя>.presync-<время>.kdbx`.
    /// По нему отменяется слияние; открывается в KeePassXC как обычная база.
    pub fn write_snapshot(&self, db: &Database, dir: &Path) -> Result<String> {
        crate::platform::create_private_dir(dir)?;
        let stem = self.path.file_stem().unwrap_or_default().to_string_lossy();
        let name = format!(
            "{stem}.presync-{}.kdbx",
            chrono::Local::now().format("%Y%m%d-%H%M%S%.3f")
        );
        write_atomic(&dir.join(&name), &serialize(db, &self.key)?)?;
        Ok(name)
    }

    /// Конфликтные копии рядом с базой: Syncthing `<имя>.sync-conflict-<дата>-<устройство>.kdbx`,
    /// Nextcloud `<имя> (conflicted copy <дата>).kdbx`, Dropbox `<имя> (… conflicted copy …).kdbx`.
    pub fn conflict_files(&self) -> Vec<PathBuf> {
        let (Some(dir), Some(stem)) = (self.path.parent(), self.path.file_stem()) else {
            return vec![];
        };
        let stem = stem.to_string_lossy().into_owned();
        let mut v: Vec<PathBuf> = fs::read_dir(if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        })
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().is_some_and(|n| {
                let n = n.to_string_lossy();
                let Some(rest) = n.strip_prefix(&stem) else {
                    return false;
                };
                n.ends_with(".kdbx")
                    && (rest.starts_with(".sync-conflict-")
                        || (rest.starts_with(" (")
                            && (rest.contains("conflicted copy") || rest.contains("conflict"))))
            })
        })
        .collect();
        v.sort();
        v
    }

    pub fn parse_file(&self, path: &Path) -> Result<Database> {
        parse(&fs::read(path)?, &self.key)
    }
}

pub struct SaveJob {
    db: Database,
    key: DatabaseKey,
    path: PathBuf,
    expected_disk_hash: [u8; 32],
    backups: Backups,
}

impl SaveJob {
    /// Проверка внешних изменений → сериализация → проверка расшифровкой → бэкап → атомарная запись.
    /// Возвращает sha256 записанного файла.
    pub fn run(self) -> Result<[u8; 32]> {
        if Sha256::digest(fs::read(&self.path)?).as_slice() != self.expected_disk_hash {
            return Err(VaultError::ChangedOnDisk);
        }
        let bytes = serialize(&self.db, &self.key)?;
        // Перечитываем то, что собираемся записать: запись в keepass-rs экспериментальная.
        let back = parse(&bytes, &self.key)?;
        // обратные ссылки (вложения, иконки) в памяти могут отставать от правок с историей;
        // на диск они не пишутся, поэтому сравниваем в пересобранном виде
        let mut mine = self.db.clone();
        mine.remove_unused_attachments();
        mine.rebuild_custom_icon_refs();
        if back != mine {
            return Err(VaultError::VerifyFailed);
        }
        self.backup()?;
        write_atomic(&self.path, &bytes)?;
        Ok(Sha256::digest(&bytes).into())
    }

    fn backup(&self) -> Result<()> {
        if !self.path.exists() || self.backups.keep == 0 {
            return Ok(());
        }
        crate::platform::create_private_dir(&self.backups.dir)?;
        let stem = self.path.file_stem().unwrap_or_default().to_string_lossy();
        let ts = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f");
        let dst = self.backups.dir.join(format!("{stem}.{ts}.kdbx"));
        write_atomic(&dst, &fs::read(&self.path)?)?;

        let mut all: Vec<PathBuf> = fs::read_dir(&self.backups.dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "kdbx"))
            .collect();
        all.sort(); // имена с меткой времени сортируются хронологически
        let extra = all.len().saturating_sub(self.backups.keep);
        for old in &all[..extra] {
            fs::remove_file(old)?;
        }
        Ok(())
    }
}

/// Парсер keepass-rs не заполняет обратные ссылки вложений (`Attachment.entries`). Без них удаление
/// вложения у текущей версии записи стирает его и из истории, поэтому пересобираем их сразу.
fn parse(bytes: &[u8], key: &DatabaseKey) -> Result<Database> {
    let mut db = Database::parse(bytes, key.clone()).map_err(open_error)?;
    // keepass-rs записывает только KDBX 4.1: старые KDBX 3.1 и 4.0 при сохранении станут 4.1
    // (шифр, KDF и содержимое те же). Их читают KeePassXC 2.7+, KeePass 2.48+, KeePassDX, KeePassium.
    if matches!(
        db.config.version,
        keepass::config::DatabaseVersion::KDB3(_) | keepass::config::DatabaseVersion::KDB4(0)
    ) {
        db.config.version = keepass::config::DatabaseVersion::KDB4(1);
    }
    db.remove_unused_attachments();
    db.rebuild_custom_icon_refs();
    Ok(db)
}

fn serialize(db: &Database, key: &DatabaseKey) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    db.save(&mut buf, key.clone())
        .map_err(|e| VaultError::Save(e.to_string()))?;
    Ok(buf)
}

fn open_error(e: DatabaseOpenError) -> VaultError {
    use keepass::db::DatabaseOpenError as E;
    match e {
        // DatabaseKeyError в keepass-rs не экспортируется, различаем по тексту
        E::Key(k) if k.to_string() == "Incorrect key" => VaultError::WrongKey,
        E::Key(k) if k.to_string().contains("hallenge") => VaultError::YubiKey(k.to_string()),
        E::Io(io) => VaultError::Io(io),
        other => VaultError::Open(other.to_string()),
    }
}

/// Временный файл в том же каталоге → fsync → rename → fsync каталога.
/// Права исходного файла сохраняются, новый файл получает 0600.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.kw-tmp-{}", std::process::id()));
    #[cfg(unix)]
    let mode = fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o600);
    #[cfg(not(unix))]
    let mode = 0o600;

    let res = (|| {
        let mut f = open_new(&tmp, mode)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        // каталог тоже, иначе после сбоя питания rename может «откатиться»
        // (на Windows каталог так не открыть, там переименование и так в журнале NTFS)
        #[cfg(unix)]
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Новый файл (ошибка, если уже есть) с правами `mode` на UNIX.
fn open_new(path: &Path, mode: u32) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    o.mode(mode);
    #[cfg(not(unix))]
    let _ = mode;
    o.open(path)
}

/// Argon2id с 256 МиБ памяти; число итераций подбирается так, чтобы разблокировка шла около `target`.
pub fn tuned_kdf(target: Duration) -> KdfConfig {
    const MEM_KIB: u32 = 256 * 1024;
    const LANES: u32 = 2;
    let cfg = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: MEM_KIB,
        time_cost: 1,
        lanes: LANES,
        thread_mode: argon2::ThreadMode::Parallel,
        hash_length: 32,
        ad: &[],
        secret: &[],
    };
    let start = Instant::now();
    let _ = argon2::hash_raw(b"benchmark", b"keywarden-bench-salt", &cfg);
    let one = start.elapsed().max(Duration::from_millis(1));
    let iterations = (target.as_secs_f64() / one.as_secs_f64()).floor().max(2.0) as u64;
    KdfConfig::Argon2id {
        iterations,
        memory: MEM_KIB as u64 * 1024,
        parallelism: LANES,
        version: argon2::Version::Version13,
    }
}

/// Дешёвый KDF для тестов. В рабочих базах не использовать.
pub fn test_kdf() -> KdfConfig {
    KdfConfig::Argon2id {
        iterations: 1,
        memory: 1024 * 1024,
        parallelism: 1,
        version: argon2::Version::Version13,
    }
}

fn hex8(bytes: &[u8]) -> String {
    bytes[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::fields;

    fn creds() -> Credentials {
        Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: None,
        }
    }

    #[test]
    fn change_key_and_keyfile() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path());
        let kf = dir.path().join("k.keyx");
        generate_keyfile(&kf).unwrap();
        assert!(generate_keyfile(&kf).is_err(), "файл-ключ не затирается");
        let new = Credentials {
            password: Some("новый".into()),
            keyfile: Some(kf.clone()),
            challenge: None,
        };
        assert!(creds().verify(v.path()).is_ok());
        assert!(matches!(new.verify(v.path()), Err(VaultError::WrongKey)));
        let old = v.replace_key(&new).unwrap();
        v.save().unwrap();
        assert!(new.verify(v.path()).is_ok(), "открывается новым ключом");
        assert!(matches!(
            creds().verify(v.path()),
            Err(VaultError::WrongKey)
        ));
        // откат на старый ключ тоже сохраняется
        v.restore_key(old);
        v.db.meta.database_name = Some("x".into());
        v.save().unwrap();
        assert!(creds().verify(v.path()).is_ok());

        let copy = dir.path().join("copy.kdbx");
        v.save_copy(&copy, &new).unwrap();
        assert!(new.verify(&copy).is_ok());
        assert!(v.save_copy(&copy, &new).is_err(), "копия не затирает файл");
    }

    fn new_vault(dir: &Path) -> Vault {
        let mut v =
            Vault::create(dir.join("db.kdbx"), &creds(), Cipher::ChaCha20, test_kdf()).unwrap();
        v.backups = Backups {
            dir: dir.join("bak"),
            keep: 3,
        };
        v
    }

    #[test]
    fn create_save_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path());
        v.db.root_mut()
            .add_entry()
            .set_protected(fields::PASSWORD, "s3cr3t");
        v.save().unwrap();

        let v2 = Vault::open(dir.path().join("db.kdbx"), &creds()).unwrap();
        assert_eq!(v2.db, v.db);
        assert!(matches!(
            Vault::open(
                dir.path().join("db.kdbx"),
                &Credentials {
                    password: Some("nope".into()),
                    keyfile: None,
                    challenge: None
                }
            ),
            Err(VaultError::WrongKey)
        ));
    }

    #[test]
    fn backups_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path());
        for _ in 0..5 {
            v.db.root_mut().add_entry();
            v.save().unwrap();
        }
        assert_eq!(fs::read_dir(dir.path().join("bak")).unwrap().count(), 3);
    }

    #[test]
    fn refuses_to_clobber_external_change() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(dir.path());
        let other = fs::read(v.path()).unwrap();
        // Syncthing подменил файл: тот же формат, другие байты
        let mut changed = Vault::open(v.path().to_path_buf(), &creds()).unwrap();
        changed.backups = v.backups.clone();
        changed.db.root_mut().add_entry();
        changed.save().unwrap();
        assert_ne!(fs::read(v.path()).unwrap(), other);

        v.db.root_mut().add_entry();
        assert!(matches!(v.save(), Err(VaultError::ChangedOnDisk)));
    }

    #[test]
    fn keyfile_and_password() {
        let dir = tempfile::tempdir().unwrap();
        let kf = dir.path().join("key.keyx");
        fs::write(&kf, b"some random keyfile bytes").unwrap();
        let c = Credentials {
            password: Some("pw".into()),
            keyfile: Some(kf.clone()),
            challenge: None,
        };
        Vault::create(dir.path().join("k.kdbx"), &c, Cipher::Aes256, test_kdf()).unwrap();
        assert!(Vault::open(dir.path().join("k.kdbx"), &c).is_ok());
        assert!(matches!(
            Vault::open(dir.path().join("k.kdbx"), &creds()),
            Err(VaultError::WrongKey)
        ));
    }

    #[test]
    fn challenge_response_is_required() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "0123456789abcdef0123456789abcdef01234567".to_string();
        let with = Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: Some(Challenge::Secret(secret)),
        };
        let mut v =
            Vault::create(dir.path().join("y.kdbx"), &with, Cipher::Aes256, test_kdf()).unwrap();
        v.backups = Backups {
            dir: dir.path().join("bak"),
            keep: 2,
        };
        v.db.root_mut().add_entry();
        v.save().unwrap(); // каждое сохранение снова спрашивает ключ (новая соль)
        assert!(Vault::open(dir.path().join("y.kdbx"), &with).is_ok());
        assert!(
            Vault::open(dir.path().join("y.kdbx"), &creds()).is_err(),
            "без YubiKey не открывается"
        );
        let wrong = Credentials {
            challenge: Some(Challenge::Secret("ff".repeat(20))),
            ..with.clone()
        };
        assert!(matches!(
            Vault::open(dir.path().join("y.kdbx"), &wrong),
            Err(VaultError::WrongKey)
        ));
        assert_eq!(
            Challenge::parse_yubikey("2:123").unwrap(),
            Challenge::YubiKey {
                slot: 2,
                serial: Some(123)
            }
        );
        assert!(Challenge::parse_yubikey("3").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_keeps_mode() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("f");
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        write_atomic(&p, b"new").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "временный файл не должен оставаться"
        );
    }
}
