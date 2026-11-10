//! `$XDG_CONFIG_HOME/keywarden/config.toml`

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// база, которую предлагать при разблокировке
    pub database: Option<PathBuf>,
    pub keyfile: Option<PathBuf>,
    /// YubiKey для базы из конфига: "2" или "2:серийный"
    pub yubikey: Option<String>,
    /// блокировка после N минут простоя, 0 = выключено
    pub autolock_minutes: u64,
    pub lock_on_screen_lock: bool,
    pub lock_on_sleep: bool,
    pub clipboard_clear_seconds: u64,
    pub backups_keep: usize,
    /// по умолчанию `$XDG_STATE_HOME/keywarden/backups`
    pub backups_dir: Option<PathBuf>,
    /// окно подтверждения (браузер, SSH); по умолчанию `keywarden-ui --confirm`.
    /// Код выхода: 11 разрешить всегда, 10 только сейчас, иначе отказ.
    pub confirm_command: Option<Vec<String>>,
    /// Secret Service (org.freedesktop.secrets): Keywarden как системная связка ключей
    pub secret_service: bool,
    /// папка базы, которую видят приложения через Secret Service
    pub secret_service_group: String,
    /// спрашивать, прежде чем отдать секрет приложению
    pub secret_service_confirm: bool,
    /// быстрая разблокировка: соль и открытый ключ PIN (сам PIN нигде не хранится)
    pub pin: Option<keywarden_core::quick::PinLock>,
    /// сколько часов после полной разблокировки работает PIN
    pub pin_hours: u64,
    pub notify_expiry: bool,
    pub notify_breaches: bool,
    /// когда последний раз проверяли утечки по расписанию (RFC 3339)
    pub last_breach_check: Option<String>,
    /// свои обозреватели блоков поверх стандартных: сеть -> шаблон с {address}
    pub explorers: std::collections::BTreeMap<String, String>,
    /// сразу сливать изменения файла базы от программ синхронизации
    pub sync_watch: bool,
    /// массовое удаление из входящей версии ждёт подтверждения
    pub sync_guard: bool,
    /// порядок типов в боковой панели окна
    pub kind_order: Vec<String>,
    /// SSH-агент отдаёт ключи из записей (выключен: ключей нет, окон нет)
    pub ssh_agent: bool,
    /// база заблокирована, а ssh просит ключ: показать окно разблокировки
    pub ssh_unlock_prompt: bool,
    /// ~/.ssh/keywarden/config: ключ под каждый хост (Include в ~/.ssh/config)
    pub ssh_host_config: bool,
    /// лаунчер: Enter на ключе SSH с хостом открывает терминал с ssh
    pub ssh_connect: bool,
    /// значок в трее (Linux, Windows)
    pub tray: bool,
    /// свой терминал для подключения, ssh дописывается в конец: ["kitty", "-e"]; пусто: найти самим
    pub terminal: Vec<String>,
    /// проверять новую версию на GitHub (выключено по умолчанию: без спроса в сеть не ходим)
    pub check_updates: bool,
    /// когда последний раз проверяли (RFC 3339)
    pub last_update_check: Option<String>,
    /// последний найденный тег релиза
    pub latest_release: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: None,
            keyfile: None,
            yubikey: None,
            autolock_minutes: 15,
            lock_on_screen_lock: true,
            lock_on_sleep: true,
            clipboard_clear_seconds: 30,
            backups_keep: 10,
            backups_dir: None,
            confirm_command: None,
            secret_service: false,
            secret_service_group: "Secret Service".into(),
            secret_service_confirm: true,
            pin: None,
            pin_hours: 24,
            notify_expiry: true,
            notify_breaches: false,
            last_breach_check: None,
            explorers: Default::default(),
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
            last_update_check: None,
            latest_release: None,
        }
    }
}

pub fn path() -> PathBuf {
    keywarden_core::ipc::config_file_for(keywarden_core::ipc::profile().as_deref())
}

impl Config {
    pub fn load_from(p: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(p) {
            Ok(s) => {
                let mut c: Config = toml::from_str(&s)?;
                c.database = c.database.map(|p| expand(&p));
                c.keyfile = c.keyfile.map(|p| expand(&p));
                c.backups_dir = c.backups_dir.map(|p| expand(&p));
                Ok(c)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save_to(&self, p: &Path) -> anyhow::Result<()> {
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        keywarden_core::vault::write_atomic(p, toml::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }
}

/// `~/x` → `$HOME/x`
pub fn expand(p: &Path) -> PathBuf {
    match (p.strip_prefix("~"), std::env::var_os("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => p.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c/config.toml");
        assert_eq!(Config::load_from(&p).unwrap().autolock_minutes, 15);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "database = \"/x/main.kdbx\"\nautolock_minutes = 5\n").unwrap();
        let c = Config::load_from(&p).unwrap();
        assert_eq!(c.database.as_deref(), Some(Path::new("/x/main.kdbx")));
        assert_eq!(c.autolock_minutes, 5);
        assert!(c.lock_on_sleep, "неуказанное берётся по умолчанию");
        c.save_to(&p).unwrap();
        assert_eq!(Config::load_from(&p).unwrap().autolock_minutes, 5);
    }
}
