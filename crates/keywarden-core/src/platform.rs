//! Различия систем в одном месте: где лежат конфиг и временные файлы, как называются точки
//! подключения к демону и как открыть соединение.
//!
//! - Linux: `$XDG_CONFIG_HOME/keywarden`, `$XDG_RUNTIME_DIR/keywarden` (tmpfs), UNIX-сокеты;
//! - macOS: `~/Library/Application Support/Keywarden`, `$TMPDIR/keywarden` (личный каталог
//!   пользователя в /var/folders), UNIX-сокеты;
//! - Windows: `%APPDATA%\Keywarden`, `%LOCALAPPDATA%\Keywarden\run`, именованные каналы
//!   `\\.\pipe\keywarden-<пользователь>-<база>-<имя>` (демон пускает только своего пользователя).

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// Домашний каталог пользователя.
pub fn home() -> PathBuf {
    env_dir("HOME")
        .or_else(|| env_dir("USERPROFILE"))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Каталог настроек (без профиля).
pub fn config_dir() -> PathBuf {
    if cfg!(windows) {
        env_dir("APPDATA")
            .unwrap_or_else(|| home().join("AppData").join("Roaming"))
            .join("Keywarden")
    } else if cfg!(target_os = "macos") {
        home()
            .join("Library")
            .join("Application Support")
            .join("Keywarden")
    } else {
        env_dir("XDG_CONFIG_HOME")
            .unwrap_or_else(|| home().join(".config"))
            .join("keywarden")
    }
}

/// Каталог для сокетов и короткоживущих файлов (карточки для печати, просмотр вложений).
pub fn runtime_base() -> PathBuf {
    if cfg!(windows) {
        env_dir("LOCALAPPDATA")
            .unwrap_or_else(|| home().join("AppData").join("Local"))
            .join("Keywarden")
            .join("run")
    } else if cfg!(target_os = "macos") {
        // $TMPDIR на macOS свой у каждого пользователя и закрыт от остальных
        env_dir("TMPDIR")
            .unwrap_or_else(|| home().join("Library").join("Caches"))
            .join("keywarden")
    } else {
        env_dir("XDG_RUNTIME_DIR")
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", uid())))
            .join("keywarden")
    }
}

#[cfg(unix)]
fn uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    // без libc в ядре: владелец домашнего каталога, на Linux точнее /proc/self
    std::fs::metadata("/proc/self")
        .or_else(|_| std::fs::metadata(home()))
        .map(|m| m.uid())
        .unwrap_or(0)
}

#[cfg(not(unix))]
fn uid() -> u32 {
    0
}

/// Каталог, закрытый от других пользователей (0700 на UNIX; на Windows закрыт сам %LOCALAPPDATA%).
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Новый файл, который может читать только владелец (0600 на UNIX).
pub fn create_private_file(path: &Path) -> io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// Права 0600 у уже созданного файла (сокет); на Windows ничего не делает.
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Точка подключения `name` (daemon, api, ssh) демона базы `profile`.
pub fn endpoint(runtime_dir: &Path, profile: Option<&str>, name: &str) -> PathBuf {
    if cfg!(windows) {
        // каналы не лежат в файловой системе: имя включает пользователя и базу
        let user: String = std::env::var("USERNAME")
            .unwrap_or_default()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        let _ = runtime_dir;
        PathBuf::from(format!(
            r"\\.\pipe\keywarden-{user}-{}-{name}",
            profile.unwrap_or("default")
        ))
    } else {
        runtime_dir.join(format!("{name}.sock"))
    }
}

/// Клиентское соединение с демоном.
#[cfg(unix)]
pub type Conn = std::os::unix::net::UnixStream;
#[cfg(windows)]
pub type Conn = std::fs::File;

#[cfg(unix)]
pub fn connect(path: &Path) -> io::Result<Conn> {
    let s = std::os::unix::net::UnixStream::connect(path)?;
    // разблокировка с Argon2 256 МиБ занимает секунды, но не минуты
    s.set_read_timeout(Some(Duration::from_secs(120)))?;
    Ok(s)
}

#[cfg(windows)]
pub fn connect(path: &Path) -> io::Result<Conn> {
    // все экземпляры канала заняты (ERROR_PIPE_BUSY = 231): демон заводит новый сразу после
    // подключения, подождать немного
    for _ in 0..50 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        {
            Err(e) if e.raw_os_error() == Some(231) => {
                std::thread::sleep(Duration::from_millis(20))
            }
            r => return r,
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        crate::tr!("канал демона занят"),
    ))
}

/// Тайм-аут чтения ответа; у каналов Windows его нет, там вызов ничего не делает.
pub fn set_read_timeout(c: &Conn, t: Option<Duration>) -> io::Result<()> {
    #[cfg(unix)]
    {
        c.set_read_timeout(t)
    }
    #[cfg(windows)]
    {
        let _ = (c, t);
        Ok(())
    }
}

/// Возможности этой системы для подсказок в окне: (что, как работает или почему нет).
pub fn capabilities() -> Vec<(&'static str, String)> {
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let wayland = std::env::var_os("WAYLAND_DISPLAY").is_some();
    let niri = std::env::var_os("NIRI_SOCKET").is_some();
    let gnome = desktop.to_ascii_lowercase().contains("gnome");
    let mut v = vec![];
    if cfg!(windows) {
        v.push((crate::tr!("Система"), "Windows".to_string()));
        v.push((
            crate::tr!("Автоввод"),
            crate::tr!("работает в любом окне (набор через SendInput)").to_string(),
        ));
        v.push((
            crate::tr!("Лаунчер"),
            crate::tr!("ярлык «keywarden-ui --launcher»: Свойства, поле «Быстрый вызов», например Ctrl+Alt+K")
                .to_string(),
        ));
        v.push((
            crate::tr!("Буфер обмена"),
            crate::tr!("пароли не попадают в журнал Win+V и облачный буфер").to_string(),
        ));
    } else if cfg!(target_os = "macos") {
        v.push((crate::tr!("Система"), "macOS".to_string()));
        v.push((
            crate::tr!("Автоввод"),
            crate::tr!(
                "нужно разрешение «Универсальный доступ», для названия окна ещё «Запись экрана»"
            )
            .to_string(),
        ));
        v.push((
            crate::tr!("Лаунчер"),
            crate::tr!("«Быстрые команды»: команда «Запустить shell-скрипт» keywarden-ui --launcher и сочетание клавиш")
                .to_string(),
        ));
        v.push((
            crate::tr!("Буфер обмена"),
            crate::tr!("пароли помечены скрытыми: менеджеры истории их не сохраняют").to_string(),
        ));
    } else {
        let session = if niri {
            "niri".to_string()
        } else if !desktop.is_empty() {
            format!("{desktop}{}", if wayland { ", Wayland" } else { ", X11" })
        } else if wayland {
            "Wayland".into()
        } else {
            "X11".into()
        };
        v.push((crate::tr!("Система"), format!("Linux ({session})")));
        v.push((
            crate::tr!("Автоввод"),
            if niri {
                crate::tr!("работает (wtype)").to_string()
            } else if !wayland {
                crate::tr!("работает через xdotool (установите пакет xdotool)").to_string()
            } else if gnome {
                crate::tr!("GNOME под Wayland не даёт печатать в чужие окна; работает в niri, Sway и X11")
                    .to_string()
            } else {
                crate::tr!("печатает через wtype; запись выбирается в лаунчере, потому что активное окно сообщает только niri")
                    .to_string()
            },
        ));
        v.push((
            crate::tr!("Лаунчер"),
            if niri {
                crate::tr!("горячая клавиша в конфиге niri: spawn \"keywarden-ui\" \"--launcher\"").to_string()
            } else {
                crate::tr!("свою горячую клавишу на команду keywarden-ui --launcher задайте в настройках клавиатуры")
                    .to_string()
            },
        ));
        v.push((
            crate::tr!("Буфер обмена"),
            if wayland && gnome {
                crate::tr!("в GNOME очистка буфера идёт через XWayland").to_string()
            } else {
                crate::tr!("пароли помечены скрытыми и очищаются сами").to_string()
            },
        ));
    }
    if !cfg!(target_os = "linux") {
        v.push(("YubiKey", crate::tr!("пока только в Linux").to_string()));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_per_profile() {
        let dir = PathBuf::from("/run/user/1000/keywarden");
        let a = endpoint(&dir, None, "daemon");
        if cfg!(windows) {
            // каналы общие для всех баз: различает имя
            assert_ne!(a, endpoint(&dir, Some("work"), "daemon"));
        } else {
            // сокеты различает каталог базы (runtime_dir_for)
            assert_eq!(a, dir.join("daemon.sock"));
        }
        assert_ne!(a, endpoint(&dir, None, "ssh"));
    }
}
