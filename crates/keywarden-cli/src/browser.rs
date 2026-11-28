//! `kw browser-setup`: зарегистрировать мост keywarden-host у браузеров (native messaging).
//!
//! - Linux: файлы в ~/.mozilla/native-messaging-hosts (и каталогах форков) и
//!   ~/.config/<браузер>/NativeMessagingHosts; для браузеров из Flatpak копия моста и манифест
//!   кладутся внутрь ~/.var/app/<id>, песочнице выдаётся доступ к сокету демона.
//!   Firefox из Snap и Firefox 157+ во Flatpak с xdg-native-messaging-proxy берут обычный файл;
//! - macOS: ~/Library/Application Support/<браузер>/NativeMessagingHosts;
//! - Windows: файлы в %APPDATA%\Keywarden\native-messaging, пути к ним в реестре HKCU.
//!
//! Chromium-браузеры пускают только расширение с известным id: его даёт `--chrome-id`.

use anyhow::{Context, Result};
use keywarden_core::tr;
use std::path::{Path, PathBuf};

const NAME: &str = "dev.keywarden.host";
const FIREFOX_ID: &str = "keywarden@onokashino.github.io";

fn manifest(host: &Path, firefox: bool, chrome_id: &str) -> String {
    let allowed = if firefox {
        format!(r#""allowed_extensions": ["{FIREFOX_ID}"]"#)
    } else {
        format!(r#""allowed_origins": ["chrome-extension://{chrome_id}/"]"#)
    };
    format!(
        "{{\n  \"name\": \"{NAME}\",\n  \"description\": \"Keywarden native messaging host\",\n  \"path\": {},\n  \"type\": \"stdio\",\n  {allowed}\n}}\n",
        serde_json::to_string(&host.display().to_string()).expect("строка")
    )
}

/// Куда писать файл связи: каталог манифестов (или ключ реестра в Windows).
struct Target {
    name: &'static str,
    firefox: bool,
    place: String,
    /// писать, даже если каталога настроек браузера ещё нет
    always: bool,
    /// id приложения Flatpak: браузер в песочнице, мост кладём внутрь неё
    flatpak: Option<&'static str>,
}

impl Target {
    fn new(name: &'static str, firefox: bool, place: impl Into<String>) -> Self {
        Target {
            name,
            firefox,
            place: place.into(),
            always: false,
            flatpak: None,
        }
    }
}

/// Браузеры в Flatpak: (id, название, Firefox ли, каталоги манифестов от ~/.var/app/<id>).
const FLATPAK: &[(&str, &str, bool, &[&str])] = &[
    ("org.mozilla.firefox", "Firefox", true, &[".mozilla"]),
    (
        "io.gitlab.librewolf-community",
        "LibreWolf",
        true,
        &[".librewolf"],
    ),
    ("app.zen_browser.zen", "Zen", true, &[".zen", ".mozilla"]),
    ("net.waterfox.waterfox", "Waterfox", true, &[".waterfox"]),
    ("one.ablaze.floorp", "Floorp", true, &[".floorp"]),
    (
        "org.chromium.Chromium",
        "Chromium",
        false,
        &["config/chromium"],
    ),
    (
        "com.google.Chrome",
        "Chrome",
        false,
        &["config/google-chrome"],
    ),
    (
        "com.brave.Browser",
        "Brave",
        false,
        &["config/BraveSoftware/Brave-Browser"],
    ),
    (
        "com.microsoft.Edge",
        "Edge",
        false,
        &["config/microsoft-edge"],
    ),
    ("com.vivaldi.Vivaldi", "Vivaldi", false, &["config/vivaldi"]),
];

/// Копия моста внутри песочницы Flatpak: снаружи лежащий файл браузеру не виден.
fn flatpak_host(home: &Path, id: &str) -> PathBuf {
    home.join(".var/app")
        .join(id)
        .join("keywarden/keywarden-host")
}

/// Браузеры этой системы.
fn targets(home: &Path) -> Vec<Target> {
    if cfg!(windows) {
        return [
            ("Firefox", true, r"Software\Mozilla"),
            ("LibreWolf", true, r"Software\LibreWolf"),
            ("Waterfox", true, r"Software\Waterfox"),
            ("Chrome", false, r"Software\Google\Chrome"),
            ("Chromium", false, r"Software\Chromium"),
            ("Edge", false, r"Software\Microsoft\Edge"),
            ("Brave", false, r"Software\BraveSoftware\Brave-Browser"),
        ]
        .into_iter()
        .map(|(n, ff, key)| Target {
            always: true,
            ..Target::new(n, ff, format!(r"{key}\NativeMessagingHosts"))
        })
        .collect();
    }
    let mac = cfg!(target_os = "macos");
    let base = if mac {
        home.join("Library/Application Support")
    } else {
        home.join(".config")
    };
    let dir = |p: PathBuf| p.display().to_string();
    let mut v = Vec::new();
    // семейство Firefox: у каждого форка свой каталог, имя подкаталога зависит от системы
    let firefox: &[(&str, &str)] = if mac {
        &[
            ("Firefox", "Mozilla"),
            ("LibreWolf", "LibreWolf"),
            ("Waterfox", "Waterfox"),
            ("Zen", "zen"),
            ("Floorp", "Floorp"),
        ]
    } else {
        &[
            ("Firefox", ".mozilla"),
            // Firefox с настройками по XDG
            ("Firefox", ".config/mozilla"),
            ("LibreWolf", ".librewolf"),
            ("Waterfox", ".waterfox"),
            ("Zen", ".zen"),
            ("Floorp", ".floorp"),
        ]
    };
    for (i, (name, d)) in firefox.iter().enumerate() {
        let place = if mac {
            base.join(d).join("NativeMessagingHosts")
        } else {
            home.join(d).join("native-messaging-hosts")
        };
        v.push(Target {
            always: i == 0,
            ..Target::new(name, true, dir(place))
        });
    }
    let chromium: &[(&str, &str)] = if mac {
        &[
            ("Chrome", "Google/Chrome"),
            ("Chromium", "Chromium"),
            ("Edge", "Microsoft Edge"),
            ("Brave", "BraveSoftware/Brave-Browser"),
            ("Vivaldi", "Vivaldi"),
            ("Opera", "com.operasoftware.Opera"),
            ("Yandex", "Yandex/YandexBrowser"),
        ]
    } else {
        &[
            ("Chrome", "google-chrome"),
            ("Chromium", "chromium"),
            ("Edge", "microsoft-edge"),
            ("Brave", "BraveSoftware/Brave-Browser"),
            ("Vivaldi", "vivaldi"),
            ("Opera", "opera"),
            ("Yandex", "yandex-browser"),
        ]
    };
    for (name, d) in chromium {
        v.push(Target::new(
            name,
            false,
            dir(base.join(d).join("NativeMessagingHosts")),
        ));
    }
    if cfg!(target_os = "linux") {
        for (id, name, ff, dirs) in FLATPAK {
            let app = home.join(".var/app").join(id);
            if !app.exists() {
                continue;
            }
            for d in *dirs {
                let sub = if *ff {
                    "native-messaging-hosts"
                } else {
                    "NativeMessagingHosts"
                };
                v.push(Target {
                    always: true,
                    flatpak: Some(id),
                    ..Target::new(name, *ff, dir(app.join(d).join(sub)))
                });
            }
        }
    }
    v
}

fn host_path() -> Result<PathBuf> {
    Ok(std::env::current_exe()?
        .parent()
        .context(tr!("каталог kw"))?
        .join(format!("keywarden-host{}", std::env::consts::EXE_SUFFIX)))
}

fn home_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .context(tr!("нет домашнего каталога"))?,
    ))
}

/// Браузер установлен: есть его каталог настроек (у Flatpak и Firefox пишем всегда).
fn present(t: &Target) -> bool {
    t.always || Path::new(&t.place).parent().is_some_and(|p| p.exists())
}

/// Песочнице Flatpak нужен доступ к сокету демона, иначе мост внутри неё никуда не достучится.
fn flatpak_socket_arg() -> String {
    "--filesystem=xdg-run/keywarden:ro".into()
}

fn flatpak_allowed(id: &str) -> bool {
    std::process::Command::new("flatpak")
        .args(["override", "--user", "--show", id])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("xdg-run/keywarden"))
}

/// Разложить файлы связи для браузеров из `home`. Возвращает строки отчёта.
fn write_all(home: &Path, host: &Path, chrome_id: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for t in targets(home) {
        if (!t.firefox && chrome_id.is_empty()) || !present(&t) {
            continue;
        }
        let dir = PathBuf::from(&t.place);
        let host = match t.flatpak {
            Some(id) => {
                let copy = flatpak_host(home, id);
                std::fs::create_dir_all(copy.parent().expect("каталог копии"))?;
                std::fs::copy(host, &copy)?;
                copy
            }
            None => host.to_path_buf(),
        };
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join(format!("{NAME}.json")),
            manifest(&host, t.firefox, chrome_id),
        )?;
        out.push(match t.flatpak {
            Some(_) => format!("{} (Flatpak): {}", t.name, dir.display()),
            None => format!("{}: {}", t.name, dir.display()),
        });
    }
    Ok(out)
}

pub fn setup(chrome_id: Option<&str>, dir: Option<&Path>) -> Result<()> {
    let host = host_path()?;
    anyhow::ensure!(
        host.exists(),
        tr!(
            "нет {path}: keywarden-host должен лежать рядом с kw",
            path = host.display()
        )
    );
    let chrome_id = chrome_id.unwrap_or("");
    // браузер не из списка (портативная сборка, редкий форк): каталог манифестов называют сами
    if let Some(dir) = dir {
        std::fs::create_dir_all(dir)?;
        std::fs::write(
            dir.join(format!("{NAME}.json")),
            manifest(&host, chrome_id.is_empty(), chrome_id),
        )?;
        println!("{}", dir.display());
        return Ok(());
    }
    let home = home_dir()?;
    if cfg!(windows) {
        for t in targets(&home) {
            if !t.firefox && chrome_id.is_empty() {
                continue;
            }
            let file = windows_file(t.firefox);
            std::fs::create_dir_all(file.parent().expect("каталог манифеста"))?;
            std::fs::write(&file, manifest(&host, t.firefox, chrome_id))?;
            let key = format!(r"HKCU\{}\{NAME}", t.place);
            let ok = std::process::Command::new("reg")
                .args(["add", &key, "/ve", "/t", "REG_SZ", "/d"])
                .arg(&file)
                .arg("/f")
                .stdout(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            println!(
                "{}: {}",
                t.name,
                if ok {
                    tr!("готово")
                } else {
                    tr!("реестр не записан")
                }
            );
        }
    } else {
        for line in write_all(&home, &host, chrome_id)? {
            println!("{line}");
        }
        let mut ids: Vec<&str> = targets(&home)
            .iter()
            .filter(|t| t.firefox || !chrome_id.is_empty())
            .filter_map(|t| t.flatpak)
            .collect();
        ids.dedup();
        for id in ids {
            let ok = std::process::Command::new("flatpak")
                .args(["override", "--user", &flatpak_socket_arg(), id])
                .status()
                .is_ok_and(|s| s.success());
            if !ok {
                println!(
                    "{}",
                    tr!(
                        "{id}: доступ к Keywarden не выдан, выполните: flatpak override --user {arg} {id}",
                        id = id,
                        arg = flatpak_socket_arg()
                    )
                );
            }
        }
    }
    if chrome_id.is_empty() {
        println!(
            "{}",
            tr!(
                "Chrome, Edge, Brave: повторите с --chrome-id <id расширения> (chrome://extensions)"
            )
        );
    }
    Ok(())
}

fn windows_file(firefox: bool) -> PathBuf {
    keywarden_core::platform::config_dir()
        .join("native-messaging")
        .join(if firefox {
            "firefox.json"
        } else {
            "chromium.json"
        })
}

/// Что не так с файлом связи одного браузера; `None`: всё в порядке.
fn problem(home: &Path, host: &Path, t: &Target) -> Option<String> {
    let file = if cfg!(windows) {
        windows_file(t.firefox)
    } else {
        Path::new(&t.place).join(format!("{NAME}.json"))
    };
    let Ok(body) = std::fs::read_to_string(&file) else {
        // пакет дистрибутива кладёт файл для Firefox на всю систему
        let system = ["/usr/lib/mozilla", "/usr/lib64/mozilla"].iter().any(|d| {
            Path::new(d)
                .join(format!("native-messaging-hosts/{NAME}.json"))
                .exists()
        });
        if t.firefox && t.flatpak.is_none() && system {
            return None;
        }
        return Some(tr!("нет файла связи").into());
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        return Some(tr!("файл связи повреждён").into());
    };
    let path = PathBuf::from(v["path"].as_str().unwrap_or_default());
    let want = match t.flatpak {
        Some(id) => flatpak_host(home, id),
        None => host.to_path_buf(),
    };
    if !path.exists() {
        return Some(tr!(
            "файл связи указывает на {path}, а его нет",
            path = path.display()
        ));
    }
    if path != want {
        return Some(tr!(
            "файл связи указывает на другую установку: {path}",
            path = path.display()
        ));
    }
    if let Some(id) = t.flatpak {
        // копия в песочнице осталась от прошлой версии
        let len = |p: &Path| std::fs::metadata(p).map(|m| m.len()).ok();
        if len(&path) != len(host) {
            return Some(tr!("копия для Flatpak устарела").into());
        }
        if !flatpak_allowed(id) {
            return Some(tr!("у браузера нет доступа к Keywarden").into());
        }
    }
    None
}

/// `kw browser-setup --check`: по шагам показать, что мешает расширению достучаться до Keywarden.
pub fn check() -> Result<()> {
    let host = host_path()?;
    let home = home_dir()?;
    let mut bad = 0;
    let mut line = |ok: bool, what: String| {
        if !ok {
            bad += 1;
        }
        println!("{} {what}", if ok { "ok  " } else { "FAIL" });
    };
    line(host.exists(), format!("keywarden-host: {}", host.display()));
    match keywarden_core::ipc::call(&keywarden_core::ipc::Request::Ping) {
        Ok(keywarden_core::ipc::Response::Pong { version }) => {
            line(true, format!("keywardend {version}"))
        }
        _ => line(
            false,
            tr!("служба keywardend не отвечает: запустите Keywarden").into(),
        ),
    }
    for t in targets(&home) {
        if !present(&t) {
            continue;
        }
        let name = match t.flatpak {
            Some(_) => format!("{} (Flatpak)", t.name),
            None => t.name.to_string(),
        };
        match problem(&home, &host, &t) {
            None => line(true, name),
            // Chromium-браузеры без id расширения не настраиваются: это не поломка
            Some(_) if !t.firefox && !Path::new(&t.place).join(format!("{NAME}.json")).exists() => {
                println!("--   {name}: {}", tr!("не настроен, нужен --chrome-id"))
            }
            Some(why) => line(false, format!("{name}: {why}")),
        }
    }
    if cfg!(target_os = "linux") && home.join("snap/firefox").exists() {
        println!(
            "--   {}",
            tr!("Firefox из Snap: при первом подключении разрешите доступ в окне системы")
        );
    }
    anyhow::ensure!(bad == 0, tr!("Починить: kw browser-setup"));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn manifest_is_valid_json() {
        let m = super::manifest(
            std::path::Path::new(r"C:\Program Files\kw\keywarden-host.exe"),
            false,
            "abc",
        );
        let v: serde_json::Value = serde_json::from_str(&m).unwrap();
        assert_eq!(v["path"], r"C:\Program Files\kw\keywarden-host.exe");
        assert_eq!(v["allowed_origins"][0], "chrome-extension://abc/");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forks_and_flatpak_get_their_own_files() {
        use super::*;
        let home = std::env::temp_dir().join(format!("kw-browser-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        for d in [
            ".librewolf",
            ".config/vivaldi",
            ".var/app/org.mozilla.firefox",
        ] {
            std::fs::create_dir_all(home.join(d)).unwrap();
        }
        let host = home.join("keywarden-host");
        std::fs::write(&host, b"bin").unwrap();

        // без id расширения Chromium-браузеры пропускаются
        let done = write_all(&home, &host, "").unwrap();
        assert_eq!(done.len(), 3, "{done:?}");
        let read = |p: &str| -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(home.join(p)).unwrap()).unwrap()
        };
        let plain = read(".mozilla/native-messaging-hosts/dev.keywarden.host.json");
        assert_eq!(plain["path"], host.display().to_string());
        assert!(
            home.join(".librewolf/native-messaging-hosts/dev.keywarden.host.json")
                .exists()
        );
        // Zen не установлен: его каталог не создаём
        assert!(!home.join(".zen").exists());
        // во Flatpak манифест указывает на копию внутри песочницы
        let boxed = read(
            ".var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/dev.keywarden.host.json",
        );
        let copy = flatpak_host(&home, "org.mozilla.firefox");
        assert_eq!(boxed["path"], copy.display().to_string());
        assert_eq!(std::fs::read(&copy).unwrap(), b"bin");

        let done = write_all(&home, &host, "abc").unwrap();
        assert!(done.iter().any(|l| l.starts_with("Vivaldi")), "{done:?}");

        // проверка замечает сломанный файл и устаревшую копию
        let ts = targets(&home);
        let ff = ts.iter().find(|t| t.always && t.flatpak.is_none()).unwrap();
        assert!(problem(&home, &host, ff).is_none());
        std::fs::write(&copy, b"old-bin").unwrap();
        let fp = ts.iter().find(|t| t.flatpak.is_some()).unwrap();
        assert!(problem(&home, &host, fp).is_some());
        std::fs::remove_file(&host).unwrap();
        assert!(problem(&home, &host, ff).is_some());
        std::fs::remove_dir_all(&home).unwrap();
    }
}
