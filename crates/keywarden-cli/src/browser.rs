//! `kw browser-setup`: зарегистрировать мост keywarden-host у браузеров (native messaging).
//!
//! - Linux: файлы в ~/.mozilla/native-messaging-hosts и ~/.config/<браузер>/NativeMessagingHosts;
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

/// Браузеры этой системы: (название, Firefox ли, каталог манифестов или ключ реестра).
fn targets(home: &Path) -> Vec<(&'static str, bool, String)> {
    if cfg!(windows) {
        vec![
            (
                "Firefox",
                true,
                r"Software\Mozilla\NativeMessagingHosts".into(),
            ),
            (
                "Chrome",
                false,
                r"Software\Google\Chrome\NativeMessagingHosts".into(),
            ),
            (
                "Chromium",
                false,
                r"Software\Chromium\NativeMessagingHosts".into(),
            ),
            (
                "Edge",
                false,
                r"Software\Microsoft\Edge\NativeMessagingHosts".into(),
            ),
            (
                "Brave",
                false,
                r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts".into(),
            ),
        ]
    } else {
        let base = if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            home.join(".config")
        };
        let firefox = if cfg!(target_os = "macos") {
            base.join("Mozilla/NativeMessagingHosts")
        } else {
            home.join(".mozilla/native-messaging-hosts")
        };
        let chromium = if cfg!(target_os = "macos") {
            vec![
                ("Chrome", "Google/Chrome"),
                ("Chromium", "Chromium"),
                ("Edge", "Microsoft Edge"),
                ("Brave", "BraveSoftware/Brave-Browser"),
            ]
        } else {
            vec![
                ("Chrome", "google-chrome"),
                ("Chromium", "chromium"),
                ("Edge", "microsoft-edge"),
                ("Brave", "BraveSoftware/Brave-Browser"),
            ]
        };
        let mut v = vec![("Firefox", true, firefox.display().to_string())];
        v.extend(chromium.into_iter().map(|(n, d)| {
            (
                n,
                false,
                base.join(d)
                    .join("NativeMessagingHosts")
                    .display()
                    .to_string(),
            )
        }));
        v
    }
}

pub fn setup(chrome_id: Option<&str>) -> Result<()> {
    let host = std::env::current_exe()?
        .parent()
        .context(tr!("каталог kw"))?
        .join(format!("keywarden-host{}", std::env::consts::EXE_SUFFIX));
    anyhow::ensure!(
        host.exists(),
        tr!(
            "нет {path}: keywarden-host должен лежать рядом с kw",
            path = host.display()
        )
    );
    let home = PathBuf::from(
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .context(tr!("нет домашнего каталога"))?,
    );
    let chrome_id = chrome_id.unwrap_or("");
    for (browser, firefox, place) in targets(&home) {
        if !firefox && chrome_id.is_empty() {
            continue;
        }
        let body = manifest(&host, firefox, chrome_id);
        if cfg!(windows) {
            let dir = keywarden_core::platform::config_dir().join("native-messaging");
            std::fs::create_dir_all(&dir)?;
            let file = dir.join(if firefox {
                "firefox.json"
            } else {
                "chromium.json"
            });
            std::fs::write(&file, body)?;
            let key = format!(r"HKCU\{place}\{NAME}");
            let ok = std::process::Command::new("reg")
                .args(["add", &key, "/ve", "/t", "REG_SZ", "/d"])
                .arg(&file)
                .arg("/f")
                .stdout(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            println!(
                "{browser}: {}",
                if ok {
                    tr!("готово")
                } else {
                    tr!("реестр не записан")
                }
            );
        } else {
            let dir = PathBuf::from(&place);
            // браузер не установлен: его каталога настроек нет
            if !firefox && !dir.parent().is_some_and(|p| p.exists()) {
                continue;
            }
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join(format!("{NAME}.json")), body)?;
            println!("{browser}: {}", dir.display());
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
}
