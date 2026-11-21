//! Какая тема сейчас у приложения. Файлы тем лежат в `themes_dir()`; окно читает их целиком,
//! а демон отдаёт цвета расширению браузера, чтобы оно выглядело так же, как приложение.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// имя темы из каталога, если `KEYWARDEN_THEME` не задана
pub const NOCTALIA: &str = "Noctalia";

pub fn themes_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("keywarden/themes")
}

pub fn wanted() -> String {
    std::env::var("KEYWARDEN_THEME").unwrap_or_else(|_| NOCTALIA.into())
}

/// Цвета выбранной темы из каталога: (`dark` | `light`, ключ темы → `#rrggbb[aa]`).
/// `None`: своей темы нет, приложение показывает встроенную.
pub fn active_colors() -> Option<(String, BTreeMap<String, String>)> {
    colors_in(&themes_dir(), &wanted())
}

fn colors_in(dir: &Path, name: &str) -> Option<(String, BTreeMap<String, String>)> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files.iter().find_map(|path| {
        // файл темы пишет сторонняя программа: больше мегабайта там быть нечему
        if std::fs::metadata(path).ok()?.len() > 1 << 20 {
            return None;
        }
        let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let theme = json["themes"]
            .as_array()?
            .iter()
            .find(|t| t["name"] == name)?;
        let mode = if theme["mode"] == "light" {
            "light"
        } else {
            "dark"
        };
        let colors = theme["colors"]
            .as_object()?
            .iter()
            .filter_map(|(k, v)| Some((k.clone(), v.as_str().filter(|c| is_hex(c))?.to_string())))
            .collect();
        Some((mode.to_string(), colors))
    })
}

/// только `#` и 3–8 шестнадцатеричных цифр: значение уходит в CSS расширения как есть
fn is_hex(c: &str) -> bool {
    c.strip_prefix('#').is_some_and(|h| {
        matches!(h.len(), 3 | 4 | 6 | 8) && h.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_named_theme_and_drops_what_is_not_a_color() {
        let dir = std::env::temp_dir().join(format!("kw-theme-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.json"), "не json").unwrap();
        std::fs::write(
            dir.join("b.json"),
            r##"{"themes":[{"name":"Other","colors":{"background":"#000000"}},
                {"name":"Noctalia","mode":"light","colors":{
                  "background":"#FAFAFA","border":"#11223344",
                  "bad":"red;} body{display:none","num":5,"long":"#123456789"}}]}"##,
        )
        .unwrap();
        let (mode, colors) = colors_in(&dir, "Noctalia").unwrap();
        assert_eq!(mode, "light");
        assert_eq!(colors.len(), 2);
        assert_eq!(colors["background"], "#FAFAFA");
        assert_eq!(colors["border"], "#11223344");
        assert!(colors_in(&dir, "Missing").is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
