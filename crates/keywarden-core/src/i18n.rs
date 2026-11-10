//! Перевод интерфейса в стиле gettext: ключ - русская строка прямо в коде (`tr!("Сохранить")`),
//! переводы лежат в `locales/<язык>/*.json` (объект «русская строка: перевод»).
//!
//! - Язык: `KEYWARDEN_LANG`, иначе файл `<config_dir>/language`, иначе язык системы.
//! - Языки находятся сами: каждая папка `locales/<код>/` (см. build.rs и docs/translating.md).
//! - Английский каталог полный (это проверяет тест) и служит образцом для переводчиков; в других
//!   языках непереведённое показывается по-английски, а не по-русски.
//! - Подстановки: `tr!("Удалено {n} из {all}", n = 3, all = 10)`; плейсхолдеры одинаковы в
//!   русском ключе и в переводе (тоже проверяется тестом).
//! - Контекст: одно русское слово бывает разным по смыслу («Логин» как тип записи и как поле).
//!   `tr!("поле§Логин")` показывает по-русски «Логин», а переводится отдельным ключом.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

include!(concat!(env!("OUT_DIR"), "/catalogs.rs"));

/// Язык строк в исходном коде.
pub const SOURCE: &str = "ru";
/// Образец для переводчиков и запасной язык.
pub const FALLBACK: &str = "en";

/// Все языки интерфейса: (код, название на нём самом). Английский и русский первыми.
pub fn languages() -> Vec<(&'static str, &'static str)> {
    let mut v: Vec<(&'static str, &'static str)> =
        CATALOGS.iter().map(|(c, n, _)| (*c, *n)).collect();
    if !v.iter().any(|(c, _)| *c == SOURCE) {
        v.push((SOURCE, "Русский"));
    }
    let rank = |c: &str| match c {
        FALLBACK => 0,
        SOURCE => 1,
        _ => 2,
    };
    v.sort_by(|a, b| rank(a.0).cmp(&rank(b.0)).then(a.1.cmp(b.1)));
    v
}

/// Название языка на нём самом.
pub fn native_name(code: &str) -> &'static str {
    languages()
        .into_iter()
        .find(|(c, _)| *c == code)
        .map_or("?", |(_, n)| n)
}

/// Код из настроек или системы (`de_DE.UTF-8`, `pt-BR`) -> известный язык: сначала точное
/// совпадение (pt-BR), потом по основному коду (de).
pub fn parse(s: &str) -> Option<&'static str> {
    let norm = s
        .trim()
        .split('.')
        .next()?
        .replace('_', "-")
        .to_ascii_lowercase();
    if norm.is_empty() {
        return None;
    }
    let langs = languages();
    let base = norm.split('-').next().unwrap_or_default().to_string();
    langs
        .iter()
        .find(|(c, _)| c.to_ascii_lowercase() == norm)
        .or_else(|| langs.iter().find(|(c, _)| c.to_ascii_lowercase() == base))
        .map(|(c, _)| *c)
}

/// Индекс текущего языка в `languages()` плюс один; 0: ещё не выбран.
static CURRENT: AtomicUsize = AtomicUsize::new(0);

fn language_file() -> std::path::PathBuf {
    crate::platform::config_dir().join("language")
}

/// Язык, выбранный в настройках (None: как в системе).
pub fn saved() -> Option<&'static str> {
    std::fs::read_to_string(language_file())
        .ok()
        .and_then(|s| parse(&s))
}

/// Сохранить выбор (None: как в системе) и сразу переключиться.
pub fn save(lang: Option<&str>) -> std::io::Result<()> {
    let path = language_file();
    match lang {
        Some(l) => {
            crate::platform::create_private_dir(&crate::platform::config_dir())?;
            std::fs::write(&path, l)?;
        }
        None => match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        },
    }
    match lang {
        Some(l) => set(l),
        None => set(system()),
    }
    Ok(())
}

/// Язык системы; незнакомый считается английским.
pub fn system() -> &'static str {
    sys_locale::get_locale()
        .and_then(|l| parse(&l))
        .unwrap_or(FALLBACK)
}

fn detect() -> &'static str {
    std::env::var("KEYWARDEN_LANG")
        .ok()
        .and_then(|s| parse(&s))
        .or_else(saved)
        .unwrap_or_else(system)
}

pub fn current() -> &'static str {
    let langs = languages();
    match CURRENT.load(Ordering::Relaxed) {
        0 => {
            let l = detect();
            set(l);
            l
        }
        i => langs.get(i - 1).map_or(FALLBACK, |(c, _)| c),
    }
}

pub fn set(lang: &str) {
    if let Some(i) = languages().iter().position(|(c, _)| *c == lang) {
        CURRENT.store(i + 1, Ordering::Relaxed);
    }
}

/// Каталог языка (все файлы `locales/<код>/*.json` вместе).
fn catalog(code: &str) -> Option<&'static HashMap<String, String>> {
    static ALL: OnceLock<HashMap<&'static str, HashMap<String, String>>> = OnceLock::new();
    ALL.get_or_init(|| {
        CATALOGS
            .iter()
            .map(|(code, _, files)| {
                let mut m = HashMap::new();
                for src in *files {
                    // битый каталог ловит тест catalogs_parse; здесь просто без перевода
                    if let Ok(part) = serde_json::from_str::<HashMap<String, String>>(src) {
                        m.extend(part.into_iter().filter(|(_, v)| !v.is_empty()));
                    }
                }
                (*code, m)
            })
            .collect()
    })
    .get(code)
}

/// Перевод строки на текущий язык; нет перевода: английский, нет и его: русский.
pub fn tr(key: &'static str) -> &'static str {
    let lang = current();
    if lang == SOURCE {
        return without_context(key);
    }
    [lang, FALLBACK]
        .into_iter()
        .find_map(|l| catalog(l).and_then(|c| c.get(key)))
        .map_or_else(|| without_context(key), String::as_str)
}

fn without_context(key: &'static str) -> &'static str {
    key.split_once('§').map_or(key, |(_, text)| text)
}

/// Подставить `{имя}` в переведённую строку.
pub fn fill(template: &str, args: &[(&str, &dyn std::fmt::Display)]) -> String {
    let mut out = template.to_string();
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), &value.to_string());
    }
    out
}

/// Какая из трёх форм нужна числу `n` в языке `lang` (0: одна, 1: несколько, 2: много).
/// Ключи у форм русские («запись», «записи», «записей»), так что языки с тремя формами
/// (украинский, польский, чешский) переводят каждую, а остальным хватает первой и третьей.
fn plural_form(lang: &str, n: u64) -> usize {
    let base = lang.split('-').next().unwrap_or(lang);
    match base {
        "ru" | "uk" | "be" | "sr" | "hr" | "bs" => match (n % 10, n % 100) {
            (1, r) if r != 11 => 0,
            (2..=4, r) if !(12..=14).contains(&r) => 1,
            _ => 2,
        },
        "pl" => match (n, n % 10, n % 100) {
            (1, _, _) => 0,
            (_, 2..=4, r) if !(12..=14).contains(&r) => 1,
            _ => 2,
        },
        "cs" | "sk" => match n {
            1 => 0,
            2..=4 => 1,
            _ => 2,
        },
        // французский и португальский (Бразилия) считают 0 единственным числом
        "fr" if n <= 1 => 0,
        _ if n == 1 => 0,
        _ => 2,
    }
}

/// Существительное после числа: `i18n::plural(n, "запись", "записи", "записей")`.
pub fn plural(n: u64, one: &'static str, few: &'static str, many: &'static str) -> &'static str {
    let form = [one, few, many][plural_form(current(), n)];
    tr(form)
}

/// `tr!("строка")` -> `&'static str`; `tr!("строка {n}", n = x)` -> `String`.
#[macro_export]
macro_rules! tr {
    ($key:literal) => {
        $crate::i18n::tr($key)
    };
    ($key:literal, $($name:ident = $value:expr),+ $(,)?) => {
        $crate::i18n::fill(
            $crate::i18n::tr($key),
            &[$((stringify!($name), &$value as &dyn ::std::fmt::Display)),+],
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Каталоги всех языков разбираются, и одна строка в разных файлах языка переведена
    /// одинаково: каталог общий, иначе победил бы файл, загруженный последним.
    #[test]
    fn catalogs_parse() {
        for (code, _, files) in CATALOGS {
            let mut seen: HashMap<String, String> = HashMap::new();
            for (i, src) in files.iter().enumerate() {
                let part = serde_json::from_str::<HashMap<String, String>>(src)
                    .unwrap_or_else(|e| panic!("locales/{code}, файл №{i}: {e}"));
                for (k, v) in part {
                    if let Some(prev) = seen.insert(k.clone(), v.clone()) {
                        assert_eq!(prev, v, "разный перевод «{k}» в locales/{code}");
                    }
                }
            }
        }
    }

    fn placeholders(s: &str) -> std::collections::BTreeSet<String> {
        regex::Regex::new(r"\{([a-z_]+)\}")
            .unwrap()
            .captures_iter(s)
            .map(|c| c[1].to_string())
            .collect()
    }

    /// Во всех языках: подстановки `{n}` те же, что в ключе, и нет ключей, которых нет в
    /// английском образце (устаревших после правок кода).
    #[test]
    fn translations_match_source() {
        let en = catalog(FALLBACK).expect("есть английский каталог");
        for (code, _, _) in CATALOGS {
            let cat = catalog(code).unwrap();
            for (k, v) in cat {
                assert_eq!(
                    placeholders(k),
                    placeholders(v),
                    "locales/{code}: подстановки в переводе «{v}» не совпадают с «{k}»"
                );
                assert!(
                    en.contains_key(k),
                    "locales/{code}: устаревший ключ «{k}» (его нет в locales/en)"
                );
            }
        }
    }

    #[test]
    fn plural_rules() {
        let forms =
            |lang: &str, ns: &[u64]| ns.iter().map(|n| plural_form(lang, *n)).collect::<Vec<_>>();
        assert_eq!(
            forms("ru", &[1, 2, 5, 11, 21, 22, 25]),
            [0, 1, 2, 2, 0, 1, 2]
        );
        assert_eq!(forms("uk", &[1, 3, 12]), [0, 1, 2]);
        assert_eq!(forms("pl", &[1, 2, 5, 21, 22]), [0, 1, 2, 2, 1]);
        assert_eq!(forms("cs", &[1, 3, 5]), [0, 1, 2]);
        assert_eq!(forms("en", &[0, 1, 2]), [2, 0, 2]);
        assert_eq!(forms("fr", &[0, 1, 2]), [0, 0, 2]);
        assert_eq!(forms("de-AT", &[1, 2]), [0, 2]);
    }

    #[test]
    fn fill_replaces_named() {
        assert_eq!(fill("{n} из {all}", &[("n", &3), ("all", &10)]), "3 из 10");
        assert_eq!(fill("{x} {x}", &[("x", &"a")]), "a a");
    }

    #[test]
    fn context_is_hidden() {
        assert_eq!(without_context("поле§Логин"), "Логин");
        assert_eq!(without_context("Логин"), "Логин");
    }

    #[test]
    fn parse_codes() {
        assert_eq!(parse("ru_RU.UTF-8"), Some("ru"));
        assert_eq!(parse("en-US"), Some("en"));
        assert_eq!(parse("EN"), Some("en"));
        assert_eq!(parse("xx-YY"), None);
        assert_eq!(parse(""), None);
    }

    /// Каждый `tr!("…")` и `plural(…)` в исходниках имеет перевод, и в каталоге нет лишнего.
    #[test]
    fn every_key_is_translated() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lit = r#""((?:[^"\\]|\\.)*)""#;
        let re =
            regex::Regex::new(&format!(r#"(?:\btr!\(\s*|i18n::plural\([^,]+,\s*){lit}"#)).unwrap();
        let re_rest = regex::Regex::new(&format!(
            r#"i18n::plural\([^,]+,\s*{lit},\s*{lit},\s*{lit}"#
        ))
        .unwrap();
        let mut used = std::collections::BTreeSet::new();
        let mut stack = vec![root.join("crates")];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") && !p.ends_with("src/i18n.rs") {
                    let src = std::fs::read_to_string(&p).unwrap();
                    for c in re.captures_iter(&src) {
                        used.insert(unescape(&c[1]));
                    }
                    for c in re_rest.captures_iter(&src) {
                        used.insert(unescape(&c[2]));
                        used.insert(unescape(&c[3]));
                    }
                }
            }
        }
        let catalog = catalog(FALLBACK).expect("есть английский каталог");
        let missing: Vec<_> = used.iter().filter(|k| !catalog.contains_key(*k)).collect();
        assert!(
            missing.is_empty(),
            "нет перевода в locales/en: {missing:#?}"
        );
        let unused: Vec<_> = catalog.keys().filter(|k| !used.contains(*k)).collect();
        assert!(
            unused.is_empty(),
            "лишнее в locales/en (ключ не встречается в коде): {unused:#?}"
        );
    }

    fn unescape(s: &str) -> String {
        s.replace("\\\"", "\"")
            .replace("\\n", "\n")
            .replace("\\\\", "\\")
    }
}
