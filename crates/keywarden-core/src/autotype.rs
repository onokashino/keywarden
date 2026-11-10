//! Автоввод как в KeePass: какие записи подходят к активному окну и что напечатать.
//! Синтаксис последовательностей KeePass: `{USERNAME}{TAB}{PASSWORD}{ENTER}`, `{TOTP}`,
//! `{S:Поле}`, `{DELAY 500}`, клавиши `{TAB}` `{ENTER}` `{ESC}` `{UP}`..., модификаторы `+` (Shift),
//! `^` (Ctrl), `%` (Alt) перед символом или клавишей, `~` это Enter, `{+}` `{^}` `{%}` `{~}`
//! `{{}` `{}}` сами символы. Набор делает keywardend (autotype.rs), здесь только логика.

use crate::model;
use crate::totp::Totp;
use keepass::Database;
use keepass::db::{EntryRef, fields};
use zeroize::Zeroizing;

pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Text(Zeroizing<String>),
    /// клавиша по имени xkb (Tab, Return, Escape, ...) с модификаторами (shift, ctrl, alt)
    Key {
        name: String,
        mods: Vec<&'static str>,
    },
    /// символ с модификаторами (Ctrl+A и т.п.)
    Chord {
        ch: char,
        mods: Vec<&'static str>,
    },
    Delay(u64),
}

/// `*` как любая подстрока, без учёта регистра (окна ассоциаций KeePass).
pub fn glob(pattern: &str, text: &str) -> bool {
    fn rec(p: &[char], t: &[char]) -> bool {
        match p.split_first() {
            None => t.is_empty(),
            Some(('*', rest)) => (0..=t.len()).any(|i| rec(rest, &t[i..])),
            Some((c, rest)) => t
                .split_first()
                .is_some_and(|(tc, trest)| tc == c && rec(rest, trest)),
        }
    }
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    rec(&p, &t)
}

fn autotype_enabled(db: &Database, e: &EntryRef<'_>) -> bool {
    if e.autotype.as_ref().is_some_and(|a| !a.enabled) {
        return false;
    }
    // ближайшая группа с явным значением решает (как EnableAutoType в KeePassXC)
    let mut gid = Some(e.parent().id());
    while let Some(gr) = gid.and_then(|id| db.group(id)) {
        if let Some(on) = gr.enable_autotype {
            return on;
        }
        gid = gr.parent().map(|p| p.id());
    }
    !model::in_recycle_bin(db, e.parent().id())
}

/// Части домена, по которым узнаём сайт в заголовке окна браузера: github.com -> "github".
fn site_word(url: &str) -> Option<String> {
    let host = url::Url::parse(url).ok()?.host_str()?.to_lowercase();
    let parts: Vec<&str> = host.split('.').filter(|p| *p != "www").collect();
    (parts.len() >= 2)
        .then(|| parts[parts.len() - 2].to_string())
        .filter(|w| w.len() >= 3)
}

/// Записи для окна и последовательность каждой: сначала совпавшие ассоциации, потом совпадение
/// названия записи или домена её адреса с заголовком окна.
pub fn candidates(db: &Database, window: &str) -> Vec<(String, String)> {
    let w = window.to_lowercase();
    let mut by_assoc = vec![];
    let mut by_title = vec![];
    for e in db.iter_all_entries() {
        // кошельки автоввод не печатает никогда: сид-фраза не должна попасть ни в одно окно
        if !autotype_enabled(db, &e)
            || model::in_recycle_bin(db, e.parent().id())
            || model::kind_of(&e) == model::EntryKind::CryptoWallet
        {
            continue;
        }
        let id = e.id().uuid().to_string();
        let default = default_sequence(&e);
        if let Some(a) = e
            .autotype
            .as_ref()
            .and_then(|a| a.associations.iter().find(|x| glob(&x.window, window)))
        {
            let seq = if a.sequence.trim().is_empty() {
                default.clone()
            } else {
                a.sequence.clone()
            };
            by_assoc.push((id, seq));
            continue;
        }
        let title = e.get(fields::TITLE).unwrap_or_default().to_lowercase();
        let site = site_word(e.get(fields::URL).unwrap_or_default());
        if (title.len() >= 3 && w.contains(&title)) || site.is_some_and(|s| w.contains(&s)) {
            by_title.push((id, default));
        }
    }
    by_assoc.extend(by_title);
    by_assoc
}

fn default_sequence(e: &EntryRef<'_>) -> String {
    if let Some(s) = e
        .autotype
        .as_ref()
        .and_then(|a| a.default_sequence.clone())
        .filter(|s| !s.trim().is_empty())
    {
        return s;
    }
    let db = e.database();
    let mut gid = Some(e.parent().id());
    while let Some(gr) = gid.and_then(|id| db.group(id)) {
        if let Some(s) = gr
            .default_autotype_sequence
            .clone()
            .filter(|s| !s.trim().is_empty())
        {
            return s;
        }
        gid = gr.parent().map(|p| p.id());
    }
    DEFAULT_SEQUENCE.into()
}

/// Последовательность записи без окна (выбор вручную в лаунчере).
pub fn sequence_for(db: &Database, id: &str) -> model::Result<String> {
    let e = db
        .entry(model::parse_entry_id(id)?)
        .ok_or(model::ModelError::EntryNotFound)?;
    Ok(default_sequence(&e))
}

fn key_name(token: &str) -> Option<&'static str> {
    Some(match token {
        "TAB" => "Tab",
        "ENTER" => "Return",
        "SPACE" => "space",
        "BACKSPACE" | "BS" | "BKSP" => "BackSpace",
        "DELETE" | "DEL" => "Delete",
        "INSERT" | "INS" => "Insert",
        "UP" => "Up",
        "DOWN" => "Down",
        "LEFT" => "Left",
        "RIGHT" => "Right",
        "HOME" => "Home",
        "END" => "End",
        "PGUP" => "Prior",
        "PGDN" => "Next",
        "ESC" => "Escape",
        "F1" => "F1",
        "F2" => "F2",
        "F3" => "F3",
        "F4" => "F4",
        "F5" => "F5",
        "F6" => "F6",
        "F7" => "F7",
        "F8" => "F8",
        "F9" => "F9",
        "F10" => "F10",
        "F11" => "F11",
        "F12" => "F12",
        _ => return None,
    })
}

/// Разобрать последовательность в действия с уже подставленными значениями записи.
pub fn compile(db: &Database, id: &str, sequence: &str) -> Result<Vec<Action>, String> {
    let e = db
        .entry(model::parse_entry_id(id).map_err(|e| e.to_string())?)
        .ok_or(crate::tr!("запись не найдена"))?;
    if model::kind_of(&e) == model::EntryKind::CryptoWallet {
        return Err(crate::tr!("автоввод для криптокошельков выключен").into());
    }
    let field = |name: &str| model::resolve(db, &e, e.get(name).unwrap_or_default());
    let mut out: Vec<Action> = vec![];
    let mut text = Zeroizing::new(String::new());
    let mut mods: Vec<&'static str> = vec![];
    let flush = |text: &mut Zeroizing<String>, out: &mut Vec<Action>| {
        if !text.is_empty() {
            out.push(Action::Text(Zeroizing::new(std::mem::take(&mut **text))));
        }
    };
    let chars: Vec<char> = sequence.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        i += 1;
        match c {
            '+' | '^' | '%' => {
                flush(&mut text, &mut out);
                mods.push(match c {
                    '+' => "shift",
                    '^' => "ctrl",
                    _ => "alt",
                });
                continue;
            }
            '~' => {
                flush(&mut text, &mut out);
                out.push(Action::Key {
                    name: "Return".into(),
                    mods: std::mem::take(&mut mods),
                });
            }
            '{' => {
                // {{} и {}}: сами скобки
                let end = chars[i..]
                    .iter()
                    .enumerate()
                    .skip(1)
                    .find(|(_, c)| **c == '}')
                    .map(|(k, _)| i + k)
                    .or_else(|| chars[i..].iter().position(|c| *c == '}').map(|k| i + k))
                    .ok_or(crate::tr!("незакрытая { в последовательности"))?;
                let token: String = chars[i..end].iter().collect();
                i = end + 1;
                let upper = token.to_uppercase();
                let value: Option<String> = match upper.as_str() {
                    "USERNAME" => Some(field(fields::USERNAME)),
                    "PASSWORD" => Some(field(fields::PASSWORD)),
                    "TITLE" => Some(field(fields::TITLE)),
                    "URL" => Some(field(fields::URL)),
                    "NOTES" => Some(field(fields::NOTES)),
                    "TOTP" => Some(
                        Totp::from_entry(&e)
                            .map_err(|e| format!("{{TOTP}}: {e}"))?
                            .now()
                            .code,
                    ),
                    "+" | "^" | "%" | "~" | "{" | "}" => Some(token.clone()),
                    _ => None,
                };
                if let Some(v) = value {
                    if mods.is_empty() {
                        text.push_str(&v);
                    } else if let Some(ch) = v.chars().next().filter(|_| v.chars().count() == 1) {
                        flush(&mut text, &mut out);
                        out.push(Action::Chord {
                            ch,
                            mods: std::mem::take(&mut mods),
                        });
                    } else {
                        text.push_str(&v);
                        mods.clear();
                    }
                    continue;
                }
                if let Some(name) = token
                    .strip_prefix("S:")
                    .or_else(|| token.strip_prefix("s:"))
                {
                    text.push_str(&field(name));
                    continue;
                }
                if let Some(n) = upper
                    .strip_prefix("DELAY ")
                    .or_else(|| upper.strip_prefix("DELAY="))
                {
                    flush(&mut text, &mut out);
                    if upper.starts_with("DELAY ") {
                        let ms: u64 = n.trim().parse().map_err(|_| {
                            crate::tr!("{t}: нужна задержка в мс", t = format!("{{{token}}}"))
                        })?;
                        out.push(Action::Delay(ms.min(10_000)));
                    }
                    continue;
                }
                // клавиша, возможно с повтором: {TAB 3}
                let (name, count) = match upper.split_once(' ') {
                    Some((n, k)) => (n.to_string(), k.trim().parse::<usize>().unwrap_or(1)),
                    None => (upper.clone(), 1),
                };
                let key = key_name(&name).ok_or_else(|| {
                    crate::tr!("неизвестный заполнитель {t}", t = format!("{{{token}}}"))
                })?;
                flush(&mut text, &mut out);
                for _ in 0..count.min(50) {
                    out.push(Action::Key {
                        name: key.into(),
                        mods: mods.clone(),
                    });
                }
                mods.clear();
            }
            c => {
                if mods.is_empty() {
                    text.push(c);
                } else {
                    flush(&mut text, &mut out);
                    out.push(Action::Chord {
                        ch: c,
                        mods: std::mem::take(&mut mods),
                    });
                }
            }
        }
    }
    flush(&mut text, &mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntryPatch, FieldSet, create_entry};
    use keepass::db::{AutoType, AutoTypeAssociation};

    fn add(db: &mut Database, title: &str, url: &str) -> String {
        create_entry(
            db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Title", title),
                    FieldSet::new("UserName", "octo"),
                    FieldSet::new("Password", "p+a{ss}"),
                    FieldSet::new("URL", url),
                    FieldSet::new("PIN", "1234"),
                ],
                ..Default::default()
            },
        )
        .unwrap()
    }

    fn text(a: &Action) -> String {
        match a {
            Action::Text(t) => t.to_string(),
            other => format!("{other:?}"),
        }
    }

    #[test]
    fn default_sequence_types_login() {
        let mut db = Database::new();
        let id = add(&mut db, "GitHub", "https://github.com/login");
        let a = compile(&db, &id, DEFAULT_SEQUENCE).unwrap();
        assert_eq!(text(&a[0]), "octo");
        assert_eq!(
            a[1],
            Action::Key {
                name: "Tab".into(),
                mods: vec![]
            }
        );
        assert_eq!(
            text(&a[2]),
            "p+a{ss}",
            "значение пароля печатается как есть"
        );
        assert_eq!(
            a[3],
            Action::Key {
                name: "Return".into(),
                mods: vec![]
            }
        );
    }

    #[test]
    fn syntax_features() {
        let mut db = Database::new();
        let id = add(&mut db, "Bank", "");
        let a = compile(&db, &id, "{S:PIN}{DELAY 200}^a{TAB 2}{+}x~").unwrap();
        assert_eq!(text(&a[0]), "1234");
        assert_eq!(a[1], Action::Delay(200));
        assert_eq!(
            a[2],
            Action::Chord {
                ch: 'a',
                mods: vec!["ctrl"]
            }
        );
        assert_eq!(
            a[3],
            Action::Key {
                name: "Tab".into(),
                mods: vec![]
            }
        );
        assert_eq!(
            a[4],
            Action::Key {
                name: "Tab".into(),
                mods: vec![]
            }
        );
        assert_eq!(text(&a[5]), "+x");
        assert_eq!(
            a[6],
            Action::Key {
                name: "Return".into(),
                mods: vec![]
            }
        );
        assert!(compile(&db, &id, "{НЕЧТО}").is_err());
        assert!(compile(&db, &id, "{TOTP}").is_err(), "у записи нет 2FA");
    }

    #[test]
    fn window_matching() {
        let mut db = Database::new();
        let gh = add(&mut db, "GitHub", "https://github.com/login");
        let bank = add(&mut db, "Мой банк", "https://online.bank.example");
        {
            let mut e = db.entry_mut(model::parse_entry_id(&bank).unwrap()).unwrap();
            e.autotype = Some(AutoType {
                enabled: true,
                associations: vec![AutoTypeAssociation {
                    window: "*Интернет-банк*".into(),
                    sequence: "{PASSWORD}{ENTER}".into(),
                }],
                ..Default::default()
            });
        }
        let off = add(&mut db, "GitHub старый", "https://github.com");
        db.entry_mut(model::parse_entry_id(&off).unwrap())
            .unwrap()
            .autotype = Some(AutoType {
            enabled: false,
            ..Default::default()
        });

        let c = candidates(&db, "Sign in to GitHub · GitHub - Mozilla Firefox");
        assert_eq!(
            c,
            [(gh.clone(), DEFAULT_SEQUENCE.to_string())],
            "выключенный автоввод пропущен"
        );
        let c = candidates(&db, "Интернет-банк - Chromium");
        assert_eq!(
            c,
            [(bank, "{PASSWORD}{ENTER}".to_string())],
            "ассоциация задаёт последовательность"
        );
        assert!(candidates(&db, "Terminal").is_empty());
        assert!(glob("*hub*", "GITHUB"));
        assert!(!glob("hub", "github"));
    }
}
