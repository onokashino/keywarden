//! Нечёткий поиск по названию, логину и адресу (nucleo, тот же движок, что в helix).
//! Записи из корзины и из групп с отключённым поиском не показываются, как в KeePassXC.
//!
//! Синтаксис запроса (как в KeePassXC, плюс сокращения):
//! - свободные слова: нечёткий поиск с ранжированием;
//! - `title:` `user:` `url:` `notes:` `group:` `tag:` (или `#тег`) `pass:`: подстрока в поле
//!   (короткие формы `t:` `u:` `n:` `g:` `p:`);
//! - `/выражение/` или `поле:/выражение/`: регулярное выражение (без учёта регистра);
//! - `"фраза с пробелами"`;
//! - `-слово` или `-поле:значение`: исключить;
//! - `is:expired` `is:otp` `is:passkey` `is:attachment`.

use crate::model::{self, EntryKind, EntrySummary};
use keepass::Database;
use keepass::db::fields;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use serde::{Deserialize, Serialize};

/// Сужение поиска: группа (вместе с подгруппами) и тип записи.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub kind: Option<EntryKind>,
    #[serde(default)]
    pub tag: Option<String>,
    /// без запроса: порядок, как в базе (ручной, общий с KeePassXC), а не недавние сверху
    #[serde(default)]
    pub manual: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Field {
    Title,
    User,
    Url,
    Notes,
    Group,
    Tag,
    Pass,
    /// без поля: название, логин, адрес, заметки, папка, теги
    Any,
}

#[derive(Debug)]
enum Test {
    Text(String),
    Regex(regex::Regex),
    Is(String),
}

#[derive(Debug)]
struct Term {
    negate: bool,
    field: Field,
    test: Test,
}

/// Разобранный запрос: свободный текст для нечёткого ранжирования и условия-фильтры.
#[derive(Debug, Default)]
struct Query {
    fuzzy: Vec<String>,
    terms: Vec<Term>,
}

/// Слова запроса; второй элемент: была ли в слове фраза в кавычках.
fn tokens(q: &str) -> Vec<(String, bool)> {
    let mut out = vec![];
    let mut cur = String::new();
    let (mut quoted, mut had_quotes) = (false, false);
    for c in q.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                had_quotes = true;
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push((std::mem::take(&mut cur), had_quotes));
                }
                had_quotes = false;
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push((cur, had_quotes));
    }
    out
}

fn parse_query(q: &str) -> Query {
    let mut query = Query::default();
    for (tok, quoted) in tokens(q) {
        let (negate, body) = match tok.strip_prefix('-') {
            Some(b) if !b.is_empty() => (true, b.to_string()),
            _ => (false, tok.clone()),
        };
        let (field, value) = if let Some(t) = body.strip_prefix('#').filter(|t| !t.is_empty()) {
            (Some(Field::Tag), t.to_string())
        } else if let Some((k, v)) = body.split_once(':').filter(|(k, _)| !k.is_empty()) {
            let f = match k.to_lowercase().as_str() {
                "title" | "t" => Some(Field::Title),
                "user" | "username" | "u" | "login" => Some(Field::User),
                "url" => Some(Field::Url),
                "notes" | "n" => Some(Field::Notes),
                "group" | "g" | "folder" => Some(Field::Group),
                "tag" | "tags" => Some(Field::Tag),
                "pass" | "password" | "p" => Some(Field::Pass),
                "is" => {
                    query.terms.push(Term {
                        negate,
                        field: Field::Any,
                        test: Test::Is(v.to_lowercase()),
                    });
                    continue;
                }
                _ => None,
            };
            match f {
                Some(f) => (Some(f), v.to_string()),
                None => (None, body.clone()), // "https://..." и прочее с двоеточием
            }
        } else {
            (None, body.clone())
        };
        if value.is_empty() {
            continue;
        }
        let test = match value
            .strip_prefix('/')
            .and_then(|v| v.strip_suffix('/'))
            .filter(|v| !v.is_empty())
            .and_then(|v| {
                regex::RegexBuilder::new(v)
                    .case_insensitive(true)
                    .build()
                    .ok()
            }) {
            Some(re) => Test::Regex(re),
            None => Test::Text(value.to_lowercase()),
        };
        match (field, negate, &test) {
            // фраза в кавычках ищется дословно во всех полях, а не нечётко
            (None, false, Test::Text(t)) if !quoted => query.fuzzy.push(t.clone()),
            _ => query.terms.push(Term {
                negate,
                field: field.unwrap_or(Field::Any),
                test,
            }),
        }
    }
    query
}

fn term_matches(t: &Term, e: &keepass::db::EntryRef<'_>, s: &EntrySummary) -> bool {
    let notes = || e.get(fields::NOTES).unwrap_or_default().to_string();
    let values: Vec<String> = match t.field {
        Field::Title => vec![s.title.clone()],
        Field::User => vec![s.username.clone()],
        Field::Url => vec![s.url.clone()],
        Field::Notes => vec![notes()],
        Field::Group => vec![s.group.clone()],
        Field::Tag => s.tags.clone(),
        Field::Pass => vec![e.get(fields::PASSWORD).unwrap_or_default().to_string()],
        Field::Any => {
            let mut v = vec![
                s.title.clone(),
                s.username.clone(),
                s.url.clone(),
                notes(),
                s.group.clone(),
            ];
            v.extend(s.tags.iter().cloned());
            // адреса кошельков: найти запись по адресу
            v.push(
                e.get(crate::wallet::ADDRESSES)
                    .unwrap_or_default()
                    .to_string(),
            );
            v
        }
    };
    let hit = match &t.test {
        Test::Text(x) => values.iter().any(|v| {
            if t.field == Field::Tag {
                v.to_lowercase() == *x
            } else {
                v.to_lowercase().contains(x.as_str())
            }
        }),
        Test::Regex(re) => values.iter().any(|v| re.is_match(v)),
        Test::Is(what) => match what.as_str() {
            "expired" => s.expired,
            "otp" | "2fa" | "totp" => s.has_otp,
            "passkey" => s.kind == EntryKind::Passkey,
            "attachment" | "attachments" => e.attachments().next().is_some(),
            _ => false,
        },
    };
    hit != t.negate
}

pub fn search(db: &Database, query: &str, limit: usize) -> Vec<EntrySummary> {
    search_filtered(db, query, limit, &Filter::default())
}

/// Если выбрана сама корзина (или группа в ней), её записи показываются; иначе корзина скрыта.
pub fn search_filtered(
    db: &Database,
    query: &str,
    limit: usize,
    filter: &Filter,
) -> Vec<EntrySummary> {
    let group = filter
        .group
        .as_deref()
        .and_then(|g| model::parse_group_id(g).ok());
    let browsing_bin = group.is_some_and(|g| model::in_recycle_bin(db, g));
    let visible = db.iter_all_entries().filter(|e| {
        let g = e.parent().id();
        if let Some(want) = group
            && !model::is_descendant(db, g, want)
        {
            return false;
        }
        if filter.kind.is_some_and(|k| model::kind_of(e) != k) {
            return false;
        }
        if let Some(t) = &filter.tag
            && !e.tags.iter().any(|x| x == t)
        {
            return false;
        }
        browsing_bin || (!model::in_recycle_bin(db, g) && !model::searching_disabled(db, g))
    });

    let q = parse_query(query.trim());
    let visible = visible.filter(|e| {
        if q.terms.is_empty() {
            return true;
        }
        let s = model::summary(e);
        q.terms.iter().all(|t| term_matches(t, e, &s))
    });
    let query = q.fuzzy.join(" ");
    if query.is_empty() {
        let mut all: Vec<_> = visible.collect();
        if filter.manual {
            let order = model::tree_order(db);
            all.sort_by_key(|e| order.get(&e.id()).copied().unwrap_or(usize::MAX));
            return all.iter().take(limit).map(model::summary).collect();
        }
        // без запроса: недавно использованные сверху (удобно для лаунчера)
        all.sort_by(|a, b| {
            b.times
                .last_access
                .cmp(&a.times.last_access)
                .then_with(|| title(a).cmp(&title(b)))
        });
        return all.iter().take(limit).map(model::summary).collect();
    }

    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(&query, CaseMatching::Smart, Normalization::Smart);
    let mut buf = Vec::new();
    let mut score = |s: &str| pattern.score(Utf32Str::new(s, &mut buf), &mut matcher);

    let mut hits: Vec<(u32, EntrySummary)> = visible
        .filter_map(|e| {
            let s = model::summary(&e);
            // адрес кошелька ищем подстрокой: нечёткое совпадение по длинному адресу даёт мусор
            let addr_hit = query.len() >= 6
                && e.get(crate::wallet::ADDRESSES)
                    .is_some_and(|a| a.to_lowercase().contains(&query.to_lowercase()));
            let best = [
                score(&s.title).map(|x| x * 2),
                score(&s.username),
                score(&host(&s.url)),
                score(&s.url),
                score(&s.group),
                addr_hit.then_some(u32::MAX / 2),
            ]
            .into_iter()
            .flatten()
            .max()?;
            Some((best, s))
        })
        .collect();
    hits.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.title.to_lowercase().cmp(&b.1.title.to_lowercase()))
    });
    hits.into_iter().take(limit).map(|(_, s)| s).collect()
}

fn title(e: &keepass::db::EntryRef<'_>) -> String {
    e.get(fields::TITLE).unwrap_or_default().to_lowercase()
}

/// Для адреса ищем по хосту: схема и путь дают ложные совпадения.
fn host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntryPatch, FieldSet, create_entry, delete_entry};

    fn add(db: &mut Database, title: &str, user: &str, url: &str) -> String {
        create_entry(
            db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Title", title),
                    FieldSet::new("UserName", user),
                    FieldSet::new("URL", url),
                ],
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn fuzzy_ranking() {
        let mut db = Database::new();
        add(&mut db, "GitHub", "octo", "https://github.com");
        add(&mut db, "GitLab", "me", "https://gitlab.com");
        add(&mut db, "Bank", "ghost", "https://bank.example");
        let r = search(&db, "ghub", 10);
        assert_eq!(r[0].title, "GitHub");
        assert_eq!(search(&db, "gitlab.com", 10)[0].title, "GitLab");
        assert!(search(&db, "zzzz", 10).is_empty());
        assert_eq!(search(&db, "", 2).len(), 2);
    }

    #[test]
    fn filters() {
        let mut db = Database::new();
        let g = model::add_group(&mut db, None, "Work").unwrap();
        let sub = model::add_group(&mut db, Some(&g), "Sub").unwrap();
        add(&mut db, "Outside", "", "");
        let inside = model::create_entry(
            &mut db,
            &EntryPatch {
                group: Some(sub),
                kind: Some(EntryKind::Card),
                set: vec![FieldSet::new("Title", "Inside")],
                ..Default::default()
            },
        )
        .unwrap();
        let f = Filter {
            group: Some(g.clone()),
            kind: None,
            tag: None,
            ..Default::default()
        };
        assert_eq!(
            search_filtered(&db, "", 10, &f)
                .iter()
                .map(|e| e.title.as_str())
                .collect::<Vec<_>>(),
            ["Inside"]
        );
        let k = Filter {
            group: None,
            kind: Some(EntryKind::Card),
            tag: None,
            ..Default::default()
        };
        assert_eq!(search_filtered(&db, "", 10, &k).len(), 1);
        delete_entry(&mut db, &inside).unwrap();
        let bin = db.recycle_bin().unwrap().id().uuid().to_string();
        assert_eq!(
            search_filtered(
                &db,
                "",
                10,
                &Filter {
                    group: Some(bin),
                    kind: None,
                    tag: None,
                    ..Default::default()
                }
            )
            .len(),
            1,
            "корзину можно открыть"
        );
    }

    #[test]
    fn recycle_bin_hidden() {
        let mut db = Database::new();
        let id = add(&mut db, "Old", "", "");
        delete_entry(&mut db, &id).unwrap();
        assert!(search(&db, "old", 10).is_empty());
        assert!(search(&db, "", 10).is_empty());
    }

    #[test]
    fn query_syntax() {
        let mut db = Database::new();
        let g = model::add_group(&mut db, None, "Work").unwrap();
        for (title, user, url, tags, group) in [
            ("GitHub", "octo", "https://github.com", vec!["dev"], None),
            (
                "GitLab",
                "me",
                "https://gitlab.com",
                vec!["dev", "work"],
                Some(g.clone()),
            ),
            ("Bank", "ivan", "https://bank.example", vec![], None),
        ] {
            create_entry(
                &mut db,
                &EntryPatch {
                    group,
                    tags: Some(tags.into_iter().map(String::from).collect()),
                    set: vec![
                        FieldSet::new("Title", title),
                        FieldSet::new("UserName", user),
                        FieldSet::new("URL", url),
                        FieldSet::new("Notes", "note with secret phrase"),
                    ],
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let titles = |q: &str| {
            let mut v: Vec<String> = search(&db, q, 50).into_iter().map(|e| e.title).collect();
            v.sort();
            v
        };
        assert_eq!(titles("#dev"), ["GitHub", "GitLab"]);
        assert_eq!(titles("tag:work"), ["GitLab"]);
        assert_eq!(titles("#dev -#work"), ["GitHub"]);
        assert_eq!(titles("user:iv"), ["Bank"]);
        assert_eq!(titles("url:/git(hub|lab)/"), ["GitHub", "GitLab"]);
        assert_eq!(titles("group:work"), ["GitLab"]);
        assert_eq!(titles("\"secret phrase\" -bank"), ["GitHub", "GitLab"]);
        assert_eq!(titles("git -lab"), ["GitHub"]);
        assert_eq!(
            titles("https://bank.example"),
            ["Bank"],
            "двоеточие в адресе не поле"
        );
        assert!(titles("is:expired").is_empty());
        let f = Filter {
            tag: Some("work".into()),
            ..Default::default()
        };
        assert_eq!(search_filtered(&db, "", 10, &f).len(), 1);
    }
}
