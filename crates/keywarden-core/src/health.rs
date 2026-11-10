//! Проверка паролей, как «Отчёты базы данных» KeePassXC: слабые (оценка zxcvbn), повторяющиеся,
//! давно не менявшиеся, истёкшие и найденные в утечках (Have I Been Pwned, только по запросу).
//! Записи с флагом «исключить из отчётов» KeePassXC (QualityCheck=false или KnownBad) пропускаются.
//!
//! HIBP по k-анонимности: наружу уходят первые 5 символов SHA-1 пароля, ответ содержит все
//! хвосты хэшей с этим началом, совпадение ищется здесь. Сеть в этом модуле не используется.

use crate::model::{self, EntryKind};
use keepass::Database;
use keepass::db::{EntryRef, Times, fields};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::collections::HashMap;

/// Пароль старше этого считается давно не менявшимся.
pub const OLD_DAYS: i64 = 365;
const KNOWN_BAD: &str = "KnownBad";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Issue {
    /// оценка zxcvbn 0..=2 из 4
    Weak {
        score: u8,
    },
    /// сколько записей с тем же паролем (включая эту)
    Reused {
        count: usize,
    },
    Old {
        days: i64,
    },
    Expired,
    /// сколько раз пароль встречался в утечках
    Breached {
        count: u64,
    },
    /// адрес http:// без шифрования: пароль уходит открытым текстом
    Insecure,
    /// сайт умеет коды 2FA (по 2fa.directory), а у записи их нет; `doc`: как включить
    NoTwoFactor {
        doc: String,
    },
    /// сайт принимает вход ключом доступа (passkey), а ключа у записи нет
    PasskeyReady {
        doc: String,
    },
    /// сид-фраза кошелька не проходит проверку (слова, длина, контрольная сумма)
    BadSeed {
        message: String,
    },
    /// сохранённые адреса не выводятся из фразы, ключа или xpub записи
    AddressMismatch {
        addresses: Vec<String>,
    },
}

/// Списки 2fa.directory: домен -> ссылка на инструкцию. Загружаются по кнопке.
#[derive(Debug, Clone, Default)]
pub struct Directory {
    pub totp: HashMap<String, String>,
    pub passkeys: HashMap<String, String>,
}

impl Directory {
    /// `https://api.2fa.directory/v3/totp.json`: [[имя, {domain, additional-domains, documentation}]]
    pub fn parse_totp(&mut self, json: &str) -> Result<(), String> {
        let list: Vec<(String, serde_json::Value)> =
            serde_json::from_str(json).map_err(|e| format!("2fa.directory: {e}"))?;
        for (_, v) in list {
            let doc = v["documentation"].as_str().unwrap_or_default().to_string();
            let extra = v["additional-domains"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            for d in std::iter::once(&v["domain"]).chain(extra.iter()) {
                if let Some(d) = d.as_str() {
                    self.totp.insert(d.to_lowercase(), doc.clone());
                }
            }
        }
        Ok(())
    }

    /// `https://passkeys-api.2fa.directory/v1/supported.json`: {домен: {passwordless, mfa, documentation}}
    pub fn parse_passkeys(&mut self, json: &str) -> Result<(), String> {
        let map: HashMap<String, serde_json::Value> =
            serde_json::from_str(json).map_err(|e| format!("passkeys.directory: {e}"))?;
        for (d, v) in map {
            if v.get("passwordless").is_some() {
                let doc = v["documentation"].as_str().unwrap_or_default().to_string();
                self.passkeys.insert(d.to_lowercase(), doc);
            }
        }
        Ok(())
    }

    /// Ищем хост адреса и все его родительские домены: accounts.google.com -> google.com.
    fn find<'a>(map: &'a HashMap<String, String>, host: &str) -> Option<&'a String> {
        let mut h = host;
        loop {
            if let Some(doc) = map.get(h) {
                return Some(doc);
            }
            h = h.split_once('.')?.1;
            if !h.contains('.') {
                return None;
            }
        }
    }
}

fn host_of(url: &str) -> Option<String> {
    let u = url::Url::parse(url)
        .or_else(|_| url::Url::parse(&format!("https://{url}")))
        .ok()?;
    Some(u.host_str()?.trim_start_matches("www.").to_lowercase())
}

/// http:// на внешний адрес (локальные адреса и сеть дома не считаются).
fn insecure(url: &str) -> bool {
    let Ok(u) = url::Url::parse(url.trim()) else {
        return false;
    };
    if u.scheme() != "http" {
        return false;
    }
    match u.host() {
        Some(url::Host::Domain(d)) => {
            !(d == "localhost" || d.ends_with(".local") || d.ends_with(".lan"))
        }
        Some(url::Host::Ipv4(ip)) => !(ip.is_loopback() || ip.is_private() || ip.is_link_local()),
        Some(url::Host::Ipv6(ip)) => !ip.is_loopback(),
        None => false,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub title: String,
    pub username: String,
    #[serde(default)]
    pub url: String,
    pub group: String,
    pub kind: EntryKind,
    pub issues: Vec<Issue>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Report {
    pub checked: usize,
    pub excluded: usize,
    pub weak: usize,
    pub reused: usize,
    pub old: usize,
    pub expired: usize,
    pub breached: usize,
    /// проверялись ли утечки (иначе `breached` всегда 0)
    pub breaches_checked: bool,
    #[serde(default)]
    pub insecure: usize,
    #[serde(default)]
    pub no_2fa: usize,
    #[serde(default)]
    pub passkey_ready: usize,
    /// кошельков с битой фразой или чужими адресами
    #[serde(default)]
    pub wallets: usize,
    /// загружались ли списки 2fa.directory (иначе `no_2fa` и `passkey_ready` всегда 0)
    #[serde(default)]
    pub sites_checked: bool,
    /// записи с проблемами: сначала самые серьёзные
    pub items: Vec<Item>,
}

pub fn excluded(e: &EntryRef<'_>) -> bool {
    !e.quality_check
        || e.custom_data
            .get(KNOWN_BAD)
            .and_then(|c| match &c.value {
                Some(keepass::db::CustomDataValue::String(s)) => Some(s == "true"),
                _ => None,
            })
            .unwrap_or(false)
}

/// Исключить запись из отчётов (или вернуть), как флажок в KeePassXC.
pub fn set_excluded(db: &mut Database, id: &str, exclude: bool) -> model::Result<()> {
    let mut e = db
        .entry_mut(model::parse_entry_id(id)?)
        .ok_or(model::ModelError::EntryNotFound)?;
    e.quality_check = !exclude;
    e.custom_data.remove(KNOWN_BAD);
    Ok(())
}

/// Пароли, которые проверяем: вне корзины, не пустые, не ссылки на другие записи.
fn checked_entries(db: &Database) -> impl Iterator<Item = (EntryRef<'_>, String)> {
    db.iter_all_entries().filter_map(move |e| {
        if model::in_recycle_bin(db, e.parent().id()) || excluded(&e) {
            return None;
        }
        let p = model::resolve(db, &e, e.get(fields::PASSWORD).unwrap_or_default());
        (!p.is_empty()).then_some((e, p))
    })
}

/// `breaches`: id записи -> сколько раз её пароль в утечках (после `hibp_*`), `None`: не проверяли.
pub fn report(
    db: &Database,
    breaches: Option<&HashMap<String, u64>>,
    sites: Option<&Directory>,
) -> Report {
    let mut r = Report {
        breaches_checked: breaches.is_some(),
        sites_checked: sites.is_some(),
        ..Default::default()
    };
    // домены, для которых в базе уже есть ключ доступа
    let passkey_hosts: std::collections::HashSet<String> = db
        .iter_all_entries()
        .filter(|e| model::kind_of(e) == EntryKind::Passkey)
        .filter_map(|e| host_of(e.get(fields::URL).unwrap_or_default()))
        .collect();
    r.excluded = db
        .iter_all_entries()
        .filter(|e| !model::in_recycle_bin(db, e.parent().id()) && excluded(e))
        .count();
    let entries: Vec<(EntryRef<'_>, String)> = checked_entries(db).collect();
    let mut uses: HashMap<&str, usize> = HashMap::new();
    for (_, p) in &entries {
        *uses.entry(p.as_str()).or_default() += 1;
    }
    let now = Times::now();
    // оценка zxcvbn дорогая: по разу на уникальный пароль
    let mut scores: HashMap<&str, u8> = HashMap::new();
    for (e, p) in &entries {
        r.checked += 1;
        let user = e.get(fields::USERNAME).unwrap_or_default();
        let title = e.get(fields::TITLE).unwrap_or_default();
        let score = *scores
            .entry(p.as_str())
            .or_insert_with(|| u8::from(zxcvbn::zxcvbn(p, &[user, title]).score()));
        let mut issues = vec![];
        if let Some(n) = breaches.and_then(|b| b.get(&e.id().uuid().to_string()))
            && *n > 0
        {
            issues.push(Issue::Breached { count: *n });
            r.breached += 1;
        }
        if score <= 2 {
            issues.push(Issue::Weak { score });
            r.weak += 1;
        }
        if uses[p.as_str()] > 1 {
            issues.push(Issue::Reused {
                count: uses[p.as_str()],
            });
            r.reused += 1;
        }
        if model::is_expired(e) {
            issues.push(Issue::Expired);
            r.expired += 1;
        }
        if let Some(t) = e.times.last_modification {
            let days = (now - t).num_days();
            if days >= OLD_DAYS {
                issues.push(Issue::Old { days });
                r.old += 1;
            }
        }
        let url = e.get(fields::URL).unwrap_or_default();
        if insecure(url) {
            issues.push(Issue::Insecure);
            r.insecure += 1;
        }
        if let (Some(dir), Some(host)) = (sites, host_of(url)) {
            if !model::has_otp(e)
                && let Some(doc) = Directory::find(&dir.totp, &host)
            {
                issues.push(Issue::NoTwoFactor { doc: doc.clone() });
                r.no_2fa += 1;
            }
            if model::kind_of(e) != EntryKind::Passkey
                && !passkey_hosts.contains(&host)
                && let Some(doc) = Directory::find(&dir.passkeys, &host)
            {
                issues.push(Issue::PasskeyReady { doc: doc.clone() });
                r.passkey_ready += 1;
            }
        }
        if !issues.is_empty() {
            let s = model::summary(e);
            r.items.push(Item {
                id: s.id,
                title: s.title,
                username: s.username,
                url: s.url,
                group: s.group,
                kind: s.kind,
                issues,
            });
        }
    }
    wallet_issues(db, &mut r);
    let weight = |i: &Item| {
        i.issues
            .iter()
            .map(|x| match x {
                Issue::Breached { .. } => 100,
                Issue::Weak { score } => 30 - *score as i32 * 10,
                Issue::Reused { count } => 10 + *count as i32,
                Issue::Expired => 8,
                Issue::Insecure => 6,
                Issue::NoTwoFactor { .. } => 4,
                Issue::Old { .. } => 2,
                Issue::PasskeyReady { .. } => 1,
                Issue::BadSeed { .. } => 90,
                Issue::AddressMismatch { .. } => 60,
            })
            .sum::<i32>()
    };
    r.items
        .sort_by(|a, b| weight(b).cmp(&weight(a)).then(a.title.cmp(&b.title)));
    r
}

/// Кошельки: фраза проходит проверку, сохранённые адреса выводятся из неё (или из ключа, xpub).
fn wallet_issues(db: &Database, r: &mut Report) {
    use crate::{wallet, wallet_derive};
    for e in db.iter_all_entries() {
        if model::kind_of(&e) != EntryKind::CryptoWallet
            || model::in_recycle_bin(db, e.parent().id())
            || excluded(&e)
        {
            continue;
        }
        let get = |k: &str| e.get(k).unwrap_or_default();
        let seed = get(wallet::SEED);
        let mut issues = vec![];
        if !seed.trim().is_empty() {
            let c = wallet::check_seed(seed);
            if !c.valid {
                issues.push(Issue::BadSeed { message: c.message });
            }
        }
        let addrs: Vec<String> = wallet::parse_addresses(get(wallet::ADDRESSES))
            .into_iter()
            .map(|(_, a)| a)
            .collect();
        let seed_ok = issues.is_empty();
        let bad = wallet_derive::unmatched_addresses(
            if seed_ok { seed } else { "" },
            get(wallet::PASSPHRASE),
            get(wallet::PRIVATE_KEY),
            get(wallet::XPUB),
            get(wallet::DERIVATION),
            &addrs,
        );
        if !bad.is_empty() {
            issues.push(Issue::AddressMismatch { addresses: bad });
        }
        if !issues.is_empty() {
            r.wallets += 1;
            let s = model::summary(&e);
            r.items.push(Item {
                id: s.id,
                title: s.title,
                username: s.username,
                url: s.url,
                group: s.group,
                kind: s.kind,
                issues,
            });
        }
    }
}

/// Запросы к HIBP: префикс SHA-1 (5 символов) -> какие записи с каким хвостом хэша ждут ответа.
pub fn hibp_queries(db: &Database) -> HashMap<String, Vec<(String, String)>> {
    let mut q: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for (e, p) in checked_entries(db) {
        let hex = data_encoding::HEXUPPER.encode(&Sha1::digest(p.as_bytes()));
        let (prefix, suffix) = hex.split_at(5);
        q.entry(prefix.to_string())
            .or_default()
            .push((suffix.to_string(), e.id().uuid().to_string()));
    }
    q
}

/// Ответ `range/{prefix}`: строки "ХВОСТ:число"; дополняющие строки с нулём пропускаются.
pub fn hibp_parse(body: &str, wanted: &[(String, String)], out: &mut HashMap<String, u64>) {
    let found: HashMap<&str, u64> = body
        .lines()
        .filter_map(|l| {
            let (s, n) = l.trim().split_once(':')?;
            Some((s, n.trim().parse().ok()?))
        })
        .collect();
    for (suffix, id) in wanted {
        out.insert(id.clone(), found.get(suffix.as_str()).copied().unwrap_or(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntryPatch, FieldSet, create_entry};

    fn add(db: &mut Database, title: &str, pw: &str) -> String {
        create_entry(
            db,
            &EntryPatch {
                set: vec![FieldSet::new("Title", title), FieldSet::new("Password", pw)],
                ..Default::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn finds_weak_reused_old_and_breached() {
        let mut db = Database::new();
        let weak = add(&mut db, "Weak", "password1");
        let a = add(&mut db, "A", "Kx9$mPq2!vLr8#Tz");
        let b = add(&mut db, "B", "Kx9$mPq2!vLr8#Tz");
        let strong = add(&mut db, "Strong", "correct-horse-battery-staple-91!Q");
        let old = add(&mut db, "Old", "Zq7&wErT5^yUi9*O");
        db.entry_mut(model::parse_entry_id(&old).unwrap())
            .unwrap()
            .times
            .last_modification = Some(Times::now() - chrono::Duration::days(400));
        let skip = add(&mut db, "Skip", "123");
        set_excluded(&mut db, &skip, true).unwrap();

        let r = report(&db, None, None);
        assert_eq!((r.checked, r.excluded), (5, 1));
        assert_eq!((r.weak, r.reused, r.old), (1, 2, 1));
        assert!(!r.items.iter().any(|i| i.id == strong));
        assert_eq!(r.items[0].id, weak, "слабый пароль выше повтора");
        assert!(r.items.iter().any(|i| i.id == a) && r.items.iter().any(|i| i.id == b));

        // HIBP: хвост хэша "password1" есть в ответе
        let q = hibp_queries(&db);
        let hex = data_encoding::HEXUPPER.encode(&Sha1::digest(b"password1"));
        let wanted = &q[&hex[..5]];
        let body = format!(
            "0000000000000000000000000000000000A:0\r\n{}:2413945\r\n",
            &hex[5..]
        );
        let mut found = HashMap::new();
        hibp_parse(&body, wanted, &mut found);
        assert_eq!(found[&weak], 2_413_945);
        let r = report(&db, Some(&found), None);
        assert_eq!(r.breached, 1);
        assert!(matches!(r.items[0].issues[0], Issue::Breached { .. }));
    }

    #[test]
    fn wallet_checks() {
        let mut db = Database::new();
        let mk = |db: &mut Database, title: &str, seed: &str, addr: &str| {
            create_entry(
                db,
                &EntryPatch {
                    set: vec![
                        FieldSet::new("Title", title),
                        FieldSet::new("Seed", seed),
                        FieldSet::new("Addresses", addr),
                    ],
                    kind: Some(EntryKind::CryptoWallet),
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let ok = mk(
            &mut db,
            "ok",
            &format!("{abandon} about"),
            "основной: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        );
        let bad = mk(&mut db, "bad", &format!("{abandon} abandon"), "");
        let typo = mk(
            &mut db,
            "typo",
            &format!("{abandon} about"),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv",
        );
        let r = report(&db, None, None);
        assert_eq!(r.wallets, 2);
        assert!(!r.items.iter().any(|i| i.id == ok));
        let issue = |id: &str| r.items.iter().find(|i| i.id == id).unwrap().issues[0].clone();
        assert!(matches!(issue(&bad), Issue::BadSeed { .. }));
        assert!(matches!(issue(&typo), Issue::AddressMismatch { .. }));
    }

    #[test]
    fn insecure_urls_and_directory() {
        assert!(insecure("http://example.com/login"));
        assert!(!insecure("https://example.com"));
        assert!(!insecure("http://192.168.1.1"));
        assert!(!insecure("http://localhost:8080"));

        let mut dir = Directory::default();
        dir.parse_totp(r#"[["GitHub",{"domain":"github.com","additional-domains":["gist.github.com"],"documentation":"https://docs.github.com/2fa"}]]"#).unwrap();
        dir.parse_passkeys(r#"{"github.com":{"passwordless":"allowed","documentation":"https://gh/pk"},"x.com":{"mfa":"allowed"}}"#).unwrap();
        assert!(dir.passkeys.contains_key("github.com") && !dir.passkeys.contains_key("x.com"));

        let mut db = Database::new();
        let gh = create_entry(
            &mut db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Title", "GitHub"),
                    FieldSet::new("Password", "Kx9$mPq2!vLr8#Tz-unique-1"),
                    FieldSet::new("URL", "https://www.github.com/login"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        let r = report(&db, None, Some(&dir));
        let item = r.items.iter().find(|i| i.id == gh).unwrap();
        assert!(item.issues.contains(&Issue::NoTwoFactor {
            doc: "https://docs.github.com/2fa".into()
        }));
        assert_eq!((r.no_2fa, r.passkey_ready, r.sites_checked), (1, 1, true));
    }
}
