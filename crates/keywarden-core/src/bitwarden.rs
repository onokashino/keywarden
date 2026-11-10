//! Импорт из Bitwarden (незашифрованный JSON-экспорт) в типы Keywarden.
//!
//! Всё кладётся в группу «Bitwarden», папки становятся подгруппами. После импорта отчёт:
//! что перенесено и что требует ручной проверки.

use crate::keeagent;
use crate::model::{self, EntryKind, EntryPatch, FieldSet};
use keepass::Database;
use keepass::db::{Times, Value};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("{}", crate::tr!("это не экспорт Bitwarden в JSON: {e}", e = .0))]
    Format(String),
    #[error(
        "{}",
        crate::tr!(
            "экспорт зашифрован; выгрузите из Bitwarden «JSON» без пароля (формат .json, не «зашифрованный»)"
        )
    )]
    Encrypted,
    #[error(transparent)]
    Model(#[from] model::ModelError),
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImportReport {
    pub logins: usize,
    pub cards: usize,
    pub identities: usize,
    pub notes: usize,
    pub ssh_keys: usize,
    pub folders: usize,
    pub skipped_deleted: usize,
    /// «название: что проверить»
    pub review: Vec<String>,
}

impl ImportReport {
    pub fn total(&self) -> usize {
        self.logins + self.cards + self.identities + self.notes + self.ssh_keys
    }
}

#[derive(Deserialize)]
struct Export {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<Folder>,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Folder {
    id: String,
    name: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Item {
    folder_id: Option<String>,
    #[serde(rename = "type")]
    kind: u8,
    name: String,
    notes: Option<String>,
    favorite: bool,
    fields: Vec<Field>,
    login: Option<Login>,
    card: Option<Card>,
    identity: Option<Identity>,
    ssh_key: Option<SshKey>,
    password_history: Option<Vec<PasswordHistory>>,
    revision_date: Option<String>,
    creation_date: Option<String>,
    deleted_date: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Field {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    kind: u8,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Login {
    uris: Option<Vec<Uri>>,
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    fido2_credentials: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Uri {
    uri: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Card {
    cardholder_name: Option<String>,
    brand: Option<String>,
    number: Option<String>,
    exp_month: Option<String>,
    exp_year: Option<String>,
    code: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct Identity {
    title: Option<String>,
    first_name: Option<String>,
    middle_name: Option<String>,
    last_name: Option<String>,
    address1: Option<String>,
    address2: Option<String>,
    address3: Option<String>,
    city: Option<String>,
    state: Option<String>,
    postal_code: Option<String>,
    country: Option<String>,
    company: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    ssn: Option<String>,
    username: Option<String>,
    passport_number: Option<String>,
    license_number: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct SshKey {
    private_key: Option<String>,
    public_key: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
struct PasswordHistory {
    last_used_date: Option<String>,
    password: Option<String>,
}

fn s(v: &Option<String>) -> String {
    v.clone().unwrap_or_default()
}

fn time(v: &Option<String>) -> Option<chrono::NaiveDateTime> {
    v.as_deref()
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| t.naive_utc().with_nanosecond(0).unwrap_or(t.naive_utc()))
}

use chrono::Timelike;

/// TOTP Bitwarden → формат KeePassXC (поле `otp` с otpauth://).
pub fn totp_uri(totp: &str, label: &str) -> String {
    let t = totp.trim();
    if t.starts_with("otpauth://") {
        return t.to_string();
    }
    let label = url::form_urlencoded::byte_serialize(label.as_bytes()).collect::<String>();
    if let Some(secret) = t.strip_prefix("steam://") {
        return format!(
            "otpauth://totp/Steam:{label}?secret={secret}&period=30&digits=5&issuer=Steam&encoder=steam"
        );
    }
    let secret: String = t
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    format!("otpauth://totp/{label}?secret={secret}&period=30&digits=6")
}

pub fn import(db: &mut Database, json: &str) -> Result<ImportReport, ImportError> {
    let export: Export =
        serde_json::from_str(json).map_err(|e| ImportError::Format(e.to_string()))?;
    if export.encrypted {
        return Err(ImportError::Encrypted);
    }
    let mut report = ImportReport::default();

    // группа «Bitwarden» и папки внутри неё (имена вида "A/B" дают вложенность)
    let root = model::add_group(db, None, "Bitwarden")?;
    let mut by_path: HashMap<String, String> = HashMap::new();
    let mut folder_group: HashMap<String, String> = HashMap::new();
    for f in &export.folders {
        let mut parent = root.clone();
        let mut path = String::new();
        for part in f.name.split('/').map(str::trim).filter(|p| !p.is_empty()) {
            path = if path.is_empty() {
                part.to_string()
            } else {
                format!("{path}/{part}")
            };
            parent = match by_path.get(&path) {
                Some(g) => g.clone(),
                None => {
                    let g = model::add_group(db, Some(&parent), part)?;
                    report.folders += 1;
                    by_path.insert(path.clone(), g.clone());
                    g
                }
            };
        }
        folder_group.insert(f.id.clone(), parent);
    }

    for item in &export.items {
        if item.deleted_date.is_some() {
            report.skipped_deleted += 1;
            continue;
        }
        let title = if item.name.trim().is_empty() {
            crate::tr!("(без названия)").to_string()
        } else {
            item.name.clone()
        };
        let mut set = vec![FieldSet::new("Title", title.clone())];
        let mut notes = s(&item.notes);
        let kind;
        let mut ssh_private: Option<String> = None;
        match (
            item.kind,
            &item.login,
            &item.card,
            &item.identity,
            &item.ssh_key,
        ) {
            (1, Some(l), ..) => {
                kind = EntryKind::Login;
                report.logins += 1;
                set.push(FieldSet::new("UserName", s(&l.username)));
                set.push(FieldSet::new("Password", s(&l.password)));
                let uris: Vec<String> = l
                    .uris
                    .iter()
                    .flatten()
                    .filter_map(|u| u.uri.clone())
                    .filter(|u| !u.is_empty())
                    .collect();
                if let Some(first) = uris.first() {
                    set.push(FieldSet::new("URL", first.clone()));
                }
                // дополнительные адреса в формате KeePass2Android/KeePassDX, их понимает и KeePassXC
                for (i, u) in uris.iter().skip(1).enumerate() {
                    set.push(FieldSet {
                        name: if i == 0 {
                            "KP2A_URL".into()
                        } else {
                            format!("KP2A_URL_{i}")
                        },
                        value: u.clone().into(),
                        protected: Some(false),
                    });
                }
                if let Some(t) = l.totp.as_ref().filter(|t| !t.trim().is_empty()) {
                    let uri = totp_uri(t, &title);
                    if crate::totp::Totp::parse(&uri).is_err() {
                        report.review.push(crate::tr!(
                            "{title}: TOTP не распознан, перенесён как есть",
                            title = title
                        ));
                    }
                    set.push(FieldSet {
                        name: "otp".into(),
                        value: uri.into(),
                        protected: Some(true),
                    });
                }
                if l.fido2_credentials.as_ref().is_some_and(|c| !c.is_empty()) {
                    report.review.push(crate::tr!("{title}: ключ доступа (passkey) из Bitwarden не переносится, создайте его заново на сайте", title = title));
                }
            }
            (3, _, Some(c), ..) => {
                kind = EntryKind::Card;
                report.cards += 1;
                let exp = match (c.exp_month.as_deref(), c.exp_year.as_deref()) {
                    (Some(m), Some(y)) if !m.is_empty() && !y.is_empty() => format!(
                        "{:0>2}/{}",
                        m,
                        y.chars()
                            .rev()
                            .take(2)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect::<String>()
                    ),
                    _ => String::new(),
                };
                set.extend([
                    FieldSet::new("Cardholder", s(&c.cardholder_name)),
                    FieldSet::new("Card Number", s(&c.number)),
                    FieldSet::new("Expiry", exp),
                    FieldSet::new("CVV", s(&c.code)),
                    FieldSet::new("Brand", s(&c.brand)),
                ]);
            }
            (4, _, _, Some(i), _) => {
                kind = EntryKind::Identity;
                report.identities += 1;
                let address = [&i.address1, &i.address2, &i.address3]
                    .iter()
                    .map(|a| s(a))
                    .filter(|a| !a.is_empty())
                    .collect::<Vec<_>>()
                    .join("\n");
                for (name, v) in [
                    ("First Name", &i.first_name),
                    ("Middle Name", &i.middle_name),
                    ("Last Name", &i.last_name),
                    ("Email", &i.email),
                    ("Phone", &i.phone),
                    ("Company", &i.company),
                    ("City", &i.city),
                    ("State", &i.state),
                    ("Postal Code", &i.postal_code),
                    ("Country", &i.country),
                    ("Passport Number", &i.passport_number),
                    ("License Number", &i.license_number),
                    ("SSN", &i.ssn),
                    ("UserName", &i.username),
                    ("Обращение", &i.title),
                ] {
                    if v.as_deref().is_some_and(|x| !x.is_empty()) {
                        set.push(FieldSet::new(name, s(v)));
                    }
                }
                if !address.is_empty() {
                    set.push(FieldSet::new("Address", address));
                }
            }
            (5, .., Some(k)) => {
                kind = EntryKind::SshKey;
                report.ssh_keys += 1;
                ssh_private = k.private_key.clone().filter(|p| !p.is_empty());
                if let Some(p) = &k.public_key {
                    notes = if notes.is_empty() {
                        p.clone()
                    } else {
                        format!("{p}\n\n{notes}")
                    };
                }
                if !ssh_private
                    .as_deref()
                    .is_some_and(|p| p.contains("BEGIN OPENSSH PRIVATE KEY"))
                {
                    report.review.push(crate::tr!(
                        "{title}: ключ SSH не в формате OpenSSH, агент его не возьмёт",
                        title = title
                    ));
                }
            }
            (2, ..) => {
                kind = EntryKind::Note;
                report.notes += 1;
            }
            (t, ..) => {
                report.review.push(crate::tr!(
                    "{title}: неизвестный тип {t}, перенесено как заметка",
                    title = title,
                    t = t
                ));
                kind = EntryKind::Note;
                report.notes += 1;
            }
        }
        for f in &item.fields {
            let name = f.name.clone().unwrap_or_default();
            if name.is_empty() || matches!(name.as_str(), "Title" | "Notes") {
                continue;
            }
            match f.kind {
                3 => report.review.push(crate::tr!(
                    "{title}: связанное поле «{name}» не переносится",
                    title = title,
                    name = name
                )),
                1 => set.push(FieldSet {
                    name,
                    value: s(&f.value).into(),
                    protected: Some(true),
                }),
                _ => set.push(FieldSet {
                    name,
                    value: s(&f.value).into(),
                    protected: Some(false),
                }),
            }
        }
        set.push(FieldSet::new("Notes", notes));

        let group = item
            .folder_id
            .as_ref()
            .and_then(|f| folder_group.get(f))
            .cloned()
            .unwrap_or_else(|| root.clone());
        let tags = item
            .favorite
            .then(|| vec![crate::tr!("Избранное").to_string()]);
        let id = model::create_entry(
            db,
            &EntryPatch {
                kind: Some(kind),
                group: Some(group),
                tags,
                set,
                remove: vec![],
                expires: None,
                autotype: None,
            },
        )?;
        let eid = model::parse_entry_id(&id)?;
        let mut e = db.entry_mut(eid).ok_or(model::ModelError::EntryNotFound)?;

        if let Some(pk) = ssh_private {
            let file = "id_bitwarden";
            e.add_attachment(file, Value::protected(pk.into_bytes()));
            e.add_attachment(
                model::KEEAGENT_SETTINGS,
                Value::unprotected(keeagent::generate(file, false)),
            );
        }
        // старые пароли → история записи (как будто пароль меняли в Keywarden)
        let mut olds: Vec<&PasswordHistory> = item
            .password_history
            .iter()
            .flatten()
            .filter(|h| h.password.is_some())
            .collect();
        olds.sort_by_key(|h| time(&h.last_used_date));
        let mut history = e.history.clone().unwrap_or_default();
        for h in olds {
            let mut v = (*e).clone();
            v.history = None;
            v.set_protected("Password", s(&h.password));
            v.times.last_modification = time(&h.last_used_date).or(Some(Times::epoch()));
            history.add_entry(v);
        }
        e.history = Some(history);
        if let Some(c) = time(&item.creation_date) {
            e.times.creation = Some(c);
        }
        if let Some(m) = time(&item.revision_date) {
            e.times.last_modification = Some(m);
        }
    }
    db.remove_unused_attachments();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{detail, field_value};
    use crate::search::search;

    const SAMPLE: &str = include_str!("../tests/fixtures/bitwarden.json");

    #[test]
    fn imports_all_types() {
        let mut db = Database::new();
        let r = import(&mut db, SAMPLE).unwrap();
        assert_eq!(
            (r.logins, r.cards, r.identities, r.notes, r.ssh_keys),
            (2, 1, 1, 1, 1),
            "{r:?}"
        );
        assert_eq!(r.skipped_deleted, 1);
        assert!(r.review.iter().any(|x| x.contains("passkey")), "{r:?}");
        assert!(r.review.iter().any(|x| x.contains("связанное")), "{r:?}");

        let gh = &search(&db, "GitHub", 1)[0];
        assert_eq!(gh.group, "Bitwarden/Dev/Work");
        assert!(gh.has_otp);
        let d = detail(&db, &gh.id, true).unwrap();
        let get = |n: &str| {
            d.fields
                .iter()
                .find(|f| f.name == n)
                .and_then(|f| f.value.clone())
                .map(|v| v.expose().to_string())
        };
        assert_eq!(get("Password").as_deref(), Some("gh-pass"));
        assert_eq!(get("KP2A_URL").as_deref(), Some("https://gist.github.com"));
        assert_eq!(get("Recovery").as_deref(), Some("rc-123"));
        assert!(
            d.fields
                .iter()
                .find(|f| f.name == "Recovery")
                .unwrap()
                .protected,
            "hidden поле защищено"
        );
        assert_eq!(d.history.len(), 2, "история паролей перенесена");
        assert!(gh.tags.contains(&"Избранное".to_string()));

        let card = &search(&db, "Visa", 1)[0];
        assert_eq!(card.kind, EntryKind::Card);
        assert_eq!(
            field_value(&db, &card.id, "Expiry")
                .unwrap()
                .unwrap()
                .expose(),
            "04/29"
        );

        let steam = &search(&db, "Steam", 1)[0];
        let otp = field_value(&db, &steam.id, "otp").unwrap().unwrap();
        assert!(otp.expose().contains("encoder=steam"));

        let ssh = &search(&db, "server key", 1)[0];
        assert_eq!(ssh.kind, EntryKind::SshKey);
        assert_eq!(detail(&db, &ssh.id, false).unwrap().attachments.len(), 2);
    }

    #[test]
    fn rejects_encrypted_and_garbage() {
        assert!(matches!(
            import(&mut Database::new(), r#"{"encrypted":true,"items":[]}"#),
            Err(ImportError::Encrypted)
        ));
        assert!(matches!(
            import(&mut Database::new(), "not json"),
            Err(ImportError::Format(_))
        ));
    }

    #[test]
    fn totp_formats() {
        assert_eq!(
            totp_uri("jbsw y3dp", "A B"),
            "otpauth://totp/A+B?secret=JBSWY3DP&period=30&digits=6"
        );
        assert!(totp_uri("otpauth://totp/x?secret=AAAA", "x").starts_with("otpauth://totp/x"));
    }
}
