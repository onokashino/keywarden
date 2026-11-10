//! Перенос: экспорт в CSV (формат KeePassXC, его принимают Bitwarden, 1Password, Proton Pass)
//! и импорт CSV из KeePassXC, Chrome, Firefox, Bitwarden, 1Password, Proton Pass, а также
//! импорт записей из другой базы KeePass (.kdbx или старой .kdb) в отдельную папку.

use crate::bitwarden::ImportReport;
use crate::model::{self, EntryKind, EntryPatch, FieldSet, ModelError};
use keepass::Database;
use keepass::db::{GroupId, GroupRef, fields};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    #[error("{}", crate::tr!("CSV не прочитан: {e}", e = .0))]
    Csv(String),
    #[error("{}", crate::tr!("в CSV нет колонок с названием, логином, паролем или адресом: {e}", e = .0))]
    UnknownColumns(String),
    #[error(transparent)]
    Model(#[from] ModelError),
}

const CSV_HEADER: [&str; 10] = [
    "Group",
    "Title",
    "Username",
    "Password",
    "URL",
    "Notes",
    "TOTP",
    "Icon",
    "Last Modified",
    "Created",
];

/// Все записи, кроме корзины, в CSV как у KeePassXC. Файл содержит пароли открытым текстом.
pub fn export_csv(db: &Database) -> String {
    let mut w = csv::WriterBuilder::new()
        .quote_style(csv::QuoteStyle::Always)
        .from_writer(vec![]);
    let _ = w.write_record(CSV_HEADER);
    let root = db.root().name.clone();
    for e in db.iter_all_entries() {
        let gid = e.parent().id();
        if model::in_recycle_bin(db, gid) {
            continue;
        }
        let path = model::group_path(db, gid);
        let group = if path.is_empty() {
            root.clone()
        } else {
            format!("{root}/{path}")
        };
        let get = |k: &str| e.get(k).unwrap_or_default().to_string();
        let ts = |t: Option<chrono::NaiveDateTime>| {
            t.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default()
        };
        let icon = match e.icon() {
            Some(keepass::db::Icon::BuiltIn(i)) => i.to_string(),
            _ => "0".into(),
        };
        let _ = w.write_record([
            group,
            get(fields::TITLE),
            get(fields::USERNAME),
            get(fields::PASSWORD),
            get(fields::URL),
            get(fields::NOTES),
            get(fields::OTP),
            icon,
            ts(e.times.last_modification),
            ts(e.times.creation),
        ]);
    }
    String::from_utf8(w.into_inner().unwrap_or_default()).unwrap_or_default()
}

/// Колонки, которые узнаём, по их названиям в разных менеджерах (сравнение без регистра).
const COLUMNS: &[(&str, &[&str])] = &[
    ("title", &["title", "name"]),
    (
        "username",
        &["username", "login_username", "login", "user", "email"],
    ),
    ("password", &["password", "login_password"]),
    ("url", &["url", "login_uri", "website", "uri", "web site"]),
    ("notes", &["notes", "note", "comments", "extra"]),
    (
        "totp",
        &["totp", "otpauth", "login_totp", "otp", "one-time password"],
    ),
    ("group", &["group", "folder", "vault", "grouping"]),
    ("tags", &["tags"]),
];

/// Импорт CSV в новую папку `group_name`; колонка папки (если есть) даёт вложенные папки.
pub fn import_csv(
    db: &mut Database,
    text: &str,
    group_name: &str,
) -> Result<ImportReport, TransferError> {
    let mut rd = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.trim_start_matches('\u{feff}').as_bytes());
    let headers: Vec<String> = rd
        .headers()
        .map_err(|e| TransferError::Csv(e.to_string()))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let col = |name: &str| -> Option<usize> {
        let aliases = COLUMNS.iter().find(|(k, _)| *k == name)?.1;
        aliases
            .iter()
            .find_map(|a| headers.iter().position(|h| h == a))
    };
    let (title, user, pass, url) = (col("title"), col("username"), col("password"), col("url"));
    if title.is_none() && user.is_none() && pass.is_none() && url.is_none() {
        return Err(TransferError::UnknownColumns(headers.join(", ")));
    }
    let (notes, totp, group, tags) = (col("notes"), col("totp"), col("group"), col("tags"));
    // KeePassXC пишет полный путь с корнем: "Root/Почта"; корень отрезаем
    let keepassxc = headers.first().is_some_and(|h| h == "group") && title.is_some();

    let mut report = ImportReport::default();
    let root = model::add_group(db, None, group_name)?;
    let mut groups: HashMap<String, String> = HashMap::new();
    for rec in rd.records() {
        let rec = rec.map_err(|e| TransferError::Csv(e.to_string()))?;
        let get = |i: Option<usize>| i.and_then(|i| rec.get(i)).unwrap_or_default().trim();
        let (t, u, p, l) = (get(title), get(user), get(pass), get(url));
        if t.is_empty() && u.is_empty() && p.is_empty() && l.is_empty() {
            continue;
        }
        let mut path = get(group).replace('\\', "/");
        if keepassxc {
            path = path
                .split_once('/')
                .map(|x| x.1.to_string())
                .unwrap_or_default();
        }
        let parent = ensure_path(db, &root, &path, &mut groups, &mut report)?;
        let title = if t.is_empty() {
            host_of(l).unwrap_or_else(|| u.to_string())
        } else {
            t.to_string()
        };
        let mut set = vec![
            FieldSet::new(fields::TITLE, title.clone()),
            FieldSet::new(fields::USERNAME, u),
            FieldSet::new(fields::PASSWORD, p),
            FieldSet::new(fields::URL, l),
            FieldSet::new(fields::NOTES, get(notes)),
        ];
        let otp = get(totp);
        if !otp.is_empty() {
            set.push(FieldSet::new(fields::OTP, otp_uri(otp, &title, u)));
        }
        let tags: Vec<String> = get(tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        let kind = if p.is_empty() && u.is_empty() && l.is_empty() {
            report.notes += 1;
            EntryKind::Note
        } else {
            report.logins += 1;
            EntryKind::Login
        };
        model::create_entry(
            db,
            &EntryPatch {
                kind: Some(kind),
                group: Some(parent),
                tags: (!tags.is_empty()).then_some(tags),
                set,
                remove: vec![],
                expires: None,
                autotype: None,
            },
        )?;
    }
    Ok(report)
}

/// "https://mail.example.org/x" -> "mail.example.org"
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    (!host.is_empty()).then(|| host.to_string())
}

/// Голый секрет base32 (как в Bitwarden и 1Password) превращаем в otpauth://, чтобы его понимали все.
fn otp_uri(v: &str, title: &str, user: &str) -> String {
    if v.starts_with("otpauth://") || v.starts_with("steam://") {
        return v.to_string();
    }
    let secret: String = v.chars().filter(|c| !c.is_whitespace()).collect();
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        enc(title),
        enc(user),
        secret.to_uppercase(),
        enc(title)
    )
}

fn ensure_path(
    db: &mut Database,
    root: &str,
    path: &str,
    cache: &mut HashMap<String, String>,
    report: &mut ImportReport,
) -> Result<String, ModelError> {
    let mut parent = root.to_string();
    let mut acc = String::new();
    for part in path.split('/').map(str::trim).filter(|p| !p.is_empty()) {
        acc = if acc.is_empty() {
            part.into()
        } else {
            format!("{acc}/{part}")
        };
        parent = match cache.get(&acc) {
            Some(g) => g.clone(),
            None => {
                let g = model::add_group(db, Some(&parent), part)?;
                report.folders += 1;
                cache.insert(acc.clone(), g.clone());
                g
            }
        };
    }
    Ok(parent)
}

/// Записи другой базы KeePass в новую папку `group_name` со всей структурой папок, полями,
/// тегами, вложениями и временем. История не переносится: её версии ссылаются на вложения
/// чужой базы. Корзина чужой базы пропускается.
pub fn import_database(
    dest: &mut Database,
    src: &Database,
    group_name: &str,
) -> Result<ImportReport, TransferError> {
    let mut report = ImportReport::default();
    let root = model::add_group(dest, None, group_name)?;
    let root = model::parse_group_id(&root)?;
    copy_group(dest, src, src.root(), root, &mut report)?;
    Ok(report)
}

fn copy_group(
    dest: &mut Database,
    src: &Database,
    from: GroupRef<'_>,
    into: GroupId,
    report: &mut ImportReport,
) -> Result<(), TransferError> {
    for e in from.entries() {
        let attachments: Vec<(String, keepass::db::Value<Vec<u8>>)> = e
            .attachments_named()
            .map(|(n, a)| (n.to_string(), a.data.clone()))
            .collect();
        let mut g = dest.group_mut(into).ok_or(ModelError::GroupNotFound)?;
        let mut ne = g.add_entry();
        ne.fields = e.fields.clone();
        ne.tags = e.tags.clone();
        ne.times = e.times.clone();
        ne.custom_data = e.custom_data.clone();
        ne.autotype = e.autotype.clone();
        ne.override_url = e.override_url.clone();
        if let Some(keepass::db::Icon::BuiltIn(i)) = e.icon() {
            ne.set_icon_builtin(*i);
        }
        for (name, data) in attachments {
            ne.add_attachment(name, data);
        }
        match model::kind_of(&e) {
            EntryKind::Card => report.cards += 1,
            EntryKind::Identity => report.identities += 1,
            EntryKind::Note => report.notes += 1,
            EntryKind::SshKey => report.ssh_keys += 1,
            _ => report.logins += 1,
        }
    }
    let bin = src.meta.recyclebin_uuid;
    for sub in from.groups() {
        if Some(sub.id().uuid()) == bin {
            continue;
        }
        let id = {
            let mut g = dest.group_mut(into).ok_or(ModelError::GroupNotFound)?;
            let mut ng = g.add_group();
            ng.name = sub.name.clone();
            ng.notes = sub.notes.clone();
            ng.times = sub.times.clone();
            ng.id()
        };
        report.folders += 1;
        copy_group(dest, src, sub, id, report)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn titles(db: &Database) -> Vec<String> {
        let mut v: Vec<String> = db
            .iter_all_entries()
            .map(|e| e.get_title().unwrap_or_default().to_string())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn csv_roundtrip_keepassxc_format() {
        let mut db = Database::new();
        let g = model::add_group(&mut db, None, "Почта").unwrap();
        model::create_entry(
            &mut db,
            &EntryPatch {
                group: Some(g),
                set: vec![
                    FieldSet::new("Title", "Gmail"),
                    FieldSet::new("UserName", "ivan"),
                    FieldSet::new("Password", "p\"a,ss\nw"),
                    FieldSet::new("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        let csv = export_csv(&db);
        assert!(csv.starts_with("\"Group\",\"Title\""));

        let mut back = Database::new();
        let r = import_csv(&mut back, &csv, "Импорт").unwrap();
        assert_eq!(r.logins, 1);
        let e = back.iter_all_entries().next().unwrap();
        assert_eq!(
            e.get_password(),
            Some("p\"a,ss\nw"),
            "кавычки, запятые, переводы строк"
        );
        assert!(e.get("otp").unwrap().contains("JBSWY3DPEHPK3PXP"));
        assert_eq!(model::group_path(&back, e.parent().id()), "Импорт/Почта");
    }

    #[test]
    fn csv_from_browsers_and_managers() {
        let chrome = "name,url,username,password,note\nGitHub,https://github.com/login,octo,pw1,\n";
        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\"\n\"https://mail.example.org\",\"bob\",\"pw2\",\"\"\n";
        let bitwarden = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,,login,Jira,,,0,https://jira.x,al,pw3,JBSWY3DPEHPK3PXP\n";
        let onepassword = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nSteam,https://store.steampowered.com,gamer,pw4,,false,false,\"games, fun\",\n";
        let mut db = Database::new();
        for (csv, n) in [
            (chrome, "c"),
            (firefox, "f"),
            (bitwarden, "b"),
            (onepassword, "o"),
        ] {
            import_csv(&mut db, csv, n).unwrap();
        }
        assert_eq!(titles(&db), ["GitHub", "Jira", "Steam", "mail.example.org"]);
        let jira = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("Jira"))
            .unwrap();
        assert!(
            jira.get("otp")
                .unwrap()
                .starts_with("otpauth://totp/Jira:al?secret=JBSWY3DPEHPK3PXP")
        );
        assert_eq!(model::group_path(&db, jira.parent().id()), "b/Work");
        let steam = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("Steam"))
            .unwrap();
        assert_eq!(steam.tags, ["games", "fun"]);
        assert!(import_csv(&mut db, "a,b\n1,2\n", "x").is_err());
    }

    #[test]
    fn import_other_database_keeps_structure_and_attachments() {
        let mut src = Database::new();
        let g = model::add_group(&mut src, None, "Банк").unwrap();
        let id = model::create_entry(
            &mut src,
            &EntryPatch {
                group: Some(g),
                set: vec![
                    FieldSet::new("Title", "Карта"),
                    FieldSet::new("Password", "1"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        model::add_attachment(&mut src, &id, "скан.pdf", b"PDF".to_vec()).unwrap();
        model::delete_entry(&mut src, &id).ok(); // в корзину: не переносится
        let id2 = model::create_entry(
            &mut src,
            &EntryPatch {
                group: None,
                set: vec![FieldSet::new("Title", "Почта")],
                ..Default::default()
            },
        )
        .unwrap();
        model::add_attachment(&mut src, &id2, "a.txt", b"AAA".to_vec()).unwrap();

        let mut dest = Database::new();
        let r = import_database(&mut dest, &src, "Старая база").unwrap();
        assert_eq!(r.total(), 1, "корзина пропущена");
        let e = dest.iter_all_entries().next().unwrap();
        assert_eq!(e.get_title(), Some("Почта"));
        assert_eq!(
            model::attachment(&dest, &e.id().uuid().to_string(), "a.txt").unwrap(),
            b"AAA"
        );
    }
}
