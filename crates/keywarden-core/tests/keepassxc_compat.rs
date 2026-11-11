//! Совместимость: база из KeePassXC → открыть и сохранить в Keywarden → keepassxc-cli видит
//! ровно то же содержимое. Сравнивается полный XML-экспорт keepassxc-cli до и после.
//! Нужен keepassxc-cli в PATH (есть в docker/Dockerfile.dev).
//! Формат файла от системы не зависит, поэтому тесты идут только на Linux (CI и docker).
#![cfg(target_os = "linux")]

use keywarden_core::vault::{Credentials, Vault};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const PW: &str = "compat-test";
const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/kpxc-full.xml");

fn kpxc(args: &[&str], stdin: &str) -> Vec<u8> {
    let mut child = Command::new("keepassxc-cli")
        .args(args)
        .env("HOME", std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("keepassxc-cli не найден: запускайте тесты в docker (make test)");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "keepassxc-cli {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn export(db: &Path, keyfile: Option<&Path>) -> String {
    let mut args = vec!["export", "-q", "-f", "xml"];
    if let Some(k) = keyfile {
        args.extend(["-k", k.to_str().unwrap()]);
    }
    args.push(db.to_str().unwrap());
    String::from_utf8(kpxc(&args, &format!("{PW}\n"))).unwrap()
}

fn import(dir: &Path, keyfile: Option<&Path>) -> std::path::PathBuf {
    let db = dir.join("from-kpxc.kdbx");
    let mut args = vec!["import", "-q", "-p", "-t", "100"];
    if let Some(k) = keyfile {
        args.extend(["-k", k.to_str().unwrap()]);
    }
    args.extend([FIXTURE, db.to_str().unwrap()]);
    kpxc(&args, &format!("{PW}\n{PW}\n"));
    db
}

/// Убирает то, что от Keywarden не зависит:
/// - `_LAST_MODIFIED`: KeePassXC пишет туда время самого экспорта;
/// - порядок `<Item>` внутри `<CustomData>`: keepass-rs хранит их в HashMap, на смысл порядок не влияет.
fn normalize(xml: &str) -> String {
    let mut out = Vec::new();
    let mut lines = xml.lines();
    while let Some(line) = lines.next() {
        // номер вложения в общем пуле зависит от версии KeePassXC и сдвигается от чужих вложений
        out.push(match line.split_once("<Value Ref=\"") {
            Some((head, _)) => format!("{head}<Value Ref/>"),
            None => line.to_string(),
        });
        if line.trim() != "<CustomData>" {
            continue;
        }
        let mut items: Vec<String> = Vec::new();
        for l in lines.by_ref() {
            match l.trim() {
                "</CustomData>" => {
                    items.retain(|i| !i.contains("<Key>_LAST_MODIFIED</Key>"));
                    items.sort();
                    out.append(&mut items);
                    out.push(l.to_string());
                    break;
                }
                "<Item>" => items.push(format!("{l}\n")),
                _ => items
                    .last_mut()
                    .expect("строка вне <Item>")
                    .push_str(&format!("{l}\n")),
            }
        }
    }
    out.join("\n")
}

/// Построчный diff, чтобы в падении теста было видно, что именно потерялось.
fn assert_same_xml(before: &str, after: &str) {
    if let Some(d) = std::env::var_os("KW_COMPAT_DUMP") {
        std::fs::write(Path::new(&d).join("before.xml"), before).unwrap();
        std::fs::write(Path::new(&d).join("after.xml"), after).unwrap();
    }
    let (before, after) = (&normalize(before), &normalize(after));
    if before == after {
        return;
    }
    let (a, b): (Vec<_>, Vec<_>) = (before.lines().collect(), after.lines().collect());
    let first = a
        .iter()
        .zip(&b)
        .position(|(x, y)| x != y)
        .unwrap_or(a.len().min(b.len()));
    let ctx = |v: &[&str]| v[first.saturating_sub(5)..(first + 10).min(v.len())].join("\n");
    panic!(
        "XML отличается со строки {first}:\n--- KeePassXC ---\n{}\n--- после Keywarden ---\n{}",
        ctx(&a),
        ctx(&b)
    );
}

#[test]
fn roundtrip_preserves_everything() {
    let dir = tempfile::tempdir().unwrap();
    let db = import(dir.path(), None);
    let before = export(&db, None);
    // фикстура действительно содержит то, что мы проверяем
    for needle in [
        "KeeAgent.settings",
        "KPEX_PASSKEY_PRIVATE_KEY_PEM",
        "otpauth://",
        "TOTP Seed",
        "<History>",
        "DeletedObject",
        "keywarden.type",
        "<Icon>",
    ] {
        assert!(before.contains(needle), "в фикстуре нет {needle}");
    }

    let creds = Credentials {
        password: Some(PW.into()),
        keyfile: None,
        challenge: None,
    };
    let mut v = Vault::open(&db, &creds).unwrap();
    v.backups.dir = dir.path().join("bak");
    v.save().unwrap();

    assert_same_xml(&before, &export(&db, None));
    // и Keywarden читает свою же запись
    Vault::open(&db, &creds).unwrap();
}

#[test]
fn roundtrip_with_keyfile() {
    let dir = tempfile::tempdir().unwrap();
    let kf = dir.path().join("k.keyx");
    std::fs::write(&kf, b"0123456789abcdef0123456789abcdef-not-xml-just-bytes").unwrap();
    let db = import(dir.path(), Some(&kf));
    let before = export(&db, Some(&kf));

    let creds = Credentials {
        password: Some(PW.into()),
        keyfile: Some(kf.clone()),
        challenge: None,
    };
    let mut v = Vault::open(&db, &creds).unwrap();
    v.backups.dir = dir.path().join("bak");
    v.save().unwrap();
    assert_same_xml(&before, &export(&db, Some(&kf)));
}

/// Смена ключа и настроек базы: KeePassXC открывает новым паролем и нашим файлом-ключом,
/// старым паролем не открывает, содержимое то же.
#[test]
fn change_key_and_settings_open_in_keepassxc() {
    let dir = tempfile::tempdir().unwrap();
    let db = import(dir.path(), None);
    let before = export(&db, None);
    let kf = dir.path().join("new.keyx");
    keywarden_core::vault::generate_keyfile(&kf).unwrap();

    let old = Credentials {
        password: Some(PW.into()),
        keyfile: None,
        challenge: None,
    };
    let new = Credentials {
        password: Some("новый пароль".into()),
        keyfile: Some(kf.clone()),
        challenge: None,
    };
    let mut v = Vault::open(&db, &old).unwrap();
    v.backups.dir = dir.path().join("bak");
    let mut s = keywarden_core::settings::get(&v.db);
    s.cipher = keywarden_core::vault::Cipher::ChaCha20;
    s.kdf = "argon2id".into();
    s.kdf_iterations = 2;
    s.kdf_parallelism = 1;
    s.kdf_memory_mib = 16;
    s.name = "Перешифрованная".into();
    keywarden_core::settings::apply(&mut v.db, &s).unwrap();
    v.replace_key(&new).unwrap();
    v.save().unwrap();

    let out = kpxc(
        &[
            "export",
            "-q",
            "-f",
            "xml",
            "-k",
            kf.to_str().unwrap(),
            db.to_str().unwrap(),
        ],
        "новый пароль\n",
    );
    let after = String::from_utf8(out).unwrap();
    assert!(after.contains("<DatabaseName>Перешифрованная</DatabaseName>"));
    // всё, кроме имени базы и меток смены ключа и настроек, совпадает
    let strip = |x: &str| {
        x.lines()
            .filter(|l| {
                !["DatabaseName", "MasterKeyChanged", "SettingsChanged"]
                    .iter()
                    .any(|t| l.contains(t))
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_same_xml(&strip(&before), &strip(&after));

    let fail = Command::new("keepassxc-cli")
        .args(["ls", "-q", db.to_str().unwrap()])
        .env("HOME", std::env::temp_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .and_then(|mut c| {
            c.stdin
                .take()
                .unwrap()
                .write_all(format!("{PW}\n").as_bytes())?;
            c.wait()
        })
        .unwrap();
    assert!(!fail.success(), "старый пароль больше не подходит");
}

/// Базы старых форматов (KDBX 3.1 от `keepassxc-cli db-create`, KDBX 4.0) открываются,
/// сохраняются как KDBX 4.1 и остаются читаемыми в KeePassXC с тем же содержимым.
#[test]
fn old_formats_are_upgraded_on_save() {
    let dir = tempfile::tempdir().unwrap();
    let ticks = regex::Regex::new(r">([A-Za-z0-9+/]{11}=)<").unwrap();
    for (name, extra) in [("v31.kdbx", vec![]), ("v4.kdbx", vec!["-t", "100"])] {
        let db = dir.path().join(name);
        let mut args = vec!["db-create", "-q", "-p"];
        args.extend(extra);
        args.push(db.to_str().unwrap());
        kpxc(&args, &format!("{PW}\n{PW}\n"));
        kpxc(
            &[
                "add",
                "-q",
                "-u",
                "old-user",
                db.to_str().unwrap(),
                "Старая запись",
            ],
            &format!("{PW}\n"),
        );
        let header = std::fs::read(&db).unwrap()[8..12].to_vec();
        let before = export(&db, None);
        let creds = Credentials {
            password: Some(PW.into()),
            keyfile: None,
            challenge: None,
        };
        let mut v = Vault::open(&db, &creds).unwrap();
        v.backups.dir = dir.path().join("bak");
        v.save()
            .unwrap_or_else(|e| panic!("{name} (заголовок {header:?}): {e}"));
        let after = std::fs::read(&db).unwrap();
        assert_eq!(&after[8..12], &[1, 0, 4, 0], "{name}: теперь KDBX 4.1");
        assert!(export(&db, None).contains("old-user"));
        // KDBX 4 хранит время тиками в base64, KDBX 3.1 текстом: приводим к одному виду
        let strip = |x: &str| {
            let x = ticks.replace_all(x, |c: &regex::Captures<'_>| {
                let b = data_encoding::BASE64.decode(c[1].as_bytes()).unwrap();
                let secs = i64::from_le_bytes(b.try_into().unwrap());
                let t = chrono::NaiveDate::from_ymd_opt(1, 1, 1)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap()
                    + chrono::Duration::seconds(secs);
                format!(">{}<", t.format("%Y-%m-%dT%H:%M:%SZ"))
            });
            x.lines()
                // признаки формата, а не данные: вложения KDBX 4 лежат во внутреннем заголовке,
                // SettingsChanged есть только в KDBX 4.x
                .filter(|l| {
                    ![
                        "<Generator>",
                        "HeaderHash",
                        "<Binaries/>",
                        "<SettingsChanged>",
                    ]
                    .iter()
                    .any(|t| l.contains(t))
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_same_xml(&strip(&before), &strip(&export(&db, None)));
    }
}

/// Правки Keywarden видны в KeePassXC, а всё, что не трогали, остаётся байт в байт.
#[test]
fn edits_are_visible_in_keepassxc() {
    use keywarden_core::model::{self, EntryPatch, FieldSet};
    let dir = tempfile::tempdir().unwrap();
    let db = import(dir.path(), None);
    let before = normalize(&export(&db, None));

    let creds = Credentials {
        password: Some(PW.into()),
        keyfile: None,
        challenge: None,
    };
    let mut v = Vault::open(&db, &creds).unwrap();
    v.backups.dir = dir.path().join("bak");
    let id = |v: &Vault, t: &str| keywarden_core::search::search(&v.db, t, 1)[0].id.clone();
    let github = id(&v, "GitHub");
    let visa = id(&v, "Visa");
    model::update_entry(
        &mut v.db,
        &github,
        &EntryPatch {
            set: vec![FieldSet::new("Password", "новый-пароль")],
            ..Default::default()
        },
    )
    .unwrap();
    model::add_attachment(&mut v.db, &github, "extra.bin", vec![1, 2, 3]).unwrap();
    model::delete_entry(&mut v.db, &visa).unwrap();
    v.save().unwrap();

    let show = |path: &str, attr: &str| {
        String::from_utf8(kpxc(
            &["show", "-q", "-s", "-a", attr, db.to_str().unwrap(), path],
            &format!("{PW}\n"),
        ))
        .unwrap()
    };
    assert_eq!(show("/GitHub", "Password").trim(), "новый-пароль");
    assert_eq!(
        show("/Recycle Bin/Visa", "Card Number").trim(),
        "4111111111111111"
    );
    let att = kpxc(
        &[
            "attachment-export",
            "-q",
            "--stdout",
            db.to_str().unwrap(),
            "/GitHub",
            "extra.bin",
        ],
        &format!("{PW}\n"),
    );
    assert_eq!(att, vec![1, 2, 3]);

    // записи, которые не трогали, не изменились
    let after = normalize(&export(&db, None));
    for untouched in [
        "<Value>github ssh</Value>",
        "<Value>webauthn.io</Value>",
        "<Value>Old 2FA</Value>",
    ] {
        assert_eq!(
            entry_block(&before, untouched),
            entry_block(&after, untouched),
            "{untouched}"
        );
    }
}

/// XML верхней версии записи (без истории), найденной по строке внутри неё.
fn entry_block<'a>(xml: &'a str, needle: &str) -> &'a str {
    let at = xml.find(needle).unwrap_or_else(|| panic!("нет {needle}"));
    let start = xml[..at].rfind("<Entry>").unwrap();
    let end = at + xml[at..].find("</Entry>").unwrap();
    &xml[start..end]
}

/// Слияние с версией, которую изменил KeePassXC, должно давать базу, которая проходит
/// проверку записи (сериализация → расшифровка → то же самое).
#[test]
fn merge_with_keepassxc_change_saves() {
    let dir = tempfile::tempdir().unwrap();
    let db = import(dir.path(), None);
    let creds = Credentials {
        password: Some(PW.into()),
        keyfile: None,
        challenge: None,
    };
    let mut v = Vault::open(&db, &creds).unwrap();
    v.backups.dir = dir.path().join("bak");
    // те же правки, что в e2e: папка, карта, правка с вложением, удаление в корзину
    {
        use keywarden_core::model::{self, EntryKind, EntryPatch, FieldSet};
        let id = |v: &Vault, t: &str| keywarden_core::search::search(&v.db, t, 1)[0].id.clone();
        let g = model::add_group(&mut v.db, None, "Cards").unwrap();
        model::create_entry(
            &mut v.db,
            &EntryPatch {
                kind: Some(EntryKind::Card),
                group: Some(g),
                set: vec![
                    FieldSet::new("Title", "Mir"),
                    FieldSet::new("Card Number", "2200"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        v.save().unwrap();
        let gh = id(&v, "GitHub");
        model::update_entry(
            &mut v.db,
            &gh,
            &EntryPatch {
                set: vec![FieldSet::new("URL", "https://github.com/login")],
                ..Default::default()
            },
        )
        .unwrap();
        v.save().unwrap();
        model::add_attachment(&mut v.db, &gh, "extra.txt", b"hello\n".to_vec()).unwrap();
        v.save().unwrap();
        let visa = id(&v, "Visa");
        model::delete_entry(&mut v.db, &visa).unwrap();
        v.save().unwrap();
    }
    kpxc(
        &[
            "add",
            "-q",
            "-p",
            "-u",
            "ext",
            db.to_str().unwrap(),
            "/Извне",
        ],
        &format!("{PW}\nвнешний\n"),
    );
    let other = Vault::open(&db, &creds).unwrap();
    keywarden_core::merge::merge(&mut v.db, &other.db).unwrap();

    let key = keepass::DatabaseKey::new().with_password(PW);
    let mut buf = vec![];
    v.db.save(&mut buf, key.clone()).unwrap();
    let mut back = keepass::Database::parse(&buf, key).unwrap();
    back.remove_unused_attachments();
    let mut mine = v.db.clone();
    mine.remove_unused_attachments();
    if back != mine {
        let mut why = vec![];
        if back.meta != mine.meta {
            why.push("meta".to_string());
        }
        if back.deleted_objects != mine.deleted_objects {
            why.push(format!(
                "deleted_objects {:?} vs {:?}",
                mine.deleted_objects, back.deleted_objects
            ));
        }
        for e in mine.iter_all_entries() {
            match back.entry(e.id()) {
                None => why.push(format!("нет записи {}", e.id())),
                Some(b) if *b != *e => {
                    let (x, y) = (&*e, &*b);
                    let mut parts = vec![];
                    if x.fields != y.fields {
                        parts.push("fields")
                    }
                    if x.times != y.times {
                        parts.push("times")
                    }
                    if x.custom_data != y.custom_data {
                        parts.push("custom_data")
                    }
                    if x.history != y.history {
                        parts.push("history")
                    }
                    if x.tags != y.tags {
                        parts.push("tags")
                    }
                    if x.autotype != y.autotype {
                        parts.push("autotype")
                    }
                    why.push(format!(
                        "запись {} «{}»: {parts:?} / attachments {:?} vs {:?}",
                        e.id(),
                        e.get("Title").unwrap_or_default(),
                        e.attachments_named()
                            .map(|(n, a)| (n.to_string(), a.id().id()))
                            .collect::<Vec<_>>(),
                        b.attachments_named()
                            .map(|(n, a)| (n.to_string(), a.id().id()))
                            .collect::<Vec<_>>()
                    ));
                }
                _ => {}
            }
        }
        for g in mine.iter_all_groups() {
            match back.group(g.id()) {
                None => why.push(format!("нет группы {}", g.name)),
                Some(b) if *b != *g => why.push(format!(
                    "группа {} отличается: times {:?} vs {:?}",
                    g.name, g.times, b.times
                )),
                _ => {}
            }
        }
        if mine.num_attachments() != back.num_attachments() {
            why.push(format!(
                "вложений {} vs {}",
                mine.num_attachments(),
                back.num_attachments()
            ));
        }
        if mine.config != back.config {
            why.push("config".into());
        }
        let ids = |d: &keepass::Database| {
            let mut v: Vec<(usize, usize)> = d
                .iter_all_attachments()
                .map(|a| (a.id().id(), a.data.len()))
                .collect();
            v.sort();
            v
        };
        if ids(&mine) != ids(&back) {
            why.push(format!(
                "вложения (id, размер): {:?} vs {:?}",
                ids(&mine),
                ids(&back)
            ));
        }
        let icons = |d: &keepass::Database| {
            let mut v: Vec<String> = d
                .iter_all_custom_icons()
                .map(|i| format!("{:?}", i.id()))
                .collect();
            v.sort();
            v
        };
        if icons(&mine) != icons(&back) {
            why.push(format!("иконки: {:?} vs {:?}", icons(&mine), icons(&back)));
        }
        for i in mine.iter_all_custom_icons() {
            if back.custom_icon(i.id()).map(|b| *b != *i).unwrap_or(true) {
                why.push(format!("иконка {:?} отличается", i.id()));
            }
        }
        panic!(
            "после слияния база не совпадает с сохранённой:\n{}",
            why.join("\n")
        );
    }
}
