//! Слияние двух версий одной базы (синхронизация через Syncthing), как Merge в KeePassXC:
//! записи и группы сопоставляются по UUID, побеждает более поздняя правка, проигравшая версия
//! уходит в историю, удаления берутся из DeletedObjects.
//!
//! Основа: `Database::merge` из keepass-rs (с нашим патчем вложений, см. vendor/keepass).
//! Сверху: custom data базы (там ключи подключённых браузеров), объединение по ключу.

use keepass::Database;
use keepass::db::CustomDataItem;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MergeReport {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub moved: usize,
    pub warnings: Vec<String>,
}

impl MergeReport {
    pub fn is_empty(&self) -> bool {
        self.created + self.updated + self.deleted + self.moved == 0
    }

    pub fn summary(&self) -> String {
        let parts: Vec<String> = [
            (self.created, crate::tr!("добавлено")),
            (self.updated, crate::tr!("изменено")),
            (self.deleted, crate::tr!("удалено")),
            (self.moved, crate::tr!("перемещено")),
        ]
        .into_iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, w)| format!("{w} {n}"))
        .collect();
        if parts.is_empty() {
            crate::tr!("изменений нет").into()
        } else {
            parts.join(", ")
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{}", crate::tr!("слияние не удалось: {e}", e = .0))]
pub struct MergeError(String);

impl MergeError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Влить `other` в `dest`.
pub fn merge(dest: &mut Database, other: &Database) -> Result<MergeReport, MergeError> {
    use keepass::db::merge::MergeEventType as T;
    let log = dest.merge(other).map_err(|e| MergeError(e.to_string()))?;
    let mut r = MergeReport {
        warnings: log.warnings,
        ..Default::default()
    };
    for ev in log.events {
        match ev.event_type {
            T::Created => r.created += 1,
            T::Updated => r.updated += 1,
            T::Deleted => r.deleted += 1,
            T::LocationUpdated => r.moved += 1,
            _ => {}
        }
    }
    merge_custom_data(&mut dest.meta.custom_data, &other.meta.custom_data);
    merge_recycle_bin(dest, other);
    Ok(r)
}

/// Какая группа корзина, хранится в метаданных, а их keepass-rs не сливает: без этого корзина,
/// впервые созданная на другом устройстве, приезжала бы обычной папкой.
fn merge_recycle_bin(dest: &mut Database, other: &Database) {
    let Some(bin) = other.meta.recyclebin_uuid else {
        return;
    };
    let newer = match (dest.meta.recyclebin_uuid, dest.meta.recyclebin_changed) {
        (None, _) => true,
        (Some(mine), _) if mine == bin => false,
        (Some(_), mine) => other.meta.recyclebin_changed > mine,
    };
    if newer && dest.group(bin.into()).is_some() {
        dest.meta.recyclebin_uuid = Some(bin);
        dest.meta.recyclebin_changed = other.meta.recyclebin_changed;
        if dest.meta.recyclebin_enabled.is_none() {
            dest.meta.recyclebin_enabled = other.meta.recyclebin_enabled;
        }
    }
}

/// Объединение по ключу, при совпадении ключа побеждает более позднее изменение.
fn merge_custom_data(
    dest: &mut std::collections::HashMap<String, CustomDataItem>,
    other: &std::collections::HashMap<String, CustomDataItem>,
) {
    for (k, v) in other {
        match dest.get(k) {
            Some(mine) if mine.last_modification_time >= v.last_modification_time => {}
            _ => {
                dest.insert(k.clone(), v.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{self, EntryPatch, FieldSet, attachment, create_entry, field_value};
    use chrono::NaiveDateTime;
    use keepass::db::{CustomDataValue, Times};

    fn t(s: &str) -> NaiveDateTime {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()
    }

    fn set_mtime(db: &mut Database, id: &str, when: &str) {
        let mut e = db.entry_mut(model::parse_entry_id(id).unwrap()).unwrap();
        e.times.last_modification = Some(t(when));
    }

    fn entry(db: &mut Database, title: &str, pw: &str) -> String {
        let id = create_entry(
            db,
            &EntryPatch {
                set: vec![FieldSet::new("Title", title), FieldSet::new("Password", pw)],
                ..Default::default()
            },
        )
        .unwrap();
        set_mtime(db, &id, "2026-01-01 00:00:00");
        id
    }

    /// Через сохранение и загрузку, как это происходит при синхронизации файлом.
    fn roundtrip(db: &Database) -> Database {
        let key = keepass::DatabaseKey::new().with_password("p");
        let mut db = db.clone();
        db.config.kdf_config = crate::vault::test_kdf();
        let mut buf = vec![];
        db.save(&mut buf, key.clone()).unwrap();
        let mut back = Database::parse(&buf, key).unwrap();
        back.remove_unused_attachments();
        back
    }

    #[test]
    fn two_devices() {
        let mut base = Database::new();
        let edited = entry(&mut base, "Почта", "old");
        let deleted = entry(&mut base, "Старое", "x");
        model::add_attachment(&mut base, &edited, "a.txt", b"AAA".to_vec()).unwrap();
        set_mtime(&mut base, &edited, "2026-01-01 00:00:00");

        // устройство A меняет пароль
        let mut a = roundtrip(&base);
        model::update_entry(
            &mut a,
            &edited,
            &EntryPatch {
                set: vec![FieldSet::new("Password", "new")],
                ..Default::default()
            },
        )
        .unwrap();
        set_mtime(&mut a, &edited, "2026-02-01 00:00:00");

        // устройство B добавляет запись с вложением (номер вложения совпадёт с номером a.txt в A)
        // и окончательно удаляет запись
        let mut b = roundtrip(&base);
        let added = entry(&mut b, "Новая", "nn");
        model::remove_attachment(&mut b, &edited, "a.txt").ok(); // B не трогает вложения A
        model::delete_entry(&mut b, &deleted).unwrap();
        model::delete_entry(&mut b, &deleted).unwrap(); // из корзины насовсем
        let b = roundtrip(&b);
        let mut b = b;
        model::add_attachment(&mut b, &added, "b.bin", b"BBBB".to_vec()).unwrap();
        set_mtime(&mut b, &added, "2026-01-15 00:00:00");
        // запись с вложением в B «старше» правки A, правка A должна победить
        set_mtime(&mut b, &edited, "2026-01-10 00:00:00");
        let b = roundtrip(&b);

        let r = merge(&mut a, &b).unwrap();
        assert!(r.created >= 1, "{r:?}");
        assert_eq!(
            field_value(&a, &edited, "Password")
                .unwrap()
                .unwrap()
                .expose(),
            "new",
            "более поздняя правка победила"
        );
        assert_eq!(
            attachment(&a, &edited, "a.txt").unwrap(),
            b"AAA",
            "вложение A на месте"
        );
        assert_eq!(
            attachment(&a, &added, "b.bin").unwrap(),
            b"BBBB",
            "вложение B указывает на свои данные"
        );
        assert!(
            model::detail(&a, &deleted, false).is_err(),
            "удаление с B применилось"
        );

        // и всё это переживает сохранение
        let back = roundtrip(&a);
        assert_eq!(attachment(&back, &added, "b.bin").unwrap(), b"BBBB");
        assert_eq!(attachment(&back, &edited, "a.txt").unwrap(), b"AAA");
    }

    #[test]
    fn concurrent_edits_keep_both() {
        let mut base = Database::new();
        let id = entry(&mut base, "Банк", "base");
        let mut a = roundtrip(&base);
        let mut b = roundtrip(&base);
        model::update_entry(
            &mut a,
            &id,
            &EntryPatch {
                set: vec![FieldSet::new("Password", "from-a")],
                ..Default::default()
            },
        )
        .unwrap();
        set_mtime(&mut a, &id, "2026-03-01 00:00:00");
        model::update_entry(
            &mut b,
            &id,
            &EntryPatch {
                set: vec![FieldSet::new("Password", "from-b")],
                ..Default::default()
            },
        )
        .unwrap();
        set_mtime(&mut b, &id, "2026-03-02 00:00:00");

        merge(&mut a, &b).unwrap();
        assert_eq!(
            field_value(&a, &id, "Password").unwrap().unwrap().expose(),
            "from-b"
        );
        let hist = a
            .entry(model::parse_entry_id(&id).unwrap())
            .unwrap()
            .history
            .clone()
            .unwrap();
        assert!(
            hist.get_entries()
                .iter()
                .any(|v| v.get("Password") == Some("from-a")),
            "проигравшая версия в истории"
        );
    }

    #[test]
    fn meta_custom_data_union() {
        let mut a = Database::new();
        let mut b = roundtrip(&a);
        let item = |v: &str, when: &str| CustomDataItem {
            value: Some(CustomDataValue::String(v.into())),
            last_modification_time: Some(t(when)),
        };
        a.meta.custom_data.insert(
            "keywarden.browser.client.firefox".into(),
            item("A", "2026-01-01 00:00:00"),
        );
        b.meta.custom_data.insert(
            "keywarden.browser.client.chrome".into(),
            item("B", "2026-01-01 00:00:00"),
        );
        b.meta
            .custom_data
            .insert("shared".into(), item("new", "2026-02-01 00:00:00"));
        a.meta
            .custom_data
            .insert("shared".into(), item("old", "2026-01-01 00:00:00"));
        let _ = Times::now();
        merge(&mut a, &b).unwrap();
        assert!(
            a.meta
                .custom_data
                .contains_key("keywarden.browser.client.firefox")
        );
        assert!(
            a.meta
                .custom_data
                .contains_key("keywarden.browser.client.chrome")
        );
        assert_eq!(
            a.meta.custom_data["shared"].value,
            Some(CustomDataValue::String("new".into()))
        );
    }
}
