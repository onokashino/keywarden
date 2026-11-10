//! Защита входящих версий при синхронизации (папка, WebDAV, устройства).
//!
//! - `preview`: что слияние сделает с базой, сколько живых записей пропадёт (удаление или корзина);
//! - `protect`: отклонить массовое удаление: записи, которые входящая версия убирает, получают
//!   текущее время и побеждают удаление при слиянии здесь и на всех других копиях;
//! - `revert`: отменить уже сделанное слияние: затронутые записи возвращаются к снимку «до» как
//!   новая правка, поэтому отмена тоже расходится по устройствам, а не откатывается обратно;
//! - ревизия в custom data базы: растёт при каждой записи, по ней видно, что подсунули старую копию.

use crate::merge::{self, MergeError, MergeReport};
use crate::model;
use keepass::Database;
use keepass::db::{CustomDataItem, CustomDataValue, Times};
use std::collections::HashSet;

pub const REVISION_KEY: &str = "Keywarden.Revision";

/// Подтверждение нужно, если пропадает больше 5 записей или больше 10% базы (но не меньше 3).
pub fn needs_confirmation(removed: usize, live: usize) -> bool {
    removed > 5 || (removed >= 3 && removed * 10 > live)
}

/// Момент, который строго позже `t` (точность KDBX секунда) и не раньше сейчас.
fn after(now: chrono::NaiveDateTime, t: Option<chrono::NaiveDateTime>) -> chrono::NaiveDateTime {
    t.map_or(now, |t| now.max(t + chrono::Duration::seconds(1)))
}

/// Записи вне корзины.
fn live(db: &Database) -> HashSet<uuid::Uuid> {
    db.iter_all_entries()
        .filter(|e| !model::in_recycle_bin(db, e.parent().id()))
        .map(|e| e.id().uuid())
        .collect()
}

#[derive(Debug, Clone, Default)]
pub struct Preview {
    pub report: MergeReport,
    /// живых записей станет меньше на столько (удалены насовсем или ушли в корзину)
    pub removed: usize,
    pub live: usize,
}

impl Preview {
    pub fn needs_confirmation(&self) -> bool {
        needs_confirmation(self.removed, self.live)
    }
}

/// Слияние на копии: база не меняется.
pub fn preview(dest: &Database, incoming: &Database) -> Result<Preview, MergeError> {
    let mut probe = dest.clone();
    let report = merge::merge(&mut probe, incoming)?;
    let before = live(dest);
    let after = live(&probe);
    Ok(Preview {
        report,
        removed: before.difference(&after).count(),
        live: before.len(),
    })
}

/// Отклонить удаления из `incoming`: записи, которые оно убрало бы, помечаются текущим временем.
/// Возвращает, сколько записей защищено. После этого `incoming` можно вливать: остальные его
/// правки придут, удаления проиграют.
pub fn protect(dest: &mut Database, incoming: &Database) -> Result<usize, MergeError> {
    let mut probe = dest.clone();
    merge::merge(&mut probe, incoming)?;
    let gone: Vec<uuid::Uuid> = live(dest).difference(&live(&probe)).copied().collect();
    let now = Times::now();
    for u in &gone {
        // позже удаления и переноса в корзину из входящей версии
        let theirs = incoming
            .deleted_objects
            .get(u)
            .copied()
            .flatten()
            .into_iter()
            .chain(
                incoming
                    .entry((*u).into())
                    .and_then(|e| e.times.location_changed),
            )
            .max();
        let at = after(now, theirs);
        if let Some(mut e) = dest.entry_mut((*u).into()) {
            e.times.last_modification = Some(at);
            e.times.location_changed = Some(at);
        }
    }
    Ok(gone.len())
}

/// Отменить слияние: `dest` сейчас после слияния, `before` снимок до него.
pub fn revert(dest: &mut Database, before: &Database) -> Result<MergeReport, MergeError> {
    let now = Times::now();
    let mut patch = before.clone();
    let mut touched = 0;
    let before_ids: Vec<uuid::Uuid> = before.iter_all_entries().map(|e| e.id().uuid()).collect();
    for u in &before_ids {
        let id = (*u).into();
        let old = before.entry(id).expect("есть в снимке");
        let mut deleted_at = None;
        let changed = match dest.entry(id) {
            // удалена насовсем: вернуть (отметку об удалении здесь снимаем, у других копий она
            // старше новой правки и проиграет)
            None => {
                deleted_at = dest.deleted_objects.remove(u).flatten();
                true
            }
            Some(cur) => {
                let moved = cur.parent().id() != old.parent().id();
                let at = after(now, cur.times.location_changed);
                if moved && let Some(mut p) = patch.entry_mut(id) {
                    p.times.location_changed = Some(at);
                }
                moved
                    || cur.fields != old.fields
                    || cur.tags != old.tags
                    || cur.times.last_modification != old.times.last_modification
            }
        };
        // правка отмены строго позже текущей версии, даже в ту же секунду (точность KDBX)
        let at = after(
            now,
            dest.entry(id)
                .and_then(|c| c.times.last_modification)
                .or(deleted_at),
        );
        if changed && let Some(mut p) = patch.entry_mut(id) {
            p.times.last_modification = Some(at);
            touched += 1;
        }
    }
    // группы, удалённые слиянием, тоже вернуть
    let gone_groups: Vec<uuid::Uuid> = before
        .iter_all_groups()
        .map(|g| g.id().uuid())
        .filter(|u| dest.group((*u).into()).is_none())
        .collect();
    for u in &gone_groups {
        dest.deleted_objects.remove(u);
        if let Some(mut g) = patch.group_mut((*u).into()) {
            g.times.last_modification = Some(now);
        }
    }
    let mut report = merge::merge(dest, &patch)?;
    report.updated = touched;
    // пришедшие слиянием записи: в корзину (не насовсем, вдруг нужны)
    let before_set: HashSet<uuid::Uuid> = before_ids.into_iter().collect();
    let added: Vec<String> = live(dest)
        .into_iter()
        .filter(|u| !before_set.contains(u))
        .map(|u| u.to_string())
        .collect();
    for id in &added {
        model::delete_entry(dest, id).map_err(|e| MergeError::new(e.to_string()))?;
    }
    report.deleted = added.len();
    Ok(report)
}

pub fn revision(db: &Database) -> u64 {
    match db
        .meta
        .custom_data
        .get(REVISION_KEY)
        .and_then(|c| c.value.as_ref())
    {
        Some(CustomDataValue::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn set_revision(db: &mut Database, n: u64) {
    db.meta.custom_data.insert(
        REVISION_KEY.into(),
        CustomDataItem {
            value: Some(CustomDataValue::String(n.to_string())),
            last_modification_time: Some(Times::now()),
        },
    );
}

/// Перед записью: ревизия на единицу больше любой виденной.
pub fn bump_revision(db: &mut Database) {
    set_revision(db, revision(db) + 1);
}

/// После слияния: custom data берёт более позднюю по времени, а ревизии нужна наибольшая.
pub fn keep_max_revision(db: &mut Database, seen: u64) {
    if seen > revision(db) {
        set_revision(db, seen);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EntryPatch, FieldSet, create_entry, field_value, update_entry};

    fn add(db: &mut Database, title: &str) -> String {
        let id = create_entry(
            db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Title", title),
                    FieldSet::new("Password", "p"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        let mut e = db.entry_mut(model::parse_entry_id(&id).unwrap()).unwrap();
        e.times.last_modification = Some(Times::now() - chrono::Duration::hours(1));
        e.times.location_changed = e.times.last_modification;
        id
    }

    fn base(n: usize) -> (Database, Vec<String>) {
        let mut db = Database::new();
        let ids = (0..n).map(|i| add(&mut db, &format!("e{i}"))).collect();
        (db, ids)
    }

    fn purge(db: &mut Database, id: &str) {
        model::delete_entry(db, id).unwrap();
        model::delete_entry(db, id).unwrap();
    }

    /// База переживает запись и чтение без расхождений (так её проверяет сохранение).
    fn survives_save(db: &Database) {
        let key = keepass::DatabaseKey::new().with_password("p");
        let mut db = db.clone();
        db.config.kdf_config = crate::vault::test_kdf();
        let mut buf = vec![];
        db.save(&mut buf, key.clone()).unwrap();
        let mut back = Database::parse(&buf, key).unwrap();
        for d in [&mut db, &mut back] {
            d.remove_unused_attachments();
            d.rebuild_custom_icon_refs();
        }
        assert!(back == db, "после записи и чтения база отличается");
    }

    fn present(db: &Database, id: &str) -> bool {
        let e = db.entry(model::parse_entry_id(id).unwrap());
        e.is_some_and(|e| !model::in_recycle_bin(db, e.parent().id()))
    }

    #[test]
    fn mass_deletion_is_detected_and_rejected() {
        let (mine, ids) = base(20);
        let mut theirs = mine.clone();
        for id in &ids[..4] {
            purge(&mut theirs, id); // насовсем
        }
        for id in &ids[4..7] {
            model::delete_entry(&mut theirs, id).unwrap(); // в корзину
        }
        let p = preview(&mine, &theirs).unwrap();
        assert_eq!((p.removed, p.live), (7, 20));
        assert!(p.needs_confirmation());
        assert!(!needs_confirmation(1, 20) && !needs_confirmation(2, 10));
        assert!(needs_confirmation(3, 20) && needs_confirmation(6, 1000));

        // отклонить: удаления проигрывают и здесь, и на копии, которая сольёт нашу версию
        let mut mine = mine;
        assert_eq!(protect(&mut mine, &theirs).unwrap(), 7);
        merge::merge(&mut mine, &theirs).unwrap();
        assert!(ids.iter().all(|id| present(&mine, id)));
        // история записей из корзины другой копии не ломает сохранение
        survives_save(&mine);
        merge::merge(&mut theirs, &mine).unwrap();
        assert!(
            ids.iter().all(|id| present(&theirs, id)),
            "другая копия тоже вернула"
        );
    }

    #[test]
    fn revert_undoes_merge_everywhere() {
        let (mine, ids) = base(5);
        let mut theirs = mine.clone();
        update_entry(
            &mut theirs,
            &ids[0],
            &EntryPatch {
                set: vec![FieldSet::new("Password", "changed")],
                ..Default::default()
            },
        )
        .unwrap();
        purge(&mut theirs, &ids[1]);
        let created = add(&mut theirs, "новая");

        let before = mine.clone();
        let mut mine = mine;
        merge::merge(&mut mine, &theirs).unwrap();
        assert!(!present(&mine, &ids[1]) && present(&mine, &created));

        let r = revert(&mut mine, &before).unwrap();
        assert_eq!((r.updated, r.deleted), (2, 1), "{r:?}");
        let pw = |db: &Database| {
            field_value(db, &ids[0], "Password")
                .unwrap()
                .unwrap()
                .expose()
                .to_string()
        };
        assert_eq!(pw(&mine), "p");
        assert!(present(&mine, &ids[1]) && !present(&mine, &created));
        survives_save(&mine);

        // откат доезжает до копии, с которой пришли изменения
        merge::merge(&mut theirs, &mine).unwrap();
        assert_eq!(pw(&theirs), "p");
        assert!(present(&theirs, &ids[1]) && !present(&theirs, &created));
    }

    #[test]
    fn revision_grows_and_keeps_max() {
        let mut a = Database::new();
        assert_eq!(revision(&a), 0);
        bump_revision(&mut a);
        bump_revision(&mut a);
        let mut b = a.clone();
        bump_revision(&mut b);
        // a записали позже, но ревизия у b больше: после слияния остаётся наибольшая
        merge::merge(&mut a, &b).unwrap();
        keep_max_revision(&mut a, revision(&b));
        assert_eq!(revision(&a), 3);
    }
}
