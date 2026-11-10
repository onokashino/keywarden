//! Синхронизация файлом (Syncthing): слежение за каталогом базы и автоматическое слияние.
//!
//! - внешнее изменение файла → файл сливается в открытую базу (как Merge в KeePassXC);
//! - файлы конфликтов `*.sync-conflict-*` сливаются туда же, после записи переезжают в бэкапы;
//! - на диск пишем, только если в памяти есть то, чего нет в файле: иначе два устройства
//!   пересохраняли бы базу друг за другом бесконечно (каждая запись даёт новые байты);
//! - пользователь получает уведомление рабочего стола.

use crate::state::{Daemon, Reply, blocking, locked};
use keepass::Database;
use keywarden_core::ipc::{ErrorCode, Event, Response, SyncFolder, SyncHeld, SyncRecord};
use keywarden_core::sync::{self as guard, Preview};
use keywarden_core::{merge, vault::DiskReader};
use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// Сколько строк журнала и снимков «до слияния» держать.
const KEEP_RECORDS: usize = 50;
const KEEP_SNAPSHOTS: usize = 20;

/// Журнал синхронизаций (`sync-journal.json` рядом с копиями базы) и версия на паузе.
#[derive(Default)]
pub struct SyncState {
    pub held: Option<Held>,
    pub records: Vec<SyncRecord>,
    /// наибольшая виденная ревизия базы: файл с меньшей значит подсунутую старую копию
    pub seen_revision: u64,
    loaded_from: Option<PathBuf>,
}

/// Входящая версия, которая убирает слишком много записей: ждёт решения пользователя.
pub struct Held {
    pub source: String,
    pub db: Database,
    /// хэш файла базы, если пришла сама база (после решения он считается записанным)
    pub hash: Option<[u8; 32]>,
    /// конфликтная копия, если пришла она
    pub file: Option<PathBuf>,
    pub preview: Preview,
}

#[derive(Serialize, Deserialize, Default)]
struct JournalFile {
    records: Vec<SyncRecord>,
    seen_revision: u64,
}

impl SyncState {
    fn file(dir: &Path) -> PathBuf {
        dir.join("sync-journal.json")
    }

    /// Журнал этой базы (у каждой базы свой каталог копий).
    fn load(&mut self, dir: &Path) {
        if self.loaded_from.as_deref() == Some(dir) {
            return;
        }
        let j: JournalFile = std::fs::read(Self::file(dir))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        self.records = j.records;
        self.seen_revision = self.seen_revision.max(j.seen_revision);
        self.loaded_from = Some(dir.to_path_buf());
    }

    fn persist(&self) {
        let Some(dir) = &self.loaded_from else { return };
        let j = JournalFile {
            records: self.records.clone(),
            seen_revision: self.seen_revision,
        };
        if let Ok(b) = serde_json::to_vec_pretty(&j) {
            let _ = std::fs::create_dir_all(dir);
            let _ = keywarden_core::vault::write_atomic(&Self::file(dir), &b);
        }
    }

    fn push(
        &mut self,
        source: String,
        summary: String,
        status: &str,
        snapshot: Option<String>,
    ) -> u64 {
        let id = self.records.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        self.records.insert(
            0,
            SyncRecord {
                id,
                when: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
                source,
                summary,
                status: status.into(),
                snapshot,
            },
        );
        self.records.truncate(KEEP_RECORDS);
        self.persist();
        id
    }
}

fn held_info(h: &Held) -> SyncHeld {
    SyncHeld {
        source: h.source.clone(),
        summary: h.preview.report.summary(),
        removed: h.preview.removed,
        live: h.preview.live,
    }
}

fn source_name(file: Option<&Path>) -> String {
    match file {
        None => tr!("файл базы").into(),
        Some(f) => tr!(
            "конфликтная копия {name}",
            name = f.file_name().unwrap_or_default().to_string_lossy()
        ),
    }
}

/// В папке какой программы синхронизации лежит файл: по служебным файлам в ней или выше.
pub fn detect_folder(db: &Path) -> Option<SyncFolder> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    // Nextcloud: localPath из настроек клиента
    let nc_roots: Vec<PathBuf> = home
        .iter()
        .flat_map(|h| {
            ["Nextcloud/nextcloud.cfg", "ownCloud/owncloud.cfg"].map(|f| h.join(".config").join(f))
        })
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .flat_map(|s| {
            s.lines()
                .filter_map(|l| {
                    l.split_once("localPath=")
                        .map(|(_, p)| PathBuf::from(p.trim()))
                })
                .collect::<Vec<_>>()
        })
        .collect();
    for dir in db.ancestors().skip(1) {
        let has = |n: &str| dir.join(n).exists();
        let kind = if has(".stfolder") {
            Some("syncthing")
        } else if has(".dropbox") || has(".dropbox.cache") {
            Some("dropbox")
        } else if has(".nextcloudsync.log")
            || has(".owncloudsync.log")
            || nc_roots
                .iter()
                .any(|r| r.as_path() == dir || r.as_path() == dir.join(""))
            || std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .any(|e| {
                    let n = e.file_name();
                    let n = n.to_string_lossy();
                    n.starts_with(".sync_") && n.ends_with(".db")
                })
        {
            Some("nextcloud")
        } else {
            None
        };
        if let Some(kind) = kind {
            return Some(SyncFolder {
                kind: kind.into(),
                root: dir.display().to_string(),
            });
        }
        if home.as_deref() == Some(dir) {
            break; // выше домашней папки не ищем
        }
    }
    None
}

/// Снимки «до слияния» сверх лимита удаляются (они зашифрованы, но копить их незачем).
fn prune_snapshots(dir: &Path) {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().contains(".presync-"))
        .collect();
    v.sort();
    let extra = v.len().saturating_sub(KEEP_SNAPSHOTS);
    for p in &v[..extra] {
        let _ = std::fs::remove_file(p);
    }
}

/// Что получилось слить за один проход.
struct Pass {
    report: merge::MergeReport,
    before: Option<Database>,
    need_save: bool,
    merged_files: Vec<PathBuf>,
    sources: Vec<String>,
    new_hold: Option<SyncHeld>,
    stale: Option<(u64, u64)>,
}

impl Daemon {
    /// Слить файл с диска и конфликтные копии в открытую базу. `Ok(None)`: снаружи ничего не менялось.
    /// Каждая входящая версия проходит шлюз: массовое удаление ставится на паузу, перед слиянием
    /// пишется зашифрованный снимок для отмены, старая ревизия файла даёт предупреждение.
    pub async fn sync_from_disk(self: &Arc<Self>) -> Result<Option<String>, String> {
        let Some((reader, known_hash, epoch, dir)) =
            self.with_vault(|v, epoch| (v.reader(), v.disk_hash(), epoch, v.backups.dir.clone()))
        else {
            return Ok(None);
        };
        let guard_on = self.config().sync_guard;
        // версия на паузе: тот же файл заново не разбираем, ждём решения
        let held_hash = self.inner().sync.held.as_ref().and_then(|h| h.hash);
        let loaded = tokio::task::spawn_blocking(move || {
            let current = reader.hash_on_disk().map_err(|e| e.to_string())?;
            let conflicts = reader.conflict_files();
            if (current == known_hash || Some(current) == held_hash) && conflicts.is_empty() {
                return Ok::<_, String>(None);
            }
            let disk = if current == known_hash || Some(current) == held_hash {
                None
            } else {
                Some(
                    reader
                        .read()
                        .map_err(|e| tr!("файл базы не читается: {e}", e = e))?,
                )
            };
            let mut parsed = vec![];
            let mut unreadable = vec![];
            for c in conflicts {
                match reader.parse_file(&c) {
                    Ok(db) => parsed.push((c, db)),
                    Err(e) => unreadable.push(format!("{}: {e}", c.display())),
                }
            }
            Ok(Some((disk, parsed, unreadable)))
        })
        .await
        .map_err(|e| e.to_string())??;
        let Some((disk, conflicts, unreadable)) = loaded else {
            return Ok(None);
        };

        // слияние в памяти: быстро, под мьютексом
        let outcome = {
            let mut g = self.inner();
            if g.epoch != epoch || g.vault.is_none() {
                return Ok(None); // базу заблокировали или сменили, пока читали файл
            }
            g.sync.load(&dir);
            let seen = g.sync.seen_revision;
            let mut sync = std::mem::take(&mut g.sync);
            let vault = g.vault.as_mut().expect("проверено выше");
            let res = (|| -> Result<Pass, String> {
                let mut pass = Pass {
                    report: Default::default(),
                    before: None,
                    need_save: false,
                    merged_files: vec![],
                    sources: vec![],
                    new_hold: None,
                    stale: None,
                };
                let snapshot = vault.db.clone();
                let mut items: Vec<(Option<PathBuf>, Database, Option<[u8; 32]>)> = vec![];
                if let Some((db, hash)) = disk {
                    let rev = guard::revision(&db);
                    if rev > 0 && rev < seen {
                        pass.stale = Some((rev, seen));
                    }
                    items.push((None, db, Some(hash)));
                }
                for (p, db) in conflicts {
                    items.push((Some(p), db, None));
                }
                let mut disk_merged = None;
                for (file, db, hash) in items {
                    let preview = guard::preview(&vault.db, &db).map_err(|e| e.to_string())?;
                    if guard_on && preview.needs_confirmation() && sync.held.is_none() {
                        let h = Held {
                            source: source_name(file.as_deref()),
                            db,
                            hash,
                            file,
                            preview,
                        };
                        pass.new_hold = Some(held_info(&h));
                        sync.held = Some(h);
                        continue;
                    }
                    if guard_on && preview.needs_confirmation() {
                        continue; // одна пауза за раз, остальное после решения
                    }
                    let r = merge::merge(&mut vault.db, &db).map_err(|e| e.to_string())?;
                    guard::keep_max_revision(&mut vault.db, guard::revision(&db));
                    if !r.is_empty() {
                        pass.sources.push(source_name(file.as_deref()));
                    }
                    pass.report.created += r.created;
                    pass.report.updated += r.updated;
                    pass.report.deleted += r.deleted;
                    pass.report.moved += r.moved;
                    if let Some(h) = hash {
                        vault.mark_saved(h);
                        disk_merged = Some(db);
                    } else if let Some(f) = file {
                        pass.merged_files.push(f);
                    }
                }
                // есть ли в памяти что-то, чего нет на диске
                pass.need_save = match &disk_merged {
                    Some(disk_db) => {
                        let mut probe = disk_db.clone();
                        !merge::merge(&mut probe, &vault.db)
                            .map_err(|e| e.to_string())?
                            .is_empty()
                    }
                    None => !pass.merged_files.is_empty(),
                };
                if !pass.report.is_empty() {
                    pass.before = Some(snapshot);
                }
                sync.seen_revision = sync.seen_revision.max(guard::revision(&vault.db));
                Ok(pass)
            })();
            g.sync = sync;
            res?
        };

        // снимок до слияния (Argon2) вне мьютекса, затем строка журнала
        if let Some(before) = outcome.before {
            let r2 = self.with_vault(|v, _| v.reader());
            let snap = match r2 {
                Some(r) => {
                    let dir2 = dir.clone();
                    tokio::task::spawn_blocking(move || {
                        let n = r.write_snapshot(&before, &dir2).ok();
                        prune_snapshots(&dir2);
                        n
                    })
                    .await
                    .ok()
                    .flatten()
                }
                None => None,
            };
            let mut g = self.inner();
            g.sync.push(
                outcome.sources.join(", "),
                outcome.report.summary(),
                "applied",
                snap,
            );
        }
        if outcome.need_save {
            self.bump_and_wait_saved().await?;
        }
        // конфликтные копии слиты и записаны: убираем их к бэкапам, не удаляем
        for f in &outcome.merged_files {
            self.archive_conflict(f);
        }
        let mut parts = vec![];
        if !outcome.report.is_empty() || !outcome.merged_files.is_empty() {
            let mut m = tr!(
                "База синхронизирована: {summary}",
                summary = outcome.report.summary()
            );
            if !outcome.merged_files.is_empty() {
                m.push_str(&tr!(
                    "; слито конфликтных копий: {n}",
                    n = outcome.merged_files.len()
                ));
            }
            parts.push(m);
        }
        if let Some((rev, seen)) = outcome.stale {
            parts.push(tr!(
                "Файл базы старее уже виденного (ревизия {rev}, была {seen}): возможно, вернули старую копию",
                rev = rev,
                seen = seen
            ));
        }
        if !unreadable.is_empty() {
            parts.push(tr!(
                "Не открылись (другой пароль?): {files}",
                files = unreadable.join(", ")
            ));
        }
        if let Some(h) = &outcome.new_hold {
            let m = tr!(
                "{source} убирает {removed} из {live} записей. Слияние на паузе: решите в Настройках, вкладка «Синхронизация»",
                source = h.source,
                removed = h.removed,
                live = h.live
            );
            tracing::warn!("{m}");
            self.events
                .send(Event::SyncHeld { message: m.clone() })
                .ok();
            notify_desktop(tr!("Keywarden: проверьте синхронизацию"), &m).await;
            parts.push(m);
        }
        if parts.is_empty() {
            return Ok(None);
        }
        let message = parts.join(". ");
        tracing::info!("{message}");
        if !outcome.report.is_empty() || !outcome.merged_files.is_empty() {
            self.events
                .send(Event::Merged {
                    message: message.clone(),
                })
                .ok();
            self.events.send(Event::Changed).ok();
            notify_desktop("Keywarden", &message).await;
        }
        Ok(Some(message))
    }

    /// Ждёт ли входящая версия решения (тогда запись базы на диск подождёт).
    pub fn sync_held(&self) -> bool {
        self.inner().sync.held.is_some()
    }

    pub(crate) fn sync_journal(&self) -> Reply<Response> {
        let mut g = self.inner();
        let dir = g.vault.as_ref().ok_or_else(locked)?.backups.dir.clone();
        g.sync.load(&dir);
        let records = g
            .sync
            .records
            .iter()
            .cloned()
            .map(|mut r| {
                // снимок могли удалить ротацией: тогда отменить уже нельзя
                if r.snapshot.as_ref().is_some_and(|s| !dir.join(s).exists()) {
                    r.snapshot = None;
                }
                r
            })
            .collect();
        let path = g.vault.as_ref().map(|v| v.reader().path().to_path_buf());
        Ok(Response::SyncJournal {
            records,
            held: g.sync.held.as_ref().map(|h| Box::new(held_info(h))),
            db_path: path.as_ref().map(|p| p.display().to_string()),
            folder: path.as_deref().and_then(detect_folder).map(Box::new),
        })
    }

    /// Переместить файл базы в каталог: запись тем же ключом с проверкой, переключение на новый
    /// файл, старый уходит к резервным копиям (не удаляется).
    pub(crate) async fn move_database(self: &Arc<Self>, dir: String) -> Reply<Response> {
        let dir = PathBuf::from(dir);
        if !dir.is_dir() {
            return Err(Response::error(ErrorCode::Invalid, tr!("нет такой папки")));
        }
        if self.sync_held() {
            return Err(Response::error(
                ErrorCode::Conflict,
                tr!("сначала решите, что делать с версией на паузе"),
            ));
        }
        // всё несохранённое сначала на диск
        self.bump_and_wait_saved()
            .await
            .map_err(|e| Response::error(ErrorCode::Conflict, e))?;
        let (reader, db, old, backups, epoch) = self
            .with_vault(|v, e| {
                (
                    v.reader(),
                    v.db.clone(),
                    v.reader().path().to_path_buf(),
                    v.backups.dir.clone(),
                    e,
                )
            })
            .ok_or_else(locked)?;
        let name = old.file_name().unwrap_or_default().to_owned();
        let new = dir.join(&name);
        let same = std::fs::canonicalize(&dir).ok()
            == old.parent().and_then(|p| std::fs::canonicalize(p).ok());
        if same {
            return Err(Response::error(
                ErrorCode::Invalid,
                tr!("база уже лежит в этой папке"),
            ));
        }
        if new.exists() {
            return Err(Response::error(
                ErrorCode::Conflict,
                tr!(
                    "в папке уже есть файл с таким именем: откройте его или слейте с ним (Настройки, Перенос)"
                ),
            ));
        }
        let n2 = new.clone();
        let hash = blocking(move || reader.write_verified(&db, &n2)).await?;
        self.with_vault_mut(epoch, |v| v.set_location(new.clone(), hash))
            .ok_or_else(locked)?;
        // старый файл к копиям: в папке синхронизации он остался бы второй базой
        let stem = old
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let _ = std::fs::create_dir_all(&backups);
        let dst = backups.join(format!(
            "{stem}.moved-{}.kdbx",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        if std::fs::rename(&old, &dst).is_err() && std::fs::copy(&old, &dst).is_ok() {
            let _ = std::fs::remove_file(&old);
        }
        let n3 = new.clone();
        self.update_config(|c| {
            if c.database.as_deref() == Some(old.as_path()) {
                c.database = Some(n3);
                true
            } else {
                false
            }
        });
        tracing::info!("база перемещена в {}", new.display());
        self.events.send(Event::Changed).ok();
        Ok(Response::Ok)
    }

    /// Принять удаления из версии на паузе или отклонить их (записи остаются и здесь, и на других
    /// копиях: они получают текущее время и побеждают удаление).
    pub(crate) async fn sync_decide(self: &Arc<Self>, accept: bool) -> Reply<Response> {
        let (summary, source, file, before) = {
            let mut g = self.inner();
            let Some(h) = g.sync.held.take() else {
                return Err(Response::error(
                    ErrorCode::NotFound,
                    tr!("ничего не ждёт решения"),
                ));
            };
            let vault = g.vault.as_mut().ok_or_else(locked)?;
            let before = vault.db.clone();
            let res = (|| -> Result<merge::MergeReport, String> {
                if !accept {
                    guard::protect(&mut vault.db, &h.db).map_err(|e| e.to_string())?;
                }
                let r = merge::merge(&mut vault.db, &h.db).map_err(|e| e.to_string())?;
                guard::keep_max_revision(&mut vault.db, guard::revision(&h.db));
                Ok(r)
            })();
            let report = match res {
                Ok(r) => r,
                Err(e) => {
                    vault.db = before;
                    g.sync.held = Some(h);
                    return Err(Response::error(ErrorCode::Internal, e));
                }
            };
            if let Some(hash) = h.hash {
                vault.mark_saved(hash);
            }
            (report.summary(), h.source, h.file, before)
        };
        let dir = self
            .with_vault(|v, _| v.backups.dir.clone())
            .ok_or_else(locked)?;
        let reader = self.with_vault(|v, _| v.reader()).ok_or_else(locked)?;
        let d2 = dir.clone();
        let snap = blocking(move || {
            let n = reader.write_snapshot(&before, &d2);
            prune_snapshots(&d2);
            n
        })
        .await
        .ok();
        self.inner().sync.push(
            source,
            if accept {
                tr!("принято: {summary}", summary = summary)
            } else {
                tr!(
                    "удаления отклонены, остальное слито: {summary}",
                    summary = summary
                )
            },
            if accept { "accepted" } else { "rejected" },
            snap,
        );
        self.bump_and_wait_saved()
            .await
            .map_err(|e| Response::error(ErrorCode::Conflict, e))?;
        if let Some(f) = file {
            self.archive_conflict(&f);
        }
        self.events.send(Event::Changed).ok();
        Ok(Response::Ok)
    }

    /// Отменить слияние из журнала по снимку «до». Отмена сама становится правкой и расходится
    /// по устройствам; её тоже можно отменить (снимок перед отменой пишется как обычно).
    pub(crate) async fn sync_revert(self: &Arc<Self>, id: u64) -> Reply<Response> {
        let (reader, dir) = self
            .with_vault(|v, _| (v.reader(), v.backups.dir.clone()))
            .ok_or_else(locked)?;
        let snap = {
            let mut g = self.inner();
            g.sync.load(&dir);
            let r = g.sync.records.iter().find(|r| r.id == id).ok_or_else(|| {
                Response::error(ErrorCode::NotFound, tr!("нет такой строки журнала"))
            })?;
            if r.status == "reverted" {
                return Err(Response::error(ErrorCode::Invalid, tr!("уже отменено")));
            }
            r.snapshot.clone().ok_or_else(|| {
                Response::error(ErrorCode::NotFound, tr!("снимка для отмены уже нет"))
            })?
        };
        if snap.contains('/') || snap.starts_with('.') {
            return Err(Response::error(
                ErrorCode::Invalid,
                tr!("неверное имя снимка"),
            ));
        }
        let path = dir.join(&snap);
        let r2: DiskReader = reader.clone();
        let before = blocking(move || r2.parse_file(&path)).await?;
        let current = self.with_vault(|v, _| v.db.clone()).ok_or_else(locked)?;
        let report = self
            .mutate_r(move |db| {
                guard::revert(db, &before)
                    .map_err(|e| Response::error(ErrorCode::Internal, e.to_string()))
            })
            .await?;
        let d2 = dir.clone();
        let undo_snap = blocking(move || reader.write_snapshot(&current, &d2))
            .await
            .ok();
        let mut g = self.inner();
        if let Some(r) = g.sync.records.iter_mut().find(|r| r.id == id) {
            r.status = "reverted".into();
        }
        g.sync.push(
            tr!("отмена").into(),
            tr!(
                "возвращено записей {updated}, в корзину {deleted}",
                updated = report.updated,
                deleted = report.deleted
            ),
            "applied",
            undo_snap,
        );
        Ok(Response::Ok)
    }

    fn archive_conflict(&self, file: &Path) {
        let Some(dir) = self.with_vault(|v, _| v.backups.dir.clone()) else {
            return;
        };
        let _ = std::fs::create_dir_all(&dir);
        let dst = dir.join(file.file_name().unwrap_or_default());
        if std::fs::rename(file, &dst).is_err() {
            // другой раздел: копия, затем удаление исходника
            if std::fs::copy(file, &dst).is_ok() {
                let _ = std::fs::remove_file(file);
            }
        }
    }
}

/// Следит за каталогом открытой базы; при смене базы переподписывается.
pub async fn watch(daemon: Arc<Daemon>) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let mut current: Option<PathBuf> = None;
    let mut watcher: Option<notify::RecommendedWatcher> = None;
    loop {
        let path = daemon.with_vault(|v, _| v.reader().path().to_path_buf());
        if path != current {
            watcher = None;
            if let Some(p) = &path {
                let dir = p
                    .parent()
                    .filter(|d| !d.as_os_str().is_empty())
                    .unwrap_or(Path::new("."))
                    .to_path_buf();
                let stem = p
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let tx = tx.clone();
                let made =
                    notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                        if let Ok(ev) = res {
                            // только наш файл и его конфликтные копии; временные файлы Syncthing (.syncthing.*) мимо
                            if ev.paths.iter().any(|p| {
                                p.file_name()
                                    .is_some_and(|n| n.to_string_lossy().starts_with(&stem))
                            }) {
                                let _ = tx.send(());
                            }
                        }
                    })
                    .and_then(|mut w| w.watch(&dir, RecursiveMode::NonRecursive).map(|_| w));
                match made {
                    Ok(w) => {
                        tracing::info!("слежу за {}", dir.display());
                        watcher = Some(w);
                    }
                    Err(e) => tracing::warn!("inotify недоступен ({e}), проверяю файл раз в 10 с"),
                }
            }
            current = path;
            // проверка сразу после открытия: конфликтные копии могли накопиться
            if current.is_some() {
                let _ = tx.send(());
            }
        }
        let poll = if watcher.is_some() {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(10)
        };
        tokio::select! {
            got = rx.recv() => {
                if got.is_none() { return; }
                // Syncthing пишет временный файл и переименовывает: ждём, пока событие утихнет
                tokio::time::sleep(Duration::from_millis(700)).await;
                while rx.try_recv().is_ok() {}
                // выключено в настройках: внешние изменения сольются при следующей записи
                if !daemon.config().sync_watch {
                    continue;
                }
                if let Err(e) = daemon.sync_from_disk().await {
                    tracing::error!("синхронизация не удалась: {e}");
                    daemon.events.send(Event::SaveFailed { message: e.clone() }).ok();
                    notify_desktop(tr!("Keywarden: синхронизация не удалась"), &e).await;
                }
            }
            _ = tokio::time::sleep(poll) => {
                if current.is_some() {
                    let _ = tx.send(());
                }
            }
        }
    }
}

/// Уведомление рабочего стола; на macOS и Windows о событии говорит окно Keywarden.
#[cfg(not(target_os = "linux"))]
pub async fn notify_desktop(summary: &str, body: &str) {
    tracing::info!("{summary}: {body}");
}

/// Уведомление рабочего стола (org.freedesktop.Notifications); без сессионной шины молча пропускаем.
#[cfg(target_os = "linux")]
pub async fn notify_desktop(summary: &str, body: &str) {
    let Ok(conn) = zbus::Connection::session().await else {
        return;
    };
    let hints: std::collections::HashMap<&str, zbus::Variant<'_>> =
        std::collections::HashMap::new();
    let _ = conn
        .call_method(
            Some("org.freedesktop.Notifications"),
            "/org/freedesktop/Notifications",
            Some("org.freedesktop.Notifications"),
            "Notify",
            &(
                "Keywarden",
                0u32,
                "dialog-password",
                summary,
                body,
                Vec::<&str>::new(),
                hints,
                8000i32,
            ),
        )
        .await;
}
