//! Настройки этого компьютера, PIN, резервные копии и уведомления по расписанию.

use crate::state::{Daemon, Reply, blocking, locked};
use keywarden_core::ipc::{BackupInfo, ErrorCode, KeySpec, Prefs, Response};
use keywarden_core::quick::{PinLock, QuickCreds, Sealed};
use keywarden_core::secret::Secret;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PIN_ATTEMPTS: u8 = 3;
/// Сколько действует повторное подтверждение для кошельков.
const ELEVATION: Duration = Duration::from_secs(120);
const ELEVATE_PIN_ATTEMPTS: u8 = 5;

/// Шифровка ключа базы, ждущая PIN.
pub struct Armed {
    lock: PinLock,
    sealed: Sealed,
    /// PIN действует до этого момента (отсчёт от полной разблокировки)
    until: Instant,
    attempts: u8,
}

impl Armed {
    pub fn usable(&self) -> bool {
        self.attempts > 0 && Instant::now() < self.until
    }
}

fn invalid(m: impl Into<String>) -> Response {
    Response::error(ErrorCode::Invalid, m)
}

impl Daemon {
    /// После полной разблокировки: запомнить ключ под PIN, если PIN задан.
    pub(crate) fn arm_quick(&self, creds: &QuickCreds) {
        let mut g = self.inner();
        let Some(lock) = g.config.pin.clone() else {
            g.quick = None;
            return;
        };
        let hours = g.config.pin_hours.max(1);
        match lock.seal(creds) {
            Ok(sealed) => {
                g.quick = Some(Armed {
                    lock,
                    sealed,
                    until: Instant::now() + Duration::from_secs(hours * 3600),
                    attempts: PIN_ATTEMPTS,
                })
            }
            Err(e) => tracing::warn!("PIN: не удалось запомнить ключ: {e}"),
        }
    }

    pub(crate) async fn quick_unlock(self: &Arc<Self>, pin: Secret) -> Reply<Response> {
        if self.is_unlocked() {
            return Ok(Response::Ok);
        }
        let (lock, sealed, until) = {
            let g = self.inner();
            let q = g.quick.as_ref().filter(|q| q.usable()).ok_or_else(|| {
                Response::error(
                    ErrorCode::WrongKey,
                    tr!("PIN сейчас не действует: введите мастер-пароль"),
                )
            })?;
            (q.lock.clone(), q.sealed.clone(), q.until)
        };
        let opened = blocking(move || Ok::<_, String>(lock.open(pin.expose(), &sealed))).await?;
        let Some(c) = opened else {
            let mut g = self.inner();
            let left = g.quick.as_mut().map(|q| {
                q.attempts = q.attempts.saturating_sub(1);
                q.attempts
            });
            let msg = match left {
                Some(n) if n > 0 => tr!("Неверный PIN, осталось попыток: {n}", n = n),
                _ => {
                    g.quick = None;
                    tr!("Неверный PIN три раза подряд: нужен мастер-пароль").into()
                }
            };
            return Err(Response::error(ErrorCode::WrongKey, msg));
        };
        let r = self
            .unlock(Some(c.path), c.password, c.keyfile, c.yubikey)
            .await;
        // срок PIN считается от полной разблокировки, разблокировка PIN-ом его не продлевает
        if let Some(q) = self.inner().quick.as_mut() {
            q.until = until;
        }
        r
    }

    // --- повторное подтверждение для криптокошельков ---

    pub(crate) fn elevated(&self) -> bool {
        self.inner()
            .elevated_until
            .is_some_and(|t| Instant::now() < t)
    }

    pub(crate) fn require_elevation(&self) -> Reply<()> {
        if self.elevated() {
            Ok(())
        } else {
            Err(Response::error(
                ErrorCode::NeedsAuth,
                tr!("Подтвердите PIN или мастер-паролем"),
            ))
        }
    }

    /// PIN или мастер-пароль открывают поля кошельков на 2 минуты. После 5 неверных PIN
    /// подряд принимается только мастер-пароль.
    pub(crate) async fn elevate(
        &self,
        pin: Option<Secret>,
        key: Option<KeySpec>,
    ) -> Reply<Response> {
        let path = self
            .with_vault(|v, _| v.path().to_path_buf())
            .ok_or_else(locked)?;
        if let Some(pin) = pin {
            let (lock, fails) = {
                let g = self.inner();
                (g.config.pin.clone(), g.elevate_fails)
            };
            let Some(lock) = lock.filter(|_| fails < ELEVATE_PIN_ATTEMPTS) else {
                return Err(Response::error(
                    ErrorCode::WrongKey,
                    tr!("PIN не принимается: введите мастер-пароль"),
                ));
            };
            let ok = blocking(move || Ok::<_, String>(lock.verify(pin.expose()))).await?;
            let mut g = self.inner();
            if !ok {
                g.elevate_fails += 1;
                let left = ELEVATE_PIN_ATTEMPTS.saturating_sub(g.elevate_fails);
                return Err(Response::error(
                    ErrorCode::WrongKey,
                    if left > 0 {
                        tr!("Неверный PIN, осталось попыток: {n}", n = left)
                    } else {
                        tr!("Неверный PIN: дальше только мастер-пароль").into()
                    },
                ));
            }
            g.elevate_fails = 0;
            g.elevated_until = Some(Instant::now() + ELEVATION);
            return Ok(Response::Ok);
        }
        let key = key.ok_or_else(|| invalid(tr!("нужен PIN или мастер-пароль")))?;
        let cur = crate::maintenance::credentials(key)?;
        blocking(move || cur.verify(&path))
            .await
            .map_err(|_| Response::error(ErrorCode::WrongKey, tr!("Мастер-пароль не подошёл")))?;
        let mut g = self.inner();
        g.elevate_fails = 0;
        g.elevated_until = Some(Instant::now() + ELEVATION);
        Ok(Response::Ok)
    }

    pub(crate) async fn set_pin(
        &self,
        pin: Option<Secret>,
        key: Option<KeySpec>,
    ) -> Reply<Response> {
        let Some(pin) = pin else {
            self.inner().quick = None;
            self.update_config(|c| c.pin.take().is_some());
            return Ok(Response::Ok);
        };
        let key = key.ok_or_else(|| invalid(tr!("нужен мастер-пароль базы")))?;
        let path = self
            .with_vault(|v, _| v.path().to_path_buf())
            .ok_or_else(locked)?;
        let creds = QuickCreds {
            path: path.display().to_string(),
            password: key.password.clone().filter(|p| !p.expose().is_empty()),
            keyfile: key.keyfile.clone().filter(|k| !k.trim().is_empty()),
            yubikey: key.yubikey.clone().filter(|y| !y.trim().is_empty()),
        };
        let cur = crate::maintenance::credentials(key)?;
        let p = path.clone();
        blocking(move || cur.verify(&p))
            .await
            .map_err(|_| Response::error(ErrorCode::WrongKey, tr!("мастер-пароль не подошёл")))?;
        let lock = blocking(move || PinLock::new(pin.expose()))
            .await
            .map_err(|e| match e {
                Response::Error { message, .. } => invalid(message),
                other => other,
            })?;
        self.update_config(|c| {
            c.pin = Some(lock);
            true
        });
        self.arm_quick(&creds);
        Ok(Response::Ok)
    }

    pub(crate) fn prefs(&self, set: Option<Prefs>) -> Response {
        if let Some(p) = set {
            self.update_config(|c| {
                c.autolock_minutes = p.autolock_minutes;
                c.lock_on_screen_lock = p.lock_on_screen_lock;
                c.lock_on_sleep = p.lock_on_sleep;
                c.clipboard_clear_seconds = p.clipboard_clear_seconds;
                c.backups_keep = p.backups_keep;
                c.pin_hours = p.pin_hours.max(1);
                c.notify_expiry = p.notify_expiry;
                c.notify_breaches = p.notify_breaches;
                c.sync_watch = p.sync_watch;
                c.sync_guard = p.sync_guard;
                if p.check_updates && !c.check_updates {
                    // только что включили: проверить при ближайшем обходе
                    c.last_update_check = None;
                }
                c.check_updates = p.check_updates;
                // Include в ~/.ssh/config только при включённом агенте: иначе ssh пойдёт в пустой агент
                let was = c.ssh_agent && c.ssh_host_config;
                let now = p.ssh_agent && p.ssh_host_config;
                if was != now {
                    crate::ssh_agent::set_host_config(now);
                }
                c.ssh_agent = p.ssh_agent;
                c.ssh_unlock_prompt = p.ssh_unlock_prompt;
                c.ssh_host_config = p.ssh_host_config;
                c.ssh_connect = p.ssh_connect;
                c.tray = p.tray;
                c.terminal = p.terminal.clone();
                // только известные типы, без повторов
                let mut seen = std::collections::HashSet::new();
                c.kind_order = p
                    .kind_order
                    .iter()
                    .filter(|k| {
                        keywarden_core::model::EntryKind::ALL
                            .iter()
                            .any(|e| e.as_str() == k.as_str())
                            && seen.insert(k.to_string())
                    })
                    .cloned()
                    .collect();
                // в конфиг пишем только отличия от стандартных: пустой шаблон возвращает стандартный
                let defaults = keywarden_core::wallet::default_explorers();
                c.explorers = p
                    .explorers
                    .iter()
                    .filter(|(k, v)| {
                        !v.trim().is_empty()
                            && defaults.get(*k) != Some(v)
                            && v.contains("{address}")
                    })
                    .map(|(k, v)| (k.clone(), v.trim().to_string()))
                    .collect();
                true
            });
            if let Some(v) = self.inner().vault.as_mut() {
                v.backups.keep = p.backups_keep;
            }
        }
        let c = self.config();
        Response::Prefs {
            prefs: Box::new(Prefs {
                autolock_minutes: c.autolock_minutes,
                lock_on_screen_lock: c.lock_on_screen_lock,
                lock_on_sleep: c.lock_on_sleep,
                clipboard_clear_seconds: c.clipboard_clear_seconds,
                backups_keep: c.backups_keep,
                pin_set: c.pin.is_some(),
                pin_hours: c.pin_hours,
                notify_expiry: c.notify_expiry,
                notify_breaches: c.notify_breaches,
                sync_watch: c.sync_watch,
                sync_guard: c.sync_guard,
                kind_order: c.kind_order.clone(),
                check_updates: c.check_updates,
                ssh_agent: c.ssh_agent,
                ssh_unlock_prompt: c.ssh_unlock_prompt,
                ssh_host_config: c.ssh_host_config,
                ssh_connect: c.ssh_connect,
                tray: c.tray,
                terminal: c.terminal.clone(),
                update_available: c.latest_release.clone().filter(|t| {
                    c.check_updates && crate::updates::is_newer(t, env!("CARGO_PKG_VERSION"))
                }),
                explorers: {
                    let mut m = keywarden_core::wallet::default_explorers();
                    m.extend(c.explorers.clone());
                    m
                },
            }),
        }
    }

    fn backups_dir(&self) -> Reply<PathBuf> {
        self.with_vault(|v, _| v.backups.dir.clone())
            .ok_or_else(locked)
    }

    pub(crate) fn backups(&self) -> Reply<Response> {
        let dir = self.backups_dir()?;
        let mut backups: Vec<(std::time::SystemTime, BackupInfo)> = std::fs::read_dir(&dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "kdbx"))
            .filter_map(|e| {
                let meta = e.metadata().ok()?;
                let name = e.file_name().to_string_lossy().into_owned();
                let modified = meta.modified().ok()?;
                let when: chrono::DateTime<chrono::Local> = modified.into();
                Some((
                    modified,
                    BackupInfo {
                        kind: backup_kind(&name).into(),
                        when: when.format("%Y-%m-%d %H:%M").to_string(),
                        size: meta.len(),
                        name,
                    },
                ))
            })
            .collect();
        backups.sort_by_key(|a| std::cmp::Reverse(a.0));
        Ok(Response::Backups {
            backups: backups.into_iter().map(|(_, b)| b).collect(),
        })
    }

    pub(crate) async fn restore_backup(&self, name: String) -> Reply<Response> {
        // только имя файла из каталога копий: никаких путей
        if name.contains('/') || name.starts_with('.') || !name.ends_with(".kdbx") {
            return Err(invalid(tr!("неверное имя копии")));
        }
        let path = self.backups_dir()?.join(&name);
        let reader = self.with_vault(|v, _| v.reader()).ok_or_else(locked)?;
        let db = blocking(move || reader.parse_file(&path))
            .await
            .map_err(|e| match e {
                Response::Error {
                    code: ErrorCode::WrongKey,
                    ..
                } => Response::error(
                    ErrorCode::WrongKey,
                    tr!("копия сделана с другим мастер-ключом: откройте её через «Слить с файлом»"),
                ),
                other => other,
            })?;
        self.mutate_r(move |cur| {
            *cur = db;
            Ok(())
        })
        .await?;
        tracing::info!("база восстановлена из копии {name}");
        Ok(Response::Ok)
    }
}

fn backup_kind(name: &str) -> &'static str {
    if name.contains(".sync-conflict-") {
        "conflict"
    } else if name.contains(".unsaved-") {
        "unsaved"
    } else if name.contains(".presync-") {
        "presync"
    } else if name.contains(".moved-") {
        "moved"
    } else {
        "backup"
    }
}

/// Уведомления: истёкшие и истекающие записи (раз в сутки на запись) и, если включено,
/// еженедельная проверка утечек.
pub async fn notifier(d: Arc<Daemon>) {
    let mut told: HashMap<String, chrono::NaiveDate> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(30 * 60));
    let mut events = d.events.subscribe();
    loop {
        // сразу после разблокировки и затем раз в полчаса
        tokio::select! {
            _ = tick.tick() => {}
            e = events.recv() => {
                if !matches!(e, Ok(keywarden_core::ipc::Event::Unlocked)) {
                    continue;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        if !d.is_unlocked() {
            continue;
        }
        let config = d.config();
        if config.notify_expiry {
            expiry(&d, &mut told).await;
        }
        if config.notify_breaches {
            breaches(&d, config.last_breach_check.as_deref()).await;
        }
    }
}

async fn expiry(d: &Daemon, told: &mut HashMap<String, chrono::NaiveDate>) {
    let today = chrono::Local::now().date_naive();
    let soon = (today + chrono::Days::new(7))
        .format("%Y-%m-%d")
        .to_string();
    let Ok(entries) = d.read(|db| {
        Ok(keywarden_core::search::search_filtered(
            db,
            "",
            usize::MAX,
            &Default::default(),
        ))
    }) else {
        return;
    };
    let (mut expired, mut expiring) = (vec![], vec![]);
    for e in entries {
        let Some(date) = e.expires.as_deref() else {
            continue;
        };
        if date > soon.as_str() || told.get(&e.id) == Some(&today) {
            continue;
        }
        told.insert(e.id.clone(), today);
        if e.expired {
            expired.push(e.title);
        } else {
            expiring.push(format!("{} ({date})", e.title));
        }
    }
    if !expired.is_empty() {
        crate::sync::notify_desktop(tr!("Keywarden: срок записей истёк"), &expired.join(", "))
            .await;
    }
    if !expiring.is_empty() {
        crate::sync::notify_desktop(tr!("Keywarden: скоро истекает срок"), &expiring.join(", "))
            .await;
    }
}

async fn breaches(d: &Daemon, last: Option<&str>) {
    let now = chrono::Utc::now();
    let due = last
        .and_then(|l| chrono::DateTime::parse_from_rfc3339(l).ok())
        .is_none_or(|l| now.signed_duration_since(l) > chrono::TimeDelta::days(7));
    if !due {
        return;
    }
    d.update_config(|c| {
        c.last_breach_check = Some(now.to_rfc3339());
        true
    });
    match d.health(true).await {
        Ok(Response::Health { report }) if report.breached > 0 => {
            let body = tr!(
                "Найдено в утечках: {n}. Откройте «Проверку паролей», чтобы сменить их",
                n = report.breached
            );
            crate::sync::notify_desktop(tr!("Keywarden: пароли в утечках"), &body).await;
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("проверка утечек по расписанию не удалась: {e:?}"),
    }
}
