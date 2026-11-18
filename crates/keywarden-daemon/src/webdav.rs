//! Копия базы на сервере WebDAV (Nextcloud, Synology, любой WebDAV).
//!
//! Раз в минуту и после каждой записи: забрать файл с сервера, если он изменился (по ETag),
//! слить тем же путём, что и файл с диска, и положить свой файл обратно, если в нём есть то,
//! чего на сервере нет. Запись условная (`If-Match`): если сервер успел получить чужую версию,
//! сначала сливаем её. Настройка лежит в самой базе (`keywarden_core::remote::webdav`).

use crate::state::{Daemon, Reply, blocking, locked};
use crate::sync::Incoming;
use data_encoding::BASE64;
use keywarden_core::ipc::{ErrorCode, Event, RemoteInfo, Response};
use keywarden_core::remote::{self, MAX_VAULT_BYTES, WebDav};
use keywarden_core::secret::Secret;
use keywarden_core::{merge, tr};
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

/// Как часто спрашивать сервер (KEYWARDEN_WEBDAV_POLL, секунды: для тестов).
fn poll() -> Duration {
    let secs = std::env::var("KEYWARDEN_WEBDAV_POLL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60);
    Duration::from_secs(secs)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("Keywarden/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn auth(c: &WebDav) -> String {
    let raw = zeroize::Zeroizing::new(format!("{}:{}", c.user, c.password.expose()));
    format!("Basic {}", BASE64.encode(raw.as_bytes()))
}

fn status_error(code: u16) -> String {
    match code {
        401 | 403 => tr!("сервер не принял логин или пароль").into(),
        409 => tr!("на сервере нет такой папки").into(),
        507 => tr!("на сервере нет места").into(),
        c => tr!("сервер ответил {code}", code = c),
    }
}

fn etag_of(resp: &ureq::Response) -> Option<String> {
    resp.header("ETag")
        .or_else(|| resp.header("OC-ETag"))
        .map(str::to_owned)
}

pub(crate) enum Got {
    NotModified,
    Missing,
    Body(Vec<u8>, Option<String>),
}

pub(crate) fn get(c: &WebDav, etag: Option<&str>) -> Result<Got, String> {
    let mut req = agent().get(&c.url).set("Authorization", &auth(c));
    if let Some(e) = etag {
        req = req.set("If-None-Match", e);
    }
    match req.call() {
        // ureq считает ошибкой только коды от 400: 304 приходит как успешный ответ без тела
        Ok(resp) if resp.status() == 304 => Ok(Got::NotModified),
        Ok(resp) => {
            let etag = etag_of(&resp);
            let mut buf = vec![];
            resp.into_reader()
                .take(MAX_VAULT_BYTES as u64 + 1)
                .read_to_end(&mut buf)
                .map_err(|e| e.to_string())?;
            if buf.len() > MAX_VAULT_BYTES {
                return Err(tr!("файл на сервере слишком большой").into());
            }
            Ok(Got::Body(buf, etag))
        }
        Err(ureq::Error::Status(404, _)) => Ok(Got::Missing),
        Err(ureq::Error::Status(code, _)) => Err(status_error(code)),
        Err(e) => Err(tr!("нет связи с сервером: {e}", e = e)),
    }
}

enum Put {
    Done(Option<String>),
    /// на сервере уже другая версия: сначала слить её
    Conflict,
}

/// `if_match`: ETag версии, поверх которой пишем; `None` и `exists = false`: файла ещё нет.
fn put(c: &WebDav, bytes: &[u8], if_match: Option<&str>, exists: bool) -> Result<Put, String> {
    let mut req = agent()
        .put(&c.url)
        .set("Authorization", &auth(c))
        .set("Content-Type", "application/octet-stream");
    match (if_match, exists) {
        // Apache отдаёт слабый ETag (W/"…") в ту же секунду после записи, а If-Match сравнивает
        // строго: без префикса метка совпадёт, как только файл перестанет быть «свежим»
        (Some(e), _) => req = req.set("If-Match", e.trim_start_matches("W/")),
        (None, false) => req = req.set("If-None-Match", "*"),
        // сервер без ETag: условной записи нет, пишем сразу после слияния
        (None, true) => {}
    }
    match req.send_bytes(bytes) {
        Ok(resp) => Ok(Put::Done(etag_of(&resp))),
        Err(ureq::Error::Status(412, _)) => Ok(Put::Conflict),
        Err(ureq::Error::Status(code, _)) => Err(status_error(code)),
        Err(e) => Err(tr!("нет связи с сервером: {e}", e = e)),
    }
}

fn head_etag(c: &WebDav) -> Option<String> {
    agent()
        .head(&c.url)
        .set("Authorization", &auth(c))
        .call()
        .ok()
        .and_then(|r| etag_of(&r))
}

/// Что мы знаем о копии на сервере для текущей разблокировки.
#[derive(Default)]
struct Link {
    key: Option<(u64, String)>,
    etag: Option<String>,
    /// файл на сервере есть
    exists: bool,
    /// sha256 последнего скачанного файла: тот же файл без ETag заново не разбираем
    body_hash: Option<[u8; 32]>,
    /// наш файл с этим sha256 уже ничем не отличается от копии на сервере
    synced: Option<[u8; 32]>,
}

pub async fn watch(daemon: Arc<Daemon>) {
    let mut events = daemon.events.subscribe();
    let mut link = Link::default();
    let mut retries = 0;
    loop {
        let again = match pass(&daemon, &mut link).await {
            Ok(again) => again,
            Err(e) => {
                tracing::warn!("WebDAV: {e}");
                daemon.set_webdav_status(false, e);
                false
            }
        };
        // сервер получил чужую версию: сразу ещё раз, но не бесконечно
        if again && retries < 3 {
            retries += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        retries = 0;
        let wait = tokio::time::sleep(poll());
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => break,
                ev = events.recv() => match ev {
                    Ok(Event::Saved) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => break,
                    Ok(_) => {}
                    Err(_) => return,
                },
            }
        }
    }
}

/// Один обход. `Ok(true)`: сервер успел получить чужую версию, обойти сразу ещё раз.
async fn pass(d: &Arc<Daemon>, link: &mut Link) -> Result<bool, String> {
    let Some((reader, epoch, cfg)) = d.with_vault(|v, e| (v.reader(), e, remote::webdav(&v.db)))
    else {
        *link = Link::default();
        return Ok(false);
    };
    let Some(cfg) = cfg else {
        *link = Link::default();
        d.inner().sync.webdav_status = None;
        return Ok(false);
    };
    let key = (epoch, cfg.url.clone());
    if link.key.as_ref() != Some(&key) {
        *link = Link {
            key: Some(key),
            ..Default::default()
        };
    }
    if d.sync_held() {
        return Ok(false); // ждём решения по массовому удалению
    }

    // 1. забрать
    let c = cfg.clone();
    let etag = link.etag.clone();
    match tokio::task::spawn_blocking(move || get(&c, etag.as_deref()))
        .await
        .map_err(|e| e.to_string())??
    {
        Got::NotModified => link.exists = true,
        Got::Missing => {
            link.exists = false;
            link.etag = None;
            link.synced = None;
        }
        Got::Body(bytes, etag) => {
            link.exists = true;
            let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&bytes).into();
            if link.body_hash != Some(hash) {
                let r = reader.clone();
                let db = tokio::task::spawn_blocking(move || r.parse_bytes(&bytes))
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| tr!("файл на сервере не открылся этим паролем: {e}", e = e))?;
                d.inner().sync.incoming.push(Incoming {
                    source: "WebDAV".into(),
                    db: db.clone(),
                });
                d.sync_from_disk().await?;
                if d.sync_held() {
                    return Ok(false);
                }
                // есть ли у нас что-то, чего нет на сервере
                let extra = d
                    .with_vault(|v, _| {
                        let mut probe = db.clone();
                        merge::merge(&mut probe, &v.db).map(|r| !r.is_empty())
                    })
                    .ok_or_else(|| tr!("база заблокирована").to_string())?
                    .map_err(|e| e.to_string())?;
                link.body_hash = Some(hash);
                if !extra {
                    let r = reader.clone();
                    link.synced = tokio::task::spawn_blocking(move || r.hash_on_disk().ok())
                        .await
                        .ok()
                        .flatten();
                }
            }
            link.etag = etag;
        }
    }

    // 2. положить свой файл, если на сервере его нет или в нём есть не всё
    let r = reader.clone();
    let (bytes, hash) = tokio::task::spawn_blocking(move || r.read_bytes())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    if link.exists && link.synced == Some(hash) {
        d.set_webdav_status(true, synced_now());
        return Ok(false);
    }
    let c = cfg.clone();
    let (etag, exists) = (link.etag.clone(), link.exists);
    let put_res = tokio::task::spawn_blocking(move || {
        put(&c, &bytes, etag.as_deref(), exists).map(|p| match p {
            Put::Done(None) => Put::Done(head_etag(&c)),
            other => other,
        })
    })
    .await
    .map_err(|e| e.to_string())??;
    match put_res {
        Put::Done(etag) => {
            tracing::info!("WebDAV: база выложена на сервер");
            link.etag = etag;
            link.exists = true;
            link.synced = Some(hash);
            link.body_hash = None;
            d.set_webdav_status(true, synced_now());
            Ok(false)
        }
        Put::Conflict => {
            tracing::info!("WebDAV: на сервере новая версия, сливаю перед записью");
            // следующий обход заберёт файл и свежую метку без If-None-Match
            link.etag = None;
            Ok(true)
        }
    }
}

fn synced_now() -> String {
    tr!(
        "синхронизировано в {time}",
        time = chrono::Local::now().format("%H:%M")
    )
}

impl Daemon {
    pub(crate) fn set_webdav_status(&self, ok: bool, message: String) {
        let changed = {
            let mut g = self.inner();
            let new = Some((ok, message));
            let changed = g.sync.webdav_status != new;
            g.sync.webdav_status = new;
            changed
        };
        if changed {
            self.events.send(Event::Changed).ok();
        }
    }

    pub(crate) fn remote_info(&self, g: &crate::state::Inner) -> RemoteInfo {
        let cfg = g.vault.as_ref().and_then(|v| remote::webdav(&v.db));
        RemoteInfo {
            webdav_url: cfg.as_ref().map(|c| c.url.clone()),
            webdav_user: cfg.as_ref().map(|c| c.user.clone()),
            webdav_state: g.sync.webdav_status.as_ref().map(|s| s.1.clone()),
            webdav_ok: g.sync.webdav_status.as_ref().is_some_and(|s| s.0),
            peers: g
                .sync
                .peers
                .iter()
                .map(|(ip, when)| tr!("{ip}, на связи в {time}", ip = ip, time = when))
                .collect(),
            lan_state: g.sync.lan_state.clone(),
        }
    }

    /// Включить, сменить или выключить WebDAV. Перед сохранением проверяем адрес и логин.
    pub(crate) async fn webdav_set(
        self: &Arc<Self>,
        url: String,
        user: String,
        password: Option<Secret>,
    ) -> Reply<Response> {
        let (file_name, old) = self
            .with_vault(|v, _| {
                (
                    v.reader()
                        .path()
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "keywarden.kdbx".into()),
                    remote::webdav(&v.db),
                )
            })
            .ok_or_else(locked)?;
        let cfg = if url.trim().is_empty() {
            None
        } else {
            let url = remote::check_webdav_url(&url, &file_name)
                .map_err(|e| Response::error(ErrorCode::Invalid, e))?;
            // пароль не ввели заново: прежний для того же сервера
            let password = match password.filter(|p| !p.is_empty()) {
                Some(p) => p,
                None => old
                    .filter(|o| o.url == url && o.user == user)
                    .map(|o| o.password)
                    .ok_or_else(|| {
                        Response::error(ErrorCode::Invalid, tr!("нужен пароль от сервера"))
                    })?,
            };
            let cfg = WebDav {
                url,
                user,
                password,
            };
            let probe = cfg.clone();
            blocking(move || get(&probe, None).map(|_| ())).await?;
            Some(cfg)
        };
        let epoch = self.inner().epoch;
        self.with_vault_mut(epoch, |v| remote::set_webdav(&mut v.db, cfg.as_ref()))
            .ok_or_else(locked)?;
        self.inner().sync.webdav_status = None;
        self.bump_and_wait_saved()
            .await
            .map_err(|e| Response::error(ErrorCode::Conflict, e))?;
        self.events.send(Event::Changed).ok();
        Ok(Response::Ok)
    }
}
