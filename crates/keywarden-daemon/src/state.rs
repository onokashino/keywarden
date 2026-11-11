//! Состояние демона и обработка запросов.
//!
//! Расшифрованная база живёт только здесь. Правки применяются в памяти под коротким мьютексом,
//! а сохранение (Argon2 при сериализации и проверке, секунды) идёт в отдельной задаче:
//! поиск из лаунчера в это время не ждёт. Запрос на правку отвечает только после записи на диск.

use crate::clipboard;
use crate::config::Config;
use data_encoding::BASE64;
use keepass::Database;
use keywarden_core::ipc::{ErrorCode, Event, Request, Response, StatusInfo};
use keywarden_core::model::{self, ModelError};
use keywarden_core::secret::Secret;
use keywarden_core::totp::Totp;
use keywarden_core::vault::{Challenge, Credentials, Vault, VaultError};
use keywarden_core::{generator, search};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, broadcast, watch};

pub struct Daemon {
    inner: Mutex<Inner>,
    config_path: PathBuf,
    pub events: broadcast::Sender<Event>,
    kick: Notify,
    saved: watch::Sender<SaveState>,
}

pub(crate) struct Inner {
    pub(crate) config: Config,
    pub(crate) vault: Option<Vault>,
    /// шифровка ключа базы для PIN (см. keywarden_core::quick)
    pub(crate) quick: Option<crate::prefs::Armed>,
    /// до какого момента открыты поля криптокошельков (повторное подтверждение)
    pub(crate) elevated_until: Option<Instant>,
    pub(crate) elevate_fails: u8,
    /// журнал синхронизаций и входящая версия на паузе
    pub(crate) sync: crate::sync::SyncState,
    /// растёт при каждой правке; сохранено всё до `SaveState::saved`
    generation: u64,
    /// растёт при каждой разблокировке, чтобы результат старого сохранения не попал в новую базу
    pub(crate) epoch: u64,
    last_activity: Instant,
}

#[derive(Debug, Clone, Default)]
struct SaveState {
    saved: u64,
    failed: Option<(u64, String)>,
}

pub(crate) type Reply<T> = Result<T, Response>;

impl Daemon {
    pub fn new(config: Config, config_path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                config,
                vault: None,
                quick: None,
                elevated_until: None,
                elevate_fails: 0,
                sync: Default::default(),
                generation: 0,
                epoch: 0,
                last_activity: Instant::now(),
            }),
            config_path,
            events: broadcast::channel(64).0,
            kick: Notify::new(),
            saved: watch::channel(SaveState::default()).0,
        })
    }

    pub(crate) fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn config(&self) -> Config {
        self.inner().config.clone()
    }

    /// Сколько база простаивает (None, если заблокирована).
    pub fn idle(&self) -> Option<Duration> {
        let g = self.inner();
        g.vault.as_ref().map(|_| g.last_activity.elapsed())
    }

    /// Номер текущей разблокировки (для кэшей, которые надо сбросить при блокировке).
    #[cfg(target_os = "linux")]
    pub fn unlocked_epoch(&self) -> Option<u64> {
        let g = self.inner();
        g.vault.as_ref().map(|_| g.epoch)
    }

    /// (разблокировка, правка): меняется при каждой разблокировке и каждом изменении базы.
    pub fn change_stamp(&self) -> Option<(u64, u64)> {
        let g = self.inner();
        g.vault.as_ref().map(|_| (g.epoch, g.generation))
    }

    pub fn is_unlocked(&self) -> bool {
        self.inner().vault.is_some()
    }

    fn emit(&self, e: Event) {
        let _ = self.events.send(e);
    }

    pub(crate) fn emit_event(&self, e: Event) {
        self.emit(e);
    }

    /// Поправить конфиг; `f` возвращает true, если есть что сохранить.
    pub(crate) fn update_config(&self, f: impl FnOnce(&mut Config) -> bool) {
        let mut g = self.inner();
        if f(&mut g.config)
            && let Err(e) = g.config.save_to(&self.config_path)
        {
            tracing::warn!("не удалось сохранить конфиг: {e}");
        }
    }

    pub async fn handle(self: &Arc<Self>, req: Request) -> Response {
        if !matches!(req, Request::Ping | Request::Status | Request::Subscribe) {
            self.inner().last_activity = Instant::now();
        }
        self.dispatch(req).await.unwrap_or_else(|e| e)
    }

    /// Новая запись «Ключ SSH»: ключ во вложении, настройки KeeAgent, открытый ключ в заметке.
    #[allow(clippy::too_many_arguments)]
    async fn ssh_entry(
        self: &Arc<Self>,
        title: String,
        pem: Vec<u8>,
        file_name: String,
        passphrase: Option<Secret>,
        group: Option<String>,
        confirm: bool,
        host: Option<String>,
    ) -> Reply<Response> {
        let pass = passphrase.clone().unwrap_or_default();
        let public = crate::ssh_agent::check_key(&pem, pass.expose())
            .map_err(|e| Response::error(ErrorCode::Invalid, e))?;
        let comment = public
            .split_whitespace()
            .nth(2)
            .unwrap_or_default()
            .to_string();
        let id = self
            .mutate(move |db| {
                let mut set = vec![
                    model::FieldSet::new("Title", title),
                    model::FieldSet::new("UserName", comment),
                ];
                if let Some(h) = host.filter(|h| !h.trim().is_empty()) {
                    set.push(model::FieldSet::new("URL", h.trim().to_string()));
                }
                if let Some(p) = passphrase {
                    set.push(model::FieldSet {
                        name: "Password".into(),
                        value: p,
                        protected: Some(true),
                    });
                }
                set.push(model::FieldSet::new("Notes", public));
                let id = model::create_entry(
                    db,
                    &model::EntryPatch {
                        kind: Some(model::EntryKind::SshKey),
                        group,
                        set,
                        ..Default::default()
                    },
                )?;
                let eid = model::parse_entry_id(&id)?;
                let mut e = db.entry_mut(eid).ok_or(ModelError::EntryNotFound)?;
                e.add_attachment(file_name.clone(), keepass::db::Value::protected(pem));
                e.add_attachment(
                    model::KEEAGENT_SETTINGS,
                    keepass::db::Value::unprotected(keywarden_core::keeagent::generate(
                        &file_name, confirm,
                    )),
                );
                Ok(id)
            })
            .await?;
        Ok(Response::Created { id })
    }

    async fn dispatch(self: &Arc<Self>, req: Request) -> Reply<Response> {
        Ok(match req {
            Request::Ping => Response::Pong {
                version: env!("CARGO_PKG_VERSION").into(),
            },
            Request::Status => Response::Status(self.status()),
            Request::Subscribe => Response::Ok,
            Request::Unlock {
                path,
                password,
                keyfile,
                yubikey,
            } => return self.unlock(path, password, keyfile, yubikey).await,
            Request::Create {
                path,
                password,
                keyfile,
                yubikey,
                cipher,
            } => {
                let path = crate::config::expand(&PathBuf::from(path));
                let challenge = yubikey
                    .as_deref()
                    .map(Challenge::parse_yubikey)
                    .transpose()
                    .map_err(|e| Response::error(ErrorCode::Invalid, e))?;
                let creds = Credentials {
                    password,
                    keyfile: keyfile.map(PathBuf::from),
                    challenge,
                };
                let kf = creds.keyfile.clone();
                let p = path.clone();
                let vault = blocking(move || {
                    Vault::create(
                        p,
                        &creds,
                        cipher,
                        keywarden_core::vault::tuned_kdf(Duration::from_secs(1)),
                    )
                })
                .await?;
                self.install(vault, path, kf);
                self.inner().quick = None;
                Response::Ok
            }
            Request::Lock => {
                self.lock("по команде").await;
                Response::Ok
            }
            Request::Search {
                query,
                limit,
                filter,
            } => {
                let entries =
                    self.read(|db| Ok(search::search_filtered(db, &query, limit, &filter)))?;
                Response::Entries { entries }
            }
            Request::Get { id, reveal } => {
                let mut entry =
                    self.read(|db| model::detail(db, &id, reveal).map_err(model_err))?;
                // поля кошелька (фраза, passphrase, ключ) без повторного подтверждения не отдаются
                if entry.summary.kind == model::EntryKind::CryptoWallet && !self.elevated() {
                    for f in entry.fields.iter_mut() {
                        let empty = f.value.as_ref().is_some_and(|v| v.expose().is_empty());
                        if keywarden_core::wallet::is_guarded(&f.name) && !empty {
                            f.value = None;
                        }
                    }
                }
                Response::Entry {
                    entry: Box::new(entry),
                }
            }
            Request::Totp { id } => {
                let code = self.read(|db| totp_code(db, &id))?;
                Response::Totp { code: code.0 }
            }
            Request::Copy { id, field } => {
                let guarded = self.read(|db| Ok(wallet_guarded(db, &id, &field)))?;
                if guarded {
                    self.require_elevation()?;
                }
                let value = self.read(|db| copy_value(db, &id, &field))?;
                self.touch(&id);
                if guarded {
                    // фраза в буфере живёт 10 секунд, а не как обычный пароль
                    blocking(move || clipboard::copy(&value, Duration::from_secs(10))).await?;
                } else {
                    self.to_clipboard(value).await?;
                }
                Response::Ok
            }
            Request::CopyText { value } => {
                self.to_clipboard(value).await?;
                Response::Ok
            }
            Request::Groups => Response::Groups {
                groups: self.read(|db| Ok(model::groups(db)))?,
            },
            Request::AttachmentGet { id, name } => {
                let data = self.read(|db| model::attachment(db, &id, &name).map_err(model_err))?;
                Response::Attachment {
                    data: BASE64.encode(&data),
                }
            }
            Request::Generate { options } => Response::Generated {
                generated: generator::generate(&options),
            },
            Request::SshGenerate {
                title,
                comment,
                host,
                group,
                confirm,
                algorithm,
            } => {
                let comment = comment.unwrap_or_else(|| title.clone());
                let (alg, file) =
                    crate::ssh_agent::algorithm(algorithm.as_deref().unwrap_or_default())
                        .map_err(|e| Response::error(ErrorCode::Invalid, e))?;
                let pem =
                    tokio::task::spawn_blocking(move || crate::ssh_agent::generate(&comment, alg))
                        .await
                        .map_err(|e| Response::error(ErrorCode::Internal, e.to_string()))?
                        .map_err(|e| Response::error(ErrorCode::Invalid, e))?;
                return self
                    .ssh_entry(title, pem, file.into(), None, group, confirm, host)
                    .await;
            }
            Request::SshLocalKeys => {
                let have = self.read(|db| Ok(crate::ssh_agent::vault_public_keys(db)))?;
                Response::SshLocalKeys {
                    keys: crate::ssh_agent::local_keys(&have),
                }
            }
            Request::SshMigrate { paths, delete } => {
                let have = self.read(|db| Ok(crate::ssh_agent::vault_public_keys(db)))?;
                // переносим только то, что сами нашли в ~/.ssh: путь от клиента не доверяем
                let found = crate::ssh_agent::local_keys(&have);
                for p in paths {
                    let Some(k) = found
                        .iter()
                        .find(|k| k.path == p && !k.in_vault && !k.encrypted)
                    else {
                        continue;
                    };
                    let pem = std::fs::read(&k.path).map_err(|e| {
                        Response::error(
                            ErrorCode::Invalid,
                            tr!("{path}: {e}", path = k.path, e = e),
                        )
                    })?;
                    let file_name = std::path::Path::new(&k.path)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "id_key".into());
                    let title = if k.comment.is_empty() {
                        file_name.clone()
                    } else {
                        format!("{file_name} ({})", k.comment)
                    };
                    self.ssh_entry(title, pem, file_name, None, None, false, None)
                        .await?;
                    // удаляем, только если ключ после сохранения действительно виден в базе
                    let now = self.read(|db| Ok(crate::ssh_agent::vault_public_keys(db)))?;
                    let saved = crate::ssh_agent::local_keys(&now)
                        .iter()
                        .any(|x| x.path == k.path && x.in_vault);
                    if delete
                        && saved
                        && let Err(e) = std::fs::remove_file(&k.path)
                    {
                        tracing::warn!("SSH: не удалось удалить {}: {e}", k.path);
                    }
                }
                let have = self.read(|db| Ok(crate::ssh_agent::vault_public_keys(db)))?;
                Response::SshLocalKeys {
                    keys: crate::ssh_agent::local_keys(&have),
                }
            }
            Request::SshHosts => {
                let c = self.config();
                let via_config = c.ssh_agent && c.ssh_host_config;
                let hosts = self.read(|db| Ok(crate::ssh_agent::load_hosts(db)))?;
                Response::SshHosts {
                    hosts: hosts
                        .into_iter()
                        .map(|h| {
                            let b = h.block();
                            keywarden_core::ipc::SshHost {
                                args: if via_config {
                                    vec![h.alias.clone()]
                                } else {
                                    h.explicit_args()
                                },
                                knock_first: b.knock && !via_config,
                                knock: b.knock,
                                forwards: b
                                    .forwards
                                    .iter()
                                    .map(|(l, r)| format!("{l} → {r}"))
                                    .collect(),
                                address: h.address.display(),
                                id: h.id,
                                title: h.title,
                                alias: h.alias,
                                group: h.group,
                                key: h.key,
                                proxy: h.proxy,
                            }
                        })
                        .collect(),
                }
            }
            Request::SshKnock { host } => {
                let h = self
                    .read(|db| Ok(crate::ssh_agent::load_hosts(db)))?
                    .into_iter()
                    .find(|h| h.alias.eq_ignore_ascii_case(&host))
                    .ok_or_else(|| {
                        Response::error(
                            ErrorCode::NotFound,
                            tr!("нет сервера SSH «{host}»", host = host),
                        )
                    })?;
                let seq = keywarden_core::ssh_hosts::knock_sequence(&h.knock)
                    .map_err(|e| Response::error(ErrorCode::Invalid, e))?;
                if !seq.is_empty() {
                    let target = h.address.host.clone();
                    blocking(move || keywarden_core::ssh_hosts::knock(&target, &seq)).await?;
                }
                Response::Ok
            }
            Request::SshConfigHosts => {
                let hosts =
                    keywarden_core::ssh_hosts::parse_config(&crate::ssh_agent::ssh_config_text());
                let h2 = hosts.clone();
                let keys =
                    blocking(move || Ok::<_, String>(crate::ssh_agent::identity_keys(&h2))).await?;
                let plan = self.read(|db| Ok(crate::ssh_agent::plan_config(db, &hosts, &keys)))?;
                Response::SshConfigHosts {
                    hosts: plan
                        .into_iter()
                        .map(|p| keywarden_core::ipc::ConfigHostPreview {
                            address: p.host.address().display(),
                            alias: p.host.alias,
                            folder: p.folder.join("/"),
                            identity: p.host.identity,
                            key: p.key,
                            in_vault: p.in_vault,
                        })
                        .collect(),
                }
            }
            Request::SshImportConfig { only } => {
                let hosts =
                    keywarden_core::ssh_hosts::parse_config(&crate::ssh_agent::ssh_config_text());
                let h2 = hosts.clone();
                let keys =
                    blocking(move || Ok::<_, String>(crate::ssh_agent::identity_keys(&h2))).await?;
                let (added, skipped) = self
                    .mutate(move |db| {
                        let plan = crate::ssh_agent::plan_config(db, &hosts, &keys);
                        crate::ssh_agent::import_config(db, &plan, only.as_deref())
                    })
                    .await?;
                Response::SshImported { added, skipped }
            }
            Request::SshImport {
                title,
                key,
                file_name,
                passphrase,
                group,
                confirm,
                host,
            } => {
                let pem = BASE64
                    .decode(key.as_bytes())
                    .map_err(|_| Response::error(ErrorCode::Invalid, tr!("ключ не в base64")))?;
                return self
                    .ssh_entry(title, pem, file_name, passphrase, group, confirm, host)
                    .await;
            }
            Request::ImportBitwarden { json } => {
                let report = self
                    .mutate(move |db| {
                        keywarden_core::bitwarden::import(db, &json)
                            .map_err(|e| ModelError::BadId(e.to_string()))
                    })
                    .await?;
                Response::Imported { report }
            }
            Request::Browser { message } => Response::Browser {
                reply: self.browser(message).await,
            },
            Request::ChangeKey { current, new } => return self.change_key(current, new).await,
            Request::GenerateKeyfile { path } => return self.generate_keyfile(path).await,
            Request::GetSettings => return self.get_settings(),
            Request::SetSettings { settings } => return self.set_settings(settings).await,
            Request::TuneKdf => return self.tune_kdf().await,
            Request::SaveCopy { path, key } => return self.save_copy(path, key).await,
            Request::ExportCsv { path } => return self.export_csv(path).await,
            Request::ImportFile { path, format, key } => {
                return self.import_file(path, format, key).await;
            }
            Request::MergeFile { path, key } => return self.merge_file(path, key).await,
            Request::QuickUnlock { pin } => return self.quick_unlock(pin).await,
            Request::SetPin { pin, key } => return self.set_pin(pin, key).await,
            Request::Prefs { set } => self.prefs(set),
            Request::Backups => return self.backups(),
            Request::Elevate { pin, key } => return self.elevate(pin, key).await,
            Request::ReorderEntry { id, target, after } => self
                .mutate(|db| model::reorder_entry(db, &id, &target, after))
                .await
                .map(ok)?,
            Request::ReorderGroup { id, target, after } => self
                .mutate(|db| model::reorder_group(db, &id, &target, after))
                .await
                .map(ok)?,
            Request::RenameTag { from, to } => self
                .mutate(|db| model::rename_tag(db, &from, &to))
                .await
                .map(|_| Response::Ok)?,
            Request::DeleteTag { tag } => self
                .mutate(|db| model::remove_tag(db, &tag))
                .await
                .map(|_| Response::Ok)?,
            Request::NudgeEntry { id, delta } => self
                .mutate(|db| model::nudge_entry(db, &id, delta))
                .await
                .map(ok)?,
            Request::RestoreBackup { name } => return self.restore_backup(name).await,
            Request::SyncJournal => return self.sync_journal(),
            Request::SyncDecide { accept } => return self.sync_decide(accept).await,
            Request::SyncRevert { id } => return self.sync_revert(id).await,
            Request::MoveDatabase { dir } => return self.move_database(dir).await,
            Request::Duplicate { id } => Response::Created {
                id: self.mutate(|db| model::duplicate_entry(db, &id)).await?,
            },
            Request::MoveEntry { id, group } => self
                .mutate(|db| model::move_entry(db, &id, &group))
                .await
                .map(ok)?,
            Request::MoveGroup { id, parent } => self
                .mutate(|db| model::move_group(db, &id, &parent))
                .await
                .map(ok)?,
            Request::Tags => Response::Tags {
                tags: self.read(|db| Ok(model::tags(db)))?,
            },
            Request::OtpPreview {
                input,
                issuer,
                account,
            } => return self.otp_preview(input, issuer, account),
            Request::SetOtp { id, value } => return self.set_otp(id, value).await,
            Request::OtpUri { id } => return self.otp_uri(id),
            Request::OtpScan { path } => return self.otp_scan(path).await,
            Request::ExportTwoFas { path } => return self.export_twofas(path).await,
            Request::Health { breaches } => return self.health(breaches).await,
            Request::FetchFavicon { id } => return self.fetch_favicon(id).await,
            Request::ClearIcon { id } => {
                self.mutate(|db| model::clear_icon(db, &id)).await.map(ok)?
            }
            Request::IconData { uuid } => return self.icon_data(uuid),
            Request::AutoType {
                id,
                window,
                sequence,
            } => return self.autotype(id, window, sequence).await,
            Request::SecretService { enable } => {
                if let Some(on) = enable {
                    self.update_config(|c| {
                        c.secret_service = on;
                        true
                    });
                }
                let cfg = self.config();
                #[cfg(target_os = "linux")]
                let (owner, active) = crate::secret_service::owner().await;
                // связка ключей Secret Service есть только в Linux
                #[cfg(not(target_os = "linux"))]
                let (owner, active) = (None, false);
                Response::SecretService {
                    enabled: cfg.secret_service,
                    owner,
                    active,
                    group: cfg.secret_service_group,
                }
            }
            Request::SecretsMigrate => {
                if !self.is_unlocked() {
                    return Err(locked());
                }
                #[cfg(not(target_os = "linux"))]
                return Err(Response::error(
                    ErrorCode::Invalid,
                    tr!("связка ключей Secret Service есть только в Linux"),
                ));
                #[cfg(target_os = "linux")]
                {
                    let m = crate::secret_service::migrate(&self.clone())
                        .await
                        .map_err(|e| Response::error(ErrorCode::Internal, e))?;
                    Response::SecretsMigrated {
                        items: m.items,
                        skipped: m.skipped,
                    }
                }
            }
            Request::HealthExclude { id, exclude } => self
                .mutate(|db| keywarden_core::health::set_excluded(db, &id, exclude))
                .await
                .map(ok)?,

            // --- правки: ответ после записи на диск ---
            Request::Add { patch } => Response::Created {
                id: self.mutate(|db| model::create_entry(db, &patch)).await?,
            },
            Request::Update { id, patch } => {
                let touches = self.read(|db| {
                    Ok(patch
                        .set
                        .iter()
                        .map(|f| f.name.as_str())
                        .chain(patch.remove.iter().map(String::as_str))
                        .any(|n| wallet_guarded(db, &id, n)))
                })?;
                if touches {
                    self.require_elevation()?;
                }
                self.mutate(|db| model::update_entry(db, &id, &patch))
                    .await
                    .map(ok)?
            }
            Request::Delete { id } => self
                .mutate(|db| model::delete_entry(db, &id))
                .await
                .map(ok)?,
            Request::RestoreHistory { id, index } => {
                // откат кошелька меняет фразу: тоже только после подтверждения
                if self.read(|db| Ok(wallet_guarded(db, &id, keywarden_core::wallet::SEED)))? {
                    self.require_elevation()?;
                }
                self.mutate(|db| model::restore_history(db, &id, index))
                    .await
                    .map(ok)?
            }
            Request::AddGroup { parent, name } => Response::Created {
                id: self
                    .mutate(|db| model::add_group(db, parent.as_deref(), &name))
                    .await?,
            },
            Request::RenameGroup { id, name } => self
                .mutate(|db| model::rename_group(db, &id, &name))
                .await
                .map(ok)?,
            Request::DeleteGroup { id } => self
                .mutate(|db| model::delete_group(db, &id))
                .await
                .map(ok)?,
            Request::AttachmentAdd { id, name, data } => {
                let bytes = BASE64.decode(data.as_bytes()).map_err(|_| {
                    Response::error(ErrorCode::Invalid, tr!("вложение не в base64"))
                })?;
                self.mutate(|db| model::add_attachment(db, &id, &name, bytes))
                    .await
                    .map(ok)?
            }
            Request::AttachmentRemove { id, name } => self
                .mutate(|db| model::remove_attachment(db, &id, &name))
                .await
                .map(ok)?,
        })
    }

    fn status(&self) -> StatusInfo {
        let g = self.inner();
        StatusInfo {
            locked: g.vault.is_none(),
            path: g.vault.as_ref().map(|v| v.path().display().to_string()),
            entries: g.vault.as_ref().map(|v| v.db.num_entries()).unwrap_or(0),
            default_path: g.config.database.as_ref().map(|p| p.display().to_string()),
            keyfile: g.config.keyfile.as_ref().map(|p| p.display().to_string()),
            yubikey: g.config.yubikey.clone(),
            quick_unlock: g.vault.is_none() && g.quick.as_ref().is_some_and(|q| q.usable()),
        }
    }

    pub(crate) async fn unlock(
        self: &Arc<Self>,
        path: Option<String>,
        password: Option<Secret>,
        keyfile: Option<String>,
        yubikey: Option<String>,
    ) -> Reply<Response> {
        if self.is_unlocked() {
            return Ok(Response::Ok);
        }
        let config = self.config();
        let path = match path.map(PathBuf::from).or(config.database.clone()) {
            Some(p) => crate::config::expand(&p),
            None => {
                return Err(Response::error(
                    ErrorCode::Invalid,
                    tr!("не указан путь к базе (kw unlock --db ПУТЬ)"),
                ));
            }
        };
        // файл-ключ из конфига подходит только к базе из конфига
        let keyfile = keyfile.map(PathBuf::from).or_else(|| {
            (config.database.as_deref() == Some(&path))
                .then(|| config.keyfile.clone())
                .flatten()
        });
        // YubiKey из конфига тоже только для базы из конфига
        let yubikey = yubikey.filter(|y| !y.is_empty()).or_else(|| {
            (config.database.as_deref() == Some(&path))
                .then(|| config.yubikey.clone())
                .flatten()
        });
        let challenge = yubikey
            .as_deref()
            .map(Challenge::parse_yubikey)
            .transpose()
            .map_err(|e| Response::error(ErrorCode::Invalid, e))?;
        let quick = keywarden_core::quick::QuickCreds {
            path: path.display().to_string(),
            password: password.clone(),
            keyfile: keyfile.as_ref().map(|k| k.display().to_string()),
            yubikey: yubikey.clone(),
        };
        let creds = Credentials {
            password,
            keyfile: keyfile.clone(),
            challenge,
        };
        let p = path.clone();
        let vault = blocking(move || Vault::open(p, &creds)).await?;
        self.install(vault, path, keyfile);
        self.arm_quick(&quick);
        Ok(Response::Ok)
    }

    fn install(&self, mut vault: Vault, path: PathBuf, keyfile: Option<PathBuf>) {
        let mut g = self.inner();
        if let Some(dir) = &g.config.backups_dir {
            vault.backups.dir = dir.join(vault.backups.dir.file_name().unwrap_or_default());
        }
        vault.backups.keep = g.config.backups_keep;
        g.vault = Some(vault);
        g.epoch += 1;
        g.last_activity = Instant::now();
        let gen_now = g.generation;
        self.saved.send_modify(|s| {
            *s = SaveState {
                saved: gen_now,
                failed: None,
            }
        });
        if g.config.database.is_none() {
            g.config.database = Some(path);
            g.config.keyfile = keyfile;
            if let Err(e) = g.config.save_to(&self.config_path) {
                tracing::warn!("не удалось сохранить конфиг: {e}");
            }
        }
        drop(g);
        tracing::info!("база разблокирована");
        self.emit(Event::Unlocked);
    }

    /// Блокировка: дождаться записи правок, затем выбросить ключ и базу из памяти (zeroize).
    pub async fn lock(&self, reason: &str) {
        if !self.is_unlocked() {
            return;
        }
        let target = self.inner().generation;
        if self
            .wait_saved(target, Duration::from_secs(60))
            .await
            .is_err()
        {
            // запись не удалась (конфликт, диск): не теряем правки, кладём копию рядом с бэкапами
            if let Some(v) = &self.inner().vault {
                match v.write_recovery() {
                    Ok(p) => tracing::warn!("несохранённые правки записаны в {}", p.display()),
                    Err(e) => tracing::error!("не удалось записать несохранённые правки: {e}"),
                }
            }
        }
        let vault = {
            let mut g = self.inner();
            let gen_now = g.generation;
            self.saved.send_modify(|s| {
                *s = SaveState {
                    saved: gen_now,
                    failed: None,
                }
            });
            // подтверждение для кошельков живёт не дольше разблокировки
            g.elevated_until = None;
            g.sync.held = None;
            g.vault.take()
        };
        drop(vault);
        tracing::info!("база заблокирована: {reason}");
        self.emit(Event::Locked);
    }

    pub(crate) fn read<T>(&self, f: impl FnOnce(&Database) -> Reply<T>) -> Reply<T> {
        let g = self.inner();
        let v = g.vault.as_ref().ok_or_else(locked)?;
        f(&v.db)
    }

    pub(crate) fn touch_entry(&self, id: &str) {
        self.touch(id);
    }

    /// Отметка использования без сохранения на диск (уйдёт со следующей правкой), как в KeePassXC.
    fn touch(&self, id: &str) {
        if let Some(v) = self.inner().vault.as_mut() {
            model::touch(&mut v.db, id);
        }
    }

    pub(crate) async fn mutate<T>(
        &self,
        f: impl FnOnce(&mut Database) -> model::Result<T>,
    ) -> Reply<T> {
        let (out, generation) = {
            let mut g = self.inner();
            let v = g.vault.as_mut().ok_or_else(locked)?;
            let out = f(&mut v.db).map_err(model_err)?;
            g.generation += 1;
            (out, g.generation)
        };
        self.emit(Event::Changed);
        self.kick.notify_one();
        self.wait_saved(generation, Duration::from_secs(120))
            .await
            .map_err(|m| Response::error(ErrorCode::Conflict, m))?;
        Ok(out)
    }

    /// Правка «всё или ничего» (импорт, слияние): идёт на копии базы, подменяет её только при успехе,
    /// так что ошибка в середине файла не оставит полуимпортированную папку.
    pub(crate) async fn mutate_r<T>(&self, f: impl FnOnce(&mut Database) -> Reply<T>) -> Reply<T> {
        let (out, generation) = {
            let mut g = self.inner();
            let v = g.vault.as_mut().ok_or_else(locked)?;
            let mut tmp = v.db.clone();
            let out = f(&mut tmp)?;
            v.db = tmp;
            g.generation += 1;
            (out, g.generation)
        };
        self.emit(Event::Changed);
        self.kick.notify_one();
        self.wait_saved(generation, Duration::from_secs(120))
            .await
            .map_err(|m| Response::error(ErrorCode::Conflict, m))?;
        Ok(out)
    }

    async fn wait_saved(&self, generation: u64, timeout: Duration) -> Result<(), String> {
        self.kick.notify_one();
        let mut rx = self.saved.subscribe();
        let wait = async {
            loop {
                {
                    let s = rx.borrow_and_update();
                    if s.saved >= generation {
                        return Ok(());
                    }
                    if let Some((g, msg)) = &s.failed
                        && *g >= generation
                    {
                        return Err(tr!("правка в памяти, но не записана: {msg}", msg = msg));
                    }
                }
                if rx.changed().await.is_err() {
                    return Err(tr!("демон завершается").into());
                }
            }
        };
        tokio::time::timeout(timeout, wait)
            .await
            .unwrap_or_else(|_| Err(tr!("сохранение не успело за отведённое время").into()))
    }

    /// Фоновая запись: берёт снимок под мьютексом, пишет без него. Подряд идущие правки склеиваются.
    pub async fn saver(self: Arc<Self>) {
        loop {
            self.kick.notified().await;
            loop {
                let (job, generation, epoch) = {
                    let mut g = self.inner();
                    if g.generation <= self.saved.borrow().saved {
                        break;
                    }
                    let Some(v) = g.vault.as_mut() else { break };
                    // каждая запись получает новую ревизию: по ней видно подсунутую старую копию
                    keywarden_core::sync::bump_revision(&mut v.db);
                    let rev = keywarden_core::sync::revision(&v.db);
                    let job = v.save_job();
                    g.sync.seen_revision = g.sync.seen_revision.max(rev);
                    (job, g.generation, g.epoch)
                };
                let res = tokio::task::spawn_blocking(move || job.run()).await;
                match res {
                    Ok(Ok(hash)) => {
                        let mut g = self.inner();
                        if g.epoch == epoch
                            && let Some(v) = g.vault.as_mut()
                        {
                            v.mark_saved(hash);
                        }
                        drop(g);
                        self.saved.send_modify(|s| {
                            s.saved = s.saved.max(generation);
                            s.failed = None;
                        });
                        tracing::info!("база сохранена");
                        self.emit(Event::Saved);
                    }
                    Ok(Err(VaultError::ChangedOnDisk)) => {
                        // файл изменили снаружи (Syncthing): сливаем и пишем снова; ожидающие
                        // правки дождутся этой записи, а не получат ошибку
                        tracing::info!("файл базы изменился снаружи, сливаю перед записью");
                        let d = self.clone();
                        tokio::spawn(async move {
                            match d.sync_from_disk().await {
                                Err(e) => d.fail_pending(e),
                                // на диске версия, которая ждёт решения: поверх неё не пишем
                                Ok(_) if d.sync_held() => d.fail_pending(
                                    tr!("синхронизация ждёт решения: Настройки, вкладка «Синхронизация»")
                                        .into(),
                                ),
                                Ok(_) => {}
                            }
                        });
                        break;
                    }
                    other => {
                        let msg = match other {
                            Ok(Err(e)) => e.to_string(),
                            Err(e) => tr!("задача сохранения упала: {e}", e = e),
                            Ok(Ok(_)) => unreachable!(),
                        };
                        tracing::error!("сохранение не удалось: {msg}");
                        self.saved
                            .send_modify(|s| s.failed = Some((generation, msg.clone())));
                        self.emit(Event::SaveFailed { message: msg });
                        break;
                    }
                }
            }
        }
    }

    /// Доступ к открытой базе (и номеру разблокировки) под мьютексом.
    pub fn with_vault<R>(&self, f: impl FnOnce(&Vault, u64) -> R) -> Option<R> {
        let g = self.inner();
        let epoch = g.epoch;
        g.vault.as_ref().map(|v| f(v, epoch))
    }

    /// Изменить открытую базу, только если это всё ещё та же разблокировка.
    pub fn with_vault_mut<R>(&self, epoch: u64, f: impl FnOnce(&mut Vault) -> R) -> Option<R> {
        let mut g = self.inner();
        if g.epoch != epoch {
            return None;
        }
        g.vault.as_mut().map(f)
    }

    /// Пометить базу изменённой (после слияния) и дождаться записи.
    pub async fn bump_and_wait_saved(&self) -> Result<(), String> {
        let generation = {
            let mut g = self.inner();
            g.generation += 1;
            g.generation
        };
        self.kick.notify_one();
        self.wait_saved(generation, Duration::from_secs(120)).await
    }

    /// Ожидающие правки получают ошибку (слияние не удалось).
    pub fn fail_pending(&self, msg: String) {
        let generation = self.inner().generation;
        tracing::error!("сохранение не удалось: {msg}");
        self.saved
            .send_modify(|s| s.failed = Some((generation, msg.clone())));
        self.emit(Event::SaveFailed { message: msg });
    }

    pub(crate) async fn to_clipboard(&self, value: Secret) -> Reply<()> {
        let secs = self.config().clipboard_clear_seconds;
        blocking(move || clipboard::copy(&value, Duration::from_secs(secs)))
            .await
            .map_err(|e| {
                Response::error(
                    ErrorCode::Internal,
                    tr!("буфер обмена: {e}", e = e.message()),
                )
            })
    }
}

fn ok(_: ()) -> Response {
    Response::Ok
}

pub(crate) fn vault_err(e: VaultError) -> Response {
    DaemonErr::from(e).0
}

pub(crate) fn locked() -> Response {
    Response::error(ErrorCode::Locked, tr!("база заблокирована"))
}

pub(crate) fn model_err(e: ModelError) -> Response {
    let code = match e {
        ModelError::EntryNotFound
        | ModelError::GroupNotFound
        | ModelError::AttachmentNotFound(_) => ErrorCode::NotFound,
        ModelError::BadId(_) => ErrorCode::Invalid,
    };
    Response::error(code, e.to_string())
}

/// `TOTP` можно не держать в мьютексе: считаем код и отпускаем.
struct CodeOut(keywarden_core::totp::Code);

fn totp_code(db: &Database, id: &str) -> Reply<CodeOut> {
    let e = db
        .entry(model::parse_entry_id(id).map_err(model_err)?)
        .ok_or_else(|| model_err(ModelError::EntryNotFound))?;
    let t =
        Totp::from_entry(&e).map_err(|e| Response::error(ErrorCode::NotFound, e.to_string()))?;
    Ok(CodeOut(t.now()))
}

/// Поле фразы, passphrase или ключа у записи-кошелька: только после повторного подтверждения.
pub(crate) fn wallet_guarded(db: &Database, id: &str, field: &str) -> bool {
    let name = match field {
        "password" => "Password",
        other => other,
    };
    keywarden_core::wallet::is_guarded(name)
        && model::parse_entry_id(id)
            .ok()
            .and_then(|e| db.entry(e))
            .is_some_and(|e| model::kind_of(&e) == model::EntryKind::CryptoWallet)
}

pub(crate) fn copy_value(db: &Database, id: &str, field: &str) -> Reply<Secret> {
    let name = match field {
        "password" => "Password",
        "username" => "UserName",
        "url" => "URL",
        "notes" => "Notes",
        "totp" => return totp_code(db, id).map(|c| Secret::new(c.0.code)),
        other => other,
    };
    model::field_value(db, id, name)
        .map_err(model_err)?
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            Response::error(
                ErrorCode::NotFound,
                tr!("поле «{name}» пустое", name = name),
            )
        })
}

trait ErrText {
    fn message(&self) -> String;
}

impl ErrText for Response {
    fn message(&self) -> String {
        match self {
            Response::Error { message, .. } => message.clone(),
            _ => String::new(),
        }
    }
}

/// Блокирующая работа (Argon2, буфер обмена) вне рантайма; ошибки превращаются в ответ клиенту.
pub(crate) async fn blocking<T, E>(f: impl FnOnce() -> Result<T, E> + Send + 'static) -> Reply<T>
where
    T: Send + 'static,
    E: Into<DaemonErr> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || f().map_err(Into::into)).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(DaemonErr(r))) => Err(r),
        Err(e) => Err(Response::error(ErrorCode::Internal, e.to_string())),
    }
}

pub struct DaemonErr(Response);

impl From<VaultError> for DaemonErr {
    fn from(e: VaultError) -> Self {
        let code = match e {
            VaultError::WrongKey | VaultError::EmptyKey | VaultError::YubiKey(_) => {
                ErrorCode::WrongKey
            }
            VaultError::ChangedOnDisk => ErrorCode::Conflict,
            VaultError::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound => {
                ErrorCode::NotFound
            }
            _ => ErrorCode::Internal,
        };
        DaemonErr(Response::error(code, e.to_string()))
    }
}

impl From<String> for DaemonErr {
    fn from(e: String) -> Self {
        DaemonErr(Response::error(ErrorCode::Internal, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keywarden_core::model::{EntryPatch, FieldSet};
    use keywarden_core::vault::{Cipher, test_kdf};

    async fn unlocked(dir: &std::path::Path) -> Arc<Daemon> {
        let db = dir.join("t.kdbx");
        Vault::create(
            &db,
            &Credentials {
                password: Some("pw".into()),
                keyfile: None,
                challenge: None,
            },
            Cipher::ChaCha20,
            test_kdf(),
        )
        .unwrap();
        let cfg = Config {
            backups_dir: Some(dir.join("bak")),
            ..Config::default()
        };
        let d = Daemon::new(cfg, dir.join("config.toml"));
        tokio::spawn(d.clone().saver());
        let r = d
            .handle(Request::Unlock {
                path: Some(db.display().to_string()),
                password: Some("pw".into()),
                keyfile: None,
                yubikey: None,
            })
            .await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        d
    }

    #[tokio::test]
    async fn add_is_on_disk_when_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let patch = EntryPatch {
            set: vec![
                FieldSet::new("Title", "Mail"),
                FieldSet::new("Password", "pw1"),
            ],
            ..Default::default()
        };
        let Response::Created { id } = d.handle(Request::Add { patch }).await else {
            panic!()
        };
        // в момент ответа запись уже на диске
        let v = Vault::open(
            dir.path().join("t.kdbx"),
            &Credentials {
                password: Some("pw".into()),
                keyfile: None,
                challenge: None,
            },
        )
        .unwrap();
        assert_eq!(
            model::field_value(&v.db, &id, "Password")
                .unwrap()
                .unwrap()
                .expose(),
            "pw1"
        );
        // конфиг запомнил базу
        assert!(
            std::fs::read_to_string(dir.path().join("config.toml"))
                .unwrap()
                .contains("t.kdbx")
        );
    }

    #[tokio::test]
    async fn pin_unlocks_and_burns_after_three_misses() {
        use keywarden_core::ipc::KeySpec;
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let key = |pw: &str| KeySpec {
            password: Some(pw.into()),
            ..Default::default()
        };
        let r = d
            .handle(Request::SetPin {
                pin: Some("2468".into()),
                key: Some(key("wrong")),
            })
            .await;
        assert!(matches!(r, Response::Error { .. }), "{r:?}");
        let r = d
            .handle(Request::SetPin {
                pin: Some("2468".into()),
                key: Some(key("pw")),
            })
            .await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        d.handle(Request::Lock).await;
        assert!(d.status().quick_unlock);
        let r = d.handle(Request::QuickUnlock { pin: "2468".into() }).await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        assert!(d.is_unlocked());

        d.handle(Request::Lock).await;
        for _ in 0..3 {
            let r = d.handle(Request::QuickUnlock { pin: "0000".into() }).await;
            assert!(matches!(
                r,
                Response::Error {
                    code: ErrorCode::WrongKey,
                    ..
                }
            ));
        }
        // после трёх ошибок даже верный PIN не работает
        assert!(!d.status().quick_unlock);
        let r = d.handle(Request::QuickUnlock { pin: "2468".into() }).await;
        assert!(matches!(r, Response::Error { .. }));
        assert!(!d.is_unlocked());
        // а полный пароль снова взводит PIN
        d.handle(Request::Unlock {
            path: None,
            password: Some("pw".into()),
            keyfile: None,
            yubikey: None,
        })
        .await;
        d.handle(Request::Lock).await;
        assert!(d.status().quick_unlock);
    }

    #[tokio::test]
    async fn wallet_secrets_need_elevation() {
        use keywarden_core::ipc::KeySpec;
        use keywarden_core::model::{EntryKind, EntryPatch, FieldSet};
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let Response::Created { id } = d
            .handle(Request::Add {
                patch: EntryPatch {
                    kind: Some(EntryKind::CryptoWallet),
                    set: vec![
                        FieldSet::new("Title", "Кошелёк"),
                        FieldSet::new("Seed", seed),
                        FieldSet::new("Addresses", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
                    ],
                    ..Default::default()
                },
            })
            .await
        else {
            panic!()
        };
        let seed_of = |r: Response| match r {
            Response::Entry { entry } => entry
                .fields
                .iter()
                .find(|f| f.name == "Seed")
                .and_then(|f| f.value.as_ref().map(|v| v.expose().to_string())),
            r => panic!("{r:?}"),
        };
        // без подтверждения: фраза не отдаётся, не копируется и не меняется
        let r = d
            .handle(Request::Get {
                id: id.clone(),
                reveal: true,
            })
            .await;
        assert_eq!(seed_of(r), None);
        let needs = |r: &Response| {
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::NeedsAuth,
                    ..
                }
            )
        };
        let r = d
            .handle(Request::Copy {
                id: id.clone(),
                field: "Seed".into(),
            })
            .await;
        assert!(needs(&r), "{r:?}");
        let r = d
            .handle(Request::Update {
                id: id.clone(),
                patch: EntryPatch {
                    set: vec![FieldSet::new("Seed", "x")],
                    ..Default::default()
                },
            })
            .await;
        assert!(needs(&r), "{r:?}");
        // адреса и название можно менять без подтверждения
        let r = d
            .handle(Request::Update {
                id: id.clone(),
                patch: EntryPatch {
                    set: vec![FieldSet::new("Title", "Основной")],
                    ..Default::default()
                },
            })
            .await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        // неверный мастер-пароль не открывает, верный открывает
        let key = |pw: &str| KeySpec {
            password: Some(pw.into()),
            ..Default::default()
        };
        let r = d
            .handle(Request::Elevate {
                pin: None,
                key: Some(key("nope")),
            })
            .await;
        assert!(matches!(
            r,
            Response::Error {
                code: ErrorCode::WrongKey,
                ..
            }
        ));
        let r = d
            .handle(Request::Elevate {
                pin: None,
                key: Some(key("pw")),
            })
            .await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        let r = d
            .handle(Request::Get {
                id: id.clone(),
                reveal: true,
            })
            .await;
        assert_eq!(seed_of(r).as_deref(), Some(seed));
        // блокировка сбрасывает подтверждение
        d.handle(Request::Lock).await;
        d.handle(Request::Unlock {
            path: None,
            password: Some("pw".into()),
            keyfile: None,
            yubikey: None,
        })
        .await;
        let r = d.handle(Request::Get { id, reveal: true }).await;
        assert_eq!(seed_of(r), None);
    }

    #[tokio::test]
    async fn restore_backup_brings_back_old_state() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        async fn groups(d: &Arc<Daemon>) -> usize {
            match d.handle(Request::Groups).await {
                Response::Groups { groups } => groups.len(),
                r => panic!("{r:?}"),
            }
        }
        let before = groups(&d).await;
        d.handle(Request::AddGroup {
            parent: None,
            name: "Временная".into(),
        })
        .await;
        assert_eq!(groups(&d).await, before + 1);
        let Response::Backups { backups } = d.handle(Request::Backups).await else {
            panic!()
        };
        // копия сделана перед записью группы: в ней группы ещё нет
        let oldest = backups.last().unwrap();
        assert_eq!(oldest.kind, "backup");
        let r = d
            .handle(Request::RestoreBackup {
                name: oldest.name.clone(),
            })
            .await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        assert_eq!(groups(&d).await, before);
        let r = d
            .handle(Request::RestoreBackup {
                name: "../t.kdbx".into(),
            })
            .await;
        assert!(matches!(r, Response::Error { .. }));
    }

    #[tokio::test]
    async fn lock_clears_and_requires_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        d.handle(Request::Lock).await;
        let r = d
            .handle(Request::Search {
                query: String::new(),
                limit: 10,
                filter: Default::default(),
            })
            .await;
        assert!(matches!(
            r,
            Response::Error {
                code: ErrorCode::Locked,
                ..
            }
        ));
        let r = d
            .handle(Request::Unlock {
                path: None,
                password: Some("wrong".into()),
                keyfile: None,
                yubikey: None,
            })
            .await;
        assert!(
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::WrongKey,
                    ..
                }
            ),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn external_change_is_merged_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        // Syncthing принёс версию с другого устройства
        let creds = Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: None,
        };
        let mut other = Vault::open(dir.path().join("t.kdbx"), &creds).unwrap();
        other.backups.dir = dir.path().join("bak2");
        model::create_entry(
            &mut other.db,
            &EntryPatch {
                set: vec![model::FieldSet::new("Title", "С телефона")],
                ..Default::default()
            },
        )
        .unwrap();
        other.save().unwrap();

        // локальная правка: запись видит изменённый файл, сливает и всё равно сохраняется
        let r = d
            .handle(Request::Add {
                patch: EntryPatch {
                    set: vec![model::FieldSet::new("Title", "С ноутбука")],
                    ..Default::default()
                },
            })
            .await;
        assert!(matches!(r, Response::Created { .. }), "{r:?}");
        let v = Vault::open(dir.path().join("t.kdbx"), &creds).unwrap();
        let titles: Vec<String> = keywarden_core::search::search(&v.db, "", 10)
            .into_iter()
            .map(|e| e.title)
            .collect();
        assert!(
            titles.contains(&"С телефона".to_string())
                && titles.contains(&"С ноутбука".to_string()),
            "{titles:?}"
        );
    }

    #[tokio::test]
    async fn syncthing_conflict_copy_is_merged_and_archived() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let creds = Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: None,
        };
        let mut other = Vault::open(dir.path().join("t.kdbx"), &creds).unwrap();
        model::create_entry(
            &mut other.db,
            &EntryPatch {
                set: vec![model::FieldSet::new("Title", "Из конфликта")],
                ..Default::default()
            },
        )
        .unwrap();
        other.backups.dir = dir.path().join("bak2");
        // конфликтная копия рядом с базой, сама база не менялась
        let conflict = dir
            .path()
            .join("t.sync-conflict-20260101-120000-ABCDEF.kdbx");
        let bytes = std::fs::read(dir.path().join("t.kdbx")).unwrap();
        other.save().unwrap();
        std::fs::rename(dir.path().join("t.kdbx"), &conflict).unwrap();
        std::fs::write(dir.path().join("t.kdbx"), bytes).unwrap();

        let msg = d.sync_from_disk().await.unwrap().unwrap();
        assert!(msg.contains("конфликтных копий: 1"), "{msg}");
        assert!(!conflict.exists(), "копия убрана из папки синхронизации");
        assert!(
            walk(&dir.path().join("bak"))
                .iter()
                .any(|p| p.to_string_lossy().contains("sync-conflict")),
            "и лежит в бэкапах"
        );
        let v = Vault::open(dir.path().join("t.kdbx"), &creds).unwrap();
        assert_eq!(
            keywarden_core::search::search(&v.db, "конфликт", 10).len(),
            1
        );
    }

    fn creds() -> Credentials {
        Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: None,
        }
    }

    async fn add_titles(d: &Arc<Daemon>, n: usize) -> Vec<String> {
        let mut ids = vec![];
        for i in 0..n {
            let Response::Created { id } = d
                .handle(Request::Add {
                    patch: EntryPatch {
                        set: vec![FieldSet::new("Title", format!("запись {i}"))],
                        ..Default::default()
                    },
                })
                .await
            else {
                panic!("не создалось")
            };
            ids.push(id);
        }
        ids
    }

    fn live_count(path: &std::path::Path) -> usize {
        let v = Vault::open(path, &creds()).unwrap();
        v.db.iter_all_entries()
            .filter(|e| !model::in_recycle_bin(&v.db, e.parent().id()))
            .count()
    }

    #[tokio::test]
    async fn mass_deletion_from_disk_waits_and_can_be_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let ids = add_titles(&d, 10).await;
        // другое устройство удалило 6 записей из 10
        let path = dir.path().join("t.kdbx");
        let mut other = Vault::open(&path, &creds()).unwrap();
        other.backups.dir = dir.path().join("bak2");
        for id in &ids[..6] {
            model::delete_entry(&mut other.db, id).unwrap();
            model::delete_entry(&mut other.db, id).unwrap();
        }
        other.save().unwrap();

        let msg = d.sync_from_disk().await.unwrap().unwrap();
        assert!(msg.contains("на паузе"), "{msg}");
        assert!(d.sync_held());
        let Response::SyncJournal { held: Some(h), .. } = d.handle(Request::SyncJournal).await
        else {
            panic!("нет паузы")
        };
        assert_eq!((h.removed, h.live), (6, 10));
        // повторная проверка того же файла не плодит паузы и уведомления
        assert!(d.sync_from_disk().await.unwrap().is_none());
        // пока решения нет, поверх этой версии не пишем
        let r = d
            .handle(Request::Add {
                patch: EntryPatch {
                    set: vec![FieldSet::new("Title", "во время паузы")],
                    ..Default::default()
                },
            })
            .await;
        assert!(format!("{r:?}").contains("ждёт решения"), "{r:?}");

        let r = d.handle(Request::SyncDecide { accept: false }).await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        assert!(!d.sync_held());
        assert_eq!(
            live_count(&path),
            11,
            "10 записей и правка из паузы на диске"
        );
        let Response::SyncJournal { records, .. } = d.handle(Request::SyncJournal).await else {
            panic!()
        };
        assert_eq!(records[0].status, "rejected");
    }

    #[tokio::test]
    async fn merge_from_disk_is_journaled_and_revertible() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        add_titles(&d, 2).await;
        let path = dir.path().join("t.kdbx");
        let mut other = Vault::open(&path, &creds()).unwrap();
        other.backups.dir = dir.path().join("bak2");
        model::create_entry(
            &mut other.db,
            &EntryPatch {
                set: vec![FieldSet::new("Title", "С телефона")],
                ..Default::default()
            },
        )
        .unwrap();
        other.save().unwrap();

        d.sync_from_disk().await.unwrap().unwrap();
        assert_eq!(live_count(&path), 3);
        let Response::SyncJournal { records, held, .. } = d.handle(Request::SyncJournal).await
        else {
            panic!()
        };
        assert!(held.is_none());
        let rec = &records[0];
        assert_eq!(rec.status, "applied");
        assert!(rec.snapshot.is_some(), "снимок для отмены записан: {rec:?}");

        let r = d.handle(Request::SyncRevert { id: rec.id }).await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        assert_eq!(live_count(&path), 2, "пришедшая запись ушла в корзину");
        let Response::SyncJournal { records, .. } = d.handle(Request::SyncJournal).await else {
            panic!()
        };
        assert!(
            records
                .iter()
                .any(|r| r.id == rec.id && r.status == "reverted")
        );
        let again = d.handle(Request::SyncRevert { id: rec.id }).await;
        assert!(format!("{again:?}").contains("уже отменено"));
    }

    #[tokio::test]
    async fn database_moves_into_sync_folder() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        add_titles(&d, 2).await;
        let st = dir.path().join("Sync");
        std::fs::create_dir_all(st.join(".stfolder")).unwrap();
        let Response::SyncJournal { folder, .. } = d.handle(Request::SyncJournal).await else {
            panic!()
        };
        assert!(folder.is_none(), "пока база не в папке синхронизации");

        let r = d
            .handle(Request::MoveDatabase {
                dir: st.display().to_string(),
            })
            .await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        assert!(
            !dir.path().join("t.kdbx").exists(),
            "старый файл убран к копиям"
        );
        assert_eq!(live_count(&st.join("t.kdbx")), 2);
        let Response::SyncJournal {
            folder, db_path, ..
        } = d.handle(Request::SyncJournal).await
        else {
            panic!()
        };
        assert_eq!(folder.unwrap().kind, "syncthing");
        assert!(std::path::Path::new(&db_path.unwrap()).ends_with("Sync/t.kdbx"));
        // дальше база пишется уже в новое место
        add_titles(&d, 1).await;
        assert_eq!(live_count(&st.join("t.kdbx")), 3);
        // в папку, где уже есть такой файл, не переносим
        let back = d
            .handle(Request::MoveDatabase {
                dir: dir.path().display().to_string(),
            })
            .await;
        assert!(matches!(back, Response::Ok), "назад можно: {back:?}");
        std::fs::write(st.join("t.kdbx"), b"x").unwrap();
        let clash = d
            .handle(Request::MoveDatabase {
                dir: st.display().to_string(),
            })
            .await;
        assert!(format!("{clash:?}").contains("уже есть файл"), "{clash:?}");
    }

    #[test]
    fn sync_folders_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("a/b/t.kdbx");
        std::fs::create_dir_all(db.parent().unwrap()).unwrap();
        assert!(crate::sync::detect_folder(&db).is_none());
        std::fs::write(dir.path().join("a/.dropbox"), b"").unwrap();
        let f = crate::sync::detect_folder(&db).unwrap();
        assert_eq!(
            (
                f.kind.as_str(),
                std::path::Path::new(&f.root).ends_with("a")
            ),
            ("dropbox", true)
        );
        std::fs::create_dir(dir.path().join("a/b/.stfolder")).unwrap();
        assert_eq!(crate::sync::detect_folder(&db).unwrap().kind, "syncthing");
    }

    #[tokio::test]
    async fn nextcloud_and_dropbox_conflicts_are_found() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let reader = d.with_vault(|v, _| v.reader()).unwrap();
        for n in [
            "t.sync-conflict-20260101-120000-ABC.kdbx",
            "t (conflicted copy 2026-01-01 120000).kdbx",
            "t (Alice's conflicted copy 2026-01-01).kdbx",
            "t (2).kdbx",
            "tt.sync-conflict-1.kdbx",
        ] {
            std::fs::write(dir.path().join(n), b"x").unwrap();
        }
        let found: Vec<String> = reader
            .conflict_files()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(found.len(), 3, "{found:?}");
        assert!(
            !found
                .iter()
                .any(|f| f == "t (2).kdbx" || f.starts_with("tt"))
        );
    }

    #[tokio::test]
    async fn unchanged_disk_is_not_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let before = std::fs::read(dir.path().join("t.kdbx")).unwrap();
        // файл «изменился» (новые байты), но содержимое то же: пересохранять нельзя
        let creds = Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: None,
        };
        let mut other = Vault::open(dir.path().join("t.kdbx"), &creds).unwrap();
        other.backups.dir = dir.path().join("bak2");
        other.save().unwrap();
        let rewritten = std::fs::read(dir.path().join("t.kdbx")).unwrap();
        assert_ne!(before, rewritten);
        d.sync_from_disk().await.unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("t.kdbx")).unwrap(),
            rewritten,
            "демон не пересохранил файл без нужды"
        );
    }

    fn walk(p: &std::path::Path) -> Vec<PathBuf> {
        let mut out = vec![];
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            let path = e.path();
            if path.is_dir() {
                out.extend(walk(&path));
            } else {
                out.push(path);
            }
        }
        out
    }

    #[tokio::test]
    async fn change_key_requires_current_and_survives_relock() {
        use keywarden_core::ipc::KeySpec;
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let db = dir.path().join("t.kdbx").display().to_string();
        let spec = |p: &str| KeySpec {
            password: Some(p.into()),
            ..Default::default()
        };
        let r = d
            .handle(Request::ChangeKey {
                current: spec("не тот"),
                new: spec("new"),
            })
            .await;
        assert!(
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::WrongKey,
                    ..
                }
            ),
            "{r:?}"
        );
        let r = d
            .handle(Request::ChangeKey {
                current: spec("pw"),
                new: KeySpec::default(),
            })
            .await;
        assert!(
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::Invalid,
                    ..
                }
            ),
            "{r:?}"
        );
        let r = d
            .handle(Request::ChangeKey {
                current: spec("pw"),
                new: spec("new"),
            })
            .await;
        assert!(matches!(r, Response::Ok), "{r:?}");
        d.lock("тест").await;
        let unlock = |p: &str| Request::Unlock {
            path: Some(db.clone()),
            password: Some(p.into()),
            keyfile: None,
            yubikey: None,
        };
        assert!(matches!(
            d.handle(unlock("pw")).await,
            Response::Error { .. }
        ));
        assert!(matches!(d.handle(unlock("new")).await, Response::Ok));
    }

    #[tokio::test]
    async fn failed_import_changes_nothing() {
        use keywarden_core::ipc::ImportFormat;
        let dir = tempfile::tempdir().unwrap();
        let d = unlocked(dir.path()).await;
        let bad = dir.path().join("bad.csv");
        // вторая строка ломает CSV (незакрытая кавычка): первая не должна остаться в базе
        std::fs::write(
            &bad,
            "name,url,username,password\nA,https://a,u,p\n\"B,https://b,u,p\n",
        )
        .unwrap();
        let groups_before = d.read(|db| Ok(db.num_groups())).unwrap();
        let r = d
            .handle(Request::ImportFile {
                path: bad.display().to_string(),
                format: ImportFormat::Csv,
                key: None,
            })
            .await;
        if let Response::Imported { .. } = r {
            // csv-крейт может принять незакрытую кавычку как поле до конца файла: тогда это не ошибка
        } else {
            assert!(matches!(r, Response::Error { .. }), "{r:?}");
            assert_eq!(d.read(|db| Ok(db.num_entries())).unwrap(), 0);
            assert_eq!(d.read(|db| Ok(db.num_groups())).unwrap(), groups_before);
        }
        let good = dir.path().join("good.csv");
        std::fs::write(&good, "name,url,username,password\nA,https://a,u,p\n").unwrap();
        let r = d
            .handle(Request::ImportFile {
                path: good.display().to_string(),
                format: ImportFormat::Csv,
                key: None,
            })
            .await;
        assert!(matches!(r, Response::Imported { .. }), "{r:?}");
        let entries = d.read(|db| Ok(db.num_entries())).unwrap();
        assert!(entries >= 1);
        let unknown = dir.path().join("x.csv");
        std::fs::write(&unknown, "a,b\n1,2\n").unwrap();
        let before = d.read(|db| Ok(db.num_groups())).unwrap();
        let r = d
            .handle(Request::ImportFile {
                path: unknown.display().to_string(),
                format: ImportFormat::Csv,
                key: None,
            })
            .await;
        assert!(matches!(r, Response::Error { .. }), "{r:?}");
        assert_eq!(
            d.read(|db| Ok(db.num_groups())).unwrap(),
            before,
            "папка импорта не осталась после ошибки"
        );
    }
}
