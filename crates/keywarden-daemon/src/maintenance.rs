//! Обслуживание базы: смена ключа, настройки, копия, экспорт, импорт, слияние с другой копией.
//! Всё долгое (Argon2, разбор файлов) идёт вне мьютекса; правки базы проходят обычным путём
//! с бэкапом, проверкой расшифровкой и атомарной записью.

use crate::state::{Daemon, Reply, blocking, locked, vault_err};
use keywarden_core::ipc::{ErrorCode, Event, ImportFormat, KeySpec, Response};
use keywarden_core::vault::{self, Challenge, Credentials};
use keywarden_core::{bitwarden, merge, settings, transfer};
use std::path::{Path, PathBuf};

fn invalid(m: impl Into<String>) -> Response {
    Response::error(ErrorCode::Invalid, m)
}

/// Пустые поля из интерфейса значат «не задано».
pub(crate) fn credentials(spec: KeySpec) -> Reply<Credentials> {
    let challenge = spec
        .yubikey
        .as_deref()
        .map(str::trim)
        .filter(|y| !y.is_empty())
        .map(Challenge::parse_yubikey)
        .transpose()
        .map_err(invalid)?;
    Ok(Credentials {
        password: spec.password.filter(|p| !p.expose().is_empty()),
        keyfile: spec
            .keyfile
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .map(|k| crate::config::expand(&PathBuf::from(k))),
        challenge,
    })
}

fn path_of(p: &str) -> PathBuf {
    crate::config::expand(&PathBuf::from(p.trim()))
}

fn stem(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl Daemon {
    pub(crate) async fn change_key(&self, current: KeySpec, new: KeySpec) -> Reply<Response> {
        let (path, epoch) = self
            .with_vault(|v, epoch| (v.path().to_path_buf(), epoch))
            .ok_or_else(locked)?;
        let cur = credentials(current)?;
        let p = path.clone();
        blocking(move || cur.verify(&p)).await.map_err(|e| {
            Response::error(
                ErrorCode::WrongKey,
                tr!("текущий ключ не подошёл: {e}", e = message(&e)),
            )
        })?;
        let yubikey = new.yubikey.clone().filter(|y| !y.trim().is_empty());
        let next = credentials(new)?;
        if next.password.is_none() && next.keyfile.is_none() {
            return Err(invalid(tr!("нужен новый пароль, файл-ключ или оба")));
        }
        if let Some(kf) = &next.keyfile
            && !kf.is_file()
        {
            return Err(Response::error(
                ErrorCode::NotFound,
                tr!("файл-ключ не найден: {path}", path = kf.display()),
            ));
        }
        let old = self
            .with_vault_mut(epoch, |v| v.replace_key(&next))
            .ok_or_else(locked)?
            .map_err(vault_err)?;
        if let Err(e) = self.bump_and_wait_saved().await {
            // на диске остался старый ключ: возвращаем его и в память
            self.with_vault_mut(epoch, |v| v.restore_key(old));
            return Err(Response::error(
                ErrorCode::Conflict,
                tr!(
                    "ключ не сменён, база по-прежнему открывается старым: {e}",
                    e = e
                ),
            ));
        }
        self.update_config(|c| {
            if c.database.as_deref() == Some(path.as_path()) {
                c.keyfile = next.keyfile.clone();
                c.yubikey = yubikey;
                true
            } else {
                false
            }
        });
        tracing::info!("ключ базы сменён");
        // PIN помнил старый ключ: до следующей полной разблокировки он не действует
        self.inner().quick = None;
        Ok(Response::Ok)
    }

    pub(crate) async fn generate_keyfile(&self, path: String) -> Reply<Response> {
        let p = path_of(&path);
        blocking(move || vault::generate_keyfile(&p).map_err(vault::VaultError::Io)).await?;
        Ok(Response::Ok)
    }

    pub(crate) fn get_settings(&self) -> Reply<Response> {
        Ok(Response::Settings {
            settings: self.read(|db| Ok(settings::get(db)))?,
        })
    }

    pub(crate) async fn set_settings(&self, s: settings::DbSettings) -> Reply<Response> {
        settings::validate(&s).map_err(invalid)?;
        self.mutate_r(move |db| settings::apply(db, &s).map_err(invalid))
            .await?;
        self.get_settings()
    }

    pub(crate) async fn tune_kdf(&self) -> Reply<Response> {
        let current = self.read(|db| Ok(settings::get(db)))?;
        let settings = blocking(move || Ok::<_, String>(settings::retuned(current))).await?;
        Ok(Response::Settings { settings })
    }

    pub(crate) async fn save_copy(&self, path: String, key: KeySpec) -> Reply<Response> {
        let creds = credentials(key)?;
        if creds.password.is_none() && creds.keyfile.is_none() {
            return Err(invalid(tr!("для копии нужен пароль, файл-ключ или оба")));
        }
        let db = self.read(|db| Ok(db.clone()))?;
        let p = path_of(&path);
        blocking(move || vault::save_copy_of(&db, &p, &creds)).await?;
        Ok(Response::Ok)
    }

    pub(crate) async fn export_csv(&self, path: String) -> Reply<Response> {
        // в CSV сид-фразы окажутся открытым текстом: только после повторного подтверждения
        let has_wallets = self.read(|db| {
            Ok(db.iter_all_entries().any(|e| {
                keywarden_core::model::kind_of(&e) == keywarden_core::model::EntryKind::CryptoWallet
            }))
        })?;
        if has_wallets {
            self.require_elevation()?;
        }
        let csv = self.read(|db| Ok(transfer::export_csv(db)))?;
        let p = path_of(&path);
        blocking(move || vault::write_atomic(&p, csv.as_bytes()).map_err(vault::VaultError::Io))
            .await?;
        tracing::info!("база выгружена в CSV");
        Ok(Response::Ok)
    }

    pub(crate) async fn import_file(
        &self,
        path: String,
        format: ImportFormat,
        key: Option<KeySpec>,
    ) -> Reply<Response> {
        let p = path_of(&path);
        let name = tr!("Импорт {name}", name = stem(&p));
        let report = match format {
            ImportFormat::Keepass => {
                let creds = credentials(key.unwrap_or_default())?;
                let src = blocking(move || vault::open_other(&p, &creds)).await?;
                self.mutate_r(move |db| {
                    transfer::import_database(db, &src, &name).map_err(|e| invalid(e.to_string()))
                })
                .await?
            }
            ImportFormat::Csv | ImportFormat::Bitwarden | ImportFormat::TwoFas => {
                let bytes =
                    blocking(move || std::fs::read(&p).map_err(vault::VaultError::Io)).await?;
                let text = String::from_utf8_lossy(&bytes).into_owned();
                self.mutate_r(move |db| match format {
                    ImportFormat::Csv => {
                        transfer::import_csv(db, &text, &name).map_err(|e| invalid(e.to_string()))
                    }
                    ImportFormat::TwoFas => keywarden_core::twofas::import(db, &text)
                        .map_err(|e| invalid(e.to_string())),
                    _ => bitwarden::import(db, &text).map_err(|e| invalid(e.to_string())),
                })
                .await?
            }
        };
        Ok(Response::Imported { report })
    }

    pub(crate) async fn merge_file(&self, path: String, key: KeySpec) -> Reply<Response> {
        let creds = credentials(key)?;
        let p = path_of(&path);
        let src = blocking(move || vault::open_other(&p, &creds)).await?;
        let summary = self
            .mutate_r(move |db| {
                merge::merge(db, &src)
                    .map(|r| r.summary())
                    .map_err(|e| invalid(e.to_string()))
            })
            .await?;
        self.emit_event(Event::Merged {
            message: tr!("Слияние: {summary}", summary = summary),
        });
        Ok(Response::Merged { summary })
    }
}

fn message(r: &Response) -> String {
    match r {
        Response::Error { message, .. } => message.clone(),
        _ => String::new(),
    }
}
