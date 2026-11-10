//! Локальный API для ассистентов и скриптов: отдельный сокет `$XDG_RUNTIME_DIR/keywarden/api.sock`.
//!
//! Нарочно узкий: значения секретов через этот сокет не выдаются никак.
//! - `list(query)`: названия, типы и id;
//! - `secret_copy(id)`: основной секрет записи в буфер (с автоочисткой), ответ только ok/ошибка;
//! - `save_from_clipboard(title, type)`: новая запись из содержимого буфера.
//!
//! Протокол: одна строка JSON на запрос, одна на ответ. Подробно: docs/local-api.md.

use crate::state::Daemon;
use keywarden_core::ipc::{ErrorCode, Request, Response};
use keywarden_core::model::{EntryKind, EntryPatch, FieldSet};
use keywarden_core::secret::Secret;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Debug, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum ApiRequest {
    List {
        #[serde(default)]
        query: String,
    },
    SecretCopy {
        id: String,
    },
    SaveFromClipboard {
        title: String,
        #[serde(rename = "type", default = "default_kind")]
        kind: EntryKind,
    },
}

fn default_kind() -> EntryKind {
    EntryKind::Login
}

#[derive(Debug, Serialize, PartialEq)]
pub struct Item {
    pub id: String,
    pub title: String,
    #[serde(rename = "type")]
    pub kind: EntryKind,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ApiReply {
    Items { ok: bool, items: Vec<Item> },
    Created { ok: bool, id: String },
    Ok { ok: bool },
    Error { ok: bool, error: String },
}

fn error(e: impl Into<String>) -> ApiReply {
    ApiReply::Error {
        ok: false,
        error: e.into(),
    }
}

/// Основной секрет записи по типу: его и копирует `secret_copy`, в него же пишет `save_from_clipboard`.
pub fn primary_field(kind: EntryKind) -> Option<&'static str> {
    match kind {
        EntryKind::Login | EntryKind::SshKey => Some("Password"),
        EntryKind::Card => Some("Card Number"),
        EntryKind::Note => Some("Notes"),
        EntryKind::Identity => Some("Passport Number"),
        EntryKind::Passkey | EntryKind::CryptoWallet | EntryKind::SshHost => None,
    }
}

pub fn socket_path() -> std::path::PathBuf {
    keywarden_core::ipc::endpoint("api")
}

pub async fn serve(daemon: Arc<Daemon>) {
    let path = socket_path();
    let listener = match crate::local::Listener::bind(&path) {
        Ok(l) => l,
        Err(e) => return tracing::error!("API: bind {}: {e}", path.display()),
    };
    while let Ok(stream) = listener.accept().await {
        tokio::spawn(connection(daemon.clone(), stream));
    }
}

async fn connection(daemon: Arc<Daemon>, stream: impl crate::local::Stream) {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut rd).take(64 * 1024).read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let reply = match serde_json::from_str::<ApiRequest>(&line) {
            Ok(req) => handle(&daemon, req).await,
            Err(e) => error(tr!("неверный запрос: {e}", e = e)),
        };
        let mut out = serde_json::to_string(&reply).expect("сериализуется");
        out.push('\n');
        if wr.write_all(out.as_bytes()).await.is_err() {
            return;
        }
    }
}

pub async fn handle(daemon: &Arc<Daemon>, req: ApiRequest) -> ApiReply {
    let err_of = |r: Response| match r {
        Response::Error {
            code: ErrorCode::Locked,
            ..
        } => error(tr!("база заблокирована")),
        Response::Error { message, .. } => error(message),
        _ => error(tr!("неожиданный ответ")),
    };
    match req {
        ApiRequest::List { query } => {
            match daemon
                .handle(Request::Search {
                    query,
                    limit: 100,
                    filter: Default::default(),
                })
                .await
            {
                Response::Entries { entries } => ApiReply::Items {
                    ok: true,
                    items: entries
                        .into_iter()
                        .map(|e| Item {
                            id: e.id,
                            title: e.title,
                            kind: e.kind,
                        })
                        .collect(),
                },
                other => err_of(other),
            }
        }
        ApiRequest::SecretCopy { id } => {
            let kind = match daemon
                .handle(Request::Get {
                    id: id.clone(),
                    reveal: false,
                })
                .await
            {
                Response::Entry { entry } => entry.summary.kind,
                other => return err_of(other),
            };
            let Some(field) = primary_field(kind) else {
                return error(tr!(
                    "у типа «{kind}» нет секрета для копирования",
                    kind = kind.label()
                ));
            };
            match daemon
                .handle(Request::Copy {
                    id,
                    field: field.into(),
                })
                .await
            {
                Response::Ok => ApiReply::Ok { ok: true },
                other => err_of(other),
            }
        }
        ApiRequest::SaveFromClipboard { title, kind } => {
            let Some(field) = primary_field(kind) else {
                return error(tr!("тип «{kind}» так не создаётся", kind = kind.label()));
            };
            let value = match tokio::task::spawn_blocking(read_clipboard).await {
                Ok(Ok(v)) if !v.is_empty() => v,
                Ok(Ok(_)) => return error(tr!("буфер обмена пуст")),
                Ok(Err(e)) => return error(e),
                Err(e) => return error(e.to_string()),
            };
            let patch = EntryPatch {
                kind: Some(kind),
                set: vec![
                    FieldSet::new("Title", title),
                    FieldSet {
                        name: field.into(),
                        value,
                        protected: None,
                    },
                ],
                ..Default::default()
            };
            match daemon.handle(Request::Add { patch }).await {
                Response::Created { id } => ApiReply::Created { ok: true, id },
                other => err_of(other),
            }
        }
    }
}

fn read_clipboard() -> Result<Secret, String> {
    match crate::clipboard::paste(false)? {
        crate::clipboard::Pasted::Text(t) => Ok(Secret::new(t.trim_end_matches('\n').to_string())),
        _ => Err(tr!("в буфере не текст").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use keywarden_core::vault::{Cipher, Credentials, Vault, test_kdf};

    #[tokio::test]
    async fn never_returns_secrets() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("a.kdbx");
        let creds = Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: None,
        };
        Vault::create(&db, &creds, Cipher::ChaCha20, test_kdf()).unwrap();
        let d = Daemon::new(
            Config {
                backups_dir: Some(dir.path().join("bak")),
                ..Config::default()
            },
            dir.path().join("c.toml"),
        );
        tokio::spawn(d.clone().saver());
        // заблокирована: ошибка без подробностей
        let r = handle(
            &d,
            ApiRequest::List {
                query: String::new(),
            },
        )
        .await;
        assert!(matches!(r, ApiReply::Error { ref error, .. } if error == "база заблокирована"));

        d.handle(Request::Unlock {
            path: Some(db.display().to_string()),
            password: Some("pw".into()),
            keyfile: None,
            yubikey: None,
        })
        .await;
        let patch = EntryPatch {
            set: vec![
                FieldSet::new("Title", "Почта"),
                FieldSet::new("Password", "top-secret-value"),
            ],
            ..Default::default()
        };
        let Response::Created { id } = d.handle(Request::Add { patch }).await else {
            panic!()
        };

        let r = handle(
            &d,
            ApiRequest::List {
                query: "почта".into(),
            },
        )
        .await;
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            json.contains("Почта") && json.contains(&id) && json.contains("\"type\":\"login\""),
            "{json}"
        );
        assert!(!json.contains("top-secret-value"));

        // копирование: без Wayland ошибка, но и в ней нет значения
        let r = serde_json::to_string(&handle(&d, ApiRequest::SecretCopy { id }).await).unwrap();
        assert!(!r.contains("top-secret-value"), "{r}");
        assert_eq!(primary_field(EntryKind::Passkey), None);
    }
}
