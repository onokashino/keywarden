//! Канал расширения браузера.
//!
//! - Ассоциация: открытый ключ расширения попадает в custom data базы только после подтверждения
//!   пользователем; там же ключ демона. Оба синхронизируются вместе с базой.
//! - Каждый запрос зашифрован crypto_box; повтор старого nonce отвергается.
//! - Пароль выдаётся только странице, адрес которой совпадает с записью (eTLD+1 по PSL), и только
//!   после разрешения сайта: «всегда» запоминается в записи (`keywarden.browser.allow`).

use crate::confirm::{self, Decision, Prompt};
use crate::state::{Daemon, Reply, model_err};
use keepass::Database;
use keepass::db::{CustomDataItem, CustomDataValue, EntryRef, Times, fields};
use keywarden_core::generator;
use keywarden_core::ipc::{ErrorCode, Response};
use keywarden_core::model::{self, EntryKind, EntryPatch, FieldSet, ModelError};
use keywarden_core::passkey;
use keywarden_core::totp::Totp;
use keywarden_ext::protocol::{
    self, BrowserReply, BrowserRequest, Folder, ItemView, Keypair, Login, Outer, OuterReply,
};
use keywarden_ext::urls::{site_of, url_matches};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Mutex;

const SERVER_KEY: &str = "keywarden.browser.server_key";
const CLIENT_PREFIX: &str = "keywarden.browser.client.";
pub const ALLOW_KEY: &str = "keywarden.browser.allow";
const BROWSER_GROUP: &str = "Из браузера";

/// Последние nonce: защита от повторной отправки перехваченного сообщения.
static SEEN: Mutex<(BTreeSet<String>, VecDeque<String>)> =
    Mutex::new((BTreeSet::new(), VecDeque::new()));

fn custom_str(db_item: Option<&CustomDataItem>) -> Option<String> {
    match db_item?.value.as_ref()? {
        CustomDataValue::String(s) => Some(s.clone()),
        CustomDataValue::Binary(_) => None,
    }
}

fn set_custom(
    map: &mut std::collections::HashMap<String, CustomDataItem>,
    key: &str,
    value: String,
) {
    map.insert(
        key.into(),
        CustomDataItem {
            value: Some(CustomDataValue::String(value)),
            last_modification_time: Some(Times::now()),
        },
    );
}

fn err(code: &str, message: impl Into<String>) -> OuterReply {
    OuterReply::Error {
        code: code.into(),
        message: message.into(),
    }
}

impl Daemon {
    pub async fn browser(&self, message: serde_json::Value) -> serde_json::Value {
        let reply = match serde_json::from_value::<Outer>(message) {
            Ok(Outer::Associate {
                client_id,
                client_public,
                name,
            }) => self.associate(client_id, client_public, name).await,
            Ok(Outer::Encrypted {
                client_id,
                nonce,
                message,
            }) => self.encrypted(client_id, nonce, message).await,
            Ok(Outer::OpenUnlock) => {
                if !self.is_unlocked()
                    && let Err(e) = std::process::Command::new(confirm::ui_binary())
                        .arg("--launcher")
                        .spawn()
                {
                    tracing::warn!("лаунчер не запустился: {e}");
                }
                OuterReply::Ok
            }
            Err(e) => err("invalid", tr!("неверное сообщение: {e}", e = e)),
        };
        serde_json::to_value(reply).expect("сериализуется")
    }

    async fn associate(
        &self,
        client_id: String,
        client_public: String,
        name: String,
    ) -> OuterReply {
        if client_id.is_empty()
            || client_id.len() > 64
            || !client_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return err("invalid", tr!("неверный client_id"));
        }
        if data_encoding::BASE64
            .decode(client_public.as_bytes())
            .map(|k| k.len())
            != Ok(32)
        {
            return err("invalid", tr!("неверный открытый ключ"));
        }
        if !self.is_unlocked() {
            return err("locked", tr!("база заблокирована"));
        }
        let name = name.chars().take(60).collect::<String>();
        let prompt = Prompt {
            title: tr!("Подключить расширение браузера?").into(),
            text: tr!(
                "«{name}» просит доступ к Keywarden. Разрешайте, только если вы сами только что нажали «Подключить» в расширении.",
                name = name
            ),
            allow_always: false,
            always_minutes: None,
        };
        if self.ask(prompt).await == Decision::Deny {
            return err("denied", tr!("пользователь отказал в подключении"));
        }
        let res = self
            .mutate(move |db| {
                let server = match custom_str(db.meta.custom_data.get(SERVER_KEY)) {
                    Some(s) => Keypair::from_secret_b64(&s).map_err(ModelError::BadId)?,
                    None => {
                        let kp = Keypair::generate();
                        set_custom(&mut db.meta.custom_data, SERVER_KEY, kp.secret_b64());
                        kp
                    }
                };
                set_custom(
                    &mut db.meta.custom_data,
                    &format!("{CLIENT_PREFIX}{client_id}"),
                    format!("{client_public}\t{name}"),
                );
                Ok(server.public_b64())
            })
            .await;
        match res {
            Ok(server_public) => OuterReply::Associated { server_public },
            Err(r) => err("internal", response_text(&r)),
        }
    }

    async fn encrypted(&self, client_id: String, nonce: String, message: String) -> OuterReply {
        // ключи берём из базы: пока она заблокирована, расширению нечего ответить
        let keys = self.read(|db| {
            let client = custom_str(
                db.meta
                    .custom_data
                    .get(&format!("{CLIENT_PREFIX}{client_id}")),
            );
            let server = custom_str(db.meta.custom_data.get(SERVER_KEY));
            Ok((
                client.and_then(|c| c.split('\t').next().map(str::to_string)),
                server,
            ))
        });
        let (client_pub, server_secret) = match keys {
            Ok((Some(c), Some(s))) => (c, s),
            Ok(_) => {
                return err(
                    "not_associated",
                    tr!("расширение не подключено к этой базе"),
                );
            }
            Err(_) => return err("locked", tr!("база заблокирована")),
        };
        {
            let mut seen = SEEN.lock().unwrap_or_else(|p| p.into_inner());
            if !seen.0.insert(nonce.clone()) {
                return err("replay", tr!("повторное сообщение"));
            }
            seen.1.push_back(nonce.clone());
            if seen.1.len() > 4096 {
                let old = seen.1.pop_front().expect("не пусто");
                seen.0.remove(&old);
            }
        }
        let plain = match protocol::open(&nonce, &message, &client_pub, &server_secret) {
            Ok(p) => p,
            Err(e) => return err("crypto", e),
        };
        let reply = match serde_json::from_slice::<BrowserRequest>(&plain) {
            Ok(req) => self.browser_request(req).await,
            Err(e) => BrowserReply::Error {
                code: "invalid".into(),
                message: tr!("неверный запрос: {e}", e = e),
            },
        };
        let json = serde_json::to_vec(&reply).expect("сериализуется");
        match protocol::seal(&json, &client_pub, &server_secret) {
            Ok((nonce, message)) => OuterReply::Encrypted { nonce, message },
            Err(e) => err("crypto", e),
        }
    }

    async fn browser_request(&self, req: BrowserRequest) -> BrowserReply {
        let res: Reply<BrowserReply> = async {
            Ok(match req {
                BrowserRequest::Status => BrowserReply::Status {
                    locked: !self.is_unlocked(),
                },
                BrowserRequest::Generate { options } => {
                    let o: generator::Generate = match options {
                        Some(v) => serde_json::from_value(v)
                            .map_err(|e| Response::error(ErrorCode::Invalid, e.to_string()))?,
                        None => Default::default(),
                    };
                    let g = generator::generate(&o);
                    BrowserReply::Generated {
                        password: g.value.expose().to_string(),
                        entropy: g.entropy_bits,
                    }
                }
                BrowserRequest::Lock => {
                    self.lock("из расширения браузера").await;
                    BrowserReply::Done
                }
                BrowserRequest::Facets => self.read(|db| {
                    Ok(BrowserReply::Facets {
                        folders: model::groups(db)
                            .into_iter()
                            .filter(|g| !g.is_recycle_bin && g.parent.is_some())
                            .map(|g| Folder {
                                id: g.id,
                                name: g.name,
                                depth: g.depth.saturating_sub(1),
                                count: g.entries,
                            })
                            .collect(),
                        tags: model::tags(db),
                    })
                })?,
                BrowserRequest::Search { query, filter } => BrowserReply::Logins {
                    logins: self.read(|db| {
                        let filter: keywarden_core::search::Filter = filter
                            .and_then(|f| serde_json::from_value(f).ok())
                            .unwrap_or_default();
                        Ok(
                            keywarden_core::search::search_filtered(db, &query, 200, &filter)
                                .into_iter()
                                .map(|s| Login {
                                    id: s.id,
                                    title: s.title,
                                    username: s.username,
                                    group: s.group,
                                    has_otp: s.has_otp,
                                    url: s.url,
                                    kind: kind_name(s.kind),
                                })
                                .collect(),
                        )
                    })?,
                },
                BrowserRequest::Item { id } => BrowserReply::Item {
                    item: self.read(|db| {
                        let e = entry(db, &id)?;
                        let s = model::summary(&e);
                        let wallet = s.kind == EntryKind::CryptoWallet;
                        Ok(ItemView {
                            kind: kind_name(s.kind),
                            addresses: if wallet {
                                keywarden_core::wallet::parse_addresses(
                                    e.get(keywarden_core::wallet::ADDRESSES).unwrap_or_default(),
                                )
                            } else {
                                vec![]
                            },
                            has_password: !wallet
                                && e.get(fields::PASSWORD).is_some_and(|p| !p.is_empty()),
                            totp: Totp::from_entry(&e)
                                .ok()
                                .map(|t| t.now())
                                .map(|c| (c.code, c.remaining, c.period)),
                            id: s.id,
                            title: s.title,
                            username: s.username,
                            url: s.url,
                            group: s.group,
                        })
                    })?,
                },
                BrowserRequest::Copy { id, field } => {
                    let wallet = self.read(|db| {
                        Ok(model::kind_of(&entry(db, &id)?) == EntryKind::CryptoWallet)
                    })?;
                    if wallet || !matches!(field.as_str(), "username" | "password" | "totp") {
                        return Err(Response::error(
                            ErrorCode::Invalid,
                            tr!("это поле не копируется"),
                        ));
                    }
                    let value = self.read(|db| crate::state::copy_value(db, &id, &field))?;
                    self.touch_entry(&id);
                    self.to_clipboard(value).await?;
                    BrowserReply::Copied
                }
                BrowserRequest::GetLogins { url } => BrowserReply::Logins {
                    logins: self.read(|db| Ok(logins_for(db, &url)))?,
                },
                BrowserRequest::Fill { id, url } => {
                    let e = self.allowed_entry(&id, &url).await?;
                    BrowserReply::Credentials {
                        username: e.0,
                        password: e.1,
                    }
                }
                BrowserRequest::Totp { id, url } => {
                    self.allowed_entry(&id, &url).await?;
                    let code = self.read(|db| {
                        let e = entry(db, &id)?;
                        Totp::from_entry(&e)
                            .map(|t| t.now())
                            .map_err(|e| Response::error(ErrorCode::NotFound, e.to_string()))
                    })?;
                    BrowserReply::Totp {
                        code: code.code,
                        remaining: code.remaining,
                    }
                }
                BrowserRequest::CheckSave {
                    url,
                    username,
                    password,
                } => self.read(|db| {
                    let same_user: Vec<_> = matching(db, &url)
                        .into_iter()
                        .filter(|e| {
                            e.get(fields::USERNAME)
                                .unwrap_or_default()
                                .eq_ignore_ascii_case(&username)
                        })
                        .collect();
                    Ok(match same_user.first() {
                        None => BrowserReply::SaveCheck {
                            state: "new".into(),
                            id: None,
                        },
                        Some(e) if e.get(fields::PASSWORD) == Some(password.as_str()) => {
                            BrowserReply::SaveCheck {
                                state: "same".into(),
                                id: None,
                            }
                        }
                        Some(e) => BrowserReply::SaveCheck {
                            state: "changed".into(),
                            id: Some(e.id().uuid().to_string()),
                        },
                    })
                })?,
                BrowserRequest::PasskeyCreate { url, options } => {
                    self.passkey_create(&url, &options).await?
                }
                BrowserRequest::PasskeyList { url, options } => {
                    let rp = passkey::assertion_rp_id(&options, &url).map_err(pk_err)?;
                    let allowed = passkey::allowed_ids(&options);
                    let candidates = self.read(|db| Ok(passkeys_for(db, &rp, &allowed)))?;
                    BrowserReply::Passkeys { candidates }
                }
                BrowserRequest::PasskeyGet { url, options, id } => {
                    let stored = self.read(|db| stored_passkey(&entry(db, &id)?))?;
                    let rp = passkey::assertion_rp_id(&options, &url).map_err(pk_err)?;
                    if stored.rp_id != rp {
                        return Err(Response::error(
                            ErrorCode::Invalid,
                            tr!("ключ от другого сайта"),
                        ));
                    }
                    let prompt = Prompt {
                        title: tr!("Вход на {rp} с ключом доступа", rp = rp),
                        text: tr!(
                            "Войти как «{name}»?",
                            name = if stored.username.is_empty() {
                                tr!("без имени")
                            } else {
                                &stored.username
                            }
                        ),
                        allow_always: false,
                        always_minutes: None,
                    };
                    if self.ask(prompt).await == Decision::Deny {
                        return Err(Response::error(
                            ErrorCode::Invalid,
                            tr!("NotAllowedError: пользователь отказал"),
                        ));
                    }
                    BrowserReply::Passkey {
                        credential: passkey::assert(&stored, &options, &url).map_err(pk_err)?,
                    }
                }
                BrowserRequest::Save {
                    url,
                    username,
                    password,
                    title,
                    update_id,
                } => {
                    let site = site_of(&url).ok_or_else(|| {
                        Response::error(ErrorCode::Invalid, tr!("неверный адрес страницы"))
                    })?;
                    let id = match update_id {
                        Some(id) => {
                            // обновлять можно только запись этого же сайта
                            self.read(|db| {
                                if entry_matches(&entry(db, &id)?, &url) {
                                    Ok(())
                                } else {
                                    Err(Response::error(
                                        ErrorCode::Invalid,
                                        tr!("запись от другого сайта"),
                                    ))
                                }
                            })?;
                            let patch = EntryPatch {
                                set: vec![FieldSet::new("Password", password)],
                                ..Default::default()
                            };
                            self.mutate(|db| model::update_entry(db, &id, &patch))
                                .await?;
                            id
                        }
                        None => {
                            let origin = url::Url::parse(&url)
                                .map(|u| u.origin().ascii_serialization())
                                .unwrap_or_else(|_| format!("https://{site}"));
                            self.mutate(move |db| {
                                let group = browser_group(db)?;
                                let id = model::create_entry(
                                    db,
                                    &EntryPatch {
                                        kind: Some(EntryKind::Login),
                                        group: Some(group),
                                        set: vec![
                                            FieldSet::new(
                                                "Title",
                                                title.unwrap_or_else(|| site.clone()),
                                            ),
                                            FieldSet::new("UserName", username),
                                            FieldSet::new("Password", password),
                                            FieldSet::new("URL", origin),
                                        ],
                                        ..Default::default()
                                    },
                                )?;
                                allow_site(db, &id, &site);
                                Ok(id)
                            })
                            .await?
                        }
                    };
                    BrowserReply::Saved { id }
                }
            })
        }
        .await;
        res.unwrap_or_else(|r| match r {
            Response::Error { code, message } => BrowserReply::Error {
                code: serde_json::to_value(code)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_default(),
                message,
            },
            _ => BrowserReply::Error {
                code: "internal".into(),
                message: String::new(),
            },
        })
    }

    /// Проверка адреса и разрешения сайта; возвращает логин и пароль.
    async fn allowed_entry(&self, id: &str, url: &str) -> Reply<(String, String)> {
        let site = site_of(url)
            .ok_or_else(|| Response::error(ErrorCode::Invalid, tr!("неверный адрес страницы")))?;
        let (title, username, password, allowed) = self.read(|db| {
            let e = entry(db, id)?;
            if !entry_matches(&e, url) {
                return Err(Response::error(
                    ErrorCode::Invalid,
                    tr!("запись не для сайта {site}", site = site),
                ));
            }
            let allow = custom_str(e.custom_data.get(ALLOW_KEY)).unwrap_or_default();
            Ok((
                e.get(fields::TITLE).unwrap_or_default().to_string(),
                // ссылки {REF:...} подставляются, как при копировании
                model::resolve(db, &e, e.get(fields::USERNAME).unwrap_or_default()),
                model::resolve(db, &e, e.get(fields::PASSWORD).unwrap_or_default()),
                allow.lines().any(|h| h == site),
            ))
        })?;
        if !allowed {
            let prompt = Prompt {
                title: tr!("Сайт {site} просит пароль", site = site),
                text: tr!(
                    "Заполнить «{title}»{user} на {site}?",
                    title = title,
                    user = if username.is_empty() {
                        String::new()
                    } else {
                        format!(" ({username})")
                    },
                    site = site
                ),
                allow_always: true,
                always_minutes: None,
            };
            match self.ask(prompt).await {
                Decision::Deny => {
                    return Err(Response::error(
                        ErrorCode::Invalid,
                        tr!("пользователь отказал"),
                    ));
                }
                Decision::Once => {}
                Decision::Always => {
                    let (id, site) = (id.to_string(), site.clone());
                    self.mutate(move |db| {
                        allow_site(db, &id, &site);
                        Ok(())
                    })
                    .await?;
                }
            }
        }
        Ok((username, password))
    }

    async fn passkey_create(&self, url: &str, options: &serde_json::Value) -> Reply<BrowserReply> {
        let created = passkey::register(options, url).map_err(pk_err)?;
        let field = |n: &str| {
            created
                .fields
                .iter()
                .find(|f| f.0 == n)
                .map(|f| f.1.clone())
                .unwrap_or_default()
        };
        let (rp, username) = (field(passkey::RELYING_PARTY), field(passkey::USERNAME));
        // excludeCredentials: у этого аккаунта ключ уже есть
        let exclude = options["excludeCredentials"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|c| c["id"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let dup = self.read(|db| {
            Ok(db.iter_all_entries().any(|e| {
                e.get(passkey::CREDENTIAL_ID)
                    .is_some_and(|c| exclude.iter().any(|x| x.trim_end_matches('=') == c))
            }))
        })?;
        if dup {
            return Err(Response::error(
                ErrorCode::Conflict,
                tr!("InvalidStateError: ключ доступа для этого аккаунта уже есть"),
            ));
        }
        let prompt = Prompt {
            title: tr!("Создать ключ доступа для {rp}?", rp = rp),
            text: tr!(
                "Сайт {rp} предлагает сохранить ключ доступа{user} в Keywarden.",
                rp = rp,
                user = if username.is_empty() {
                    String::new()
                } else {
                    tr!(" для «{username}»", username = username)
                }
            ),
            allow_always: false,
            always_minutes: None,
        };
        if self.ask(prompt).await == Decision::Deny {
            return Err(Response::error(
                ErrorCode::Invalid,
                tr!("NotAllowedError: пользователь отказал"),
            ));
        }
        let title = if created.rp_name.is_empty() {
            rp.clone()
        } else {
            created.rp_name.clone()
        };
        let mut set = vec![
            FieldSet::new("Title", title),
            FieldSet::new("UserName", username),
            FieldSet::new("URL", format!("https://{rp}")),
        ];
        set.extend(created.fields.iter().map(|(n, v, p)| FieldSet {
            name: (*n).into(),
            value: v.clone().into(),
            protected: Some(*p),
        }));
        self.mutate(move |db| {
            let group = browser_group(db)?;
            model::create_entry(
                db,
                &EntryPatch {
                    kind: Some(EntryKind::Passkey),
                    group: Some(group),
                    tags: Some(vec!["Passkey".into()]),
                    set,
                    remove: vec![],
                    expires: None,
                    autotype: None,
                },
            )
        })
        .await?;
        Ok(BrowserReply::Passkey {
            credential: created.credential,
        })
    }

    async fn ask(&self, prompt: Prompt) -> Decision {
        let cmd = self.config().confirm_command;
        tokio::task::spawn_blocking(move || confirm::ask(cmd.as_deref(), &prompt))
            .await
            .unwrap_or(Decision::Deny)
    }
}

fn pk_err(e: passkey::PasskeyError) -> Response {
    let name = match e {
        passkey::PasskeyError::Security(_) => "SecurityError",
        passkey::PasskeyError::NotSupported => "NotSupportedError",
        _ => "NotAllowedError",
    };
    Response::error(ErrorCode::Invalid, format!("{name}: {e}"))
}

fn stored_passkey(e: &EntryRef<'_>) -> Reply<passkey::Stored> {
    let get = |n: &str| e.get(n).unwrap_or_default().to_string();
    let flag = |n: &str| {
        e.get(n)
            .is_none_or(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    };
    if get(passkey::PRIVATE_KEY).is_empty() {
        return Err(Response::error(
            ErrorCode::NotFound,
            tr!("в записи нет ключа доступа"),
        ));
    }
    Ok(passkey::Stored {
        rp_id: get(passkey::RELYING_PARTY),
        credential_id: get(passkey::CREDENTIAL_ID)
            .trim_end_matches('=')
            .to_string(),
        user_handle: get(passkey::USER_HANDLE),
        username: get(passkey::USERNAME),
        private_key_pem: get(passkey::PRIVATE_KEY),
        be: flag(passkey::FLAG_BE),
        bs: flag(passkey::FLAG_BS),
    })
}

/// Ключи доступа сайта (KeePassXC: KPEX_PASSKEY_RELYING_PARTY == rpId), с учётом allowCredentials.
fn passkeys_for(db: &Database, rp_id: &str, allowed: &[String]) -> Vec<Login> {
    db.iter_all_entries()
        .filter(|e| !model::in_recycle_bin(db, e.parent().id()))
        .filter(|e| {
            e.get(passkey::RELYING_PARTY) == Some(rp_id) && e.get(passkey::PRIVATE_KEY).is_some()
        })
        .filter(|e| {
            allowed.is_empty()
                || e.get(passkey::CREDENTIAL_ID)
                    .is_some_and(|c| allowed.iter().any(|a| a == c.trim_end_matches('=')))
        })
        .map(|e| {
            let s = model::summary(&e);
            Login {
                id: s.id,
                title: s.title,
                username: e.get(passkey::USERNAME).unwrap_or(&s.username).to_string(),
                group: s.group,
                has_otp: false,
                url: s.url,
                kind: kind_name(s.kind),
            }
        })
        .collect()
}

fn kind_name(k: EntryKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn response_text(r: &Response) -> String {
    match r {
        Response::Error { message, .. } => message.clone(),
        _ => String::new(),
    }
}

fn entry<'a>(db: &'a Database, id: &str) -> Reply<EntryRef<'a>> {
    let eid = model::parse_entry_id(id).map_err(model_err)?;
    db.entry(eid)
        .ok_or_else(|| model_err(ModelError::EntryNotFound))
}

/// Адрес записи и дополнительные адреса (KP2A_URL*, как у KeePassDX и KeePassXC).
fn entry_matches(e: &EntryRef<'_>, page: &str) -> bool {
    e.fields
        .iter()
        .any(|(k, v)| (k == fields::URL || k.starts_with("KP2A_URL")) && url_matches(page, v.get()))
}

fn matching<'a>(db: &'a Database, page: &str) -> Vec<EntryRef<'a>> {
    db.iter_all_entries()
        .filter(|e| !model::in_recycle_bin(db, e.parent().id()) && entry_matches(e, page))
        .collect()
}

fn logins_for(db: &Database, page: &str) -> Vec<Login> {
    let mut v: Vec<Login> = matching(db, page)
        .iter()
        .filter(|e| matches!(model::kind_of(e), EntryKind::Login | EntryKind::Passkey))
        .map(|e| {
            let s = model::summary(e);
            Login {
                id: s.id,
                title: s.title,
                username: s.username,
                group: s.group,
                has_otp: s.has_otp,
                url: s.url,
                kind: kind_name(s.kind),
            }
        })
        .collect();
    v.sort_by_key(|a| a.title.to_lowercase());
    v
}

fn allow_site(db: &mut Database, id: &str, site: &str) {
    let Ok(eid) = model::parse_entry_id(id) else {
        return;
    };
    let Some(mut e) = db.entry_mut(eid) else {
        return;
    };
    let mut hosts: Vec<String> = custom_str(e.custom_data.get(ALLOW_KEY))
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect();
    if !hosts.iter().any(|h| h == site) {
        hosts.push(site.to_string());
        set_custom(&mut e.custom_data, ALLOW_KEY, hosts.join("\n"));
    }
}

fn browser_group(db: &mut Database) -> model::Result<String> {
    if let Some(g) = db.root().groups().find(|g| g.name == BROWSER_GROUP) {
        return Ok(g.id().uuid().to_string());
    }
    model::add_group(db, None, BROWSER_GROUP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use keywarden_core::ipc::Request;
    use keywarden_core::vault::{Cipher, Credentials, Vault, test_kdf};
    use std::sync::Arc;

    struct Ext {
        id: String,
        kp: Keypair,
        server: Option<String>,
    }

    impl Ext {
        fn new() -> Self {
            Self {
                id: "ext-1".into(),
                kp: Keypair::generate(),
                server: None,
            }
        }
        async fn call(&self, d: &Arc<Daemon>, req: BrowserRequest) -> BrowserReply {
            let (nonce, message) = protocol::seal(
                &serde_json::to_vec(&req).unwrap(),
                self.server.as_ref().unwrap(),
                &self.kp.secret_b64(),
            )
            .unwrap();
            let msg = serde_json::to_value(Outer::Encrypted {
                client_id: self.id.clone(),
                nonce,
                message,
            })
            .unwrap();
            let Response::Browser { reply } = d.handle(Request::Browser { message: msg }).await
            else {
                panic!()
            };
            match serde_json::from_value::<OuterReply>(reply).unwrap() {
                OuterReply::Encrypted { nonce, message } => serde_json::from_slice(
                    &protocol::open(
                        &nonce,
                        &message,
                        self.server.as_ref().unwrap(),
                        &self.kp.secret_b64(),
                    )
                    .unwrap(),
                )
                .unwrap(),
                other => panic!("{other:?}"),
            }
        }
    }

    async fn daemon(dir: &std::path::Path, decision: i32) -> Arc<Daemon> {
        let db = dir.join("b.kdbx");
        let creds = Credentials {
            password: Some("pw".into()),
            keyfile: None,
            challenge: None,
        };
        let mut v = Vault::create(&db, &creds, Cipher::ChaCha20, test_kdf()).unwrap();
        v.backups.dir = dir.join("bak");
        model::create_entry(
            &mut v.db,
            &EntryPatch {
                set: vec![
                    FieldSet::new("Title", "GitHub"),
                    FieldSet::new("UserName", "octo"),
                    FieldSet::new("Password", "s3cret"),
                    FieldSet::new("URL", "https://github.com"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
        v.save().unwrap();
        let cfg = Config {
            backups_dir: Some(dir.join("bak")),
            confirm_command: Some(vec![
                "sh".into(),
                "-c".into(),
                format!("exit {decision}"),
                "sh".into(),
            ]),
            ..Config::default()
        };
        let d = Daemon::new(cfg, dir.join("c.toml"));
        tokio::spawn(d.clone().saver());
        d.handle(Request::Unlock {
            path: Some(db.display().to_string()),
            password: Some("pw".into()),
            keyfile: None,
            yubikey: None,
        })
        .await;
        d
    }

    async fn associate(d: &Arc<Daemon>, ext: &mut Ext) -> OuterReply {
        let msg = serde_json::to_value(Outer::Associate {
            client_id: ext.id.clone(),
            client_public: ext.kp.public_b64(),
            name: "Firefox".into(),
        })
        .unwrap();
        let Response::Browser { reply } = d.handle(Request::Browser { message: msg }).await else {
            panic!()
        };
        let r: OuterReply = serde_json::from_value(reply).unwrap();
        if let OuterReply::Associated { server_public } = &r {
            ext.server = Some(server_public.clone());
        }
        r
    }

    #[tokio::test]
    async fn full_flow() {
        let dir = tempfile::tempdir().unwrap();
        let d = daemon(dir.path(), 11).await;
        let mut ext = Ext::new();
        assert!(matches!(
            associate(&d, &mut ext).await,
            OuterReply::Associated { .. }
        ));

        let BrowserReply::Logins { logins } = ext
            .call(
                &d,
                BrowserRequest::GetLogins {
                    url: "https://github.com/login".into(),
                },
            )
            .await
        else {
            panic!()
        };
        assert_eq!(logins.len(), 1);
        assert!(
            matches!(ext.call(&d, BrowserRequest::GetLogins { url: "https://evil.com".into() }).await, BrowserReply::Logins { logins } if logins.is_empty())
        );

        let id = logins[0].id.clone();
        let r = ext
            .call(
                &d,
                BrowserRequest::Fill {
                    id: id.clone(),
                    url: "https://github.com/login".into(),
                },
            )
            .await;
        assert!(
            matches!(r, BrowserReply::Credentials { ref password, .. } if password == "s3cret"),
            "{r:?}"
        );
        // чужой сайт не получает пароль даже по известному id
        let r = ext
            .call(
                &d,
                BrowserRequest::Fill {
                    id: id.clone(),
                    url: "https://evil.com".into(),
                },
            )
            .await;
        assert!(matches!(r, BrowserReply::Error { .. }), "{r:?}");

        // сохранение: новая учётка и смена пароля
        let r = ext
            .call(
                &d,
                BrowserRequest::CheckSave {
                    url: "https://github.com".into(),
                    username: "octo".into(),
                    password: "new".into(),
                },
            )
            .await;
        assert!(matches!(r, BrowserReply::SaveCheck { ref state, .. } if state == "changed"));
        let r = ext
            .call(
                &d,
                BrowserRequest::CheckSave {
                    url: "https://gitlab.com".into(),
                    username: "me".into(),
                    password: "x".into(),
                },
            )
            .await;
        assert!(matches!(r, BrowserReply::SaveCheck { ref state, .. } if state == "new"));
        let r = ext
            .call(
                &d,
                BrowserRequest::Save {
                    url: "https://gitlab.com/users/sign_in".into(),
                    username: "me".into(),
                    password: "x".into(),
                    title: None,
                    update_id: None,
                },
            )
            .await;
        assert!(matches!(r, BrowserReply::Saved { .. }), "{r:?}");
        let BrowserReply::Logins { logins } = ext
            .call(
                &d,
                BrowserRequest::GetLogins {
                    url: "https://gitlab.com/".into(),
                },
            )
            .await
        else {
            panic!()
        };
        assert_eq!(logins[0].group, BROWSER_GROUP);
    }

    #[tokio::test]
    async fn denied_and_unknown_clients() {
        let dir = tempfile::tempdir().unwrap();
        let d = daemon(dir.path(), 1).await;
        let mut ext = Ext::new();
        assert!(
            matches!(associate(&d, &mut ext).await, OuterReply::Error { ref code, .. } if code == "denied")
        );

        // подделка: шифруем «своим» серверным ключом, которого демон не знает
        let fake = Ext {
            id: "ext-1".into(),
            kp: Keypair::generate(),
            server: Some(Keypair::generate().public_b64()),
        };
        let (nonce, message) = protocol::seal(
            b"{\"action\":\"status\"}",
            fake.server.as_ref().unwrap(),
            &fake.kp.secret_b64(),
        )
        .unwrap();
        let msg = serde_json::to_value(Outer::Encrypted {
            client_id: fake.id,
            nonce,
            message,
        })
        .unwrap();
        let Response::Browser { reply } = d.handle(Request::Browser { message: msg }).await else {
            panic!()
        };
        assert!(
            matches!(serde_json::from_value::<OuterReply>(reply).unwrap(), OuterReply::Error { ref code, .. } if code == "not_associated")
        );
    }
}
