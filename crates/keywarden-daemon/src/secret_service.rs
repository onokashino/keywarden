//! Secret Service (org.freedesktop.secrets) на сессионной шине: системная связка ключей, в которой
//! браузеры, git, NetworkManager и другие хранят свои пароли. Включается в конфиге
//! (`secret_service = true`); если имя уже занято (gnome-keyring), Keywarden его не отнимает.
//!
//! Приложениям видна только папка `secret_service_group` базы. Чтение секрета приложением
//! подтверждается окном Keywarden (`secret_service_confirm`), «всегда» действует до блокировки.
//! Сессии: plain и dh-ietf1024-sha256-aes128-cbc-pkcs7 (её выбирает libsecret).

use crate::confirm::{Decision, Prompt as Ask};
use crate::state::Daemon;
use keywarden_core::ipc::Event;
use keywarden_core::secrets::{self, SessionKey};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zbus::fdo;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;
use zbus::{Connection, interface};
use zbus::{ObjectPath, OwnedObjectPath, OwnedVariant as OwnedValue, Variant as Value};

const NAME: &str = "org.freedesktop.secrets";
const SERVICE: &str = "/org/freedesktop/secrets";
const COLLECTION: &str = "/org/freedesktop/secrets/collection/keywarden";
const ALIAS: &str = "/org/freedesktop/secrets/aliases/default";
/// Сколько ждать разблокировки, когда приложение обратилось к закрытой базе.
const UNLOCK_WAIT: Duration = Duration::from_secs(20);

/// Секрет на шине: (сессия, параметры, значение, тип содержимого) = (oayays).
type SecretStruct = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

struct Shared {
    daemon: Arc<Daemon>,
    group: String,
    confirm: bool,
    sessions: Mutex<HashMap<String, Option<SessionKey>>>,
    next: AtomicU64,
    /// приложения, которым разрешено «всегда»: (номер разблокировки, путь к программе)
    trusted: Mutex<HashSet<(u64, String)>>,
    /// зарегистрированные на шине элементы (uuid)
    registered: Mutex<HashSet<String>>,
}

fn path(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p.to_string()).expect("правильный путь")
}

fn item_path(id: &str) -> OwnedObjectPath {
    path(&format!("{COLLECTION}/{}", id.replace('-', "")))
}

fn failed(m: impl Into<String>) -> fdo::Error {
    fdo::Error::Failed(m.into())
}

fn reply_err(r: keywarden_core::ipc::Response) -> fdo::Error {
    match r {
        keywarden_core::ipc::Response::Error { message, .. } => failed(message),
        _ => failed(tr!("ошибка")),
    }
}

/// uuid записи из пути элемента (сверка с тем, что реально лежит в папке).
fn id_of(shared: &Shared, p: &ObjectPath<'_>) -> Option<String> {
    let tail = p.as_str().strip_prefix(&format!("{COLLECTION}/"))?;
    shared
        .daemon
        .read(|db| Ok(secrets::items(db, &shared.group)))
        .ok()?
        .into_iter()
        .map(|i| i.id)
        .find(|id| id.replace('-', "") == tail)
}

impl Shared {
    fn session(&self, p: &ObjectPath<'_>) -> fdo::Result<Option<SessionKey>> {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(p.as_str())
            .cloned()
            .ok_or_else(|| fdo::Error::Failed(tr!("сессия не найдена").into()))
    }

    fn pack(
        &self,
        session: &ObjectPath<'_>,
        plain: &[u8],
        content_type: String,
    ) -> fdo::Result<SecretStruct> {
        let s = OwnedObjectPath::from(session.to_owned());
        Ok(match self.session(session)? {
            None => (s, vec![], plain.to_vec(), content_type),
            Some(key) => {
                let (iv, ct) = secrets::encrypt(&key, plain);
                (s, iv, ct, content_type)
            }
        })
    }

    fn unpack(&self, secret: &SecretStruct) -> fdo::Result<zeroize::Zeroizing<Vec<u8>>> {
        let (session, params, value, _) = secret;
        match self.session(session)? {
            None => Ok(zeroize::Zeroizing::new(value.clone())),
            Some(key) => secrets::decrypt(&key, params, value).map_err(failed),
        }
    }

    /// База закрыта: показать окно разблокировки и немного подождать.
    async fn ensure_unlocked(&self) -> fdo::Result<()> {
        if self.daemon.is_unlocked() {
            return Ok(());
        }
        let mut rx = self.daemon.events.subscribe();
        let _ = std::process::Command::new(crate::confirm::ui_binary()).spawn();
        let wait = async {
            loop {
                match rx.recv().await {
                    Ok(Event::Unlocked) => return,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                    _ => {}
                }
            }
        };
        let _ = tokio::time::timeout(UNLOCK_WAIT, wait).await;
        if self.daemon.is_unlocked() {
            Ok(())
        } else {
            Err(fdo::Error::AccessDenied(
                tr!("хранилище Keywarden заблокировано").into(),
            ))
        }
    }

    /// Кто спрашивает: путь к программе по PID отправителя.
    async fn client(&self, conn: &Connection, hdr: &Header<'_>) -> String {
        let Some(sender) = hdr.sender() else {
            return String::new();
        };
        let Ok(dbus) = fdo::DBusProxy::new(conn).await else {
            return String::new();
        };
        match dbus
            .get_connection_unix_process_id(sender.clone().into())
            .await
        {
            Ok(pid) => std::fs::read_link(format!("/proc/{pid}/exe"))
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| format!("PID {pid}")),
            Err(_) => sender.to_string(),
        }
    }

    /// Подтверждение выдачи секретов приложению.
    async fn allow(
        &self,
        conn: &Connection,
        hdr: &Header<'_>,
        labels: &[String],
    ) -> fdo::Result<()> {
        if !self.confirm {
            return Ok(());
        }
        let client = self.client(conn, hdr).await;
        let epoch = self.daemon.unlocked_epoch().unwrap_or(0);
        if self
            .trusted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&(epoch, client.clone()))
        {
            return Ok(());
        }
        let prompt = Ask {
            title: tr!("Доступ к связке ключей").into(),
            text: tr!(
                "{client} просит {what}:\n{labels}",
                client = if client.is_empty() {
                    tr!("Неизвестная программа").to_string()
                } else {
                    client.clone()
                },
                what = if labels.len() == 1 {
                    tr!("секрет")
                } else {
                    tr!("секреты")
                },
                labels = labels.join(", ")
            ),
            allow_always: true,
            always_minutes: None,
        };
        let cmd = self.daemon.config().confirm_command;
        let decision =
            tokio::task::spawn_blocking(move || crate::confirm::ask(cmd.as_deref(), &prompt))
                .await
                .unwrap_or(Decision::Deny);
        match decision {
            Decision::Deny => Err(fdo::Error::AccessDenied(tr!("доступ не разрешён").into())),
            Decision::Once => Ok(()),
            Decision::Always => {
                self.trusted
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert((epoch, client));
                Ok(())
            }
        }
    }

    /// Привести объекты элементов на шине в соответствие с папкой базы.
    async fn sync_items(self: &Arc<Self>, conn: &Connection) {
        let now: HashSet<String> = self
            .daemon
            .read(|db| Ok(secrets::items(db, &self.group)))
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.id)
            .collect();
        let (add, remove) = {
            let reg = self.registered.lock().unwrap_or_else(|e| e.into_inner());
            (
                now.difference(&reg).cloned().collect::<Vec<_>>(),
                reg.difference(&now).cloned().collect::<Vec<_>>(),
            )
        };
        let server = conn.object_server();
        for id in add {
            let _ = server
                .at(
                    item_path(&id),
                    Item {
                        shared: self.clone(),
                        id: id.clone(),
                    },
                )
                .await;
            self.registered
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(id);
        }
        for id in remove {
            let _ = server.remove::<Item, _>(item_path(&id)).await;
            self.registered
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&id);
        }
    }

    fn items(&self) -> Vec<secrets::ItemView> {
        self.daemon
            .read(|db| Ok(secrets::items(db, &self.group)))
            .unwrap_or_default()
    }
}

struct Service(Arc<Shared>);

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(
        &self,
        algorithm: &str,
        input: OwnedValue,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let n = self.0.next.fetch_add(1, Ordering::Relaxed);
        let p = path(&format!("{SERVICE}/session/s{n}"));
        let (output, key) = match algorithm {
            "plain" => (Value::from(""), None),
            "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
                let client = Vec::<u8>::try_from(input).map_err(|_| {
                    fdo::Error::InvalidArgs(tr!("ожидался открытый ключ ay").into())
                })?;
                let (public, key) =
                    secrets::dh_negotiate(&client).map_err(fdo::Error::InvalidArgs)?;
                (Value::from(public), Some(key))
            }
            other => {
                return Err(fdo::Error::NotSupported(tr!(
                    "алгоритм {other}",
                    other = other
                )));
            }
        };
        self.0
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(p.as_str().to_string(), key);
        server
            .at(
                p.clone(),
                Session {
                    shared: self.0.clone(),
                },
            )
            .await?;
        Ok((
            OwnedValue::try_from(output).map_err(|e| failed(e.to_string()))?,
            p,
        ))
    }

    /// Своя коллекция одна; на создание отвечаем ею же.
    async fn create_collection(
        &self,
        _properties: HashMap<String, OwnedValue>,
        _alias: &str,
    ) -> (OwnedObjectPath, OwnedObjectPath) {
        (path(COLLECTION), path("/"))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        self.0.ensure_unlocked().await?;
        let found = self
            .0
            .daemon
            .read(|db| Ok(secrets::search(db, &self.0.group, &attributes)))
            .map_err(reply_err)?;
        Ok((found.iter().map(|i| item_path(&i.id)).collect(), vec![]))
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        if self.0.daemon.is_unlocked() {
            return Ok((objects, path("/")));
        }
        let n = self.0.next.fetch_add(1, Ordering::Relaxed);
        let p = path(&format!("{SERVICE}/prompt/p{n}"));
        server
            .at(
                p.clone(),
                PromptObj {
                    shared: self.0.clone(),
                    objects,
                },
            )
            .await?;
        Ok((vec![], p))
    }

    async fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.0.daemon.lock("по запросу Secret Service").await;
        (objects, path("/"))
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<HashMap<OwnedObjectPath, SecretStruct>> {
        self.0.ensure_unlocked().await?;
        let all = self.0.items();
        let wanted: Vec<(OwnedObjectPath, String, String)> = items
            .into_iter()
            .filter_map(|p| {
                let id = id_of(&self.0, &p)?;
                let label = all
                    .iter()
                    .find(|i| i.id == id)
                    .map(|i| i.label.clone())
                    .unwrap_or_default();
                Some((p, id, label))
            })
            .collect();
        if wanted.is_empty() {
            return Ok(HashMap::new());
        }
        let labels: Vec<String> = wanted.iter().map(|w| w.2.clone()).collect();
        self.0.allow(conn, &hdr, &labels).await?;
        let mut out = HashMap::new();
        for (p, id, _) in wanted {
            let (value, ct) = self
                .0
                .daemon
                .read(|db| secrets::secret(db, &self.0.group, &id).map_err(crate::state::model_err))
                .map_err(reply_err)?;
            out.insert(p, self.0.pack(&session, &value, ct)?);
        }
        Ok(out)
    }

    async fn read_alias(&self, name: &str) -> OwnedObjectPath {
        match name {
            "default" | "login" => path(COLLECTION),
            _ => path("/"),
        }
    }

    async fn set_alias(&self, _name: &str, _collection: OwnedObjectPath) {}

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        vec![path(COLLECTION)]
    }
}

struct Collection(Arc<Shared>);

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    async fn delete(&self) -> fdo::Result<OwnedObjectPath> {
        Err(fdo::Error::NotSupported(
            tr!("коллекцию Keywarden нельзя удалить через Secret Service").into(),
        ))
    }

    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        self.0.ensure_unlocked().await?;
        Ok(self
            .0
            .daemon
            .read(|db| Ok(secrets::search(db, &self.0.group, &attributes)))
            .map_err(reply_err)?
            .iter()
            .map(|i| item_path(&i.id))
            .collect())
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretStruct,
        replace: bool,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        self.0.ensure_unlocked().await?;
        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|v| String::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let attrs: HashMap<String, String> = properties
            .get("org.freedesktop.Secret.Item.Attributes")
            .and_then(|v| HashMap::<String, String>::try_from(v.try_clone().ok()?).ok())
            .unwrap_or_default();
        let value = self.0.unpack(&secret)?;
        let ct = if secret.3.is_empty() {
            "text/plain".to_string()
        } else {
            secret.3.clone()
        };
        let group = self.0.group.clone();
        let id = self
            .0
            .daemon
            .mutate(move |db| secrets::create(db, &group, &label, &attrs, &value, &ct, replace))
            .await
            .map_err(reply_err)?;
        self.0.sync_items(conn).await;
        Ok((item_path(&id), path("/")))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        self.0.items().iter().map(|i| item_path(&i.id)).collect()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        "Keywarden".into()
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        !self.0.daemon.is_unlocked()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        0
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        0
    }
}

struct Item {
    shared: Arc<Shared>,
    id: String,
}

impl Item {
    fn view(&self) -> fdo::Result<secrets::ItemView> {
        self.shared
            .items()
            .into_iter()
            .find(|i| i.id == self.id)
            .ok_or_else(|| fdo::Error::UnknownObject(tr!("элемент удалён").into()))
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    async fn delete(&self, #[zbus(connection)] conn: &Connection) -> fdo::Result<OwnedObjectPath> {
        let (group, id) = (self.shared.group.clone(), self.id.clone());
        self.shared
            .daemon
            .mutate(move |db| secrets::delete(db, &group, &id))
            .await
            .map_err(reply_err)?;
        self.shared.sync_items(conn).await;
        Ok(path("/"))
    }

    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<(SecretStruct,)> {
        self.shared.ensure_unlocked().await?;
        let label = self.view()?.label;
        self.shared.allow(conn, &hdr, &[label]).await?;
        let (value, ct) = self
            .shared
            .daemon
            .read(|db| {
                secrets::secret(db, &self.shared.group, &self.id).map_err(crate::state::model_err)
            })
            .map_err(reply_err)?;
        // одна структура (oayays), а не четыре значения: кортеж из одного элемента
        Ok((self.shared.pack(&session, &value, ct)?,))
    }

    async fn set_secret(&self, secret: SecretStruct) -> fdo::Result<()> {
        let value = self.shared.unpack(&secret)?;
        let ct = if secret.3.is_empty() {
            "text/plain".to_string()
        } else {
            secret.3.clone()
        };
        let (group, id) = (self.shared.group.clone(), self.id.clone());
        self.shared
            .daemon
            .mutate(move |db| secrets::set_secret(db, &group, &id, &value, &ct))
            .await
            .map_err(reply_err)
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        !self.shared.daemon.is_unlocked()
    }

    #[zbus(property)]
    async fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        Ok(self.view()?.attributes)
    }

    #[zbus(property)]
    async fn set_attributes(&self, attributes: HashMap<String, String>) -> fdo::Result<()> {
        let (group, id) = (self.shared.group.clone(), self.id.clone());
        self.shared
            .daemon
            .mutate(move |db| secrets::set_attributes(db, &group, &id, &attributes))
            .await
            .map_err(reply_err)
    }

    #[zbus(property)]
    async fn label(&self) -> fdo::Result<String> {
        Ok(self.view()?.label)
    }

    #[zbus(property)]
    async fn set_label(&self, label: String) -> fdo::Result<()> {
        let (group, id) = (self.shared.group.clone(), self.id.clone());
        self.shared
            .daemon
            .mutate(move |db| secrets::set_label(db, &group, &id, &label))
            .await
            .map_err(reply_err)
    }

    #[zbus(property)]
    async fn created(&self) -> fdo::Result<u64> {
        Ok(self.view()?.created)
    }

    #[zbus(property)]
    async fn modified(&self) -> fdo::Result<u64> {
        Ok(self.view()?.modified)
    }
}

struct Session {
    shared: Arc<Shared>,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> fdo::Result<()> {
        if let Some(p) = hdr.path() {
            self.shared
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(p.as_str());
            server.remove::<Session, _>(p.to_owned()).await?;
        }
        Ok(())
    }
}

struct PromptObj {
    shared: Arc<Shared>,
    objects: Vec<OwnedObjectPath>,
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptObj {
    /// Окно разблокировки Keywarden; Completed приходит, когда база открыта или вышло время.
    async fn prompt(
        &self,
        _window_id: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> fdo::Result<()> {
        let unlocked = self.shared.ensure_unlocked().await.is_ok();
        let result = Value::from(if unlocked {
            self.objects.clone()
        } else {
            vec![]
        });
        Self::completed(&emitter, !unlocked, result).await?;
        Ok(())
    }

    async fn dismiss(&self, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        Self::completed(&emitter, true, Value::from(Vec::<OwnedObjectPath>::new())).await?;
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

/// Запуск сервиса; работает, пока жив демон.
pub async fn serve(daemon: Arc<Daemon>) {
    let cfg = daemon.config();
    if !cfg.secret_service {
        return;
    }
    let shared = Arc::new(Shared {
        daemon: daemon.clone(),
        group: cfg.secret_service_group.clone(),
        confirm: cfg.secret_service_confirm,
        sessions: Mutex::new(HashMap::new()),
        next: AtomicU64::new(1),
        trusted: Mutex::new(HashSet::new()),
        registered: Mutex::new(HashSet::new()),
    });
    let conn = match zbus::connection::Builder::session()
        .serve_at(SERVICE, Service(shared.clone()))
        .serve_at(COLLECTION, Collection(shared.clone()))
        .serve_at(ALIAS, Collection(shared.clone()))
        .build()
        .await
    {
        Ok(c) => c,
        Err(e) => return tracing::warn!("Secret Service: сессионная шина недоступна: {e}"),
    };
    match conn
        .request_name_with_flags(NAME, zbus::fdo::RequestNameFlags::DO_NOT_QUEUE)
        .await
    {
        Ok(zbus::fdo::RequestNameReply::PrimaryOwner) => {
            tracing::info!("Secret Service: Keywarden обслуживает {NAME}")
        }
        Ok(_) | Err(_) => {
            return tracing::warn!(
                "Secret Service: имя {NAME} уже занято (gnome-keyring или KeePassXC); отключите их компонент secrets, чтобы Keywarden стал связкой ключей"
            );
        }
    }
    shared.sync_items(&conn).await;
    let mut rx = daemon.events.subscribe();
    loop {
        match rx.recv().await {
            Ok(Event::Unlocked | Event::Changed | Event::Merged { .. }) => {
                shared.sync_items(&conn).await
            }
            Ok(Event::Locked) => {
                shared
                    .trusted
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clear();
                shared.sync_items(&conn).await;
            }
            Ok(_) => {}
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                shared.sync_items(&conn).await
            }
            Err(_) => return,
        }
    }
}

/// Клиент чужой связки ключей (gnome-keyring, KeePassXC), чтобы перенести её содержимое.
mod client {
    use std::collections::HashMap;
    use zbus::{OwnedObjectPath, OwnedVariant as OwnedValue, Variant as Value};

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Service",
        default_service = "org.freedesktop.secrets",
        default_path = "/org/freedesktop/secrets"
    )]
    pub trait Service {
        fn open_session(
            &self,
            algorithm: &str,
            input: &Value<'_>,
        ) -> zbus::Result<(OwnedValue, OwnedObjectPath)>;
        fn unlock(
            &self,
            objects: &[OwnedObjectPath],
        ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;
        fn get_secrets(
            &self,
            items: &[OwnedObjectPath],
            session: &OwnedObjectPath,
        ) -> zbus::Result<HashMap<OwnedObjectPath, (OwnedObjectPath, Vec<u8>, Vec<u8>, String)>>;
        #[zbus(property)]
        fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Collection",
        default_service = "org.freedesktop.secrets"
    )]
    pub trait Collection {
        #[zbus(property)]
        fn items(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
        #[zbus(property)]
        fn label(&self) -> zbus::Result<String>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Item",
        default_service = "org.freedesktop.secrets"
    )]
    pub trait Item {
        #[zbus(property)]
        fn label(&self) -> zbus::Result<String>;
        #[zbus(property)]
        fn attributes(&self) -> zbus::Result<HashMap<String, String>>;
    }

    #[zbus::proxy(
        interface = "org.freedesktop.Secret.Prompt",
        default_service = "org.freedesktop.secrets"
    )]
    pub trait Prompt {
        fn prompt(&self, window_id: &str) -> zbus::Result<()>;
        #[zbus(signal)]
        fn completed(&self, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
    }
}

/// Что перенесено из чужой связки.
pub struct Migrated {
    pub items: usize,
    pub skipped: usize,
}

/// Перенести все элементы текущего владельца org.freedesktop.secrets в папку Secret Service базы.
/// Свою связку (Keywarden сам владелец имени) переносить не нужно: это та же папка.
pub async fn migrate(daemon: &Arc<Daemon>) -> Result<Migrated, String> {
    use futures_util::StreamExt;
    let group = daemon.config().secret_service_group;
    let conn = Connection::session()
        .await
        .map_err(|e| tr!("сессионная шина: {e}", e = e))?;
    let svc = client::ServiceProxy::new(&conn)
        .await
        .map_err(|e| tr!("связка ключей не найдена: {e}", e = e))?;
    let (_, session) = svc
        .open_session("plain", &Value::from(""))
        .await
        .map_err(|e| tr!("связка ключей не открыла сессию: {e}", e = e))?;
    // связка ключей этого же процесса: переносить нечего, это та же папка базы
    if let Ok(dbus) = fdo::DBusProxy::new(&conn).await
        && let Ok(name) = zbus::names::BusName::try_from(NAME)
        && dbus.get_connection_unix_process_id(name).await.ok() == Some(std::process::id())
    {
        return Err(tr!("связкой ключей уже служит этот Keywarden: переносить нечего").into());
    }
    let collections = svc.collections().await.map_err(|e| e.to_string())?;
    // разблокировка; у gnome-keyring откроется его окно с паролем
    let (_, prompt) = svc.unlock(&collections).await.map_err(|e| e.to_string())?;
    if prompt.as_str() != "/" {
        let p = client::PromptProxy::builder(&conn)
            .path(prompt)
            .build()
            .await
            .map_err(|e| e.to_string())?;
        let mut done = p.receive_completed().await.map_err(|e| e.to_string())?;
        p.prompt("").await.map_err(|e| e.to_string())?;
        match tokio::time::timeout(Duration::from_secs(120), done.next()).await {
            Ok(Some(sig)) if !sig.args().map(|a| a.dismissed).unwrap_or(true) => {}
            _ => return Err(tr!("разблокировка связки ключей отменена").into()),
        }
    }
    let mut out = Migrated {
        items: 0,
        skipped: 0,
    };
    for c in collections {
        let col = client::CollectionProxy::builder(&conn)
            .path(c)
            .build()
            .await
            .map_err(|e| e.to_string())?;
        let items = col.items().await.unwrap_or_default();
        if items.is_empty() {
            continue;
        }
        let secrets = svc
            .get_secrets(&items, &session)
            .await
            .map_err(|e| tr!("секреты не выданы: {e}", e = e))?;
        for p in items {
            let item = client::ItemProxy::builder(&conn)
                .path(p.clone())
                .build()
                .await
                .map_err(|e| e.to_string())?;
            let (Some((_, _, value, ct)), Ok(label), Ok(attrs)) =
                (secrets.get(&p), item.label().await, item.attributes().await)
            else {
                out.skipped += 1;
                continue;
            };
            let value = zeroize::Zeroizing::new(value.clone());
            let ct = if ct.is_empty() {
                "text/plain".to_string()
            } else {
                ct.clone()
            };
            let g = group.clone();
            daemon
                .mutate(move |db| secrets::create(db, &g, &label, &attrs, &value, &ct, true))
                .await
                .map_err(|r| match r {
                    keywarden_core::ipc::Response::Error { message, .. } => message,
                    _ => String::new(),
                })?;
            out.items += 1;
        }
    }
    Ok(out)
}

/// Кто сейчас держит org.freedesktop.secrets: путь к программе и «это мы».
pub async fn owner() -> (Option<String>, bool) {
    let Ok(conn) = Connection::session().await else {
        return (None, false);
    };
    let Ok(dbus) = fdo::DBusProxy::new(&conn).await else {
        return (None, false);
    };
    let Ok(name) = zbus::names::BusName::try_from(NAME) else {
        return (None, false);
    };
    match dbus.get_connection_unix_process_id(name).await {
        Ok(pid) => (
            Some(
                std::fs::read_link(format!("/proc/{pid}/exe"))
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| format!("PID {pid}")),
            ),
            pid == std::process::id(),
        ),
        Err(_) => (None, false),
    }
}
