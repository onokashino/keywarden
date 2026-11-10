//! SSH-агент: `ssh.sock` в каталоге демона (Linux, macOS) или именованный канал (Windows,
//! его понимает встроенный OpenSSH через SSH_AUTH_SOCK), см. `kw ssh-env`.
//!
//! - Отдаёт ключи из записей с настройками KeeAgent (как в KeePassXC), пока база открыта;
//!   после блокировки ключей нет, расшифрованные копии выброшены.
//! - Зашифрованные ключи расшифровываются паролем из поля Password записи.
//! - «Подтверждать каждое использование» (UseConfirmConstraintWhenAdding): окно с ключом
//!   и командой клиента (например, `ssh git@github.com`).
//! - Приватный ключ никогда не пишется на диск.
//! - База заблокирована, а ssh просит ключ: окно разблокировки (`keywarden-ui --unlock`), после
//!   разблокировки ssh продолжает сам. Одно окно на все одновременные запросы, после отмены
//!   десять секунд не переспрашиваем.

use crate::confirm::{Decision, Prompt};
use crate::state::Daemon;
use keepass::Database;
use keepass::db::fields;
use keywarden_core::keeagent;
use keywarden_core::model;
#[cfg(windows)]
use ssh_agent_lib::agent::NamedPipeListener;
use ssh_agent_lib::agent::{Agent, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest, signature};
use ssh_key::private::KeypairData;
use ssh_key::{Algorithm, PrivateKey, PublicKey, Signature};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[cfg(windows)]
use tokio::net::windows::named_pipe::NamedPipeServer;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use zeroize::Zeroizing;

/// Ключ, расшифрованный для текущей разблокировки.
struct Loaded {
    entry: String,
    title: String,
    /// хосты из поля «Хост» записи (для ~/.ssh/keywarden/config)
    hosts: Vec<String>,
    confirm: bool,
    key: PrivateKey,
}

/// ((разблокировка, правка), расшифрованные ключи)
type KeyCache = ((u64, u64), Option<Vec<Arc<Loaded>>>);

#[derive(Clone)]
pub struct KeyAgent {
    daemon: Arc<Daemon>,
    /// (эпоха разблокировки, ключи); при блокировке или смене базы сбрасывается
    cache: Arc<Mutex<KeyCache>>,
    /// окно разблокировки одно на всех; внутри время последней отмены
    unlock_prompt: Arc<tokio::sync::Mutex<Option<Instant>>>,
    /// «разрешить на 15 минут»: запись -> (разблокировка, до когда); после блокировки не действует
    allowed: Arc<Mutex<std::collections::HashMap<String, (u64, Instant)>>>,
}

/// Сколько действует «разрешить на время» для ключа с подтверждением.
const ALLOW_MINUTES: u32 = 15;

pub fn socket_path() -> std::path::PathBuf {
    keywarden_core::ipc::endpoint("ssh")
}

pub async fn serve(daemon: Arc<Daemon>) {
    let path = socket_path();
    #[cfg(unix)]
    let listener = {
        let _ = std::fs::remove_file(&path);
        match UnixListener::bind(&path) {
            Ok(l) => {
                let _ = keywarden_core::platform::restrict_to_owner(&path);
                l
            }
            Err(e) => return tracing::error!("SSH-агент: bind {}: {e}", path.display()),
        }
    };
    #[cfg(windows)]
    let listener = match NamedPipeListener::bind(path.as_os_str()) {
        Ok(l) => l,
        Err(e) => return tracing::error!("SSH-агент: канал {}: {e}", path.display()),
    };
    tracing::info!(socket = %path.display(), "SSH-агент слушает (SSH_AUTH_SOCK)");
    let agent = KeyAgent {
        daemon,
        cache: Arc::new(Mutex::new(((u64::MAX, 0), None))),
        unlock_prompt: Default::default(),
        allowed: Default::default(),
    };
    tokio::spawn(host_config_watch(agent.clone()));
    if let Err(e) = ssh_agent_lib::agent::listen(listener, agent).await {
        tracing::error!("SSH-агент остановился: {e}");
    }
}

#[cfg(unix)]
impl Agent<UnixListener> for KeyAgent {
    fn new_session(&mut self, socket: &UnixStream) -> impl Session {
        let cred = socket.peer_cred().ok();
        let trusted = cred
            .as_ref()
            .is_some_and(|c| c.uid() == unsafe { libc::getuid() });
        let client = cred
            .and_then(|c| c.pid())
            .map(client_command)
            .unwrap_or_default();
        KeySession {
            agent: self.clone(),
            trusted,
            client,
            bound: None,
        }
    }
}

#[cfg(windows)]
impl Agent<NamedPipeListener> for KeyAgent {
    fn new_session(&mut self, socket: &NamedPipeServer) -> impl Session {
        use std::os::windows::io::AsRawHandle;
        let mut pid = 0u32;
        let ok = unsafe {
            windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId(
                socket.as_raw_handle() as _,
                &mut pid,
            )
        } != 0;
        // чужой пользователь получит пустой список ключей и отказ в подписи
        let trusted = ok && crate::local::same_user_pid(pid);
        KeySession {
            agent: self.clone(),
            trusted,
            client: String::new(),
            bound: None,
        }
    }
}

/// Команда процесса-клиента для окна подтверждения (`ssh -T git@github.com`); на macOS пусто.
#[cfg(unix)]
fn client_command(pid: i32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|p| !p.is_empty())
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

struct KeySession {
    agent: KeyAgent,
    trusted: bool,
    client: String,
    /// session-bind@openssh.com: ключ сервера (OpenSSH) и проброс ли это агента
    bound: Option<(String, bool)>,
}

impl KeySession {
    /// Куда входят: имя из known_hosts по ключу сервера, иначе None.
    fn server_name(&self) -> Option<String> {
        let (key, _) = self.bound.as_ref()?;
        let known = std::fs::read_to_string(ssh_dir().join("known_hosts")).unwrap_or_default();
        let cands = keywarden_core::ssh_setup::host_candidates(&self.client);
        keywarden_core::ssh_setup::known_host_name(&known, key, &cands)
    }
}

impl KeyAgent {
    /// База открыта; если нет, попросить пользователя её разблокировать и дождаться.
    async fn ensure_unlocked(&self, client: &str) -> bool {
        // агент выключен в настройках: ключей нет, окон тоже
        if !self.daemon.config().ssh_agent {
            return false;
        }
        if self.daemon.is_unlocked() {
            return true;
        }
        if !self.daemon.config().ssh_unlock_prompt {
            return false;
        }
        let mut cancelled = self.unlock_prompt.lock().await;
        // пока ждали своей очереди, базу могли открыть
        if self.daemon.is_unlocked() {
            return true;
        }
        if cancelled.is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
            return false;
        }
        let client: String = client.chars().take(80).collect();
        let reason = if client.is_empty() {
            tr!("SSH просит ключ из хранилища").to_string()
        } else {
            tr!("SSH просит ключ из хранилища: {client}", client = client)
        };
        let _ = tokio::task::spawn_blocking(move || crate::confirm::unlock(&reason)).await;
        let unlocked = self.daemon.is_unlocked();
        *cancelled = (!unlocked).then(Instant::now);
        unlocked
    }

    /// Ключи текущей открытой базы (расшифровываются один раз на разблокировку).
    fn keys(&self) -> Vec<Arc<Loaded>> {
        let Some(stamp) = self.daemon.change_stamp() else {
            *self.cache.lock().unwrap_or_else(|p| p.into_inner()) = ((u64::MAX, 0), None);
            return vec![];
        };
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        // ключ, добавленный или изменённый в открытой базе, виден сразу
        if cache.0 != stamp || cache.1.is_none() {
            let loaded = self.daemon.read(|db| Ok(load_keys(db))).unwrap_or_default();
            *cache = (stamp, Some(loaded.into_iter().map(Arc::new).collect()));
        }
        cache.1.clone().unwrap_or_default()
    }
}

fn load_keys(db: &Database) -> Vec<Loaded> {
    let mut out = vec![];
    for e in db.iter_all_entries() {
        if model::in_recycle_bin(db, e.parent().id()) {
            continue;
        }
        let Some(settings) = e
            .attachment_by_name(model::KEEAGENT_SETTINGS)
            .and_then(|a| keeagent::parse(a.data.get()))
        else {
            continue;
        };
        if !settings.allow_use || !settings.add_at_open {
            continue;
        }
        let pem: Option<Zeroizing<Vec<u8>>> = match (&settings.attachment, &settings.file) {
            (Some(name), _) => e
                .attachment_by_name(name)
                .map(|a| Zeroizing::new(a.data.get().clone())),
            (None, Some(path)) => std::fs::read(path).ok().map(Zeroizing::new),
            _ => None,
        };
        let title = e.get(fields::TITLE).unwrap_or_default().to_string();
        let Some(pem) = pem else {
            tracing::warn!("SSH: у «{title}» нет файла ключа");
            continue;
        };
        let key = match PrivateKey::from_openssh(&*pem) {
            Ok(k) if k.is_encrypted() => {
                match k.decrypt(model::resolve(
                    db,
                    &e,
                    e.get(fields::PASSWORD).unwrap_or_default(),
                )) {
                    Ok(k) => k,
                    Err(_) => {
                        tracing::warn!("SSH: ключ «{title}» не расшифровался паролем из записи");
                        continue;
                    }
                }
            }
            Ok(k) => k,
            Err(err) => {
                tracing::warn!("SSH: ключ «{title}» не в формате OpenSSH: {err}");
                continue;
            }
        };
        out.push(Loaded {
            entry: e.id().uuid().to_string(),
            hosts: keywarden_core::ssh_setup::hosts(&model::resolve(
                db,
                &e,
                e.get(fields::URL).unwrap_or_default(),
            )),
            title,
            confirm: settings.confirm,
            key,
        });
    }
    out
}

#[ssh_agent_lib::async_trait]
impl Session for KeySession {
    /// OpenSSH 8.9+ сообщает, к какому серверу привязано соединение (подпись сервера проверяется).
    async fn extension(
        &mut self,
        ext: ssh_agent_lib::proto::Extension,
    ) -> Result<Option<ssh_agent_lib::proto::Extension>, AgentError> {
        use ssh_agent_lib::proto::extension::SessionBind;
        match ext.parse_message::<SessionBind>() {
            Ok(Some(bind)) if bind.verify_signature().is_ok() => {
                let key = PublicKey::from(bind.host_key.clone())
                    .to_openssh()
                    .unwrap_or_default();
                self.bound = Some((key, bind.is_forwarding));
                Ok(None)
            }
            Ok(Some(_)) => Err(AgentError::Failure),
            _ => Err(AgentError::from(
                ssh_agent_lib::proto::ProtoError::UnsupportedCommand { command: 27 },
            )),
        }
    }

    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        if !self.trusted || !self.agent.ensure_unlocked(&self.client).await {
            return Ok(vec![]);
        }
        Ok(self
            .agent
            .keys()
            .iter()
            .map(|k| Identity {
                credential: k.key.public_key().key_data().clone().into(),
                comment: k.title.clone(),
            })
            .collect())
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        if !self.trusted || !self.agent.ensure_unlocked(&self.client).await {
            return Err(AgentError::Failure);
        }
        let wanted: PublicKey = req.credential.key_data().clone().into();
        let Some(k) = self
            .agent
            .keys()
            .into_iter()
            .find(|k| k.key.public_key().key_data() == wanted.key_data())
        else {
            return Err(AgentError::Failure);
        };
        let epoch = self.agent.daemon.change_stamp().map_or(0, |s| s.0);
        let allowed = self
            .agent
            .allowed
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&k.entry)
            .is_some_and(|(e, until)| *e == epoch && Instant::now() < *until);
        if k.confirm && !allowed {
            let forwarded = self.bound.as_ref().is_some_and(|(_, f)| *f);
            let title = match self.server_name() {
                Some(host) => tr!(
                    "Вход на {host} ключом «{title}»",
                    host = host,
                    title = k.title
                ),
                None => tr!("Подпись SSH-ключом «{title}»", title = k.title),
            };
            let mut text = vec![if self.client.is_empty() {
                tr!("Неизвестный процесс просит подпись.").to_string()
            } else {
                tr!("Кто просит: {client}", client = self.client)
            }];
            if forwarded {
                text.push(
                    tr!("Запрос пришёл через проброс агента с другого сервера: разрешайте, только если ждёте его")
                        .to_string(),
                );
            }
            text.push(k.key.fingerprint(Default::default()).to_string());
            let prompt = Prompt {
                title,
                text: text.join("\n"),
                allow_always: true,
                always_minutes: Some(ALLOW_MINUTES),
            };
            let cmd = self.agent.daemon.config().confirm_command;
            let decision =
                tokio::task::spawn_blocking(move || crate::confirm::ask(cmd.as_deref(), &prompt))
                    .await
                    .unwrap_or(Decision::Deny);
            match decision {
                Decision::Deny => {
                    tracing::info!("SSH: подпись ключом «{}» отклонена пользователем", k.title);
                    return Err(AgentError::Failure);
                }
                Decision::Always => {
                    let until = Instant::now() + Duration::from_secs(u64::from(ALLOW_MINUTES) * 60);
                    self.agent
                        .allowed
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .insert(k.entry.clone(), (epoch, until));
                }
                Decision::Once => {}
            }
        }
        tracing::info!(entry = %k.entry, "SSH: подпись ключом «{}»", k.title);
        sign(&k.key, &req.data, req.flags).map_err(|e| AgentError::Other(e.into()))
    }
}

fn ssh_dir() -> std::path::PathBuf {
    keywarden_core::platform::home().join(".ssh")
}

/// Включить или выключить строку Include в ~/.ssh/config; при выключении убрать и наш каталог.
pub fn set_host_config(on: bool) {
    use keywarden_core::ssh_setup::{with_include, without_include};
    let dir = ssh_dir();
    let config = dir.join("config");
    let res = (|| -> std::io::Result<()> {
        keywarden_core::platform::create_private_dir(&dir)?;
        let existed = config.exists();
        let text = std::fs::read_to_string(&config).unwrap_or_default();
        let new = if on {
            with_include(&text)
        } else {
            without_include(&text)
        };
        if new != text {
            std::fs::write(&config, new)?;
            if !existed {
                keywarden_core::platform::restrict_to_owner(&config)?;
            }
        }
        if !on {
            match std::fs::remove_dir_all(dir.join("keywarden")) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(())
    })();
    if let Err(e) = res {
        tracing::warn!("SSH: ~/.ssh/config: {e}");
    }
}

/// Держит ~/.ssh/keywarden/ в соответствии с ключами базы, пока настройка включена.
async fn host_config_watch(agent: KeyAgent) {
    let mut last: Option<(u64, u64)> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tick.tick().await;
        let c = agent.daemon.config();
        if !c.ssh_agent || !c.ssh_host_config {
            last = None;
            continue;
        }
        let stamp = agent.daemon.change_stamp();
        if stamp.is_none() || stamp == last {
            continue;
        }
        last = stamp;
        let hosts = agent
            .daemon
            .read(|db| Ok(load_hosts(db)))
            .unwrap_or_default();
        if let Err(e) = write_host_config(&agent.keys(), &hosts) {
            tracing::warn!("SSH: ~/.ssh/keywarden: {e}");
        }
    }
}

fn write_host_config(keys: &[Arc<Loaded>], hosts: &[HostRec]) -> std::io::Result<()> {
    use keywarden_core::ssh_setup::{key_file_name, render_config};
    let dir = ssh_dir().join("keywarden");
    keywarden_core::platform::create_private_dir(&dir)?;
    let mut files: Vec<String> = vec![];
    let mut blocks: Vec<(String, Vec<String>)> = vec![];
    // файл открытого ключа: по названию записи ключа (на него ссылаются «Серверы SSH»)
    let mut by_title: std::collections::HashMap<&str, String> = Default::default();
    let wanted = |k: &Loaded| hosts.iter().any(|h| h.key.as_deref() == Some(&k.title));
    for k in keys.iter().filter(|k| !k.hosts.is_empty() || wanted(k)) {
        let name = key_file_name(&k.title, &files);
        by_title.entry(&k.title).or_insert_with(|| name.clone());
        let public = k
            .key
            .public_key()
            .to_openssh()
            .map_err(std::io::Error::other)?;
        std::fs::write(
            dir.join(&name),
            format!("{public} {}\n", k.title.replace(['\n', '\r'], " ")),
        )?;
        for h in &k.hosts {
            match blocks.iter_mut().find(|(host, _)| host == h) {
                Some((_, f)) => f.push(name.clone()),
                None => blocks.push((h.clone(), vec![name.clone()])),
            }
        }
        files.push(name);
    }
    // ключи, которых больше нет в базе
    for e in std::fs::read_dir(&dir)?.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.ends_with(".pub") && !files.contains(&n) {
            let _ = std::fs::remove_file(e.path());
        }
    }
    let mut text = render_config(&blocks, &socket_path());
    let kw = kw_path();
    for h in hosts {
        let mut b = h.block();
        b.key_file = h.key.as_deref().and_then(|t| by_title.get(t).cloned());
        if h.key.is_some() && b.key_file.is_none() {
            tracing::warn!(
                "SSH: у «{}» нет ключа «{}» в базе",
                h.title,
                h.key.as_deref().unwrap_or_default()
            );
        }
        text.push_str(&keywarden_core::ssh_hosts::render_host(
            &b,
            &socket_path(),
            &kw,
        ));
    }
    std::fs::write(dir.join("config"), text)
}

/// `kw` рядом с демоном (его вызывает `Match exec` для стука), иначе имя из PATH.
pub fn kw_path() -> std::path::PathBuf {
    let name = format!("kw{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(&name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| name.into())
}

/// Запись «Сервер SSH».
#[derive(Debug, Clone)]
pub struct HostRec {
    pub id: String,
    pub title: String,
    pub alias: String,
    pub group: String,
    pub address: keywarden_core::ssh_hosts::Address,
    pub key: Option<String>,
    pub proxy: Option<String>,
    pub forward: String,
    pub options: String,
    /// последовательность портов (секрет: наружу только в стук)
    pub knock: zeroize::Zeroizing<String>,
}

impl HostRec {
    pub fn block(&self) -> keywarden_core::ssh_hosts::HostBlock {
        use keywarden_core::ssh_hosts as h;
        h::HostBlock {
            alias: self.alias.clone(),
            address: self.address.clone(),
            key_file: None,
            proxy: self.proxy.clone(),
            forwards: h::forwards(&self.forward),
            options: h::options(&self.options),
            knock: !self.knock.trim().is_empty(),
        }
    }

    /// Аргументы ssh без нашего конфига: всё явно.
    pub fn explicit_args(&self) -> Vec<String> {
        let b = self.block();
        let mut a: Vec<String> = vec![];
        if let Some(p) = b.address.port {
            a.extend(["-p".into(), p.to_string()]);
        }
        if let Some(j) = b.proxy.filter(|j| keywarden_core::ssh_hosts::proxy_ok(j)) {
            a.extend(["-J".into(), j]);
        }
        for (l, r) in b.forwards {
            a.extend(["-L".into(), format!("{l}:{r}")]);
        }
        for o in b.options {
            let o = match o.split_once(|c: char| c.is_whitespace() || c == '=') {
                Some((k, v)) => format!("{k}={}", v.trim().trim_start_matches('=').trim()),
                None => o,
            };
            a.extend(["-o".into(), o]);
        }
        let mut target = b.address.clone();
        target.port = None;
        a.push(target.display());
        a
    }
}

/// Записи «Сервер SSH» вне корзины; одинаковое имя: побеждает первая (как в ssh_config).
pub fn load_hosts(db: &Database) -> Vec<HostRec> {
    use keywarden_core::ssh_hosts as h;
    let mut out: Vec<HostRec> = vec![];
    for e in db.iter_all_entries() {
        if model::kind_of(&e) != model::EntryKind::SshHost
            || model::in_recycle_bin(db, e.parent().id())
        {
            continue;
        }
        let get = |name: &str| model::resolve(db, &e, e.get(name).unwrap_or_default());
        let some = |v: String| Some(v.trim().to_string()).filter(|v| !v.is_empty());
        let title = get(fields::TITLE);
        let (Some(alias), Some(address)) = (h::alias(&title), h::address(&get(fields::URL))) else {
            continue;
        };
        if out.iter().any(|o| o.alias.eq_ignore_ascii_case(&alias)) {
            tracing::warn!("SSH: имя «{alias}» уже занято другой записью, «{title}» пропущена");
            continue;
        }
        out.push(HostRec {
            id: e.id().uuid().to_string(),
            group: model::group_path(db, e.parent().id()),
            alias,
            address,
            key: some(get(h::KEY)),
            proxy: some(get(h::PROXY)),
            forward: get(h::FORWARD),
            options: get(h::OPTIONS),
            knock: zeroize::Zeroizing::new(get(h::KNOCK)),
            title,
        });
    }
    out
}

/// Открытая часть ключа с диска: файл `.pub` рядом, иначе заголовок приватного файла
/// (открытый ключ в нём не зашифрован). Ответ: «тип base64».
pub fn disk_public_key(path: &std::path::Path) -> Option<String> {
    let pub_path = std::path::PathBuf::from(format!("{}.pub", path.display()));
    let text = std::fs::read_to_string(&pub_path).ok().or_else(|| {
        let data = std::fs::read(path).ok().filter(|d| d.len() < 16 * 1024)?;
        PrivateKey::from_openssh(&data)
            .ok()?
            .public_key()
            .to_openssh()
            .ok()
    })?;
    keywarden_core::git_signing::key_body(text.trim())
}

/// Название записи ключа в базе по открытому ключу («тип base64»).
pub fn vault_key_titles(db: &Database) -> Vec<(String, String)> {
    load_keys(db)
        .iter()
        .filter_map(|k| {
            let body =
                keywarden_core::git_signing::key_body(&k.key.public_key().to_openssh().ok()?)?;
            Some((body, k.title.clone()))
        })
        .collect()
}

/// `~` в начале пути IdentityFile.
pub fn expand_home(p: &str) -> std::path::PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => keywarden_core::platform::home().join(rest),
        None => p.into(),
    }
}

/// Хост ~/.ssh/config и что из него получится в базе.
pub struct Planned {
    pub host: keywarden_core::ssh_hosts::ConfigHost,
    /// папка от корня: ["SSH", "prod"]
    pub folder: Vec<String>,
    /// запись ключа в базе, если IdentityFile уже перенесён
    pub key: Option<String>,
    /// сервер с таким именем уже есть
    pub in_vault: bool,
}

/// План переноса ~/.ssh/config: папка «SSH» с автопапками по именам, ключи по открытому
/// ключу IdentityFile (`keys`: путь -> «тип base64» с диска).
pub fn plan_config(
    db: &Database,
    hosts: &[keywarden_core::ssh_hosts::ConfigHost],
    keys: &[(String, String)],
) -> Vec<Planned> {
    use keywarden_core::ssh_hosts as h;
    let titles = vault_key_titles(db);
    let taken: Vec<String> = load_hosts(db).into_iter().map(|h| h.alias).collect();
    let in_vault = |c: &h::ConfigHost| taken.iter().any(|t| t.eq_ignore_ascii_case(&c.alias));
    let pairs: Vec<(String, String)> = hosts
        .iter()
        .filter(|c| !in_vault(c))
        .map(|c| (c.alias.clone(), c.address().host))
        .collect();
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let groups = h::auto_groups(&refs);
    let any = groups.iter().any(Option::is_some);
    let mut groups = groups.into_iter();
    hosts
        .iter()
        .map(|c| {
            let mut folder = vec!["SSH".to_string()];
            let exists = in_vault(c);
            if !exists {
                let g = groups.next().flatten();
                if any {
                    folder.push(g.unwrap_or_else(|| tr!("Прочие").to_string()));
                }
            }
            let key = c.identity.as_ref().and_then(|i| {
                let body = keys.iter().find(|(p, _)| p == i).map(|(_, b)| b)?;
                titles
                    .iter()
                    .find(|(b, _)| b == body)
                    .map(|(_, t)| t.clone())
            });
            Planned {
                host: c.clone(),
                folder,
                key,
                in_vault: exists,
            }
        })
        .collect()
}

/// Перенести хосты плана в записи «Сервер SSH»; `only`: только эти имена.
/// Ответ: (добавлено, пропущено как уже перенесённые).
pub fn import_config(
    db: &mut Database,
    plan: &[Planned],
    only: Option<&[String]>,
) -> model::Result<(usize, usize)> {
    use keywarden_core::ssh_hosts as h;
    let mut taken: Vec<String> = load_hosts(db).into_iter().map(|h| h.alias).collect();
    let (mut added, mut skipped) = (0, 0);
    for p in plan {
        let c = &p.host;
        if only.is_some_and(|o| !o.iter().any(|a| a == &c.alias)) {
            continue;
        }
        if taken.iter().any(|t| t.eq_ignore_ascii_case(&c.alias)) {
            skipped += 1;
            continue;
        }
        let group = ensure_group(db, &p.folder)?;
        let mut options = c.other.clone();
        // ключа нет в базе: ssh по-прежнему берёт его с диска
        if let (None, Some(i)) = (&p.key, &c.identity) {
            options.push(format!("IdentityFile {i}"));
        }
        let mut set = vec![
            model::FieldSet::new(fields::TITLE, c.alias.clone()),
            model::FieldSet::new(fields::URL, c.address().display()),
            model::FieldSet::new(h::FORWARD, c.forwards.join(", ")),
            model::FieldSet::new(h::OPTIONS, options.join("; ")),
        ];
        if let Some(k) = &p.key {
            set.push(model::FieldSet::new(h::KEY, k.clone()));
        }
        if let Some(px) = &c.proxy {
            set.push(model::FieldSet::new(h::PROXY, px.clone()));
        }
        model::create_entry(
            db,
            &model::EntryPatch {
                kind: Some(model::EntryKind::SshHost),
                group: Some(group),
                set,
                ..Default::default()
            },
        )?;
        taken.push(c.alias.clone());
        added += 1;
    }
    Ok((added, skipped))
}

/// IdentityFile хостов -> открытый ключ с диска (читается файл .pub или заголовок ключа).
pub fn identity_keys(hosts: &[keywarden_core::ssh_hosts::ConfigHost]) -> Vec<(String, String)> {
    hosts
        .iter()
        .filter_map(|h| h.identity.clone())
        .filter_map(|p| Some((p.clone(), disk_public_key(&expand_home(&p))?)))
        .collect()
}

/// Папка по пути от корня; недостающие создаются.
fn ensure_group(db: &mut Database, path: &[String]) -> model::Result<String> {
    let mut parent: Option<String> = None;
    for i in 0..path.len() {
        let want = path[..=i].join("/");
        let found = model::groups(db)
            .into_iter()
            .find(|g| g.path == want && !g.is_recycle_bin)
            .map(|g| g.id);
        parent = Some(match found {
            Some(id) => id,
            None => model::add_group(db, parent.as_deref(), &path[i])?,
        });
    }
    parent.ok_or(model::ModelError::GroupNotFound)
}

pub fn ssh_config_text() -> String {
    std::fs::read_to_string(ssh_dir().join("config")).unwrap_or_default()
}

fn sign(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Signature, String> {
    use ::signature::Signer;
    match key.key_data() {
        // ssh-key 0.6.7 собирает RSA-ключ из (p, p) вместо (p, q): подписываем сами
        KeypairData::Rsa(k) => {
            use rsa::pkcs1v15::SigningKey;
            use rsa::signature::{SignatureEncoding, Signer as _};
            let n = |v: &ssh_key::Mpint| rsa::BigUint::try_from(v).map_err(|e| e.to_string());
            let private = rsa::RsaPrivateKey::from_components(
                n(&k.public.n)?,
                n(&k.public.e)?,
                n(&k.private.d)?,
                vec![n(&k.private.p)?, n(&k.private.q)?],
            )
            .map_err(|e| e.to_string())?;
            let (alg, bytes) = if flags & signature::RSA_SHA2_512 != 0 {
                (
                    "rsa-sha2-512",
                    SigningKey::<sha2::Sha512>::new(private).sign(data).to_vec(),
                )
            } else if flags & signature::RSA_SHA2_256 != 0 {
                (
                    "rsa-sha2-256",
                    SigningKey::<sha2::Sha256>::new(private).sign(data).to_vec(),
                )
            } else {
                (
                    "ssh-rsa",
                    SigningKey::<sha1::Sha1>::new(private).sign(data).to_vec(),
                )
            };
            Signature::new(Algorithm::new(alg).map_err(|e| e.to_string())?, bytes)
                .map_err(|e| e.to_string())
        }
        _ => key.try_sign(data).map_err(|e| e.to_string()),
    }
}

/// Новый ключ ed25519 в формате OpenSSH (без пароля: его защищает сама база).
/// Алгоритмы нового ключа: имя в запросе и имя файла, как у ssh-keygen.
pub fn algorithm(name: &str) -> Result<(Algorithm, &'static str), String> {
    Ok(match name {
        "" | "ed25519" => (Algorithm::Ed25519, "id_ed25519"),
        "ecdsa" => (
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
            "id_ecdsa",
        ),
        "rsa" => (Algorithm::Rsa { hash: None }, "id_rsa"),
        other => return Err(tr!("неизвестный алгоритм: {other}", other = other)),
    })
}

/// Новый ключ OpenSSH без пароля (RSA 4096 считается секунды: вызывать вне async).
pub fn generate(comment: &str, algorithm: Algorithm) -> Result<Vec<u8>, String> {
    let mut key =
        PrivateKey::random(&mut rand_core::OsRng, algorithm).map_err(|e| e.to_string())?;
    key.set_comment(comment);
    let pem = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| e.to_string())?;
    Ok(pem.as_bytes().to_vec())
}

/// Открытые ключи всех ключей SSH базы («тип base64», без комментария).
pub fn vault_public_keys(db: &Database) -> Vec<String> {
    load_keys(db)
        .iter()
        .filter_map(|k| k.key.public_key().to_openssh().ok())
        .filter_map(|p| keywarden_core::git_signing::key_body(&p))
        .collect()
}

/// Приватные ключи OpenSSH в ~/.ssh (по заголовку файла, без захода в подкаталоги).
pub fn local_keys(in_vault: &[String]) -> Vec<keywarden_core::ipc::LocalSshKey> {
    let mut out = vec![];
    let Ok(dir) = std::fs::read_dir(ssh_dir()) else {
        return out;
    };
    for e in dir.flatten() {
        let path = e.path();
        if !path.is_file() || path.extension().is_some_and(|x| x == "pub") {
            continue;
        }
        // приватный ключ OpenSSH меньше 16 КиБ; большие файлы не читаем
        if e.metadata().map_or(true, |m| m.len() > 16 * 1024) {
            continue;
        }
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(key) = PrivateKey::from_openssh(&data) else {
            continue;
        };
        let public = key.public_key();
        let body = public
            .to_openssh()
            .ok()
            .and_then(|p| keywarden_core::git_signing::key_body(&p))
            .unwrap_or_default();
        out.push(keywarden_core::ipc::LocalSshKey {
            path: path.to_string_lossy().into_owned(),
            comment: public.comment().to_string(),
            fingerprint: public.fingerprint(Default::default()).to_string(),
            algorithm: algorithm_label(public.key_data()),
            in_vault: in_vault.contains(&body),
            encrypted: key.is_encrypted(),
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// Короткое имя алгоритма для списка ключей: «ed25519», «ecdsa», «rsa 3072».
fn algorithm_label(k: &ssh_key::public::KeyData) -> String {
    match k {
        ssh_key::public::KeyData::Rsa(r) => {
            // длина модуля в битах без ведущих нулей
            let n = r.n.as_positive_bytes().unwrap_or_default();
            format!("rsa {}", n.len() * 8)
        }
        ssh_key::public::KeyData::Ecdsa(_) => "ecdsa".into(),
        ssh_key::public::KeyData::Ed25519(_) => "ed25519".into(),
        other => other.algorithm().as_str().to_string(),
    }
}

/// Импорт ключа из файла OpenSSH в запись (для kw ssh-import): проверка формата и пароля.
pub fn check_key(pem: &[u8], passphrase: &str) -> Result<String, String> {
    let k = PrivateKey::from_openssh(pem).map_err(|e| tr!("не ключ OpenSSH: {e}", e = e))?;
    let k = if k.is_encrypted() {
        k.decrypt(passphrase)
            .map_err(|_| tr!("неверный пароль ключа").to_string())?
    } else {
        k
    };
    k.public_key().to_openssh().map_err(|e| e.to_string())
}
