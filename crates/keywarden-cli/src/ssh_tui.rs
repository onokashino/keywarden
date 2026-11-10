//! `kw ssh`: выбор сервера в терминале. Слева папки (папки базы и ~/.ssh/config, разложенный
//! автоматически по именам), справа хосты, внизу подробности. Enter входит (ssh заменяет kw),
//! остальные действия на клавишах, `?` показывает все.
//!
//! Хосты: записи «Сервер SSH», адреса из записей «Ключ SSH» и ~/.ssh/config (хосты, уже
//! перенесённые в базу, из него не повторяются).
//!
//! Приватные ключи не читаются: из ~/.ssh/config берётся только имя файла IdentityFile.

use keywarden_core::ipc::SshHost;
use keywarden_core::model::{EntryKind, EntrySummary};
use keywarden_core::tr;
use keywarden_core::{ssh_hosts, ssh_setup};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, List, ListItem, ListState, Paragraph};
use std::collections::HashSet;

/// Корневая папка хостов из ~/.ssh/config.
pub const SSH_CONFIG: &str = "~/.ssh/config";

#[derive(Debug, Clone, PartialEq)]
pub enum Source {
    /// адрес из поля «Хост» записи «Ключ SSH»; url: всё поле целиком (для правки)
    Vault {
        id: String,
        url: String,
    },
    /// запись «Сервер SSH»; knock_first: стучать перед ssh самим (конфиг Keywarden выключен)
    Server {
        id: String,
        alias: String,
        knock_first: bool,
    },
    Config,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Host {
    /// путь папки: ["Работа", "prod"]
    pub folder: Vec<String>,
    /// название записи или имя из ~/.ssh/config
    pub name: String,
    /// куда: user@host:port
    pub target: String,
    /// аргументы ssh
    pub args: Vec<String>,
    /// какой ключ: запись базы или имя файла IdentityFile
    pub key: Option<String>,
    pub proxy: Option<String>,
    /// «8080 → localhost:80»
    pub forwards: Vec<String>,
    pub knock: bool,
    /// адрес как записан: часть поля «Хост» или псевдоним из config
    pub address: String,
    pub source: Source,
}

impl Host {
    fn path(&self) -> String {
        self.folder.join(" / ")
    }
}

/// Хосты из записей «Ключ SSH»: каждый адрес из поля «Хост» отдельной строкой.
pub fn from_vault(entries: &[EntrySummary]) -> Vec<Host> {
    let mut out = vec![];
    for e in entries.iter().filter(|e| e.kind == EntryKind::SshKey) {
        for part in addresses(&e.url) {
            let Some(args) = ssh_setup::ssh_args(part) else {
                continue;
            };
            let folder = if e.group.is_empty() {
                vec![tr!("Без папки").to_string()]
            } else {
                e.group.split('/').map(str::to_string).collect()
            };
            out.push(Host {
                folder,
                name: e.title.clone(),
                target: part.split_once("://").map_or(part, |(_, r)| r).to_string(),
                args,
                key: Some(e.title.clone()),
                proxy: None,
                forwards: vec![],
                knock: false,
                address: part.to_string(),
                source: Source::Vault {
                    id: e.id.clone(),
                    url: e.url.clone(),
                },
            });
        }
    }
    out
}

fn addresses(field: &str) -> impl Iterator<Item = &str> {
    field
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
}

/// Записи «Сервер SSH»: папка из группы базы, аргументы ssh от демона.
pub fn from_servers(servers: &[SshHost]) -> Vec<Host> {
    servers
        .iter()
        .map(|h| Host {
            folder: if h.group.is_empty() {
                vec![tr!("Без папки").to_string()]
            } else {
                h.group.split('/').map(str::to_string).collect()
            },
            name: h.alias.clone(),
            target: h.address.clone(),
            args: h.args.clone(),
            key: h.key.clone(),
            proxy: h.proxy.clone(),
            forwards: h.forwards.clone(),
            knock: h.knock,
            address: h.address.clone(),
            source: Source::Server {
                id: h.id.clone(),
                alias: h.alias.clone(),
                knock_first: h.knock_first,
            },
        })
        .collect()
}

/// Хосты из ~/.ssh/config: псевдонимы из строк Host без масок; для подписи HostName, User,
/// Port, ProxyJump и имя файла IdentityFile. Разложены по папкам автоматически.
pub fn from_ssh_config(text: &str) -> Vec<Host> {
    let mut out: Vec<Host> = ssh_hosts::parse_config(text)
        .into_iter()
        .map(|c| Host {
            folder: vec![SSH_CONFIG.into()],
            name: c.alias.clone(),
            target: c.address().display(),
            args: vec![c.alias.clone()],
            key: c.identity.as_deref().map(|f| {
                std::path::Path::new(f)
                    .file_name()
                    .map_or(f.to_string(), |n| n.to_string_lossy().into_owned())
            }),
            proxy: c.proxy.clone(),
            forwards: c
                .forwards
                .iter()
                .filter_map(|f| ssh_hosts::forward(f))
                .map(|(l, r)| format!("{l} → {r}"))
                .collect(),
            knock: false,
            address: c.alias,
            source: Source::Config,
        })
        .collect();
    auto_group(&mut out);
    out
}

/// Папки ~/.ssh/config: по общему префиксу имени или домену (см. ssh_hosts::auto_groups);
/// без единой группы хосты лежат прямо в ~/.ssh/config, без лишней папки «Прочие».
pub fn auto_group(hosts: &mut [Host]) {
    let pairs: Vec<(String, String)> = hosts
        .iter()
        .map(|h| {
            let host = h.target.rsplit('@').next().unwrap_or_default();
            (
                h.name.clone(),
                host.split(':').next().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let groups = ssh_hosts::auto_groups(&refs);
    let any = groups.iter().any(Option::is_some);
    for (h, g) in hosts.iter_mut().zip(groups) {
        h.folder = vec![SSH_CONFIG.into()];
        if any {
            h.folder
                .push(g.unwrap_or_else(|| tr!("Прочие").to_string()));
        }
    }
}

/// Все хосты экрана: серверы базы, адреса ключей, затем ~/.ssh/config без перенесённых в базу.
pub fn all_hosts(keys: &[EntrySummary], servers: &[SshHost], config: &str) -> Vec<Host> {
    let mut hosts = from_servers(servers);
    hosts.extend(from_vault(keys));
    hosts.extend(from_ssh_config(config).into_iter().filter(|c| {
        !servers
            .iter()
            .any(|s| s.alias.eq_ignore_ascii_case(&c.name))
    }));
    hosts
}

/// Подходит ли хост под запрос: все слова в названии, адресе, папке или ключе.
pub fn matches(h: &Host, query: &str) -> bool {
    let hay = format!(
        "{} {} {} {}",
        h.name,
        h.target,
        h.path(),
        h.key.as_deref().unwrap_or_default()
    )
    .to_lowercase();
    query
        .to_lowercase()
        .split_whitespace()
        .all(|w| hay.contains(w))
}

// --- дерево папок ---

#[derive(Debug, Clone, PartialEq)]
struct Node {
    /// пустой путь: «Все хосты»
    path: Vec<String>,
    count: usize,
    has_children: bool,
}

/// Папки по алфавиту, «Без папки» после них, ~/.ssh/config последним; детей свёрнутых не видно.
fn tree(hosts: &[Host], collapsed: &HashSet<Vec<String>>) -> Vec<Node> {
    let mut paths: Vec<Vec<String>> = vec![];
    for h in hosts {
        for i in 1..=h.folder.len() {
            let p = h.folder[..i].to_vec();
            if !paths.contains(&p) {
                paths.push(p);
            }
        }
    }
    paths.sort_by_key(|p| folder_order(p));
    let mut out = vec![Node {
        path: vec![],
        count: hosts.len(),
        has_children: true,
    }];
    for p in &paths {
        if (1..p.len()).any(|i| collapsed.contains(&p[..i].to_vec())) {
            continue;
        }
        out.push(Node {
            path: p.clone(),
            count: hosts.iter().filter(|h| h.folder.starts_with(p)).count(),
            has_children: paths.iter().any(|q| q.len() > p.len() && q.starts_with(p)),
        });
    }
    out
}

/// Порядок папок: свои по алфавиту, «Без папки» и «Прочие» после них, ~/.ssh/config последним.
fn folder_order(path: &[String]) -> Vec<(u8, String)> {
    let (no_folder, other) = (tr!("Без папки"), tr!("Прочие"));
    path.iter()
        .map(|s| {
            let rank = match s.as_str() {
                SSH_CONFIG => 2,
                s if s == no_folder || s == other => 1,
                _ => 0,
            };
            (rank, s.to_lowercase())
        })
        .collect()
}

/// Хосты справа: при поиске совпадения из всех папок, иначе из выбранной папки и вложенных.
fn visible(hosts: &[Host], folder: &[String], query: &str) -> Vec<usize> {
    let mut v: Vec<usize> = (0..hosts.len())
        .filter(|&i| {
            if query.trim().is_empty() {
                hosts[i].folder.starts_with(folder)
            } else {
                matches(&hosts[i], query)
            }
        })
        .collect();
    v.sort_by_key(|&i| (folder_order(&hosts[i].folder), hosts[i].name.to_lowercase()));
    v
}

// --- экран ---

/// Чем закончился выбор.
pub enum Exit {
    Quit,
    /// заменить kw этой программой; note печатается перед запуском
    Exec {
        program: &'static str,
        args: Vec<String>,
        note: Option<String>,
    },
}

/// Доступ к базе из экрана: перечитать записи, поменять поле «Хост», терминал из настроек.
pub trait Backend {
    fn entries(&mut self) -> anyhow::Result<Vec<EntrySummary>>;
    /// записи «Сервер SSH»
    fn servers(&mut self) -> anyhow::Result<Vec<SshHost>>;
    /// постучать по портам сервера (последовательность знает только демон)
    fn knock(&mut self, alias: &str) -> anyhow::Result<()>;
    fn set_url(&mut self, id: &str, url: String) -> anyhow::Result<()>;
    fn terminal(&mut self) -> Vec<String>;
}

#[derive(Clone, Copy, PartialEq)]
enum Pane {
    Folders,
    Hosts,
}

enum Mode {
    Normal,
    Search,
    Help,
    /// строка ввода: правка адреса, новый адрес, проброс порта
    Prompt {
        kind: Ask,
        input: String,
    },
    /// выбор ключа для нового адреса
    PickKey {
        address: String,
        sel: usize,
    },
}

#[derive(Clone)]
enum Ask {
    Edit(usize),
    New,
    Forward(usize),
}

struct App {
    hosts: Vec<Host>,
    keys: Vec<EntrySummary>,
    config: String,
    query: String,
    pane: Pane,
    folder_sel: usize,
    host_sel: usize,
    collapsed: HashSet<Vec<String>>,
    mode: Mode,
    status: Option<(String, bool)>,
}

impl App {
    fn new(keys: Vec<EntrySummary>, servers: &[SshHost], config: String) -> Self {
        Self {
            hosts: all_hosts(&keys, servers, &config),
            keys,
            config,
            query: String::new(),
            pane: Pane::Hosts,
            folder_sel: 0,
            host_sel: 0,
            collapsed: HashSet::new(),
            mode: Mode::Normal,
            status: None,
        }
    }

    fn nodes(&self) -> Vec<Node> {
        tree(&self.hosts, &self.collapsed)
    }

    fn folder(&self) -> Vec<String> {
        self.nodes()
            .get(self.folder_sel)
            .map(|n| n.path.clone())
            .unwrap_or_default()
    }

    fn shown(&self) -> Vec<usize> {
        visible(&self.hosts, &self.folder(), &self.query)
    }

    fn current(&self) -> Option<usize> {
        self.shown().get(self.host_sel).copied()
    }

    fn reload(&mut self, b: &mut dyn Backend) {
        match b.entries().and_then(|e| Ok((b.servers()?, e))) {
            Ok((servers, e)) => {
                self.hosts = all_hosts(&e, &servers, &self.config);
                self.keys = e;
            }
            Err(e) => self.status = Some((e.to_string(), true)),
        }
    }
}

pub fn pick(b: &mut dyn Backend, config: String) -> anyhow::Result<Exit> {
    let servers = b.servers()?;
    let mut app = App::new(b.entries()?, &servers, config);
    let mut terminal = ratatui::init();
    let res = run(&mut terminal, &mut app, b);
    ratatui::restore();
    res
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    b: &mut dyn Backend,
) -> anyhow::Result<Exit> {
    loop {
        let n_hosts = app.shown().len();
        app.host_sel = app.host_sel.min(n_hosts.saturating_sub(1));
        app.folder_sel = app.folder_sel.min(app.nodes().len().saturating_sub(1));
        terminal.draw(|f| draw(f, app))?;
        let Event::Key(k) = event::read()? else {
            continue;
        };
        if k.kind != KeyEventKind::Press {
            continue;
        }
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            return Ok(Exit::Quit);
        }
        if let Some(exit) = key(app, b, k.code)? {
            return Ok(exit);
        }
    }
}

fn step(sel: &mut usize, len: usize, code: KeyCode) -> bool {
    let last = len.saturating_sub(1);
    *sel = match code {
        KeyCode::Up | KeyCode::Char('k') => sel.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => (*sel + 1).min(last),
        KeyCode::PageUp => sel.saturating_sub(10),
        KeyCode::PageDown => (*sel + 10).min(last),
        KeyCode::Home | KeyCode::Char('g') => 0,
        KeyCode::End | KeyCode::Char('G') => last,
        _ => return false,
    };
    true
}

/// sftp понимает те же аргументы, кроме порта: -P вместо -p.
fn sftp_args(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|a| if a == "-p" { "-P".into() } else { a.clone() })
        .collect()
}

fn command_line(args: &[String]) -> String {
    format!("ssh {}", args.join(" "))
}

/// Скопировать строку: wl-copy, xclip, pbcopy или clip, что найдётся.
fn copy(text: &str) -> bool {
    use std::io::Write;
    let tools: [(&str, &[&str]); 4] = [
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("pbcopy", &[]),
        ("clip", &[]),
    ];
    tools.iter().any(|(cmd, args)| {
        let Ok(mut child) = std::process::Command::new(cmd)
            .args(*args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return false;
        };
        let ok = child
            .stdin
            .take()
            .is_some_and(|mut i| i.write_all(text.as_bytes()).is_ok());
        ok && child.wait().is_ok_and(|s| s.success())
    })
}

fn bad_address() -> String {
    tr!("Не похоже на адрес: user@host, host:2222 или ssh://user@host:port").into()
}

fn key(app: &mut App, b: &mut dyn Backend, code: KeyCode) -> anyhow::Result<Option<Exit>> {
    app.status = None;
    match &mut app.mode {
        Mode::Help => {
            app.mode = Mode::Normal;
            return Ok(None);
        }
        Mode::Search => {
            match code {
                KeyCode::Esc => {
                    app.query.clear();
                    app.mode = Mode::Normal;
                }
                KeyCode::Enter | KeyCode::Down => {
                    app.mode = Mode::Normal;
                    app.pane = Pane::Hosts;
                }
                KeyCode::Backspace => {
                    app.query.pop();
                }
                KeyCode::Char(c) => {
                    app.query.push(c);
                    app.host_sel = 0;
                }
                _ => {}
            }
            return Ok(None);
        }
        Mode::Prompt { kind, input } => {
            match code {
                KeyCode::Esc => app.mode = Mode::Normal,
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(c) => input.push(c),
                KeyCode::Enter => {
                    let (kind, input) = (kind.clone(), input.trim().to_string());
                    app.mode = Mode::Normal;
                    return prompt_done(app, b, kind, input);
                }
                _ => {}
            }
            return Ok(None);
        }
        Mode::PickKey { address, sel } => {
            let keys: Vec<&EntrySummary> = app
                .keys
                .iter()
                .filter(|e| e.kind == EntryKind::SshKey)
                .collect();
            match code {
                KeyCode::Esc => app.mode = Mode::Normal,
                KeyCode::Enter => {
                    if let Some(e) = keys.get(*sel) {
                        let url = addresses(&e.url)
                            .chain([address.as_str()])
                            .collect::<Vec<_>>()
                            .join(", ");
                        let (id, title) = (e.id.clone(), e.title.clone());
                        app.mode = Mode::Normal;
                        save_url(
                            app,
                            b,
                            &id,
                            url,
                            tr!("Добавлено к ключу «{title}»", title = title),
                        );
                    }
                }
                c => {
                    step(sel, keys.len(), c);
                }
            }
            return Ok(None);
        }
        Mode::Normal => {}
    }

    match code {
        KeyCode::Char('q') => return Ok(Some(Exit::Quit)),
        KeyCode::Esc if !app.query.is_empty() => app.query.clear(),
        KeyCode::Esc => return Ok(Some(Exit::Quit)),
        KeyCode::Char('?') => app.mode = Mode::Help,
        KeyCode::Char('/') => app.mode = Mode::Search,
        KeyCode::Tab | KeyCode::BackTab => {
            app.pane = match app.pane {
                Pane::Folders => Pane::Hosts,
                Pane::Hosts => Pane::Folders,
            }
        }
        KeyCode::Char('n') => {
            app.mode = Mode::Prompt {
                kind: Ask::New,
                input: String::new(),
            }
        }
        _ if app.pane == Pane::Folders => folders_key(app, code),
        _ => return hosts_key(app, b, code),
    }
    Ok(None)
}

fn folders_key(app: &mut App, code: KeyCode) {
    let nodes = app.nodes();
    let Some(node) = nodes.get(app.folder_sel).cloned() else {
        return;
    };
    match code {
        KeyCode::Left | KeyCode::Char('h') if !node.path.is_empty() => {
            if node.has_children && !app.collapsed.contains(&node.path) {
                app.collapsed.insert(node.path);
            } else if node.path.len() > 1 {
                // на родителя
                let parent = node.path[..node.path.len() - 1].to_vec();
                app.folder_sel = nodes.iter().position(|n| n.path == parent).unwrap_or(0);
            }
        }
        KeyCode::Right | KeyCode::Char('l') if app.collapsed.contains(&node.path) => {
            app.collapsed.remove(&node.path);
        }
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => {
            app.pane = Pane::Hosts;
            app.host_sel = 0;
        }
        c => {
            if step(&mut app.folder_sel, nodes.len(), c) {
                app.host_sel = 0;
            }
        }
    }
}

fn hosts_key(app: &mut App, b: &mut dyn Backend, code: KeyCode) -> anyhow::Result<Option<Exit>> {
    let shown = app.shown();
    if step(&mut app.host_sel, shown.len(), code) {
        return Ok(None);
    }
    if matches!(code, KeyCode::Left | KeyCode::Char('h')) {
        app.pane = Pane::Folders;
        return Ok(None);
    }
    let Some(i) = app.current() else {
        return Ok(None);
    };
    let h = app.hosts[i].clone();
    let launches = matches!(code, KeyCode::Enter | KeyCode::Char('s' | 'o'));
    if launches && !knock(app, b, &h) {
        return Ok(None);
    }
    match code {
        KeyCode::Enter => {
            return Ok(Some(Exit::Exec {
                program: "ssh",
                args: h.args,
                note: None,
            }));
        }
        KeyCode::Char('s') => {
            return Ok(Some(Exit::Exec {
                program: "sftp",
                args: sftp_args(&h.args),
                note: None,
            }));
        }
        KeyCode::Char('o') => {
            let custom = b.terminal();
            app.status = Some(match ssh_setup::terminal_command(&h.args, &custom) {
                Some(mut c) => match c.spawn() {
                    Ok(_) => (tr!("Открыто в новом окне: {name}", name = h.name), false),
                    Err(e) => (tr!("Терминал не запустился: {e}", e = e), true),
                },
                None => (
                    tr!("Терминал не найден: выберите его в настройках, вкладка SSH").into(),
                    true,
                ),
            });
        }
        KeyCode::Char('c') => {
            let line = command_line(&h.args);
            app.status = Some(if copy(&line) {
                (tr!("Скопировано: {line}", line = line), false)
            } else {
                (tr!("Буфер обмена недоступен: {line}", line = line), true)
            });
        }
        KeyCode::Char('f') => {
            app.mode = Mode::Prompt {
                kind: Ask::Forward(i),
                input: String::new(),
            }
        }
        KeyCode::Char('e') => match h.source {
            Source::Vault { .. } | Source::Server { .. } => {
                app.mode = Mode::Prompt {
                    kind: Ask::Edit(i),
                    input: h.address.clone(),
                }
            }
            Source::Config => {
                app.status = Some((
                    tr!("Этот хост из ~/.ssh/config: правится в файле").into(),
                    true,
                ))
            }
        },
        _ => {}
    }
    Ok(None)
}

/// Стук перед ssh, когда его не сделает `Match exec` из конфига Keywarden. false: не вышло.
fn knock(app: &mut App, b: &mut dyn Backend, h: &Host) -> bool {
    let Source::Server {
        alias,
        knock_first: true,
        ..
    } = &h.source
    else {
        return true;
    };
    match b.knock(alias) {
        Ok(()) => true,
        Err(e) => {
            app.status = Some((tr!("Стук не прошёл: {e}", e = e), true));
            false
        }
    }
}

fn save_url(app: &mut App, b: &mut dyn Backend, id: &str, url: String, done: String) {
    app.status = Some(match b.set_url(id, url) {
        Ok(()) => (done, false),
        Err(e) => (e.to_string(), true),
    });
    app.reload(b);
}

fn prompt_done(
    app: &mut App,
    b: &mut dyn Backend,
    kind: Ask,
    input: String,
) -> anyhow::Result<Option<Exit>> {
    match kind {
        Ask::Edit(i) => {
            let h = app.hosts[i].clone();
            if let Source::Server { id, .. } = &h.source {
                if ssh_setup::ssh_args(&input).is_none() {
                    app.status = Some((bad_address(), true));
                } else {
                    save_url(app, b, id, input, tr!("Сохранено").into());
                }
                return Ok(None);
            }
            let Source::Vault { id, url } = &h.source else {
                return Ok(None);
            };
            if !input.is_empty() && ssh_setup::ssh_args(&input).is_none() {
                app.status = Some((bad_address(), true));
                return Ok(None);
            }
            // пустая строка убирает адрес из ключа
            let parts: Vec<&str> = addresses(url)
                .map(|p| if p == h.address { input.as_str() } else { p })
                .filter(|p| !p.is_empty())
                .collect();
            save_url(app, b, id, parts.join(", "), tr!("Сохранено").into());
        }
        Ask::New => {
            if ssh_setup::ssh_args(&input).is_none() {
                app.status = Some((bad_address(), true));
            } else if !app.keys.iter().any(|e| e.kind == EntryKind::SshKey) {
                app.status = Some((
                    tr!("В базе нет ключей SSH: создайте ключ в Keywarden").into(),
                    true,
                ));
            } else {
                app.mode = Mode::PickKey {
                    address: input,
                    sel: 0,
                };
            }
        }
        Ask::Forward(i) => {
            // «8080» или «8080:5432»: локальный и удалённый порт
            let (local, remote) = input.split_once(':').unwrap_or((&input, &input));
            let ok = |p: &str| p.parse::<u16>().is_ok_and(|p| p > 0);
            if !ok(local) || !ok(remote) {
                app.status = Some((
                    tr!("Порт: 8080 или 8080:5432 (локальный:на сервере)").into(),
                    true,
                ));
                return Ok(None);
            }
            let h = app.hosts[i].clone();
            if !knock(app, b, &h) {
                return Ok(None);
            }
            let mut args = vec![
                "-N".into(),
                "-L".into(),
                format!("{local}:localhost:{remote}"),
            ];
            args.extend(h.args.iter().cloned());
            return Ok(Some(Exit::Exec {
                program: "ssh",
                args,
                note: Some(tr!(
                    "Проброс: localhost:{local} → {host}:{remote}. Остановить: Ctrl+C",
                    local = local,
                    host = h.name,
                    remote = remote
                )),
            }));
        }
    }
    Ok(None)
}

// --- отрисовка ---

const ACCENT: Color = Color::Rgb(0x8b, 0x6c, 0xff);

fn muted() -> Style {
    Style::new().fg(Color::DarkGray)
}

fn pane_block(title: String, focused: bool) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(if focused {
            Style::new().fg(ACCENT)
        } else {
            muted()
        })
        .title(Span::styled(
            format!(" {title} "),
            if focused {
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            },
        ))
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let [head, body, detail, foot] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(5),
        Constraint::Length(1),
    ])
    .areas(f.area());

    // шапка: название и строка поиска
    let searching = matches!(app.mode, Mode::Search);
    let mut head_spans = vec![
        Span::styled(
            " Keywarden SSH ",
            Style::new()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled("/ ", Style::new().fg(ACCENT)),
    ];
    if app.query.is_empty() && !searching {
        head_spans.push(Span::styled(tr!("поиск"), muted()));
    } else {
        head_spans.push(Span::raw(app.query.clone()));
        if searching {
            head_spans.push(Span::styled("▏", Style::new().fg(ACCENT)));
        }
    }
    f.render_widget(Paragraph::new(Line::from(head_spans)), head);

    let [left, right] =
        Layout::horizontal([Constraint::Length(30), Constraint::Min(20)]).areas(body);

    // папки
    let nodes = app.nodes();
    let items: Vec<ListItem> = nodes
        .iter()
        .map(|n| {
            let depth = n.path.len().saturating_sub(1);
            let name = n
                .path
                .last()
                .cloned()
                .unwrap_or_else(|| tr!("Все хосты").to_string());
            let mark = if n.path.is_empty() {
                "◆ "
            } else if !n.has_children {
                "• "
            } else if app.collapsed.contains(&n.path) {
                "▸ "
            } else {
                "▾ "
            };
            let width = 26usize.saturating_sub(depth * 2 + 2);
            let count = n.count.to_string();
            let name = clip(&name, width.saturating_sub(count.len() + 1));
            let pad = width.saturating_sub(name.chars().count() + count.len());
            ListItem::new(Line::from(vec![
                Span::raw("  ".repeat(depth)),
                Span::styled(mark, Style::new().fg(ACCENT)),
                Span::raw(name),
                Span::raw(" ".repeat(pad)),
                Span::styled(count, muted()),
            ]))
        })
        .collect();
    let folders_focused = app.pane == Pane::Folders && !searching;
    let mut st = ListState::default().with_selected(Some(app.folder_sel));
    f.render_stateful_widget(
        List::new(items)
            .block(pane_block(tr!("Папки").into(), folders_focused))
            .highlight_style(highlight(folders_focused)),
        left,
        &mut st,
    );

    // хосты
    let shown = app.shown();
    let name_w = shown
        .iter()
        .map(|&i| app.hosts[i].name.chars().count())
        .max()
        .unwrap_or(0)
        .min(28);
    let target_w = shown
        .iter()
        .map(|&i| app.hosts[i].target.chars().count())
        .max()
        .unwrap_or(0)
        .min(36);
    let items: Vec<ListItem> = shown
        .iter()
        .map(|&i| {
            let h = &app.hosts[i];
            let mut spans = vec![
                Span::styled(
                    format!("{:<name_w$}", clip(&h.name, name_w)),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::raw("  "),
                Span::styled(
                    format!("{:<target_w$}", clip(&h.target, target_w)),
                    Style::new().fg(Color::Cyan),
                ),
            ];
            if !app.query.is_empty() {
                spans.push(Span::styled(format!("  {}", h.path()), muted()));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let hosts_focused = app.pane == Pane::Hosts && !searching;
    let title = if app.query.is_empty() {
        nodes
            .get(app.folder_sel)
            .and_then(|n| n.path.last().cloned())
            .unwrap_or_else(|| tr!("Все хосты").to_string())
    } else {
        tr!("Найдено: {n}", n = shown.len())
    };
    let hosts_block = pane_block(title, hosts_focused);
    if shown.is_empty() {
        let text = if app.hosts.is_empty() {
            tr!(
                "Нет хостов: kw ssh-import-config перенесёт ~/.ssh/config в базу, n добавит адрес к ключу"
            )
        } else {
            tr!("Ничего не найдено")
        };
        f.render_widget(
            Paragraph::new(Span::styled(text, muted())).block(hosts_block),
            right,
        );
    } else {
        let mut st = ListState::default().with_selected(Some(app.host_sel));
        f.render_stateful_widget(
            List::new(items)
                .block(hosts_block)
                .highlight_style(highlight(hosts_focused))
                .highlight_symbol("› "),
            right,
            &mut st,
        );
    }

    // подробности выбранного хоста
    let lines = match app.current().map(|i| &app.hosts[i]) {
        None => vec![Line::from(Span::styled(tr!("Выберите хост"), muted()))],
        Some(h) => {
            let mut facts = vec![];
            if let Some(k) = &h.key {
                facts.push(match h.source {
                    Source::Config => tr!("ключ: {k}", k = k),
                    _ => tr!("ключ из базы: {k}", k = k),
                });
            }
            if let Some(p) = &h.proxy {
                facts.push(tr!("через {p}", p = p));
            }
            if !h.forwards.is_empty() {
                facts.push(tr!("проброс {f}", f = h.forwards.join(", ")));
            }
            if h.knock {
                facts.push("port knocking".to_string());
            }
            let source = match h.source {
                Source::Config => tr!("{path}, только чтение", path = h.path()),
                _ => tr!("база: {path}", path = h.path()),
            };
            vec![
                Line::from(vec![
                    Span::styled(h.name.clone(), Style::new().add_modifier(Modifier::BOLD)),
                    Span::raw("  "),
                    Span::styled(h.target.clone(), Style::new().fg(Color::Cyan)),
                ]),
                Line::from(Span::raw(facts.join("  •  "))),
                Line::from(vec![
                    Span::styled(source, muted()),
                    Span::styled(format!("  •  {}", command_line(&h.args)), muted()),
                ]),
            ]
        }
    };
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(muted()),
        ),
        detail,
    );

    // подвал: сообщение или подсказки
    let footer = match &app.status {
        Some((text, err)) => Line::from(Span::styled(
            format!(" {text}"),
            Style::new().fg(if *err { Color::Red } else { Color::Green }),
        )),
        None => {
            let keys: Vec<(&str, &str)> = match (&app.mode, app.pane) {
                (Mode::Search, _) => {
                    vec![("Enter", tr!("к результатам")), ("Esc", tr!("сбросить"))]
                }
                (_, Pane::Folders) => vec![
                    ("↑↓", tr!("папка")),
                    ("←→", tr!("свернуть")),
                    ("Tab", tr!("к хостам")),
                    ("/", tr!("поиск")),
                    ("?", tr!("все клавиши")),
                ],
                _ => vec![
                    ("Enter", tr!("войти")),
                    ("o", tr!("в новом окне")),
                    ("c", tr!("команда")),
                    ("/", tr!("поиск")),
                    ("?", tr!("все клавиши")),
                    ("q", tr!("выход")),
                ],
            };
            hints(&keys)
        }
    };
    f.render_widget(Paragraph::new(footer), foot);

    // окна поверх
    match &app.mode {
        Mode::Help => {
            let rows = [
                ("Enter", tr!("войти по ssh в этом терминале")),
                ("o", tr!("открыть в новом окне терминала")),
                ("s", tr!("sftp на этот хост")),
                ("f", tr!("проброс порта на localhost")),
                ("c", tr!("скопировать команду ssh")),
                ("e", tr!("изменить адрес (хосты из базы)")),
                ("", tr!("всё остальное у сервера правится в Keywarden")),
                ("n", tr!("новый адрес для ключа из базы")),
                ("/", tr!("поиск по всем папкам")),
                ("Tab ←→", tr!("папки и хосты, свернуть папку")),
                ("q Esc", tr!("выход")),
            ];
            let lines: Vec<Line> = rows
                .iter()
                .map(|(k, v)| {
                    Line::from(vec![
                        Span::styled(
                            format!(" {k:<8}"),
                            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(*v),
                    ])
                })
                .collect();
            popup(f, tr!("Клавиши").into(), lines, 56);
        }
        Mode::Prompt { kind, input } => {
            let (title, hint) = match kind {
                Ask::Edit(_) => (tr!("Адрес"), tr!("пусто: убрать адрес из ключа")),
                Ask::New => (
                    tr!("Новый адрес"),
                    tr!("user@host, host:2222 или ssh://user@host:port"),
                ),
                Ask::Forward(_) => (
                    tr!("Проброс порта"),
                    tr!("8080 или 8080:5432 (локальный:на сервере)"),
                ),
            };
            let lines = vec![
                Line::from(vec![
                    Span::styled("› ", Style::new().fg(ACCENT)),
                    Span::raw(input.clone()),
                    Span::styled("▏", Style::new().fg(ACCENT)),
                ]),
                Line::from(Span::styled(hint, muted())),
                hints(&[("Enter", tr!("готово")), ("Esc", tr!("отмена"))]),
            ];
            popup(f, title.into(), lines, 56);
        }
        Mode::PickKey { address, sel } => {
            let lines: Vec<Line> = app
                .keys
                .iter()
                .filter(|e| e.kind == EntryKind::SshKey)
                .enumerate()
                .map(|(i, e)| {
                    let style = if i == *sel {
                        highlight(true)
                    } else {
                        Style::new()
                    };
                    Line::from(vec![
                        Span::styled(if i == *sel { "› " } else { "  " }, Style::new().fg(ACCENT)),
                        Span::styled(e.title.clone(), style),
                        Span::styled(format!("  {}", e.group), muted()),
                    ])
                })
                .collect();
            popup(
                f,
                tr!("Каким ключом входить на {address}", address = address),
                lines,
                60,
            );
        }
        Mode::Normal | Mode::Search => {}
    }
}

fn highlight(focused: bool) -> Style {
    if focused {
        Style::new()
            .bg(Color::Rgb(0x2a, 0x24, 0x48))
            .add_modifier(Modifier::BOLD)
    } else {
        Style::new().bg(Color::Rgb(0x26, 0x26, 0x2c))
    }
}

fn hints(keys: &[(&str, &str)]) -> Line<'static> {
    let mut spans = vec![];
    for (k, what) in keys {
        spans.push(Span::styled(
            format!(" {k} "),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(format!("{what} "), muted()));
    }
    Line::from(spans)
}

fn popup(f: &mut ratatui::Frame, title: String, lines: Vec<Line>, width: u16) {
    let area = f.area();
    let w = width.min(area.width.saturating_sub(4));
    let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let rect = Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 3,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    f.render_widget(Paragraph::new(lines).block(pane_block(title, true)), rect);
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.into()
    } else {
        format!(
            "{}…",
            s.chars().take(n.saturating_sub(1)).collect::<String>()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(title: &str, group: &str, url: &str) -> EntrySummary {
        serde_json::from_value(serde_json::json!({
            "id": title, "kind": "ssh_key", "title": title, "username": "", "url": url,
            "group": group, "tags": [], "has_otp": false
        }))
        .unwrap()
    }

    #[test]
    fn vault_hosts_one_row_per_address() {
        let h = from_vault(&[
            entry(
                "Deploy",
                "Работа/prod",
                "ssh://deploy@prod:2222, git@github.com",
            ),
            entry("Broken", "", "-oProxyCommand=evil"),
        ]);
        assert_eq!(h.len(), 2);
        assert_eq!(h[0].args, ["-p", "2222", "deploy@prod"]);
        assert_eq!(h[0].target, "deploy@prod:2222");
        assert_eq!(h[0].folder, ["Работа", "prod"]);
        assert_eq!(h[1].args, ["git@github.com"]);
    }

    #[test]
    fn ssh_config_details_without_patterns() {
        let h = from_ssh_config(
            "Include ~/.ssh/keywarden/config\n# Host commented\nHost homelab nas\n  HostName 192.168.1.10\n  User me\n  Port 2200\n  IdentityFile ~/.ssh/id_home\n  ProxyJump bastion\nHost *.corp !x\n  User other\nMatch host foo\n  HostName bar\n",
        );
        let names: Vec<_> = h.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["homelab", "nas"]);
        assert_eq!(h[0].target, "me@192.168.1.10:2200");
        assert_eq!(h[0].key.as_deref(), Some("id_home"));
        assert_eq!(h[0].proxy.as_deref(), Some("bastion"));
        assert_eq!(h[0].args, ["homelab"]);
    }

    #[test]
    fn config_hosts_grouped_by_name_or_domain() {
        let h = from_ssh_config(
            "Host prod-api\nHost prod-db\nHost web1\nHost web2\nHost a\n HostName a.example.com\nHost b\n HostName b.example.com\nHost lonely\n HostName 10.0.0.1\n",
        );
        let group = |name: &str| h.iter().find(|x| x.name == name).unwrap().folder[1].clone();
        assert_eq!(group("prod-api"), "prod");
        assert_eq!(group("prod-db"), "prod");
        assert_eq!(group("web1"), "web");
        assert_eq!(group("a"), "example.com");
        assert_eq!(group("lonely"), tr!("Прочие"));
        assert!(h.iter().all(|x| x.folder[0] == SSH_CONFIG));
    }

    #[test]
    fn tree_orders_counts_and_collapses() {
        let mut hosts = from_vault(&[
            entry("VPS", "Серверы", "root@vps"),
            entry("Prod", "Работа/prod", "deploy@prod"),
            entry("Stage", "Работа/stage", "deploy@stage"),
        ]);
        hosts.extend(from_ssh_config("Host db-1\nHost db-2\n"));
        let t = tree(&hosts, &HashSet::new());
        let names: Vec<String> = t.iter().map(|n| n.path.join("/")).collect();
        let x = format!("{SSH_CONFIG}/db");
        assert_eq!(
            names,
            [
                "",
                "Работа",
                "Работа/prod",
                "Работа/stage",
                "Серверы",
                SSH_CONFIG,
                x.as_str()
            ]
        );
        assert_eq!(t[0].count, 5);
        assert_eq!(t[1].count, 2);
        let closed: HashSet<Vec<String>> = [vec!["Работа".to_string()]].into();
        assert_eq!(tree(&hosts, &closed).len(), 5);
        assert_eq!(visible(&hosts, &["Работа".into()], "").len(), 2);
        assert_eq!(visible(&hosts, &[], "stage").len(), 1);
    }

    fn server(alias: &str, group: &str, knock_first: bool) -> SshHost {
        SshHost {
            id: alias.into(),
            title: alias.into(),
            alias: alias.into(),
            group: group.into(),
            address: format!("root@{alias}.example.net:2222"),
            key: Some("Рабочий".into()),
            proxy: Some("bastion".into()),
            forwards: vec!["5432 → localhost:5432".into()],
            knock: true,
            args: vec![alias.into()],
            knock_first,
        }
    }

    #[test]
    fn servers_replace_config_hosts_with_same_name() {
        let h = all_hosts(
            &[],
            &[server("prod", "SSH/prod", false)],
            "Host prod
  HostName old
Host other
",
        );
        let names: Vec<_> = h.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["prod", "other"]);
        assert_eq!(h[0].folder, ["SSH", "prod"]);
        assert!(matches!(h[0].source, Source::Server { .. }));
    }

    struct Fake {
        knocked: Vec<String>,
    }

    impl Backend for Fake {
        fn entries(&mut self) -> anyhow::Result<Vec<EntrySummary>> {
            Ok(vec![])
        }
        fn servers(&mut self) -> anyhow::Result<Vec<SshHost>> {
            Ok(vec![])
        }
        fn knock(&mut self, alias: &str) -> anyhow::Result<()> {
            self.knocked.push(alias.into());
            Ok(())
        }
        fn set_url(&mut self, _: &str, _: String) -> anyhow::Result<()> {
            Ok(())
        }
        fn terminal(&mut self) -> Vec<String> {
            vec![]
        }
    }

    #[test]
    fn knocks_before_ssh_only_without_config() {
        for (knock_first, want) in [(true, 1), (false, 0)] {
            let mut app = App::new(vec![], &[server("prod", "", knock_first)], String::new());
            let mut b = Fake { knocked: vec![] };
            let exit = key(&mut app, &mut b, KeyCode::Enter).unwrap();
            assert!(matches!(exit, Some(Exit::Exec { program: "ssh", .. })));
            assert_eq!(b.knocked.len(), want);
        }
    }

    #[test]
    fn sftp_uses_capital_p() {
        assert_eq!(
            sftp_args(&["-p".into(), "2222".into(), "u@h".into()]),
            ["-P", "2222", "u@h"]
        );
    }

    #[test]
    fn screen_renders_panes_and_details() {
        let app = App::new(
            vec![
                entry(
                    "Ключ деплоя",
                    "Работа",
                    "ssh://deploy@prod.example.org:2222",
                ),
                entry("GitLab", "Работа", "git@gitlab.corp"),
            ],
            &[],
            "Host homelab\n  HostName 192.168.1.10\n  ProxyJump bastion\n".into(),
        );
        let mut t = ratatui::Terminal::new(ratatui::backend::TestBackend::new(96, 18)).unwrap();
        t.draw(|f| draw(f, &app)).unwrap();
        let screen: String = t
            .backend()
            .buffer()
            .content()
            .chunks(96)
            .map(|line| line.iter().map(|c| c.symbol()).collect::<String>() + "\n")
            .collect();
        println!("{screen}");
        for want in [
            "Keywarden SSH",
            "Все хосты",
            "• Работа",
            "• ~/.ssh/config",
            "› GitLab",
            "deploy@prod.example.org:2222",
            "ключ из базы: GitLab",
            "ssh git@gitlab.corp",
            "Enter",
        ] {
            assert!(screen.contains(want), "нет «{want}»:\n{screen}");
        }
    }
}
