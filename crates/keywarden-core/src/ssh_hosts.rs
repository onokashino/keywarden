//! Записи «Сервер SSH»: поля, разбор `~/.ssh/config` (импорт и `kw ssh`), автопапки по
//! именам, проброс портов, port knocking и блок для `~/.ssh/keywarden/config`.
//!
//! Адрес хоста в поле URL (`user@host:port`), остальное в своих полях. Названия полей
//! английские: так их видят KeePassXC и мобильные клиенты.

use std::collections::BTreeMap;
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Duration;

/// Название записи «Ключ SSH», которым входить.
pub const KEY: &str = "SSH Key";
pub const PROXY: &str = "ProxyJump";
/// Пробросы через запятую: `8080`, `8080:5432`, `8080:db:5432`, `127.0.0.1:8080:db:5432`.
pub const FORWARD: &str = "LocalForward";
/// Другие строки ssh_config через `;`: `ServerAliveInterval 30; Compression yes`.
pub const OPTIONS: &str = "SSH Options";
/// Последовательность портов: `7000 8000:udp 9000` (по умолчанию tcp, как у knock).
pub const KNOCK: &str = "Port Knock";

/// Куда входить: из `user@host:port`, `ssh://user@host:port/...`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Address {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
}

fn safe_word(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// Адрес из первого слова поля; хост и пользователь без опций и подстановок ssh.
pub fn address(field: &str) -> Option<Address> {
    let first = field
        .split(|c: char| c.is_whitespace() || c == ',')
        .find(|s| !s.is_empty())?;
    let rest = first.split_once("://").map_or(first, |(_, r)| r);
    let rest = rest.split('/').next().unwrap_or_default();
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, p.parse().ok()),
        _ => (hostport, None),
    };
    safe_word(host).then(|| Address {
        user: user.filter(|u| safe_word(u)).map(str::to_string),
        host: host.to_string(),
        port: port.filter(|p| *p != 22),
    })
}

impl Address {
    /// `user@host:port` для показа и поля URL.
    pub fn display(&self) -> String {
        let mut s = match &self.user {
            Some(u) => format!("{u}@{}", self.host),
            None => self.host.clone(),
        };
        if let Some(p) = self.port {
            s.push_str(&format!(":{p}"));
        }
        s
    }
}

/// Имя для `Host` и `ssh имя` из названия записи: латиница, цифры, `.-_`, остальное дефис.
pub fn alias(title: &str) -> Option<String> {
    let s: String = title
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    let s = s
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    safe_word(&s).then_some(s)
}

/// Один проброс: (слушать, куда) для `LocalForward` и `ssh -L слушать:куда`.
pub fn forward(item: &str) -> Option<(String, String)> {
    let p: Vec<&str> = item.trim().split(':').collect();
    let port = |s: &str| s.parse::<u16>().is_ok_and(|p| p > 0);
    let host = |s: &str| safe_word(s);
    match p.as_slice() {
        [l] if port(l) => Some((l.to_string(), format!("localhost:{l}"))),
        [l, r] if port(l) && port(r) => Some((l.to_string(), format!("localhost:{r}"))),
        [l, h, r] if port(l) && host(h) && port(r) => Some((l.to_string(), format!("{h}:{r}"))),
        [b, l, h, r] if host(b) && port(l) && host(h) && port(r) => {
            Some((format!("{b}:{l}"), format!("{h}:{r}")))
        }
        _ => None,
    }
}

/// Все пробросы поля; непонятные пропускаются.
pub fn forwards(field: &str) -> Vec<(String, String)> {
    field
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(forward)
        .collect()
}

/// Строки ssh_config из поля «другие настройки»: без `Host`, `Match`, `Include`, чтобы
/// не сломать блок. Разделитель `;`, поэтому значение с `;` внутри задать нельзя.
pub fn options(field: &str) -> Vec<String> {
    field
        .split([';', '\n'])
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| !l.chars().any(char::is_control))
        .filter(|l| {
            let k = l.split([' ', '\t', '=']).next().unwrap_or_default();
            !matches!(
                k.to_ascii_lowercase().as_str(),
                "host" | "match" | "include"
            ) && !k.is_empty()
        })
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// `7000 8000:udp 9000,10000:tcp`
pub fn knock_sequence(field: &str) -> Result<Vec<(u16, Proto)>, String> {
    field
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|item| {
            let (port, proto) = item.split_once(':').unwrap_or((item, "tcp"));
            let proto = match proto.to_ascii_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                _ => return Err(crate::tr!("knocking: «{item}»: tcp или udp", item = item)),
            };
            match port.parse::<u16>() {
                Ok(p) if p > 0 => Ok((p, proto)),
                _ => Err(crate::tr!("knocking: «{item}»: не порт", item = item)),
            }
        })
        .collect()
}

/// Стук по портам хоста. TCP: попытка соединения (уходит SYN), UDP: пустой пакет.
/// Пауза между стуками постоянная (100 мс); если понадобится своя, добавить её в поле.
pub fn knock(host: &str, seq: &[(u16, Proto)]) -> Result<(), String> {
    let ip = (host, 0)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .next()
        .ok_or_else(|| format!("{host}: ?"))?
        .ip();
    for (port, proto) in seq {
        let addr = (ip, *port).into();
        match proto {
            // закрытый порт и ответит отказом, и промолчит: стук засчитан в обоих случаях
            Proto::Tcp => {
                let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(300));
            }
            Proto::Udp => {
                let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let s = UdpSocket::bind(bind).map_err(|e| e.to_string())?;
                s.send_to(&[], addr).map_err(|e| format!("{addr}: {e}"))?;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // файрволу нужно мгновение, чтобы открыть порт
    std::thread::sleep(Duration::from_millis(200));
    Ok(())
}

/// Запись «Сервер SSH», готовая к выводу в конфиг.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct HostBlock {
    pub alias: String,
    pub address: Address,
    /// файл открытого ключа в ~/.ssh/keywarden/
    pub key_file: Option<String>,
    pub proxy: Option<String>,
    pub forwards: Vec<(String, String)>,
    pub options: Vec<String>,
    pub knock: bool,
}

/// Блок `Host` записи; со стуком ещё `Match ... exec "kw knock"` (ssh выполняет его при
/// разборе конфига, то есть до соединения, и для scp, rsync, git тоже).
pub fn render_host(b: &HostBlock, agent: &Path, kw: &Path) -> String {
    let mut s = format!("\nHost {}\n  HostName {}\n", b.alias, b.address.host);
    if let Some(u) = &b.address.user {
        s.push_str(&format!("  User {u}\n"));
    }
    if let Some(p) = b.address.port {
        s.push_str(&format!("  Port {p}\n"));
    }
    if let Some(j) = b.proxy.as_deref().filter(|j| proxy_ok(j)) {
        s.push_str(&format!("  ProxyJump {j}\n"));
    }
    for (l, r) in &b.forwards {
        s.push_str(&format!("  LocalForward {l} {r}\n"));
    }
    for o in &b.options {
        s.push_str(&format!("  {o}\n"));
    }
    if let Some(f) = &b.key_file {
        s.push_str(&format!("  IdentityAgent \"{}\"\n", agent.display()));
        s.push_str(&format!("  IdentityFile \"~/.ssh/keywarden/{f}\"\n"));
        s.push_str("  IdentitiesOnly yes\n");
    }
    if b.knock {
        // путь в одинарных кавычках для sh; ' внутри пути закрываем и экранируем
        // OpenSSH на Windows выполняет exec через cmd: такие кавычки там не проверены
        let kw = kw.display().to_string().replace('\'', r"'\''");
        s.push_str(&format!(
            "\nMatch originalhost {} exec \"'{kw}' knock {}\"\n",
            b.alias, b.alias
        ));
    }
    s
}

/// ProxyJump: список `[user@]host[:port]` через запятую.
pub fn proxy_ok(j: &str) -> bool {
    !j.is_empty()
        && j.split(',')
            .all(|p| address(p).is_some() && !p.contains(' '))
}

// --- ~/.ssh/config ---

/// Хост из `~/.ssh/config` (одна строка Host с несколькими именами даёт несколько).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConfigHost {
    pub alias: String,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<String>,
    pub proxy: Option<String>,
    /// путь как записан (`~/.ssh/id_work`); файл не читаем
    pub identity: Option<String>,
    /// в формате поля FORWARD
    pub forwards: Vec<String>,
    /// остальные строки блока как есть (`ServerAliveInterval 30`)
    pub other: Vec<String>,
}

impl ConfigHost {
    pub fn address(&self) -> Address {
        Address {
            user: self.user.clone(),
            host: self.hostname.clone().unwrap_or_else(|| self.alias.clone()),
            port: self
                .port
                .as_deref()
                .and_then(|p| p.parse().ok())
                .filter(|p| *p != 22),
        }
    }
}

/// Блоки `Host` без масок; `Match` и `Include` пропускаем (Include ведёт и на файл
/// Keywarden). Как в ssh: первое значение побеждает.
pub fn parse_config(text: &str) -> Vec<ConfigHost> {
    let mut out: Vec<ConfigHost> = vec![];
    let mut block: Option<(Vec<String>, ConfigHost)> = None;
    let flush = |b: Option<(Vec<String>, ConfigHost)>, out: &mut Vec<ConfigHost>| {
        if let Some((aliases, h)) = b {
            for a in aliases {
                out.push(ConfigHost {
                    alias: a,
                    ..h.clone()
                });
            }
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(|c: char| c.is_whitespace() || c == '=') else {
            continue;
        };
        let v = v.trim().trim_start_matches('=').trim();
        let unq = v.trim_matches('"').to_string();
        match k.to_ascii_lowercase().as_str() {
            "host" => {
                flush(block.take(), &mut out);
                let aliases: Vec<String> = v
                    .split_whitespace()
                    .filter(|a| !a.contains(['*', '?', '!']) && safe_word(a))
                    .map(str::to_string)
                    .collect();
                block = Some((aliases, ConfigHost::default()));
            }
            "match" => flush(block.take(), &mut out),
            key => {
                let Some((_, h)) = block.as_mut() else {
                    continue;
                };
                let slot = match key {
                    "hostname" => &mut h.hostname,
                    "user" => &mut h.user,
                    "port" => &mut h.port,
                    "proxyjump" => &mut h.proxy,
                    "identityfile" => &mut h.identity,
                    "localforward" => {
                        let mut it = unq.split_whitespace();
                        match (it.next(), it.next()) {
                            (Some(l), Some(r)) if forward(&format!("{l}:{r}")).is_some() => {
                                h.forwards.push(format!("{l}:{r}"))
                            }
                            _ => h.other.push(line.to_string()),
                        }
                        continue;
                    }
                    // свой агент и ключи пропишет Keywarden
                    "identityagent" | "identitiesonly" => continue,
                    _ => {
                        h.other.push(line.to_string());
                        continue;
                    }
                };
                slot.get_or_insert(unq);
            }
        }
    }
    flush(block, &mut out);
    out
}

/// Папки без ручной работы: общий префикс имени (prod-api, prod-db: «prod»), иначе общий
/// домен (a.example.com, b.example.com: «example.com»). Группа из одного хоста не заводится.
/// `items`: (имя, хост).
pub fn auto_groups(items: &[(&str, &str)]) -> Vec<Option<String>> {
    let prefix = |name: &str| {
        let first = name.split(['-', '_', '.']).next().unwrap_or_default();
        let base = first.trim_end_matches(|c: char| c.is_ascii_digit());
        (base.len() >= 2 && base.len() < name.len()).then(|| base.to_lowercase())
    };
    let domain = |host: &str| {
        let labels: Vec<&str> = host.split('.').collect();
        let ip = labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit()));
        (labels.len() >= 2 && !ip).then(|| labels[labels.len() - 2..].join(".").to_lowercase())
    };
    let count = |keys: Vec<Option<String>>| {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for k in keys.into_iter().flatten() {
            *m.entry(k).or_default() += 1;
        }
        m
    };
    let by_prefix = count(items.iter().map(|(n, _)| prefix(n)).collect());
    let by_domain = count(items.iter().map(|(_, h)| domain(h)).collect());
    items
        .iter()
        .map(|(n, h)| {
            prefix(n)
                .filter(|p| by_prefix[p] >= 2)
                .or_else(|| domain(h).filter(|d| by_domain[d] >= 2))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_address() {
        let a = address("ssh://root@db.example.com:2222/x").unwrap();
        assert_eq!(a.display(), "root@db.example.com:2222");
        assert_eq!(address("me@host:22").unwrap().display(), "me@host");
        assert!(address("-oProxyCommand=x").is_none());
        assert_eq!(alias("Prod DB (main)").as_deref(), Some("Prod-DB-main"));
        assert_eq!(alias("Сервер"), None);
    }

    #[test]
    fn parses_forwards_and_options() {
        assert_eq!(
            forwards("8080, 8081:80 5432:db:5432 127.0.0.1:9000:x:90 bad:x"),
            [
                ("8080".into(), "localhost:8080".into()),
                ("8081".into(), "localhost:80".into()),
                ("5432".into(), "db:5432".into()),
                ("127.0.0.1:9000".into(), "x:90".into()),
            ]
        );
        assert_eq!(
            options("ServerAliveInterval 30; Host evil; Match all;Compression yes"),
            ["ServerAliveInterval 30", "Compression yes"]
        );
    }

    #[test]
    fn parses_knock() {
        assert_eq!(
            knock_sequence("7000 8000:udp,9000:TCP").unwrap(),
            [(7000, Proto::Tcp), (8000, Proto::Udp), (9000, Proto::Tcp)]
        );
        assert!(knock_sequence("7000:icmp").is_err());
        assert!(knock_sequence("0").is_err());
    }

    #[test]
    fn knocks_ports_in_order() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (tp, up) = (
            tcp.local_addr().unwrap().port(),
            udp.local_addr().unwrap().port(),
        );
        knock("127.0.0.1", &[(tp, Proto::Tcp), (up, Proto::Udp)]).unwrap();
        tcp.set_nonblocking(true).unwrap();
        assert!(tcp.accept().is_ok(), "TCP-стук не дошёл");
        assert!(udp.recv_from(&mut [0; 8]).is_ok(), "UDP-стук не дошёл");
    }

    #[test]
    fn renders_block_with_knock() {
        let b = HostBlock {
            alias: "prod".into(),
            address: address("root@10.0.0.5:2222").unwrap(),
            key_file: Some("work.pub".into()),
            proxy: Some("bastion".into()),
            forwards: forwards("5432"),
            options: options("ServerAliveInterval 30"),
            knock: true,
        };
        let s = render_host(&b, Path::new("/run/kw/ssh.sock"), Path::new("/opt/kw/kw"));
        assert_eq!(
            s,
            "\nHost prod\n  HostName 10.0.0.5\n  User root\n  Port 2222\n  ProxyJump bastion\n  \
             LocalForward 5432 localhost:5432\n  ServerAliveInterval 30\n  \
             IdentityAgent \"/run/kw/ssh.sock\"\n  IdentityFile \"~/.ssh/keywarden/work.pub\"\n  \
             IdentitiesOnly yes\n\nMatch originalhost prod exec \"'/opt/kw/kw' knock prod\"\n"
        );
    }

    #[test]
    fn parses_ssh_config() {
        let text = "Include ~/.ssh/keywarden/config\n\
            Host *\n  ServerAliveInterval 60\n\
            Host prod-api prod-api.alias\n  HostName 10.0.0.1\n  User root\n  Port 2222\n  \
            IdentityFile ~/.ssh/id_work\n  IdentityFile ~/.ssh/other\n  LocalForward 8080 localhost:80\n  \
            ForwardAgent yes\n  IdentitiesOnly yes\n\
            Match host x\n  User nobody\n\
            Host gh\n  HostName github.com\n  User=git\n";
        let h = parse_config(text);
        assert_eq!(
            h.iter().map(|h| h.alias.as_str()).collect::<Vec<_>>(),
            ["prod-api", "prod-api.alias", "gh"]
        );
        assert_eq!(h[0].address().display(), "root@10.0.0.1:2222");
        assert_eq!(h[0].identity.as_deref(), Some("~/.ssh/id_work"));
        assert_eq!(h[0].forwards, ["8080:localhost:80"]);
        assert_eq!(h[0].other, ["ForwardAgent yes"]);
        assert_eq!(h[2].address().display(), "git@github.com");
    }

    #[test]
    fn groups_by_prefix_then_domain() {
        let g = auto_groups(&[
            ("prod-api", "10.0.0.1"),
            ("prod-db", "10.0.0.2"),
            ("a", "a.example.com"),
            ("b", "b.example.com"),
            ("solo", "1.2.3.4"),
        ]);
        assert_eq!(
            g,
            [
                Some("prod".into()),
                Some("prod".into()),
                Some("example.com".into()),
                Some("example.com".into()),
                None
            ]
        );
    }
}
