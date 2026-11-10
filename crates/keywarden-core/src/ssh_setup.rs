//! SSH-агент Keywarden для всех программ без ручной настройки `SSH_AUTH_SOCK`:
//!
//! - Linux: `~/.config/environment.d/60-keywarden-ssh.conf` (systemd читает при входе) и сразу
//!   `systemctl --user set-environment`, чтобы новые программы видели агента без перезахода;
//! - macOS: LaunchAgent, который при входе выполняет `launchctl setenv`, и тот же вызов сейчас;
//! - Windows: пользовательская переменная окружения (`setx`), её видят все новые программы.
//!
//! Уже открытые терминалы остаются со старым окружением: там `eval "$(kw ssh-env)"`.

use crate::platform;
use std::path::{Path, PathBuf};
use std::process::Command;

const VAR: &str = "SSH_AUTH_SOCK";

/// Состояние настройки для окна и `kw ssh-setup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// не включено
    Off,
    /// включено, и окружение сессии уже указывает на Keywarden
    Active,
    /// включено, начнёт работать после перезахода в систему
    AfterRelogin,
    /// включено, но сессия указывает на другой агент (путь)
    Overridden(String),
}

/// Путь агента основной базы.
pub fn agent_path() -> PathBuf {
    platform::endpoint(&crate::ipc::runtime_dir_for(None), None, "ssh")
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

// --- Linux ---

#[cfg(all(unix, not(target_os = "macos")))]
fn env_file() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")
        });
    base.join("environment.d").join("60-keywarden-ssh.conf")
}

/// Содержимое файла environment.d: путь через `${XDG_RUNTIME_DIR}`, чтобы не зависеть от uid.
pub fn environment_d(agent: &Path) -> String {
    let runtime = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
    let shown = agent.to_string_lossy();
    let value = match shown.strip_prefix(runtime.as_str()) {
        Some(rest) if !runtime.is_empty() => format!("${{XDG_RUNTIME_DIR}}{rest}"),
        _ => shown.into_owned(),
    };
    format!(
        "# SSH-агент Keywarden для всех программ сессии (отключается в настройках Keywarden)\n{VAR}={value}\n"
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn enable() -> std::io::Result<()> {
    let file = env_file();
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let agent = agent_path();
    std::fs::write(&file, environment_d(&agent))?;
    let kv = format!("{VAR}={}", agent.display());
    run("systemctl", &["--user", "set-environment", &kv]);
    run("dbus-update-activation-environment", &[&kv]);
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn disable() -> std::io::Result<()> {
    match std::fs::remove_file(env_file()) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    if session_value().as_deref() == Some(agent_path().to_string_lossy().as_ref()) {
        run("systemctl", &["--user", "unset-environment", VAR]);
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn enabled() -> bool {
    env_file().exists()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn session_value() -> Option<String> {
    let env = run("systemctl", &["--user", "show-environment"])?;
    env.lines()
        .find_map(|l| l.strip_prefix(&format!("{VAR}=")))
        .map(str::to_string)
}

// --- macOS ---

#[cfg(target_os = "macos")]
fn plist() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
        .join("Library/LaunchAgents/dev.keywarden.ssh-auth-sock.plist")
}

#[cfg(target_os = "macos")]
pub fn enable() -> std::io::Result<()> {
    let agent = agent_path();
    let p = plist();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(
        &p,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.keywarden.ssh-auth-sock</string>
  <key>ProgramArguments</key><array>
    <string>/bin/launchctl</string><string>setenv</string><string>{VAR}</string><string>{}</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
"#,
            agent.display()
        ),
    )?;
    run("launchctl", &["setenv", VAR, &agent.to_string_lossy()]);
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn disable() -> std::io::Result<()> {
    match std::fs::remove_file(plist()) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    if session_value().as_deref() == Some(agent_path().to_string_lossy().as_ref()) {
        run("launchctl", &["unsetenv", VAR]);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn enabled() -> bool {
    plist().exists()
}

#[cfg(target_os = "macos")]
fn session_value() -> Option<String> {
    run("launchctl", &["getenv", VAR]).filter(|v| !v.is_empty())
}

// --- Windows ---

#[cfg(windows)]
pub fn enable() -> std::io::Result<()> {
    let agent = agent_path();
    match run("setx", &[VAR, &agent.to_string_lossy()]) {
        Some(_) => Ok(()),
        None => Err(std::io::Error::other("setx")),
    }
}

#[cfg(windows)]
pub fn disable() -> std::io::Result<()> {
    if enabled() {
        run("reg", &["delete", r"HKCU\Environment", "/v", VAR, "/f"]);
    }
    Ok(())
}

#[cfg(windows)]
fn enabled() -> bool {
    session_value().as_deref() == Some(agent_path().to_string_lossy().as_ref())
}

/// Значение из HKCU\Environment (то, что получат новые программы).
#[cfg(windows)]
fn session_value() -> Option<String> {
    let out = run("reg", &["query", r"HKCU\Environment", "/v", VAR])?;
    out.lines()
        .find(|l| l.trim_start().starts_with(VAR))
        .and_then(|l| l.split_whitespace().last())
        .map(str::to_string)
}

pub fn status() -> Status {
    if !enabled() {
        return Status::Off;
    }
    let ours = agent_path().to_string_lossy().into_owned();
    match session_value() {
        Some(v) if v == ours => Status::Active,
        Some(v) => Status::Overridden(v),
        None => Status::AfterRelogin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_d_uses_runtime_var() {
        let rt = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
        if rt.is_empty() {
            return;
        }
        let text = environment_d(&Path::new(&rt).join("keywarden/ssh.sock"));
        assert!(text.contains("SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/keywarden/ssh.sock"));
    }

    #[test]
    fn environment_d_keeps_other_paths() {
        let text = environment_d(Path::new("/srv/agent.sock"));
        assert!(text.ends_with("SSH_AUTH_SOCK=/srv/agent.sock\n"));
    }
}

// --- ключ под каждый хост: ~/.ssh/keywarden/config ---

/// Строка, которую Keywarden добавляет в начало `~/.ssh/config`.
pub const INCLUDE_LINE: &str = "Include ~/.ssh/keywarden/config";
const INCLUDE_MARK: &str = "# Keywarden: ключ под каждый хост (выключается в настройках Keywarden)";

/// Хосты из поля «Хост» записи: `github.com`, `git@github.com`, `ssh://git@host:2222`,
/// `https://gitlab.com/group`; несколько через пробел или запятую.
pub fn hosts(field: &str) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for part in field.split(|c: char| c.is_whitespace() || c == ',') {
        let s = part.trim();
        let s = s.split_once("://").map_or(s, |(_, rest)| rest);
        let s = s.rsplit_once('@').map_or(s, |(_, host)| host);
        let s = s.split(['/', ':']).next().unwrap_or_default();
        // с дефиса начинаются опции ssh: такой «хост» не берём
        let ok = !s.is_empty()
            && !s.starts_with('-')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | '?'));
        if ok && !out.iter().any(|h| h == s) {
            out.push(s.to_string());
        }
    }
    out
}

/// Имя файла открытого ключа из названия записи: латиница, цифры, дефис.
pub fn key_file_name(title: &str, taken: &[String]) -> String {
    let mut base: String = title
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if base.is_empty() {
        base = "key".into();
    }
    let mut name = format!("{base}.pub");
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{base}-{n}.pub");
        n += 1;
    }
    name
}

/// Текст `~/.ssh/keywarden/config`: (хост, файлы ключей) и путь агента Keywarden.
pub fn render_config(blocks: &[(String, Vec<String>)], agent: &Path) -> String {
    let mut s = String::from(
        "# Создаёт Keywarden: у каждого хоста свой ключ, ssh не перебирает все ключи агента.\n\
         # Ключ берётся из записи с этим хостом; файл перезаписывается, правки здесь пропадут.\n",
    );
    for (host, files) in blocks {
        s.push_str(&format!("\nHost {host}\n"));
        s.push_str(&format!("  IdentityAgent \"{}\"\n", agent.display()));
        for f in files {
            s.push_str(&format!("  IdentityFile \"~/.ssh/keywarden/{f}\"\n"));
        }
        s.push_str("  IdentitiesOnly yes\n");
    }
    s
}

/// `~/.ssh/config` с нашей строкой Include в начале (не дублируется).
pub fn with_include(config: &str) -> String {
    if config.lines().any(|l| l.trim() == INCLUDE_LINE) {
        return config.to_string();
    }
    format!("{INCLUDE_MARK}\n{INCLUDE_LINE}\n\n{config}")
}

/// `~/.ssh/config` без нашей строки и пометки.
pub fn without_include(config: &str) -> String {
    let kept: Vec<&str> = config
        .lines()
        .filter(|l| l.trim() != INCLUDE_LINE && l.trim() != INCLUDE_MARK)
        .collect();
    let mut out = kept.join("\n").trim_start_matches('\n').to_string();
    if config.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn parses_hosts() {
        assert_eq!(hosts("github.com"), ["github.com"]);
        assert_eq!(hosts("git@github.com"), ["github.com"]);
        assert_eq!(
            hosts("ssh://git@gitlab.example.org:2222/x"),
            ["gitlab.example.org"]
        );
        assert_eq!(
            hosts("https://gitlab.com/group, *.corp.lan prod-1"),
            ["gitlab.com", "*.corp.lan", "prod-1"]
        );
        assert!(hosts("").is_empty());
        assert!(hosts("bad host; rm -rf").iter().all(|h| !h.contains(';')));
    }

    #[test]
    fn file_names_are_unique() {
        assert_eq!(key_file_name("GitHub SSH", &[]), "github-ssh.pub");
        assert_eq!(
            key_file_name("GitHub SSH", &["github-ssh.pub".into()]),
            "github-ssh-2.pub"
        );
        assert_eq!(key_file_name("Ключ деплоя", &[]), "key.pub");
    }

    #[test]
    fn include_roundtrip() {
        let orig = "Host x\n  User y\n";
        let on = with_include(orig);
        assert!(on.starts_with(INCLUDE_MARK));
        assert_eq!(with_include(&on), on);
        assert_eq!(without_include(&on), orig);
        assert_eq!(without_include(&with_include("")), "");
    }

    #[test]
    fn config_has_identities_only() {
        let c = render_config(
            &[("github.com".into(), vec!["gh.pub".into()])],
            Path::new("/run/a.sock"),
        );
        assert!(c.contains("Host github.com\n  IdentityAgent \"/run/a.sock\"\n  IdentityFile \"~/.ssh/keywarden/gh.pub\"\n  IdentitiesOnly yes"));
    }
}

// --- кто просит подпись: имя сервера по его ключу ---

/// Возможные имена сервера из командной строки клиента (`ssh -T git@github.com`):
/// слова без опций, `пользователь@` отброшен.
pub fn host_candidates(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .skip(1)
        .filter(|w| !w.starts_with('-') && !w.contains('/') && !w.contains('='))
        .map(|w| {
            w.rsplit_once('@')
                .map_or(w, |(_, h)| h)
                .trim_matches('\'')
                .to_string()
        })
        .filter(|h| !h.is_empty())
        .collect()
}

/// Имя сервера с этим ключом (`тип base64`) по known_hosts. Хешированные имена (`|1|соль|хэш`)
/// проверяются на кандидатах, обычные берутся как есть.
pub fn known_host_name(known_hosts: &str, key: &str, candidates: &[String]) -> Option<String> {
    use hmac::{Hmac, KeyInit, Mac};
    let b64 = |s: &str| data_encoding::BASE64.decode(s.as_bytes()).ok();
    let want = key.split_whitespace().nth(1)?;
    for line in known_hosts.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('@') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let (Some(hosts), Some(_), Some(k)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        if k != want {
            continue;
        }
        for h in hosts.split(',') {
            if let Some(rest) = h.strip_prefix("|1|") {
                let Some((salt, hash)) = rest.split_once('|') else {
                    continue;
                };
                let (Some(salt), Some(hash)) = (b64(salt), b64(hash)) else {
                    continue;
                };
                for c in candidates {
                    let Ok(mut mac) = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(&salt) else {
                        continue;
                    };
                    mac.update(c.as_bytes());
                    if mac.finalize().into_bytes().as_slice() == hash.as_slice() {
                        return Some(c.clone());
                    }
                }
            } else if !h.starts_with('!') {
                // [host]:2222 -> host:2222
                return Some(h.replace(['[', ']'], ""));
            }
        }
    }
    None
}

#[cfg(test)]
mod known_hosts_tests {
    use super::*;

    #[test]
    fn candidates_from_command() {
        assert_eq!(
            host_candidates(
                "ssh -o SendEnv=GIT_PROTOCOL git@github.com git-upload-pack 'me/x.git'"
            ),
            ["github.com", "git-upload-pack"]
        );
        assert_eq!(host_candidates("ssh -T prod-1"), ["prod-1"]);
    }

    #[test]
    fn plain_and_hashed_names() {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
        let plain = format!("github.com,140.82.121.4 {key}\n");
        assert_eq!(
            known_host_name(&plain, key, &[]).as_deref(),
            Some("github.com")
        );
        // |1|соль|HMAC-SHA1(соль, "github.com"), как пишет ssh при HashKnownHosts yes
        use hmac::{Hmac, KeyInit, Mac};
        let salt = b"0123456789abcdef0123";
        let mut mac = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(salt).unwrap();
        mac.update(b"github.com");
        let hashed = format!(
            "|1|{}|{} {key}\n",
            data_encoding::BASE64.encode(salt),
            data_encoding::BASE64.encode(&mac.finalize().into_bytes())
        );
        let cands = vec!["git-upload-pack".to_string(), "github.com".to_string()];
        assert_eq!(
            known_host_name(&hashed, key, &cands).as_deref(),
            Some("github.com")
        );
        assert_eq!(known_host_name(&hashed, key, &["gitlab.com".into()]), None);
        assert_eq!(known_host_name(&plain, "ssh-ed25519 OTHER", &[]), None);
        assert_eq!(
            known_host_name(&format!("[git.corp]:2222 {key}"), key, &[]).as_deref(),
            Some("git.corp:2222")
        );
    }
}

// --- подключение из лаунчера: ssh в терминале ---

/// Аргументы ssh для первого хоста поля: `git@host` -> [git@host], `ssh://u@h:2222` -> [-p, 2222, u@h].
pub fn ssh_args(field: &str) -> Option<Vec<String>> {
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
        Some((h, p)) if p.parse::<u16>().is_ok() => (h, Some(p)),
        _ => (hostport, None),
    };
    // имя хоста уже проверено так же, как для ~/.ssh/config: никаких опций и подстановок
    let host = hosts(host)
        .into_iter()
        .next()
        .filter(|h| !h.contains(['*', '?']))?;
    let ok_user = |u: &str| {
        !u.is_empty()
            && u.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    };
    let mut args = vec![];
    if let Some(p) = port {
        args.extend(["-p".to_string(), p.to_string()]);
    }
    args.push(match user {
        Some(u) if ok_user(u) => format!("{u}@{host}"),
        _ => host,
    });
    Some(args)
}

/// Команда терминала, в котором выполнится `ssh АРГУМЕНТЫ`. `custom`: своя команда из конфига
/// (например `["kitty", "-e"]`), ssh дописывается в конец.
pub fn terminal_command(args: &[String], custom: &[String]) -> Option<Command> {
    let mut ssh = vec!["ssh".to_string()];
    ssh.extend(args.iter().cloned());
    if let [prog, rest @ ..] = custom {
        let mut c = Command::new(prog);
        c.args(rest).args(&ssh);
        return Some(c);
    }
    #[cfg(windows)]
    {
        let mut c = if which("wt.exe") {
            Command::new("wt.exe")
        } else {
            let mut c = Command::new("cmd");
            c.args(["/c", "start", ""]);
            c
        };
        c.args(&ssh);
        Some(c)
    }
    #[cfg(target_os = "macos")]
    {
        // Terminal.app: строка для «do script»; аргументы уже без пробелов и кавычек
        let mut c = Command::new("osascript");
        c.args([
            "-e",
            &format!(
                "tell application \"Terminal\" to do script \"{}\"",
                ssh.join(" ")
            ),
            "-e",
            "tell application \"Terminal\" to activate",
        ]);
        Some(c)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let from_env = std::env::var("TERMINAL").ok().filter(|t| which(t));
        let (prog, flag) = match from_env {
            Some(t) => (t, "-e".to_string()),
            None => TERMINALS
                .iter()
                .find(|(t, _)| which(t))
                .map(|(t, f)| (t.to_string(), f.to_string()))?,
        };
        let mut c = Command::new(prog);
        if !flag.is_empty() {
            c.arg(flag);
        }
        c.args(&ssh);
        Some(c)
    }
}

/// Известные терминалы Linux и ключ, после которого идёт команда (в порядке предпочтения).
#[cfg(all(unix, not(target_os = "macos")))]
pub const TERMINALS: [(&str, &str); 9] = [
    ("ghostty", "-e"),
    ("kitty", ""),
    ("foot", ""),
    ("alacritty", "-e"),
    ("wezterm", "start"),
    ("gnome-terminal", "--"),
    ("konsole", "-e"),
    ("xfce4-terminal", "-x"),
    ("xterm", "-e"),
];

/// Установленные терминалы для выбора в настройках (на Windows и macOS выбора нет).
pub fn installed_terminals() -> Vec<(&'static str, &'static str)> {
    #[cfg(all(unix, not(target_os = "macos")))]
    return TERMINALS.into_iter().filter(|(t, _)| which(t)).collect();
    #[cfg(not(all(unix, not(target_os = "macos"))))]
    vec![]
}

#[cfg(not(target_os = "macos"))]
fn which(prog: &str) -> bool {
    let p = Path::new(prog);
    if p.is_absolute() {
        return p.exists();
    }
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|d| {
            d.join(prog).is_file() || (cfg!(windows) && d.join(format!("{prog}.exe")).is_file())
        })
    })
}

#[cfg(test)]
mod connect_tests {
    use super::*;

    #[test]
    fn ssh_args_from_host_field() {
        assert_eq!(ssh_args("git@github.com").unwrap(), ["git@github.com"]);
        assert_eq!(ssh_args("prod-1, prod-2").unwrap(), ["prod-1"]);
        assert_eq!(
            ssh_args("ssh://deploy@prod.example.org:2222/x").unwrap(),
            ["-p", "2222", "deploy@prod.example.org"]
        );
        assert_eq!(
            ssh_args("server.lan:2200").unwrap(),
            ["-p", "2200", "server.lan"]
        );
        assert!(ssh_args("").is_none());
        assert!(ssh_args("*.corp").is_none());
        // ни опций, ни подстановок оболочки
        assert!(
            ssh_args("-oProxyCommand=x")
                .is_none_or(|a| a.iter().all(|s| !s.starts_with('-') || s == "-p"))
        );
        assert!(ssh_args("$(rm)@host").unwrap() == ["host"]);
        assert!(ssh_args("-oLocalCommand").is_none());
        assert!(hosts("-oFoo github.com") == ["github.com"]);
    }

    #[test]
    fn custom_terminal_command() {
        let c = terminal_command(&["host".into()], &["kitty".into(), "--hold".into()]).unwrap();
        let args: Vec<_> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(c.get_program(), "kitty");
        assert_eq!(args, ["--hold", "ssh", "host"]);
    }
}
