//! Запуск демона при входе в систему (переключатель в настройках, по умолчанию выключено):
//!
//! - Linux: пользовательская служба systemd `keywardend.service`; если пакет её не поставил,
//!   пишем свою в `~/.config/systemd/user`;
//! - macOS: LaunchAgent `dev.keywarden.daemon`;
//! - Windows: значение в `HKCU\...\CurrentVersion\Run`.

use std::path::PathBuf;
#[cfg(all(unix, not(target_os = "macos")))]
use std::process::Command;

/// keywardend рядом с запущенной программой, иначе просто имя (ищется в PATH).
pub fn daemon_path() -> PathBuf {
    let name = format!("keywardend{}", std::env::consts::EXE_SUFFIX);
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(&name)))
        .filter(|p| p.exists())
        .unwrap_or_else(|| name.into())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

// --- Linux ---

#[cfg(all(unix, not(target_os = "macos")))]
const UNIT: &str = "keywardend.service";

#[cfg(all(unix, not(target_os = "macos")))]
fn own_unit() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| crate::platform::home().join(".config"));
    base.join("systemd/user").join(UNIT)
}

/// Своя служба, когда пакет её не поставил (архив с GitHub, сборка из исходников).
pub fn unit_text(daemon: &std::path::Path) -> String {
    format!(
        "# Keywarden: запуск при входе (выключается в настройках Keywarden)\n\
         [Unit]\nDescription=Keywarden password manager daemon\n\
         PartOf=graphical-session.target\nAfter=graphical-session.target\n\n\
         [Service]\nExecStart={}\nRestart=on-failure\nLimitCORE=0\nLimitMEMLOCK=infinity\n\
         MemorySwapMax=0\nNoNewPrivileges=yes\n\n\
         [Install]\nWantedBy=graphical-session.target\n",
        daemon.display()
    )
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn enable() -> std::io::Result<()> {
    if !ok("systemctl", &["--user", "cat", UNIT]) {
        let file = own_unit();
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&file, unit_text(&daemon_path()))?;
        ok("systemctl", &["--user", "daemon-reload"]);
    }
    if ok("systemctl", &["--user", "enable", UNIT]) {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "systemctl --user enable keywardend.service",
        ))
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn disable() -> std::io::Result<()> {
    ok("systemctl", &["--user", "disable", UNIT]);
    // свою службу убираем, пакетную не трогаем
    let file = own_unit();
    if std::fs::read_to_string(&file).is_ok_and(|t| t.starts_with("# Keywarden")) {
        std::fs::remove_file(file)?;
        ok("systemctl", &["--user", "daemon-reload"]);
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn enabled() -> bool {
    ok("systemctl", &["--user", "is-enabled", "--quiet", UNIT])
}

// --- macOS ---

#[cfg(target_os = "macos")]
fn plist() -> PathBuf {
    crate::platform::home().join("Library/LaunchAgents/dev.keywarden.daemon.plist")
}

#[cfg(target_os = "macos")]
pub fn enable() -> std::io::Result<()> {
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
  <key>Label</key><string>dev.keywarden.daemon</string>
  <key>ProgramArguments</key><array><string>{}</string></array>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Interactive</string>
</dict></plist>
"#,
            daemon_path().display()
        ),
    )
}

#[cfg(target_os = "macos")]
pub fn disable() -> std::io::Result<()> {
    match std::fs::remove_file(plist()) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(target_os = "macos")]
pub fn enabled() -> bool {
    plist().exists()
}

// --- Windows ---

#[cfg(windows)]
const RUN: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";

#[cfg(windows)]
fn reg(args: &[&str]) -> bool {
    use std::os::windows::process::CommandExt;
    std::process::Command::new("reg")
        .args(args)
        .creation_flags(0x0800_0000)
        .output()
        .is_ok_and(|o| o.status.success())
}

#[cfg(windows)]
pub fn enable() -> std::io::Result<()> {
    let value = format!("\"{}\"", daemon_path().display());
    if reg(&[
        "add",
        RUN,
        "/v",
        "Keywarden",
        "/t",
        "REG_SZ",
        "/d",
        &value,
        "/f",
    ]) {
        Ok(())
    } else {
        Err(std::io::Error::other("reg add"))
    }
}

#[cfg(windows)]
pub fn disable() -> std::io::Result<()> {
    if enabled() {
        reg(&["delete", RUN, "/v", "Keywarden", "/f"]);
    }
    Ok(())
}

#[cfg(windows)]
pub fn enabled() -> bool {
    reg(&["query", RUN, "/v", "Keywarden"])
}

#[cfg(test)]
mod tests {
    #[test]
    fn unit_runs_given_daemon() {
        let t = super::unit_text(std::path::Path::new("/opt/kw/keywardend"));
        assert!(t.starts_with("# Keywarden"));
        assert!(t.contains("\nExecStart=/opt/kw/keywardend\n"));
        assert!(t.contains("WantedBy=graphical-session.target"));
    }
}
