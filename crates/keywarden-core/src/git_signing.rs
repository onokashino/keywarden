//! Подпись коммитов и тегов git SSH-ключом из базы: git подписывает через агент Keywarden
//! (`ssh-keygen -Y sign` с открытым ключом), приватный ключ на диск не попадает.
//!
//! Пишется глобальный конфиг git: `gpg.format ssh`, `user.signingkey key::<ключ>`,
//! `commit.gpgsign`, `tag.gpgsign`, `gpg.ssh.allowedSignersFile` (для проверки своих подписей).

use std::path::PathBuf;
use std::process::Command;

fn git(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .output()
        .map_err(|e| crate::tr!("git не найден: {e}", e = e))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn get(key: &str) -> Option<String> {
    git(&["config", "--global", "--get", key])
        .ok()
        .filter(|v| !v.is_empty())
}

/// Открытый ключ без комментария: «ssh-ed25519 AAAA…».
pub fn key_body(public: &str) -> Option<String> {
    let mut parts = public.split_whitespace();
    let (alg, data) = (parts.next()?, parts.next()?);
    (alg.starts_with("ssh-") || alg.starts_with("ecdsa-") || alg.starts_with("sk-"))
        .then(|| format!("{alg} {data}"))
}

fn allowed_signers() -> PathBuf {
    crate::platform::home()
        .join(".ssh")
        .join("keywarden")
        .join("allowed_signers")
}

/// Ключ, которым git сейчас подписывает (если подпись через SSH включена).
pub fn current() -> Option<String> {
    (get("gpg.format").as_deref() == Some("ssh"))
        .then(|| get("user.signingkey"))
        .flatten()
        .map(|k| k.strip_prefix("key::").unwrap_or(&k).to_string())
}

/// Подписывать этим ключом (открытый ключ в формате OpenSSH).
pub fn enable(public: &str) -> Result<(), String> {
    let body =
        key_body(public).ok_or_else(|| crate::tr!("это не открытый ключ SSH").to_string())?;
    let email = get("user.email").unwrap_or_else(|| "*".into());
    let file = allowed_signers();
    if let Some(dir) = file.parent() {
        crate::platform::create_private_dir(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(&file, format!("{email} {body}\n")).map_err(|e| e.to_string())?;
    let signing = format!("key::{body}");
    let file = file.to_string_lossy().into_owned();
    for (k, v) in [
        ("gpg.format", "ssh"),
        ("user.signingkey", signing.as_str()),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
        ("gpg.ssh.allowedSignersFile", file.as_str()),
    ] {
        git(&["config", "--global", k, v])?;
    }
    Ok(())
}

/// Перестать подписывать: убрать настройки, если они наши (чужую подпись GPG не трогаем).
pub fn disable() -> Result<(), String> {
    if current().is_none() {
        return Ok(());
    }
    for k in [
        "user.signingkey",
        "commit.gpgsign",
        "tag.gpgsign",
        "gpg.format",
        "gpg.ssh.allowedSignersFile",
    ] {
        let _ = git(&["config", "--global", "--unset", k]);
    }
    let _ = std::fs::remove_file(allowed_signers());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::key_body;

    #[test]
    fn strips_comment() {
        assert_eq!(
            key_body("ssh-ed25519 AAAAC3Nz me@host").as_deref(),
            Some("ssh-ed25519 AAAAC3Nz")
        );
        assert_eq!(key_body("not a key").as_deref(), None);
        assert_eq!(key_body("").as_deref(), None);
    }
}
