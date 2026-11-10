//! Подтверждение действия пользователем: окно `keywarden-ui --confirm` поверх всего.
//! Используется для подключения расширения, выдачи пароля новому сайту и подписи SSH-ключом.

use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Deny,
    Once,
    Always,
}

#[derive(Debug, Clone, Serialize)]
pub struct Prompt {
    pub title: String,
    pub text: String,
    /// показывать ли кнопку «Разрешить всегда»
    pub allow_always: bool,
    /// «всегда» означает N минут (SSH): так и подписать кнопку
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_minutes: Option<u32>,
}

const TIMEOUT: Duration = Duration::from_secs(60);

/// Блокирующий вызов: ждёт ответа пользователя (не дольше минуты, потом отказ).
pub fn ask(command: Option<&[String]>, prompt: &Prompt) -> Decision {
    let json = serde_json::to_string(prompt).expect("сериализуется");
    let mut cmd = match command {
        Some([prog, args @ ..]) => {
            let mut c = Command::new(prog);
            c.args(args);
            c
        }
        _ => {
            let mut c = Command::new(ui_binary());
            c.arg("--confirm");
            c
        }
    };
    cmd.arg(&json);
    let Ok(child) = cmd
        .spawn()
        .map_err(|e| tracing::warn!("окно подтверждения не запустилось: {e}"))
    else {
        return Decision::Deny;
    };
    match wait(child, TIMEOUT).and_then(|s| s.code()) {
        Some(11) => Decision::Always,
        Some(10) => Decision::Once,
        _ => Decision::Deny,
    }
}

/// Окно разблокировки `keywarden-ui --unlock ПРИЧИНА` (просит SSH-агент). Ждёт, пока его
/// закроют: после разблокировки окно закрывается само. Не дольше двух минут.
pub fn unlock(reason: &str) {
    match Command::new(ui_binary())
        .arg("--unlock")
        .arg(reason)
        .spawn()
    {
        Ok(child) => {
            wait(child, Duration::from_secs(120));
        }
        Err(e) => tracing::warn!("окно разблокировки не запустилось: {e}"),
    }
}

/// Дождаться выхода процесса; по тайм-ауту он убивается и возвращается None.
fn wait(mut child: std::process::Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// keywarden-ui рядом с демоном, иначе из PATH.
pub fn ui_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|d| d.join(format!("keywarden-ui{}", std::env::consts::EXE_SUFFIX)))
        })
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("keywarden-ui"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prompt() -> Prompt {
        Prompt {
            title: "t".into(),
            text: "x".into(),
            allow_always: true,
            always_minutes: None,
        }
    }

    #[test]
    fn exit_codes() {
        let sh = |code: &str| {
            vec![
                "sh".to_string(),
                "-c".into(),
                format!("exit {code}"),
                "sh".into(),
            ]
        };
        assert_eq!(ask(Some(&sh("11")), &prompt()), Decision::Always);
        assert_eq!(ask(Some(&sh("10")), &prompt()), Decision::Once);
        assert_eq!(ask(Some(&sh("1")), &prompt()), Decision::Deny);
        assert_eq!(
            ask(Some(&["/нет/такой/программы".to_string()]), &prompt()),
            Decision::Deny
        );
    }
}
