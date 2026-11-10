//! Проверка новой версии: выключена по умолчанию, раз в сутки один запрос к GitHub Releases.
//! Ничего не скачивает и не ставит: обновляет менеджер пакетов или сам пользователь.

use crate::state::Daemon;
use std::sync::Arc;
use std::time::Duration;

const LATEST: &str = "https://api.github.com/repos/onokashino/keywarden/releases/latest";

pub async fn watch(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10 * 60));
    loop {
        tick.tick().await;
        let c = d.config();
        let now = chrono::Utc::now();
        let due = c
            .last_update_check
            .as_deref()
            .and_then(|l| chrono::DateTime::parse_from_rfc3339(l).ok())
            .is_none_or(|l| now.signed_duration_since(l) > chrono::TimeDelta::days(1));
        if !c.check_updates || !due {
            continue;
        }
        d.update_config(|c| {
            c.last_update_check = Some(now.to_rfc3339());
            true
        });
        let tag = match tokio::task::spawn_blocking(latest).await {
            Ok(Ok(tag)) => tag,
            Ok(Err(e)) => {
                tracing::warn!("проверка обновлений не удалась: {e}");
                continue;
            }
            Err(_) => continue,
        };
        let fresh = is_newer(&tag, env!("CARGO_PKG_VERSION"))
            && c.latest_release.as_deref() != Some(tag.as_str());
        d.update_config(|c| {
            c.latest_release = Some(tag.clone());
            true
        });
        if fresh {
            let body = tr!(
                "Вышла версия {version}. Подробности в настройках, вкладка «Этот компьютер»",
                version = tag
            );
            crate::sync::notify_desktop(tr!("Keywarden: доступно обновление"), &body).await;
        }
    }
}

fn latest() -> Result<String, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .user_agent("Keywarden-password-manager")
        .build();
    let body = agent
        .get(LATEST)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
    v["tag_name"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "нет tag_name".into())
}

/// Тег `vX.Y.Z` новее текущей версии `X.Y.Z`. Предрелизы (с дефисом) не предлагаем.
pub fn is_newer(tag: &str, current: &str) -> bool {
    fn parse(s: &str) -> Option<Vec<u64>> {
        let s = s.strip_prefix('v').unwrap_or(s);
        if s.contains('-') {
            return None;
        }
        s.split('.').map(|p| p.parse().ok()).collect()
    }
    matches!((parse(tag), parse(current)), (Some(t), Some(c)) if t > c)
}

#[cfg(test)]
mod tests {
    use super::is_newer;

    #[test]
    fn compares_versions() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("v0.10.0", "0.9.3"));
        assert!(is_newer("v1.0.0", "0.99.99"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.0.9", "0.1.0"));
        assert!(!is_newer("v0.2.0-rc1", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"));
    }
}
