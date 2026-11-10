//! Проверка паролей. Утечки: Have I Been Pwned по k-анонимности, только когда пользователь нажал
//! кнопку; наружу уходят первые 5 символов SHA-1, никогда пароль или полный хэш.

use crate::state::{Daemon, Reply, blocking};
use keywarden_core::health;
use keywarden_core::ipc::Response;
use std::collections::HashMap;
use std::time::Duration;

fn fetch(queries: HashMap<String, Vec<(String, String)>>) -> Result<HashMap<String, u64>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .user_agent("Keywarden-password-manager")
        .build();
    let mut found = HashMap::new();
    for (prefix, wanted) in queries {
        let body = agent
            .get(&format!("https://api.pwnedpasswords.com/range/{prefix}"))
            // ответ дополняется пустыми строками до одинакового размера: по длине не понять, что искали
            .set("Add-Padding", "true")
            .call()
            .map_err(|e| tr!("Have I Been Pwned недоступен: {e}", e = e))?
            .into_string()
            .map_err(|e| e.to_string())?;
        health::hibp_parse(&body, &wanted, &mut found);
    }
    Ok(found)
}

/// Списки 2fa.directory целиком (наружу ничего о базе не уходит). Ошибка не мешает остальному отчёту.
fn fetch_directory() -> Option<health::Directory> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(20))
        .user_agent("Keywarden-password-manager")
        .build();
    let get = |url: &str| -> Result<String, String> {
        agent
            .get(url)
            .call()
            .map_err(|e| e.to_string())?
            .into_string()
            .map_err(|e| e.to_string())
    };
    let mut dir = health::Directory::default();
    let r = get("https://api.2fa.directory/v3/totp.json")
        .and_then(|b| dir.parse_totp(&b))
        .and_then(|_| get("https://passkeys-api.2fa.directory/v1/supported.json"))
        .and_then(|b| dir.parse_passkeys(&b));
    match r {
        Ok(()) => Some(dir),
        Err(e) => {
            tracing::warn!("2fa.directory недоступен: {e}");
            None
        }
    }
}

impl Daemon {
    pub(crate) async fn health(&self, breaches: bool) -> Reply<Response> {
        if !breaches {
            return Ok(Response::Health {
                report: self.read(|db| Ok(health::report(db, None, None)))?,
            });
        }
        let queries = self.read(|db| Ok(health::hibp_queries(db)))?;
        tracing::info!("проверка утечек: {} запросов к HIBP", queries.len());
        let (found, dir) = blocking(move || fetch(queries).map(|f| (f, fetch_directory()))).await?;
        Ok(Response::Health {
            report: self.read(|db| Ok(health::report(db, Some(&found), dir.as_ref())))?,
        })
    }
}
