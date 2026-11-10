//! Бэкап приложения 2FAS (`.2fas`, JSON, схема 4): импорт кодов в папку «2FAS» и экспорт всех
//! кодов базы обратно в этот формат, чтобы перенести их на телефон. Зашифрованные бэкапы
//! (`servicesEncrypted`) не читаются: в 2FAS нужно выгрузить бэкап без пароля.

use crate::bitwarden::ImportReport;
use crate::model::{self, EntryKind, EntryPatch, FieldSet};
use crate::totp::{self, Totp};
use keepass::Database;
use keepass::db::fields;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum TwoFasError {
    #[error("{}", crate::tr!("это не бэкап 2FAS: {e}", e = .0))]
    Format(String),
    #[error("{}", crate::tr!("бэкап 2FAS зашифрован паролем; выгрузите в 2FAS бэкап без пароля"))]
    Encrypted,
    #[error(transparent)]
    Model(#[from] model::ModelError),
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Backup {
    #[serde(default)]
    services: Vec<Service>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    services_encrypted: Option<String>,
    #[serde(default)]
    groups: Vec<Group>,
    #[serde(default)]
    updated_at: u64,
    #[serde(default)]
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app_version_code: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app_version_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    app_origin: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Group {
    id: String,
    name: String,
    #[serde(default)]
    is_expanded: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Service {
    name: String,
    secret: String,
    #[serde(default)]
    updated_at: u64,
    #[serde(default)]
    otp: Otp,
    #[serde(default)]
    order: Order,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group_id: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Otp {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    account: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    digits: Option<u32>,
    #[serde(default)]
    period: Option<u64>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    counter: Option<u64>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Order {
    #[serde(default)]
    position: u64,
}

pub fn import(db: &mut Database, json: &str) -> Result<ImportReport, TwoFasError> {
    let b: Backup = serde_json::from_str(json).map_err(|e| TwoFasError::Format(e.to_string()))?;
    if b.services.is_empty() && b.services_encrypted.is_some() {
        return Err(TwoFasError::Encrypted);
    }
    let mut report = ImportReport::default();
    let root = model::add_group(db, None, "2FAS")?;
    let mut groups: HashMap<String, String> = HashMap::new();
    for g in &b.groups {
        let id = model::add_group(db, Some(&root), &g.name)?;
        report.folders += 1;
        groups.insert(g.id.clone(), id);
    }
    for s in &b.services {
        let kind = s.otp.token_type.as_deref().unwrap_or("TOTP").to_uppercase();
        let account = s
            .otp
            .account
            .clone()
            .or(s.otp.label.clone())
            .unwrap_or_default();
        let issuer = s.otp.issuer.clone().unwrap_or_else(|| s.name.clone());
        if kind == "HOTP" {
            report.review.push(crate::tr!(
                "{name}: HOTP (счётчик) не поддерживается, пропущено",
                name = s.name
            ));
            continue;
        }
        let mut uri = format!(
            "otpauth://totp/x?secret={}&period={}&digits={}&algorithm={}",
            s.secret.replace(' ', ""),
            s.otp.period.unwrap_or(30),
            s.otp.digits.unwrap_or(6),
            s.otp.algorithm.as_deref().unwrap_or("SHA1")
        );
        if kind == "STEAM" {
            uri.push_str("&encoder=steam");
        }
        let t = match Totp::parse(&uri) {
            Ok(t) => t,
            Err(e) => {
                report.review.push(format!("{}: {e}", s.name));
                continue;
            }
        };
        let group = s
            .group_id
            .as_ref()
            .and_then(|g| groups.get(g))
            .cloned()
            .unwrap_or_else(|| root.clone());
        model::create_entry(
            db,
            &EntryPatch {
                kind: Some(EntryKind::Login),
                group: Some(group),
                set: vec![
                    FieldSet::new(fields::TITLE, s.name.clone()),
                    FieldSet::new(fields::USERNAME, account.clone()),
                    FieldSet::new(fields::OTP, t.to_uri(&issuer, &account).to_string()),
                ],
                ..Default::default()
            },
        )?;
        report.logins += 1;
    }
    Ok(report)
}

/// Все записи с 2FA (вне корзины) как бэкап 2FAS. В файле секреты открытым текстом.
pub fn export(db: &Database) -> String {
    let mut services = vec![];
    for e in db.iter_all_entries() {
        if model::in_recycle_bin(db, e.parent().id()) {
            continue;
        }
        let Ok(t) = Totp::from_entry(&e) else {
            continue;
        };
        let title = e.get(fields::TITLE).unwrap_or_default().to_string();
        let account = e.get(fields::USERNAME).unwrap_or_default().to_string();
        let modified = e
            .times
            .last_modification
            .map(|t| t.and_utc().timestamp_millis().max(0) as u64)
            .unwrap_or(0);
        services.push(Service {
            name: title.clone(),
            secret: t.secret_base32().to_string(),
            updated_at: modified,
            otp: Otp {
                label: Some(account.clone()),
                account: Some(account),
                issuer: Some(title),
                digits: Some(t.digits),
                period: Some(t.period),
                algorithm: Some(t.algorithm_name().into()),
                counter: Some(0),
                token_type: Some(if t.steam { "STEAM" } else { "TOTP" }.into()),
                source: Some("Link".into()),
            },
            order: Order {
                position: services.len() as u64,
            },
            group_id: None,
        });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let b = Backup {
        services,
        updated_at: now,
        schema_version: 4,
        app_version_code: Some(5_000_000),
        app_version_name: Some("Keywarden".into()),
        app_origin: Some("android".into()),
        ..Default::default()
    };
    serde_json::to_string_pretty(&b).unwrap_or_default()
}

/// Подсказка для мастера: код по введённому значению (без сохранения).
pub fn preview(input: &str, issuer: &str, account: &str) -> Result<(String, totp::Code), String> {
    let uri = totp::normalize(input, issuer, account).map_err(|e| e.to_string())?;
    let t = Totp::parse(&uri).map_err(|e| e.to_string())?;
    Ok((uri.to_string(), t.now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "services": [
        {"name": "GitHub", "secret": "JBSWY3DPEHPK3PXP", "updatedAt": 1700000000000,
         "otp": {"label": "octo", "account": "octo", "issuer": "GitHub", "digits": 6, "period": 30,
                 "algorithm": "SHA1", "counter": 0, "tokenType": "TOTP", "source": "Manual"},
         "order": {"position": 0}, "groupId": "g1"},
        {"name": "Steam", "secret": "JBSWY3DPEHPK3PXP",
         "otp": {"account": "gamer", "tokenType": "STEAM", "digits": 5, "period": 30, "algorithm": "SHA1"},
         "order": {"position": 1}},
        {"name": "Old", "secret": "JBSWY3DPEHPK3PXP", "otp": {"tokenType": "HOTP", "counter": 5}}
      ],
      "groups": [{"id": "g1", "name": "Работа", "isExpanded": true}],
      "updatedAt": 1700000000000, "schemaVersion": 4, "appVersionCode": 5000000, "appOrigin": "android"
    }"#;

    #[test]
    fn import_export_roundtrip() {
        let mut db = Database::new();
        let r = import(&mut db, SAMPLE).unwrap();
        assert_eq!(r.logins, 2);
        assert_eq!(r.review.len(), 1, "HOTP пропущен с пометкой");
        let gh = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("GitHub"))
            .unwrap();
        assert_eq!(model::group_path(&db, gh.parent().id()), "2FAS/Работа");
        let steam = db
            .iter_all_entries()
            .find(|e| e.get_title() == Some("Steam"))
            .unwrap();
        assert_eq!(Totp::from_entry(&steam).unwrap().now().code.len(), 5);

        let json = export(&db);
        let mut back = Database::new();
        let r2 = import(&mut back, &json).unwrap();
        assert_eq!(r2.logins, 2);
        let code = |db: &Database, t: &str| {
            Totp::from_entry(
                &db.iter_all_entries()
                    .find(|e| e.get_title() == Some(t))
                    .unwrap(),
            )
            .unwrap()
            .at(1_700_000_000)
            .code
        };
        assert_eq!(code(&db, "GitHub"), code(&back, "GitHub"));
        assert_eq!(code(&db, "Steam"), code(&back, "Steam"));
    }

    #[test]
    fn encrypted_backup_is_refused() {
        let mut db = Database::new();
        let e = import(
            &mut db,
            r#"{"services":[],"servicesEncrypted":"abc:def:ghi","schemaVersion":4}"#,
        );
        assert!(matches!(e, Err(TwoFasError::Encrypted)));
    }
}
