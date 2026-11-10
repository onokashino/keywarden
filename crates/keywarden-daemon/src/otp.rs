//! 2FA: предпросмотр в мастере, установка в запись, ссылка для QR (перенос на телефон),
//! распознавание QR-кода с картинки или из буфера обмена (скриншот области в niri кладёт
//! картинку в буфер), экспорт в бэкап 2FAS.

use crate::state::{Daemon, Reply, blocking, model_err};
use keepass::db::fields;
use keywarden_core::ipc::{ErrorCode, Response};
use keywarden_core::model::{self, EntryPatch, FieldSet, LEGACY_TOTP_SEED, LEGACY_TOTP_SETTINGS};
use keywarden_core::secret::Secret;
use keywarden_core::totp::{self, Totp};
use keywarden_core::{twofas, vault};
use std::path::PathBuf;

fn invalid(m: impl Into<String>) -> Response {
    Response::error(ErrorCode::Invalid, m)
}

/// Первый QR-код на картинке.
pub(crate) fn scan_qr(bytes: &[u8]) -> Result<String, String> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| tr!("картинка не прочитана: {e}", e = e))?
        .to_luma8();
    scan_luma(img)
}

fn scan_luma(img: image::GrayImage) -> Result<String, String> {
    let mut prepared = rqrr::PreparedImage::prepare(img);
    for grid in prepared.detect_grids() {
        if let Ok((_, content)) = grid.decode() {
            return Ok(content);
        }
    }
    Err(tr!("QR-код на картинке не найден").into())
}

/// Буфер обмена: картинка (скриншот) или текст (скопированный секрет либо ссылка).
fn from_clipboard() -> Result<String, String> {
    use crate::clipboard::Pasted;
    let text = match crate::clipboard::paste(true)? {
        Pasted::Encoded(bytes) => return scan_qr(&bytes),
        Pasted::Rgba {
            width,
            height,
            bytes,
        } => {
            let img = image::RgbaImage::from_raw(width, height, bytes)
                .ok_or(tr!("картинка в буфере повреждена"))?;
            return scan_luma(image::DynamicImage::ImageRgba8(img).to_luma8());
        }
        Pasted::Text(t) => t.trim().to_string(),
    };
    if text.is_empty() {
        return Err(tr!("в буфере обмена нет ни картинки, ни текста").into());
    }
    Ok(text)
}

impl Daemon {
    pub(crate) fn otp_preview(
        &self,
        input: Secret,
        issuer: String,
        account: String,
    ) -> Reply<Response> {
        let (uri, code) = twofas::preview(input.expose(), &issuer, &account).map_err(invalid)?;
        Ok(Response::OtpPreview {
            uri: Secret::new(uri),
            code,
        })
    }

    pub(crate) async fn set_otp(&self, id: String, value: Secret) -> Reply<Response> {
        // ссылку с названием из мастера оставляем как есть, голый секрет превращаем в ссылку
        let (title, user) = self.read(|db| {
            let d = model::detail(db, &id, false).map_err(model_err)?;
            Ok((d.summary.title, d.summary.username))
        })?;
        let (issuer, account) = if value.expose().trim().starts_with("otpauth://") {
            (String::new(), String::new())
        } else {
            (title, user)
        };
        let uri = totp::normalize(value.expose(), &issuer, &account)
            .map_err(|e| invalid(e.to_string()))?;
        let patch = EntryPatch {
            set: vec![FieldSet {
                name: fields::OTP.into(),
                value: Secret::new(uri.to_string()),
                protected: Some(true),
            }],
            remove: vec![LEGACY_TOTP_SEED.into(), LEGACY_TOTP_SETTINGS.into()],
            ..Default::default()
        };
        self.mutate(move |db| model::update_entry(db, &id, &patch))
            .await?;
        Ok(Response::Ok)
    }

    pub(crate) fn otp_uri(&self, id: String) -> Reply<Response> {
        let uri = self.read(|db| {
            let e = db
                .entry(model::parse_entry_id(&id).map_err(model_err)?)
                .ok_or_else(|| model_err(model::ModelError::EntryNotFound))?;
            let t = Totp::from_entry(&e)
                .map_err(|e| Response::error(ErrorCode::NotFound, e.to_string()))?;
            Ok(t.to_uri(
                e.get(fields::TITLE).unwrap_or_default(),
                e.get(fields::USERNAME).unwrap_or_default(),
            ))
        })?;
        Ok(Response::OtpUri {
            uri: Secret::new(uri.to_string()),
        })
    }

    pub(crate) async fn otp_scan(&self, path: Option<String>) -> Reply<Response> {
        let text = blocking(move || -> Result<String, String> {
            match path {
                Some(p) => {
                    let bytes = std::fs::read(crate::config::expand(&PathBuf::from(p)))
                        .map_err(|e| e.to_string())?;
                    scan_qr(&bytes)
                }
                None => from_clipboard(),
            }
        })
        .await?;
        if text.starts_with("otpauth-migration://") {
            return Err(invalid(tr!(
                "это экспорт Google Authenticator (несколько кодов сразу), он пока не поддерживается: добавляйте коды по одному"
            )));
        }
        Ok(Response::OtpScanned {
            text: Secret::new(text),
        })
    }

    pub(crate) async fn export_twofas(&self, path: String) -> Reply<Response> {
        let json = self.read(|db| Ok(twofas::export(db)))?;
        let p = crate::config::expand(&PathBuf::from(path));
        blocking(move || vault::write_atomic(&p, json.as_bytes()).map_err(vault::VaultError::Io))
            .await?;
        Ok(Response::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_generated_qr() {
        // QR, нарисованный нашим же qr_matrix, распознаётся обратно
        let text = "otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let (w, cells) = totp::qr_matrix(text).unwrap();
        let scale = 8u32;
        let border = 4u32;
        let side = (w as u32 + border * 2) * scale;
        let img = image::GrayImage::from_fn(side, side, |x, y| {
            let (cx, cy) = (x / scale, y / scale);
            let dark = cx >= border
                && cy >= border
                && cx < border + w as u32
                && cy < border + w as u32
                && cells[((cy - border) as usize) * w + (cx - border) as usize];
            image::Luma([if dark { 0 } else { 255 }])
        });
        let mut png = vec![];
        img.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .unwrap();
        assert_eq!(scan_qr(&png).unwrap(), text);
        assert!(scan_qr(b"not an image").is_err());
    }
}
