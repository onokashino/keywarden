//! Иконка сайта записи по нажатию кнопки (как «Загрузить favicon» в KeePassXC): только https,
//! с ограничением размера; результат PNG 64×64 сохраняется в базу как собственная иконка,
//! её видят KeePassXC и KeePassDX. Сам по себе Keywarden в сеть не ходит.

use crate::state::{Daemon, Reply, blocking, model_err};
use data_encoding::BASE64;
use keywarden_core::ipc::{ErrorCode, Response};
use keywarden_core::model;
use std::io::Read;
use std::time::Duration;

const MAX_HTML: u64 = 512 * 1024;
const MAX_ICON: u64 = 512 * 1024;

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) Keywarden-favicon")
        .build()
}

fn get(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>, String> {
    let resp = agent.get(url).call().map_err(|e| e.to_string())?;
    let mut buf = vec![];
    resp.into_reader()
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Ссылки на иконки из `<link rel="...icon..." href="...">`: сначала apple-touch-icon (крупнее).
pub(crate) fn icon_links(html: &str, base: &url::Url) -> Vec<url::Url> {
    let lower = html.to_lowercase();
    let mut found: Vec<(u8, url::Url)> = vec![];
    let mut pos = 0;
    while let Some(start) = lower[pos..].find("<link") {
        let start = pos + start;
        let end = lower[start..]
            .find('>')
            .map(|e| start + e)
            .unwrap_or(lower.len());
        let tag = &html[start..end];
        let tag_l = &lower[start..end];
        pos = end;
        let attr = |name: &str| -> Option<String> {
            let i = tag_l.find(&format!("{name}="))? + name.len() + 1;
            let rest = &tag[i..];
            let q = rest.chars().next()?;
            if q == '"' || q == '\'' {
                rest[1..].find(q).map(|e| rest[1..1 + e].to_string())
            } else {
                Some(
                    rest.split([' ', '/'])
                        .next()
                        .unwrap_or_default()
                        .to_string(),
                )
            }
        };
        let Some(rel) = attr("rel").map(|r| r.to_lowercase()) else {
            continue;
        };
        if !rel.contains("icon") || rel.contains("mask") {
            continue;
        }
        let Some(href) = attr("href").and_then(|h| base.join(&h).ok()) else {
            continue;
        };
        if href.scheme() != "https" {
            continue;
        }
        found.push((if rel.contains("apple-touch") { 0 } else { 1 }, href));
    }
    found.sort_by_key(|(p, _)| *p);
    found.into_iter().map(|(_, u)| u).collect()
}

fn to_png(bytes: &[u8]) -> Option<Vec<u8>> {
    let img = image::load_from_memory(bytes).ok()?;
    let img = img.resize(64, 64, image::imageops::FilterType::Lanczos3);
    let mut out = vec![];
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
        .ok()?;
    Some(out)
}

fn fetch(site: url::Url) -> Result<Vec<u8>, String> {
    let agent = agent();
    let mut candidates = vec![];
    if let Ok(html) = get(&agent, site.as_str(), MAX_HTML) {
        candidates = icon_links(&String::from_utf8_lossy(&html), &site);
    }
    if let Ok(ico) = site.join("/favicon.ico") {
        candidates.push(ico);
    }
    for url in candidates {
        if let Ok(bytes) = get(&agent, url.as_str(), MAX_ICON)
            && let Some(png) = to_png(&bytes)
        {
            return Ok(png);
        }
    }
    Err(tr!(
        "у {site} не нашлось иконки",
        site = site.host_str().unwrap_or_default()
    ))
}

impl Daemon {
    pub(crate) async fn fetch_favicon(&self, id: String) -> Reply<Response> {
        let url = self.read(|db| {
            let d = model::detail(db, &id, false).map_err(model_err)?;
            Ok(d.summary.url)
        })?;
        let site = url::Url::parse(&url)
            .or_else(|_| url::Url::parse(&format!("https://{url}")))
            .ok()
            .and_then(|u| u.host_str().map(|h| format!("https://{h}/")))
            .and_then(|u| url::Url::parse(&u).ok())
            .ok_or_else(|| Response::error(ErrorCode::Invalid, tr!("у записи нет адреса сайта")))?;
        let png = blocking(move || fetch(site)).await?;
        self.mutate(move |db| model::set_custom_icon(db, &id, png))
            .await?;
        Ok(Response::Ok)
    }

    pub(crate) fn icon_data(&self, uuid: String) -> Reply<Response> {
        let data = self.read(|db| {
            model::icon_data(db, &uuid)
                .ok_or_else(|| Response::error(ErrorCode::NotFound, tr!("иконки нет")))
        })?;
        // битая картинка (бывает в базах из других программ): окно покажет логотип или монограмму
        let data = match image::guess_format(&data) {
            Ok(image::ImageFormat::Png) if image::load_from_memory(&data).is_ok() => data,
            _ => to_png(&data)
                .ok_or_else(|| Response::error(ErrorCode::NotFound, tr!("иконка повреждена")))?,
        };
        Ok(Response::IconData {
            data: BASE64.encode(&data),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_icon_links() {
        let base = url::Url::parse("https://example.com/login").unwrap();
        let html = r#"<html><head>
            <link rel="stylesheet" href="/a.css">
            <link rel='icon' type="image/png" href="/static/fav.png">
            <link href="https://cdn.example.com/apple.png" rel="apple-touch-icon" sizes="180x180">
            <link rel="mask-icon" href="/mask.svg">
            <LINK REL="shortcut icon" HREF="http://insecure.example.com/x.ico">
        </head></html>"#;
        let v: Vec<String> = icon_links(html, &base)
            .into_iter()
            .map(|u| u.to_string())
            .collect();
        assert_eq!(
            v,
            [
                "https://cdn.example.com/apple.png",
                "https://example.com/static/fav.png"
            ]
        );
    }

    #[test]
    fn converts_to_small_png() {
        let img = image::RgbaImage::from_pixel(200, 100, image::Rgba([10, 20, 30, 255]));
        let mut bytes = vec![];
        img.write_to(
            &mut std::io::Cursor::new(&mut bytes),
            image::ImageFormat::Png,
        )
        .unwrap();
        let png = to_png(&bytes).unwrap();
        let back = image::load_from_memory(&png).unwrap();
        assert!(back.width() <= 64 && back.height() <= 64);
        assert!(to_png(b"<html>").is_none());
    }
}
