//! Логотипы сервисов (Simple Icons, CC0; товарные знаки принадлежат владельцам) и плитка записи
//! в варианте C: полупрозрачная подложка цвета бренда и логотип этого цвета. Без логотипа:
//! монограмма с цветом из названия (логины) или иконка типа записи (карты, заметки, ключи).
//! Всё офлайн: таблица вшита в бинарник (assets/brands.tsv.gz, scripts/gen-brands.py).

use gpui_kit::component::{Icon, Sizable as _};
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::model::{EntryKind, EntrySummary};
use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

pub struct Brand {
    pub slug: String,
    pub rgb: u32,
    path: String,
}

struct Index {
    brands: Vec<Brand>,
    by_name: HashMap<String, usize>,
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn index() -> &'static Index {
    static INDEX: OnceLock<Index> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut text = String::new();
        let _ = flate2::read::GzDecoder::new(&include_bytes!("../assets/brands.tsv.gz")[..])
            .read_to_string(&mut text);
        let mut brands = vec![];
        let mut by_name = HashMap::new();
        for line in text.lines() {
            let mut f = line.split('\t');
            let (Some(slug), Some(hex), Some(title), Some(aliases), Some(path)) =
                (f.next(), f.next(), f.next(), f.next(), f.next())
            else {
                continue;
            };
            let ix = brands.len();
            for name in [slug, title].into_iter().chain(aliases.split(',')) {
                let n = norm(name);
                if !n.is_empty() {
                    by_name.entry(n).or_insert(ix);
                }
            }
            brands.push(Brand {
                slug: slug.into(),
                rgb: u32::from_str_radix(hex, 16).unwrap_or(0x888888),
                path: path.into(),
            });
        }
        Index { brands, by_name }
    })
}

/// SVG логотипа для источника ассетов: `brand/<slug>.svg`.
pub fn svg_source(slug: &str) -> Option<String> {
    let ix = index();
    let b = ix.brands.iter().find(|b| b.slug == slug)?;
    Some(format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="{}"/></svg>"#,
        b.path
    ))
}

/// Части домена от главной к поддоменам: store.steampowered.com -> [steampowered, store].
fn host_labels(url: &str) -> Vec<String> {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .or_else(|| {
            (!url.contains(' ') && url.contains('.'))
                .then(|| url.split('/').next().unwrap_or_default().to_string())
        })
        .unwrap_or_default();
    let parts: Vec<&str> = host
        .split('.')
        .filter(|p| !p.is_empty() && *p != "www")
        .collect();
    if parts.len() < 2 {
        return vec![];
    }
    // без доменной зоны (последняя часть; для co.uk и подобных хватает и этого)
    parts[..parts.len() - 1]
        .iter()
        .rev()
        .map(|p| p.to_string())
        .collect()
}

/// Домены, которые не совпадают с названием бренда.
const DOMAIN_ALIASES: &[(&str, &str)] = &[
    ("steampowered", "steam"),
    ("steamcommunity", "steam"),
    ("live", "microsoft"),
    ("microsoftonline", "microsoft"),
    ("ya", "yandexcloud"),
    ("vk", "vk"),
    ("t", "telegram"),
];

/// Поддомены, по которым логотип не подбираем: они есть у тысяч сайтов.
const GENERIC: &[&str] = &[
    "mail",
    "login",
    "auth",
    "account",
    "accounts",
    "id",
    "my",
    "app",
    "apps",
    "web",
    "portal",
    "secure",
    "online",
    "store",
    "shop",
    "admin",
    "api",
    "cloud",
    "dashboard",
    "console",
    "panel",
];

/// Логотип для записи: по названию, затем по адресу (домен второго уровня, потом поддомены).
pub fn find(title: &str, url: &str) -> Option<&'static Brand> {
    let ix = index();
    let by = |n: &str| ix.by_name.get(n).map(|&i| &ix.brands[i]);
    let t = norm(title);
    if t.len() >= 2
        && let Some(b) = by(&t)
    {
        return Some(b);
    }
    let labels = host_labels(url);
    labels.iter().enumerate().find_map(|(i, l)| {
        let l = norm(l);
        if let Some((_, slug)) = DOMAIN_ALIASES.iter().find(|(d, _)| *d == l) {
            return ix.brands.iter().find(|b| b.slug == *slug);
        }
        // домен второго уровня берём всегда, поддомены только неслужебные
        if l.len() < 3 || (i > 0 && GENERIC.contains(&l.as_str())) {
            return None;
        }
        by(&l)
    })
}

fn rgb(c: u32) -> Hsla {
    gpui_kit::rgb(c).into()
}

fn luminance(c: u32) -> f32 {
    let (r, g, b) = ((c >> 16) as f32, ((c >> 8) & 255) as f32, (c & 255) as f32);
    (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255.
}

/// Цвет монограммы из названия: стабильный, приглушённый.
fn monogram_color(s: &str) -> Hsla {
    let h = s
        .chars()
        .fold(0u32, |h, c| h.wrapping_mul(31).wrapping_add(c as u32));
    hsla((h % 360) as f32 / 360., 0.55, 0.48, 1.)
}

/// Плитка записи (список, карточка, коды, лаунчер). `custom`: собственная иконка записи (favicon).
pub fn tile(
    e: &EntrySummary,
    size: f32,
    kind_icon: IconName,
    custom: Option<std::sync::Arc<Image>>,
    theme: &gpui_kit::component::Theme,
) -> Div {
    let base = div()
        .size(px(size))
        .flex_shrink_0()
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(size * 0.25))
        .border_1();
    let logo = (size * 0.56).round();
    if let Some(image) = custom {
        return base
            .bg(theme.secondary)
            .border_color(theme.border)
            .child(img(image).size(px((size * 0.62).round())));
    }
    if let Some(b) = find(&e.title, &e.url) {
        let dark = luminance(b.rgb) < 0.12;
        // тёмный фирменный цвет (Visa, тёмно-синие и фиолетовые) на тёмном фоне не виден:
        // оттенок сохраняем, яркость поднимаем
        let mut brand = rgb(b.rgb);
        if theme.mode.is_dark() && brand.l < 0.58 {
            brand.l = 0.66;
        }
        let color = if dark { gpui_kit::white() } else { brand };
        let tile = if dark {
            base.bg(theme.secondary).border_color(theme.border)
        } else {
            base.bg(brand.opacity(0.15))
                .border_color(brand.opacity(0.28))
        };
        return tile.child(
            svg()
                .path(SharedString::from(format!("brand/{}.svg", b.slug)))
                .size(px(logo))
                .text_color(color),
        );
    }
    if matches!(e.kind, EntryKind::Login | EntryKind::Passkey) {
        let letter = e
            .title
            .chars()
            .find(|c| c.is_alphanumeric())
            .map(|c| c.to_uppercase().to_string())
            .unwrap_or_else(|| "?".into());
        return base
            .bg(monogram_color(&e.title))
            .border_color(transparent_black())
            .text_color(gpui_kit::white())
            .font_weight(FontWeight::SEMIBOLD)
            .text_size(px(size * 0.45))
            .child(letter);
    }
    base.bg(theme.secondary)
        .border_color(theme.border)
        .child(Icon::new(kind_icon).small().text_color(theme.primary))
}

#[cfg(test)]
mod tests {
    // не `super::*`: вместе с gpui_kit::* приходит gpui-шный #[test]
    use super::{find, index, svg_source};

    fn slug(title: &str, url: &str) -> Option<String> {
        find(title, url).map(|b| b.slug.clone())
    }

    #[test]
    fn matches_by_title_and_domain() {
        assert_eq!(slug("GitHub", "").as_deref(), Some("github"));
        assert_eq!(
            slug("Моя почта", "https://mail.google.com/").as_deref(),
            Some("google")
        );
        assert_eq!(
            slug("магазин", "https://store.steampowered.com").as_deref(),
            Some("steam")
        );
        assert_eq!(
            slug("Работа", "https://mail.example.org").as_deref(),
            None,
            "поддомен mail не бренд"
        );
        assert!(slug("Совсем неизвестный сервис", "https://example.invalid").is_none());
        assert!(svg_source("github").unwrap().starts_with("<svg"));
        assert!(index().brands.len() > 3000);
    }
}
