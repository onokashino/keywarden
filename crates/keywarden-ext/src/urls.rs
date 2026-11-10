//! Сопоставление адресов страницы и записи.
//!
//! Совпадение по зарегистрированному домену (eTLD+1 по Public Suffix List) с учётом поддоменов:
//! запись `github.com` подходит для `gist.github.com`, но запись `co.uk` не подходит ни к чему,
//! а `evil-github.com` и `github.com.evil.io` не подходят к `github.com`.

use url::Url;

pub fn url_matches(page_url: &str, entry_url: &str) -> bool {
    let (Some(page), Some(entry)) = (parse(page_url), parse(entry_url)) else {
        return false;
    };
    if !matches!(page.scheme(), "http" | "https") {
        return false;
    }
    // https-запись не отдаём странице по http: пароль ушёл бы открытым текстом
    if entry.scheme() == "https" && page.scheme() != "https" {
        return false;
    }
    let (Some(p), Some(e)) = (page.host_str(), entry.host_str()) else {
        return false;
    };
    if p == e {
        return port_ok(&page, &entry);
    }
    // запись на публичный суффикс ("co.uk", "github.io") ни к чему не подходит: у него нет eTLD+1
    let Some(entry_reg) = registrable(e) else {
        return false;
    };
    // страница должна быть тем же хостом или его поддоменом
    p.strip_suffix(e).is_some_and(|rest| rest.ends_with('.'))
        && registrable(p) == Some(entry_reg)
        && port_ok(&page, &entry)
}

fn port_ok(page: &Url, entry: &Url) -> bool {
    // порт в записи задан явно → должен совпасть; иначе любой
    entry.port().is_none() || entry.port_or_known_default() == page.port_or_known_default()
}

/// Зарегистрированный домен ("gist.github.com" → "github.com"); для IP и localhost сам хост.
pub fn registrable(host: &str) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') || !host.contains('.') {
        return Some(host.to_string());
    }
    psl::domain_str(host).map(str::to_string)
}

/// Хост страницы для разрешений сайта ("accounts.google.com").
pub fn site_of(page_url: &str) -> Option<String> {
    parse(page_url).and_then(|u| u.host_str().map(str::to_string))
}

/// В KeePass адрес часто хранят без схемы ("github.com").
fn parse(s: &str) -> Option<Url> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    Url::parse(s).ok().filter(|u| u.has_host()).or_else(|| {
        Url::parse(&format!("https://{s}"))
            .ok()
            .filter(|u| u.has_host())
    })
}

#[cfg(test)]
mod tests {
    use super::url_matches as m;

    #[test]
    fn domains() {
        assert!(m("https://github.com/login", "https://github.com"));
        assert!(m("https://gist.github.com/", "github.com"));
        assert!(m("https://a.b.example.co.uk/x", "example.co.uk"));
        assert!(!m("https://github.com.evil.io/", "github.com"));
        assert!(!m("https://evilgithub.com/", "github.com"));
        assert!(
            !m("https://evil.co.uk/", "co.uk"),
            "публичный суффикс не подходит ни к чему"
        );
        assert!(
            !m("https://other.github.io/", "github.io"),
            "github.io тоже публичный суффикс"
        );
        assert!(
            !m("https://github.com/", "https://gist.github.com"),
            "запись на поддомен не отдаётся родителю"
        );
        assert!(
            !m("http://github.com/", "https://github.com"),
            "https-запись не для http-страницы"
        );
        assert!(m("https://github.com/", "http://github.com"));
        assert!(!m("file:///etc/passwd", "github.com"));
        assert!(!m("not a url", "github.com"));
        assert!(!m("https://github.com/", ""));
    }

    #[test]
    fn ports_and_local() {
        assert!(m("http://localhost:8080/", "http://localhost:8080"));
        assert!(!m("http://localhost:9090/", "http://localhost:8080"));
        assert!(m("https://192.168.1.1/", "https://192.168.1.1"));
        assert!(!m("https://192.168.1.2/", "https://192.168.1.1"));
    }
}
