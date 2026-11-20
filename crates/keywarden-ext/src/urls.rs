//! Сопоставление адресов страницы и записи.
//!
//! Совпадение по зарегистрированному домену (eTLD+1 по Public Suffix List) с учётом поддоменов:
//! запись `github.com` подходит для `gist.github.com`, но запись `co.uk` не подходит ни к чему,
//! а `evil-github.com` и `github.com.evil.io` не подходят к `github.com`.

use url::Url;

/// Имя поля записи с правилом совпадения адреса (обычное поле: видно и в других клиентах KeePass).
pub const MATCH_FIELD: &str = "URL Match";

/// Как адрес записи сравнивается с адресом страницы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Match {
    /// весь зарегистрированный домен с поддоменами записи
    #[default]
    Domain,
    /// только тот же хост (и порт, если задан)
    Host,
    /// адрес страницы начинается с адреса записи
    Starts,
    /// адрес страницы равен адресу записи (без #якоря)
    Exact,
    /// запись не предлагается и не заполняется в браузере
    Never,
}

impl Match {
    /// Значение поля [`MATCH_FIELD`]; пустое и незнакомое: по домену.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "host" => Self::Host,
            "starts" => Self::Starts,
            "exact" => Self::Exact,
            "never" => Self::Never,
            _ => Self::Domain,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Host => "host",
            Self::Starts => "starts",
            Self::Exact => "exact",
            Self::Never => "never",
        }
    }
}

/// То же, что [`url_matches`], с правилом записи.
pub fn url_matches_with(page_url: &str, entry_url: &str, rule: Match) -> bool {
    match rule {
        Match::Domain => url_matches(page_url, entry_url),
        Match::Never => false,
        Match::Host => {
            let (Some(page), Some(entry)) = (parse(page_url), parse(entry_url)) else {
                return false;
            };
            page.host_str() == entry.host_str() && url_matches(page_url, entry_url)
        }
        Match::Starts | Match::Exact => {
            let (Some(mut page), Some(mut entry)) = (parse(page_url), parse(entry_url)) else {
                return false;
            };
            // схема, хост и порт должны совпасть точно: сравниваем origin, а не строки
            if page.origin() != entry.origin() || !matches!(page.scheme(), "http" | "https") {
                return false;
            }
            page.set_fragment(None);
            entry.set_fragment(None);
            if rule == Match::Exact {
                page.as_str() == entry.as_str()
            } else {
                page.as_str().starts_with(entry.as_str())
            }
        }
    }
}

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
    fn rules() {
        use super::{Match, url_matches_with as w};
        assert_eq!(Match::parse(" Host "), Match::Host);
        assert_eq!(Match::parse("что-то"), Match::Domain);
        for r in [
            Match::Domain,
            Match::Host,
            Match::Starts,
            Match::Exact,
            Match::Never,
        ] {
            assert_eq!(Match::parse(r.name()), r);
        }
        assert!(w("https://gist.github.com/", "github.com", Match::Domain));
        assert!(!w("https://gist.github.com/", "github.com", Match::Host));
        assert!(w("https://github.com/login", "github.com", Match::Host));
        assert!(!w("http://github.com/", "https://github.com", Match::Host));
        assert!(w(
            "https://host.io/team/a?x=1",
            "https://host.io/team/",
            Match::Starts
        ));
        assert!(!w(
            "https://host.io/other",
            "https://host.io/team/",
            Match::Starts
        ));
        assert!(!w(
            "https://host.io.evil.com/team/",
            "https://host.io/team/",
            Match::Starts
        ));
        assert!(!w(
            "http://host.io/team/",
            "https://host.io/team/",
            Match::Starts
        ));
        assert!(w(
            "https://host.io/login#top",
            "https://host.io/login",
            Match::Exact
        ));
        assert!(!w(
            "https://host.io/login?next=1",
            "https://host.io/login",
            Match::Exact
        ));
        assert!(!w("https://github.com/", "github.com", Match::Never));
    }

    #[test]
    fn ports_and_local() {
        assert!(m("http://localhost:8080/", "http://localhost:8080"));
        assert!(!m("http://localhost:9090/", "http://localhost:8080"));
        assert!(m("https://192.168.1.1/", "https://192.168.1.1"));
        assert!(!m("https://192.168.1.2/", "https://192.168.1.1"));
    }
}
