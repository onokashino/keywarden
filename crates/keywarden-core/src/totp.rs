//! TOTP (RFC 6238) в форматах KeePassXC:
//! - поле `otp` с `otpauth://totp/...` (в том числе `encoder=steam`) или KeeOtp `key=...&size=..&step=..`;
//! - старые поля `TOTP Seed` + `TOTP Settings` ("30;6", "30;8", "30;S" для Steam).

use crate::model::{LEGACY_TOTP_SEED, LEGACY_TOTP_SETTINGS};
use hmac::{Hmac, KeyInit, Mac};
use keepass::db::{EntryRef, fields};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TotpError {
    #[error("{}", crate::tr!("в записи нет 2FA"))]
    Missing,
    #[error("{}", crate::tr!("секрет 2FA не в base32"))]
    BadSecret,
    #[error("{}", crate::tr!("неверные параметры 2FA: {e}", e = .0))]
    BadParams(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
    pub steam: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Code {
    pub code: String,
    /// сколько секунд код ещё действует
    pub remaining: u64,
    pub period: u64,
    /// следующий код: показывается, когда текущий вот-вот сменится
    #[serde(default)]
    pub next: String,
}

impl Totp {
    pub fn from_entry(e: &EntryRef<'_>) -> Result<Self, TotpError> {
        if let Some(otp) = e.get(fields::OTP).filter(|s| !s.trim().is_empty()) {
            return Self::parse(otp);
        }
        match e.get(LEGACY_TOTP_SEED).filter(|s| !s.trim().is_empty()) {
            Some(seed) => Self::from_legacy(seed, e.get(LEGACY_TOTP_SETTINGS)),
            None => Err(TotpError::Missing),
        }
    }

    /// Значение поля `otp`.
    pub fn parse(s: &str) -> Result<Self, TotpError> {
        let s = s.trim();
        if s.starts_with("otpauth://") {
            let url = url::Url::parse(s).map_err(|e| TotpError::BadParams(e.to_string()))?;
            if url.host_str() != Some("totp") {
                return Err(TotpError::BadParams(
                    crate::tr!("поддерживается только totp").into(),
                ));
            }
            let mut t = Self::new(None, 30, 6, Algorithm::Sha1, false);
            let mut secret = None;
            for (k, v) in url.query_pairs() {
                match k.as_ref() {
                    "secret" => secret = Some(decode_base32(&v)?),
                    "period" => t.period = num(&v)?,
                    "digits" => t.digits = num(&v)?,
                    "algorithm" => t.algorithm = algorithm(&v)?,
                    "encoder" if v == "steam" => t.steam = true,
                    _ => {}
                }
            }
            if url.path().to_ascii_lowercase().contains("steam")
                && url
                    .query_pairs()
                    .any(|(k, v)| k == "issuer" && v == "Steam")
            {
                t.steam = true;
            }
            t.secret = Zeroizing::new(secret.ok_or(TotpError::BadSecret)?);
            return t.validated();
        }
        // KeeOtp: key=BASE32&size=6&step=30&otpHashMode=SHA256
        let mut t = Self::new(None, 30, 6, Algorithm::Sha1, false);
        let mut secret = None;
        for pair in s.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v);
            match k {
                "key" => secret = Some(decode_base32(&v)?),
                "size" => t.digits = num(&v)?,
                "step" => t.period = num(&v)?,
                "otpHashMode" => t.algorithm = algorithm(&v)?,
                _ => {}
            }
        }
        t.secret = Zeroizing::new(secret.ok_or(TotpError::BadSecret)?);
        t.validated()
    }

    /// `TOTP Seed` + `TOTP Settings` ("период;цифры" или "период;S"), как в старых KeePassXC.
    pub fn from_legacy(seed: &str, settings: Option<&str>) -> Result<Self, TotpError> {
        let mut t = Self::new(Some(decode_base32(seed)?), 30, 6, Algorithm::Sha1, false);
        if let Some(s) = settings.filter(|s| !s.trim().is_empty()) {
            let mut parts = s.trim().split(';');
            if let Some(p) = parts.next() {
                t.period = num(p)?;
            }
            match parts.next() {
                Some("S") => t.steam = true,
                Some(d) => t.digits = num(d)?,
                None => {}
            }
        }
        t.validated()
    }

    fn new(
        secret: Option<Vec<u8>>,
        period: u64,
        digits: u32,
        algorithm: Algorithm,
        steam: bool,
    ) -> Self {
        Self {
            secret: Zeroizing::new(secret.unwrap_or_default()),
            period,
            digits,
            algorithm,
            steam,
        }
    }

    fn validated(mut self) -> Result<Self, TotpError> {
        if self.steam {
            self.digits = 5;
        }
        if self.secret.is_empty() {
            return Err(TotpError::BadSecret);
        }
        if self.period == 0 || !(1..=10).contains(&self.digits) {
            return Err(TotpError::BadParams(format!(
                "period={} digits={}",
                self.period, self.digits
            )));
        }
        Ok(self)
    }

    pub fn at(&self, unix: u64) -> Code {
        Code {
            code: self.code_for(unix / self.period),
            remaining: self.period - unix % self.period,
            period: self.period,
            next: self.code_for(unix / self.period + 1),
        }
    }

    fn code_for(&self, step: u64) -> String {
        let counter = step.to_be_bytes();
        macro_rules! mac {
            ($d:ty) => {{
                let mut m = <Hmac<$d> as KeyInit>::new_from_slice(&self.secret)
                    .expect("HMAC принимает ключ любой длины");
                m.update(&counter);
                m.finalize().into_bytes().to_vec()
            }};
        }
        let h: Vec<u8> = match self.algorithm {
            Algorithm::Sha1 => mac!(sha1::Sha1),
            Algorithm::Sha256 => mac!(sha2::Sha256),
            Algorithm::Sha512 => mac!(sha2::Sha512),
        };
        let off = (h[h.len() - 1] & 0x0f) as usize;
        let mut bin =
            u32::from_be_bytes([h[off], h[off + 1], h[off + 2], h[off + 3]]) & 0x7fff_ffff;
        if self.steam {
            (0..5)
                .map(|_| {
                    let c = STEAM_ALPHABET[(bin % STEAM_ALPHABET.len() as u32) as usize] as char;
                    bin /= STEAM_ALPHABET.len() as u32;
                    c
                })
                .collect()
        } else {
            format!(
                "{:0width$}",
                bin as u64 % 10u64.pow(self.digits),
                width = self.digits as usize
            )
        }
    }

    /// Секрет в base32 (для экспорта в 2FAS и QR).
    pub fn secret_base32(&self) -> Zeroizing<String> {
        Zeroizing::new(data_encoding::BASE32_NOPAD.encode(&self.secret))
    }

    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    /// Ссылка `otpauth://totp/...`, которую понимают все приложения (Google Authenticator, 2FAS,
    /// KeePassXC, Aegis). Steam: `encoder=steam`, как у KeePassXC.
    pub fn to_uri(&self, issuer: &str, account: &str) -> Zeroizing<String> {
        let enc = |s: &str| {
            url::form_urlencoded::byte_serialize(s.as_bytes())
                .collect::<String>()
                .replace('+', "%20")
        };
        let label = match (issuer.is_empty(), account.is_empty()) {
            (false, false) => format!("{}:{}", enc(issuer), enc(account)),
            (false, true) => enc(issuer),
            (true, _) => enc(account),
        };
        let mut uri = format!(
            "otpauth://totp/{label}?secret={}&period={}&digits={}&algorithm={}",
            self.secret_base32().as_str(),
            self.period,
            self.digits,
            self.algorithm_name()
        );
        if !issuer.is_empty() {
            uri.push_str(&format!("&issuer={}", enc(issuer)));
        }
        if self.steam {
            uri.push_str("&encoder=steam");
        }
        Zeroizing::new(uri)
    }
}

/// Что пользователь вставил в мастер 2FA: ссылка otpauth://, голый секрет base32
/// (как показывают сайты под QR) или KeeOtp. Возвращает каноническую ссылку для поля `otp`.
pub fn normalize(input: &str, issuer: &str, account: &str) -> Result<Zeroizing<String>, TotpError> {
    let input = input.trim();
    if input.starts_with("otpauth://totp/") || input.starts_with("otpauth://totp?") {
        let t = Totp::parse(input)?;
        // своё название, если в ссылке его нет или его поменяли в мастере
        return Ok(if issuer.is_empty() && account.is_empty() {
            Zeroizing::new(input.to_string())
        } else {
            t.to_uri(issuer, account)
        });
    }
    if input.starts_with("otpauth://hotp") {
        return Err(TotpError::BadParams(
            crate::tr!("HOTP (счётчик) не поддерживается, только TOTP (по времени)").into(),
        ));
    }
    if input.contains("key=") {
        let t = Totp::parse(input)?;
        return Ok(t.to_uri(issuer, account));
    }
    let t = Totp::new(Some(decode_base32(input)?), 30, 6, Algorithm::Sha1, false).validated()?;
    Ok(t.to_uri(issuer, account))
}

/// Матрица QR-кода (true = тёмная клетка) и её сторона.
pub fn qr_matrix(text: &str) -> Option<(usize, Vec<bool>)> {
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::M).ok()?;
    let w = code.width();
    let cells = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    Some((w, cells))
}

impl Totp {
    pub fn now(&self) -> Code {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.at(unix)
    }
}

fn decode_base32(s: &str) -> Result<Vec<u8>, TotpError> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    data_encoding::BASE32_NOPAD
        .decode(clean.as_bytes())
        .map_err(|_| TotpError::BadSecret)
}

fn num<T: std::str::FromStr>(s: &str) -> Result<T, TotpError> {
    s.trim().parse().map_err(|_| TotpError::BadParams(s.into()))
}

fn algorithm(s: &str) -> Result<Algorithm, TotpError> {
    match s.to_ascii_uppercase().replace('-', "").as_str() {
        "SHA1" => Ok(Algorithm::Sha1),
        "SHA256" => Ok(Algorithm::Sha256),
        "SHA512" => Ok(Algorithm::Sha512),
        other => Err(TotpError::BadParams(other.into())),
    }
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={s}").as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b32(s: &[u8]) -> String {
        data_encoding::BASE32_NOPAD.encode(s)
    }

    /// RFC 6238, приложение B
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            ("SHA1", b"12345678901234567890".as_slice(), 94287082),
            (
                "SHA256",
                b"12345678901234567890123456789012".as_slice(),
                46119246,
            ),
            (
                "SHA512",
                b"1234567890123456789012345678901234567890123456789012345678901234".as_slice(),
                90693936,
            ),
        ];
        for (alg, key, want) in cases {
            let t = Totp::parse(&format!(
                "otpauth://totp/x?secret={}&digits=8&algorithm={alg}",
                b32(key)
            ))
            .unwrap();
            assert_eq!(t.at(59).code, format!("{want:08}"), "{alg}");
        }
        let t = Totp::parse(&format!(
            "otpauth://totp/x?secret={}&digits=8",
            b32(b"12345678901234567890")
        ))
        .unwrap();
        assert_eq!(t.at(1111111109).code, "07081804");
        assert_eq!(t.at(59).remaining, 1);
    }

    #[test]
    fn formats() {
        let seed = b32(b"12345678901234567890");
        let legacy = Totp::from_legacy(&seed, Some("30;8")).unwrap();
        assert_eq!(legacy.at(59).code, "94287082");
        let keeotp = Totp::parse(&format!("key={seed}&size=8&step=30")).unwrap();
        assert_eq!(keeotp.at(59).code, "94287082");
        // секрет с пробелами и в нижнем регистре, как его часто вставляют
        let spaced = Totp::parse(&format!(
            "otpauth://totp/x?secret={}",
            seed.to_lowercase().replace("GE", "ge ")
        ))
        .unwrap();
        assert_eq!(spaced.at(59).code.len(), 6);
    }

    #[test]
    fn steam() {
        let t = Totp::from_legacy(&b32(b"12345678901234567890"), Some("30;S")).unwrap();
        let code = t.at(59).code;
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|c| STEAM_ALPHABET.contains(&c)));
        let t2 = Totp::parse(&format!(
            "otpauth://totp/Steam:me?secret={}&encoder=steam",
            b32(b"12345678901234567890")
        ))
        .unwrap();
        assert_eq!(t2.at(59).code, code);
    }

    #[test]
    fn errors() {
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=!!!").err(),
            Some(TotpError::BadSecret)
        );
        assert!(Totp::parse("otpauth://hotp/x?secret=GEZDGNBV").is_err());
        assert!(Totp::parse("otpauth://totp/x?secret=GEZDGNBV&period=0").is_err());
    }

    #[test]
    fn normalize_and_uri_roundtrip() {
        let uri = normalize("jbsw y3dp ehpk 3pxp", "GitHub", "octo@example.com").unwrap();
        assert!(
            uri.starts_with("otpauth://totp/GitHub:octo%40example.com?secret=JBSWY3DPEHPK3PXP")
        );
        assert!(uri.contains("issuer=GitHub"));
        let a = Totp::parse(&uri).unwrap();
        let b = Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(a.at(1_700_000_000), b.at(1_700_000_000));
        // ссылка как есть, если название не задано
        let raw = "otpauth://totp/A:b?secret=JBSWY3DPEHPK3PXP&issuer=A";
        assert_eq!(normalize(raw, "", "").unwrap().as_str(), raw);
        assert!(normalize("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1", "", "").is_err());
        assert!(normalize("не секрет!", "", "").is_err());
        // Steam сохраняет свой формат
        let steam =
            Totp::parse("otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&encoder=steam").unwrap();
        let again = Totp::parse(&steam.to_uri("Steam", "me")).unwrap();
        assert_eq!(steam.at(1_700_000_000).code, again.at(1_700_000_000).code);
        assert_eq!(again.at(1_700_000_000).code.len(), 5);
    }

    #[test]
    fn next_code_is_following_step() {
        let t = Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(t.at(1_700_000_000).next, t.at(1_700_000_030).code);
    }

    #[test]
    fn qr_matrix_has_finder_patterns() {
        let (w, cells) = qr_matrix("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(cells.len(), w * w);
        assert!(
            cells[0] && cells[6] && cells[6 * w],
            "угол поискового узора тёмный"
        );
    }
}
