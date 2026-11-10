//! Ключи доступа (WebAuthn passkeys) в формате KeePassXC: атрибуты `KPEX_PASSKEY_*`,
//! приватный ключ ES256 (P-256) в PKCS#8 PEM. Такие записи понимают KeePassXC и KeePassDX.
//!
//! Мы программный аутентификатор: attestation "none", счётчик подписей 0, флаги BE/BS
//! (ключ синхронизируется вместе с базой), UV ставится после подтверждения пользователем.

use data_encoding::BASE64URL_NOPAD as B64U;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const USERNAME: &str = "KPEX_PASSKEY_USERNAME";
pub const CREDENTIAL_ID: &str = "KPEX_PASSKEY_CREDENTIAL_ID";
pub const PRIVATE_KEY: &str = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
pub const RELYING_PARTY: &str = "KPEX_PASSKEY_RELYING_PARTY";
pub const USER_HANDLE: &str = "KPEX_PASSKEY_USER_HANDLE";
pub const FLAG_BE: &str = "KPEX_PASSKEY_FLAG_BE";
pub const FLAG_BS: &str = "KPEX_PASSKEY_FLAG_BS";

/// AAGUID аутентификатора Keywarden (случайная константа).
const AAGUID: [u8; 16] = [
    0x6b, 0x77, 0x2d, 0x6b, 0x65, 0x79, 0x77, 0x61, 0x72, 0x64, 0x65, 0x6e, 0x2d, 0x30, 0x30, 0x31,
];
const ES256: i64 = -7;

const UP: u8 = 1 << 0;
const UV: u8 = 1 << 2;
const BE: u8 = 1 << 3;
const BS: u8 = 1 << 4;
const AT: u8 = 1 << 6;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum PasskeyError {
    /// NotAllowedError / SecurityError / NotSupportedError в терминах WebAuthn
    #[error("{0}")]
    NotAllowed(String),
    #[error("{}", crate::tr!("адрес страницы не подходит к сайту {e}", e = .0))]
    Security(String),
    #[error("{}", crate::tr!("поддерживается только ES256 (P-256)"))]
    NotSupported,
    #[error("{}", crate::tr!("неверные параметры WebAuthn: {e}", e = .0))]
    Invalid(String),
}

/// Сохранённый ключ доступа (поля записи).
#[derive(Debug, Clone)]
pub struct Stored {
    pub rp_id: String,
    pub credential_id: String,
    pub user_handle: String,
    pub username: String,
    pub private_key_pem: String,
    pub be: bool,
    pub bs: bool,
}

/// Новый ключ: поля записи (имя, значение, защищено) и ответ для страницы.
pub struct Created {
    pub fields: Vec<(&'static str, String, bool)>,
    pub rp_name: String,
    pub credential: Value,
}

/// Можно ли странице `origin` использовать `rp_id` (WebAuthn §5.1.3, шаг rpId):
/// тот же хост или его зарегистрированный суффикс, не публичный суффикс; только https
/// (http разрешён для localhost, как в браузерах).
pub fn rp_id_allowed(rp_id: &str, origin: &str) -> bool {
    let Ok(u) = url::Url::parse(origin) else {
        return false;
    };
    let Some(host) = u.host_str() else {
        return false;
    };
    let secure = u.scheme() == "https"
        || (u.scheme() == "http" && (host == "localhost" || host.ends_with(".localhost")));
    if !secure || rp_id.is_empty() {
        return false;
    }
    if host == rp_id {
        return true;
    }
    // суффикс: только зарегистрируемый домен, не "com" и не "github.io"
    host.ends_with(&format!(".{rp_id}"))
        && psl::domain_str(rp_id)
            .is_some_and(|reg| rp_id == reg || rp_id.ends_with(&format!(".{reg}")))
}

fn b64(v: &Value) -> Result<Vec<u8>, PasskeyError> {
    let s = v
        .as_str()
        .ok_or_else(|| PasskeyError::Invalid(crate::tr!("ожидалась строка base64url").into()))?;
    B64U.decode(s.trim_end_matches('=').as_bytes())
        .map_err(|_| PasskeyError::Invalid(crate::tr!("не base64url").into()))
}

fn origin_of(page_url: &str) -> Result<String, PasskeyError> {
    url::Url::parse(page_url)
        .map(|u| u.origin().ascii_serialization())
        .map_err(|_| PasskeyError::Invalid(crate::tr!("адрес страницы").into()))
}

fn client_data(kind: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    // порядок полей как у браузеров; crossOrigin false: во фреймах мы не работаем
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        B64U.encode(challenge)
    )
    .into_bytes()
}

fn auth_data(rp_id: &str, flags: u8, attested: Option<&[u8]>) -> Vec<u8> {
    let mut d = Sha256::digest(rp_id.as_bytes()).to_vec();
    d.push(flags);
    d.extend_from_slice(&0u32.to_be_bytes()); // счётчик: синхронизируемый ключ, всегда 0
    if let Some(a) = attested {
        d.extend_from_slice(a);
    }
    d
}

/// navigator.credentials.create: `options` это publicKey с полями-буферами в base64url.
pub fn register(options: &Value, page_url: &str) -> Result<Created, PasskeyError> {
    let origin = origin_of(page_url)?;
    let host = url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let rp = &options["rp"];
    let rp_id = rp["id"].as_str().map(str::to_string).unwrap_or(host);
    if !rp_id_allowed(&rp_id, &origin) {
        return Err(PasskeyError::Security(rp_id));
    }
    let algs: Vec<i64> = options["pubKeyCredParams"]
        .as_array()
        .map(|a| a.iter().filter_map(|p| p["alg"].as_i64()).collect())
        .unwrap_or_default();
    if !algs.is_empty() && !algs.contains(&ES256) {
        return Err(PasskeyError::NotSupported);
    }
    let challenge = b64(&options["challenge"])?;
    let user = &options["user"];
    let user_id = b64(&user["id"])?;
    let username = user["name"].as_str().unwrap_or_default().to_string();

    let key = SigningKey::random(&mut rand_core06::OsRng);
    let mut cred_id = [0u8; 32];
    rand_core06::RngCore::fill_bytes(&mut rand_core06::OsRng, &mut cred_id);
    let point = key.verifying_key().to_encoded_point(false);
    let (x, y) = (point.x().expect("точка"), point.y().expect("точка"));

    // COSE_Key EC2: {1: 2, 3: -7, -1: 1, -2: x, -3: y}
    let mut cose = Cbor::default();
    cose.map(5)
        .int(1)
        .int(2)
        .int(3)
        .int(ES256)
        .int(-1)
        .int(1)
        .int(-2)
        .bytes(x)
        .int(-3)
        .bytes(y);
    let mut attested = AAGUID.to_vec();
    attested.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
    attested.extend_from_slice(&cred_id);
    attested.extend_from_slice(&cose.0);
    let auth = auth_data(&rp_id, UP | UV | BE | BS | AT, Some(&attested));
    let mut att = Cbor::default();
    att.map(3)
        .text("fmt")
        .text("none")
        .text("attStmt")
        .map(0)
        .text("authData")
        .bytes(&auth);

    let cdj = client_data("webauthn.create", &challenge, &origin);
    let spki = p256::pkcs8::EncodePublicKey::to_public_key_der(key.verifying_key())
        .map_err(|e| PasskeyError::Invalid(e.to_string()))?;
    let pem = key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| PasskeyError::Invalid(e.to_string()))?
        .to_string();
    let id = B64U.encode(&cred_id);
    Ok(Created {
        fields: vec![
            (USERNAME, username, false),
            (CREDENTIAL_ID, id.clone(), true),
            (PRIVATE_KEY, pem, true),
            (RELYING_PARTY, rp_id, false),
            (USER_HANDLE, B64U.encode(&user_id), true),
            (FLAG_BE, "1".into(), false),
            (FLAG_BS, "1".into(), false),
        ],
        rp_name: rp["name"].as_str().unwrap_or_default().to_string(),
        credential: json!({
            "id": id,
            "rawId": id,
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": B64U.encode(&cdj),
                "attestationObject": B64U.encode(&att.0),
                "authenticatorData": B64U.encode(&auth),
                "publicKey": B64U.encode(spki.as_bytes()),
                "publicKeyAlgorithm": ES256,
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
        }),
    })
}

/// rpId запроса navigator.credentials.get (по умолчанию хост страницы) и проверка.
pub fn assertion_rp_id(options: &Value, page_url: &str) -> Result<String, PasskeyError> {
    let origin = origin_of(page_url)?;
    let host = url::Url::parse(page_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default();
    let rp_id = options["rpId"].as_str().map(str::to_string).unwrap_or(host);
    if !rp_id_allowed(&rp_id, &origin) {
        return Err(PasskeyError::Security(rp_id));
    }
    Ok(rp_id)
}

/// Разрешённые id (allowCredentials), пустой список: любой ключ этого сайта.
pub fn allowed_ids(options: &Value) -> Vec<String> {
    options["allowCredentials"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| {
                    c["id"]
                        .as_str()
                        .map(|s| s.trim_end_matches('=').to_string())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// navigator.credentials.get
pub fn assert(stored: &Stored, options: &Value, page_url: &str) -> Result<Value, PasskeyError> {
    let origin = origin_of(page_url)?;
    let rp_id = assertion_rp_id(options, page_url)?;
    if rp_id != stored.rp_id {
        return Err(PasskeyError::Security(rp_id));
    }
    let challenge = b64(&options["challenge"])?;
    let key = SigningKey::from_pkcs8_pem(&stored.private_key_pem)
        .map_err(|_| PasskeyError::Invalid(crate::tr!("приватный ключ не PKCS#8 P-256").into()))?;
    let flags = UP | UV | if stored.be { BE } else { 0 } | if stored.bs { BS } else { 0 };
    let auth = auth_data(&stored.rp_id, flags, None);
    let cdj = client_data("webauthn.get", &challenge, &origin);
    let mut signed = auth.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig: Signature = key.sign(&signed);
    Ok(json!({
        "id": stored.credential_id,
        "rawId": stored.credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "response": {
            "clientDataJSON": B64U.encode(&cdj),
            "authenticatorData": B64U.encode(&auth),
            "signature": B64U.encode(sig.to_der().as_bytes()),
            "userHandle": stored.user_handle,
        },
        "clientExtensionResults": {},
    }))
}

/// Минимальный CBOR (RFC 8949) для attestationObject и COSE_Key.
#[derive(Default)]
struct Cbor(Vec<u8>);

impl Cbor {
    fn head(&mut self, major: u8, n: u64) -> &mut Self {
        let m = major << 5;
        match n {
            0..=23 => self.0.push(m | n as u8),
            24..=0xff => self.0.extend([m | 24, n as u8]),
            0x100..=0xffff => {
                self.0.push(m | 25);
                self.0.extend((n as u16).to_be_bytes());
            }
            _ => {
                self.0.push(m | 26);
                self.0.extend((n as u32).to_be_bytes());
            }
        }
        self
    }
    fn int(&mut self, v: i64) -> &mut Self {
        if v >= 0 {
            self.head(0, v as u64)
        } else {
            self.head(1, (-1 - v) as u64)
        }
    }
    fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.head(2, b.len() as u64);
        self.0.extend_from_slice(b);
        self
    }
    fn text(&mut self, s: &str) -> &mut Self {
        self.head(3, s.len() as u64);
        self.0.extend_from_slice(s.as_bytes());
        self
    }
    fn map(&mut self, pairs: u64) -> &mut Self {
        self.head(5, pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{VerifyingKey, signature::Verifier};

    fn create_opts() -> Value {
        json!({
            "rp": {"id": "example.com", "name": "Example"},
            "user": {"id": B64U.encode(b"user-123"), "name": "alice", "displayName": "Alice"},
            "challenge": B64U.encode(b"challenge-1"),
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        })
    }

    fn stored(c: &Created) -> Stored {
        let get = |n: &str| c.fields.iter().find(|f| f.0 == n).unwrap().1.clone();
        Stored {
            rp_id: get(RELYING_PARTY),
            credential_id: get(CREDENTIAL_ID),
            user_handle: get(USER_HANDLE),
            username: get(USERNAME),
            private_key_pem: get(PRIVATE_KEY),
            be: true,
            bs: true,
        }
    }

    #[test]
    fn register_then_assert_verifies() {
        let c = register(&create_opts(), "https://login.example.com/signup").unwrap();
        let r = &c.credential["response"];
        let auth = B64U
            .decode(r["authenticatorData"].as_str().unwrap().as_bytes())
            .unwrap();
        assert_eq!(
            &auth[..32],
            Sha256::digest(b"example.com").as_slice(),
            "rpIdHash"
        );
        assert_eq!(auth[32] & (UP | UV | AT), UP | UV | AT);
        let cdj: Value = serde_json::from_slice(
            &B64U
                .decode(r["clientDataJSON"].as_str().unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(cdj["type"], "webauthn.create");
        assert_eq!(cdj["origin"], "https://login.example.com");
        assert_eq!(cdj["challenge"], B64U.encode(b"challenge-1"));
        let s = stored(&c);
        assert!(s.private_key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(s.user_handle, B64U.encode(b"user-123"));

        // вход: подпись проверяется открытым ключом из регистрации
        let opts = json!({"rpId": "example.com", "challenge": B64U.encode(b"login-2"), "allowCredentials": [{"type":"public-key","id": s.credential_id}]});
        assert_eq!(allowed_ids(&opts), vec![s.credential_id.clone()]);
        let a = assert(&s, &opts, "https://example.com/login").unwrap();
        let ra = &a["response"];
        let auth = B64U
            .decode(ra["authenticatorData"].as_str().unwrap().as_bytes())
            .unwrap();
        let cdj = B64U
            .decode(ra["clientDataJSON"].as_str().unwrap().as_bytes())
            .unwrap();
        let sig = Signature::from_der(
            &B64U
                .decode(ra["signature"].as_str().unwrap().as_bytes())
                .unwrap(),
        )
        .unwrap();
        let spki = B64U
            .decode(r["publicKey"].as_str().unwrap().as_bytes())
            .unwrap();
        let vk =
            <VerifyingKey as p256::pkcs8::DecodePublicKey>::from_public_key_der(&spki).unwrap();
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(&cdj));
        vk.verify(&signed, &sig).expect("подпись верна");
        assert_eq!(auth[32] & (BE | BS), BE | BS);
    }

    #[test]
    fn rp_id_rules() {
        assert!(rp_id_allowed("example.com", "https://example.com"));
        assert!(rp_id_allowed("example.com", "https://a.b.example.com"));
        assert!(
            !rp_id_allowed("com", "https://example.com"),
            "публичный суффикс"
        );
        assert!(
            !rp_id_allowed("github.io", "https://me.github.io"),
            "публичный суффикс из PSL"
        );
        assert!(!rp_id_allowed("example.com", "https://evil.com"));
        assert!(
            !rp_id_allowed("example.com", "http://example.com"),
            "только https"
        );
        assert!(rp_id_allowed("localhost", "http://localhost:8080"));
        assert!(matches!(
            register(&create_opts(), "https://evil.com/"),
            Err(PasskeyError::Security(_))
        ));
        let rsa_only = json!({"rp":{"id":"example.com"},"user":{"id":"dQ","name":"a"},"challenge":"Yw","pubKeyCredParams":[{"alg":-257}]});
        assert_eq!(
            register(&rsa_only, "https://example.com").err(),
            Some(PasskeyError::NotSupported)
        );
    }

    #[test]
    fn cbor_encoding() {
        let mut c = Cbor::default();
        c.map(1).int(-7).bytes(&[1, 2]).text("a");
        assert_eq!(c.0, vec![0xa1, 0x26, 0x42, 1, 2, 0x61, b'a']);
        let mut big = Cbor::default();
        big.int(500).int(-300);
        assert_eq!(big.0, vec![0x19, 0x01, 0xf4, 0x39, 0x01, 0x2b]);
    }
}
