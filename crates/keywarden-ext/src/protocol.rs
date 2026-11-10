//! Протокол расширение ↔ keywarden-host ↔ keywardend.
//!
//! Внешний слой (открытым текстом, через host): ассоциация и зашифрованные конверты.
//! Внутренний слой шифруется crypto_box (X25519 + XSalsa20-Poly1305), как в KeePassXC-Browser:
//! у расширения и демона по паре ключей, демон знает открытые ключи доверенных расширений.

use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

pub const NONCE_LEN: usize = 24;

/// Сообщение расширения демону (через host без изменений).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outer {
    /// Первое подключение: демон спросит пользователя и запомнит открытый ключ клиента.
    Associate {
        client_id: String,
        client_public: String,
        name: String,
    },
    Encrypted {
        client_id: String,
        nonce: String,
        message: String,
    },
    /// база заблокирована: показать лаунчер с полем пароля (без шифрования, секретов тут нет)
    OpenUnlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OuterReply {
    Ok,
    Associated { server_public: String },
    Encrypted { nonce: String, message: String },
    Error { code: String, message: String },
}

/// Запрос внутри шифрованного конверта.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BrowserRequest {
    Status,
    /// подходящие учётки для страницы (без паролей)
    GetLogins {
        url: String,
    },
    /// логин и пароль для заполнения; первый раз для сайта спрашивает пользователя
    Fill {
        id: String,
        url: String,
    },
    Totp {
        id: String,
        url: String,
    },
    /// есть ли уже такая учётка (для предложения сохранить/обновить)
    CheckSave {
        url: String,
        username: String,
        password: String,
    },
    Save {
        url: String,
        username: String,
        password: String,
        #[serde(default)]
        title: Option<String>,
        /// обновить эту запись вместо создания новой
        #[serde(default)]
        update_id: Option<String>,
    },
    /// `options`: keywarden_core::generator::Generate в JSON ({"mode":"password",...}); нет: по умолчанию
    Generate {
        #[serde(default)]
        options: Option<serde_json::Value>,
    },
    /// navigator.credentials.create: publicKey-опции с буферами в base64url
    PasskeyCreate {
        url: String,
        options: serde_json::Value,
    },
    /// подходящие ключи доступа для navigator.credentials.get
    PasskeyList {
        url: String,
        options: serde_json::Value,
    },
    PasskeyGet {
        url: String,
        options: serde_json::Value,
        id: String,
    },
    /// поиск по всей базе для popup расширения (без паролей)
    Search {
        query: String,
        /// keywarden_core::search::Filter в JSON: {group, kind, tag}
        #[serde(default)]
        filter: Option<serde_json::Value>,
    },
    /// папки и теги для фильтров popup
    Facets,
    /// заблокировать хранилище (кнопка замка в popup)
    Lock,
    /// карточка записи для popup: без пароля, с текущим кодом 2FA
    Item {
        id: String,
    },
    /// скопировать username, password или totp в системный буфер (копирует демон, браузер значение не видит)
    Copy {
        id: String,
        field: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ItemView {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub group: String,
    pub has_password: bool,
    /// код 2FA сейчас: код, сколько секунд осталось, период
    pub totp: Option<(String, u64, u64)>,
    /// login, card, crypto_wallet…
    #[serde(default)]
    pub kind: String,
    /// публичные адреса кошелька: (подпись, адрес); секреты кошелька расширению не отдаются
    #[serde(default)]
    pub addresses: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Login {
    pub id: String,
    pub title: String,
    pub username: String,
    pub group: String,
    pub has_otp: bool,
    #[serde(default)]
    pub url: String,
    /// login, card, identity, note, ssh_key, passkey
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Folder {
    pub id: String,
    pub name: String,
    pub depth: usize,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum BrowserReply {
    Status {
        locked: bool,
    },
    Logins {
        logins: Vec<Login>,
    },
    Credentials {
        username: String,
        password: String,
    },
    Totp {
        code: String,
        remaining: u64,
    },
    /// `new`: учётки нет, `changed`: есть с другим паролем (id), `same`: ничего не делать
    SaveCheck {
        state: String,
        id: Option<String>,
    },
    Saved {
        id: String,
    },
    Generated {
        password: String,
        #[serde(default)]
        entropy: f64,
    },
    /// PublicKeyCredential с буферами в base64url
    Passkey {
        credential: serde_json::Value,
    },
    Passkeys {
        candidates: Vec<Login>,
    },
    Item {
        item: ItemView,
    },
    Copied,
    /// действие выполнено (например, блокировка)
    Done,
    Facets {
        folders: Vec<Folder>,
        tags: Vec<(String, usize)>,
    },
    Error {
        code: String,
        message: String,
    },
}

pub struct Keypair {
    pub secret: SecretKey,
}

impl Keypair {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(&mut OsRng),
        }
    }
    pub fn from_secret_b64(s: &str) -> Result<Self, String> {
        Ok(Self {
            secret: SecretKey::from(key32(s)?),
        })
    }
    pub fn public_b64(&self) -> String {
        BASE64.encode(self.secret.public_key().as_bytes())
    }
    pub fn secret_b64(&self) -> String {
        BASE64.encode(&self.secret.to_bytes())
    }
}

fn key32(s: &str) -> Result<[u8; 32], String> {
    let v = BASE64
        .decode(s.as_bytes())
        .map_err(|_| "ключ не в base64".to_string())?;
    v.try_into()
        .map_err(|_| "ключ должен быть 32 байта".to_string())
}

fn salsa(peer_public: &str, own_secret: &str) -> Result<SalsaBox, String> {
    Ok(SalsaBox::new(
        &PublicKey::from(key32(peer_public)?),
        &SecretKey::from(key32(own_secret)?),
    ))
}

/// → (nonce, ciphertext) в base64
pub fn seal(
    plaintext: &[u8],
    peer_public: &str,
    own_secret: &str,
) -> Result<(String, String), String> {
    let b = salsa(peer_public, own_secret)?;
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let ct = b
        .encrypt(&nonce, plaintext)
        .map_err(|_| "шифрование не удалось".to_string())?;
    Ok((BASE64.encode(&nonce), BASE64.encode(&ct)))
}

pub fn open(
    nonce: &str,
    message: &str,
    peer_public: &str,
    own_secret: &str,
) -> Result<Vec<u8>, String> {
    let b = salsa(peer_public, own_secret)?;
    let n = BASE64
        .decode(nonce.as_bytes())
        .map_err(|_| "nonce не в base64".to_string())?;
    if n.len() != NONCE_LEN {
        return Err("неверная длина nonce".into());
    }
    let ct = BASE64
        .decode(message.as_bytes())
        .map_err(|_| "сообщение не в base64".to_string())?;
    b.decrypt(n.as_slice().into(), ct.as_slice())
        .map_err(|_| "сообщение не расшифровалось (чужой ключ или подделка)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper() {
        let (client, server) = (Keypair::generate(), Keypair::generate());
        let (n, m) = seal(
            br#"{"action":"status"}"#,
            &server.public_b64(),
            &client.secret_b64(),
        )
        .unwrap();
        let pt = open(&n, &m, &client.public_b64(), &server.secret_b64()).unwrap();
        assert_eq!(pt, br#"{"action":"status"}"#);

        let mut bad = BASE64.decode(m.as_bytes()).unwrap();
        bad[0] ^= 1;
        assert!(
            open(
                &n,
                &BASE64.encode(&bad),
                &client.public_b64(),
                &server.secret_b64()
            )
            .is_err()
        );
        let stranger = Keypair::generate();
        assert!(
            open(&n, &m, &stranger.public_b64(), &server.secret_b64()).is_err(),
            "чужой клиент не проходит"
        );
    }

    #[test]
    fn wire_format() {
        let r: BrowserRequest =
            serde_json::from_str(r#"{"action":"get_logins","url":"https://x.y"}"#).unwrap();
        assert!(matches!(r, BrowserRequest::GetLogins { .. }));
    }
}
