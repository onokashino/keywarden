//! Синхронизация без папки: сервер WebDAV и соседний компьютер в той же сети.
//!
//! Обе дороги приносят зашифрованный файл базы целиком; сливает его демон тем же путём, что и
//! файл с диска (защита от массового удаления, журнал, отмена). Здесь только то, что не зависит
//! от ввода-вывода: где хранятся настройки WebDAV и криптография обмена по сети.
//!
//! Сеть: ключ связи выводится Argon2id из отпечатка пароля и файла-ключа (`DiskReader::key_digest`)
//! и UUID корневой группы. У копий одной базы он одинаковый, сопряжение не нужно. Чужой в сети
//! без пароля не пройдёт рукопожатие, а подслушанное рукопожатие перебирается не быстрее
//! самого файла базы (тот же порядок стоимости Argon2). Сам файл идёт зашифрованным дважды:
//! KDBX и X25519 + XSalsa20-Poly1305 с одноразовыми ключами сеанса.

use crate::secret::Secret;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use hmac::{Hmac, KeyInit, Mac};
use keepass::Database;
use keepass::db::{CustomDataItem, CustomDataValue, Times};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<sha2::Sha256>;

/// Порт обмена в сети: UDP для маяков, TCP для передачи базы.
pub const LAN_PORT: u16 = 47470;
/// Больше этого база по сети не передаётся (защита от мусора).
pub const MAX_VAULT_BYTES: usize = 256 * 1024 * 1024;

const WEBDAV_KEY: &str = "Keywarden.WebDAV";

/// Где лежит копия базы на сервере WebDAV. Хранится в самой базе (зашифрованные служебные
/// данные), поэтому на другом компьютере настройка появляется вместе с базой.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebDav {
    /// адрес файла, например `https://cloud.example.com/remote.php/dav/files/anna/vault.kdbx`
    pub url: String,
    pub user: String,
    pub password: Secret,
}

pub fn webdav(db: &Database) -> Option<WebDav> {
    match db
        .meta
        .custom_data
        .get(WEBDAV_KEY)
        .and_then(|c| c.value.as_ref())
    {
        Some(CustomDataValue::String(s)) if !s.is_empty() => serde_json::from_str(s).ok(),
        _ => None,
    }
}

/// `None` выключает WebDAV. Пустое значение, а не удаление ключа: при слиянии побеждает более
/// свежий элемент, и выключение доходит до других копий, а удалённый ключ вернулся бы с них.
pub fn set_webdav(db: &mut Database, cfg: Option<&WebDav>) {
    let value = cfg
        .map(|c| serde_json::to_string(c).expect("сериализация строк"))
        .unwrap_or_default();
    db.meta.custom_data.insert(
        WEBDAV_KEY.into(),
        CustomDataItem {
            value: Some(CustomDataValue::String(value)),
            last_modification_time: Some(Times::now()),
        },
    );
}

/// Адрес сервера: https; http только для своей машины и домашней сети, иначе пароль от сервера
/// уйдёт открытым текстом. Адрес папки (с `/` на конце) дополняется именем файла базы.
pub fn check_webdav_url(raw: &str, file_name: &str) -> Result<String, String> {
    let mut url =
        url::Url::parse(raw.trim()).map_err(|e| crate::tr!("неверный адрес: {e}", e = e))?;
    match url.scheme() {
        "https" => {}
        "http" if url.host().is_some_and(|h| is_local_host(&h)) => {}
        "http" => {
            return Err(crate::tr!(
                "нужен https: по http пароль от сервера уйдёт открытым текстом (http можно только в своей сети)"
            )
            .into());
        }
        _ => return Err(crate::tr!("адрес должен начинаться с https://").into()),
    }
    if url.path().ends_with('/') {
        let p = format!("{}{}", url.path(), file_name);
        url.set_path(&p);
    }
    Ok(url.to_string())
}

fn is_local_host(h: &url::Host<&str>) -> bool {
    match h {
        // имя без точки (nas, synology) разрешается только в своей сети
        url::Host::Domain(d) => {
            !d.contains('.')
                || d.ends_with(".local")
                || d.ends_with(".lan")
                || d.ends_with(".home.arpa")
        }
        url::Host::Ipv4(ip) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        url::Host::Ipv6(ip) => ip.is_loopback() || (ip.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Ключ связи в сети для этой базы. Медленно (Argon2id, 64 МиБ): считать один раз на разблокировку.
pub fn lan_key(key_digest: &[u8; 32], root: uuid::Uuid) -> Lan {
    let cfg = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: 64 * 1024,
        time_cost: 3,
        lanes: 1,
        thread_mode: argon2::ThreadMode::Sequential,
        hash_length: 32,
        ad: &[],
        secret: &[],
    };
    let mut salt = b"keywarden-lan-v1".to_vec();
    salt.extend_from_slice(root.as_bytes());
    let raw = Zeroizing::new(
        argon2::hash_raw(key_digest, &salt, &cfg).expect("валидные параметры Argon2"),
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&raw);
    Lan { key }
}

/// Ключ связи одной базы.
#[derive(Clone)]
pub struct Lan {
    key: [u8; 32],
}

impl Drop for Lan {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("любой ключ");
    for p in parts {
        m.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(m.finalize().into_bytes().as_slice());
    out
}

fn mac_ok(key: &[u8], parts: &[&[u8]], tag: &[u8]) -> bool {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("любой ключ");
    for p in parts {
        m.update(p);
    }
    let full = m.finalize().into_bytes();
    // сравнение за постоянное время
    tag.len() <= full.len() && {
        let mut diff = 0u8;
        for (a, b) in full.iter().zip(tag) {
            diff |= a ^ b;
        }
        diff == 0 && !tag.is_empty()
    }
}

/// Маяк: «у меня открыта эта база, файл в таком состоянии». Чужие базы его не узнают.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beacon {
    /// случайный номер запуска демона: свои маяки не принимаем
    pub instance: [u8; 8],
    pub port: u16,
    /// метка текущего файла: изменилась, значит, есть что забрать
    pub tag: [u8; 8],
}

const BEACON_MAGIC: &[u8; 4] = b"KWB1";
const BEACON_LEN: usize = 4 + 8 + 8 + 2 + 8 + 16;

impl Lan {
    /// Метка базы в маяке: одинакова у всех её копий и ничего не говорит постороннему.
    fn vault_id(&self) -> [u8; 8] {
        let m = mac(&self.key, &[b"vault-id"]);
        m[..8].try_into().expect("8 байт")
    }

    /// Метка состояния файла (по его sha256).
    pub fn file_tag(&self, file_hash: &[u8; 32]) -> [u8; 8] {
        let m = mac(&self.key, &[b"file", file_hash]);
        m[..8].try_into().expect("8 байт")
    }

    pub fn encode_beacon(&self, b: &Beacon) -> Vec<u8> {
        let mut out = Vec::with_capacity(BEACON_LEN);
        out.extend_from_slice(BEACON_MAGIC);
        out.extend_from_slice(&self.vault_id());
        out.extend_from_slice(&b.instance);
        out.extend_from_slice(&b.port.to_be_bytes());
        out.extend_from_slice(&b.tag);
        let m = mac(&self.key, &[b"beacon", &out]);
        out.extend_from_slice(&m[..16]);
        out
    }

    /// `None`: чужая база, подделка или мусор.
    pub fn decode_beacon(&self, data: &[u8]) -> Option<Beacon> {
        if data.len() != BEACON_LEN || &data[..4] != BEACON_MAGIC || data[4..12] != self.vault_id()
        {
            return None;
        }
        let (body, tag) = data.split_at(BEACON_LEN - 16);
        if !mac_ok(&self.key, &[b"beacon", body], tag) {
            return None;
        }
        Some(Beacon {
            instance: body[12..20].try_into().ok()?,
            port: u16::from_be_bytes(body[20..22].try_into().ok()?),
            tag: body[22..30].try_into().ok()?,
        })
    }
}

const HELLO_MAGIC: &[u8; 6] = b"KWLAN1";
pub const HELLO_LEN: usize = 6 + 32 + 16;
pub const REPLY_LEN: usize = 32 + 16 + 32;
pub const FINISH_LEN: usize = 32;

/// Сторона, которая подключается (забирает базу).
pub struct ClientHello {
    secret: SecretKey,
    hello: Vec<u8>,
}

/// Рукопожатие: клиент шлёт свой одноразовый ключ, сервер отвечает своим и доказывает, что знает
/// ключ связи; клиент доказывает то же. Подпись охватывает оба одноразовых ключа, поэтому
/// подменить их посередине нельзя.
pub fn client_hello() -> ClientHello {
    let secret = SecretKey::generate(&mut OsRng);
    let mut nonce = [0u8; 16];
    rand::fill(&mut nonce);
    let mut hello = HELLO_MAGIC.to_vec();
    hello.extend_from_slice(secret.public_key().as_bytes());
    hello.extend_from_slice(&nonce);
    ClientHello { secret, hello }
}

impl ClientHello {
    pub fn message(&self) -> &[u8] {
        &self.hello
    }

    /// Проверить ответ сервера; вернуть сеанс и последнее сообщение клиента.
    pub fn finish(self, lan: &Lan, reply: &[u8]) -> Result<(Session, Vec<u8>), String> {
        if reply.len() != REPLY_LEN {
            return Err("handshake: bad reply".into());
        }
        let (server_part, tag) = reply.split_at(48);
        if !mac_ok(&lan.key, &[b"server", &self.hello, server_part], tag) {
            return Err(crate::tr!("соседний компьютер не подтвердил ключ базы").into());
        }
        let server_pub: [u8; 32] = server_part[..32].try_into().expect("32 байта");
        let fin = mac(&lan.key, &[b"client", &self.hello, server_part]).to_vec();
        Ok((
            Session(SalsaBox::new(&PublicKey::from(server_pub), &self.secret)),
            fin,
        ))
    }
}

/// Сторона, которая отдаёт базу.
pub struct ServerReply {
    secret: SecretKey,
    hello: Vec<u8>,
    part: Vec<u8>,
}

pub fn server_reply(lan: &Lan, hello: &[u8]) -> Result<(ServerReply, Vec<u8>), String> {
    if hello.len() != HELLO_LEN || &hello[..6] != HELLO_MAGIC {
        return Err("handshake: bad hello".into());
    }
    let secret = SecretKey::generate(&mut OsRng);
    let mut nonce = [0u8; 16];
    rand::fill(&mut nonce);
    let mut part = secret.public_key().as_bytes().to_vec();
    part.extend_from_slice(&nonce);
    let tag = mac(&lan.key, &[b"server", hello, &part]);
    let mut msg = part.clone();
    msg.extend_from_slice(&tag);
    Ok((
        ServerReply {
            secret,
            hello: hello.to_vec(),
            part,
        },
        msg,
    ))
}

impl ServerReply {
    /// Клиент подтвердил ключ связи: только теперь можно отдавать базу.
    pub fn finish(self, lan: &Lan, fin: &[u8]) -> Result<Session, String> {
        if !mac_ok(&lan.key, &[b"client", &self.hello, &self.part], fin) || fin.len() != FINISH_LEN
        {
            return Err("handshake: client key mismatch".into());
        }
        let client_pub: [u8; 32] = self.hello[6..38].try_into().expect("32 байта");
        Ok(Session(SalsaBox::new(
            &PublicKey::from(client_pub),
            &self.secret,
        )))
    }
}

/// Зашифрованный канал после рукопожатия. Кадр: одноразовый nonce (24 байта) и шифротекст.
pub struct Session(SalsaBox);

impl Session {
    pub fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let mut out = nonce.to_vec();
        out.extend(self.0.encrypt(&nonce, plain).expect("шифрование в памяти"));
        out
    }

    pub fn open(&self, frame: &[u8]) -> Result<Vec<u8>, String> {
        if frame.len() < 24 {
            return Err("frame too short".into());
        }
        let (n, c) = frame.split_at(24);
        let nonce = crypto_box::Nonce::clone_from_slice(n);
        self.0
            .decrypt(&nonce, c)
            .map_err(|_| crate::tr!("данные из сети повреждены").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lan(seed: u8) -> Lan {
        // без Argon2: в тестах ключ задаём сами
        Lan { key: [seed; 32] }
    }

    #[test]
    fn handshake_and_frames() {
        let (a, b) = (lan(1), lan(1));
        let c = client_hello();
        let (s, reply) = server_reply(&b, c.message()).unwrap();
        let (client, fin) = c.finish(&a, &reply).unwrap();
        let server = s.finish(&b, &fin).unwrap();
        let frame = server.seal(b"vault bytes");
        assert_eq!(client.open(&frame).unwrap(), b"vault bytes");
        let mut bad = frame.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(client.open(&bad).is_err());
    }

    #[test]
    fn handshake_needs_the_same_key() {
        let c = client_hello();
        let (_, reply) = server_reply(&lan(2), c.message()).unwrap();
        assert!(c.finish(&lan(1), &reply).is_err());
        // клиент с чужим ключом не получает базу: сервер отвергает его подтверждение
        let c = client_hello();
        let (s, reply) = server_reply(&lan(1), c.message()).unwrap();
        let forged = mac(&[9; 32], &[b"client", c.message(), &reply[..48]]);
        assert!(s.finish(&lan(1), &forged).is_err());
    }

    #[test]
    fn beacon_roundtrip_and_foreign() {
        let b = Beacon {
            instance: [7; 8],
            port: 47470,
            tag: lan(1).file_tag(&[3; 32]),
        };
        let wire = lan(1).encode_beacon(&b);
        assert_eq!(lan(1).decode_beacon(&wire), Some(b));
        assert_eq!(lan(2).decode_beacon(&wire), None);
        let mut forged = wire.clone();
        forged[25] ^= 1;
        assert_eq!(lan(1).decode_beacon(&forged), None);
    }

    #[test]
    fn webdav_in_custom_data() {
        let mut db = Database::new();
        assert_eq!(webdav(&db), None);
        let cfg = WebDav {
            url: "https://dav.example/vault.kdbx".into(),
            user: "anna".into(),
            password: Secret::new("pw"),
        };
        set_webdav(&mut db, Some(&cfg));
        assert_eq!(webdav(&db), Some(cfg));
        set_webdav(&mut db, None);
        assert_eq!(webdav(&db), None);
    }

    #[test]
    fn webdav_urls() {
        assert_eq!(
            check_webdav_url("https://dav.example/files/", "v.kdbx").unwrap(),
            "https://dav.example/files/v.kdbx"
        );
        assert!(check_webdav_url("http://192.168.1.5/dav/v.kdbx", "v.kdbx").is_ok());
        assert!(check_webdav_url("http://localhost:8080/v.kdbx", "v.kdbx").is_ok());
        assert!(check_webdav_url("http://nas/dav/v.kdbx", "v.kdbx").is_ok());
        assert!(check_webdav_url("http://dav.example/v.kdbx", "v.kdbx").is_err());
        assert!(check_webdav_url("ftp://dav.example/v.kdbx", "v.kdbx").is_err());
    }

    #[test]
    fn lan_key_depends_on_password_and_vault() {
        let root = uuid::Uuid::from_bytes([5; 16]);
        let a = lan_key(&[1; 32], root);
        assert_eq!(a.key, lan_key(&[1; 32], root).key);
        assert_ne!(a.key, lan_key(&[2; 32], root).key);
        assert_ne!(
            a.key,
            lan_key(&[1; 32], uuid::Uuid::from_bytes([6; 16])).key
        );
    }
}
