//! Secret Service (org.freedesktop.secrets) без D-Bus: криптография сессий и хранение элементов
//! в базе. Сам сервер на шине в keywardend (secret_service.rs).
//!
//! Хранение как у KeePassXC: элементы лежат записями в отдельной папке базы; метка в Title, секрет
//! в Password, атрибуты полями записи с теми же именами, тип содержимого в FDO_SECRETS_CONTENT_TYPE.
//! Приложения видят только эту папку, а не всю базу.

use crate::model::{self, ModelError};
use keepass::Database;
use keepass::db::{GroupId, Times, Value, fields};
use num_bigint::BigUint;
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const CONTENT_TYPE: &str = "FDO_SECRETS_CONTENT_TYPE";
/// Поля записи, которые не являются атрибутами элемента.
const RESERVED: &[&str] = &[
    fields::TITLE,
    fields::USERNAME,
    fields::PASSWORD,
    fields::URL,
    fields::NOTES,
    CONTENT_TYPE,
];

// --- сессии: dh-ietf1024-sha256-aes128-cbc-pkcs7 (как в libsecret и gnome-keyring) ---

/// RFC 2409, Second Oakley Group (1024 бита), генератор 2.
const PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";

fn prime() -> BigUint {
    BigUint::parse_bytes(PRIME_HEX.as_bytes(), 16).expect("константа")
}

/// Ключ сессии AES-128.
#[derive(Clone)]
pub struct SessionKey(Zeroizing<[u8; 16]>);

/// Наша половина обмена: открытый ключ (128 байт) и ключ сессии из открытого ключа клиента.
pub fn dh_negotiate(client_public: &[u8]) -> Result<(Vec<u8>, SessionKey), String> {
    use rand_core06::RngCore;
    let p = prime();
    let theirs = BigUint::from_bytes_be(client_public);
    let one = BigUint::from(1u8);
    if theirs <= one || theirs >= &p - &one {
        return Err(crate::tr!("неверный открытый ключ клиента").into());
    }
    let mut secret = Zeroizing::new([0u8; 128]);
    rand_core06::OsRng.fill_bytes(&mut secret[..]);
    let x = BigUint::from_bytes_be(&secret[..]);
    let ours = BigUint::from(2u8).modpow(&x, &p);
    let shared = theirs.modpow(&x, &p);
    // общий секрет дополняется нулями слева до длины простого числа, как в libsecret
    let mut ikm = Zeroizing::new([0u8; 128]);
    let s = shared.to_bytes_be();
    ikm[128 - s.len()..].copy_from_slice(&s);
    let key = Zeroizing::new(hkdf16(&ikm[..]));
    let mut public = vec![0u8; 128];
    let o = ours.to_bytes_be();
    public[128 - o.len()..].copy_from_slice(&o);
    Ok((public, SessionKey(key)))
}

/// HKDF-SHA256 (RFC 5869) с пустыми солью и info, 16 байт: так ключ сессии выводит libsecret.
fn hkdf16(ikm: &[u8]) -> [u8; 16] {
    use hmac::{Hmac, KeyInit, Mac};
    let mut extract =
        <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&[0u8; 32]).expect("любой ключ");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();
    let mut expand = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&prk).expect("любой ключ");
    expand.update(&[1u8]);
    let okm = expand.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&okm[..16]);
    out
}

/// Секрет для отправки клиенту: (параметры = IV, шифротекст).
pub fn encrypt(key: &SessionKey, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
    use rand_core06::RngCore;
    let mut iv = [0u8; 16];
    rand_core06::OsRng.fill_bytes(&mut iv);
    let ct = cbc::Encryptor::<aes::Aes128>::new(key.0.as_ref().into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plain);
    (iv.to_vec(), ct)
}

pub fn decrypt(key: &SessionKey, iv: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
    if iv.len() != 16 {
        return Err(crate::tr!("неверный IV").into());
    }
    cbc::Decryptor::<aes::Aes128>::new(key.0.as_ref().into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map(Zeroizing::new)
        .map_err(|_| crate::tr!("секрет не расшифровался").to_string())
}

// --- элементы в базе ---

#[derive(Debug, Clone, PartialEq)]
pub struct ItemView {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub created: u64,
    pub modified: u64,
}

fn group(db: &Database, name: &str) -> Option<GroupId> {
    db.root().groups().find(|g| g.name == name).map(|g| g.id())
}

fn ensure_group(db: &mut Database, name: &str) -> model::Result<GroupId> {
    if let Some(g) = group(db, name) {
        return Ok(g);
    }
    let id = model::add_group(db, None, name)?;
    model::parse_group_id(&id)
}

fn unix(t: Option<chrono::NaiveDateTime>) -> u64 {
    t.map(|t| t.and_utc().timestamp().max(0) as u64)
        .unwrap_or(0)
}

/// Элементы папки Secret Service (без секретов).
pub fn items(db: &Database, group_name: &str) -> Vec<ItemView> {
    let Some(g) = group(db, group_name) else {
        return vec![];
    };
    let Some(g) = db.group(g) else { return vec![] };
    g.entries()
        // кошельки приложениям через связку ключей не отдаются
        .filter(|e| crate::model::kind_of(e) != crate::model::EntryKind::CryptoWallet)
        .map(|e| ItemView {
            id: e.id().uuid().to_string(),
            label: e.get(fields::TITLE).unwrap_or_default().to_string(),
            attributes: e
                .fields
                .iter()
                .filter(|(k, _)| !RESERVED.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.get().clone()))
                .collect(),
            created: unix(e.times.creation),
            modified: unix(e.times.last_modification),
        })
        .collect()
}

/// Элементы, у которых совпадают все заданные атрибуты.
pub fn search(db: &Database, group_name: &str, attrs: &HashMap<String, String>) -> Vec<ItemView> {
    items(db, group_name)
        .into_iter()
        .filter(|i| attrs.iter().all(|(k, v)| i.attributes.get(k) == Some(v)))
        .collect()
}

fn in_group(db: &Database, group_name: &str, id: &str) -> model::Result<keepass::db::EntryId> {
    let eid = model::parse_entry_id(id)?;
    let e = db.entry(eid).ok_or(ModelError::EntryNotFound)?;
    if Some(e.parent().id()) != group(db, group_name) {
        return Err(ModelError::EntryNotFound);
    }
    Ok(eid)
}

/// Секрет и его тип; только для элементов папки Secret Service.
pub fn secret(
    db: &Database,
    group_name: &str,
    id: &str,
) -> model::Result<(Zeroizing<Vec<u8>>, String)> {
    let e = db
        .entry(in_group(db, group_name, id)?)
        .ok_or(ModelError::EntryNotFound)?;
    Ok((
        Zeroizing::new(
            e.get(fields::PASSWORD)
                .unwrap_or_default()
                .as_bytes()
                .to_vec(),
        ),
        e.get(CONTENT_TYPE).unwrap_or("text/plain").to_string(),
    ))
}

/// CreateItem: при `replace` элемент с теми же атрибутами перезаписывается.
pub fn create(
    db: &mut Database,
    group_name: &str,
    label: &str,
    attrs: &HashMap<String, String>,
    secret: &[u8],
    content_type: &str,
    replace: bool,
) -> model::Result<String> {
    let g = ensure_group(db, group_name)?;
    let existing = replace
        .then(|| {
            items(db, group_name)
                .into_iter()
                .find(|i| &i.attributes == attrs)
                .map(|i| i.id)
        })
        .flatten();
    let now = Times::now();
    let value = String::from_utf8_lossy(secret).into_owned();
    let eid = match existing {
        Some(id) => model::parse_entry_id(&id)?,
        None => {
            let mut gm = db.group_mut(g).ok_or(ModelError::GroupNotFound)?;
            let e = gm.add_entry();
            e.id()
        }
    };
    let mut e = db.entry_mut(eid).ok_or(ModelError::EntryNotFound)?;
    e.fields.retain(|k, _| RESERVED.contains(&k.as_str()));
    e.set_unprotected(fields::TITLE, label);
    e.set(fields::PASSWORD, Value::protected(value));
    e.set_unprotected(CONTENT_TYPE, content_type);
    for (k, v) in attrs {
        if !RESERVED.contains(&k.as_str()) {
            e.set_unprotected(k.clone(), v.clone());
        }
    }
    e.times.last_modification = Some(now);
    Ok(eid.uuid().to_string())
}

pub fn set_secret(
    db: &mut Database,
    group_name: &str,
    id: &str,
    secret: &[u8],
    content_type: &str,
) -> model::Result<()> {
    let eid = in_group(db, group_name, id)?;
    let mut e = db.entry_mut(eid).ok_or(ModelError::EntryNotFound)?;
    e.set(
        fields::PASSWORD,
        Value::protected(String::from_utf8_lossy(secret).into_owned()),
    );
    e.set_unprotected(CONTENT_TYPE, content_type);
    e.times.last_modification = Some(Times::now());
    Ok(())
}

pub fn set_label(db: &mut Database, group_name: &str, id: &str, label: &str) -> model::Result<()> {
    let eid = in_group(db, group_name, id)?;
    let mut e = db.entry_mut(eid).ok_or(ModelError::EntryNotFound)?;
    e.set_unprotected(fields::TITLE, label);
    e.times.last_modification = Some(Times::now());
    Ok(())
}

pub fn set_attributes(
    db: &mut Database,
    group_name: &str,
    id: &str,
    attrs: &HashMap<String, String>,
) -> model::Result<()> {
    let eid = in_group(db, group_name, id)?;
    let mut e = db.entry_mut(eid).ok_or(ModelError::EntryNotFound)?;
    e.fields.retain(|k, _| RESERVED.contains(&k.as_str()));
    for (k, v) in attrs {
        if !RESERVED.contains(&k.as_str()) {
            e.set_unprotected(k.clone(), v.clone());
        }
    }
    e.times.last_modification = Some(Times::now());
    Ok(())
}

/// Удаление элемента: как любая запись, сначала в корзину.
pub fn delete(db: &mut Database, group_name: &str, id: &str) -> model::Result<()> {
    in_group(db, group_name, id)?;
    model::delete_entry(db, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Клиентская сторона обмена, как в libsecret.
    fn client() -> (BigUint, Vec<u8>) {
        let x = BigUint::from_bytes_be(&[7u8; 64]);
        let public = BigUint::from(2u8).modpow(&x, &prime()).to_bytes_be();
        (x, public)
    }

    /// RFC 5869, тест 3: пустые соль и info
    #[test]
    fn hkdf_rfc5869_case3() {
        let okm = hkdf16(&[0x0b; 22]);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&okm),
            "8da4e775a563c18f715f802a063c5a31"
        );
    }

    #[test]
    fn dh_session_roundtrip() {
        let (x, public) = client();
        let (server_pub, key) = dh_negotiate(&public).unwrap();
        assert_eq!(server_pub.len(), 128);
        // клиент получает тот же ключ
        let shared = BigUint::from_bytes_be(&server_pub).modpow(&x, &prime());
        let mut ikm = [0u8; 128];
        let s = shared.to_bytes_be();
        ikm[128 - s.len()..].copy_from_slice(&s);
        assert_eq!(&hkdf16(&ikm), key.0.as_ref());

        let (iv, ct) = encrypt(&key, b"hunter2");
        assert_ne!(ct, b"hunter2");
        assert_eq!(&*decrypt(&key, &iv, &ct).unwrap(), b"hunter2");
        assert!(decrypt(&key, &iv, &ct[..ct.len() - 1]).is_err());
        assert!(dh_negotiate(&[1]).is_err(), "вырожденный ключ отвергается");
    }

    #[test]
    fn items_live_in_their_group_only() {
        let mut db = Database::new();
        let outside = model::create_entry(&mut db, &Default::default()).unwrap();
        let attrs: HashMap<String, String> = [
            ("service".into(), "git".into()),
            ("user".into(), "octo".into()),
        ]
        .into();
        let id = create(
            &mut db,
            "Secret Service",
            "Git",
            &attrs,
            b"tok1",
            "text/plain",
            true,
        )
        .unwrap();
        let same = create(
            &mut db,
            "Secret Service",
            "Git",
            &attrs,
            b"tok2",
            "text/plain",
            true,
        )
        .unwrap();
        assert_eq!(
            id, same,
            "replace перезаписывает элемент с теми же атрибутами"
        );
        assert_eq!(&*secret(&db, "Secret Service", &id).unwrap().0, b"tok2");
        let found = search(
            &db,
            "Secret Service",
            &[("service".to_string(), "git".to_string())].into(),
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].attributes, attrs);
        assert!(
            secret(&db, "Secret Service", &outside).is_err(),
            "записи вне папки недоступны"
        );
        set_label(&mut db, "Secret Service", &id, "Git token").unwrap();
        assert_eq!(items(&db, "Secret Service")[0].label, "Git token");
        delete(&mut db, "Secret Service", &id).unwrap();
        assert!(items(&db, "Secret Service").is_empty());
    }
}
