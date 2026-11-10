//! Быстрая разблокировка PIN-кодом.
//!
//! Из PIN через Argon2id выводится ключевая пара X25519; на диск (конфиг) попадают только соль
//! и открытый ключ. При полной разблокировке демон шифрует ключ базы этим открытым ключом
//! (crypto_box, одноразовая пара отправителя) и держит шифровку только в памяти. Открыть её
//! можно только PIN-ом. Перебор PIN по конфигу ничего не даёт без памяти живого демона,
//! а у живого демона число попыток ограничено.

use crate::secret::Secret;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Что хранится в конфиге.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinLock {
    pub salt: String,
    pub public: String,
}

/// Ключ базы, как его вводили при полной разблокировке.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuickCreds {
    pub path: String,
    pub password: Option<Secret>,
    pub keyfile: Option<String>,
    pub yubikey: Option<String>,
}

/// Шифровка ключа базы; живёт только в памяти демона.
#[derive(Clone)]
pub struct Sealed {
    sender: PublicKey,
    nonce: crypto_box::Nonce,
    ciphertext: Vec<u8>,
}

/// PIN короче 4 символов перебирается мгновенно даже с Argon2.
pub const MIN_PIN: usize = 4;

fn derive(pin: &str, salt: &[u8]) -> SecretKey {
    // 64 МиБ, 3 прохода: около 0,2-0,4 с, PIN вводят редко
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
    let raw = Zeroizing::new(
        argon2::hash_raw(pin.as_bytes(), salt, &cfg).expect("валидные параметры Argon2"),
    );
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);
    SecretKey::from(bytes)
}

impl PinLock {
    pub fn new(pin: &str) -> Result<Self, String> {
        if pin.chars().count() < MIN_PIN {
            return Err(crate::tr!("PIN не короче {n} символов", n = MIN_PIN));
        }
        let mut salt = [0u8; 16];
        rand::fill(&mut salt);
        let public = derive(pin, &salt).public_key();
        Ok(Self {
            salt: BASE64.encode(&salt),
            public: BASE64.encode(public.as_bytes()),
        })
    }

    fn public_key(&self) -> Result<PublicKey, String> {
        let b = BASE64
            .decode(self.public.as_bytes())
            .map_err(|e| e.to_string())?;
        let a: [u8; 32] = b
            .try_into()
            .map_err(|_| crate::tr!("открытый ключ PIN повреждён").to_string())?;
        Ok(PublicKey::from(a))
    }

    pub fn seal(&self, creds: &QuickCreds) -> Result<Sealed, String> {
        let plain = Zeroizing::new(serde_json::to_vec(creds).map_err(|e| e.to_string())?);
        let ephemeral = SecretKey::generate(&mut OsRng);
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let ciphertext = SalsaBox::new(&self.public_key()?, &ephemeral)
            .encrypt(&nonce, plain.as_slice())
            .map_err(|e| e.to_string())?;
        Ok(Sealed {
            sender: ephemeral.public_key(),
            nonce,
            ciphertext,
        })
    }

    /// Верен ли PIN (без шифровки ключа): для повторного подтверждения при открытой базе.
    pub fn verify(&self, pin: &str) -> bool {
        let Ok(salt) = BASE64.decode(self.salt.as_bytes()) else {
            return false;
        };
        self.public_key()
            .is_ok_and(|p| derive(pin, &salt).public_key() == p)
    }

    /// `None`: PIN неверный.
    pub fn open(&self, pin: &str, sealed: &Sealed) -> Option<QuickCreds> {
        let salt = BASE64.decode(self.salt.as_bytes()).ok()?;
        let secret = derive(pin, &salt);
        if secret.public_key() != self.public_key().ok()? {
            return None;
        }
        let plain = Zeroizing::new(
            SalsaBox::new(&sealed.sender, &secret)
                .decrypt(&sealed.nonce, sealed.ciphertext.as_slice())
                .ok()?,
        );
        serde_json::from_slice(&plain).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{PinLock, QuickCreds};

    #[test]
    fn right_pin_opens_wrong_does_not() {
        let lock = PinLock::new("2468").unwrap();
        let creds = QuickCreds {
            path: "/x/db.kdbx".into(),
            password: Some("hunter2".into()),
            keyfile: None,
            yubikey: Some("2".into()),
        };
        let sealed = lock.seal(&creds).unwrap();
        let back = lock.open("2468", &sealed).unwrap();
        assert_eq!(back.password.unwrap().expose(), "hunter2");
        assert_eq!(back.yubikey.as_deref(), Some("2"));
        assert!(lock.open("2469", &sealed).is_none());
        // другая настройка PIN не открывает старую шифровку
        assert!(
            PinLock::new("2468")
                .unwrap()
                .open("2468", &sealed)
                .is_none()
        );
        assert!(PinLock::new("12").is_err());
    }
}
