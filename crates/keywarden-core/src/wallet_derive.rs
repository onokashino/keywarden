//! Публичные адреса из сид-фразы или приватного ключа: BTC, LTC, DOGE, ETH, BNB, SOL, TRON.
//!
//! Только адреса для получения и сверки: ключи не сохраняются и не уходят из этой функции,
//! промежуточные байты затираются. Пути BIP44/49/84 (secp256k1, BIP32) и SLIP-10 (ed25519,
//! Solana как Phantom). Сид: BIP39 (+ passphrase), Electrum (PBKDF2 «electrum»), SLIP-39
//! (общий секрет, расшифрованный сетью Фейстеля с passphrase).

use crate::wallet;
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Digest as _;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Coin {
    Btc,
    Ltc,
    Doge,
    Eth,
    Bnb,
    Sol,
    Tron,
}

/// Вид адреса Bitcoin и Litecoin: native SegWit (84'), nested SegWit (49'), legacy (44').
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Script {
    Segwit,
    Nested,
    Legacy,
}

impl Coin {
    pub const ALL: [Coin; 7] = [
        Coin::Btc,
        Coin::Ltc,
        Coin::Doge,
        Coin::Eth,
        Coin::Bnb,
        Coin::Sol,
        Coin::Tron,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Coin::Btc => "btc",
            Coin::Ltc => "ltc",
            Coin::Doge => "doge",
            Coin::Eth => "eth",
            Coin::Bnb => "bnb",
            Coin::Sol => "sol",
            Coin::Tron => "tron",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Coin::Btc => "Bitcoin",
            Coin::Ltc => "Litecoin",
            Coin::Doge => "Dogecoin",
            Coin::Eth => "Ethereum",
            Coin::Bnb => "BNB Chain",
            Coin::Sol => "Solana",
            Coin::Tron => "TRON",
        }
    }

    /// Bitcoin и Litecoin различают виды адресов (SegWit, Nested, Legacy).
    pub fn has_scripts(self) -> bool {
        matches!(self, Coin::Btc | Coin::Ltc)
    }

    fn slip44(self) -> u32 {
        match self {
            Coin::Btc => 0,
            Coin::Ltc => 2,
            Coin::Doge => 3,
            Coin::Eth | Coin::Bnb => 60,
            Coin::Sol => 501,
            Coin::Tron => 195,
        }
    }
}

/// Стандартный путь: аккаунт и номер адреса. Solana как Phantom: m/44'/501'/аккаунт'/0'.
pub fn default_path(coin: Coin, script: Script, account: u32, index: u32) -> String {
    let purpose = match (coin.has_scripts(), script) {
        (true, Script::Segwit) => 84,
        (true, Script::Nested) => 49,
        _ => 44,
    };
    match coin {
        Coin::Sol => format!("m/44'/501'/{account}'/0'"),
        _ => format!("m/{purpose}'/{}'/{account}'/0/{index}", coin.slip44()),
    }
}

/// Путь для фразы Electrum: segwit m/0'/0/i, стандартный m/0/i (только Bitcoin).
pub fn electrum_path(segwit: bool, index: u32) -> String {
    if segwit {
        format!("m/0'/0/{index}")
    } else {
        format!("m/0/{index}")
    }
}

const HARD: u32 = 0x8000_0000;

fn parse_path(path: &str) -> Result<Vec<u32>, String> {
    let rest = path
        .trim()
        .strip_prefix('m')
        .ok_or(crate::tr!("путь начинается с m, например m/84'/0'/0'/0/0"))?;
    rest.split('/')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (n, h) = match p.strip_suffix(['\'', 'h', 'H']) {
                Some(n) => (n, HARD),
                None => (p, 0),
            };
            let v: u32 = n
                .parse()
                .map_err(|_| crate::tr!("неверный шаг пути «{p}»", p = p))?;
            if v >= HARD {
                return Err(crate::tr!("слишком большой номер «{p}»", p = p));
            }
            Ok(v | h)
        })
        .collect()
}

fn hmac512(key: &[u8], data: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut m = <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(key).expect("любой ключ");
    for d in data {
        m.update(d);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

/// PBKDF2-HMAC (SHA-512 для Electrum, SHA-256 для SLIP-39).
fn pbkdf2<M: Mac + KeyInit + Clone>(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let prf = <M as KeyInit>::new_from_slice(password).expect("любой ключ");
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut block = 1u32;
    while out.len() < len {
        let mut u = {
            let mut m = prf.clone();
            m.update(salt);
            m.update(&block.to_be_bytes());
            m.finalize().into_bytes().to_vec()
        };
        let mut t = u.clone();
        for _ in 1..rounds {
            let mut m = prf.clone();
            m.update(&u);
            u = m.finalize().into_bytes().to_vec();
            t.iter_mut().zip(&u).for_each(|(a, b)| *a ^= b);
        }
        let take = (len - out.len()).min(t.len());
        out.extend_from_slice(&t[..take]);
        block += 1;
    }
    out
}

/// Сид для BIP32/SLIP-10 из фразы любого поддержанного формата.
pub fn seed_bytes(phrase: &str, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let check = wallet::check_seed(phrase);
    if !(check.valid && check.complete) {
        return Err(check.message);
    }
    let norm = phrase
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    match check.format.as_str() {
        "bip39" => {
            let m = bip39::Mnemonic::parse_in(bip39::Language::English, &norm)
                .map_err(|e| e.to_string())?;
            Ok(Zeroizing::new(m.to_seed(passphrase).to_vec()))
        }
        "electrum" => Ok(pbkdf2::<Hmac<sha2::Sha512>>(
            norm.as_bytes(),
            format!("electrum{passphrase}").as_bytes(),
            2048,
            64,
        )),
        "slip39" => {
            let lines: Vec<&str> = phrase
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            let (ems, id, ext, exp) = wallet::slip39_encrypted_master(&lines)?;
            Ok(slip39_decrypt(&ems, passphrase.as_bytes(), exp, id, ext))
        }
        _ => Err(crate::tr!("формат фразы не распознан").into()),
    }
}

/// Расшифровка общего секрета SLIP-39: 4 раунда Фейстеля на PBKDF2-HMAC-SHA256.
fn slip39_decrypt(
    ems: &[u8],
    passphrase: &[u8],
    exp: u8,
    id: u16,
    ext: bool,
) -> Zeroizing<Vec<u8>> {
    let half = ems.len() / 2;
    let (mut l, mut r) = (
        Zeroizing::new(ems[..half].to_vec()),
        Zeroizing::new(ems[half..].to_vec()),
    );
    let mut salt = vec![];
    if !ext {
        salt.extend_from_slice(b"shamir");
        salt.extend_from_slice(&id.to_be_bytes());
    }
    let rounds = (10_000u32 << exp) / 4;
    for i in (0..4u8).rev() {
        let mut pw = vec![i];
        pw.extend_from_slice(passphrase);
        let mut s = salt.clone();
        s.extend_from_slice(&r);
        let f = pbkdf2::<Hmac<sha2::Sha256>>(&pw, &s, rounds, r.len());
        let next: Vec<u8> = l.iter().zip(f.iter()).map(|(a, b)| a ^ b).collect();
        l = std::mem::replace(&mut r, Zeroizing::new(next));
    }
    let mut out = Zeroizing::new(r.to_vec());
    out.extend_from_slice(&l);
    out
}

/// Приватный ключ secp256k1 по пути BIP32.
fn bip32_key(seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 32]>, String> {
    let i = hmac512(b"Bitcoin seed", &[seed]);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&i[..32]);
    chain.copy_from_slice(&i[32..]);
    for &step in path {
        let sk =
            k256::SecretKey::from_slice(key.as_ref()).map_err(|_| crate::tr!("ключ вне поля"))?;
        let i = if step & HARD != 0 {
            hmac512(chain.as_ref(), &[&[0u8], key.as_ref(), &step.to_be_bytes()])
        } else {
            let pubkey = sk.public_key().to_encoded_point(true);
            hmac512(chain.as_ref(), &[pubkey.as_bytes(), &step.to_be_bytes()])
        };
        let il = Option::<k256::Scalar>::from(k256::Scalar::from_repr(
            k256::FieldBytes::clone_from_slice(&i[..32]),
        ))
        .ok_or(crate::tr!(
            "неудачный шаг деривации (вероятность 2^-127): возьмите следующий номер"
        ))?;
        let child = il + sk.to_nonzero_scalar().as_ref();
        if bool::from(k256::elliptic_curve::Field::is_zero(&child)) {
            return Err(crate::tr!("неудачный шаг деривации: возьмите следующий номер").into());
        }
        key.copy_from_slice(&child.to_repr());
        chain.copy_from_slice(&i[32..]);
    }
    Ok(key)
}

/// Приватный ключ ed25519 по пути SLIP-10 (только усиленные шаги).
fn slip10_key(seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 32]>, String> {
    let i = hmac512(b"ed25519 seed", &[seed]);
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&i[..32]);
    chain.copy_from_slice(&i[32..]);
    for &step in path {
        if step & HARD == 0 {
            return Err(crate::tr!("для Solana все шаги пути усиленные: 44'/501'/0'/0'").into());
        }
        let i = hmac512(chain.as_ref(), &[&[0u8], key.as_ref(), &step.to_be_bytes()]);
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
    }
    Ok(key)
}

fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Digest as _;
    let sha = sha2::Sha256::digest(data);
    ripemd::Ripemd160::digest(sha).into()
}

fn base58check(version: &[u8], payload: &[u8]) -> String {
    let mut v = version.to_vec();
    v.extend_from_slice(payload);
    bs58::encode(v).with_check().into_string()
}

fn keccak20(pubkey_uncompressed: &[u8]) -> [u8; 20] {
    use sha3::Digest as _;
    let h = sha3::Keccak256::digest(&pubkey_uncompressed[1..]);
    h[12..].try_into().expect("20 байт")
}

/// Адрес Ethereum с контрольной суммой регистра (EIP-55).
fn eip55(addr: &[u8; 20]) -> String {
    use sha3::Digest as _;
    let hex = data_encoding::HEXLOWER.encode(addr);
    let h = sha3::Keccak256::digest(hex.as_bytes());
    let mut out = String::from("0x");
    for (i, c) in hex.chars().enumerate() {
        let nib = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 0xf;
        out.push(if c.is_ascii_alphabetic() && nib >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

fn secp_address(coin: Coin, script: Script, secret: &[u8; 32]) -> Result<String, String> {
    let sk =
        k256::SecretKey::from_slice(secret).map_err(|_| crate::tr!("неверный приватный ключ"))?;
    pubkey_address(coin, script, &sk.public_key())
}

fn pubkey_address(coin: Coin, script: Script, pk: &k256::PublicKey) -> Result<String, String> {
    let compressed = pk.to_encoded_point(true);
    let h = || hash160(compressed.as_bytes());
    Ok(match coin {
        Coin::Btc | Coin::Ltc => {
            let (hrp, p2pkh, p2sh) = if coin == Coin::Btc {
                ("bc", 0x00u8, 0x05u8)
            } else {
                ("ltc", 0x30, 0x32)
            };
            match script {
                Script::Segwit => bech32::segwit::encode_v0(
                    bech32::Hrp::parse(hrp).map_err(|e| e.to_string())?,
                    &h(),
                )
                .map_err(|e| e.to_string())?,
                Script::Nested => {
                    let mut redeem = vec![0x00, 0x14];
                    redeem.extend_from_slice(&h());
                    base58check(&[p2sh], &hash160(&redeem))
                }
                Script::Legacy => base58check(&[p2pkh], &h()),
            }
        }
        Coin::Doge => base58check(&[0x1e], &h()),
        Coin::Eth | Coin::Bnb => eip55(&keccak20(pk.to_encoded_point(false).as_bytes())),
        Coin::Tron => base58check(&[0x41], &keccak20(pk.to_encoded_point(false).as_bytes())),
        Coin::Sol => return Err(crate::tr!("Solana на другой кривой").into()),
    })
}

/// Адрес по пути из готового сида.
pub fn derive(seed: &[u8], coin: Coin, script: Script, path: &str) -> Result<String, String> {
    let steps = parse_path(path)?;
    if coin == Coin::Sol {
        let key = slip10_key(seed, &steps)?;
        let pubkey = ed25519_dalek::SigningKey::from_bytes(&key).verifying_key();
        return Ok(bs58::encode(pubkey.as_bytes()).into_string());
    }
    let key = bip32_key(seed, &steps)?;
    secp_address(coin, script, &key)
}

/// Адрес из сохранённого приватного ключа (hex, WIF, base58 или массив Solana).
pub fn address_from_private_key(text: &str, coin: Coin, script: Script) -> Result<String, String> {
    let t = text.trim();
    if coin == Coin::Sol {
        let bytes: Zeroizing<Vec<u8>> = if t.starts_with('[') {
            Zeroizing::new(
                t.trim_matches(['[', ']'])
                    .split(',')
                    .map(|x| {
                        x.trim()
                            .parse::<u8>()
                            .map_err(|_| crate::tr!("неверный массив"))
                    })
                    .collect::<Result<_, _>>()?,
            )
        } else {
            Zeroizing::new(
                bs58::decode(t)
                    .into_vec()
                    .map_err(|_| crate::tr!("не base58"))?,
            )
        };
        // 64 байта: секрет и публичный ключ; 32 байта: только секрет
        let pubkey = match bytes.len() {
            64 => bytes[32..].to_vec(),
            32 => {
                let k: [u8; 32] = bytes[..].try_into().expect("32");
                ed25519_dalek::SigningKey::from_bytes(&k)
                    .verifying_key()
                    .as_bytes()
                    .to_vec()
            }
            _ => return Err(crate::tr!("ключ Solana: 32 или 64 байта").into()),
        };
        return Ok(bs58::encode(pubkey).into_string());
    }
    let hex = t.strip_prefix("0x").unwrap_or(t);
    let mut key = Zeroizing::new([0u8; 32]);
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let b = Zeroizing::new(
            data_encoding::HEXLOWER_PERMISSIVE
                .decode(hex.as_bytes())
                .map_err(|e| e.to_string())?,
        );
        key.copy_from_slice(&b);
    } else {
        let b = Zeroizing::new(
            bs58::decode(t)
                .with_check(None)
                .into_vec()
                .map_err(|_| crate::tr!("формат ключа не распознан"))?,
        );
        if !(b.len() == 33 || b.len() == 34) {
            return Err(crate::tr!("формат ключа не распознан").into());
        }
        key.copy_from_slice(&b[1..33]);
    }
    secp_address(coin, script, &key)
}

/// Расширенный публичный ключ аккаунта (xpub, ypub, zpub, Ltub, Mtub, dgub): только адреса,
/// без секретов. Префикс подсказывает сеть и вид адреса.
pub struct Xpub {
    key: k256::PublicKey,
    chain: [u8; 32],
    pub coin: Coin,
    /// Вид адреса задан префиксом (ypub, zpub, Mtub); у xpub выбирает пользователь.
    pub script: Option<Script>,
}

pub fn parse_xpub(text: &str) -> Result<Xpub, String> {
    let b = bs58::decode(text.trim())
        .with_check(None)
        .into_vec()
        .map_err(|_| crate::tr!("не похоже на xpub: ошибка base58check"))?;
    if b.len() != 78 {
        return Err(crate::tr!("не похоже на xpub: неверная длина").into());
    }
    let (coin, script) = match u32::from_be_bytes(b[..4].try_into().expect("4")) {
        0x0488_B21E => (Coin::Btc, None),
        0x049D_7CB2 => (Coin::Btc, Some(Script::Nested)),
        0x04B2_4746 => (Coin::Btc, Some(Script::Segwit)),
        0x019D_A462 => (Coin::Ltc, Some(Script::Legacy)),
        0x01B2_6EF6 => (Coin::Ltc, Some(Script::Nested)),
        0x02FA_CAFD => (Coin::Doge, Some(Script::Legacy)),
        _ => {
            return Err(crate::tr!(
                "неизвестный префикс: нужен xpub, ypub, zpub, Ltub, Mtub или dgub"
            )
            .into());
        }
    };
    let key = k256::PublicKey::from_sec1_bytes(&b[45..])
        .map_err(|_| crate::tr!("в xpub неверный ключ"))?;
    Ok(Xpub {
        key,
        chain: b[13..45].try_into().expect("32"),
        coin,
        script,
    })
}

impl Xpub {
    /// Адрес по относительному пути от аккаунта: change (0 приём, 1 сдача) и номер.
    pub fn address(
        &self,
        coin: Coin,
        script: Script,
        change: u32,
        index: u32,
    ) -> Result<String, String> {
        if coin == Coin::Sol {
            return Err(crate::tr!("xpub только для сетей на secp256k1").into());
        }
        let mut key = self.key;
        let mut chain = self.chain;
        for step in [change, index] {
            if step >= HARD {
                return Err(crate::tr!("из xpub только неусиленные шаги").into());
            }
            let i = hmac512(
                &chain,
                &[key.to_encoded_point(true).as_bytes(), &step.to_be_bytes()],
            );
            let il = Option::<k256::Scalar>::from(k256::Scalar::from_repr(
                k256::FieldBytes::clone_from_slice(&i[..32]),
            ))
            .ok_or(crate::tr!(
                "неудачный шаг деривации: возьмите следующий номер"
            ))?;
            let p = k256::ProjectivePoint::GENERATOR * il + key.to_projective();
            key = k256::PublicKey::from_affine(p.to_affine())
                .map_err(|_| crate::tr!("неудачный шаг деривации: возьмите следующий номер"))?;
            chain.copy_from_slice(&i[32..]);
        }
        pubkey_address(coin, self.script.unwrap_or(script), &key)
    }
}

/// Сети, к которым подходит приватный ключ (по формату).
pub fn key_coins(text: &str) -> Vec<Coin> {
    match wallet::private_key_format(text) {
        Some(f) if f.contains("Solana") => vec![Coin::Sol],
        Some(f) if f.starts_with("WIF") => {
            if f.contains("Litecoin") {
                vec![Coin::Ltc]
            } else if f.contains("Dogecoin") {
                vec![Coin::Doge]
            } else {
                vec![Coin::Btc]
            }
        }
        Some(_) => vec![
            Coin::Eth,
            Coin::Bnb,
            Coin::Tron,
            Coin::Btc,
            Coin::Ltc,
            Coin::Doge,
        ],
        None => vec![],
    }
}

/// Сохранённые адреса, которых нет среди адресов из фразы, ключа или xpub (первые 20 приёма и
/// сдачи стандартных путей аккаунта 0 и пути из записи). Опечатка при переносе адреса или
/// фраза от другого кошелька. Возвращает непойманные адреса; пусто, если сверять не с чем.
pub fn unmatched_addresses(
    seed: &str,
    passphrase: &str,
    key: &str,
    xpub: &str,
    derivation: &str,
    addresses: &[String],
) -> Vec<String> {
    const N: u32 = 20;
    let sb = (!seed.trim().is_empty())
        .then(|| seed_bytes(seed, passphrase).ok())
        .flatten();
    let xp = (!xpub.trim().is_empty())
        .then(|| parse_xpub(xpub).ok())
        .flatten();
    let key = key.trim();
    if sb.is_none() && xp.is_none() && key.is_empty() {
        return vec![];
    }
    let electrum = sb.is_some() && wallet::check_seed(seed).format == "electrum";
    let base = derivation.trim().trim_end_matches('/');
    let scripts = [Script::Segwit, Script::Nested, Script::Legacy];
    let mut known: std::collections::HashMap<Coin, std::collections::HashSet<String>> =
        Default::default();
    let candidates = |coin: Coin| -> std::collections::HashSet<String> {
        let mut out = std::collections::HashSet::new();
        let mut add = |r: Result<String, String>| {
            if let Ok(a) = r {
                out.insert(a.to_lowercase());
            }
        };
        let scs: &[Script] = if coin.has_scripts() {
            &scripts
        } else {
            &scripts[2..]
        };
        if let Some(sb) = &sb {
            for i in 0..N {
                if electrum {
                    for p in [format!("m/0'/0/{i}"), format!("m/0'/1/{i}")] {
                        add(derive(sb, coin, Script::Segwit, &p));
                    }
                    for p in [format!("m/0/{i}"), format!("m/1/{i}")] {
                        add(derive(sb, coin, Script::Legacy, &p));
                    }
                    continue;
                }
                if coin == Coin::Sol {
                    add(derive(
                        sb,
                        coin,
                        Script::Legacy,
                        &default_path(coin, Script::Legacy, i, 0),
                    ));
                    continue;
                }
                for &sc in scs {
                    // m/84'/0'/0'/0/i: приём, тот же аккаунт с /1/i: сдача
                    let p = default_path(coin, sc, 0, i);
                    let account = p.rsplitn(3, '/').nth(2).unwrap_or_default();
                    add(derive(sb, coin, sc, &p));
                    add(derive(sb, coin, sc, &format!("{account}/1/{i}")));
                    if !base.is_empty() {
                        for p in [
                            format!("{base}/{i}"),
                            format!("{base}/0/{i}"),
                            format!("{base}/1/{i}"),
                        ] {
                            add(derive(sb, coin, sc, &p));
                        }
                    }
                }
            }
        }
        if let Some(x) = &xp {
            for i in 0..N {
                for &sc in scs {
                    add(x.address(coin, sc, 0, i));
                    add(x.address(coin, sc, 1, i));
                }
            }
        }
        if !key.is_empty() {
            for &sc in scs {
                add(address_from_private_key(key, coin, sc));
            }
        }
        out
    };
    addresses
        .iter()
        .filter(|a| {
            let coins: Vec<Coin> = wallet::address_networks(a)
                .into_iter()
                .filter_map(|id| Coin::ALL.into_iter().find(|c| c.id() == id))
                .collect();
            // адрес неизвестной сети не сверяем
            !coins.is_empty()
                && !coins.iter().any(|&c| {
                    known
                        .entry(c)
                        .or_insert_with(|| candidates(c))
                        .contains(&a.to_lowercase())
                })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod xpub_tests {
    use super::*;

    // векторы BIP84 и BIP49 для фразы abandon x11 about, аккаунт 0
    #[test]
    fn xpub_addresses() {
        let z = parse_xpub("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs").unwrap();
        assert_eq!((z.coin, z.script), (Coin::Btc, Some(Script::Segwit)));
        assert_eq!(
            z.address(Coin::Btc, Script::Legacy, 0, 0).unwrap(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            z.address(Coin::Btc, Script::Segwit, 1, 0).unwrap(),
            "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"
        );
        let y = parse_xpub("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP").unwrap();
        assert_eq!(
            y.address(Coin::Btc, Script::Segwit, 0, 0).unwrap(),
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        );
        assert!(parse_xpub("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYt").is_err());
    }

    #[test]
    fn finds_mistyped_addresses() {
        let seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let good = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_string();
        let change = "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el".to_string();
        let eth = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".to_string();
        let typo = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv".to_string();
        let addrs = [good.clone(), change.clone(), eth, typo.clone()];
        assert_eq!(
            unmatched_addresses(seed, "", "", "", "", &addrs),
            vec![typo.clone()]
        );
        // другая passphrase: ни один адрес фразы не подходит
        assert_eq!(unmatched_addresses(seed, "x", "", "", "", &addrs).len(), 4);
        // сверять не с чем
        assert!(unmatched_addresses("", "", "", "", "", &addrs).is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABOUT: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Эталон посчитан независимо библиотекой bip_utils (Python).
    #[test]
    fn addresses_match_reference() {
        let seed = seed_bytes(ABOUT, "").unwrap();
        let d = |c, s, a, i| derive(&seed, c, s, &default_path(c, s, a, i)).unwrap();
        use Coin::*;
        use Script::*;
        assert_eq!(
            d(Btc, Segwit, 0, 0),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            d(Btc, Segwit, 0, 1),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
        assert_eq!(d(Btc, Nested, 0, 0), "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf");
        assert_eq!(d(Btc, Legacy, 0, 0), "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA");
        assert_eq!(
            d(Ltc, Segwit, 0, 0),
            "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh"
        );
        assert_eq!(d(Ltc, Nested, 0, 0), "M7wtsL7wSHDBJVMWWhtQfTMSYYkyooAAXM");
        assert_eq!(d(Ltc, Legacy, 0, 0), "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez");
        assert_eq!(d(Doge, Legacy, 0, 0), "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC");
        assert_eq!(
            d(Eth, Legacy, 0, 0),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(
            d(Bnb, Legacy, 0, 0),
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(d(Tron, Legacy, 0, 0), "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH");
        assert_eq!(
            d(Sol, Legacy, 0, 0),
            "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
        );
        let pp = seed_bytes(ABOUT, "TREZOR").unwrap();
        assert_eq!(
            derive(&pp, Eth, Legacy, &default_path(Eth, Legacy, 0, 0)).unwrap(),
            "0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6"
        );
    }

    #[test]
    fn electrum_and_private_key() {
        let e =
            "wild father tree among universe such mobile favorite target dynamic credit identify";
        let seed = seed_bytes(e, "").unwrap();
        assert_eq!(
            derive(&seed, Coin::Btc, Script::Segwit, &electrum_path(true, 0)).unwrap(),
            "bc1q4794m2uuw9jmjszmplfj4wvvr5j272fpnx2cse"
        );
        let pk = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        assert_eq!(
            address_from_private_key(pk, Coin::Eth, Script::Legacy).unwrap(),
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
        );
        assert_eq!(
            address_from_private_key(pk, Coin::Tron, Script::Legacy).unwrap(),
            "TE2H9hWjzYdwzDFRJfx9BFhr4MmjH1CHaz"
        );
        assert_eq!(
            address_from_private_key(pk, Coin::Btc, Script::Segwit).unwrap(),
            "bc1qnduq8yy8h4nr7g9vuuglzklqatmaquq9ac42k2"
        );
    }

    /// SLIP-39: общий секрет из официальных векторов Trezor (passphrase «TREZOR»).
    #[test]
    fn slip39_master_secret_vectors() {
        let v: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/slip39_vectors.json")).unwrap();
        let mut checked = 0;
        for case in v {
            let secret = case[2].as_str().unwrap();
            if secret.is_empty() {
                continue;
            }
            let shares: Vec<&str> = case[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect();
            let got = seed_bytes(&shares.join("\n"), "TREZOR").unwrap();
            assert_eq!(data_encoding::HEXLOWER.encode(&got), secret, "{}", case[0]);
            checked += 1;
        }
        assert!(checked > 10);
    }
}
