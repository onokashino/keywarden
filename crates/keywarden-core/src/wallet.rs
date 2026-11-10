//! Криптокошельки: хранение и проверка сид-фраз, генерация BIP39, форматы приватных ключей,
//! SeedQR, сеть адреса по его виду.
//!
//! Из фраз здесь ничего не выводится (ни ключи, ни адреса): только проверка, что фраза записана
//! без ошибок. SLIP-39 проверяется полностью (контрольные суммы, согласованность и то, что доли
//! сходятся по дайджесту), но сам кошелёк не расшифровывается.

use crate::secret::Secret;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

// Имена полей записи «Криптокошелёк» (английские: так их видят KeePassXC и мобильные клиенты).
pub const WALLET_TYPE: &str = "Wallet Type";
pub const NETWORKS: &str = "Networks";
pub const SEED: &str = "Seed";
pub const PASSPHRASE: &str = "Passphrase";
pub const PRIVATE_KEY: &str = "Private Key";
pub const DERIVATION: &str = "Derivation Path";
pub const ADDRESSES: &str = "Addresses";
pub const XPUB: &str = "xpub";

/// Поля, которые отдаются и меняются только после повторного подтверждения (PIN или мастер-пароль).
pub const GUARDED: [&str; 3] = [SEED, PASSPHRASE, PRIVATE_KEY];

pub fn is_guarded(field: &str) -> bool {
    GUARDED.contains(&field)
}

/// Сети, для которых есть обозреватели и распознавание адресов.
pub const NETWORK_IDS: [(&str, &str); 7] = [
    ("btc", "Bitcoin"),
    ("ltc", "Litecoin"),
    ("doge", "Dogecoin"),
    ("eth", "Ethereum"),
    ("bnb", "BNB Smart Chain"),
    ("sol", "Solana"),
    ("tron", "TRON"),
];

/// Обозреватели по умолчанию: шаблон с `{address}`.
pub fn default_explorers() -> BTreeMap<String, String> {
    [
        ("btc", "https://mempool.space/address/{address}"),
        ("ltc", "https://litecoinspace.org/address/{address}"),
        ("doge", "https://blockchair.com/dogecoin/address/{address}"),
        ("eth", "https://etherscan.io/address/{address}"),
        ("bnb", "https://bscscan.com/address/{address}"),
        ("sol", "https://solscan.io/account/{address}"),
        ("tron", "https://tronscan.org/#/address/{address}"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

// --- проверка фразы ---

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SeedCheck {
    /// bip39, electrum, slip39 или пусто (не распознано)
    pub format: String,
    /// «BIP39, 24 слова»
    pub label: String,
    /// слова и контрольные суммы верны
    pub valid: bool,
    /// всё на месте: для SLIP-39 долей хватает и они сходятся
    pub complete: bool,
    /// номера слов (с 0, сквозные по всему тексту) не из словаря
    pub bad_words: Vec<usize>,
    pub message: String,
}

const BIP39_LENGTHS: [usize; 5] = [12, 15, 18, 21, 24];

fn bip39_list() -> &'static [&'static str; 2048] {
    bip39::Language::English.word_list()
}

/// Подсказка по началу слова (до `limit` вариантов), словарь BIP39.
pub fn suggest(prefix: &str, limit: usize) -> Vec<&'static str> {
    let p = prefix.trim().to_lowercase();
    if p.is_empty() {
        return vec![];
    }
    bip39_list()
        .iter()
        .copied()
        .filter(|w| w.starts_with(&p))
        .take(limit)
        .collect()
}

pub fn is_bip39_word(w: &str) -> bool {
    bip39::Language::English
        .find_word(&w.to_lowercase())
        .is_some()
}

/// Проверить фразу или доли SLIP-39 (по доле на строку).
pub fn check_seed(text: &str) -> SeedCheck {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let words: Vec<String> = text.split_whitespace().map(|w| w.to_lowercase()).collect();
    if words.is_empty() {
        return SeedCheck {
            message: crate::tr!("Пусто").into(),
            ..Default::default()
        };
    }
    // SLIP-39: доли по 20 или 33 слова (у BIP39 таких длин нет), по одной на строку
    let share_lens = |n: usize| n == 20 || n == 33;
    let looks_slip = if lines.len() > 1 {
        lines
            .iter()
            .all(|l| share_lens(l.split_whitespace().count()))
    } else {
        let all_slip = words.iter().all(|w| slip39_index(w).is_some());
        // не той длины, но явно SLIP-39 (часть слов есть только в его словаре): понятная ошибка длины
        all_slip && (share_lens(words.len()) || !words.iter().all(|w| is_bip39_word(w)))
    };
    if looks_slip {
        return check_slip39(&lines);
    }
    check_bip39_or_electrum(&words)
}

fn check_bip39_or_electrum(words: &[String]) -> SeedCheck {
    let joined = words.join(" ");
    let n = words.len();
    let electrum = electrum_version(&joined);
    if bip39::Mnemonic::parse_in(bip39::Language::English, &joined).is_ok() {
        return SeedCheck {
            format: "bip39".into(),
            label: bip39_label(n),
            valid: true,
            complete: true,
            message: match electrum {
                Some(_) => {
                    crate::tr!("Контрольная сумма верна (фраза подходит и как Electrum)").into()
                }
                None => crate::tr!("Контрольная сумма верна").into(),
            },
            ..Default::default()
        };
    }
    let bad_words: Vec<usize> = words
        .iter()
        .enumerate()
        .filter(|(_, w)| !is_bip39_word(w))
        .map(|(i, _)| i)
        .collect();
    if bad_words.is_empty()
        && let Some(v) = electrum
    {
        return SeedCheck {
            format: "electrum".into(),
            label: format!("Electrum, {v}"),
            valid: true,
            complete: true,
            message: crate::tr!("Версия фразы Electrum распознана").into(),
            ..Default::default()
        };
    }
    let message = if !bad_words.is_empty() {
        let list: Vec<String> = bad_words.iter().map(|i| (i + 1).to_string()).collect();
        crate::tr!("Нет в словаре BIP39: слово {list}", list = list.join(", "))
    } else if !BIP39_LENGTHS.contains(&n) {
        crate::tr!(
            "{n} {words}: у BIP39 бывает 12, 15, 18, 21 или 24",
            n = n,
            words = words_noun(n)
        )
    } else {
        crate::tr!("Контрольная сумма не сходится: проверьте слова и их порядок").into()
    };
    SeedCheck {
        format: "bip39".into(),
        label: bip39_label(n),
        bad_words,
        message,
        ..Default::default()
    }
}

fn words_noun(n: usize) -> &'static str {
    crate::i18n::plural(n as u64, "слово", "слова", "слов")
}

fn bip39_label(n: usize) -> String {
    format!("BIP39, {n} {}", words_noun(n))
}

/// Версия фразы Electrum: HMAC-SHA512("Seed version", фраза) начинается с префикса версии.
fn electrum_version(words: &str) -> Option<&'static str> {
    let norm = words
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let mut mac = <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(b"Seed version").ok()?;
    mac.update(norm.as_bytes());
    let h = data_encoding::HEXLOWER.encode(&mac.finalize().into_bytes());
    // сначала трёхзначные префиксы: «100» тоже начинается с «1»
    [
        ("100", "segwit"),
        ("101", "2FA"),
        ("102", "2FA segwit"),
        ("01", crate::tr!("стандартный")),
    ]
    .into_iter()
    .find(|(p, _)| h.starts_with(p))
    .map(|(_, v)| v)
}

// --- генерация ---

/// Новая фраза BIP39 из системного генератора случайных чисел: 12 или 24 слова.
pub fn generate_bip39(words: usize) -> Result<Secret, String> {
    let len = match words {
        12 => 16,
        24 => 32,
        _ => return Err(crate::tr!("12 или 24 слова").into()),
    };
    let mut entropy = zeroize::Zeroizing::new(vec![0u8; len]);
    rand::fill(entropy.as_mut_slice());
    let m = bip39::Mnemonic::from_entropy(&entropy).map_err(|e| e.to_string())?;
    Ok(Secret::new(m.to_string()))
}

// --- SeedQR (стандарт SeedSigner), только BIP39 ---

/// Матрица QR: обычный (номера слов по 4 цифры) или компактный (энтропия байтами).
pub fn seedqr(phrase: &str, compact: bool) -> Option<(usize, Vec<bool>)> {
    let m = bip39::Mnemonic::parse_in(bip39::Language::English, phrase.trim()).ok()?;
    let level = qrcode::EcLevel::L;
    let code = if compact {
        let entropy = zeroize::Zeroizing::new(m.to_entropy());
        qrcode::QrCode::with_error_correction_level(entropy.as_slice(), level).ok()?
    } else {
        let digits = zeroize::Zeroizing::new(seedqr_digits(&m));
        qrcode::QrCode::with_error_correction_level(digits.as_bytes(), level).ok()?
    };
    let w = code.width();
    Some((
        w,
        code.to_colors()
            .into_iter()
            .map(|c| c == qrcode::Color::Dark)
            .collect(),
    ))
}

fn seedqr_digits(m: &bip39::Mnemonic) -> String {
    m.words()
        .map(|w| {
            let i = bip39::Language::English.find_word(w).unwrap_or(0);
            format!("{i:04}")
        })
        .collect()
}

// --- приватные ключи и адреса ---

/// Формат приватного ключа, если распознан: WIF, hex, base58, массив байт Solana.
pub fn private_key_format(s: &str) -> Option<String> {
    let t = s.trim();
    let hex = t.strip_prefix("0x").unwrap_or(t);
    if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(crate::tr!("hex, 32 байта (Ethereum, BNB, TRON)").into());
    }
    if t.starts_with('[') && t.ends_with(']') {
        let n = t[1..t.len() - 1]
            .split(',')
            .filter(|x| x.trim().parse::<u8>().is_ok())
            .count();
        if n == 64 {
            return Some(crate::tr!("массив 64 байта (Solana, solana-keygen)").into());
        }
    }
    if let Ok(b) = bs58::decode(t).with_check(None).into_vec()
        && (b.len() == 33 || b.len() == 34)
    {
        let coin = match b[0] {
            0x80 => "Bitcoin",
            0xb0 => "Litecoin",
            0x9e => "Dogecoin",
            0xef => crate::tr!("тестовая сеть"),
            _ => return None,
        };
        let compressed = b.len() == 34 && b[33] == 1;
        return Some(format!(
            "WIF, {coin}{}",
            if compressed {
                crate::tr!(", сжатый")
            } else {
                ""
            }
        ));
    }
    match bs58::decode(t).into_vec() {
        Ok(b) if b.len() == 64 => Some(crate::tr!("base58, 64 байта (Solana)").into()),
        _ => None,
    }
}

/// Сети, к которым подходит адрес (по виду). `0x…` подходит и к Ethereum, и к BNB.
pub fn address_networks(a: &str) -> Vec<&'static str> {
    let a = a.trim();
    let low = a.to_lowercase();
    if low.starts_with("bc1") || low.starts_with("tb1") {
        return vec!["btc"];
    }
    if low.starts_with("ltc1") {
        return vec!["ltc"];
    }
    if let Some(h) = a.strip_prefix("0x")
        && h.len() == 40
        && h.chars().all(|c| c.is_ascii_hexdigit())
    {
        return vec!["eth", "bnb"];
    }
    if let Ok(b) = bs58::decode(a).with_check(None).into_vec() {
        match (b.len(), b[0]) {
            (21, 0x00 | 0x05) => return vec!["btc"],
            (21, 0x30 | 0x32) => return vec!["ltc"],
            (21, 0x1e | 0x16) => return vec!["doge"],
            (21, 0x41) => return vec!["tron"],
            _ => {}
        }
    }
    match bs58::decode(a).into_vec() {
        Ok(b) if b.len() == 32 => vec!["sol"],
        _ => vec![],
    }
}

/// Адреса из поля: по одному на строку, подпись перед адресом через двоеточие по желанию
/// («основной: bc1q…»). Возвращает (подпись, адрес).
pub fn parse_addresses(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let addr = l.split_whitespace().last()?;
            let label = l[..l.len() - addr.len()]
                .trim()
                .trim_end_matches(':')
                .trim()
                .to_string();
            Some((label, addr.to_string()))
        })
        .collect()
}

/// Ссылка на обозреватель: шаблон с `{address}`.
pub fn explorer_url(template: &str, address: &str) -> String {
    let safe: String = address
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    template.replace("{address}", &safe)
}

// --- SLIP-39 ---

fn slip39_words() -> &'static HashMap<&'static str, u16> {
    static W: OnceLock<HashMap<&'static str, u16>> = OnceLock::new();
    W.get_or_init(|| {
        include_str!("../data/slip39_wordlist.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .enumerate()
            .map(|(i, w)| (w, i as u16))
            .collect()
    })
}

fn slip39_index(w: &str) -> Option<u16> {
    slip39_words().get(w).copied()
}

struct Share {
    id: u16,
    ext: bool,
    exp: u8,
    group_index: u8,
    group_threshold: u8,
    group_count: u8,
    member_index: u8,
    member_threshold: u8,
    value: Vec<u8>,
}

fn rs1024_polymod(values: impl Iterator<Item = u32>) -> u32 {
    const GEN: [u32; 10] = [
        0xE0E040, 0x1C1C080, 0x3838100, 0x7070200, 0xE0E0009, 0x1C0C2412, 0x38086C24, 0x3090FC48,
        0x21B1F890, 0x3F3F120,
    ];
    let mut chk: u32 = 1;
    for v in values {
        let b = chk >> 20;
        chk = ((chk & 0xFFFFF) << 10) ^ v;
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn parse_share(line: &str, offset: usize) -> Result<Share, (String, Vec<usize>)> {
    let words: Vec<String> = line.split_whitespace().map(|w| w.to_lowercase()).collect();
    let bad: Vec<usize> = words
        .iter()
        .enumerate()
        .filter(|(_, w)| slip39_index(w).is_none())
        .map(|(i, _)| offset + i)
        .collect();
    if !bad.is_empty() {
        return Err((crate::tr!("Нет в словаре SLIP-39").into(), bad));
    }
    let idx: Vec<u32> = words
        .iter()
        .map(|w| slip39_index(w).unwrap_or(0) as u32)
        .collect();
    if idx.len() < 20 {
        return Err((crate::tr!("доля короче 20 слов").into(), vec![]));
    }
    let id = ((idx[0] << 5) | (idx[1] >> 5)) as u16;
    let ext = (idx[1] >> 4) & 1 == 1;
    let exp = (idx[1] & 0xF) as u8;
    let cs: &[u8] = if ext { b"shamir_extendable" } else { b"shamir" };
    if rs1024_polymod(cs.iter().map(|b| *b as u32).chain(idx.iter().copied())) != 1 {
        return Err((
            crate::tr!("контрольная сумма доли не сходится").into(),
            vec![],
        ));
    }
    let v = (idx[2] << 10) | idx[3];
    let group_index = (v >> 16) as u8;
    let group_threshold = ((v >> 12) & 0xF) as u8 + 1;
    let group_count = ((v >> 8) & 0xF) as u8 + 1;
    let member_index = ((v >> 4) & 0xF) as u8;
    let member_threshold = (v & 0xF) as u8 + 1;
    // значение: слова между заголовком (4) и контрольной суммой (3), слева выравнивание нулями
    let value_words = &idx[4..idx.len() - 3];
    let bits = value_words.len() * 10;
    let padding = bits % 16;
    if padding > 8 {
        return Err((crate::tr!("неверная длина доли").into(), vec![]));
    }
    let mut stream: Vec<bool> = Vec::with_capacity(bits);
    for w in value_words {
        for i in (0..10).rev() {
            stream.push((w >> i) & 1 == 1);
        }
    }
    if stream[..padding].iter().any(|b| *b) {
        return Err((crate::tr!("неверное выравнивание доли").into(), vec![]));
    }
    let value: Vec<u8> = stream[padding..]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, b| (acc << 1) | *b as u8))
        .collect();
    if value.len() < 16 {
        return Err((crate::tr!("секрет короче 128 бит").into(), vec![]));
    }
    Ok(Share {
        id,
        ext,
        exp,
        group_index,
        group_threshold,
        group_count,
        member_index,
        member_threshold,
        value,
    })
}

fn gf_tables() -> &'static ([u8; 255], [u8; 256]) {
    static T: OnceLock<([u8; 255], [u8; 256])> = OnceLock::new();
    T.get_or_init(|| {
        let (mut exp, mut log) = ([0u8; 255], [0u8; 256]);
        let mut x: u8 = 1;
        for (i, e) in exp.iter_mut().enumerate() {
            *e = x;
            log[x as usize] = i as u8;
            // умножение на 3 в GF(256) с многочленом Rijndael
            let x2 = (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 };
            x ^= x2;
        }
        (exp, log)
    })
}

/// Интерполяция Лагранжа в точке `x` (как в python-shamir-mnemonic).
fn interpolate(shares: &[(u8, &[u8])], x: u8) -> Option<Vec<u8>> {
    if let Some((_, v)) = shares.iter().find(|(sx, _)| *sx == x) {
        return Some(v.to_vec());
    }
    let (exp, log) = gf_tables();
    let len = shares.first()?.1.len();
    if shares.iter().any(|(_, v)| v.len() != len) {
        return None;
    }
    let lg = |v: u8| log[v as usize] as i32;
    let log_prod: i32 = shares.iter().map(|(sx, _)| lg(sx ^ x)).sum();
    let mut out = vec![0u8; len];
    for (sx, sv) in shares {
        let others: i32 = shares.iter().map(|(ox, _)| lg(sx ^ ox)).sum();
        let basis = (log_prod - lg(sx ^ x) - others).rem_euclid(255);
        for (o, b) in out.iter_mut().zip(sv.iter()) {
            if *b != 0 {
                *o ^= exp[((lg(*b) + basis) % 255) as usize];
            }
        }
    }
    Some(out)
}

/// Общий секрет из `threshold` долей; при пороге больше 1 проверяется дайджест.
fn recover_secret(threshold: u8, shares: &[(u8, &[u8])]) -> Result<Vec<u8>, String> {
    if threshold == 1 {
        return Ok(shares[0].1.to_vec());
    }
    let shared = interpolate(shares, 255).ok_or(crate::tr!("доли разной длины"))?;
    let digest_share = interpolate(shares, 254).ok_or(crate::tr!("доли разной длины"))?;
    let (digest, random) = digest_share.split_at(4);
    let mut mac =
        <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(random).map_err(|e| e.to_string())?;
    mac.update(&shared);
    if mac.finalize().into_bytes()[..4] != *digest {
        return Err(
            crate::tr!("доли не сходятся: одна из них с ошибкой или от другого набора").into(),
        );
    }
    Ok(shared)
}

/// Проверка SLIP-39 и, если доли сходятся, зашифрованный общий секрет с параметрами.
#[allow(clippy::type_complexity)]
fn slip39_inner(lines: &[&str]) -> (SeedCheck, Option<(Vec<u8>, u16, bool, u8)>) {
    let total_words: usize = lines.iter().map(|l| l.split_whitespace().count()).sum();
    let mut out = SeedCheck {
        format: "slip39".into(),
        label: format!(
            "SLIP-39, {} {}",
            lines.len(),
            crate::i18n::plural(lines.len() as u64, "доля", "доли", "долей")
        ),
        ..Default::default()
    };
    let mut shares = vec![];
    let mut offset = 0;
    for (i, l) in lines.iter().enumerate() {
        match parse_share(l, offset) {
            Ok(s) => shares.push(s),
            Err((msg, bad)) => {
                out.bad_words.extend(bad);
                out.message = crate::tr!("Доля {n}: {msg}", n = i + 1, msg = msg);
                return (out, None);
            }
        }
        offset += l.split_whitespace().count();
    }
    let _ = total_words;
    let first = &shares[0];
    let same = |f: fn(&Share) -> u32| shares.iter().all(|s| f(s) == f(first));
    if !same(|s| s.id as u32) || !same(|s| s.ext as u32) {
        out.message = crate::tr!("Доли от разных кошельков (разные идентификаторы)").into();
        return (out, None);
    }
    if !same(|s| s.exp as u32)
        || !same(|s| s.group_threshold as u32)
        || !same(|s| s.group_count as u32)
    {
        out.message = crate::tr!("Доли не согласованы между собой").into();
        return (out, None);
    }
    if first.group_threshold > first.group_count {
        out.message = crate::tr!("Порог групп больше числа групп").into();
        return (out, None);
    }
    let mut groups: BTreeMap<u8, Vec<&Share>> = BTreeMap::new();
    for s in &shares {
        groups.entry(s.group_index).or_default().push(s);
    }
    for g in groups.values() {
        if g.iter()
            .any(|s| s.member_threshold != g[0].member_threshold)
        {
            out.message = crate::tr!("Внутри группы разные пороги").into();
            return (out, None);
        }
        let mut seen = std::collections::HashSet::new();
        if g.iter().any(|s| !seen.insert(s.member_index)) {
            out.message = crate::tr!("Одна и та же доля указана дважды").into();
            return (out, None);
        }
    }
    out.valid = true;
    let ready: Vec<(&u8, &Vec<&Share>)> = groups
        .iter()
        .filter(|(_, g)| g.len() >= g[0].member_threshold as usize)
        .collect();
    let gt = first.group_threshold as usize;
    if ready.len() < gt {
        out.message = if first.group_count == 1 {
            crate::tr!(
                "Доли верные; чтобы собрать кошелёк, нужно {need} из {all}, есть {have}",
                need = first.member_threshold,
                all = first.member_threshold.max(shares.len() as u8),
                have = shares.len()
            )
        } else {
            crate::tr!(
                "Доли верные; нужно групп: {gt} из {all}, собрано: {have}",
                gt = gt,
                all = first.group_count,
                have = ready.len()
            )
        };
        return (out, None);
    }
    let mut group_secrets: Vec<(u8, Vec<u8>)> = vec![];
    for (gi, g) in ready.into_iter().take(gt) {
        let mt = g[0].member_threshold;
        let members: Vec<(u8, &[u8])> = g
            .iter()
            .take(mt as usize)
            .map(|s| (s.member_index, s.value.as_slice()))
            .collect();
        match recover_secret(mt, &members) {
            Ok(v) => group_secrets.push((*gi, v)),
            Err(e) => {
                out.valid = false;
                out.message = e;
                return (out, None);
            }
        }
    }
    let gs: Vec<(u8, &[u8])> = group_secrets
        .iter()
        .map(|(i, v)| (*i, v.as_slice()))
        .collect();
    match recover_secret(first.group_threshold, &gs) {
        Ok(ems) => {
            out.complete = true;
            out.message = if shares.len() == 1 {
                crate::tr!("Контрольная сумма верна (без разделения на доли)").into()
            } else {
                crate::tr!("Доли верные и сходятся в один кошелёк").into()
            };
            let params = (first.id, first.ext, first.exp);
            (out, Some((ems, params.0, params.1, params.2)))
        }
        Err(e) => {
            out.valid = false;
            out.message = e;
            (out, None)
        }
    }
}

fn check_slip39(lines: &[&str]) -> SeedCheck {
    slip39_inner(lines).0
}

/// Зашифрованный общий секрет SLIP-39 (идентификатор, extendable, показатель итераций):
/// для расшифровки с passphrase при выводе адресов.
pub fn slip39_encrypted_master(lines: &[&str]) -> Result<(Vec<u8>, u16, bool, u8), String> {
    match slip39_inner(lines) {
        (_, Some(v)) => Ok(v),
        (c, None) => Err(c.message),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        address_networks, check_seed, generate_bip39, parse_addresses, private_key_format, seedqr,
        suggest,
    };

    #[test]
    fn bip39_valid_invalid_and_typo() {
        let ok = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let c = check_seed(ok);
        assert!(c.valid && c.complete && c.format == "bip39", "{c:?}");
        let bad_sum = ok.replace("about", "abandon");
        assert!(!check_seed(&bad_sum).valid);
        let typo = ok.replace("about", "abuot");
        let c = check_seed(&typo);
        assert_eq!(c.bad_words, vec![11]);
        assert!(c.message.contains("12"));
        assert_eq!(suggest("abo", 3), vec!["about", "above"]);
    }

    #[test]
    fn electrum_segwit_vector() {
        // tests/test_mnemonic.py из Electrum: SEED_PREFIX_SW
        let c = check_seed(
            "wild father tree among universe such mobile favorite target dynamic credit identify",
        );
        assert_eq!((c.format.as_str(), c.valid), ("electrum", true), "{c:?}");
        assert!(c.label.contains("segwit"));
    }

    #[test]
    fn generated_bip39_is_valid_and_seedqr_sizes() {
        for n in [12, 24] {
            let s = generate_bip39(n).unwrap();
            assert_eq!(s.expose().split_whitespace().count(), n);
            assert!(check_seed(s.expose()).valid);
        }
        // размеры SeedQR по спецификации SeedSigner
        let p12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert_eq!(seedqr(p12, false).unwrap().0, 25);
        assert_eq!(seedqr(p12, true).unwrap().0, 21);
        let p24 = generate_bip39(24).unwrap();
        assert_eq!(seedqr(p24.expose(), false).unwrap().0, 29);
        assert_eq!(seedqr(p24.expose(), true).unwrap().0, 25);
    }

    #[test]
    fn slip39_official_vectors() {
        let v: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/slip39_vectors.json")).unwrap();
        for case in v {
            let name = case[0].as_str().unwrap();
            let shares: Vec<&str> = case[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap())
                .collect();
            let expect_ok = !case[2].as_str().unwrap().is_empty();
            let c = check_seed(&shares.join("\n"));
            assert_eq!(c.format, "slip39", "{name}");
            assert_eq!(c.valid && c.complete, expect_ok, "{name}: {c:?}");
        }
    }

    #[test]
    fn keys_and_addresses() {
        assert!(
            private_key_format(
                "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
            )
            .unwrap()
            .contains("hex")
        );
        // WIF из BIP-0178 / bitcoin wiki
        assert_eq!(
            private_key_format("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ").unwrap(),
            "WIF, Bitcoin"
        );
        assert_eq!(
            address_networks("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"),
            vec!["btc"]
        );
        assert_eq!(
            address_networks("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"),
            vec!["btc"]
        );
        assert_eq!(
            address_networks("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"),
            vec!["eth", "bnb"]
        );
        assert_eq!(
            address_networks("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
            vec!["tron"]
        );
        assert_eq!(
            address_networks("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L"),
            vec!["doge"]
        );
        assert_eq!(
            address_networks("4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T"),
            vec!["sol"]
        );
        assert_eq!(
            parse_addresses(
                "основной: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe"
            ),
            vec![
                (
                    "основной".to_string(),
                    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()
                ),
                (
                    String::new(),
                    "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe".to_string()
                ),
            ]
        );
    }
}
