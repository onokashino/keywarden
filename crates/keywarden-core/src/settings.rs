//! Настройки базы, как «Настройки базы данных» в KeePassXC: имя, описание, корзина, лимиты истории,
//! шифр и параметры Argon2. Всё хранится в самом файле KDBX, поэтому одинаково видно на всех устройствах.

use crate::vault::Cipher;
use keepass::Database;
use keepass::config::{CompressionConfig, KdfConfig, OuterCipherConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbSettings {
    pub name: String,
    pub description: String,
    pub recycle_bin: bool,
    /// сколько версий хранить у записи; -1 без ограничения
    pub history_max_items: i64,
    /// предел истории одной записи в МиБ; -1 без ограничения
    pub history_max_size_mib: i64,
    pub cipher: Cipher,
    /// "argon2id", "argon2d" или "aes" (старые базы KeePass); при правке AES меняется на Argon2id
    pub kdf: String,
    pub kdf_iterations: u64,
    pub kdf_memory_mib: u64,
    pub kdf_parallelism: u32,
    pub compression: bool,
}

pub fn get(db: &Database) -> DbSettings {
    let m = &db.meta;
    let (kdf, kdf_iterations, kdf_memory_mib, kdf_parallelism) = match &db.config.kdf_config {
        KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            ..
        } => ("argon2id", *iterations, memory / MIB, *parallelism),
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            ..
        } => ("argon2d", *iterations, memory / MIB, *parallelism),
        KdfConfig::Aes { rounds } => ("aes", *rounds, 0, 1),
        _ => ("unknown", 0, 0, 1),
    };
    DbSettings {
        name: m.database_name.clone().unwrap_or_default(),
        description: m.database_description.clone().unwrap_or_default(),
        recycle_bin: m.recyclebin_enabled.unwrap_or(true),
        history_max_items: m.history_max_items.map(|v| v as i64).unwrap_or(10),
        history_max_size_mib: m
            .history_max_size
            .map(|v| if v < 0 { -1 } else { v as i64 / MIB as i64 })
            .unwrap_or(6),
        cipher: match db.config.outer_cipher_config {
            OuterCipherConfig::ChaCha20 => Cipher::ChaCha20,
            _ => Cipher::Aes256,
        },
        kdf: kdf.into(),
        kdf_iterations,
        kdf_memory_mib,
        kdf_parallelism,
        compression: !matches!(db.config.compression_config, CompressionConfig::None),
    }
}

const MIB: u64 = 1024 * 1024;

/// Проверить и применить. Ошибка, если параметры сделают базу неоткрываемой на слабых устройствах
/// или бессмысленно слабой.
pub fn apply(db: &mut Database, s: &DbSettings) -> Result<(), String> {
    validate(s)?;
    apply_valid(db, s);
    Ok(())
}

pub fn validate(s: &DbSettings) -> Result<(), String> {
    if s.kdf == "aes" {
        if s.kdf_iterations < 1000 {
            return Err(crate::tr!("AES-KDF: не меньше 1000 раундов").into());
        }
    } else if !(8..=4096).contains(&s.kdf_memory_mib) {
        return Err(crate::tr!("память Argon2: от 8 до 4096 МиБ").into());
    } else if !(1..=1000).contains(&s.kdf_iterations) {
        return Err(crate::tr!("итераций Argon2: от 1 до 1000").into());
    } else if !(1..=16).contains(&s.kdf_parallelism) {
        return Err(crate::tr!("потоков Argon2: от 1 до 16").into());
    }
    if s.history_max_items < -1 || s.history_max_size_mib < -1 {
        return Err(crate::tr!("лимит истории: -1 (без ограничения) или число").into());
    }
    Ok(())
}

fn apply_valid(db: &mut Database, s: &DbSettings) {
    let now = keepass::db::Times::now();
    let m = &mut db.meta;
    if m.database_name.as_deref().unwrap_or_default() != s.name {
        m.database_name = Some(s.name.clone());
        m.database_name_changed = Some(now);
    }
    if m.database_description.as_deref().unwrap_or_default() != s.description {
        m.database_description = Some(s.description.clone());
        m.database_description_changed = Some(now);
    }
    if m.recyclebin_enabled != Some(s.recycle_bin) {
        m.recyclebin_enabled = Some(s.recycle_bin);
        m.recyclebin_changed = Some(now);
    }
    m.history_max_items = Some(s.history_max_items as isize);
    m.history_max_size = Some(if s.history_max_size_mib < 0 {
        -1
    } else {
        (s.history_max_size_mib as u64 * MIB) as isize
    });
    m.settings_changed = Some(now);

    let version = argon2::Version::Version13;
    let (iterations, memory, parallelism) =
        (s.kdf_iterations, s.kdf_memory_mib * MIB, s.kdf_parallelism);
    db.config.kdf_config = if s.kdf == "aes" {
        // старые базы KeePass: функцию ключа не меняем, пока не попросят Argon2
        KdfConfig::Aes {
            rounds: s.kdf_iterations,
        }
    } else if s.kdf == "argon2d" {
        KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            version,
        }
    } else {
        KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            version,
        }
    };
    db.config.outer_cipher_config = match s.cipher {
        Cipher::Aes256 => OuterCipherConfig::AES256,
        Cipher::ChaCha20 => OuterCipherConfig::ChaCha20,
    };
    db.config.compression_config = if s.compression {
        CompressionConfig::GZip
    } else {
        CompressionConfig::None
    };
}

/// Параметры Argon2id под ~1 с на этом компьютере, как при создании базы.
pub fn retuned(mut s: DbSettings) -> DbSettings {
    if let KdfConfig::Argon2id {
        iterations,
        memory,
        parallelism,
        ..
    } = crate::vault::tuned_kdf(std::time::Duration::from_secs(1))
    {
        s.kdf = "argon2id".into();
        s.kdf_iterations = iterations;
        s.kdf_memory_mib = memory / MIB;
        s.kdf_parallelism = parallelism;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_validation() {
        let mut db = Database::new();
        let mut s = get(&db);
        s.name = "Семья".into();
        s.recycle_bin = false;
        s.history_max_items = 3;
        s.kdf = "argon2id".into();
        s.kdf_iterations = 4;
        s.kdf_memory_mib = 64;
        s.kdf_parallelism = 2;
        s.cipher = Cipher::ChaCha20;
        apply(&mut db, &s).unwrap();
        assert_eq!(get(&db), s);

        // AES-KDF старых баз сохраняется как есть
        db.config.kdf_config = KdfConfig::Aes { rounds: 8_000_000 };
        let mut aes = get(&db);
        assert_eq!((aes.kdf.as_str(), aes.kdf_iterations), ("aes", 8_000_000));
        aes.name = "Старая".into();
        apply(&mut db, &aes).unwrap();
        assert!(matches!(
            db.config.kdf_config,
            KdfConfig::Aes { rounds: 8_000_000 }
        ));
        apply(&mut db, &s).unwrap();

        let mut bad = s.clone();
        bad.kdf_memory_mib = 1;
        assert!(apply(&mut db, &bad).is_err());
        assert_eq!(get(&db), s, "неверные параметры ничего не меняют");
    }
}
