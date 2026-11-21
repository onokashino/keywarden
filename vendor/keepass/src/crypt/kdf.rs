use std::convert::TryInto;

use aes::Aes256;
use cipher::{BlockCipherEncrypt, KeyInit};
use hybrid_array::{typenum::U32, Array as GenericArray};
use sha2::{Digest, Sha256};

use super::CryptographyError;

pub(crate) trait Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError>;
}

/// Keywarden: the last derived key, see KEYWARDEN-PATCH.md. A save derives the key for the
/// new seed and then the written bytes are parsed back to verify them: same password, same
/// seed, same parameters. Without this the slow derivation ran twice per save.
static LAST: std::sync::Mutex<Option<([u8; 32], [u8; 32])>> = std::sync::Mutex::new(None);

/// Fingerprint of everything the derived key depends on.
fn fingerprint(composite_key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(composite_key);
    for p in parts {
        d.update((p.len() as u64).to_le_bytes());
        d.update(p);
    }
    d.finalize().into()
}

fn remembered(fp: &[u8; 32]) -> Option<GenericArray<u8, U32>> {
    let g = LAST.lock().unwrap_or_else(|p| p.into_inner());
    g.as_ref().filter(|(k, _)| k == fp).map(|(_, v)| GenericArray::from(*v))
}

fn remember(fp: [u8; 32], key: &GenericArray<u8, U32>) {
    let mut v = [0u8; 32];
    v.copy_from_slice(key.as_slice());
    *LAST.lock().unwrap_or_else(|p| p.into_inner()) = Some((fp, v));
}

/// Wipe the remembered derived key (the vault is being locked).
pub fn forget_derived_key() {
    if let Some((a, b)) = LAST.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
        a.fill(0);
        b.fill(0);
    }
    *LAST.lock().unwrap_or_else(|p| p.into_inner()) = None;
}

pub struct AesKdf {
    pub seed: Vec<u8>,
    pub rounds: u64,
}

impl Kdf for AesKdf {
    #[allow(clippy::indexing_slicing)] // Slicing is safe because composite_key is always 32 bytes
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        let seed_arr = self
            .seed
            .as_slice()
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        let fp = fingerprint(composite_key, &[&self.seed, &self.rounds.to_le_bytes(), b"aes"]);
        if let Some(key) = remembered(&fp) {
            return Ok(key);
        }
        let cipher = Aes256::new(&seed_arr);
        let mut block1: GenericArray<u8, _> = composite_key[..16]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        let mut block2: GenericArray<u8, _> = composite_key[16..]
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        for _ in 0..self.rounds {
            cipher.encrypt_block(&mut block1);
            cipher.encrypt_block(&mut block2);
        }

        let mut digest = Sha256::new();

        digest.update(block1);
        digest.update(block2);

        let key = digest.finalize();
        remember(fp, &key);
        Ok(key)
    }
}

pub struct Argon2Kdf {
    pub memory: u64,
    pub salt: Vec<u8>,
    pub iterations: u64,
    pub parallelism: u32,
    pub version: argon2::Version,
    pub variant: argon2::Variant,
}

impl Kdf for Argon2Kdf {
    fn transform_key(
        &self,
        composite_key: &GenericArray<u8, U32>,
    ) -> Result<GenericArray<u8, U32>, CryptographyError> {
        let fp = fingerprint(
            composite_key,
            &[
                &self.salt,
                &self.memory.to_le_bytes(),
                &self.iterations.to_le_bytes(),
                &self.parallelism.to_le_bytes(),
                &[self.version as u8, self.variant as u8],
            ],
        );
        if let Some(key) = remembered(&fp) {
            return Ok(key);
        }

        // Disable Argon2 multithreading on wasm32 targets to avoid panics on platforms without thread support.
        let thread_mode = if cfg!(target_arch = "wasm32") {
            argon2::ThreadMode::Sequential
        } else {
            argon2::ThreadMode::Parallel
        };

        let config = argon2::Config {
            thread_mode,
            ad: &[],
            hash_length: 32,
            lanes: self.parallelism,
            mem_cost: (self.memory / 1024) as u32,
            secret: &[],
            time_cost: self.iterations as u32,
            variant: self.variant,
            version: self.version,
        };

        let key = argon2::hash_raw(composite_key, &self.salt, &config)?;

        let key: GenericArray<u8, U32> = key
            .as_slice()
            .try_into()
            .map_err(|_| CryptographyError::InvalidLength(cipher::InvalidLength))?;
        remember(fp, &key);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use argon2::{hash_raw, Config, ThreadMode, Variant, Version};
    use hybrid_array::{typenum::U32, Array as GenericArray};

    use super::{Argon2Kdf, Kdf};

    #[test]
    fn argon2_memory_is_interpreted_as_bytes() {
        let composite_key = GenericArray::<u8, U32>::from([7_u8; 32]);
        let salt = vec![9_u8; 32];
        let kdf = Argon2Kdf {
            memory: 64 * 1024,
            salt: salt.clone(),
            iterations: 1,
            parallelism: 1,
            version: Version::Version13,
            variant: Variant::Argon2id,
        };

        let expected = hash_raw(
            &composite_key,
            &salt,
            &Config {
                thread_mode: ThreadMode::Parallel,
                ad: &[],
                hash_length: 32,
                lanes: 1,
                mem_cost: 64,
                secret: &[],
                time_cost: 1,
                variant: Variant::Argon2id,
                version: Version::Version13,
            },
        )
        .expect("argon2 test vector should derive successfully");

        let actual = kdf
            .transform_key(&composite_key)
            .expect("argon2 kdf should derive successfully");

        assert_eq!(actual.as_slice(), expected.as_slice());

        // Keywarden: the second call is answered from memory, another salt is derived anew
        assert_eq!(kdf.transform_key(&composite_key).unwrap().as_slice(), expected.as_slice());
        let other = Argon2Kdf { salt: vec![8_u8; 32], ..kdf };
        assert_ne!(other.transform_key(&composite_key).unwrap().as_slice(), expected.as_slice());
        super::forget_derived_key();
        assert!(super::LAST.lock().unwrap().is_none());
    }
}
