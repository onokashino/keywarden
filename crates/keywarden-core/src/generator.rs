//! Генератор паролей и парольных фраз (словарь EFF large, 7776 слов, CC-BY 3.0).

use crate::secret::Secret;
use serde::{Deserialize, Serialize};

const WORDLIST: &str = include_str!("../data/eff_large_wordlist.txt");
const AMBIGUOUS: &str = "Il1O0o|`'\"";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?~";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    /// добавить цифру к случайному слову (для сайтов, которые требуют цифру)
    pub number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            number: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Generate {
    Password(PasswordOptions),
    Passphrase(PassphraseOptions),
}

impl Default for Generate {
    fn default() -> Self {
        Self::Password(PasswordOptions::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generated {
    pub value: Secret,
    pub entropy_bits: f64,
}

pub fn generate(g: &Generate) -> Generated {
    match g {
        Generate::Password(o) => password(o),
        Generate::Passphrase(o) => passphrase(o),
    }
}

pub fn password(o: &PasswordOptions) -> Generated {
    let keep = |set: &str| -> Vec<char> {
        set.chars()
            .filter(|c| !o.exclude_ambiguous || !AMBIGUOUS.contains(*c))
            .collect()
    };
    let mut classes: Vec<Vec<char>> = Vec::new();
    if o.lower {
        classes.push(keep("abcdefghijklmnopqrstuvwxyz"));
    }
    if o.upper {
        classes.push(keep("ABCDEFGHIJKLMNOPQRSTUVWXYZ"));
    }
    if o.digits {
        classes.push(keep("0123456789"));
    }
    if o.symbols {
        classes.push(keep(SYMBOLS));
    }
    if classes.is_empty() {
        classes.push(keep("abcdefghijklmnopqrstuvwxyz"));
    }
    let all: Vec<char> = classes.concat();
    let len = o.length.clamp(classes.len().max(4), 256);

    // по символу из каждого выбранного класса, остальное из общего набора, потом перемешать
    let mut chars: Vec<char> = classes.iter().map(|c| c[pick(c.len())]).collect();
    chars.extend((chars.len()..len).map(|_| all[pick(all.len())]));
    shuffle(&mut chars);
    Generated {
        value: Secret::new(chars.into_iter().collect::<String>()),
        entropy_bits: len as f64 * (all.len() as f64).log2(),
    }
}

pub fn passphrase(o: &PassphraseOptions) -> Generated {
    let words: Vec<&str> = WORDLIST
        .lines()
        .filter_map(|l| l.split('\t').nth(1))
        .collect();
    let n = o.words.clamp(3, 20);
    let mut chosen: Vec<String> = (0..n)
        .map(|_| {
            let w = words[pick(words.len())];
            if o.capitalize {
                let mut c = w.chars();
                c.next()
                    .map(|f| f.to_uppercase().chain(c).collect())
                    .unwrap_or_default()
            } else {
                w.to_string()
            }
        })
        .collect();
    let mut bits = n as f64 * (words.len() as f64).log2();
    if o.number {
        let i = pick(n);
        chosen[i].push_str(&pick(10).to_string());
        bits += 10f64.log2() + (n as f64).log2();
    }
    Generated {
        value: Secret::new(chosen.join(&o.separator)),
        entropy_bits: bits,
    }
}

/// Равномерное число в 0..n из ОС-генератора (без смещения по модулю).
fn pick(n: usize) -> usize {
    rand::random_range(0..n)
}

fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        v.swap(i, pick(i + 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_has_every_class() {
        for _ in 0..200 {
            let p = password(&PasswordOptions {
                length: 8,
                ..Default::default()
            });
            let s = p.value.expose();
            assert_eq!(s.chars().count(), 8);
            assert!(s.chars().any(|c| c.is_ascii_lowercase()));
            assert!(s.chars().any(|c| c.is_ascii_uppercase()));
            assert!(s.chars().any(|c| c.is_ascii_digit()));
            assert!(s.chars().any(|c| SYMBOLS.contains(c)));
            assert!(!s.chars().any(|c| AMBIGUOUS.contains(c)));
        }
        let digits = password(&PasswordOptions {
            length: 6,
            lower: false,
            upper: false,
            symbols: false,
            ..Default::default()
        });
        assert!(digits.value.expose().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn passphrase_shape() {
        assert_eq!(WORDLIST.lines().count(), 7776);
        let p = passphrase(&PassphraseOptions {
            words: 5,
            separator: " ".into(),
            capitalize: true,
            number: true,
        });
        let words: Vec<_> = p.value.expose().split(' ').collect();
        assert_eq!(words.len(), 5);
        assert!(
            words
                .iter()
                .all(|w| w.chars().next().unwrap().is_uppercase())
        );
        assert!(p.value.expose().chars().any(|c| c.is_ascii_digit()));
        assert!(p.entropy_bits > 64.0);
    }
}
