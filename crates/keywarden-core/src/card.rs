//! Банковская карта: тип по номеру, проверка номера, разбор срока.

/// Типы карт для выбора в редакторе. Имена как пишут сами платёжные системы.
pub const BRANDS: &[&str] = &[
    "Visa",
    "Mastercard",
    "Мир",
    "American Express",
    "UnionPay",
    "Maestro",
    "JCB",
    "Discover",
    "Diners Club",
];

fn digits(number: &str) -> String {
    number.chars().filter(char::is_ascii_digit).collect()
}

/// Тип карты по первым цифрам номера (диапазоны ISO/IEC 7812 платёжных систем).
pub fn brand(number: &str) -> Option<&'static str> {
    let d = digits(number);
    let prefix = |n: usize| d.get(..n).and_then(|p| p.parse::<u32>().ok());
    let (p2, p3, p4) = (prefix(2)?, prefix(3), prefix(4));
    Some(match () {
        _ if p4.is_some_and(|p| (2200..=2204).contains(&p)) => "Мир",
        _ if d.starts_with('4') => "Visa",
        _ if (51..=55).contains(&p2) || p4.is_some_and(|p| (2221..=2720).contains(&p)) => {
            "Mastercard"
        }
        _ if matches!(p2, 34 | 37) => "American Express",
        _ if p4.is_some_and(|p| (3528..=3589).contains(&p)) => "JCB",
        _ if p3.is_some_and(|p| (300..=305).contains(&p)) || matches!(p2, 36 | 38) => "Diners Club",
        _ if p4 == Some(6011) || p3.is_some_and(|p| (644..=649).contains(&p)) || p2 == 65 => {
            "Discover"
        }
        _ if p2 == 62 => "UnionPay",
        _ if matches!(p2, 50 | 56..=58 | 63 | 67) => "Maestro",
        _ => return None,
    })
}

/// Контрольная цифра номера (алгоритм Луна). Короткие и пустые номера не проходят.
pub fn luhn(number: &str) -> bool {
    let d = digits(number);
    if !(12..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d
        .bytes()
        .rev()
        .enumerate()
        .map(|(i, b)| {
            let n = u32::from(b - b'0');
            if i % 2 == 1 {
                if n * 2 > 9 { n * 2 - 9 } else { n * 2 }
            } else {
                n
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// Срок карты «ММ/ГГ», «ММ/ГГГГ», «ММ-ГГ», «ММГГ», «М/ГГ» → (месяц, год четырьмя цифрами).
pub fn parse_expiry(s: &str) -> Option<(u32, u32)> {
    let d = digits(s);
    let (m, y) = match d.len() {
        4 | 6 => d.split_at(2),
        3 | 5 => d.split_at(1),
        _ => return None,
    };
    let month: u32 = m.parse().ok().filter(|m| (1..=12).contains(m))?;
    let year: u32 = y.parse().ok()?;
    Some((month, if y.len() == 2 { 2000 + year } else { year }))
}

/// Срок в общепринятом виде «ММ/ГГ».
pub fn format_expiry(month: u32, year: u32) -> String {
    format!("{month:02}/{:02}", year % 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brands_by_number() {
        for (n, b) in [
            ("4111 1111 1111 1111", "Visa"),
            ("5555 5555 5555 4444", "Mastercard"),
            ("2223 0000 4841 0010", "Mastercard"),
            ("2200 1234 5678 9010", "Мир"),
            ("3782 822463 10005", "American Express"),
            ("6200 0000 0000 0005", "UnionPay"),
            ("3566 0020 2036 0505", "JCB"),
            ("6011 1111 1111 1117", "Discover"),
            ("3056 9309 0259 04", "Diners Club"),
            ("6759 6498 2643 8453", "Maestro"),
        ] {
            assert_eq!(brand(n), Some(b), "{n}");
            assert!(BRANDS.contains(&b));
        }
        assert_eq!(brand(""), None);
        assert_eq!(brand("9"), None);
        assert_eq!(brand("99"), None);
    }

    #[test]
    fn luhn_check() {
        assert!(luhn("4111 1111 1111 1111"));
        assert!(luhn("3782 822463 10005"));
        assert!(!luhn("4111 1111 1111 1112"));
        assert!(!luhn("4111"));
        assert!(!luhn(""));
    }

    #[test]
    fn expiry() {
        assert_eq!(parse_expiry("04/29"), Some((4, 2029)));
        assert_eq!(parse_expiry("7/27"), Some((7, 2027)));
        assert_eq!(parse_expiry("12-2031"), Some((12, 2031)));
        assert_eq!(parse_expiry("0128"), Some((1, 2028)));
        assert_eq!(parse_expiry("13/27"), None);
        assert_eq!(parse_expiry("апрель"), None);
        assert_eq!(format_expiry(4, 2029), "04/29");
    }
}
