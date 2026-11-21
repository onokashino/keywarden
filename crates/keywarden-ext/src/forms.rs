//! Поиск полей входа на странице. Content script собирает описание полей (без значений),
//! здесь решаем, где логин, пароль, новый пароль и код 2FA.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct FieldInfo {
    /// индекс поля в списке content script
    pub index: usize,
    /// номер формы (поля вне <form> получают общий -1)
    pub form: i64,
    #[serde(rename = "type")]
    pub kind: String,
    pub name: String,
    pub id: String,
    pub autocomplete: String,
    pub placeholder: String,
    pub label: String,
    pub visible: bool,
    pub maxlength: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct LoginForm {
    pub form: i64,
    pub username: Option<usize>,
    pub password: Option<usize>,
    /// поля «новый пароль» и «повторите пароль» (регистрация, смена пароля)
    pub new_passwords: Vec<usize>,
    pub otp: Option<usize>,
}

const USER_HINTS: &[&str] = &[
    "user",
    "login",
    "email",
    "e-mail",
    "mail",
    "account",
    "ident",
    "логин",
    "почт",
    "телефон",
    "phone",
];
const PHONE_HINTS: &[&str] = &["phone", "телефон"];
const NEW_HINTS: &[&str] = &[
    "new",
    "confirm",
    "repeat",
    "retype",
    "again",
    "register",
    "signup",
    "sign-up",
    "create",
    "нов",
    "повтор",
];
const OTP_HINTS: &[&str] = &[
    "otp",
    "totp",
    "2fa",
    "mfa",
    "one-time",
    "onetime",
    "verification",
    "verify",
    "auth_code",
    "authcode",
    "security_code",
    "token",
    "код",
];
// поиск, промокоды и контакты «для связи» (ник в мессенджере) это не логин этого сайта
const NOT_USER: &[&str] = &[
    "search",
    "query",
    "captcha",
    "coupon",
    "promo",
    "поиск",
    "telegram",
    "whatsapp",
    "viber",
    "skype",
    "jabber",
    "contact",
    "контакт",
    "для связи",
    "телеграм",
];

impl FieldInfo {
    fn text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.name, self.id, self.placeholder, self.label
        )
        .to_lowercase()
    }
    fn has(&self, hints: &[&str]) -> bool {
        let t = self.text();
        hints.iter().any(|h| t.contains(h))
    }
    fn auto(&self, token: &str) -> bool {
        self.autocomplete
            .to_lowercase()
            .split_whitespace()
            .any(|t| t == token)
    }
    fn is_textual(&self) -> bool {
        matches!(
            self.kind.as_str(),
            "text" | "email" | "tel" | "number" | "" | "search"
        )
    }
    fn is_otp(&self) -> bool {
        if self.auto("one-time-code") {
            return true;
        }
        let short = self.maxlength.is_none_or(|m| (4..=10).contains(&m));
        matches!(self.kind.as_str(), "text" | "tel" | "number" | "")
            && short
            && self.has(OTP_HINTS)
            && !self.has(USER_HINTS)
    }
}

pub fn classify(fields: &[FieldInfo]) -> Vec<LoginForm> {
    let mut forms: Vec<LoginForm> = vec![];
    let mut ids: Vec<i64> = fields
        .iter()
        .filter(|f| f.visible)
        .map(|f| f.form)
        .collect();
    ids.dedup();
    ids.sort();
    ids.dedup();
    for form in ids {
        // невидимые поля не заполняем никогда: это классическая ловушка для автозаполнения
        let fs: Vec<&FieldInfo> = fields
            .iter()
            .filter(|f| f.form == form && f.visible)
            .collect();
        let passwords: Vec<&&FieldInfo> = fs.iter().filter(|f| f.kind == "password").collect();
        let mut out = LoginForm {
            form,
            ..Default::default()
        };

        let is_new = |f: &FieldInfo| f.auto("new-password") || f.has(NEW_HINTS);
        let current: Vec<&&FieldInfo> = passwords
            .iter()
            .copied()
            .filter(|f| f.auto("current-password") || !is_new(f))
            .collect();
        if passwords.len() >= 2 && current.len() == passwords.len() {
            // два «обычных» поля пароля подряд: регистрация (пароль + повтор)
            out.new_passwords = passwords.iter().map(|f| f.index).collect();
        } else {
            out.password = current.first().map(|f| f.index);
            out.new_passwords = passwords
                .iter()
                .filter(|f| Some(f.index) != out.password)
                .map(|f| f.index)
                .collect();
        }

        out.otp = fs
            .iter()
            .find(|f| f.kind != "password" && f.is_otp())
            .map(|f| f.index);

        let anchor = out.password.or(out.new_passwords.first().copied());
        let candidates: Vec<&&FieldInfo> = fs
            .iter()
            .filter(|f| {
                f.is_textual() && !f.is_otp() && !f.has(NOT_USER) && Some(f.index) != out.otp
            })
            .collect();
        out.username = candidates
            .iter()
            .find(|f| f.auto("username") || f.auto("email"))
            // телефон это тоже логин, но только если нет поля почты или имени пользователя:
            // в анкетах перед паролем часто стоит телефон или факс
            .or_else(|| {
                candidates.iter().find(|f| {
                    f.has(USER_HINTS) && !f.has(PHONE_HINTS) && anchor.is_none_or(|a| f.index < a)
                })
            })
            .or_else(|| {
                candidates
                    .iter()
                    .find(|f| f.has(USER_HINTS) && anchor.is_none_or(|a| f.index < a))
            })
            // ближайшее текстовое поле перед паролем
            .or_else(|| anchor.and_then(|a| candidates.iter().rev().find(|f| f.index < a)))
            // форма из двух шагов: на первом только логин
            .or_else(|| {
                (anchor.is_none() && candidates.len() == 1 && candidates[0].has(USER_HINTS))
                    .then(|| &candidates[0])
            })
            .map(|f| f.index);

        if out.username.is_some()
            || out.password.is_some()
            || !out.new_passwords.is_empty()
            || out.otp.is_some()
        {
            forms.push(out);
        }
    }
    forms
}

/// Поле карты или личных данных: `role` назван как токен autocomplete из стандарта HTML
/// (`cc-number`, `given-name`, `postal-code`…).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DataField {
    pub index: usize,
    pub form: i64,
    /// `card` или `identity`
    pub group: &'static str,
    pub role: &'static str,
    /// поле уверенно распознано: значок и меню под полем. Иначе только по явной просьбе
    /// (правая кнопка мыши): одно поле почты это скорее вход, чем анкета
    pub auto: bool,
}

const CARD_ROLES: &[&str] = &[
    "cc-name",
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-csc",
];
const IDENTITY_ROLES: &[&str] = &[
    "name",
    "given-name",
    "additional-name",
    "family-name",
    "email",
    "tel",
    "organization",
    "street-address",
    "address-line1",
    "address-line2",
    "address-level2",
    "postal-code",
    "country",
    "country-name",
];

// порядок важен: первое совпадение побеждает
const CARD_HINTS: &[(&str, &[&str])] = &[
    (
        "cc-csc",
        &[
            "cvc",
            "cvv",
            "csc",
            "cv2",
            "security code",
            "securitycode",
            "код безопасности",
        ],
    ),
    (
        "cc-exp-month",
        &[
            "exp month",
            "expmonth",
            "expirymonth",
            "exp mm",
            "cardmonth",
            "card month",
        ],
    ),
    (
        "cc-exp-year",
        &[
            "exp year",
            "expyear",
            "expiryyear",
            "exp yy",
            "cardyear",
            "card year",
        ],
    ),
    (
        "cc-exp",
        &[
            "expir",
            "exp date",
            "expdate",
            "mm/yy",
            "мм/гг",
            "mm / yy",
            "срок действ",
            "valid thru",
        ],
    ),
    (
        "cc-name",
        &[
            "cardholder",
            "card holder",
            "holder",
            "ccname",
            "cc name",
            "name on card",
            "nameoncard",
            "cardname",
            "card name",
            "владел",
            "имя на карте",
        ],
    ),
    (
        "cc-number",
        &[
            "cardnumber",
            "card number",
            "ccnum",
            "cc num",
            "cardnum",
            "card num",
            "номер карты",
        ],
    ),
];
const IDENTITY_HINTS: &[(&str, &[&str])] = &[
    ("email", &["email", "e mail", "почт"]),
    ("tel", &["phone", "mobile", "tel", "телефон"]),
    (
        "given-name",
        &["first name", "firstname", "fname", "given", "имя"],
    ),
    // раньше фамилии: в «fullname» есть «lname»
    ("name", &["fullname", "full name", "your name", "фио"]),
    ("additional-name", &["middle", "patronym", "отчеств"]),
    (
        "family-name",
        &[
            "last name",
            "lastname",
            "lname",
            "surname",
            "family",
            "фамил",
        ],
    ),
    (
        "organization",
        &[
            "company",
            "organization",
            "organisation",
            "компани",
            "организац",
        ],
    ),
    (
        "postal-code",
        &["zip", "postal", "postcode", "post code", "индекс"],
    ),
    ("address-level2", &["city", "town", "город"]),
    ("country", &["country", "страна"]),
    // вторая строка адреса распознаётся, чтобы в неё не попал тот же адрес: заполнять её нечем
    (
        "address-line2",
        &[
            "address2",
            "address 2",
            "line2",
            "line 2",
            "apartment",
            "suite",
            "квартир",
        ],
    ),
    ("street-address", &["address", "street", "адрес", "улиц"]),
];
// слова, с которыми поле точно не про человека (логин, поиск, название компании как «name»)
const NOT_IDENTITY: &[&str] = &[
    "user",
    "login",
    "search",
    "captcha",
    "coupon",
    "promo",
    "польз",
    "логин",
    "поиск",
];

impl FieldInfo {
    fn role(
        &self,
        roles: &[&'static str],
        hints: &[(&'static str, &[&str])],
    ) -> Option<&'static str> {
        let auto = self.autocomplete.to_lowercase();
        if let Some(r) = roles
            .iter()
            .find(|r| auto.split_whitespace().any(|t| t == **r))
        {
            return Some(r);
        }
        // у поля есть свой autocomplete про другое (current-password, one-time-code…): подсказкам не верим
        if auto
            .split_whitespace()
            .any(|t| !matches!(t, "on" | "off" | "nope" | "false"))
        {
            return None;
        }
        // подсказки записаны через пробел: card_number, card-number и «card number» одно и то же
        let t = self.text().replace(['_', '-'], " ");
        hints
            .iter()
            .find(|(_, h)| h.iter().any(|h| t.contains(h)))
            .map(|(r, _)| *r)
    }
}

/// Поля карты и личных данных на странице. Карта: форма с полем номера карты.
/// Личные данные уверенно (`auto`): форма без пароля, где таких полей не меньше трёх.
pub fn classify_data(fields: &[FieldInfo]) -> Vec<DataField> {
    let mut out = vec![];
    let mut ids: Vec<i64> = fields
        .iter()
        .filter(|f| f.visible)
        .map(|f| f.form)
        .collect();
    ids.sort();
    ids.dedup();
    for form in ids {
        let all: Vec<&FieldInfo> = fields
            .iter()
            .filter(|f| f.form == form && f.visible)
            .collect();
        let fs: Vec<&FieldInfo> = all
            .iter()
            .copied()
            .filter(|f| f.kind != "password" && !f.is_otp())
            .collect();
        let card: Vec<DataField> = all
            .iter()
            .filter(|f| f.is_textual() || matches!(f.kind.as_str(), "select" | "password"))
            .filter_map(|f| {
                f.role(CARD_ROLES, CARD_HINTS)
                    // CVC часто делают полем типа password; остальное в таком поле не карта
                    .filter(|r| f.kind != "password" || *r == "cc-csc")
                    .map(|role| DataField {
                        index: f.index,
                        form,
                        group: "card",
                        role,
                        auto: true,
                    })
            })
            .collect();
        let has_card = card.iter().any(|d| d.role == "cc-number");
        if has_card {
            // в форме карты списки «month» и «year» без слова «срок» это всё равно срок карты
            let known: Vec<usize> = card.iter().map(|d| d.index).collect();
            let has_role = |r: &str| card.iter().any(|d| d.role == r);
            let extra: Vec<DataField> = [
                ("cc-exp-month", ["month", "мес"]),
                ("cc-exp-year", ["year", "год"]),
            ]
            .into_iter()
            .filter(|(role, _)| !has_role(role) && !has_role("cc-exp"))
            .filter_map(|(role, hints)| {
                all.iter()
                    .find(|f| f.kind == "select" && !known.contains(&f.index) && f.has(&hints))
                    .map(|f| DataField {
                        index: f.index,
                        form,
                        group: "card",
                        role,
                        auto: true,
                    })
            })
            .collect();
            out.extend(card);
            out.extend(extra);
        }
        let taken: Vec<usize> = out.iter().map(|d| d.index).collect();
        // поле CVC типа password не делает форму формой входа
        let has_password = all
            .iter()
            .any(|f| f.kind == "password" && !taken.contains(&f.index));
        let identity: Vec<DataField> = fs
            .iter()
            .filter(|f| (f.is_textual() || f.kind == "select") && !taken.contains(&f.index))
            .filter(|f| !f.has(NOT_IDENTITY))
            .filter_map(|f| {
                f.role(IDENTITY_ROLES, IDENTITY_HINTS)
                    .map(|role| DataField {
                        index: f.index,
                        form,
                        group: "identity",
                        role,
                        auto: !has_password,
                    })
            })
            .collect();
        let sure = identity.len() >= 3;
        out.extend(identity.into_iter().map(|d| DataField {
            auto: d.auto && sure,
            ..d
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(index: usize, form: i64, kind: &str, name: &str) -> FieldInfo {
        FieldInfo {
            index,
            form,
            kind: kind.into(),
            name: name.into(),
            visible: true,
            ..Default::default()
        }
    }

    #[test]
    fn plain_login() {
        let r = classify(&[
            f(0, 0, "text", "q-search"),
            f(1, 1, "email", "email"),
            f(2, 1, "password", "pass"),
        ]);
        assert_eq!(
            r,
            vec![LoginForm {
                form: 1,
                username: Some(1),
                password: Some(2),
                ..Default::default()
            }]
        );
    }

    #[test]
    fn hidden_fields_are_ignored() {
        let mut hidden = f(1, 0, "password", "pass");
        hidden.visible = false;
        assert!(
            classify(&[f(0, 0, "text", "user"), hidden])
                .iter()
                .all(|l| l.password.is_none())
        );
    }

    #[test]
    fn registration_and_change() {
        let r = classify(&[
            f(0, 0, "text", "username"),
            f(1, 0, "password", "password"),
            f(2, 0, "password", "password2"),
        ]);
        assert_eq!(r[0].new_passwords, vec![1, 2]);
        assert_eq!(r[0].password, None);
        let mut cur = f(1, 0, "password", "current");
        cur.autocomplete = "current-password".into();
        let r = classify(&[
            cur,
            f(2, 0, "password", "new_password"),
            f(3, 0, "password", "confirm_password"),
        ]);
        assert_eq!(r[0].password, Some(1));
        assert_eq!(r[0].new_passwords, vec![2, 3]);
    }

    #[test]
    fn otp_field() {
        let mut otp = f(0, 0, "text", "code");
        otp.autocomplete = "one-time-code".into();
        let r = classify(&[otp]);
        assert_eq!(r[0].otp, Some(0));
        assert_eq!(r[0].username, None);
        let mut by_name = f(0, 0, "tel", "totp_token");
        by_name.maxlength = Some(6);
        assert_eq!(classify(&[by_name])[0].otp, Some(0));
    }

    #[test]
    fn two_step_login() {
        assert_eq!(
            classify(&[f(0, 0, "email", "identifier")])[0].username,
            Some(0)
        );
        assert!(classify(&[f(0, 0, "text", "comment")]).is_empty());
    }

    fn fa(index: usize, kind: &str, name: &str, auto: &str) -> FieldInfo {
        FieldInfo {
            autocomplete: auto.into(),
            ..f(index, 0, kind, name)
        }
    }
    /// только уверенно распознанные поля
    fn roles(v: &[DataField]) -> Vec<(usize, &str, &str)> {
        v.iter()
            .filter(|d| d.auto)
            .map(|d| (d.index, d.group, d.role))
            .collect()
    }

    #[test]
    fn card_form_by_autocomplete_and_hints() {
        let v = classify_data(&[
            fa(0, "text", "a", "cc-name"),
            fa(1, "tel", "b", "cc-number"),
            fa(2, "text", "c", "cc-exp"),
            fa(3, "password", "d", "cc-csc"),
            fa(4, "text", "e", "cc-csc"),
        ]);
        assert_eq!(
            roles(&v),
            [
                (0, "card", "cc-name"),
                (1, "card", "cc-number"),
                (2, "card", "cc-exp"),
                (3, "card", "cc-csc"),
                (4, "card", "cc-csc")
            ],
            "CVC бывает и полем типа password"
        );
        let v = classify_data(&[
            f(0, 0, "text", "cardnumber"),
            f(1, 0, "select", "exp_month"),
            f(2, 0, "select", "exp_year"),
            f(3, 0, "text", "cvv"),
            f(4, 0, "text", "cardholder"),
        ]);
        assert_eq!(
            roles(&v),
            [
                (0, "card", "cc-number"),
                (1, "card", "cc-exp-month"),
                (2, "card", "cc-exp-year"),
                (3, "card", "cc-csc"),
                (4, "card", "cc-name")
            ]
        );
        // без номера карты это не форма карты
        assert!(classify_data(&[f(0, 0, "text", "cvv"), f(1, 0, "text", "expiry")]).is_empty());
    }

    #[test]
    fn identity_form_needs_three_fields_and_no_password() {
        let addr = [
            f(0, 0, "text", "first_name"),
            f(1, 0, "text", "last_name"),
            f(2, 0, "email", "email"),
            f(3, 0, "tel", "phone"),
            f(4, 0, "text", "city"),
            f(5, 0, "text", "zip"),
            f(6, 0, "text", "search"),
        ];
        assert_eq!(
            roles(&classify_data(&addr)),
            [
                (0, "identity", "given-name"),
                (1, "identity", "family-name"),
                (2, "identity", "email"),
                (3, "identity", "tel"),
                (4, "identity", "address-level2"),
                (5, "identity", "postal-code")
            ]
        );
        // вход: почта и пароль
        assert!(
            roles(&classify_data(&[
                f(0, 0, "email", "email"),
                f(1, 0, "password", "password")
            ]))
            .is_empty()
        );
        // одно поле почты (подписка, первый шаг входа)
        assert!(roles(&classify_data(&[f(0, 0, "email", "email")])).is_empty());
        // регистрация с паролем: меню личных данных не мешает меню логина
        let mut signup = addr.to_vec();
        signup.push(f(7, 0, "password", "password"));
        assert!(roles(&classify_data(&signup)).is_empty());
        assert_eq!(
            classify_data(&signup).len(),
            6,
            "по правой кнопке мыши поля доступны"
        );
        // «имя пользователя» не имя человека
        let v = classify_data(&[
            f(0, 0, "text", "username"),
            f(1, 0, "text", "city"),
            f(2, 0, "text", "zip"),
        ]);
        assert!(roles(&v).is_empty() && v.iter().all(|d| d.index != 0));
    }

    #[test]
    fn checkout_has_both_groups() {
        let v = classify_data(&[
            f(0, 0, "text", "first_name"),
            f(1, 0, "text", "last_name"),
            f(2, 0, "text", "address"),
            f(3, 0, "text", "card_number"),
            f(4, 0, "text", "name_on_card"),
            f(5, 0, "text", "cvc"),
        ]);
        assert_eq!(v.iter().filter(|d| d.group == "card").count(), 3);
        assert_eq!(v.iter().filter(|d| d.group == "identity").count(), 3);
    }

    #[test]
    fn lessons_from_real_pages() {
        // анкета: факс и телефон перед паролем, логином всё равно считается почта
        let forms = classify(&[
            f(0, 0, "text", "faxphone"),
            f(1, 0, "text", "emailadr"),
            f(2, 0, "password", "password"),
        ]);
        assert_eq!(forms[0].username, Some(1));
        // вход по телефону, когда другого поля нет
        let forms = classify(&[f(0, 0, "tel", "phone"), f(1, 0, "password", "password")]);
        assert_eq!(forms[0].username, Some(0));
        // обменник: одно поле «Telegram для связи» с подсказкой @username это контакт, а не вход
        let mut tg = f(0, 0, "text", "");
        tg.placeholder = "@username".into();
        tg.label = "Telegram для связи".into();
        assert!(classify(&[tg]).is_empty());
        // форма оплаты со списками month и year без слова «срок»
        let v = classify_data(&[
            f(0, 0, "text", "card_number"),
            f(1, 0, "select", "month"),
            f(2, 0, "select", "year"),
            f(3, 0, "text", "cvv_code"),
        ]);
        assert_eq!(
            roles(&v),
            [
                (0, "card", "cc-number"),
                (3, "card", "cc-csc"),
                (1, "card", "cc-exp-month"),
                (2, "card", "cc-exp-year")
            ]
        );
        // «fullname» это полное имя, а не фамилия; вторая строка адреса отдельно
        let v = classify_data(&[
            f(0, 0, "text", "fullname"),
            f(1, 0, "text", "address1"),
            f(2, 0, "text", "address2"),
            f(3, 0, "text", "city"),
        ]);
        assert_eq!(
            roles(&v),
            [
                (0, "identity", "name"),
                (1, "identity", "street-address"),
                (2, "identity", "address-line2"),
                (3, "identity", "address-level2")
            ]
        );
    }
}
