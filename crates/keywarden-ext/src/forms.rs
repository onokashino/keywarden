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
const NOT_USER: &[&str] = &["search", "query", "captcha", "coupon", "promo", "поиск"];

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
}
