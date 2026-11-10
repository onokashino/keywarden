//! Логика расширения Keywarden на Rust. Компилируется в WASM для браузера и используется
//! демоном как обычная библиотека: правила сопоставления адресов и протокол одни и те же.

pub mod forms;
pub mod protocol;
pub mod urls;

use wasm_bindgen::prelude::*;

pub use urls::url_matches;

/// Можно ли заполнять запись с адресом `entry_url` на странице `page_url`.
#[wasm_bindgen(js_name = urlMatches)]
pub fn url_matches_js(page_url: &str, entry_url: &str) -> bool {
    urls::url_matches(page_url, entry_url)
}

/// Классификация полей страницы: JSON `[FieldInfo]` → JSON `[LoginForm]`.
#[wasm_bindgen(js_name = classifyFields)]
pub fn classify_fields_js(fields_json: &str) -> String {
    let fields: Vec<forms::FieldInfo> = serde_json::from_str(fields_json).unwrap_or_default();
    serde_json::to_string(&forms::classify(&fields)).expect("сериализуется")
}

/// Ключи клиента: `{"public": base64, "secret": base64}`.
#[wasm_bindgen(js_name = generateKeypair)]
pub fn generate_keypair_js() -> String {
    let kp = protocol::Keypair::generate();
    serde_json::json!({ "public": kp.public_b64(), "secret": kp.secret_b64() }).to_string()
}

/// Зашифровать JSON для демона: `{"nonce","message"}` или `{"error"}`.
#[wasm_bindgen]
pub fn seal(plaintext: &str, server_public: &str, client_secret: &str) -> String {
    match protocol::seal(plaintext.as_bytes(), server_public, client_secret) {
        Ok((nonce, message)) => {
            serde_json::json!({ "nonce": nonce, "message": message }).to_string()
        }
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

/// Расшифровать ответ демона; `{"plaintext"}` или `{"error"}`.
#[wasm_bindgen]
pub fn open(nonce: &str, message: &str, server_public: &str, client_secret: &str) -> String {
    match protocol::open(nonce, message, server_public, client_secret) {
        Ok(bytes) => {
            serde_json::json!({ "plaintext": String::from_utf8_lossy(&bytes) }).to_string()
        }
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}
