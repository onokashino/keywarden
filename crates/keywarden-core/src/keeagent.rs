//! Настройки KeeAgent (вложение `KeeAgent.settings`), как их пишут KeePassXC и плагин KeeAgent.
//! Благодаря этому SSH-ключи из базы работают и в KeePassXC, и в Keywarden.

/// Только то, что нужно агенту; остальные элементы XML при импорте генерируются по умолчанию.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Settings {
    pub allow_use: bool,
    pub add_at_open: bool,
    pub remove_at_close: bool,
    /// спрашивать подтверждение при каждом использовании ключа
    pub confirm: bool,
    pub lifetime: Option<u32>,
    /// ключ лежит во вложении с этим именем (`SelectedType=attachment`)
    pub attachment: Option<String>,
    /// или в файле на диске (`SelectedType=file`)
    pub file: Option<String>,
}

/// XML из вложения: KeePassXC пишет UTF-16 с BOM, KeeAgent и Keywarden пишут UTF-8.
pub fn parse(bytes: &[u8]) -> Option<Settings> {
    let text = decode(bytes)?;
    let tag = |name: &str| -> Option<String> {
        let open = format!("<{name}>");
        let start = text.find(&open)? + open.len();
        let end = text[start..].find(&format!("</{name}>"))? + start;
        Some(text[start..end].trim().to_string())
    };
    let flag = |name: &str| tag(name).is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let selected = tag("SelectedType").unwrap_or_default();
    Some(Settings {
        allow_use: flag("AllowUseOfSshKey"),
        add_at_open: flag("AddAtDatabaseOpen"),
        remove_at_close: flag("RemoveAtDatabaseClose"),
        confirm: flag("UseConfirmConstraintWhenAdding"),
        lifetime: flag("UseLifetimeConstraintWhenAdding")
            .then(|| tag("LifetimeConstraintDuration").and_then(|v| v.parse().ok()))
            .flatten(),
        attachment: (selected == "attachment")
            .then(|| tag("AttachmentName"))
            .flatten()
            .map(unescape),
        file: (selected == "file")
            .then(|| tag("FileName"))
            .flatten()
            .map(unescape),
    })
}

fn decode(bytes: &[u8]) -> Option<String> {
    match bytes {
        [0xFF, 0xFE, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xEF, 0xBB, 0xBF, rest @ ..] => String::from_utf8(rest.to_vec()).ok(),
        // UTF-16LE без BOM: второй байт '<' нулевой
        [b'<', 0, ..] => utf16(bytes, u16::from_le_bytes),
        _ => String::from_utf8(bytes.to_vec()).ok(),
    }
}

fn utf16(bytes: &[u8], f: fn([u8; 2]) -> u16) -> Option<String> {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| f([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn unescape(s: String) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// XML для нового ключа (UTF-8): ключ из вложения, добавлять при открытии базы.
pub fn generate(attachment: &str, confirm: bool) -> Vec<u8> {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<EntrySettings xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <AllowUseOfSshKey>true</AllowUseOfSshKey>
  <AddAtDatabaseOpen>true</AddAtDatabaseOpen>
  <RemoveAtDatabaseClose>true</RemoveAtDatabaseClose>
  <UseConfirmConstraintWhenAdding>{confirm}</UseConfirmConstraintWhenAdding>
  <UseLifetimeConstraintWhenAdding>false</UseLifetimeConstraintWhenAdding>
  <LifetimeConstraintDuration>600</LifetimeConstraintDuration>
  <Location>
    <SelectedType>attachment</SelectedType>
    <AttachmentName>{}</AttachmentName>
    <SaveAttachmentToTempFile>false</SaveAttachmentToTempFile>
  </Location>
</EntrySettings>
"#,
        escape(attachment)
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_roundtrip() {
        let s = parse(&generate("id_ed25519 & co", true)).unwrap();
        assert!(s.allow_use && s.add_at_open && s.confirm);
        assert_eq!(s.attachment.as_deref(), Some("id_ed25519 & co"));
        assert_eq!(s.file, None);
    }

    #[test]
    fn utf16_bom_like_keepassxc() {
        let xml = String::from_utf8(generate("id_rsa", false))
            .unwrap()
            .replace("UTF-8", "UTF-16");
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        let s = parse(&bytes).unwrap();
        assert_eq!(s.attachment.as_deref(), Some("id_rsa"));
        assert!(!s.confirm);
    }

    #[test]
    fn file_location() {
        let xml = r#"<EntrySettings><AllowUseOfSshKey>true</AllowUseOfSshKey><Location><SelectedType>file</SelectedType><FileName>/home/u/.ssh/id</FileName></Location></EntrySettings>"#;
        let s = parse(xml.as_bytes()).unwrap();
        assert_eq!(s.file.as_deref(), Some("/home/u/.ssh/id"));
        assert!(!s.add_at_open);
    }
}
