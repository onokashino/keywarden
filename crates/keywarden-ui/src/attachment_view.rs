//! Просмотр вложения по типу файла: код и конфиги с подсветкой (syntect, по расширению), Markdown
//! с переключением «вид / текст», картинки, шестнадцатеричный дамп для остального. Всё из памяти:
//! содержимое не пишется во временные файлы. Копирование идёт через демон (буфер с пометкой
//! «секрет» и автоочисткой), как у паролей.

use crate::client;
use crate::ui::segmented;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Editor, EditorState};
use gpui_kit::component::text::TextView;
use gpui_kit::component::{ActiveTheme as _, Icon, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use gpui_kit_assets::IconName;
use keywarden_core::ipc::Request;
use keywarden_core::secret::Secret;
use keywarden_core::tr;
use std::rc::Rc;
use std::sync::Arc;

/// «Сохранить на диск» из окна просмотра (делает главное окно).
pub type SaveFn = Rc<dyn Fn(&mut Window, &mut App)>;

/// Больше этого не показываем: только «Сохранить на диск».
pub const MAX_PREVIEW: usize = 10 * 1024 * 1024;
const HEX_BYTES: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Image(ImageFormat),
    /// текст и язык подсветки (расширение или имя, понятное syntect; пусто: без подсветки)
    Code {
        language: String,
    },
    Markdown,
    /// страницы рисует pdftoppm (poppler)
    Pdf,
    Binary,
    TooLarge,
}

/// Сколько страниц PDF показываем.
const PDF_PAGES: usize = 20;

/// Страницы PDF в PNG через pdftoppm (poppler): PDF идёт через stdin, страницы пишутся в личный
/// каталог демона (в Linux tmpfs, только память) и удаляются сразу после чтения.
fn render_pdf(data: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    use std::io::Write as _;
    let base = keywarden_core::platform::runtime_base();
    let dir = base.join(format!(
        "keywarden-pdf-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    keywarden_core::platform::create_private_dir(&dir).map_err(|e| e.to_string())?;
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let mut child = std::process::Command::new("pdftoppm")
        .args([
            "-png",
            "-r",
            "110",
            "-f",
            "1",
            "-l",
            &PDF_PAGES.to_string(),
            "-",
        ])
        .arg(dir.join("page"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| tr!("для просмотра PDF нужен pdftoppm (пакет poppler)").to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(data);
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "png"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(tr!(
            "PDF не открылся: {e}",
            e = String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    files
        .into_iter()
        .map(|f| std::fs::read(f).map_err(|e| e.to_string()))
        .collect()
}

/// Тип по содержимому и имени. Картинки узнаются по сигнатуре, текст по валидному UTF-8.
pub fn detect(name: &str, data: &[u8]) -> Kind {
    if data.len() > MAX_PREVIEW {
        return Kind::TooLarge;
    }
    let lower = name.to_lowercase();
    let ext = lower
        .rsplit_once('.')
        .map(|(_, e)| e.to_string())
        .unwrap_or_default();
    let image = match data {
        [0x89, b'P', b'N', b'G', ..] => Some(ImageFormat::Png),
        [0xFF, 0xD8, 0xFF, ..] => Some(ImageFormat::Jpeg),
        [b'G', b'I', b'F', b'8', ..] => Some(ImageFormat::Gif),
        [
            b'R',
            b'I',
            b'F',
            b'F',
            _,
            _,
            _,
            _,
            b'W',
            b'E',
            b'B',
            b'P',
            ..,
        ] => Some(ImageFormat::Webp),
        _ if ext == "svg" => Some(ImageFormat::Svg),
        _ => None,
    };
    if let Some(f) = image {
        return Kind::Image(f);
    }
    if data.starts_with(b"%PDF") {
        return Kind::Pdf;
    }
    let head = &data[..data.len().min(8192)];
    if head.contains(&0) || std::str::from_utf8(data).is_err() {
        return Kind::Binary;
    }
    if matches!(ext.as_str(), "md" | "markdown") {
        return Kind::Markdown;
    }
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    let language = match (base, ext.as_str()) {
        ("dockerfile", _) => "Dockerfile",
        ("makefile", _) => "Makefile",
        (_, "env") | (".env", _) => "sh",
        (_, "conf" | "cfg" | "properties" | "desktop" | "service") => "ini",
        (_, "kdbx-xml" | "settings" | "plist" | "svg" | "xml") => "xml",
        (_, "yml") => "yaml",
        (_, "jsonc" | "json5") => "json",
        // ключи, сертификаты и просто текст без подсветки
        (_, "txt" | "pem" | "key" | "pub" | "crt" | "cer" | "csr" | "asc" | "log") => "",
        (_, e) => e,
    };
    Kind::Code {
        language: language.to_string(),
    }
}

/// Иконка в списке вложений по расширению (содержимое там ещё не загружено).
pub fn icon_for_name(name: &str) -> IconName {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "svg" => IconName::Image,
        "pdf" => IconName::FileText,
        "" | "zip" | "gz" | "7z" | "bin" | "kdbx" => IconName::File,
        _ => IconName::FileCode,
    }
}

fn human(n: usize) -> String {
    match n {
        n if n >= 1 << 20 => tr!("{n} МБ", n = format!("{:.1}", n as f64 / (1 << 20) as f64)),
        n if n >= 1 << 10 => tr!("{n} КБ", n = format!("{:.1}", n as f64 / 1024.)),
        n => tr!("{n} Б", n = n),
    }
}

fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data[..data.len().min(HEX_BYTES)].chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{:08x}  {:<48}  {ascii}\n", i * 16, hex.join(" ")));
    }
    if data.len() > HEX_BYTES {
        out.push_str(&tr!("… ещё {size}\n", size = human(data.len() - HEX_BYTES)));
    }
    out
}

pub struct AttachmentView {
    name: String,
    size: usize,
    kind: Kind,
    text: Option<Secret>,
    image: Option<Arc<Image>>,
    editor: Option<Entity<EditorState>>,
    /// страницы PDF; `None` пока рисуются
    pages: Option<Result<Vec<Arc<Image>>, String>>,
    /// Markdown: 0 вид, 1 исходный текст
    md_mode: usize,
    wrap: bool,
    on_save: SaveFn,
    status: Option<SharedString>,
    tasks: Vec<Task<()>>,
}

impl AttachmentView {
    pub fn new(
        name: String,
        data: Vec<u8>,
        on_save: SaveFn,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let size = data.len();
        let kind = detect(&name, &data);
        let mut text = None;
        let mut image = None;
        let mut editor = None;
        match &kind {
            Kind::Image(f) => image = Some(Arc::new(Image::from_bytes(*f, data))),
            Kind::Code { language } => {
                let mut s = String::from_utf8(data).unwrap_or_default();
                // JSON в одну строку разворачиваем: читать удобнее
                if language == "json"
                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(&s)
                    && let Ok(pretty) = serde_json::to_string_pretty(&v)
                {
                    s = pretty;
                }
                editor = Some(code_editor(&s, language, window, cx));
                text = Some(Secret::new(s));
            }
            Kind::Markdown => {
                let s = String::from_utf8(data).unwrap_or_default();
                editor = Some(code_editor(&s, "markdown", window, cx));
                text = Some(Secret::new(s));
            }
            Kind::Binary => {
                editor = Some(code_editor(&hex_dump(&data), "", window, cx));
            }
            Kind::Pdf => {
                let bytes = data.clone();
                cx.spawn(async move |this, cx| {
                    let res = cx
                        .background_spawn(async move { render_pdf(&bytes) })
                        .await
                        .map(|pages| {
                            pages
                                .into_iter()
                                .map(|png| Arc::new(Image::from_bytes(ImageFormat::Png, png)))
                                .collect()
                        });
                    let _ = this.update(cx, |this, cx| {
                        this.pages = Some(res);
                        cx.notify();
                    });
                })
                .detach();
            }
            Kind::TooLarge => {}
        }
        Self {
            name,
            size,
            kind,
            text,
            image,
            editor,
            pages: None,
            md_mode: 0,
            wrap: false,
            on_save,
            status: None,
            tasks: vec![],
        }
    }

    fn copy(&mut self, cx: &mut Context<Self>) {
        let Some(value) = self.text.clone() else {
            return;
        };
        self.tasks.push(client::call(
            cx,
            Request::CopyText { value },
            |this, res, cx| {
                this.status = Some(match res {
                    Ok(_) => tr!("Скопировано, буфер очистится сам").into(),
                    Err(e) => e.message().into(),
                });
                cx.notify();
            },
        ));
    }

    fn toggle_wrap(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.wrap = !self.wrap;
        if let Some(e) = &self.editor {
            let wrap = self.wrap;
            e.update(cx, |s, cx| s.set_soft_wrap(wrap, window, cx));
        }
        cx.notify();
    }

    fn type_label(&self) -> String {
        match &self.kind {
            Kind::Image(f) => tr!(
                "изображение {format}",
                format = format!("{f:?}").to_uppercase()
            ),
            Kind::Code { language } if language.is_empty() => tr!("текст").into(),
            Kind::Code { language } => language.clone(),
            Kind::Markdown => "Markdown".into(),
            Kind::Pdf => match &self.pages {
                Some(Ok(p)) if p.len() >= PDF_PAGES => {
                    tr!("PDF, первые {n} страниц", n = PDF_PAGES)
                }
                Some(Ok(p)) => tr!("PDF, страниц: {n}", n = p.len()),
                _ => "PDF".into(),
            },
            Kind::Binary => tr!("двоичный файл").into(),
            Kind::TooLarge => tr!("слишком большой для просмотра").into(),
        }
    }
}

fn code_editor(
    text: &str,
    language: &str,
    window: &mut Window,
    cx: &mut Context<AttachmentView>,
) -> Entity<EditorState> {
    let lang = if language.is_empty() {
        "text"
    } else {
        language
    }
    .to_string();
    let text = text.to_string();
    cx.new(|cx| {
        EditorState::new(window, cx)
            .language(lang)
            .line_number(true)
            .searchable(true)
            .soft_wrap(false)
            .default_value(text)
    })
}

impl Render for AttachmentView {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let icon = match self.kind {
            Kind::Image(_) => IconName::Image,
            Kind::Pdf => IconName::FileText,
            Kind::Code { .. } | Kind::Markdown => IconName::FileCode,
            _ => IconName::File,
        };
        let is_md = self.kind == Kind::Markdown;
        let show_code = !is_md || self.md_mode == 1;
        let body: AnyElement = match (&self.kind, &self.image, &self.editor) {
            (Kind::Pdf, _, _) => match &self.pages {
                None => v_flex()
                    .size_full()
                    .items_center()
                    .justify_center()
                    .gap_2()
                    .text_color(theme.muted_foreground)
                    .child(gpui_kit::component::spinner::Spinner::new())
                    .child(tr!("Рисую страницы…"))
                    .into_any_element(),
                Some(Err(e)) => v_flex()
                    .size_full()
                    .items_center()
                    .justify_center()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(e.clone())
                    .into_any_element(),
                Some(Ok(pages)) => div()
                    .id("att-pdf")
                    .size_full()
                    .overflow_y_scroll()
                    .bg(theme.list_even)
                    .child(v_flex().items_center().gap_4().p_4().children(
                        pages.iter().enumerate().map(|(i, p)| {
                            v_flex()
                                .items_center()
                                .gap_1()
                                .child(img(p.clone()).w(px(760.)).shadow_md())
                                .child(
                                    div()
                                        .text_xs()
                                        .text_color(theme.muted_foreground)
                                        .child(format!("{}", i + 1)),
                                )
                        }),
                    ))
                    .into_any_element(),
            },
            (Kind::Image(_), Some(img_src), _) => div()
                .id("att-image")
                .size_full()
                .overflow_scroll()
                .flex()
                .items_center()
                .justify_center()
                .bg(theme.list_even)
                .child(img(img_src.clone()).max_w_full().max_h_full())
                .into_any_element(),
            (Kind::Markdown, _, _) if !show_code => div()
                .id("att-md")
                .size_full()
                .overflow_y_scroll()
                .p_6()
                .child(TextView::markdown(
                    "att-md-view",
                    self.text
                        .as_ref()
                        .map(|t| t.expose().to_string())
                        .unwrap_or_default(),
                ))
                .into_any_element(),
            (_, _, Some(e)) => div()
                .size_full()
                .child(Editor::new(e).readonly(true).bordered(false).h_full())
                .into_any_element(),
            _ => v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_2()
                .text_color(theme.muted_foreground)
                .child(Icon::new(IconName::File).large())
                .child(tr!(
                    "Файл {size} слишком большой для просмотра: сохраните его на диск",
                    size = human(self.size)
                ))
                .into_any_element(),
        };
        let save = self.on_save.clone();
        v_flex()
            .w(px(920.))
            .h(px(620.))
            .gap_3()
            .child(
                h_flex()
                    .gap_3()
                    .child(crate::ui::icon_tile(icon, 36., &theme))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .text_base()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .truncate()
                                    .child(self.name.clone()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(theme.muted_foreground)
                                    .child(format!("{} · {}", self.type_label(), human(self.size))),
                            ),
                    )
                    .when(is_md, |d| {
                        d.child(segmented(
                            "md-mode",
                            vec![
                                (Some(IconName::Eye), tr!("Вид").into()),
                                (Some(IconName::FileCode), tr!("Текст").into()),
                            ],
                            self.md_mode,
                            cx,
                            |this, ix, _, cx| {
                                this.md_mode = ix;
                                cx.notify();
                            },
                        ))
                    })
                    .when(self.editor.is_some() && show_code, |d| {
                        d.child(
                            Button::new("wrap")
                                .ghost()
                                .icon(IconName::TextWrap)
                                .tooltip(if self.wrap {
                                    tr!("Без переноса строк")
                                } else {
                                    tr!("Переносить строки")
                                })
                                .on_click(cx.listener(|this, _, w, cx| this.toggle_wrap(w, cx))),
                        )
                    })
                    .when(self.text.is_some(), |d| {
                        d.child(
                            Button::new("copy-att")
                                .outline()
                                .icon(IconName::Copy)
                                .label(tr!("Скопировать"))
                                .on_click(cx.listener(|this, _, _, cx| this.copy(cx))),
                        )
                    })
                    .child(
                        Button::new("save-att-view")
                            .outline()
                            .icon(IconName::Download)
                            .label(tr!("Сохранить"))
                            .on_click(move |_, w, cx| save(w, cx)),
                    ),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .overflow_hidden()
                    .child(body),
            )
            .when_some(self.status.clone(), |d, s| {
                d.child(div().text_xs().text_color(theme.muted_foreground).child(s))
            })
    }
}

#[cfg(test)]
mod tests {
    // не `super::*`: вместе с gpui_kit::* приходит gpui-шный #[test]
    use super::{Kind, detect, hex_dump};
    use gpui_kit::ImageFormat;

    #[test]
    fn detects_by_content_and_name() {
        assert_eq!(
            detect("x.bin", b"\x89PNG\r\n\x1a\n...."),
            Kind::Image(ImageFormat::Png)
        );
        assert_eq!(
            detect("photo.txt", &[0xFF, 0xD8, 0xFF, 0xE0]),
            Kind::Image(ImageFormat::Jpeg),
            "по содержимому, не по имени"
        );
        assert_eq!(
            detect("main.rs", b"fn main() {}"),
            Kind::Code {
                language: "rs".into()
            }
        );
        assert_eq!(
            detect("id_ed25519.pub", b"ssh-ed25519 AAAA"),
            Kind::Code {
                language: String::new()
            }
        );
        assert_eq!(
            detect("KeeAgent.settings", b"<?xml?>"),
            Kind::Code {
                language: "xml".into()
            }
        );
        assert_eq!(detect("README.md", b"# hi"), Kind::Markdown);
        assert_eq!(detect("blob", &[0, 1, 2, 3]), Kind::Binary);
        assert_eq!(detect("scan", b"%PDF-1.7\n"), Kind::Pdf);
        assert_eq!(
            detect("bad.txt", &[0xC3, 0x28]),
            Kind::Binary,
            "невалидный UTF-8"
        );
        assert!(hex_dump(b"AB\x00").starts_with("00000000  41 42 00"));
    }
}
