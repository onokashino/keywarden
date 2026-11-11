//! Буфер обмена.
//!
//! - Wayland с data-control (niri, Sway, KDE): своя раздача через wl-clipboard-rs; значение
//!   предлагается вместе с `x-kde-passwordManagerHint: secret`, менеджеры истории его не хранят;
//! - остальное (X11, GNOME, macOS, Windows): arboard с пометкой «не в историю» (KDE hint на X11,
//!   ConcealedType на macOS, исключение из истории Win+V и облачного буфера на Windows);
//! - через N секунд буфер очищается, но только если в нём всё ещё наше значение.

use keywarden_core::secret::Secret;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

static GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn copy(value: &Secret, clear_after: Duration) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        match wayland::copy(value, clear_after) {
            Ok(()) => return Ok(()),
            // GNOME: протокола data-control нет, остаётся X11 через XWayland
            Err(e) if std::env::var_os("DISPLAY").is_some() => {
                tracing::debug!("буфер Wayland недоступен ({e}), беру X11");
            }
            Err(e) => return Err(e),
        }
    }
    native::copy(value, clear_after)
}

/// Содержимое буфера: картинка (закодированная или сырая RGBA) либо текст.
pub enum Pasted {
    /// PNG или JPEG как есть (Wayland отдаёт файл картинки)
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Encoded(Vec<u8>),
    Rgba {
        width: u32,
        height: u32,
        bytes: Vec<u8>,
    },
    Text(zeroize::Zeroizing<String>),
}

/// Прочитать буфер: сначала картинку (`want_image`), потом текст.
pub fn paste(want_image: bool) -> Result<Pasted, String> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        match wayland::paste(want_image) {
            Ok(p) => return Ok(p),
            Err(e) if std::env::var_os("DISPLAY").is_some() => {
                tracing::debug!("буфер Wayland недоступен ({e}), беру X11");
            }
            Err(e) => return Err(e),
        }
    }
    let mut cb = arboard::Clipboard::new().map_err(|e| tr!("буфер обмена: {e}", e = e))?;
    if want_image && let Ok(img) = cb.get_image() {
        return Ok(Pasted::Rgba {
            width: img.width as u32,
            height: img.height as u32,
            bytes: img.bytes.into_owned(),
        });
    }
    cb.get_text()
        .map(|t| Pasted::Text(zeroize::Zeroizing::new(t)))
        .map_err(|e| tr!("буфер обмена: {e}", e = e))
}

mod native {
    use super::GENERATION;
    use keywarden_core::secret::Secret;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use zeroize::Zeroizing;

    pub fn copy(value: &Secret, clear_after: Duration) -> Result<(), String> {
        let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        let text = Zeroizing::new(value.expose().to_string());
        let (tx, rx) = std::sync::mpsc::channel();
        let served = text.clone();
        // на X11 значение раздаёт владелец выделения: поток живёт, пока буфер наш
        std::thread::Builder::new()
            .name("clipboard-serve".into())
            .spawn(move || {
                let mut cb = match arboard::Clipboard::new() {
                    Ok(c) => c,
                    Err(e) => return drop(tx.send(Err(e.to_string()))),
                };
                let set = cb.set();
                #[cfg(windows)]
                let set = {
                    use arboard::SetExtWindows;
                    set.exclude_from_history()
                        .exclude_from_cloud()
                        .exclude_from_monitoring()
                };
                #[cfg(target_os = "macos")]
                let set = {
                    use arboard::SetExtApple;
                    set.exclude_from_history()
                };
                #[cfg(target_os = "linux")]
                let set = {
                    use arboard::SetExtLinux;
                    let _ = tx.send(Ok(()));
                    set.exclude_from_history().wait()
                };
                let r = set.text(served.as_str()).map_err(|e| e.to_string());
                let _ = tx.send(r);
            })
            .map_err(|e| e.to_string())?;
        rx.recv_timeout(Duration::from_secs(3))
            .map_err(|_| tr!("буфер обмена не ответил").to_string())??;

        if !clear_after.is_zero() {
            std::thread::spawn(move || {
                std::thread::sleep(clear_after);
                if GENERATION.load(Ordering::SeqCst) != generation {
                    return;
                }
                if let Ok(mut cb) = arboard::Clipboard::new()
                    && cb.get_text().is_ok_and(|t| Zeroizing::new(t) == text)
                {
                    let _ = cb.clear();
                }
            });
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod wayland {
    use super::GENERATION;
    use keywarden_core::secret::Secret;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use wl_clipboard_rs::copy::{ClipboardType, MimeType, Options, Seat, Source, clear};

    pub fn copy(value: &Secret, clear_after: Duration) -> Result<(), String> {
        let generation = GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
        let ours = Arc::new(AtomicBool::new(true));
        // копия байтов внутри wl-clipboard-rs не обнуляется после раздачи; живёт не дольше clear_after
        let bytes: Box<[u8]> = value.expose().as_bytes().into();
        let (tx, rx) = std::sync::mpsc::channel();

        let serving = ours.clone();
        std::thread::Builder::new()
            .name("clipboard-serve".into())
            .spawn(move || {
                let mut opts = Options::new();
                opts.clipboard(ClipboardType::Regular)
                    .foreground(true)
                    .sensitive(true);
                match opts.prepare_copy(Source::Bytes(bytes), MimeType::Text) {
                    Ok(prepared) => {
                        let _ = tx.send(Ok(()));
                        let _ = prepared.serve(); // блокирует, пока выделение наше
                    }
                    Err(e) => {
                        let _ = tx.send(Err(e.to_string()));
                    }
                }
                serving.store(false, Ordering::SeqCst);
            })
            .map_err(|e| e.to_string())?;

        rx.recv_timeout(Duration::from_secs(3))
            .map_err(|_| tr!("буфер обмена не ответил").to_string())??;

        if !clear_after.is_zero() {
            std::thread::spawn(move || {
                std::thread::sleep(clear_after);
                if GENERATION.load(Ordering::SeqCst) == generation && ours.load(Ordering::SeqCst) {
                    let _ = clear(ClipboardType::Regular, Seat::All);
                }
            });
        }
        Ok(())
    }

    pub fn paste(want_image: bool) -> Result<super::Pasted, String> {
        use std::io::Read;
        use wl_clipboard_rs::paste::{
            ClipboardType, MimeType, Seat as PSeat, get_contents, get_mime_types,
        };
        let types = get_mime_types(ClipboardType::Regular, PSeat::Unspecified)
            .map_err(|e| tr!("буфер обмена: {e}", e = e))?;
        let read = |mime: MimeType| -> Result<Vec<u8>, String> {
            let (mut pipe, _) = get_contents(ClipboardType::Regular, PSeat::Unspecified, mime)
                .map_err(|e| tr!("буфер обмена: {e}", e = e))?;
            let mut buf = vec![];
            pipe.read_to_end(&mut buf).map_err(|e| e.to_string())?;
            Ok(buf)
        };
        if want_image
            && let Some(img) = ["image/png", "image/jpeg"]
                .iter()
                .find(|m| types.contains(**m))
        {
            return Ok(super::Pasted::Encoded(read(MimeType::Specific(img))?));
        }
        let text = String::from_utf8(read(MimeType::Text)?)
            .map_err(|_| tr!("в буфере не текст").to_string())?;
        Ok(super::Pasted::Text(zeroize::Zeroizing::new(text)))
    }
}

// на Windows и macOS буфер есть всегда, проверка имеет смысл только для Wayland
#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn fails_cleanly_without_wayland() {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return; // на живом рабочем столе не трогаем буфер пользователя
        }
        let r = super::copy(&"x".into(), std::time::Duration::ZERO);
        assert!(r.is_err());
    }
}
