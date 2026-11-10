//! Автоввод: узнать активное окно и набрать в нём последовательность записи.
//!
//! - niri: окно из IPC niri, набор через `wtype` (виртуальная клавиатура Wayland);
//! - X11 (и окна XWayland): `xdotool`;
//! - Windows и macOS: активное окно через active-win-pos-rs, набор через enigo (на macOS нужно
//!   разрешение «Универсальный доступ», для заголовка окна ещё «Запись экрана»).
//!
//! Текст передаётся программам через stdin, поэтому пароль не виден в /proc/*/cmdline.
//! Перед набором окно перепроверяется: если фокус ушёл в другое окно, ничего не печатается.

use crate::state::{Daemon, Reply, blocking, model_err};
use keywarden_core::autotype::{self, Action};
use keywarden_core::ipc::{ErrorCode, Response};
use keywarden_core::model;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq)]
pub struct Window {
    pub id: String,
    pub title: String,
}

/// Активное окно на этой системе.
pub fn focused_window() -> Result<Option<Window>, String> {
    backend::focused_window()
}

fn type_actions(actions: &[Action]) -> Result<(), String> {
    backend::type_actions(actions)
}

#[cfg(target_os = "linux")]
mod backend {
    use super::*;

    fn wayland() -> bool {
        std::env::var_os("WAYLAND_DISPLAY").is_some()
    }

    /// Активное окно: niri (IPC) или X11; другие рабочие столы Wayland его не сообщают.
    pub fn focused_window() -> Result<Option<Window>, String> {
        if std::env::var_os("NIRI_SOCKET").is_some() {
            niri::focused_window()
        } else if !wayland() && std::env::var_os("DISPLAY").is_some() {
            x11::focused_window()
        } else {
            Err(tr!(
                "автоввод: этот рабочий стол Wayland не сообщает активное окно; работает в niri и X11"
            )
            .into())
        }
    }

    /// Набор: wtype на Wayland с виртуальной клавиатурой (niri, Sway, Hyprland), xdotool на X11.
    pub fn type_actions(actions: &[Action]) -> Result<(), String> {
        if wayland() {
            niri::type_actions(actions).map_err(|e| {
                if e.contains("virtual keyboard") {
                    tr!(
                        "автоввод: этот рабочий стол Wayland не даёт печатать в чужие окна (нет виртуальной клавиатуры); работает в niri, Sway и X11"
                    )
                    .into()
                } else {
                    e
                }
            })
        } else if std::env::var_os("DISPLAY").is_some() {
            x11::type_actions(actions)
        } else {
            Err(tr!("автоввод: нет графического сеанса").into())
        }
    }
}

#[cfg(target_os = "linux")]
mod niri {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    /// Активное окно niri (`$NIRI_SOCKET`, запрос "FocusedWindow").
    pub(crate) fn focused_window() -> Result<Option<Window>, String> {
        let sock = std::env::var("NIRI_SOCKET")
            .map_err(|_| tr!("автоввод работает в niri: нет NIRI_SOCKET").to_string())?;
        let mut s =
            std::os::unix::net::UnixStream::connect(&sock).map_err(|e| format!("niri: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        s.write_all(b"\"FocusedWindow\"\n")
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        BufReader::new(s)
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        parse_focused(&line)
    }

    pub(crate) fn parse_focused(line: &str) -> Result<Option<Window>, String> {
        let v: serde_json::Value = serde_json::from_str(line).map_err(|e| format!("niri: {e}"))?;
        let w = &v["Ok"]["FocusedWindow"];
        if w.is_null() {
            return Ok(None);
        }
        Ok(Some(Window {
            id: w["id"]
                .as_u64()
                .ok_or(tr!("niri: нет id окна"))?
                .to_string(),
            title: w["title"].as_str().unwrap_or_default().to_string(),
        }))
    }

    fn wtype(args: &[&str], stdin: Option<&str>) -> Result<(), String> {
        let mut cmd = Command::new("wtype");
        // wtype загружает раскладку при каждом запуске; часть программ (GPUI, Zed) применяет её
        // с задержкой и теряет первый символ без паузы
        cmd.args(["-s", "200"])
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| tr!("wtype не запустился ({e}): установите пакет wtype", e = e))?;
        if let Some(text) = stdin
            && let Some(mut pipe) = child.stdin.take()
        {
            pipe.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "wtype: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    pub(crate) fn type_actions(actions: &[Action]) -> Result<(), String> {
        for a in actions {
            match a {
                Action::Text(t) => wtype(&["-"], Some(t))?,
                Action::Key { name, mods } => {
                    let mut args: Vec<&str> = vec![];
                    for m in mods {
                        args.extend(["-M", m]);
                    }
                    args.extend(["-k", name.as_str()]);
                    for m in mods {
                        args.extend(["-m", m]);
                    }
                    wtype(&args, None)?;
                }
                Action::Chord { ch, mods } => {
                    let s = ch.to_string();
                    let mut args: Vec<&str> = vec![];
                    for m in mods {
                        args.extend(["-M", m]);
                    }
                    args.push(&s);
                    for m in mods {
                        args.extend(["-m", m]);
                    }
                    wtype(&args, None)?;
                }
                Action::Delay(ms) => std::thread::sleep(Duration::from_millis(*ms)),
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod x11 {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn xdotool(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let mut child = Command::new("xdotool")
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                tr!(
                    "xdotool не запустился ({e}): установите пакет xdotool",
                    e = e
                )
            })?;
        if let Some(text) = stdin
            && let Some(mut pipe) = child.stdin.take()
        {
            pipe.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        }
        let out = child.wait_with_output().map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "xdotool: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    pub fn focused_window() -> Result<Option<Window>, String> {
        let Ok(id) = xdotool(&["getactivewindow"], None) else {
            return Ok(None);
        };
        let title = xdotool(&["getwindowname", &id], None).unwrap_or_default();
        Ok(Some(Window { id, title }))
    }

    pub fn type_actions(actions: &[Action]) -> Result<(), String> {
        for a in actions {
            match a {
                Action::Text(t) => {
                    xdotool(&["type", "--clearmodifiers", "--file", "-"], Some(t))?;
                }
                Action::Key { name, mods } => {
                    let combo = mods
                        .iter()
                        .copied()
                        .chain([name.as_str()])
                        .collect::<Vec<_>>()
                        .join("+");
                    xdotool(&["key", "--clearmodifiers", &combo], None)?;
                }
                Action::Chord { ch, mods } => {
                    let s = ch.to_string();
                    let combo = mods
                        .iter()
                        .copied()
                        .chain([s.as_str()])
                        .collect::<Vec<_>>()
                        .join("+");
                    xdotool(&["key", "--clearmodifiers", &combo], None)?;
                }
                Action::Delay(ms) => std::thread::sleep(Duration::from_millis(*ms)),
            }
        }
        Ok(())
    }
}

#[cfg(any(windows, target_os = "macos"))]
mod backend {
    use super::*;
    use enigo::{Direction, Enigo, Key, Keyboard, Settings};

    /// Окно на переднем плане.
    #[cfg(windows)]
    pub fn focused_window() -> Result<Option<Window>, String> {
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowTextW};
        unsafe {
            let h = GetForegroundWindow();
            if h.is_null() {
                return Ok(None);
            }
            let mut buf = [0u16; 512];
            let n = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
            Ok(Some(Window {
                id: format!("{}", h as usize),
                title: String::from_utf16_lossy(&buf[..n]),
            }))
        }
    }

    /// Окно на переднем плане: первое обычное окно (слой 0) в списке экранных окон по порядку.
    /// Без разрешения «Запись экрана» macOS отдаёт пустое имя окна, тогда берём имя программы.
    #[cfg(target_os = "macos")]
    pub fn focused_window() -> Result<Option<Window>, String> {
        use std::ffi::{c_char, c_void};
        type Cf = *const c_void;
        #[link(name = "CoreGraphics", kind = "framework")]
        unsafe extern "C" {
            fn CGWindowListCopyWindowInfo(option: u32, relative_to: u32) -> Cf;
        }
        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            fn CFArrayGetCount(a: Cf) -> isize;
            fn CFArrayGetValueAtIndex(a: Cf, i: isize) -> Cf;
            fn CFDictionaryGetValue(d: Cf, key: Cf) -> Cf;
            fn CFStringCreateWithCString(a: Cf, s: *const c_char, enc: u32) -> Cf;
            fn CFStringGetCString(s: Cf, buf: *mut c_char, len: isize, enc: u32) -> u8;
            fn CFNumberGetValue(n: Cf, kind: isize, out: *mut c_void) -> u8;
            fn CFRelease(p: Cf);
        }
        const UTF8: u32 = 0x0800_0100;
        const SINT64: isize = 4;
        // kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements
        const OPTIONS: u32 = 1 | 16;
        unsafe {
            let key =
                |k: &std::ffi::CStr| CFStringCreateWithCString(std::ptr::null(), k.as_ptr(), UTF8);
            let string = |v: Cf| -> String {
                if v.is_null() {
                    return String::new();
                }
                let mut buf = [0 as c_char; 1024];
                if CFStringGetCString(v, buf.as_mut_ptr(), buf.len() as isize, UTF8) == 0 {
                    return String::new();
                }
                std::ffi::CStr::from_ptr(buf.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            let number = |v: Cf| -> i64 {
                let mut n = 0i64;
                if !v.is_null() {
                    CFNumberGetValue(v, SINT64, (&mut n as *mut i64).cast());
                }
                n
            };
            let list = CGWindowListCopyWindowInfo(OPTIONS, 0);
            if list.is_null() {
                return Ok(None);
            }
            let (k_layer, k_num, k_name, k_owner) = (
                key(c"kCGWindowLayer"),
                key(c"kCGWindowNumber"),
                key(c"kCGWindowName"),
                key(c"kCGWindowOwnerName"),
            );
            let mut found = None;
            for i in 0..CFArrayGetCount(list) {
                let w = CFArrayGetValueAtIndex(list, i);
                if number(CFDictionaryGetValue(w, k_layer)) != 0 {
                    continue;
                }
                let name = string(CFDictionaryGetValue(w, k_name));
                let owner = string(CFDictionaryGetValue(w, k_owner));
                found = Some(Window {
                    id: number(CFDictionaryGetValue(w, k_num)).to_string(),
                    title: if name.is_empty() {
                        owner
                    } else {
                        format!("{name} - {owner}")
                    },
                });
                break;
            }
            for k in [k_layer, k_num, k_name, k_owner, list] {
                CFRelease(k);
            }
            Ok(found)
        }
    }

    fn key(name: &str) -> Result<Key, String> {
        Ok(match name {
            "Tab" => Key::Tab,
            "Return" => Key::Return,
            "space" => Key::Space,
            "BackSpace" => Key::Backspace,
            "Delete" => Key::Delete,
            "Up" => Key::UpArrow,
            "Down" => Key::DownArrow,
            "Left" => Key::LeftArrow,
            "Right" => Key::RightArrow,
            "Home" => Key::Home,
            "End" => Key::End,
            "Prior" => Key::PageUp,
            "Next" => Key::PageDown,
            "Escape" => Key::Escape,
            "F1" => Key::F1,
            "F2" => Key::F2,
            "F3" => Key::F3,
            "F4" => Key::F4,
            "F5" => Key::F5,
            "F6" => Key::F6,
            "F7" => Key::F7,
            "F8" => Key::F8,
            "F9" => Key::F9,
            "F10" => Key::F10,
            "F11" => Key::F11,
            "F12" => Key::F12,
            #[cfg(windows)]
            "Insert" => Key::Insert,
            other => {
                return Err(tr!(
                    "клавиша {other} на этой системе не поддерживается",
                    other = other
                ));
            }
        })
    }

    fn modifier(m: &str) -> Key {
        match m {
            "shift" => Key::Shift,
            "alt" => Key::Alt,
            _ => Key::Control,
        }
    }

    fn with_mods(e: &mut Enigo, mods: &[&'static str], k: Key) -> Result<(), enigo::InputError> {
        for m in mods {
            e.key(modifier(m), Direction::Press)?;
        }
        let r = e.key(k, Direction::Click);
        for m in mods.iter().rev() {
            e.key(modifier(m), Direction::Release)?;
        }
        r
    }

    pub fn type_actions(actions: &[Action]) -> Result<(), String> {
        let mut e = Enigo::new(&Settings::default()).map_err(|e| {
            if cfg!(target_os = "macos") {
                tr!(
                    "автоввод: разрешите Keywarden «Универсальный доступ» в настройках ({e})",
                    e = e
                )
            } else {
                tr!("автоввод: {e}", e = e)
            }
        })?;
        for a in actions {
            let r = match a {
                Action::Text(t) => e.text(t),
                Action::Key { name, mods } => with_mods(&mut e, mods, key(name)?),
                Action::Chord { ch, mods } => with_mods(&mut e, mods, Key::Unicode(*ch)),
                Action::Delay(ms) => {
                    std::thread::sleep(Duration::from_millis(*ms));
                    Ok(())
                }
            };
            r.map_err(|e| tr!("автоввод: {e}", e = e))?;
        }
        Ok(())
    }
}

fn invalid(m: impl Into<String>) -> Response {
    Response::error(ErrorCode::Invalid, m)
}

impl Daemon {
    /// `window`: заголовок окна вместо niri (проверка и тесты), тогда фокус не перепроверяется.
    pub(crate) async fn autotype(
        &self,
        id: Option<String>,
        window: Option<String>,
        sequence: Option<String>,
    ) -> Reply<Response> {
        let target = match &window {
            Some(t) => Window {
                id: String::new(),
                title: t.clone(),
            },
            None => blocking(focused_window)
                .await?
                .ok_or_else(|| invalid(tr!("нет активного окна")))?,
        };
        let title = target.title.clone();
        let candidates = self.read(|db| Ok(autotype::candidates(db, &title)))?;
        let (id, seq) = match id {
            Some(id) => {
                let seq = match candidates.iter().find(|(c, _)| *c == id) {
                    Some((_, s)) => s.clone(),
                    None => self.read(|db| autotype::sequence_for(db, &id).map_err(model_err))?,
                };
                (id, seq)
            }
            None => match candidates.len() {
                0 => {
                    return Err(Response::error(
                        ErrorCode::NotFound,
                        tr!("нет записи для окна «{title}»", title = title),
                    ));
                }
                1 => candidates[0].clone(),
                _ => {
                    let entries = self.read(|db| {
                        candidates
                            .iter()
                            .map(|(id, _)| model::detail(db, id, false).map(|d| d.summary))
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(model_err)
                    })?;
                    return Ok(Response::AutoTypeChoices {
                        window: title,
                        entries,
                    });
                }
            },
        };
        let seq = sequence.unwrap_or(seq);
        let actions = self.read(|db| autotype::compile(db, &id, &seq).map_err(invalid))?;
        self.touch_entry(&id);
        let check = window.is_none().then(|| target.id.clone());
        blocking(move || -> Result<(), String> {
            if let Some(want) = check {
                // лаунчер закрывается, фокус возвращается в окно: ждём до 2 с
                let started = Instant::now();
                loop {
                    match focused_window()? {
                        Some(w) if w.id == want => break,
                        _ if started.elapsed() > Duration::from_secs(2) => {
                            return Err(tr!("фокус ушёл в другое окно: автоввод отменён").into());
                        }
                        _ => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
                // небольшая пауза, чтобы окно успело принять фокус клавиатуры
                std::thread::sleep(Duration::from_millis(120));
            }
            type_actions(&actions)
        })
        .await?;
        tracing::info!("автоввод выполнен");
        Ok(Response::Ok)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn parses_niri_reply() {
        use super::niri::parse_focused;
        let w = parse_focused(r#"{"Ok":{"FocusedWindow":{"id":42,"title":"GitHub - Firefox","app_id":"firefox","pid":1,"workspace_id":1,"is_focused":true}}}"#).unwrap();
        assert_eq!(
            w,
            Some(Window {
                id: "42".into(),
                title: "GitHub - Firefox".into()
            })
        );
        assert_eq!(
            parse_focused(r#"{"Ok":{"FocusedWindow":null}}"#).unwrap(),
            None
        );
        assert!(parse_focused("not json").is_err());
    }
}
