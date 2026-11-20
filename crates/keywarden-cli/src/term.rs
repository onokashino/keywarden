//! Вид сообщений kw в терминале: значок результата, цвета темы окна, индикатор ожидания.
//! Всё это только когда stderr это терминал и нет NO_COLOR: скрипты и перенаправления
//! получают прежний простой текст.

use ratatui::style::Color;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";

pub fn fancy() -> bool {
    static F: OnceLock<bool> = OnceLock::new();
    *F.get_or_init(|| {
        std::io::stderr().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").is_ok_and(|t| t != "dumb")
    })
}

/// То же для stdout: таблицы и карточки записей.
pub fn fancy_out() -> bool {
    static F: OnceLock<bool> = OnceLock::new();
    *F.get_or_init(|| {
        std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").is_ok_and(|t| t != "dumb")
    })
}

/// Ширина терминала в знаках; вне терминала считаем 100.
pub fn width() -> usize {
    ratatui::crossterm::terminal::size()
        .map(|(w, _)| w as usize)
        .unwrap_or(100)
}

pub fn bold(s: &str) -> String {
    format!("{BOLD}{s}{RESET}")
}
pub fn dim(s: &str) -> String {
    format!("{}{s}{RESET}", paint(Tone::Muted))
}
pub fn accent(s: &str) -> String {
    format!("{}{s}{RESET}", paint(Tone::Accent))
}
pub fn green(s: &str) -> String {
    format!("{}{s}{RESET}", paint(Tone::Ok))
}
pub fn red(s: &str) -> String {
    format!("{}{s}{RESET}", paint(Tone::Err))
}

enum Tone {
    Accent,
    Ok,
    Err,
    Muted,
}

/// Цвет темы окна (как у kw ssh); у темы без точных цветов обычные цвета терминала.
fn paint(tone: Tone) -> String {
    let [accent, ok, err, muted] = crate::ssh_tui::tones();
    let (color, basic) = match tone {
        Tone::Accent => (accent, "35"),
        Tone::Ok => (ok, "32"),
        Tone::Err => (err, "31"),
        Tone::Muted => (muted, "2"),
    };
    match color {
        Color::Rgb(r, g, b) => format!("\x1b[38;2;{r};{g};{b}m"),
        _ => format!("\x1b[{basic}m"),
    }
}

fn capitalized(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

fn line(tone: Tone, mark: &str, text: &str) {
    eprintln!("{}{mark}{RESET} {}", paint(tone), capitalized(text));
}

/// Действие выполнено.
pub fn ok(text: impl AsRef<str>) {
    if fancy() {
        line(Tone::Ok, "✓", text.as_ref());
    } else {
        eprintln!("{}", text.as_ref());
    }
}

/// Пояснение или следующий шаг: не результат и не ошибка.
pub fn info(text: impl AsRef<str>) {
    if fancy() {
        line(Tone::Accent, "›", text.as_ref());
    } else {
        eprintln!("{}", text.as_ref());
    }
}

/// Итог команды в stdout (его ждут скрипты): в терминале с галочкой.
pub fn done(text: impl AsRef<str>) {
    if fancy_out() {
        println!("{} {}", green("✓"), text.as_ref());
    } else {
        println!("{}", text.as_ref());
    }
}

/// Следующий шаг или пояснение в stdout.
pub fn note(text: impl AsRef<str>) {
    if fancy_out() {
        println!("{} {}", accent("›"), text.as_ref());
    } else {
        println!("{}", text.as_ref());
    }
}

/// То, на что надо обратить внимание, в stdout.
pub fn warn(text: impl AsRef<str>) {
    if fancy_out() {
        println!("{} {}", red("!"), bold(text.as_ref()));
    } else {
        println!("{}", text.as_ref());
    }
}

/// Строка «что: значение…»: скриптам через табуляцию, в терминале колонкой с приглушённой подписью.
pub fn row(cells: &[&str]) {
    if fancy_out() {
        let (head, rest) = cells.split_first().unwrap_or((&"", &[]));
        println!("  {}  {}", dim(&format!("{head:<14}")), rest.join("  "));
    } else {
        println!("{}", cells.join("\t"));
    }
}

pub fn fail(text: &str) {
    if fancy() {
        line(Tone::Err, "✗", text);
    } else {
        eprintln!("kw: {text}");
    }
}

/// Подпись для ввода пароля.
pub fn prompt_label(text: &str) -> String {
    if fancy() {
        format!("{}◆{RESET} {BOLD}{text}{RESET}", paint(Tone::Accent))
    } else {
        text.to_string()
    }
}

/// Индикатор ожидания на строке stderr. Появляется, только если ответ задержался,
/// и стирает себя, когда его отпускают.
pub struct Spinner {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

pub fn spinner(label: &str) -> Option<Spinner> {
    if !fancy() {
        return None;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let (flag, label) = (stop.clone(), label.to_string());
    let (accent, muted) = (paint(Tone::Accent), paint(Tone::Muted));
    let thread = std::thread::spawn(move || {
        const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut err = std::io::stderr();
        let mut drawn = false;
        // быстрые ответы (большинство команд) проходят без мигания
        for tick in 0u64.. {
            if flag.load(Ordering::Relaxed) {
                break;
            }
            if tick >= 2 {
                let frame = FRAMES[(tick as usize) % FRAMES.len()];
                let secs = tick * 80 / 1000;
                let time = if secs >= 3 {
                    format!(" {muted}{secs} с{RESET}")
                } else {
                    String::new()
                };
                let _ = write!(err, "\r{accent}{frame}{RESET} {label}{time}\x1b[K");
                let _ = err.flush();
                drawn = true;
            }
            std::thread::sleep(Duration::from_millis(80));
        }
        if drawn {
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    });
    Some(Spinner {
        stop,
        thread: Some(thread),
    })
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn first_letter_only() {
        assert_eq!(super::capitalized("база открыта"), "База открыта");
        assert_eq!(super::capitalized("«x» удалено"), "«x» удалено");
        assert_eq!(super::capitalized(""), "");
    }
}
