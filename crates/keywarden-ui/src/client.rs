//! Связь с keywardend из UI: блокирующий IPC уходит в фоновый пул, результат возвращается
//! в поток интерфейса. UI ничего не хранит: секреты приходят по запросу и живут в окне.

use gpui_kit::{AppContext as _, Context, Task};
use keywarden_core::ipc::{self, Client, ErrorCode, Event, Request, Response};
use keywarden_core::tr;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum CallError {
    Locked,
    WrongKey(String),
    Daemon(String),
    Unavailable(String),
}

impl CallError {
    pub fn message(&self) -> String {
        match self {
            Self::Locked => tr!("База заблокирована").into(),
            Self::WrongKey(m) | Self::Daemon(m) => m.clone(),
            Self::Unavailable(m) => tr!("keywardend недоступен: {m}", m = m),
        }
    }
}

pub type CallResult = Result<Response, CallError>;

pub fn blocking(req: &Request) -> CallResult {
    classify(ipc::call(req))
}

/// Запрос к демону другой базы (лаунчер ищет по всем открытым).
pub fn blocking_on(profile: Option<&str>, req: &Request) -> CallResult {
    classify(Client::connect_to(profile).and_then(|mut c| c.call(req)))
}

/// Запустить демон базы: в Linux через systemd (keywardend@ИМЯ), иначе напрямую рядом с окном;
/// ждёт ответа до 3 с.
pub fn start_daemon(profile: &str) -> Result<(), String> {
    if Client::connect_to(Some(profile)).is_ok() {
        return Ok(());
    }
    let via_systemd = cfg!(target_os = "linux")
        && std::process::Command::new("systemctl")
            .args(["--user", "start", &format!("keywardend@{profile}.service")])
            .status()
            .is_ok_and(|s| s.success());
    if !via_systemd {
        let name = format!("keywardend{}", std::env::consts::EXE_SUFFIX);
        let bin = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(&name)))
            .filter(|p| p.exists())
            .unwrap_or_else(|| name.into());
        let mut cmd = std::process::Command::new(bin);
        cmd.args(["--profile", profile])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            // без окна консоли
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000);
        }
        cmd.spawn()
            .map_err(|e| tr!("keywardend не запустился: {e}", e = e))?;
    }
    for _ in 0..30 {
        if Client::connect_to(Some(profile)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(tr!("демон базы не ответил").into())
}

fn classify(r: std::io::Result<Response>) -> CallResult {
    match r {
        Ok(Response::Error {
            code: ErrorCode::Locked,
            ..
        }) => Err(CallError::Locked),
        Ok(Response::Error {
            code: ErrorCode::WrongKey,
            message,
        }) => Err(CallError::WrongKey(message)),
        Ok(Response::Error { message, .. }) => Err(CallError::Daemon(message)),
        Ok(r) => Ok(r),
        Err(e) => Err(CallError::Unavailable(e.to_string())),
    }
}

/// Запрос к демону; `done` вызывается в потоке UI с доступом к view.
pub fn call<T: 'static>(
    cx: &mut Context<T>,
    req: Request,
    done: impl FnOnce(&mut T, CallResult, &mut Context<T>) + 'static,
) -> Task<()> {
    cx.spawn(async move |this, cx| {
        let res = cx.background_spawn(async move { blocking(&req) }).await;
        let _ = this.update(cx, |view, cx| done(view, res, cx));
    })
}

/// Запрос к демону базы `profile` (None: текущая); `done` в потоке UI.
pub fn call_on<T: 'static>(
    cx: &mut Context<T>,
    profile: Option<String>,
    req: Request,
    done: impl FnOnce(&mut T, CallResult, &mut Context<T>) + 'static,
) -> Task<()> {
    cx.spawn(async move |this, cx| {
        let res = cx
            .background_spawn(async move {
                match profile {
                    Some(p) => blocking_on(Some(&p), &req),
                    None => blocking(&req),
                }
            })
            .await;
        let _ = this.update(cx, |view, cx| done(view, res, cx));
    })
}

/// Поток событий демона (блокировка, правки, слияние). Переподключается сам.
pub fn subscribe<T: 'static>(
    cx: &mut Context<T>,
    on: impl Fn(&mut T, Event, &mut Context<T>) + 'static,
) -> Task<()> {
    cx.spawn(async move |this, cx| {
        loop {
            let conn = cx
                .background_spawn(async {
                    let mut c = Client::connect()?;
                    c.call(&Request::Subscribe)?;
                    c.set_read_timeout(None)?;
                    Ok::<_, std::io::Error>(c)
                })
                .await;
            if let Ok(mut client) = conn {
                loop {
                    let (c, r) = cx
                        .background_spawn(async move {
                            let r = client.read();
                            (client, r)
                        })
                        .await;
                    client = c;
                    match r {
                        Ok(Response::Event(e)) => {
                            if this.update(cx, |v, cx| on(v, e, cx)).is_err() {
                                return; // окно закрыто
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
            cx.background_executor().timer(Duration::from_secs(2)).await;
        }
    })
}

/// То же, что `call`, но с доступом к окну (фокус, значения полей ввода).
pub fn call_in<T: 'static>(
    window: &mut gpui_kit::Window,
    cx: &mut Context<T>,
    req: Request,
    done: impl FnOnce(&mut T, CallResult, &mut gpui_kit::Window, &mut Context<T>) + 'static,
) -> Task<()> {
    cx.spawn_in(window, async move |this, cx| {
        let res = cx.background_spawn(async move { blocking(&req) }).await;
        let _ = this.update_in(cx, |view, window, cx| done(view, res, window, cx));
    })
}
