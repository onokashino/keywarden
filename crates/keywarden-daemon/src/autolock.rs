//! Автоблокировка: простой, блокировка экрана и сон.
//!
//! - Linux: сигналы logind по системной шине; перед сном держим delay-inhibitor, и система ждёт,
//!   пока база заблокируется. Без D-Bus (контейнер, тесты) работает только таймер простоя;
//! - macOS и Windows: опрос раз в 2 с: заблокирован ли экран и не было ли сна (часы ушли вперёд
//!   больше, чем прошло между опросами). После сна база блокируется при пробуждении.

use crate::state::Daemon;
use std::sync::Arc;
use std::time::Duration;

pub async fn idle_watch(d: Arc<Daemon>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        let minutes = d.config().autolock_minutes;
        if minutes == 0 {
            continue;
        }
        if d.idle()
            .is_some_and(|idle| idle >= Duration::from_secs(minutes * 60))
        {
            d.lock("простой").await;
        }
    }
}

pub async fn system_watch(d: Arc<Daemon>) {
    #[cfg(target_os = "linux")]
    if let Err(e) = logind::watch(d).await {
        tracing::warn!("logind недоступен, блокировка при сне и блокировке экрана выключена: {e}");
    }
    #[cfg(not(target_os = "linux"))]
    poll_watch(d).await;
}

#[cfg(not(target_os = "linux"))]
async fn poll_watch(d: Arc<Daemon>) {
    const STEP: Duration = Duration::from_secs(2);
    let mut tick = tokio::time::interval(STEP);
    let mut last = std::time::SystemTime::now();
    let mut was_locked = false;
    loop {
        tick.tick().await;
        let now = std::time::SystemTime::now();
        let gap = now.duration_since(last).unwrap_or_default();
        last = now;
        if gap > STEP + Duration::from_secs(30) && d.config().lock_on_sleep {
            d.lock("сон").await;
        }
        let locked = screen_locked();
        if locked && !was_locked && d.config().lock_on_screen_lock {
            d.lock("блокировка экрана").await;
        }
        was_locked = locked;
    }
}

/// Экран заблокирован: на Windows рабочий стол ввода недоступен (открыт защищённый).
#[cfg(windows)]
fn screen_locked() -> bool {
    use windows_sys::Win32::System::StationsAndDesktops::{
        CloseDesktop, DESKTOP_SWITCHDESKTOP, OpenInputDesktop, SwitchDesktop,
    };
    unsafe {
        let h = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP);
        if h.is_null() {
            return true;
        }
        let locked = SwitchDesktop(h) == 0;
        CloseDesktop(h);
        locked
    }
}

/// Экран заблокирован: ключ CGSSessionScreenIsLocked в словаре текущего сеанса.
#[cfg(target_os = "macos")]
fn screen_locked() -> bool {
    use std::ffi::c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> *const c_void;
    }
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDictionaryGetValue(d: *const c_void, key: *const c_void) -> *const c_void;
        fn CFStringCreateWithCString(a: *const c_void, s: *const i8, enc: u32) -> *const c_void;
        fn CFBooleanGetValue(b: *const c_void) -> u8;
        fn CFRelease(p: *const c_void);
    }
    unsafe {
        let dict = CGSessionCopyCurrentDictionary();
        if dict.is_null() {
            return false;
        }
        // kCFStringEncodingUTF8
        let key = CFStringCreateWithCString(
            std::ptr::null(),
            c"CGSSessionScreenIsLocked".as_ptr(),
            0x0800_0100,
        );
        let v = CFDictionaryGetValue(dict, key);
        let locked = !v.is_null() && CFBooleanGetValue(v) != 0;
        CFRelease(key);
        CFRelease(dict);
        locked
    }
}

#[cfg(target_os = "linux")]
mod logind {
    use crate::state::Daemon;
    use futures_util::StreamExt;
    use std::sync::Arc;
    use zbus::{Connection, Proxy};
    use zbus::{OwnedFd, OwnedObjectPath};

    const LOGIN1: &str = "org.freedesktop.login1";

    pub async fn watch(d: Arc<Daemon>) -> zbus::Result<()> {
        let conn = Connection::system().await?;
        let mgr = Proxy::new(
            &conn,
            LOGIN1,
            "/org/freedesktop/login1",
            "org.freedesktop.login1.Manager",
        )
        .await?;
        let mut sleep = mgr.receive_signal("PrepareForSleep").await?;
        let mut inhibitor = inhibit(&mgr).await;

        // графическая сессия пользователя: демон работает как user unit вне её scope, поэтому через User.Display
        let uid = unsafe { libc::getuid() };
        let user_path: OwnedObjectPath = mgr.call("GetUser", &(uid,)).await?;
        let user = Proxy::new(&conn, LOGIN1, user_path, "org.freedesktop.login1.User").await?;
        let (_, session_path): (String, OwnedObjectPath) = user.get_property("Display").await?;
        let session = Proxy::new(
            &conn,
            LOGIN1,
            session_path,
            "org.freedesktop.login1.Session",
        )
        .await?;
        let mut lock = session.receive_signal("Lock").await?;
        let mut hint = session.receive_property_changed::<bool>("LockedHint").await;
        tracing::info!("подписка на logind: сон, Lock, LockedHint");

        loop {
            tokio::select! {
                Some(msg) = sleep.next() => {
                    let going_to_sleep: bool = msg.body().deserialize()?;
                    if going_to_sleep {
                        if d.config().lock_on_sleep {
                            d.lock("сон").await;
                        }
                        inhibitor = None; // отпускаем: можно засыпать
                    } else {
                        inhibitor = inhibit(&mgr).await;
                    }
                }
                Some(_) = lock.next() => {
                    if d.config().lock_on_screen_lock {
                        d.lock("блокировка экрана").await;
                    }
                }
                Some(change) = hint.next() => {
                    if change.get().await.unwrap_or(false) && d.config().lock_on_screen_lock {
                        d.lock("блокировка экрана").await;
                    }
                }
                else => break,
            }
        }
        drop(inhibitor);
        Ok(())
    }

    async fn inhibit(mgr: &Proxy<'_>) -> Option<OwnedFd> {
        let r: zbus::Result<OwnedFd> = mgr
            .call(
                "Inhibit",
                &(
                    "sleep",
                    "Keywarden",
                    tr!("Заблокировать базу паролей перед сном"),
                    "delay",
                ),
            )
            .await;
        r.map_err(|e| tracing::warn!("delay-inhibitor не получен: {e}"))
            .ok()
    }
}
