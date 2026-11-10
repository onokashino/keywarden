//! keywardend: держит расшифрованную базу в памяти и отвечает клиентам по локальному сокету
//! (UNIX-сокет на Linux и macOS, именованный канал на Windows, см. `local`).

#[macro_use]
extern crate keywarden_core;

mod api;
mod autolock;
mod autotype;
mod browser;
mod clipboard;
mod config;
mod confirm;
mod favicon;
mod health;
mod local;
mod maintenance;
mod otp;
mod prefs;
#[cfg(target_os = "linux")]
mod secret_service;
mod ssh_agent;
mod state;
mod sync;
#[cfg(any(target_os = "linux", windows))]
mod tray;
mod updates;

use anyhow::{Context, Result};
use keywarden_core::ipc::{self, ErrorCode, Request, Response};
use state::Daemon;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Больше строки запроса не бывает (вложения идут в base64; KeePassXC сам ограничивает их размер).
const MAX_LINE: usize = 64 << 20;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();
    harden_process()?;

    // --profile ИМЯ: отдельная база со своим сокетом и конфигом (keywardend@ИМЯ.service)
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--profile") {
        let name = args.get(i + 1).map(String::as_str);
        ipc::set_profile(name).map_err(|e| anyhow::anyhow!(e))?;
        tracing::info!("профиль {}", name.unwrap_or("default"));
    }

    let config_path = config::path();
    let cfg = config::Config::load_from(&config_path)
        .with_context(|| tr!("конфиг {path}", path = config_path.display()))?;
    let daemon = Daemon::new(cfg, config_path);

    let dir = ipc::runtime_dir();
    keywarden_core::platform::create_private_dir(&dir)
        .with_context(|| format!("create {}", dir.display()))?;
    let sock = ipc::daemon_socket();
    let listener =
        local::Listener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
    tracing::info!(socket = %sock.display(), "слушаю");

    tokio::spawn(daemon.clone().saver());
    tokio::spawn(autolock::idle_watch(daemon.clone()));
    tokio::spawn(autolock::system_watch(daemon.clone()));
    tokio::spawn(ssh_agent::serve(daemon.clone()));
    tokio::spawn(sync::watch(daemon.clone()));
    tokio::spawn(prefs::notifier(daemon.clone()));
    tokio::spawn(updates::watch(daemon.clone()));
    tokio::spawn(api::serve(daemon.clone()));
    #[cfg(target_os = "linux")]
    tokio::spawn(secret_service::serve(daemon.clone()));
    #[cfg(any(target_os = "linux", windows))]
    tokio::spawn(tray::run(daemon.clone()));

    let stop = shutdown_signal();
    tokio::pin!(stop);
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let stream = accepted?;
                tokio::spawn(serve(daemon.clone(), stream));
            }
            _ = &mut stop => break,
        }
    }
    // правки должны успеть записаться
    daemon.lock("остановка демона").await;
    drop(listener);
    Ok(())
}

/// Ctrl+C, SIGTERM (systemd, launchd) или закрытие консоли и выход из системы на Windows.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_close, ctrl_logoff, ctrl_shutdown};
        let (mut close, mut logoff, mut shut) = (
            ctrl_close().expect("ctrl_close"),
            ctrl_logoff().expect("ctrl_logoff"),
            ctrl_shutdown().expect("ctrl_shutdown"),
        );
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = close.recv() => {}
            _ = logoff.recv() => {}
            _ = shut.recv() => {}
        }
    }
}

/// Секреты не должны попасть в дамп и в своп.
#[cfg(target_os = "macos")]
fn harden_process() -> Result<()> {
    unsafe {
        // без core dump и без подключения отладчика (PT_DENY_ATTACH = 31)
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        libc::ptrace(31, 0, std::ptr::null_mut(), 0);
    }
    // mlockall на macOS нет: секреты обнуляются zeroize, своп на macOS шифруется системой
    Ok(())
}

/// Секреты не должны попасть в дамп.
#[cfg(windows)]
fn harden_process() -> Result<()> {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SetErrorMode,
    };
    // без окна отчёта об ошибке Windows (WER собирает дамп памяти процесса)
    unsafe { SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) };
    // VirtualLock для всей кучи на Windows не сделать: секреты обнуляются zeroize
    Ok(())
}

/// Секреты не должны попасть в дамп и в своп.
#[cfg(target_os = "linux")]
fn harden_process() -> Result<()> {
    unsafe {
        // без core dump и без ptrace от того же uid
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            anyhow::bail!("prctl(PR_SET_DUMPABLE) failed");
        }
        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);

        // mlockall с MCL_FUTURE при маленьком RLIMIT_MEMLOCK уронил бы Argon2 (256 МиБ) по ENOMEM,
        // поэтому только когда лимит позволяет (в systemd unit стоит LimitMEMLOCK=infinity)
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim);
        if lim.rlim_cur == libc::RLIM_INFINITY || lim.rlim_cur >= 2 << 30 {
            if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT) != 0 {
                tracing::warn!("mlockall не удался: {}", std::io::Error::last_os_error());
            }
        } else {
            tracing::warn!(
                "RLIMIT_MEMLOCK = {} байт, mlockall пропущен; память не попадёт в своп только при MemorySwapMax=0 (есть в keywardend.service)",
                lim.rlim_cur
            );
        }
    }
    Ok(())
}

async fn serve(d: Arc<Daemon>, stream: impl local::Stream) {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut rd = BufReader::new(rd);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut rd).take(MAX_LINE as u64).read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) if !line.ends_with('\n') => {
                let _ = write(
                    &mut wr,
                    &Response::error(ErrorCode::Invalid, tr!("слишком длинный запрос")),
                )
                .await;
                return;
            }
            Ok(_) => {}
        }
        let req = match serde_json::from_str::<Request>(&line) {
            Ok(r) => r,
            Err(e) => {
                // текст ошибки serde не содержит значений, только позицию и тип
                let msg = tr!("неверный запрос: {e}", e = e);
                let _ = write(&mut wr, &Response::error(ErrorCode::Invalid, msg)).await;
                continue;
            }
        };
        line.clear(); // в строке мог быть пароль; String обнулится при выходе, но не держим лишнего
        tracing::debug!(cmd = req.name(), "запрос");
        let subscribe = matches!(req, Request::Subscribe);
        let mut events = d.events.subscribe();
        let resp = d.handle(req).await;
        if write(&mut wr, &resp).await.is_err() {
            return;
        }
        if subscribe {
            while let Ok(ev) = events.recv().await {
                if write(&mut wr, &Response::Event(ev)).await.is_err() {
                    return;
                }
            }
            return;
        }
    }
}

async fn write(
    wr: &mut (impl tokio::io::AsyncWrite + Unpin),
    resp: &Response,
) -> std::io::Result<()> {
    let mut out = serde_json::to_string(resp).expect("Response сериализуется");
    out.push('\n');
    wr.write_all(out.as_bytes()).await
}
