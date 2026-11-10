//! Сервер локальных соединений: UNIX-сокет (Linux, macOS) или именованный канал (Windows).
//! Пускает только процессы того же пользователя: на UNIX проверка uid собеседника
//! (`SO_PEERCRED`, `getpeereid`), на Windows сравнение SID владельца процесса-клиента.

use std::io;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

#[cfg(unix)]
pub use unix::Listener;
#[cfg(windows)]
pub use windows::Listener;

#[cfg(windows)]
pub use windows::same_user_pid;

#[cfg(unix)]
mod unix {
    use super::*;
    use tokio::net::{UnixListener, UnixStream};

    pub struct Listener {
        inner: UnixListener,
        path: PathBuf,
        uid: u32,
    }

    impl Listener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            let _ = std::fs::remove_file(path);
            let inner = UnixListener::bind(path)?;
            keywarden_core::platform::restrict_to_owner(path)?;
            Ok(Self {
                inner,
                path: path.to_path_buf(),
                uid: unsafe { libc::getuid() },
            })
        }

        /// Следующий клиент того же пользователя; чужие закрываются молча (с записью в журнал).
        pub async fn accept(&self) -> io::Result<UnixStream> {
            loop {
                let (s, _) = self.inner.accept().await?;
                match s.peer_cred() {
                    Ok(c) if c.uid() == self.uid => return Ok(s),
                    other => tracing::warn!(?other, "отклонён клиент с чужим uid"),
                }
            }
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::sync::Mutex;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub struct Listener {
        name: PathBuf,
        next: Mutex<NamedPipeServer>,
    }

    impl Listener {
        pub fn bind(path: &Path) -> io::Result<Self> {
            // first_pipe_instance: если канал с этим именем уже создал кто-то другой, не запускаемся
            let first = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create(path)?;
            Ok(Self {
                name: path.to_path_buf(),
                next: Mutex::new(first),
            })
        }

        pub async fn accept(&self) -> io::Result<NamedPipeServer> {
            loop {
                let mut next = self.next.lock().await;
                next.connect().await?;
                // новый экземпляр сразу, чтобы следующий клиент не получил «канал занят»
                let fresh = ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&self.name)?;
                let conn = std::mem::replace(&mut *next, fresh);
                drop(next);
                let mut pid = 0u32;
                let ok = unsafe {
                    GetNamedPipeClientProcessId(conn.as_raw_handle() as HANDLE, &mut pid)
                } != 0;
                if ok && same_user_pid(pid) {
                    return Ok(conn);
                }
                tracing::warn!(pid, "отклонён клиент другого пользователя");
            }
        }
    }

    /// SID пользователя, которому принадлежит токен процесса.
    unsafe fn token_user(process: HANDLE) -> Option<Vec<u8>> {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
            let mut buf = vec![0u8; len as usize];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            CloseHandle(token);
            (ok != 0).then_some(buf)
        }
    }

    /// Процесс `pid` запущен тем же пользователем, что и демон.
    pub fn same_user_pid(pid: u32) -> bool {
        unsafe {
            let Some(mine) = token_user(GetCurrentProcess()) else {
                return false;
            };
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if h.is_null() {
                return false;
            }
            let theirs = token_user(h);
            CloseHandle(h);
            let Some(theirs) = theirs else { return false };
            let a = (*(mine.as_ptr() as *const TOKEN_USER)).User.Sid;
            let b = (*(theirs.as_ptr() as *const TOKEN_USER)).User.Sid;
            EqualSid(a, b) != 0
        }
    }
}
