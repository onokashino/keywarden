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
    use keywarden_core::platform::same_user_pid;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

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
}
