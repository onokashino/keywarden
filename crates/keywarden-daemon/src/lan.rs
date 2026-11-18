//! Синхронизация напрямую с компьютерами в той же сети.
//!
//! Каждый компьютер с открытой базой раз в 15 с и после каждой записи шлёт широковещательный
//! маяк (UDP): «у меня эта база, файл в таком состоянии, забирай с такого порта». Маяк узнаёт
//! только копия той же базы с тем же паролем. Увидев новое состояние у соседа, компьютер
//! забирает его файл по TCP (рукопожатие и шифрование в `keywarden_core::remote`) и сливает тем
//! же путём, что и файл с диска. Если после слияния ему есть что записать, его маяк изменится,
//! и сосед заберёт уже его файл. Пустые слияния ничего не пишут, так что обмен затихает.

use crate::state::Daemon;
use crate::sync::Incoming;
use keywarden_core::ipc::Event;
use keywarden_core::remote::{
    self, Beacon, FINISH_LEN, HELLO_LEN, LAN_PORT, Lan, MAX_VAULT_BYTES, REPLY_LEN,
};
use keywarden_core::tr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

const BEACON_EVERY: Duration = Duration::from_secs(15);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// шифрование добавляет к файлу nonce и метку
const FRAME_OVERHEAD: usize = 24 + 16;

pub async fn serve(daemon: Arc<Daemon>) {
    let mut events = daemon.events.subscribe();
    loop {
        if let Some(active) = start(&daemon).await {
            run(&daemon, active, &mut events).await;
            let mut g = daemon.inner();
            g.sync.peers.clear();
            g.sync.lan_state = None;
        }
        // ждём включения или разблокировки
        tokio::select! {
            ev = events.recv() => if matches!(ev, Err(tokio::sync::broadcast::error::RecvError::Closed)) { return; },
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

struct Active {
    epoch: u64,
    lan: Arc<Lan>,
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    port: u16,
    instance: [u8; 8],
}

async fn start(d: &Arc<Daemon>) -> Option<Active> {
    if !d.config().lan_sync {
        return None;
    }
    let (reader, epoch, root) = d.with_vault(|v, e| (v.reader(), e, v.db.root().id().uuid()))?;
    let udp = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, LAN_PORT)).await {
        Ok(u) => u,
        Err(e) => {
            d.set_lan_state(tr!("порт {port} занят: {e}", port = LAN_PORT, e = e));
            return None;
        }
    };
    udp.set_broadcast(true).ok()?;
    // TCP на том же порту; если занят, любой свободный (его номер уходит в маяке)
    let tcp = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, LAN_PORT)).await {
        Ok(t) => t,
        Err(_) => TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?,
    };
    let port = tcp.local_addr().ok()?.port();
    // Argon2 после того, как порты получены: при занятом порте не считаем его каждые 5 с
    let lan =
        tokio::task::spawn_blocking(move || reader.key_digest().map(|k| remote::lan_key(&k, root)))
            .await
            .ok()?
            .ok()?;
    let mut instance = [0u8; 8];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut instance);
    tracing::info!("сеть: жду соседей на порту {port}");
    d.set_lan_state(tr!("ищу компьютеры в сети (порт {port})", port = LAN_PORT));
    Some(Active {
        epoch,
        lan: Arc::new(lan),
        udp: Arc::new(udp),
        tcp,
        port,
        instance,
    })
}

/// Работает, пока включено и открыта та же база.
async fn run(d: &Arc<Daemon>, a: Active, events: &mut tokio::sync::broadcast::Receiver<Event>) {
    let mut tick = tokio::time::interval(BEACON_EVERY);
    let mut buf = [0u8; 128];
    // что уже забрали у каждого соседа: по метке файла
    let mut pulled: HashMap<[u8; 8], [u8; 8]> = HashMap::new();
    let (done_tx, mut done_rx) = mpsc::unbounded_channel::<([u8; 8], [u8; 8], bool)>();
    loop {
        let alive = d.config().lan_sync && d.with_vault(|_, e| e) == Some(a.epoch);
        if !alive {
            return;
        }
        tokio::select! {
            _ = tick.tick() => beacon(d, &a).await,
            ev = events.recv() => match ev {
                Ok(Event::Saved) => beacon(d, &a).await,
                Ok(Event::Locked) => return,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                _ => {}
            },
            got = a.udp.recv_from(&mut buf) => {
                let Ok((n, from)) = got else { continue };
                let Some(b) = a.lan.decode_beacon(&buf[..n]) else { continue };
                if b.instance == a.instance {
                    continue;
                }
                d.saw_peer(from.ip());
                let mine = d.with_vault(|v, _| a.lan.file_tag(&v.disk_hash()));
                if mine == Some(b.tag) || pulled.get(&b.instance) == Some(&b.tag) {
                    continue;
                }
                pulled.insert(b.instance, b.tag);
                let (d2, lan, tx) = (d.clone(), a.lan.clone(), done_tx.clone());
                let addr = SocketAddr::new(from.ip(), b.port);
                tokio::spawn(async move {
                    let ok = match pull(&d2, &lan, addr).await {
                        Ok(()) => true,
                        Err(e) => {
                            tracing::warn!("сеть: не удалось забрать базу с {addr}: {e}");
                            false
                        }
                    };
                    tx.send((b.instance, b.tag, ok)).ok();
                });
            }
            Some((inst, tag, ok)) = done_rx.recv() => {
                // не вышло: попробуем со следующим маяком
                if !ok && pulled.get(&inst) == Some(&tag) {
                    pulled.remove(&inst);
                }
            }
            conn = a.tcp.accept() => {
                let Ok((stream, peer)) = conn else { continue };
                let (d2, lan) = (d.clone(), a.lan.clone());
                tokio::spawn(async move {
                    if let Err(e) = tokio::time::timeout(Duration::from_secs(120), give(&d2, &lan, stream)).await.unwrap_or_else(|_| Err("timeout".into())) {
                        tracing::debug!("сеть: {peer} не получил базу: {e}");
                    }
                });
            }
        }
    }
}

async fn beacon(d: &Daemon, a: &Active) {
    let Some(hash) = d.with_vault(|v, _| v.disk_hash()) else {
        return;
    };
    let wire = a.lan.encode_beacon(&Beacon {
        instance: a.instance,
        port: a.port,
        tag: a.lan.file_tag(&hash),
    });
    // 255.255.255.255 уходит только через основную карту: шлём ещё в каждую сеть отдельно
    for to in broadcast_targets() {
        if let Err(e) = a.udp.send_to(&wire, (to, LAN_PORT)).await {
            tracing::debug!("сеть: маяк на {to} не ушёл: {e}");
        }
    }
}

/// Широковещательные адреса всех поднятых сетей IPv4 (кроме петли) и общий 255.255.255.255.
fn broadcast_targets() -> Vec<Ipv4Addr> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut out = vec![Ipv4Addr::BROADCAST];
    #[cfg(unix)]
    // SAFETY: список от getifaddrs читается только до freeifaddrs, указатели проверяются на null
    unsafe {
        let mut ifs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifs) == 0 {
            let mut cur = ifs;
            while !cur.is_null() {
                let i = &*cur;
                let flags = i.ifa_flags as libc::c_int;
                let up = flags & libc::IFF_UP != 0
                    && flags & libc::IFF_BROADCAST != 0
                    && flags & libc::IFF_LOOPBACK == 0;
                #[cfg(target_os = "linux")]
                let bcast = i.ifa_ifu;
                #[cfg(not(target_os = "linux"))]
                let bcast = i.ifa_dstaddr;
                if up
                    && !i.ifa_addr.is_null()
                    && (*i.ifa_addr).sa_family as libc::c_int == libc::AF_INET
                    && !bcast.is_null()
                    && (*bcast).sa_family as libc::c_int == libc::AF_INET
                {
                    let sin = &*(bcast as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    if !out.contains(&ip) {
                        out.push(ip);
                    }
                }
                cur = i.ifa_next;
            }
            libc::freeifaddrs(ifs);
        }
    }
    out
}

async fn read_exact(s: &mut TcpStream, n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(buf)
}

async fn write_all(s: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(60), s.write_all(data))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())
}

/// Отдать свой файл соседу, который доказал, что знает ключ базы.
async fn give(d: &Arc<Daemon>, lan: &Lan, mut s: TcpStream) -> Result<(), String> {
    let hello = read_exact(&mut s, HELLO_LEN).await?;
    let (pending, reply) = remote::server_reply(lan, &hello)?;
    write_all(&mut s, &reply).await?;
    let fin = read_exact(&mut s, FINISH_LEN).await?;
    let session = pending.finish(lan, &fin)?;
    let reader = d.with_vault(|v, _| v.reader()).ok_or("locked")?;
    let (bytes, _) = tokio::task::spawn_blocking(move || reader.read_bytes())
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    let frame = session.seal(&bytes);
    write_all(&mut s, &(frame.len() as u32).to_be_bytes()).await?;
    write_all(&mut s, &frame).await?;
    s.shutdown().await.ok();
    Ok(())
}

/// Забрать файл соседа и слить.
async fn pull(d: &Arc<Daemon>, lan: &Lan, addr: SocketAddr) -> Result<(), String> {
    let mut s = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let hello = remote::client_hello();
    write_all(&mut s, hello.message()).await?;
    let reply = read_exact(&mut s, REPLY_LEN).await?;
    let (session, fin) = hello.finish(lan, &reply)?;
    write_all(&mut s, &fin).await?;
    let len =
        u32::from_be_bytes(read_exact(&mut s, 4).await?.try_into().expect("4 байта")) as usize;
    if len > MAX_VAULT_BYTES + FRAME_OVERHEAD {
        return Err(tr!("файл соседа слишком большой").into());
    }
    let mut frame = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(120), s.read_exact(&mut frame))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let bytes = session.open(&frame)?;
    let reader = d.with_vault(|v, _| v.reader()).ok_or("locked")?;
    let db = tokio::task::spawn_blocking(move || reader.parse_bytes(&bytes))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())?;
    d.inner().sync.incoming.push(Incoming {
        source: tr!("компьютер {ip}", ip = addr.ip()),
        db,
    });
    d.sync_from_disk().await?;
    Ok(())
}

impl Daemon {
    fn set_lan_state(&self, s: String) {
        self.inner().sync.lan_state = Some(s);
        self.events.send(Event::Changed).ok();
    }

    fn saw_peer(&self, ip: IpAddr) {
        let now = chrono::Local::now().format("%H:%M").to_string();
        let new = {
            let mut g = self.inner();
            g.sync.peers.insert(ip, now).is_none()
        };
        if new {
            tracing::info!("сеть: рядом {ip} с этой же базой");
            self.events.send(Event::Changed).ok();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn broadcast_targets_include_the_global_one() {
        let t = super::broadcast_targets();
        assert_eq!(t[0], std::net::Ipv4Addr::BROADCAST);
        assert!(t.iter().all(|ip| !ip.is_loopback()));
    }
}
