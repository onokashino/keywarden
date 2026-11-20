//! Синхронизация напрямую с компьютерами в той же сети.
//!
//! Каждый компьютер с открытой базой раз в 15 с и после каждой записи шлёт широковещательный
//! маяк (UDP): «у меня эта база, файл в таком состоянии, забирай с такого порта». Маяк узнаёт
//! только копия той же базы с тем же паролем. Увидев новое состояние у соседа, компьютер
//! забирает его файл по TCP (рукопожатие и шифрование в `keywarden_core::remote`) и сливает тем
//! же путём, что и файл с диска. Если после слияния ему есть что записать, его маяк изменится,
//! и сосед заберёт уже его файл. Пустые слияния ничего не пишут, так что обмен затихает.
//!
//! Обмен привязан к доверенным сетям: в чужой сети (кафе, гостиница) маяки не уходят и порт
//! закрыт. Сеть узнаётся по аппаратному адресу шлюза. Это защита от лишней огласки, а не
//! проверка подлинности: подлинность даёт только ключ базы в рукопожатии.

use crate::state::Daemon;
use crate::sync::Incoming;
use keywarden_core::ipc::{Event, LanCheck, LanNetwork, Response};
use keywarden_core::remote::{
    self, Beacon, FINISH_LEN, HELLO_LEN, LAN_PORT, Lan, MAX_VAULT_BYTES, REPLY_LEN,
};
use keywarden_core::tr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

const BEACON_EVERY: Duration = Duration::from_secs(15);
/// сосед, от которого столько нет маяка, ушёл из сети (три пропущенных маяка и запас)
const PEER_TTL: Duration = Duration::from_secs(50);
/// сколько номеров знакомых компьютеров помнить
const KEEP_KNOWN: usize = 64;
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
            g.sync.lan_checks.clear();
            g.sync.lan_state = None;
        }
        // ждём включения или разблокировки
        tokio::select! {
            ev = events.recv() => if matches!(ev, Err(tokio::sync::broadcast::error::RecvError::Closed)) { return; },
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

/// Передача базы на новый компьютер: код, ключ связи из него и срок.
pub struct Offer {
    code: String,
    lan: Arc<Lan>,
    until: Instant,
}

impl Offer {
    /// `None`: срок вышел.
    pub fn info(&self) -> Option<keywarden_core::ipc::LanOffer> {
        let left = self.until.checked_duration_since(Instant::now())?;
        Some(keywarden_core::ipc::LanOffer {
            code: self.code.clone(),
            seconds: left.as_secs(),
        })
    }
}

/// Сосед в сети: когда слышали и новый ли он для этого компьютера.
pub struct Peer {
    /// «14:03»
    pub seen: String,
    at: Instant,
    pub new: bool,
    /// почему не удалось забрать его базу (до первой удачи)
    pub error: Option<String>,
}

struct Active {
    epoch: u64,
    /// сеть, в которой запущен обмен: сменилась, значит, останавливаемся
    net: Option<String>,
    lan: Arc<Lan>,
    udp: Arc<UdpSocket>,
    tcp: TcpListener,
    port: u16,
    instance: [u8; 8],
}

async fn start(d: &Arc<Daemon>) -> Option<Active> {
    let cfg = d.config();
    if !cfg.lan_sync {
        return None;
    }
    let now = current_network();
    if NETWORKS_SUPPORTED {
        // обмен включили до появления списка сетей: сеть, где он работал, считаем своей
        if cfg.lan_networks.is_none() && now.is_some() {
            d.update_config(trust_current);
        }
        let trusted = d.config().lan_networks.unwrap_or_default();
        match &now {
            None => {
                d.set_lan_state(tr!("сеть не определилась, обмен ждёт").into());
                return None;
            }
            Some(n) if !trusted.iter().any(|t| t.id == n.id) => {
                d.set_lan_state(
                    tr!("эта сеть не в доверенных: обмен выключен, порт закрыт").into(),
                );
                return None;
            }
            Some(_) => {}
        }
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
    let instance = device_id(d);
    tracing::info!("сеть: жду другие компьютеры на порту {port}");
    d.refresh_lan_checks(port).await;
    d.set_lan_state(tr!("ищу компьютеры в сети (порт {port})", port = LAN_PORT));
    Some(Active {
        epoch,
        net: now.map(|n| n.id),
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
    let mut ticks = 0u32;
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
            _ = tick.tick() => {
                // ушли в другую сеть или сеть убрали из доверенных: замолчать сразу
                if NETWORKS_SUPPORTED && !network_allowed(d, &a.net) {
                    return;
                }
                d.drop_stale_peers();
                // раз в минуту: правило брандмауэра могли добавить, пока окно открыто
                ticks += 1;
                if ticks.is_multiple_of(4) {
                    d.refresh_lan_checks(a.port).await;
                }
                beacon(d, &a).await
            }
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
                d.saw_peer(from.ip(), b.instance).await;
                let mine = d.with_vault(|v, _| a.lan.file_tag(&v.disk_hash()));
                if mine == Some(b.tag) || pulled.get(&b.instance) == Some(&b.tag) {
                    continue;
                }
                pulled.insert(b.instance, b.tag);
                let (d2, lan, tx) = (d.clone(), a.lan.clone(), done_tx.clone());
                let addr = SocketAddr::new(from.ip(), b.port);
                tokio::spawn(async move {
                    let res = pull(&d2, &lan, addr).await;
                    if let Err(e) = &res {
                        tracing::warn!("сеть: не удалось забрать базу с {addr}: {e}");
                    }
                    d2.pull_result(addr, res.as_ref().err());
                    let ok = res.is_ok();
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
                    if let Err(e) = tokio::time::timeout(Duration::from_secs(120), give(&d2, &lan, stream, peer)).await.unwrap_or_else(|_| Err("timeout".into())) {
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
async fn give(
    d: &Arc<Daemon>,
    lan: &Lan,
    mut s: TcpStream,
    peer: SocketAddr,
) -> Result<(), String> {
    let hello = read_exact(&mut s, HELLO_LEN).await?;
    if remote::is_pair_hello(&hello) {
        return give_first(d, s, &hello, peer.ip()).await;
    }
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

/// Первая передача базы на новый компьютер по одноразовому коду.
///
/// Код забывается до ответа: на него приходится ровно одна попытка, удачная или нет. Ответ
/// позволяет перебирать код без сети, поэтому после него код не должен ничего открывать.
async fn give_first(
    d: &Arc<Daemon>,
    mut s: TcpStream,
    hello: &[u8],
    ip: IpAddr,
) -> Result<(), String> {
    let offer = d.inner().sync.offer.take().filter(|o| o.info().is_some());
    let Some(offer) = offer else {
        return Err("no offer".into());
    };
    d.events.send(Event::Changed).ok();
    let sent = async {
        let (pending, reply) = remote::server_reply(&offer.lan, hello)?;
        write_all(&mut s, &reply).await?;
        let fin = read_exact(&mut s, FINISH_LEN).await?;
        let session = pending.finish(&offer.lan, &fin)?;
        let reader = d.with_vault(|v, _| v.reader()).ok_or("locked")?;
        let name = reader
            .path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let (bytes, _) = tokio::task::spawn_blocking(move || reader.read_bytes())
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        let frame = session.seal(&remote::pair_pack(&name, &bytes));
        write_all(&mut s, &(frame.len() as u32).to_be_bytes()).await?;
        write_all(&mut s, &frame).await?;
        s.shutdown().await.ok();
        Ok::<_, String>(())
    }
    .await;
    let message = match &sent {
        Ok(()) => tr!(
            "База передана на компьютер {ip}. Откройте её там мастер-паролем",
            ip = ip
        ),
        Err(_) => tr!(
            "Код передачи отменён: с {ip} подключились с неверным кодом. Создайте новый код",
            ip = ip
        ),
    };
    tracing::info!("сеть: {message}");
    d.events
        .send(Event::Merged {
            message: message.clone(),
        })
        .ok();
    crate::sync::notify_desktop("Keywarden", &message).await;
    sent
}

/// Попытка получить базу с одного адреса. `Ok(None)`: там нет передачи с нашим кодом.
async fn take_first(lan: &Lan, addr: SocketAddr) -> Option<(String, Vec<u8>)> {
    let mut s = tokio::time::timeout(Duration::from_millis(1500), TcpStream::connect(addr))
        .await
        .ok()?
        .ok()?;
    let hello = remote::pair_hello();
    write_all(&mut s, hello.message()).await.ok()?;
    let reply = read_exact(&mut s, REPLY_LEN).await.ok()?;
    // отдающий не знает наш код: это чужая передача, ему ничего не доказываем
    let (session, fin) = hello.finish(lan, &reply).ok()?;
    write_all(&mut s, &fin).await.ok()?;
    let len = u32::from_be_bytes(read_exact(&mut s, 4).await.ok()?.try_into().ok()?) as usize;
    if len > MAX_VAULT_BYTES + FRAME_OVERHEAD + 256 {
        return None;
    }
    let mut frame = vec![0u8; len];
    tokio::time::timeout(Duration::from_secs(120), s.read_exact(&mut frame))
        .await
        .ok()?
        .ok()?;
    let plain = session.open(&frame).ok()?;
    let (name, vault) = remote::pair_unpack(&plain)?;
    Some((name, vault.to_vec()))
}

/// Адреса, где искать отдающий компьютер: все соседи по каждой своей сети IPv4.
fn sweep_targets() -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for (addr, mask) in local_nets() {
        // сеть крупнее /22 (1022 адреса) целиком не обходим: берём /24 вокруг своего адреса
        let mask = if u32::from(mask).count_ones() < 22 {
            0xffff_ff00
        } else {
            u32::from(mask)
        };
        let net = u32::from(addr) & mask;
        for host in 1..!mask {
            let ip = Ipv4Addr::from(net | host);
            if ip != addr && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Свои адреса IPv4 с масками (кроме петли).
fn local_nets() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut out = Vec::new();
    #[cfg(unix)]
    // SAFETY: список от getifaddrs читается только до freeifaddrs, указатели проверяются на null
    unsafe {
        let mut ifs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifs) == 0 {
            let mut cur = ifs;
            while !cur.is_null() {
                let i = &*cur;
                let flags = i.ifa_flags as libc::c_int;
                let v4 = |p: *const libc::sockaddr| {
                    (!p.is_null() && (*p).sa_family as libc::c_int == libc::AF_INET).then(|| {
                        let sin = &*(p as *const libc::sockaddr_in);
                        Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))
                    })
                };
                if flags & libc::IFF_UP != 0
                    && flags & libc::IFF_LOOPBACK == 0
                    && let (Some(a), Some(m)) = (v4(i.ifa_addr), v4(i.ifa_netmask))
                {
                    out.push((a, m));
                }
                cur = i.ifa_next;
            }
            libc::freeifaddrs(ifs);
        }
    }
    // ponytail: без getifaddrs (Windows) берём адрес основной сети и считаем её /24
    #[cfg(not(unix))]
    if let Ok(s) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        && s.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).is_ok()
        && let Ok(SocketAddr::V4(a)) = s.local_addr()
    {
        out.push((*a.ip(), Ipv4Addr::new(255, 255, 255, 0)));
    }
    out
}

/// Имя для полученной базы: только имя файла .kdbx, без путей и скрытых файлов.
fn safe_vault_name(name: &str) -> String {
    let base = std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ok = base.to_lowercase().ends_with(".kdbx")
        && !base.starts_with('.')
        && !base.contains(['/', '\\', '\0']);
    if ok { base } else { "Keywarden.kdbx".into() }
}

/// Записать полученную базу в `dir` под свободным именем. Существующий файл не затирается:
/// имя занимается атомарно, как при создании базы.
fn save_received(dir: &std::path::Path, name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let name = safe_vault_name(name);
    let stem = name[..name.len() - ".kdbx".len()].to_string();
    for n in 1..1000 {
        let path = dir.join(if n == 1 {
            name.clone()
        } else {
            format!("{stem} {n}.kdbx")
        });
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        match o.open(&path) {
            Ok(mut f) => {
                let written = f.write_all(bytes).and_then(|()| f.sync_all());
                if let Err(e) = written {
                    let _ = std::fs::remove_file(&path);
                    return Err(e);
                }
                return Ok(path);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::ErrorKind::AlreadyExists.into())
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
        return Err(tr!("база с другого компьютера слишком большая").into());
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
    /// Сообщает только о перемене: `start` зовёт это каждые 5 с, пока обмен ждёт сеть.
    fn set_lan_state(&self, s: String) {
        let changed = {
            let mut g = self.inner();
            let changed = g.sync.lan_state.as_deref() != Some(s.as_str());
            g.sync.lan_state = Some(s);
            changed
        };
        if changed {
            self.events.send(Event::Changed).ok();
        }
    }

    async fn saw_peer(&self, ip: IpAddr, device: [u8; 8]) {
        let id = data_encoding::HEXLOWER.encode(&device);
        let seen = chrono::Local::now().format("%H:%M").to_string();
        let (appeared, new) = {
            let mut g = self.inner();
            let known = g.config.lan_known.contains(&id);
            let was = g.sync.peers.get(&ip).map(|p| (p.new, p.error.clone()));
            g.sync.peers.insert(
                ip,
                Peer {
                    seen,
                    at: Instant::now(),
                    new: was.as_ref().map(|w| w.0).unwrap_or(!known),
                    error: was.as_ref().and_then(|w| w.1.clone()),
                },
            );
            (was.is_none(), !known)
        };
        if new {
            self.update_config(|c| {
                c.lan_known.push(id);
                let extra = c.lan_known.len().saturating_sub(KEEP_KNOWN);
                c.lan_known.drain(..extra);
                true
            });
            tracing::info!("сеть: новый компьютер {ip} с этой же базой");
            let m = tr!("В обмене по сети появился новый компьютер: {ip}", ip = ip);
            self.events.send(Event::Merged { message: m.clone() }).ok();
            crate::sync::notify_desktop("Keywarden", &m).await;
        } else if appeared {
            tracing::info!("сеть: рядом {ip} с этой же базой");
            self.events.send(Event::Changed).ok();
        }
    }

    /// Итог попытки забрать базу: ошибка видна в настройках рядом с компьютером.
    fn pull_result(&self, addr: SocketAddr, err: Option<&String>) {
        let error = err.map(|e| {
            if e == "timeout" || e.contains("refused") || e.contains("unreachable") {
                tr!(
                    "слышу, но подключиться не могу: на том компьютере закрыт порт {port} (TCP)",
                    port = addr.port()
                )
            } else {
                e.clone()
            }
        });
        let changed = {
            let mut g = self.inner();
            match g.sync.peers.get_mut(&addr.ip()) {
                Some(p) if p.error != error => {
                    p.error = error;
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.events.send(Event::Changed).ok();
        }
    }

    async fn refresh_lan_checks(&self, tcp_port: u16) {
        let checks = tokio::task::spawn_blocking(move || self_checks(tcp_port))
            .await
            .unwrap_or_default();
        let changed = {
            let mut g = self.inner();
            let changed = g.sync.lan_checks != checks;
            g.sync.lan_checks = checks;
            changed
        };
        if changed {
            self.events.send(Event::Changed).ok();
        }
    }

    fn drop_stale_peers(&self) {
        let dropped = {
            let mut g = self.inner();
            let before = g.sync.peers.len();
            g.sync.peers.retain(|_, p| p.at.elapsed() < PEER_TTL);
            g.sync.peers.len() != before
        };
        if dropped {
            self.events.send(Event::Changed).ok();
        }
    }

    /// Завести одноразовый код передачи базы на новый компьютер или отменить его.
    pub(crate) async fn lan_offer(&self, on: bool) -> Result<Response, Response> {
        let invalid = |m: &str| Response::error(keywarden_core::ipc::ErrorCode::Invalid, m);
        if !on {
            self.inner().sync.offer = None;
            self.events.send(Event::Changed).ok();
            return Ok(Response::Ok);
        }
        if self.with_vault(|_, _| ()).is_none() {
            return Err(Response::error(
                keywarden_core::ipc::ErrorCode::Locked,
                tr!("база заблокирована"),
            ));
        }
        let code = remote::pair_code();
        let c2 = code.clone();
        let lan = tokio::task::spawn_blocking(move || remote::pair_key(&c2))
            .await
            .ok()
            .flatten()
            .ok_or_else(|| invalid("pair key"))?;
        // передачу принимает тот же порт, что и обмен, а после неё компьютеры обмениваются сами
        self.update_config(|c| {
            trust_current(c);
            c.lan_sync = true;
            true
        });
        self.inner().sync.offer = Some(Offer {
            code,
            lan: Arc::new(lan),
            until: Instant::now() + Duration::from_secs(remote::PAIR_SECONDS),
        });
        self.events.send(Event::Changed).ok();
        Ok(Response::Ok)
    }

    /// Получить базу с компьютера в этой сети по одноразовому коду.
    pub(crate) async fn lan_receive(
        &self,
        code: keywarden_core::secret::Secret,
        dir: String,
    ) -> Result<Response, Response> {
        let invalid = |m: String| Response::error(keywarden_core::ipc::ErrorCode::Invalid, m);
        if self.with_vault(|_, _| ()).is_some() {
            return Err(invalid(
                tr!("сначала заблокируйте открытую базу: получить можно только на её место").into(),
            ));
        }
        let lan = tokio::task::spawn_blocking(move || remote::pair_key(code.expose()))
            .await
            .ok()
            .flatten()
            .ok_or_else(|| invalid(tr!("в коде должно быть 8 цифр").into()))?;
        let lan = Arc::new(lan);
        // сами стучимся к каждому адресу своей сети: так на этом компьютере не нужен открытый порт
        let mut tries = tokio::task::JoinSet::new();
        for ip in sweep_targets() {
            let lan = lan.clone();
            tries
                .spawn(async move { take_first(&lan, SocketAddr::new(ip.into(), LAN_PORT)).await });
        }
        let mut got = None;
        while let Some(res) = tries.join_next().await {
            if let Ok(Some(found)) = res {
                got = Some(found);
                break;
            }
        }
        tries.abort_all();
        let (name, bytes) = got.ok_or_else(|| {
            invalid(tr!(
                "Компьютер с таким кодом не найден. Проверьте код (он одноразовый: после ошибки нужен новый), что оба компьютера в одной сети и что на том открыт порт {port} (TCP)",
                port = LAN_PORT
            ))
        })?;
        // подпись KDBX: по коду мог прийти только файл базы, но чужой мусор на диск не пишем
        if bytes.len() < 8 || bytes[..4] != [0x03, 0xd9, 0xa2, 0x9a] {
            return Err(invalid(tr!("получен не файл базы").into()));
        }
        let dir = crate::config::expand(std::path::Path::new(&dir));
        let path = tokio::task::spawn_blocking(move || save_received(&dir, &name, &bytes))
            .await
            .map_err(|e| invalid(e.to_string()))?
            .map_err(|e| invalid(tr!("база получена, но не записана: {e}", e = e)))?;
        self.update_config(|c| {
            c.database = Some(path.clone());
            // у полученной базы свои ключи: прежние файл-ключ, YubiKey и PIN к ней не относятся
            c.keyfile = None;
            c.yubikey = None;
            c.pin = None;
            trust_current(c);
            c.lan_sync = true;
            true
        });
        tracing::info!("сеть: база получена и записана в {}", path.display());
        self.events.send(Event::Changed).ok();
        Ok(Response::LanReceived {
            path: path.display().to_string(),
        })
    }

    /// Доверять сети или убрать её из списка. `None`: сеть, в которой компьютер сейчас.
    pub(crate) fn lan_trust(&self, network: Option<String>, on: bool) -> Response {
        let current = current_network();
        let Some(id) = network.or(current.as_ref().map(|n| n.id.clone())) else {
            return Response::Error {
                code: keywarden_core::ipc::ErrorCode::Invalid,
                message: tr!("сеть не определилась").into(),
            };
        };
        self.update_config(|c| {
            let list = c.lan_networks.get_or_insert_with(Vec::new);
            list.retain(|n| n.id != id);
            if on && let Some(n) = current.filter(|n| n.id == id) {
                list.push(n);
            }
            true
        });
        self.events.send(Event::Changed).ok();
        Response::Ok
    }
}

/// Постоянный номер этого компьютера в маяках; заводится один раз.
fn device_id(d: &Daemon) -> [u8; 8] {
    let saved = d.config().lan_device.and_then(|h| {
        let b = data_encoding::HEXLOWER.decode(h.as_bytes()).ok()?;
        <[u8; 8]>::try_from(b).ok()
    });
    saved.unwrap_or_else(|| {
        let mut id = [0u8; 8];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
        d.update_config(|c| {
            c.lan_device = Some(data_encoding::HEXLOWER.encode(&id));
            true
        });
        id
    })
}

fn network_allowed(d: &Daemon, started_in: &Option<String>) -> bool {
    let now = current_network().map(|n| n.id);
    now == *started_in
        && d.config()
            .lan_networks
            .unwrap_or_default()
            .iter()
            .any(|t| Some(&t.id) == now.as_ref())
}

/// Добавить текущую сеть в доверенные (и завести список, если его не было).
pub(crate) fn trust_current(c: &mut crate::config::Config) -> bool {
    // сеть ещё не определилась: список не заводим, её добавит `start`, когда она станет известна
    let Some(n) = current_network() else {
        return false;
    };
    let list = c.lan_networks.get_or_insert_with(Vec::new);
    if !list.iter().any(|t| t.id == n.id) {
        list.push(n);
    }
    true
}

/// Самопроверка: свой порт и брандмауэр. Чужой брандмауэр отсюда не виден, о нём говорит
/// ошибка рядом с компьютером в списке (`pull_result`).
fn self_checks(tcp_port: u16) -> Vec<LanCheck> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut out = vec![if tcp_port == LAN_PORT {
        LanCheck {
            ok: Some(true),
            text: tr!("Keywarden слушает порт {port}: UDP и TCP", port = LAN_PORT),
            fix: None,
        }
    } else {
        LanCheck {
            ok: Some(false),
            text: tr!(
                "TCP {port} занят другой программой, базу отдаю с порта {other}: в брандмауэре нужен и он",
                port = LAN_PORT,
                other = tcp_port
            ),
            fix: None,
        }
    }];
    #[cfg(target_os = "linux")]
    out.extend(firewall_check());
    out
}

/// Что известно о брандмауэре этого компьютера без прав администратора: ufw и firewalld.
// ponytail: голые nftables и iptables читаются только от root, для них проверки нет
#[cfg(target_os = "linux")]
fn firewall_check() -> Option<LanCheck> {
    use std::process::Command;
    let subnet = std::fs::read_to_string("/proc/net/route")
        .ok()
        .zip(std::fs::read_to_string("/proc/net/arp").ok())
        .and_then(|(r, a)| subnet_from(&r, &a));
    let ufw_on = std::fs::read_to_string("/etc/ufw/ufw.conf").is_ok_and(|c| {
        c.lines()
            .any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes"))
    });
    if ufw_on {
        let fix = match &subnet {
            Some(net) => format!("sudo ufw allow from {net} to any port {LAN_PORT}"),
            None => format!("sudo ufw allow {LAN_PORT}"),
        };
        return Some(match std::fs::read_to_string("/etc/ufw/user.rules") {
            Ok(rules) if ufw_allows(&rules, LAN_PORT) => LanCheck {
                ok: Some(true),
                text: tr!("Брандмауэр ufw пропускает порт {port}", port = LAN_PORT),
                fix: None,
            },
            Ok(_) => LanCheck {
                ok: Some(false),
                text: tr!(
                    "Брандмауэр ufw закрывает порт {port}: другие компьютеры вас не услышат",
                    port = LAN_PORT
                ),
                fix: Some(fix),
            },
            Err(_) => LanCheck {
                ok: None,
                text: tr!(
                    "Включён брандмауэр ufw, его правила отсюда не прочитать. Если обмен не идёт, разрешите порт"
                )
                .into(),
                fix: Some(fix),
            },
        });
    }
    let fw = |args: &[&str]| {
        Command::new("firewall-cmd")
            .args(args)
            .output()
            .is_ok_and(|o| o.status.success())
    };
    if fw(&["--state"]) {
        let open = fw(&[&format!("--query-port={LAN_PORT}/udp")])
            && fw(&[&format!("--query-port={LAN_PORT}/tcp")]);
        return Some(if open {
            LanCheck {
                ok: Some(true),
                text: tr!(
                    "Брандмауэр firewalld пропускает порт {port}",
                    port = LAN_PORT
                ),
                fix: None,
            }
        } else {
            LanCheck {
                ok: Some(false),
                text: tr!(
                    "Брандмауэр firewalld закрывает порт {port}: другие компьютеры вас не услышат",
                    port = LAN_PORT
                ),
                fix: Some(format!(
                    "sudo firewall-cmd --permanent --add-port={LAN_PORT}/udp --add-port={LAN_PORT}/tcp && sudo firewall-cmd --reload"
                )),
            }
        });
    }
    Some(LanCheck {
        ok: None,
        text: tr!(
            "Брандмауэр ufw или firewalld не найден. Если стоит другой, разрешите порт {port} (UDP и TCP) сами",
            port = LAN_PORT
        ),
        fix: None,
    })
}

/// Есть ли в правилах ufw разрешение входящих UDP и TCP на порт (строки `### tuple ###`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn ufw_allows(rules: &str, port: u16) -> bool {
    // порт в правиле: «47470», список «80,443» или диапазон «47000:48000»
    let covers = |spec: &str| {
        spec == "any"
            || spec.split(',').any(|p| match p.split_once(':') {
                Some((a, b)) => {
                    a.parse().is_ok_and(|a: u16| a <= port)
                        && b.parse().is_ok_and(|b: u16| port <= b)
                }
                None => p.parse() == Ok(port),
            })
    };
    let allowed = |proto: &str| {
        rules.lines().any(|l| {
            let Some(t) = l.strip_prefix("### tuple ###") else {
                return false;
            };
            // действие, протокол, порт назначения, адрес назначения, порт и адрес источника, направление
            let f: Vec<&str> = t.split_whitespace().collect();
            f.len() >= 7
                && f[0].starts_with("allow")
                && (f[1] == proto || f[1] == "any")
                && covers(f[2])
                && f[6].starts_with("in")
        })
    };
    allowed("udp") && allowed("tcp")
}

/// Подсеть текущей сети, «192.168.0.0/24»: для правила брандмауэра только на свою сеть.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn subnet_from(routes: &str, arp: &str) -> Option<String> {
    let name = network_from(routes, arp)?.name;
    routes.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 || !name.contains(&format!("({})", f[0])) {
            return None;
        }
        let net = u32::from_str_radix(f[1], 16).ok()?;
        let mask = u32::from_str_radix(f[7], 16).ok()?;
        (u32::from_str_radix(f[2], 16).ok()? == 0 && mask != 0).then(|| {
            format!(
                "{}/{}",
                Ipv4Addr::from(net.to_ne_bytes()),
                mask.count_ones()
            )
        })
    })
}

/// Различает ли эта система сети. Где нет, обмен работает в любой сети, как раньше.
// ponytail: только Linux (/proc); для macOS и Windows нужен разбор `route` и `arp`
pub const NETWORKS_SUPPORTED: bool = cfg!(target_os = "linux");

/// Сеть, в которой компьютер сейчас.
pub fn current_network() -> Option<LanNetwork> {
    #[cfg(target_os = "linux")]
    {
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        let arp = std::fs::read_to_string("/proc/net/arp").ok()?;
        let found = network_from(&routes, &arp);
        if found.is_none() {
            // адрес шлюза ядро узнаёт только при обращении к нему: в тихой сети его может
            // не быть. Пустой пакет заставит спросить, следующий вызов уже увидит ответ
            for gw in gateways(&routes) {
                if let Ok(s) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                    s.send_to(&[], (gw, 9)).ok();
                }
            }
        }
        found
    }
    #[cfg(not(target_os = "linux"))]
    None
}

/// Шлюз с наименьшей метрикой, чей аппаратный адрес известен. Маршруты через VPN (tun, wg)
/// отпадают сами: у их шлюзов нет записи в таблице ARP.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn network_from(routes: &str, arp: &str) -> Option<LanNetwork> {
    let mut best: Option<(u32, LanNetwork)> = None;
    for (iface, gw, metric) in gateway_routes(routes) {
        let ip = gw.to_string();
        let mac = arp.lines().skip(1).find_map(|l| {
            let a: Vec<&str> = l.split_whitespace().collect();
            (a.len() >= 6 && a[0] == ip && a[5] == iface && a[3] != "00:00:00:00:00:00")
                .then(|| a[3].to_lowercase())
        });
        if let Some(mac) = mac
            && best.as_ref().is_none_or(|(m, _)| metric < *m)
        {
            let name = tr!("шлюз {ip} ({iface})", ip = ip, iface = iface);
            best = Some((metric, LanNetwork { id: mac, name }));
        }
    }
    best.map(|(_, n)| n)
}

/// Строки /proc/net/route со шлюзом: интерфейс, адрес шлюза, метрика.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn gateway_routes(routes: &str) -> impl Iterator<Item = (&str, Ipv4Addr, u32)> {
    const RTF_UP_GATEWAY: u32 = 0x1 | 0x2;
    routes.lines().skip(1).filter_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 7 {
            return None;
        }
        let flags = u32::from_str_radix(f[3], 16).ok()?;
        let gw = u32::from_str_radix(f[2], 16).ok()?;
        if flags & RTF_UP_GATEWAY != RTF_UP_GATEWAY || gw == 0 {
            return None;
        }
        // адрес записан в порядке байтов сети, прочитанном как число хоста
        Some((
            f[0],
            Ipv4Addr::from(gw.to_ne_bytes()),
            f[6].parse().unwrap_or(u32::MAX),
        ))
    })
}

#[cfg(target_os = "linux")]
fn gateways(routes: &str) -> Vec<Ipv4Addr> {
    gateway_routes(routes).map(|(_, gw, _)| gw).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn network_is_the_gateway_with_a_known_mac() {
        let routes = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            tun0\t00000000\t0100080A\t0003\t0\t0\t50\t00000000\t0\t0\t0\n\
            wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        let arp = "IP address       HW type     Flags       HW address            Mask     Device\n\
            192.168.1.1      0x1         0x2         AA:BB:CC:00:11:22     *        wlan0\n\
            192.168.2.1      0x1         0x2         aa:bb:cc:00:11:33     *        eth0\n\
            192.168.9.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        // VPN без записи ARP пропущен, из двух сетей выбрана с меньшей метрикой
        let n = super::network_from(routes, arp).unwrap();
        assert_eq!(n.id, "aa:bb:cc:00:11:33");
        assert!(n.name.contains("192.168.2.1") && n.name.contains("eth0"));
        // шлюз ещё не ответил на ARP: сеть не определилась
        assert!(super::network_from(routes, "IP address\n").is_none());
        assert_eq!(super::subnet_from(routes, arp), None);
        let direct =
            format!("{routes}eth0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n");
        assert_eq!(
            super::subnet_from(&direct, arp).as_deref(),
            Some("192.168.2.0/24")
        );
    }

    #[test]
    fn received_vault_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("kw-recv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = super::save_received(&dir, "../../etc/Сейф.kdbx", b"one").unwrap();
        assert_eq!(first, dir.join("Сейф.kdbx"));
        let second = super::save_received(&dir, "Сейф.kdbx", b"two").unwrap();
        assert_eq!(second, dir.join("Сейф 2.kdbx"));
        assert_eq!(std::fs::read(&first).unwrap(), b"one");
        // имя без .kdbx или скрытое: берём своё
        assert_eq!(super::safe_vault_name(".bashrc"), "Keywarden.kdbx");
        assert_eq!(super::safe_vault_name("x.exe"), "Keywarden.kdbx");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sweep_skips_own_address() {
        let own: Vec<_> = super::local_nets().into_iter().map(|n| n.0).collect();
        assert!(super::sweep_targets().iter().all(|ip| !own.contains(ip)));
    }

    #[test]
    fn ufw_rule_must_cover_both_protocols() {
        let udp = "### tuple ### allow udp 47470 0.0.0.0/0 any 192.168.0.0/24 in\n";
        let tcp = "### tuple ### allow tcp 47470 0.0.0.0/0 any 192.168.0.0/24 in\n";
        let any = "### tuple ### allow any 47470 0.0.0.0/0 any 192.168.0.0/24 in\n";
        assert!(!super::ufw_allows(udp, 47470));
        assert!(super::ufw_allows(&format!("{udp}{tcp}"), 47470));
        assert!(super::ufw_allows(any, 47470));
        let range =
            "### tuple ### allow any 47000:48000 0.0.0.0/0 any 192.168.0.0/24 in comment=6b77\n";
        assert!(super::ufw_allows(range, 47470) && !super::ufw_allows(range, 22));
        assert!(!super::ufw_allows(
            "### tuple ### deny any 47470 0.0.0.0/0 any 0.0.0.0/0 in\n",
            47470
        ));
        assert!(!super::ufw_allows(
            "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n",
            47470
        ));
    }

    #[test]
    fn broadcast_targets_include_the_global_one() {
        let t = super::broadcast_targets();
        assert_eq!(t[0], std::net::Ipv4Addr::BROADCAST);
        assert!(t.iter().all(|ip| !ip.is_loopback()));
    }
}
