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
use keywarden_core::ipc::{Event, LanNetwork, Response};
use keywarden_core::remote::{
    self, Beacon, FINISH_LEN, HELLO_LEN, LAN_PORT, Lan, MAX_VAULT_BYTES, REPLY_LEN,
};
use keywarden_core::tr;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
            g.sync.lan_state = None;
        }
        // ждём включения или разблокировки
        tokio::select! {
            ev = events.recv() => if matches!(ev, Err(tokio::sync::broadcast::error::RecvError::Closed)) { return; },
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }
}

/// Сосед в сети: когда слышали и новый ли он для этого компьютера.
pub struct Peer {
    /// «14:03»
    pub seen: String,
    at: Instant,
    pub new: bool,
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
    tracing::info!("сеть: жду соседей на порту {port}");
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
            let was = g.sync.peers.get(&ip).map(|p| p.new);
            g.sync.peers.insert(
                ip,
                Peer {
                    seen,
                    at: Instant::now(),
                    new: was.unwrap_or(!known),
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
    }

    #[test]
    fn broadcast_targets_include_the_global_one() {
        let t = super::broadcast_targets();
        assert_eq!(t[0], std::net::Ipv4Addr::BROADCAST);
        assert!(t.iter().all(|ip| !ip.is_loopback()));
    }
}
