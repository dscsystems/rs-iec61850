use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::ethernet::{self, Frame, Interface, ETHER_TYPE_GOOSE, ETHER_TYPE_SV};

use super::replay::ReplayWindow;
use super::{marshal, unmarshal, Error, KeyStore, Payload, PayloadType, Result, SessionId, Spdu};

/// The UDP port of the session protocol.
pub const DEFAULT_PORT: u16 = 102;

/// Receives an SPDU a session refused, for audit (IEC 62351-14 security
/// events). It is called from the receiving thread and must not block.
pub type RejectHandler = Arc<dyn Fn(&Reject) + Send + Sync>;

/// Configures a [`Session`].
#[derive(Clone, Default)]
pub struct Config {
    /// The local UDP address to receive on, e.g. `0.0.0.0:102`. Empty with no
    /// `groups` makes a send-only session.
    pub listen: String,
    /// Multicast groups to join for receiving, each `address` or
    /// `address:port` (the port defaults to `listen`'s, else 102). A group
    /// socket receives only what is sent to its group, and cannot share a port
    /// with `listen`: give a session `listen` for unicast, `groups` for
    /// multicast, or both on different ports.
    pub groups: Vec<String>,
    /// The network interface to join `groups` and send multicast on; empty
    /// lets the system choose.
    pub interface: String,
    /// Where [`send`](Session::send) and `write_frame` send, `address:port`
    /// (port 102 when omitted), unicast or multicast. Empty makes a
    /// receive-only session.
    pub remote: String,
    /// The hop limit of multicast sent (1 when 0, which does not leave the
    /// local network: routing R-GOOSE needs more).
    pub ttl: u32,
    /// The keys: the active one secures what is sent, and every one of them
    /// is accepted on receipt. `None` sends unsecured.
    pub keys: Option<Arc<KeyStore>>,
    /// The protocol version sent, 1 or 2 (2 when 0). Both are accepted on
    /// receipt. Version 1 cannot carry encryption.
    pub version: u16,
    /// Accepts SPDUs that carry no key. By default they are refused: a
    /// receiver that holds keys expects its publishers to use them, and one
    /// that accepts unsecured traffic can be fed forged messages by anyone on
    /// the path.
    pub allow_unsecured: bool,
    /// How many SPDU numbers below the highest seen from a sender are still
    /// accepted, once each (64 when 0, at most 64; negative disables replay
    /// protection). It applies to secured SPDUs, whose numbers cannot be
    /// forged.
    pub replay_window: i32,
    /// How long a sender may be silent before its numbering is allowed to
    /// start again, as a restarted publisher's does (10 s when `None`).
    /// `Some(Duration::ZERO)` never resets.
    pub replay_reset: Option<Duration>,
    /// Told of every SPDU refused.
    pub on_reject: Option<RejectHandler>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("listen", &self.listen)
            .field("groups", &self.groups)
            .field("interface", &self.interface)
            .field("remote", &self.remote)
            .field("ttl", &self.ttl)
            .field("keys", &self.keys.as_ref().map(|k| k.ids()))
            .field("version", &self.version)
            .field("allow_unsecured", &self.allow_unsecured)
            .field("replay_window", &self.replay_window)
            .field("replay_reset", &self.replay_reset)
            .finish_non_exhaustive()
    }
}

/// An SPDU a session refused.
#[derive(Debug)]
pub struct Reject {
    pub from: SocketAddr,
    pub err: Error,
}

/// Counts what a session has received.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub accepted: u64,
    pub malformed: u64,
    pub unknown_key: u64,
    pub unauthentic: u64,
    pub unsecured: u64,
    pub replayed: u64,
}

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    malformed: AtomicU64,
    unknown_key: AtomicU64,
    unauthentic: AtomicU64,
    unsecured: AtomicU64,
    replayed: AtomicU64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StreamKey {
    from: SocketAddr,
    si: SessionId,
    key_id: u32,
}

/// Bounds the replay state kept: beyond it, the state of senders silent
/// longer than the reset time is dropped.
const MAX_STREAMS: usize = 4096;

/// How often a receiving thread looks up from its socket to see whether the
/// session has closed.
const POLL: Duration = Duration::from_millis(100);

type Datagram = (Vec<u8>, SocketAddr);

/// Sends and receives SPDUs of the IEC 61850-90-5 session protocol over UDP:
/// R-GOOSE and R-SV.
///
/// A `Session` is also an [`ethernet::Interface`], so the GOOSE and sampled
/// value publishers and subscribers of this crate run over it unchanged: a
/// frame written is sent as the payload of an SPDU, with the frame's APPID
/// and simulation bit in the session header, and an SPDU received is handed
/// back as a frame of its EtherType.
///
/// ```no_run
/// use std::sync::Arc;
/// use iec61850::rsession::{Config, Key, KeyStore, Session, SigAlgorithm};
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let keys = Arc::new(KeyStore::with_keys([Key {
///     id: 1,
///     material: b"0123456789ABCDEF".to_vec(),
///     sig: SigAlgorithm::HMAC_SHA256_128,
///     ..Default::default()
/// }])?);
/// let s = Session::open(Config {
///     remote: "239.0.0.1:102".into(),
///     keys: Some(keys),
///     ..Default::default()
/// })?;
/// # Ok(())
/// # }
/// ```
pub struct Session {
    cfg: Config,
    replay_reset: Option<Duration>,
    send: Option<UdpSocket>,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
    rx: Option<Mutex<Receiver<Datagram>>>,
    readers: Mutex<Vec<JoinHandle<()>>>,
    closed: Arc<AtomicBool>,
    number: AtomicU32,
    send_lock: Mutex<()>,
    replay: Mutex<HashMap<StreamKey, ReplayWindow>>,
    pending: Mutex<VecDeque<Frame>>,
    stats: Counters,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("remote", &self.remote)
            .field("local", &self.local)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

fn resolve(addr: &str, default_port: u16) -> Result<SocketAddr> {
    let with_port = if addr.parse::<SocketAddr>().is_ok() || has_port(addr) {
        addr.to_string()
    } else if addr.contains(':') {
        format!("[{addr}]:{default_port}")
    } else {
        format!("{addr}:{default_port}")
    };
    with_port
        .to_socket_addrs()
        .map_err(Error::Io)?
        .next()
        .ok_or_else(|| Error::Address(format!("{addr} does not resolve")))
}

/// Reports whether `addr` ends in a port: `host:port` or `[v6]:port`.
fn has_port(addr: &str) -> bool {
    match addr.rsplit_once(':') {
        Some((host, port)) => {
            port.parse::<u16>().is_ok() && (!host.contains(':') || host.starts_with('['))
        }
        None => false,
    }
}

/// Returns the index and first IPv4 address of the named interface.
#[cfg(target_os = "linux")]
fn interface(name: &str) -> Result<(u32, Option<Ipv4Addr>)> {
    let cname = std::ffi::CString::new(name).map_err(|_| Error::Address(format!("interface {name:?}")))?;
    // SAFETY: if_nametoindex reads a NUL-terminated string.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(Error::Address(format!("no interface {name}")));
    }
    let mut addr = None;
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list that freeifaddrs releases; every
    // node is read only while the list is alive, and each address is read as
    // the family its sa_family names.
    unsafe {
        if libc::getifaddrs(&mut ifap) == 0 {
            let mut p = ifap;
            while !p.is_null() {
                let ifa = &*p;
                if !ifa.ifa_addr.is_null()
                    && i32::from((*ifa.ifa_addr).sa_family) == libc::AF_INET
                    && std::ffi::CStr::from_ptr(ifa.ifa_name) == cname.as_c_str()
                {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    addr = Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                    break;
                }
                p = ifa.ifa_next;
            }
            libc::freeifaddrs(ifap);
        }
    }
    Ok((index, addr))
}

#[cfg(not(target_os = "linux"))]
fn interface(name: &str) -> Result<(u32, Option<Ipv4Addr>)> {
    Err(Error::Address(format!(
        "selecting interface {name} is supported on Linux only; leave it empty to let the system choose"
    )))
}

impl Session {
    /// Opens a session.
    pub fn open(cfg: Config) -> Result<Session> {
        let mut cfg = cfg;
        if cfg.version == 0 {
            cfg.version = 2;
        }
        if cfg.version != 1 && cfg.version != 2 {
            return Err(Error::Version(cfg.version));
        }
        if cfg.replay_window == 0 {
            cfg.replay_window = 64;
        }
        cfg.replay_window = cfg.replay_window.min(64);
        let replay_reset = match cfg.replay_reset {
            None => Some(Duration::from_secs(10)),
            Some(d) if d.is_zero() => None,
            Some(d) => Some(d),
        };
        if cfg.ttl == 0 {
            cfg.ttl = 1;
        }
        let ifi = if cfg.interface.is_empty() {
            None
        } else {
            Some(interface(&cfg.interface)?)
        };

        let mut send = None;
        let mut remote = None;
        if !cfg.remote.is_empty() {
            let ra = resolve(&cfg.remote, DEFAULT_PORT)?;
            let sock = if ra.is_ipv4() {
                UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?
            } else {
                UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?
            };
            if ra.ip().is_multicast() {
                let s2 = socket2::SockRef::from(&sock);
                match ra.ip() {
                    IpAddr::V4(_) => {
                        s2.set_multicast_ttl_v4(cfg.ttl)?;
                        match ifi {
                            Some((_, Some(addr))) => s2.set_multicast_if_v4(&addr)?,
                            Some(_) => {
                                return Err(Error::Address(format!(
                                    "interface {} has no IPv4 address",
                                    cfg.interface
                                )))
                            }
                            None => {}
                        }
                    }
                    IpAddr::V6(_) => {
                        s2.set_multicast_hops_v6(cfg.ttl)?;
                        if let Some((index, _)) = ifi {
                            s2.set_multicast_if_v6(index)?;
                        }
                    }
                }
            }
            send = Some(sock);
            remote = Some(ra);
        }

        let mut recv: Vec<UdpSocket> = Vec::new();
        let mut listen_port = DEFAULT_PORT;
        if !cfg.listen.is_empty() {
            let la = resolve(&cfg.listen, DEFAULT_PORT)?;
            listen_port = la.port();
            recv.push(UdpSocket::bind(la)?);
        }
        for g in &cfg.groups {
            let ga = resolve(g, listen_port)?;
            if !ga.ip().is_multicast() {
                return Err(Error::Address(format!("{g} is not a multicast group")));
            }
            recv.push(join_group(ga, ifi).map_err(|e| Error::Address(format!("joining {g}: {e}")))?);
        }

        let local = recv.first().and_then(|s| s.local_addr().ok());
        let closed = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        let rx = if recv.is_empty() {
            None
        } else {
            let (tx, rx) = mpsc::sync_channel::<Datagram>(64);
            for sock in recv {
                sock.set_read_timeout(Some(POLL))?;
                let (tx, closed) = (tx.clone(), Arc::clone(&closed));
                readers.push(std::thread::spawn(move || read_loop(sock, tx, closed)));
            }
            Some(Mutex::new(rx))
        };

        Ok(Session {
            cfg,
            replay_reset,
            send,
            remote,
            local,
            rx,
            readers: Mutex::new(readers),
            closed,
            number: AtomicU32::new(0),
            send_lock: Mutex::new(()),
            replay: Mutex::new(HashMap::new()),
            pending: Mutex::new(VecDeque::new()),
            stats: Counters::default(),
        })
    }

    /// Returns the address the session receives on (the first, when it
    /// listens on several), `None` when it does not receive.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local
    }

    /// Sends one SPDU carrying `payloads`, secured with the active key of the
    /// configured key store; unsecured when the session has none. A session
    /// with a key store and no active key sends nothing:
    /// [`Error::NoActiveKey`].
    pub fn send(&self, si: SessionId, payloads: Vec<Payload>) -> Result<()> {
        let (Some(sock), Some(remote)) = (&self.send, self.remote) else {
            return Err(Error::NoRemote);
        };
        let key = match &self.cfg.keys {
            Some(ks) => Some(ks.active_key().ok_or(Error::NoActiveKey)?),
            None => None,
        };
        // Numbers are taken and sent in order, so a receiver's replay window
        // sees them increase.
        let _guard = self.send_lock.lock().unwrap();
        let spdu = Spdu {
            si,
            number: self.number.load(Ordering::Relaxed),
            version: self.cfg.version,
            payloads,
            ..Default::default()
        };
        let b = marshal(&spdu, key.as_ref())?;
        self.number.fetch_add(1, Ordering::Relaxed);
        sock.send_to(&b, remote)?;
        Ok(())
    }

    /// Returns the next SPDU that passes the session's checks, and its
    /// sender. SPDUs that fail are counted in [`stats`](Session::stats) and
    /// reported to the reject handler, and it carries on. It returns
    /// [`Error::Closed`] once the session is closed.
    pub fn receive(&self) -> Result<(Spdu, SocketAddr)> {
        self.receive_until(None)?.ok_or(Error::Closed)
    }

    /// Like [`receive`](Session::receive), giving up with `Ok(None)` after
    /// `timeout`.
    pub fn receive_timeout(&self, timeout: Duration) -> Result<Option<(Spdu, SocketAddr)>> {
        self.receive_until(Some(Instant::now() + timeout))
    }

    fn receive_until(&self, deadline: Option<Instant>) -> Result<Option<(Spdu, SocketAddr)>> {
        let Some(rx) = &self.rx else {
            return Err(Error::NotListening);
        };
        let rx = rx.lock().unwrap();
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(Error::Closed);
            }
            let wait = match deadline {
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Ok(None);
                    }
                    left.min(POLL)
                }
                None => POLL,
            };
            let (b, from) = match rx.recv_timeout(wait) {
                Ok(d) => d,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => return Err(Error::Closed),
            };
            match self.check(&b, from) {
                Ok(spdu) => {
                    self.stats.accepted.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some((spdu, from)));
                }
                Err(err) => {
                    if let Some(h) = &self.cfg.on_reject {
                        h(&Reject { from, err });
                    }
                }
            }
        }
    }

    /// Decodes and verifies one datagram against the session's keys and
    /// policy.
    fn check(&self, b: &[u8], from: SocketAddr) -> Result<Spdu> {
        let spdu = match unmarshal(b, self.cfg.keys.as_deref()) {
            Ok(s) => s,
            Err(e) => {
                let counter = match e {
                    Error::UnknownKey(_) => &self.stats.unknown_key,
                    Error::Authentication(_) | Error::Algorithm(_) => &self.stats.unauthentic,
                    _ => &self.stats.malformed,
                };
                counter.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        if spdu.key_id == 0 {
            if !self.cfg.allow_unsecured {
                self.stats.unsecured.fetch_add(1, Ordering::Relaxed);
                return Err(Error::Unsecured);
            }
            return Ok(spdu);
        }
        if self.cfg.replay_window > 0 && !self.fresh(from, &spdu) {
            self.stats.replayed.fetch_add(1, Ordering::Relaxed);
            return Err(Error::Replay(format!("number {} from {from}", spdu.number)));
        }
        Ok(spdu)
    }

    fn fresh(&self, from: SocketAddr, spdu: &Spdu) -> bool {
        let k = StreamKey {
            from,
            si: spdu.si,
            key_id: spdu.key_id,
        };
        let now = Instant::now();
        let mut replay = self.replay.lock().unwrap();
        if !replay.contains_key(&k) && replay.len() >= MAX_STREAMS {
            if let Some(reset) = self.replay_reset {
                replay.retain(|_, w| w.last().is_some_and(|l| now.saturating_duration_since(l) <= reset));
            }
        }
        replay.entry(k).or_default().accept(
            spdu.number,
            now,
            self.cfg.replay_window as u32,
            self.replay_reset,
        )
    }

    /// Returns the session's receive counters.
    pub fn stats(&self) -> Stats {
        let s = &self.stats;
        Stats {
            accepted: s.accepted.load(Ordering::Relaxed),
            malformed: s.malformed.load(Ordering::Relaxed),
            unknown_key: s.unknown_key.load(Ordering::Relaxed),
            unauthentic: s.unauthentic.load(Ordering::Relaxed),
            unsecured: s.unsecured.load(Ordering::Relaxed),
            replayed: s.replayed.load(Ordering::Relaxed),
        }
    }

    /// Stops receiving and unblocks [`receive`](Session::receive) and
    /// `read_frame`.
    pub fn shutdown(&self) {
        self.closed.store(true, Ordering::SeqCst);
        for h in self.readers.lock().unwrap().drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Opens a socket bound to a multicast group's port and joined to it.
fn join_group(ga: SocketAddr, ifi: Option<(u32, Option<Ipv4Addr>)>) -> std::io::Result<UdpSocket> {
    let domain = if ga.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    sock.set_reuse_port(true)?;
    match ga.ip() {
        IpAddr::V4(g) => {
            // Bound to the group itself, so the socket receives only what is
            // sent to it, as Go's ListenMulticastUDP does.
            sock.bind(&SockAddr::from(SocketAddr::new(IpAddr::V4(g), ga.port())))?;
            let iface = ifi.and_then(|(_, a)| a).unwrap_or(Ipv4Addr::UNSPECIFIED);
            sock.join_multicast_v4(&g, &iface)?;
        }
        IpAddr::V6(g) => {
            sock.bind(&SockAddr::from(SocketAddr::new(IpAddr::V6(g), ga.port())))?;
            sock.join_multicast_v6(&g, ifi.map_or(0, |(i, _)| i))?;
        }
    }
    Ok(sock.into())
}

/// Feeds the datagrams of one socket to the session until it closes.
fn read_loop(sock: UdpSocket, tx: SyncSender<Datagram>, closed: Arc<AtomicBool>) {
    let mut buf = vec![0u8; 65536];
    while !closed.load(Ordering::SeqCst) {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if tx.send((buf[..n].to_vec(), from)).is_err() {
                    return;
                }
            }
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(_) => std::thread::sleep(POLL),
        }
    }
}

/// The frame header of a GOOSE or SV APDU on Ethernet: APPID, length, two
/// reserved words, the first of which carries the simulation bit.
const L2_HEADER: usize = 8;
const SIM_BIT: u16 = 0x8000;

impl Interface for Session {
    /// Sends a GOOSE or SV frame as an SPDU: the APDU without its layer-2
    /// header is the payload, and the APPID and the simulation bit of
    /// Reserved 1 go in the session's payload element. The addresses and VLAN
    /// of the frame are not used; the session's remote address is.
    fn write_frame(&self, f: &Frame) -> ethernet::Result<()> {
        let (si, kind) = match f.ether_type {
            ETHER_TYPE_GOOSE => (SessionId::GOOSE, PayloadType::GOOSE),
            ETHER_TYPE_SV => (SessionId::SV, PayloadType::SV),
            t => {
                return Err(ethernet::Error::Frame(format!(
                    "EtherType {t:#06x} is neither GOOSE nor SV"
                )))
            }
        };
        let p = &f.payload;
        if p.len() < L2_HEADER {
            return Err(ethernet::Error::Frame(format!("frame payload of {} octets", p.len())));
        }
        let mut length = usize::from(u16::from_be_bytes([p[2], p[3]]));
        if length < L2_HEADER || length > p.len() {
            length = p.len();
        }
        self.send(
            si,
            vec![Payload {
                kind,
                simulation: u16::from_be_bytes([p[4], p[5]]) & SIM_BIT != 0,
                app_id: u16::from_be_bytes([p[0], p[1]]),
                apdu: p[L2_HEADER..length].to_vec(),
            }],
        )
        .map_err(|e| match e {
            Error::Io(io) => ethernet::Error::Io(io),
            other => ethernet::Error::Frame(other.to_string()),
        })
    }

    /// Returns the next GOOSE or SV payload received, as a frame of its
    /// EtherType with the layer-2 header rebuilt from the session's payload
    /// element. Payloads of other types are skipped, and so are SPDUs the
    /// session refuses.
    fn read_frame(&self) -> ethernet::Result<Frame> {
        loop {
            if let Some(f) = self.pending.lock().unwrap().pop_front() {
                return Ok(f);
            }
            let (spdu, _) = self.receive().map_err(|e| match e {
                Error::Closed => ethernet::Error::Closed,
                other => ethernet::Error::Frame(other.to_string()),
            })?;
            let mut frames: VecDeque<Frame> = spdu
                .payloads
                .into_iter()
                .filter_map(|p| {
                    let ether_type = match p.kind {
                        PayloadType::GOOSE => ETHER_TYPE_GOOSE,
                        PayloadType::SV => ETHER_TYPE_SV,
                        _ => return None,
                    };
                    let length = L2_HEADER + p.apdu.len();
                    let length16 = u16::try_from(length).ok()?;
                    let r1 = if p.simulation { SIM_BIT } else { 0 };
                    let mut b = Vec::with_capacity(length);
                    b.extend_from_slice(&p.app_id.to_be_bytes());
                    b.extend_from_slice(&length16.to_be_bytes());
                    b.extend_from_slice(&r1.to_be_bytes());
                    b.extend_from_slice(&[0, 0]);
                    b.extend_from_slice(&p.apdu);
                    Some(Frame {
                        src: [0; 6],
                        dst: [0; 6],
                        ether_type,
                        vlan: None,
                        payload: b,
                    })
                })
                .collect();
            let Some(first) = frames.pop_front() else {
                continue;
            };
            self.pending.lock().unwrap().extend(frames);
            return Ok(first);
        }
    }

    fn close(&self) -> ethernet::Result<()> {
        self.shutdown();
        Ok(())
    }
}
