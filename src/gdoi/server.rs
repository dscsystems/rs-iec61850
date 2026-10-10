//! The key server (group controller/key server, GCKS): IKE main mode as
//! responder and GROUPKEY-PULL for its groups, over UDP.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use super::crypto::{
    constant_eq, phase1_iv, prf, random_bytes, sign, verify, Dh, Keys, Suite, AUTH_PSK, DEFAULT_SUITES,
};
use super::exchange::{
    cert_payloads, hashed, informational, message, open, parse_certs, parse_phase1_sa, phase1_sa_with_doi,
    random_cookie, AuthorizeFn, Credentials, Peer, DEFAULT_PORT, NONCE_LEN,
};
use super::isakmp::{
    encode_chain, find, malformed, parse_header, parse_id, Header, Payload, MAX_MESSAGE, NOTIFY_AUTH_FAILED,
    NOTIFY_INVALID_CERT, NOTIFY_INVALID_HASH_INFO, NOTIFY_INVALID_ID_INFO, NOTIFY_INVALID_SIGNATURE,
    NOTIFY_NO_PROPOSAL_CHOSEN, P_HASH, P_ID, P_KD, P_KE, P_NONCE, P_NONE, P_SA, P_SIG, P_TRANS, XCHG_INFO, XCHG_MAIN,
    XCHG_PULL,
};
use super::tek::{kd_body, sa_body, GroupId, Tek};
use super::{Error, Result};

/// The policy and keys a key server hands out for one group: its TEKs, each
/// with the time it becomes usable and the time it expires.
///
/// A key rotation adds the next TEK with an activation delay, so members that
/// register before the change hold both, and removes the old one once it has
/// expired. Safe for concurrent use.
#[derive(Debug, Default)]
pub struct Group {
    teks: Mutex<Vec<GroupTek>>,
}

#[derive(Debug)]
struct GroupTek {
    tek: Tek,
    activates: Instant,
    expires: Option<Instant>,
}

impl Group {
    pub fn new() -> Group {
        Group::default()
    }

    /// Adds a TEK to the group. Its activation delay and lifetime count from
    /// now. A TEK whose SPI the group already uses is refused.
    pub fn add(&self, t: Tek) -> Result<()> {
        t.check_policy()?;
        let now = Instant::now();
        let mut teks = self.teks.lock().unwrap();
        if teks.iter().any(|x| x.tek.spi == t.spi) {
            return Err(Error::Policy(format!("SPI {} is already in use in the group", t.spi)));
        }
        teks.push(GroupTek {
            activates: now + t.activation_delay,
            expires: (!t.lifetime.is_zero()).then(|| now + t.lifetime),
            tek: t,
        });
        Ok(())
    }

    /// Withdraws the TEK with the given SPI: members stop receiving it at
    /// their next registration, and drop it then.
    pub fn remove(&self, spi: u32) {
        self.teks.lock().unwrap().retain(|x| x.tek.spi != spi);
    }

    /// Returns the TEKs still valid at `now`, with the lifetime and activation
    /// delay they have left, soonest activation first. Expired ones are
    /// dropped from the group.
    pub fn snapshot(&self, now: Instant) -> Vec<Tek> {
        let mut teks = self.teks.lock().unwrap();
        teks.retain(|x| x.expires.is_none_or(|e| now < e));
        let mut out: Vec<Tek> = teks
            .iter()
            .map(|x| Tek {
                activation_delay: x.activates.saturating_duration_since(now),
                lifetime: x.expires.map_or(Duration::ZERO, |e| e - now),
                ..x.tek.clone()
            })
            .collect();
        out.sort_by_key(|t| t.activation_delay);
        out
    }
}

/// Returns the pre-shared key of the member at an address.
pub type PskFn = Arc<dyn Fn(SocketAddr) -> Option<Vec<u8>> + Send + Sync>;
/// Told of every completed registration.
pub type RegisterFn = Arc<dyn Fn(&Peer, &GroupId, &[Tek]) + Send + Sync>;
/// Told of every refused message or registration.
pub type RejectFn = Arc<dyn Fn(SocketAddr, &Error) + Send + Sync>;

/// Configures a key server.
#[derive(Clone, Default)]
pub struct ServerConfig {
    /// Authenticate the key server to members, and members to it. Certificate
    /// credentials serve members that authenticate with certificates; `psk`
    /// serves members with pre-shared keys; both may be set. The credentials'
    /// own `psk` is not used by a server.
    pub credentials: Credentials,
    /// Returns the pre-shared key of the member at an address, `None` when it
    /// has none. Main mode commits to the key before the member names itself,
    /// so the address is all there is to choose by.
    pub psk: Option<PskFn>,
    /// Decides whether an authenticated member may have a group's keys (RFC
    /// 6407 3.1). Required: a key server hands keys only to members it has
    /// been told to.
    pub authorize: Option<AuthorizeFn>,
    /// The phase 1 algorithms accepted ([`DEFAULT_SUITES`] when empty); a
    /// member's first offer among them is chosen.
    pub suites: Vec<Suite>,
    /// Told of every completed registration, and of every refused one, for
    /// the security event log. They must not block.
    pub on_register: Option<RegisterFn>,
    pub on_reject: Option<RejectFn>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("credentials", &self.credentials)
            .field("psk", &self.psk.is_some())
            .field("authorize", &self.authorize.is_some())
            .field("suites", &self.suites)
            .finish_non_exhaustive()
    }
}

/// Bounds the phase 1 states kept; beyond it the least recently active are
/// dropped.
const MAX_PEERS: usize = 4096;

/// How long a phase 1 state is kept after its last message.
const PEER_TTL: Duration = Duration::from_secs(120);

/// A GDOI key server serving GROUPKEY-PULL registrations for its groups over
/// UDP. Clone it to share it; the clones serve the same groups.
#[derive(Clone)]
pub struct Server {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    cfg: ServerConfig,
    /// The signature method of the certificate credentials, 0 without.
    sig_method: u16,
    state: Mutex<ServerState>,
}

#[derive(Default)]
struct ServerState {
    groups: HashMap<GroupId, Arc<Group>>,
    peers: HashMap<[u8; 8], Responder>,
    local: Option<SocketAddr>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.inner.state.lock().unwrap();
        f.debug_struct("Server")
            .field("groups", &state.groups.keys().collect::<Vec<_>>())
            .field("peers", &state.peers.len())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Returns a key server.
    pub fn new(mut cfg: ServerConfig) -> Result<Server> {
        if cfg.authorize.is_none() {
            return Err(Error::Config("ServerConfig::authorize is required".into()));
        }
        let mut sig_method = 0;
        if let Some(key) = &cfg.credentials.key {
            if cfg.credentials.certificates.is_empty() || cfg.credentials.roots.is_empty() {
                return Err(Error::Config("certificate credentials need a certificate and roots".into()));
            }
            sig_method = key.auth_method()?;
        }
        if sig_method == 0 && cfg.psk.is_none() {
            return Err(Error::Config("a key server needs certificate credentials or a PSK function".into()));
        }
        if cfg.suites.is_empty() {
            cfg.suites = DEFAULT_SUITES.to_vec();
        }
        Ok(Server {
            inner: Arc::new(ServerInner {
                cfg,
                sig_method,
                state: Mutex::new(ServerState::default()),
            }),
        })
    }

    /// Serves `id` with the TEKs of `g`.
    pub fn add_group(&self, id: GroupId, g: Arc<Group>) {
        self.inner.state.lock().unwrap().groups.insert(id, g);
    }

    /// Binds `addr` (`0.0.0.0:848` when empty) and serves on it.
    pub async fn listen_and_serve(&self, addr: &str) -> Result<()> {
        let addr = if addr.is_empty() { format!("0.0.0.0:{DEFAULT_PORT}") } else { addr.to_string() };
        self.serve(UdpSocket::bind(addr).await?).await
    }

    /// Serves registrations on `sock` until the future is dropped or the
    /// socket fails.
    pub async fn serve(&self, sock: UdpSocket) -> Result<()> {
        self.inner.state.lock().unwrap().local = sock.local_addr().ok();
        let mut buf = vec![0u8; MAX_MESSAGE];
        loop {
            let (n, addr) = match sock.recv_from(&mut buf).await {
                Ok(r) => r,
                // A member gone away surfaces as an ICMP error on some systems.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                Err(e) => return Err(e.into()),
            };
            if let Some(resp) = self.handle(&buf[..n], addr) {
                let _ = sock.send_to(&resp, addr).await;
            }
        }
    }

    fn reject(&self, addr: SocketAddr, err: &Error) {
        if let Some(h) = &self.inner.cfg.on_reject {
            h(addr, err);
        }
    }

    /// Processes one datagram and returns the reply, if any.
    pub(crate) fn handle(&self, msg: &[u8], addr: SocketAddr) -> Option<Vec<u8>> {
        let h = match parse_header(msg) {
            Ok(h) => h,
            Err(e) => {
                self.reject(addr, &e);
                return None;
            }
        };
        let now = Instant::now();
        let mut state = self.inner.state.lock().unwrap();
        let state = &mut *state;
        let created = !state.peers.contains_key(&h.ic);
        if created {
            if h.exchange != XCHG_MAIN || h.rc != [0; 8] {
                return None; // not ours, or long forgotten
            }
            expire(&mut state.peers, now);
            state.peers.insert(
                h.ic,
                Responder {
                    addr,
                    ic: h.ic,
                    rc: random_cookie(),
                    state: Stage::Sa,
                    touched: now,
                    sa_i: Vec::new(),
                    suite: DEFAULT_SUITES[0],
                    auth: 0,
                    psk: Vec::new(),
                    dh: None,
                    gxi: Vec::new(),
                    skeyid: Vec::new(),
                    keys: None,
                    iv: Vec::new(),
                    peer: None,
                    last_req: Vec::new(),
                    last_resp: Vec::new(),
                    pulls: HashMap::new(),
                },
            );
        }
        let r = state.peers.get_mut(&h.ic).expect("present");
        if r.addr != addr {
            return None;
        }
        if !r.last_req.is_empty() && msg == r.last_req.as_slice() {
            // A retransmitted request gets the reply it had; a retransmitted
            // message 1 still carries no responder cookie.
            r.touched = now;
            return Some(r.last_resp.clone());
        }
        if !created && h.rc != r.rc {
            return None;
        }
        r.touched = now;
        let ctx = Ctx {
            inner: &self.inner,
            groups: &state.groups,
            local: state.local,
        };
        match r.step(&ctx, &h, msg) {
            Ok(resp) => {
                if let Some(resp) = &resp {
                    r.last_req = msg.to_vec();
                    r.last_resp = resp.clone();
                }
                resp
            }
            Err(err) => {
                self.reject(addr, &err);
                let resp = match &err {
                    Error::Refused(n, _) => {
                        // Before phase 1 completes a notification goes in the
                        // clear (RFC 2409 5.7); after, it is protected.
                        let keys = (r.state == Stage::Established).then_some(r.keys.as_ref()).flatten();
                        Some(informational(keys, r.ic, r.rc, *n))
                    }
                    _ => None,
                };
                // A failed exchange is over: its state goes.
                if r.state != Stage::Established {
                    state.peers.remove(&h.ic);
                }
                resp
            }
        }
    }
}

/// Drops phase 1 states idle past the TTL, and the oldest when there are too
/// many.
fn expire(peers: &mut HashMap<[u8; 8], Responder>, now: Instant) {
    peers.retain(|_, r| now.duration_since(r.touched) <= PEER_TTL);
    while peers.len() >= MAX_PEERS {
        let oldest = peers.iter().min_by_key(|(_, r)| r.touched).map(|(k, _)| *k);
        match oldest {
            Some(k) => peers.remove(&k),
            None => break,
        };
    }
}

fn refuse(n: u16, msg: impl Into<String>) -> Error {
    Error::Refused(n, msg.into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Stage {
    /// Waiting for the key exchange.
    Sa,
    /// Waiting for the authentication.
    Ke,
    Established,
}

/// What a responder step needs of the server besides its own state.
struct Ctx<'a> {
    inner: &'a ServerInner,
    groups: &'a HashMap<GroupId, Arc<Group>>,
    local: Option<SocketAddr>,
}

/// The state of one member's phase 1 SA at the key server.
struct Responder {
    addr: SocketAddr,
    ic: [u8; 8],
    rc: [u8; 8],
    state: Stage,
    touched: Instant,

    sa_i: Vec<u8>,
    suite: Suite,
    auth: u16,
    psk: Vec<u8>,
    dh: Option<Dh>,
    gxi: Vec<u8>,
    skeyid: Vec<u8>,
    keys: Option<Keys>,
    iv: Vec<u8>,
    peer: Option<Peer>,

    last_req: Vec<u8>,
    last_resp: Vec<u8>,
    pulls: HashMap<u32, PullState>,
}

#[derive(Default)]
struct PullState {
    iv: Vec<u8>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    group: Option<GroupId>,
    teks: Vec<Tek>,
    done: bool,
    last_req: Vec<u8>,
    last_resp: Vec<u8>,
}

impl Responder {
    fn step(&mut self, ctx: &Ctx<'_>, h: &Header, msg: &[u8]) -> Result<Option<Vec<u8>>> {
        match (h.exchange, self.state) {
            (XCHG_MAIN, Stage::Sa) if h.rc == [0; 8] => self.main_sa(ctx, msg).map(Some),
            (XCHG_MAIN, Stage::Sa) => self.main_ke(msg).map(Some),
            (XCHG_MAIN, Stage::Ke) => self.main_auth(ctx, msg).map(Some),
            (XCHG_PULL, Stage::Established) => self.pull(ctx, h, msg).map(Some),
            (XCHG_INFO, _) => Ok(None),
            (x, s) => Err(malformed(format!("unexpected exchange {x} in state {s:?}"))),
        }
    }

    fn header(&self, exchange: u8, msg_id: u32) -> Header {
        Header {
            ic: self.ic,
            rc: self.rc,
            exchange,
            msg_id,
            ..Default::default()
        }
    }

    /// Answers main mode message 1: the member's first offer the server
    /// accepts, returned unchanged.
    fn main_sa(&mut self, ctx: &Ctx<'_>, msg: &[u8]) -> Result<Vec<u8>> {
        let o = open(None, msg, &[])?;
        let sa = find(&o.payloads, P_SA).ok_or_else(|| malformed("main mode request without an SA"))?;
        for t in parse_phase1_sa(&sa.body)? {
            if !ctx.inner.cfg.suites.contains(&t.suite) {
                continue;
            }
            if t.auth == AUTH_PSK {
                let Some(psk) = ctx.inner.cfg.psk.as_ref().and_then(|f| f(self.addr)) else {
                    continue;
                };
                if psk.is_empty() {
                    continue;
                }
                self.psk = psk;
            } else if t.auth != ctx.inner.sig_method {
                continue;
            }
            self.sa_i = sa.body.clone();
            self.suite = t.suite;
            self.auth = t.auth;
            // The reply carries the initiator's DOI with its chosen transform.
            let doi = u32::from_be_bytes([sa.body[0], sa.body[1], sa.body[2], sa.body[3]]);
            let chosen = phase1_sa_with_doi(doi, &[Payload::new(P_TRANS, t.body)]);
            return Ok(message(self.header(XCHG_MAIN, 0), &[Payload::new(P_SA, chosen)]));
        }
        Err(refuse(NOTIFY_NO_PROPOSAL_CHOSEN, format!("no acceptable phase 1 proposal from {}", self.addr)))
    }

    /// Answers main mode message 3 with the server's key exchange value and
    /// nonce, and derives the keys.
    fn main_ke(&mut self, msg: &[u8]) -> Result<Vec<u8>> {
        let o = open(None, msg, &[])?;
        let (Some(ke), Some(nonce)) = (find(&o.payloads, P_KE), find(&o.payloads, P_NONCE)) else {
            return Err(malformed("main mode request without KE and nonce"));
        };
        if nonce.body.len() < 8 || nonce.body.len() > 256 {
            return Err(malformed(format!("nonce of {} octets", nonce.body.len())));
        }
        let dh = Dh::new(self.suite.group)?;
        let gxy = dh.shared(&ke.body)?;
        let (ni, nr) = (nonce.body.clone(), random_bytes(NONCE_LEN));
        let hf = self.suite.hash_alg();
        self.skeyid = if self.auth == AUTH_PSK {
            prf(hf, &self.psk, &[&ni, &nr])
        } else {
            prf(hf, &[ni.as_slice(), &nr].concat(), &[&gxy])
        };
        self.keys = Some(Keys::derive(self.suite, &self.skeyid, &gxy, &self.ic, &self.rc)?);
        self.gxi = ke.body.clone();
        self.iv = phase1_iv(hf, &self.gxi, dh.public());
        let resp = message(
            self.header(XCHG_MAIN, 0),
            &[Payload::new(P_KE, dh.public().to_vec()), Payload::new(P_NONCE, nr)],
        );
        self.dh = Some(dh);
        self.state = Stage::Ke;
        Ok(resp)
    }

    /// Checks the member's identity and authentication, and answers with the
    /// server's.
    fn main_auth(&mut self, ctx: &Ctx<'_>, msg: &[u8]) -> Result<Vec<u8>> {
        let k = self.keys.as_ref().expect("derived in main_ke");
        let dh = self.dh.as_ref().expect("made in main_ke");
        // Keys derived from a different pre-shared key decrypt the message
        // into garbage: that is how a wrong key shows.
        let o = open(Some(k), msg, &self.iv).map_err(|e| {
            refuse(NOTIFY_AUTH_FAILED, format!("member {}: message 5 does not decrypt: {e}", self.addr))
        })?;
        if !o.header.encrypted() {
            return Err(malformed("main mode authentication in the clear"));
        }
        let idp = find(&o.payloads, P_ID)
            .ok_or_else(|| refuse(NOTIFY_AUTH_FAILED, format!("member {}: message 5 without identification", self.addr)))?;
        let idii = parse_id(&idp.body).map_err(|e| refuse(NOTIFY_AUTH_FAILED, format!("member {}: {e}", self.addr)))?;
        let hf = k.hash;
        let hash_i = prf(hf, &self.skeyid, &[&self.gxi, dh.public(), &self.ic, &self.rc, &self.sa_i, &idii.body()]);
        let mut peer = Peer {
            addr: self.addr,
            id_type: idii.kind,
            id: idii.data.clone(),
            certificate: None,
            common_name: None,
        };
        if self.auth == AUTH_PSK {
            match find(&o.payloads, P_HASH) {
                Some(hp) if constant_eq(&hp.body, &hash_i) => {}
                _ => {
                    return Err(refuse(
                        NOTIFY_AUTH_FAILED,
                        format!("member {} failed pre-shared key authentication", self.addr),
                    ))
                }
            }
        } else {
            let certs = parse_certs(&o.payloads).map_err(|e| refuse(NOTIFY_INVALID_CERT, e.to_string()))?;
            let leaf = ctx
                .inner
                .cfg
                .credentials
                .verify_peer(&idii, &certs)
                .map_err(|e| refuse(NOTIFY_INVALID_CERT, format!("member {}: {e}", self.addr)))?;
            let sp = find(&o.payloads, P_SIG).ok_or_else(|| malformed("main mode request without a signature"))?;
            verify(self.auth, &leaf.public_key, &hash_i, &sp.body)
                .map_err(|e| refuse(NOTIFY_INVALID_SIGNATURE, format!("member {}: {e}", self.addr)))?;
            peer.certificate = Some(certs[0].clone());
            peer.common_name = leaf.common_name;
        }

        let idir = ctx.inner.cfg.credentials.own_id(ctx.local)?;
        let hash_r = prf(hf, &self.skeyid, &[dh.public(), &self.gxi, &self.rc, &self.ic, &self.sa_i, &idir.body()]);
        let mut out = vec![Payload::new(P_ID, idir.body())];
        if self.auth == AUTH_PSK {
            out.push(Payload::new(P_HASH, hash_r));
        } else {
            let key = ctx.inner.cfg.credentials.key.as_ref().expect("checked in Server::new");
            out.extend(cert_payloads(&ctx.inner.cfg.credentials.certificates));
            out.push(Payload::new(P_SIG, sign(self.auth, key, &hash_r)?));
        }
        let (resp, last) = k.sealed(self.header(XCHG_MAIN, 0), &out, &o.next_iv);
        self.keys.as_mut().expect("derived").phase1_last = Some(last);
        self.peer = Some(peer);
        self.state = Stage::Established;
        Ok(resp)
    }

    /// Serves the GROUPKEY-PULL exchange: message 1 with the group's policy,
    /// message 3 with its keys. Nothing about the member is recorded before
    /// message 3 proves it holds the server's nonce.
    fn pull(&mut self, ctx: &Ctx<'_>, h: &Header, msg: &[u8]) -> Result<Vec<u8>> {
        if let Some(p) = self.pulls.get(&h.msg_id) {
            if !p.last_req.is_empty() && msg == p.last_req.as_slice() {
                return Ok(p.last_resp.clone());
            }
            if p.done {
                return Err(malformed("message for a completed GROUPKEY-PULL"));
            }
        } else if self.pulls.len() >= 16 {
            return Err(malformed("too many GROUPKEY-PULL exchanges on one phase 1 SA"));
        }
        let k = self.keys.as_ref().expect("established");
        let mut p = self.pulls.remove(&h.msg_id).unwrap_or_else(|| PullState {
            iv: k.phase2_iv(h.msg_id),
            ..Default::default()
        });
        let result = self.pull_step(ctx, &mut p, h, msg);
        self.pulls.insert(h.msg_id, p);
        result
    }

    fn pull_step(&self, ctx: &Ctx<'_>, p: &mut PullState, h: &Header, msg: &[u8]) -> Result<Vec<u8>> {
        let k = self.keys.as_ref().expect("established");
        let o = open(Some(k), msg, &p.iv)?;
        let (hp, rest, covered) = hashed(&o)?;
        let (a, hf) = (&k.a, k.hash);
        let mid = h.msg_id.to_be_bytes();
        let hdr = self.header(XCHG_PULL, h.msg_id);
        let peer = self.peer.as_ref().expect("established");

        if p.ni.is_empty() {
            // Message 1: HASH(1) = prf(SKEYID_a, M-ID | Ni | ID).
            if !constant_eq(&hp.body, &prf(hf, a, &[&mid, covered])) {
                return Err(refuse(NOTIFY_INVALID_HASH_INFO, format!("HASH(1) from {} does not verify", self.addr)));
            }
            let (Some(nonce), Some(idp)) = (find(rest, P_NONCE), find(rest, P_ID)) else {
                return Err(malformed("GROUPKEY-PULL request without nonce and ID"));
            };
            if nonce.body.len() < 8 || nonce.body.len() > 128 {
                return Err(malformed(format!("nonce of {} octets", nonce.body.len())));
            }
            let id = parse_id(&idp.body)?;
            let group = GroupId::from_id(&id).map_err(|e| refuse(NOTIFY_INVALID_ID_INFO, e.to_string()))?;
            let g = ctx
                .groups
                .get(&group)
                .ok_or_else(|| refuse(NOTIFY_INVALID_ID_INFO, format!("{peer} asked for unknown {group}")))?;
            let authorize = ctx.inner.cfg.authorize.as_ref().expect("checked in Server::new");
            if !authorize(peer, &group) {
                return Err(refuse(NOTIFY_INVALID_ID_INFO, format!("{peer} is not authorised for {group}")));
            }
            let teks = g.snapshot(Instant::now());
            let sa = sa_body(&teks).map_err(|e| refuse(NOTIFY_INVALID_ID_INFO, format!("{group} has no keys: {e}")))?;
            p.ni = nonce.body.clone();
            p.nr = random_bytes(NONCE_LEN);
            p.group = Some(group);
            p.teks = teks;
            let out = [Payload::new(P_NONCE, p.nr.clone()), Payload::new(P_SA, sa)];
            let h2 = prf(hf, a, &[&mid, &p.ni, &encode_chain(&out, P_NONE)]);
            let mut ps = vec![Payload::new(P_HASH, h2)];
            ps.extend(out);
            let (resp, next) = k.sealed(hdr, &ps, &o.next_iv);
            p.iv = next;
            p.last_req = msg.to_vec();
            p.last_resp = resp.clone();
            return Ok(resp);
        }

        // Message 3: HASH(3) = prf(SKEYID_a, M-ID | Ni_b | Nr_b [| GAP]).
        if !constant_eq(&hp.body, &prf(hf, a, &[&mid, &p.ni, &p.nr, covered])) {
            return Err(refuse(NOTIFY_INVALID_HASH_INFO, format!("HASH(3) from {} does not verify", self.addr)));
        }
        let out = [Payload::new(P_KD, kd_body(&p.teks))];
        let h4 = prf(hf, a, &[&mid, &p.ni, &p.nr, &encode_chain(&out, P_NONE)]);
        let (resp, _) = k.sealed(hdr, &[Payload::new(P_HASH, h4), out[0].clone()], &o.next_iv);
        p.done = true;
        p.last_req = msg.to_vec();
        p.last_resp = resp.clone();
        if let (Some(f), Some(group)) = (&ctx.inner.cfg.on_register, &p.group) {
            f(peer, group, &p.teks);
        }
        // The state stays, so a retransmitted message 3 gets message 4 again;
        // anything else for this exchange is refused.
        Ok(resp)
    }
}
