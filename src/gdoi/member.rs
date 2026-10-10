//! A group member's registration with a key server: IKE main mode as
//! initiator, then GROUPKEY-PULL.

use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use super::crypto::{
    constant_eq, phase1_iv, prf, random_bytes, sign, verify, Dh, Keys, Suite, AUTH_PSK, DEFAULT_SUITES,
};
use super::exchange::{
    cert_payloads, hashed, message, open, parse_certs, parse_phase1_sa, phase1_sa_body, random_cookie,
    random_msg_id, read_informational, AuthorizeServerFn, Credentials, Peer, DEFAULT_PORT, NONCE_LEN,
};
use super::isakmp::{
    encode_chain, find, malformed, parse_header, parse_id, Header, Payload, MAX_MESSAGE, P_HASH, P_ID, P_KD, P_KE,
    P_NONCE, P_NONE, P_SA, P_SIG, XCHG_INFO, XCHG_MAIN, XCHG_PULL,
};
use super::tek::{parse_kd, parse_sa, GroupId, Tek};
use super::{Error, Result};

/// Configures a group member's registrations with a key server (the GCKS).
#[derive(Clone, Default)]
pub struct MemberConfig {
    /// The key server, `host:port` (port 848 when omitted).
    pub server: String,
    /// Authenticate this member to the key server and the key server to it.
    pub credentials: Credentials,
    /// Decides whether the authenticated key server is one this member takes
    /// keys from: RFC 6407 requires a member to list its authorised key
    /// servers, since any peer the roots vouch for could otherwise hand it
    /// keys. Required with certificate credentials. With a pre-shared key,
    /// holding the key is the authorisation, and `None` accepts it.
    pub authorize_server: Option<AuthorizeServerFn>,
    /// The phase 1 algorithms offered, in order of preference
    /// ([`DEFAULT_SUITES`] when empty).
    pub suites: Vec<Suite>,
    /// How long to wait for a reply before sending a request again (1 s when
    /// zero), and how many times to send it (4 when zero).
    pub retransmit: Duration,
    pub attempts: u32,
}

impl std::fmt::Debug for MemberConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemberConfig")
            .field("server", &self.server)
            .field("credentials", &self.credentials)
            .field("authorize_server", &self.authorize_server.is_some())
            .field("suites", &self.suites)
            .field("retransmit", &self.retransmit)
            .field("attempts", &self.attempts)
            .finish()
    }
}

impl MemberConfig {
    fn check(&self) -> Result<u16> {
        let auth = self.credentials.auth_method()?;
        if auth != AUTH_PSK && self.authorize_server.is_none() {
            return Err(Error::Config(
                "MemberConfig::authorize_server is required with certificate credentials".into(),
            ));
        }
        if let Some(s) = self.suites.iter().find(|s| !s.valid()) {
            return Err(Error::Config(format!("suite {s:?} is not supported")));
        }
        Ok(auth)
    }
}

/// The result of one GROUPKEY-PULL: the group's current TEKs, the key server
/// that issued them, and when.
#[derive(Debug, Clone)]
pub struct Registration {
    pub group: GroupId,
    pub server: Peer,
    pub teks: Vec<Tek>,
    pub received: Instant,
}

/// Runs one registration: a phase 1 exchange authenticating the member and
/// the key server to each other (IKE main mode, RFC 2409), then a
/// GROUPKEY-PULL for `group` (RFC 6407 3), and returns the group's TEKs.
///
/// Dropping the future abandons the registration; bound it with
/// `tokio::time::timeout` to give it a deadline.
pub async fn register(cfg: &MemberConfig, group: &GroupId) -> Result<Registration> {
    let auth = cfg.check()?;
    let mut cfg = cfg.clone();
    if cfg.suites.is_empty() {
        cfg.suites = DEFAULT_SUITES.to_vec();
    }
    if cfg.retransmit.is_zero() {
        cfg.retransmit = Duration::from_secs(1);
    }
    if cfg.attempts == 0 {
        cfg.attempts = 4;
    }
    let addr = with_default_port(&cfg.server);
    let remote = tokio::net::lookup_host(&addr)
        .await?
        .next()
        .ok_or_else(|| Error::Config(format!("{addr} does not resolve")))?;
    let local: std::net::SocketAddr = if remote.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("an address");
    let conn = UdpSocket::bind(local).await?;
    conn.connect(remote).await?;
    let mut m = Initiator {
        cfg,
        auth,
        conn,
        ic: [0; 8],
        rc: [0; 8],
        keys: None,
    };
    let peer = m.phase1().await?;
    let teks = m.pull(group).await?;
    Ok(Registration {
        group: group.clone(),
        server: peer,
        teks,
        received: Instant::now(),
    })
}

struct Initiator {
    cfg: MemberConfig,
    auth: u16,
    conn: UdpSocket,
    ic: [u8; 8],
    rc: [u8; 8],
    keys: Option<Keys>,
}

impl Initiator {
    /// Sends `req` until a reply `accept` takes arrives, or an informational
    /// message refusing the exchange. Replies to other exchanges are ignored.
    async fn round_trip(&self, req: &[u8], accept: impl Fn(&Header) -> bool) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_MESSAGE];
        for _ in 0..self.cfg.attempts {
            self.conn.send(req).await?;
            let deadline = tokio::time::Instant::now() + self.cfg.retransmit;
            loop {
                let n = match tokio::time::timeout_at(deadline, self.conn.recv(&mut buf)).await {
                    Err(_) => break,
                    // An ICMP unreachable from a previous send surfaces here;
                    // the retransmission carries on.
                    Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
                    Ok(Err(e)) => return Err(e.into()),
                    Ok(Ok(n)) => n,
                };
                let msg = &buf[..n];
                let Ok(h) = parse_header(msg) else { continue };
                if h.ic != self.ic {
                    continue;
                }
                if h.exchange == XCHG_INFO {
                    if let Ok(t) = read_informational(self.keys.as_ref(), msg) {
                        return Err(Error::Notify(t));
                    }
                    continue;
                }
                if accept(&h) {
                    return Ok(msg.to_vec());
                }
            }
        }
        Err(Error::Timeout)
    }

    /// Runs main mode as initiator.
    async fn phase1(&mut self) -> Result<Peer> {
        self.ic = random_cookie();
        let sa_i = phase1_sa_body(&self.cfg.suites, self.auth);
        let msg1 = message(
            Header {
                ic: self.ic,
                exchange: XCHG_MAIN,
                ..Default::default()
            },
            &[Payload::new(P_SA, sa_i.clone())],
        );
        let resp = self
            .round_trip(&msg1, |h| h.exchange == XCHG_MAIN && h.rc != [0; 8] && !h.encrypted())
            .await?;
        let o = open(None, &resp, &[])?;
        self.rc = o.header.rc;
        let sa = find(&o.payloads, P_SA).ok_or_else(|| malformed("main mode reply without an SA"))?;
        let chosen = parse_phase1_sa(&sa.body)?;
        if chosen.len() != 1 || !offered(&sa_i, &chosen[0].body) {
            return Err(Error::Auth("key server chose a transform that was not offered".into()));
        }
        let suite = chosen[0].suite;

        let dh = Dh::new(suite.group)?;
        let ni = random_bytes(NONCE_LEN);
        let hdr = Header {
            ic: self.ic,
            rc: self.rc,
            exchange: XCHG_MAIN,
            ..Default::default()
        };
        let msg3 = message(hdr, &[Payload::new(P_KE, dh.public().to_vec()), Payload::new(P_NONCE, ni.clone())]);
        let rc = self.rc;
        let resp = self
            .round_trip(&msg3, |h| h.exchange == XCHG_MAIN && h.rc == rc && !h.encrypted() && h.next != P_SA)
            .await?;
        let o = open(None, &resp, &[])?;
        let (Some(ke), Some(nonce)) = (find(&o.payloads, P_KE), find(&o.payloads, P_NONCE)) else {
            return Err(malformed("main mode reply without KE and nonce"));
        };
        let nr = &nonce.body;
        if nr.len() < 8 || nr.len() > 256 {
            return Err(malformed(format!("nonce of {} octets", nr.len())));
        }
        let gxy = dh.shared(&ke.body)?;
        let hf = suite.hash_alg();
        let skeyid = if self.auth == AUTH_PSK {
            prf(hf, &self.cfg.credentials.psk, &[&ni, nr])
        } else {
            prf(hf, &[ni.as_slice(), nr].concat(), &[&gxy])
        };
        let keys = Keys::derive(suite, &skeyid, &gxy, &self.ic, &self.rc)?;

        let idii = self.cfg.credentials.own_id(self.conn.local_addr().ok())?;
        let hash_i = prf(hf, &skeyid, &[dh.public(), &ke.body, &self.ic, &self.rc, &sa_i, &idii.body()]);
        let mut ps5 = vec![Payload::new(P_ID, idii.body())];
        if self.auth == AUTH_PSK {
            ps5.push(Payload::new(P_HASH, hash_i));
        } else {
            let key = self.cfg.credentials.key.as_ref().expect("checked by auth_method");
            ps5.extend(cert_payloads(&self.cfg.credentials.certificates));
            ps5.push(Payload::new(P_SIG, sign(self.auth, key, &hash_i)?));
        }
        let (msg5, iv) = keys.sealed(hdr, &ps5, &phase1_iv(hf, dh.public(), &ke.body));
        self.keys = Some(keys);
        let resp = self
            .round_trip(&msg5, |h| h.exchange == XCHG_MAIN && h.rc == rc && h.encrypted())
            .await?;
        let o = open(self.keys.as_ref(), &resp, &iv)?;
        self.keys.as_mut().expect("set above").phase1_last = Some(o.next_iv.clone());
        let idp = find(&o.payloads, P_ID).ok_or_else(|| malformed("main mode reply without identification"))?;
        let idir = parse_id(&idp.body)?;
        let hash_r = prf(hf, &skeyid, &[&ke.body, dh.public(), &self.rc, &self.ic, &sa_i, &idir.body()]);
        let mut peer = Peer {
            addr: self.conn.peer_addr()?,
            id_type: idir.kind,
            id: idir.data.clone(),
            certificate: None,
            common_name: None,
        };
        if self.auth == AUTH_PSK {
            match find(&o.payloads, P_HASH) {
                Some(hp) if constant_eq(&hp.body, &hash_r) => {}
                _ => return Err(Error::Auth("key server failed pre-shared key authentication".into())),
            }
        } else {
            let certs = parse_certs(&o.payloads)?;
            let leaf = self.cfg.credentials.verify_peer(&idir, &certs)?;
            let sp = find(&o.payloads, P_SIG).ok_or_else(|| malformed("main mode reply without a signature"))?;
            verify(self.auth, &leaf.public_key, &hash_r, &sp.body)
                .map_err(|e| Error::Auth(format!("key server signature: {e}")))?;
            peer.certificate = Some(certs[0].clone());
            peer.common_name = leaf.common_name;
        }
        if let Some(authorize) = &self.cfg.authorize_server {
            authorize(&peer).map_err(|e| Error::Auth(format!("key server {peer} not authorised: {e}")))?;
        }
        Ok(peer)
    }

    /// Runs the GROUPKEY-PULL exchange (RFC 6407 figure 2).
    async fn pull(&mut self, group: &GroupId) -> Result<Vec<Tek>> {
        let id = group.id()?;
        let k = self.keys.as_ref().expect("phase 1 completed");
        let mid = random_msg_id();
        let mb = mid.to_be_bytes();
        let hdr = Header {
            ic: self.ic,
            rc: self.rc,
            exchange: XCHG_PULL,
            msg_id: mid,
            ..Default::default()
        };
        let (a, hf) = (k.a.clone(), k.hash);
        let ni = random_bytes(NONCE_LEN);
        let rest = [Payload::new(P_NONCE, ni.clone()), Payload::new(P_ID, id.body())];
        let h1 = prf(hf, &a, &[&mb, &encode_chain(&rest, P_NONE)]);
        let mut ps1 = vec![Payload::new(P_HASH, h1)];
        ps1.extend(rest);
        let (msg1, iv) = k.sealed(hdr, &ps1, &k.phase2_iv(mid));
        let rc = self.rc;
        let accept = move |h: &Header| h.exchange == XCHG_PULL && h.msg_id == mid && h.rc == rc && h.encrypted();
        let resp = self.round_trip(&msg1, accept).await?;
        let k = self.keys.as_ref().expect("phase 1 completed");
        let o = open(Some(k), &resp, &iv)?;
        let (hp, rest2, covered) = hashed(&o)?;
        if !constant_eq(&hp.body, &prf(hf, &a, &[&mb, &ni, covered])) {
            return Err(Error::Auth("HASH(2) does not verify".into()));
        }
        let (Some(nonce), Some(sa)) = (find(rest2, P_NONCE), find(rest2, P_SA)) else {
            return Err(malformed("GROUPKEY-PULL reply without nonce and SA"));
        };
        let nr = nonce.body.clone();
        if nr.len() < 8 || nr.len() > 128 {
            return Err(malformed(format!("nonce of {} octets", nr.len())));
        }
        let policy = parse_sa(&sa.body)?;
        if policy.is_empty() {
            return Err(Error::Policy("the group's policy has no IEC 61850 TEK".into()));
        }

        let h3 = prf(hf, &a, &[&mb, &ni, &nr]);
        let (msg3, iv) = k.sealed(hdr, &[Payload::new(P_HASH, h3)], &o.next_iv);
        let resp = self.round_trip(&msg3, accept).await?;
        let k = self.keys.as_ref().expect("phase 1 completed");
        let o = open(Some(k), &resp, &iv)?;
        let (hp, rest4, covered) = hashed(&o)?;
        if !constant_eq(&hp.body, &prf(hf, &a, &[&mb, &ni, &nr, covered])) {
            return Err(Error::Auth("HASH(4) does not verify".into()));
        }
        let kd = find(rest4, P_KD).ok_or_else(|| malformed("GROUPKEY-PULL reply without key download"))?;
        let material = parse_kd(&kd.body)?;
        let mut teks = Vec::with_capacity(policy.len());
        for mut t in policy {
            let kp = material
                .get(&t.spi)
                .ok_or_else(|| Error::Policy(format!("no keys for TEK {}", t.spi)))?;
            t.algorithm_key = kp.algorithm.clone();
            t.integrity_key = kp.integrity.clone();
            t.check_policy()?;
            teks.push(t);
        }
        Ok(teks)
    }
}

/// Appends the GDOI port to an address that names none: `host`, `1.2.3.4`,
/// `::1` or `[::1]`.
fn with_default_port(addr: &str) -> String {
    if addr.parse::<std::net::SocketAddr>().is_ok() {
        return addr.to_string();
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() && !host.contains(':') => addr.to_string(),
        _ if addr.contains(':') && !addr.starts_with('[') => format!("[{addr}]:{DEFAULT_PORT}"),
        _ => format!("{addr}:{DEFAULT_PORT}"),
    }
}

/// Reports whether a transform body is one of those in the SA the member
/// sent: a responder must return an offer unchanged.
fn offered(sa_i: &[u8], body: &[u8]) -> bool {
    parse_phase1_sa(sa_i).is_ok_and(|ts| ts.iter().any(|t| t.body == body))
}
