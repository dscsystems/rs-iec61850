//! What the member and the key server share: credentials and peers, the phase
//! 1 SA payload, message protection, and informational exchanges.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};

use super::crypto::{constant_eq, prf, random_bytes, suite_from_attrs, Keys, PrivateKey, Suite, AUTH_PSK};
use super::isakmp::{
    encode_attrs, encode_chain, find, malformed, parse_attrs, parse_chain, parse_header, parse_notify, notify,
    Header, IdPayload, Payload, DOI_GDOI, FLAG_ENCRYPTED, HEADER_LEN, ID_DER_ASN1_DN, ID_IPV4_ADDR, ID_IPV6_ADDR,
    ID_KEY_ID, PROTO_ISAKMP, P_CERT, P_HASH, P_NONE, P_NOTIFY, P_PROPOSAL, P_TRANS, SIT_IDENTITY, TRANS_KEY_IKE,
    XCHG_INFO,
};
use super::{Error, Result};
use crate::x509;

/// The GDOI port (RFC 6407 2.2).
pub const DEFAULT_PORT: u16 = 848;

/// The lifetime proposed for the phase 1 SA. A registration uses its phase 1
/// SA once, so it only needs to outlive the exchange.
pub(crate) const PHASE1_LIFE: u32 = 3600;

/// The length of the nonces sent (RFC 6407 5.8: 8 to 128).
pub(crate) const NONCE_LEN: usize = 32;

/// Authenticates one end of the phase 1 exchange.
#[derive(Clone, Default)]
pub struct Credentials {
    /// This end's certificate chain, leaf first, DER. The leaf's subject is
    /// the phase 1 identity.
    pub certificates: Vec<CertificateDer<'static>>,
    /// The private key of the leaf: RSA (2048 bits or more) or ECDSA P-256 or
    /// P-384.
    pub key: Option<PrivateKey>,
    /// The authorities a peer's certificate must chain to.
    pub roots: Vec<CertificateDer<'static>>,
    /// On a group member, authenticates with a pre-shared key instead of a
    /// certificate. Main mode binds a pre-shared key to the peer's address, so
    /// a key server looks it up by address ([`ServerConfig::psk`](super::ServerConfig::psk)).
    pub psk: Vec<u8>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("certificates", &self.certificates.len())
            .field("key", &self.key)
            .field("roots", &self.roots.len())
            .field("psk", &!self.psk.is_empty())
            .finish()
    }
}

impl Credentials {
    pub(crate) fn auth_method(&self) -> Result<u16> {
        if !self.psk.is_empty() {
            if self.key.is_some() {
                return Err(Error::Config("credentials name both a pre-shared key and a certificate".into()));
            }
            return Ok(AUTH_PSK);
        }
        let Some(key) = &self.key else {
            return Err(Error::Config("credentials need a certificate and key, or a pre-shared key".into()));
        };
        if self.certificates.is_empty() {
            return Err(Error::Config("credentials need a certificate and key, or a pre-shared key".into()));
        }
        if self.roots.is_empty() {
            return Err(Error::Config("certificate credentials need roots to verify the peer".into()));
        }
        key.auth_method()
    }

    /// This end's phase 1 identification: the certificate subject, or with a
    /// pre-shared key the local address.
    pub(crate) fn own_id(&self, local: Option<SocketAddr>) -> Result<IdPayload> {
        if let Some(leaf) = self.certificates.first() {
            let c = x509::parse(leaf.as_ref()).map_err(|e| Error::Config(format!("own certificate: {e}")))?;
            return Ok(IdPayload {
                kind: ID_DER_ASN1_DN,
                data: c.subject,
            });
        }
        Ok(match local.map(|a| a.ip()) {
            Some(IpAddr::V4(ip)) => IdPayload {
                kind: ID_IPV4_ADDR,
                data: ip.octets().to_vec(),
            },
            Some(IpAddr::V6(ip)) => IdPayload {
                kind: ID_IPV6_ADDR,
                data: ip.octets().to_vec(),
            },
            None => IdPayload {
                kind: ID_KEY_ID,
                data: vec![0; 4],
            },
        })
    }

    /// Checks a peer's certificates against the roots and binds the
    /// identification payload to the leaf.
    pub(crate) fn verify_peer(&self, id: &IdPayload, certs: &[CertificateDer<'static>]) -> Result<x509::Certificate> {
        let Some(leaf) = certs.first() else {
            return Err(Error::Auth("peer sent no certificate".into()));
        };
        let anchors: Vec<TrustAnchor<'_>> = self
            .roots
            .iter()
            .filter_map(|r| webpki::anchor_from_trusted_cert(r).ok())
            .collect();
        let ee = webpki::EndEntityCert::try_from(leaf).map_err(|e| Error::Auth(format!("peer certificate: {e}")))?;
        let algs = rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms;
        let now = UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default());
        ee.verify_for_usage(algs.all, &anchors, &certs[1..], now, AnyUsage, None, None)
            .map_err(|e| Error::Auth(format!("peer certificate: {e:?}")))?;
        let parsed = x509::parse(leaf.as_ref()).map_err(|e| Error::Auth(format!("peer certificate: {e}")))?;
        if id.kind != ID_DER_ASN1_DN || id.data != parsed.subject {
            return Err(Error::Auth("peer identification does not match its certificate's subject".into()));
        }
        Ok(parsed)
    }
}

/// Accepts a certificate whatever its extended key usage: IKE certificates
/// carry whichever their authority chose, if any.
struct AnyUsage;

impl webpki::ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, _: webpki::KeyPurposeIdIter<'_, '_>) -> std::result::Result<(), webpki::Error> {
        Ok(())
    }
}

/// The authenticated identity at the other end of a phase 1 exchange.
#[derive(Debug, Clone)]
pub struct Peer {
    pub addr: SocketAddr,
    /// The identification payload the peer sent: its certificate subject
    /// (ID_DER_ASN1_DN) with certificates, or what the peer chose (usually its
    /// address) with a pre-shared key.
    pub id_type: u8,
    pub id: Vec<u8>,
    /// The peer's verified leaf certificate, `None` with a pre-shared key.
    pub certificate: Option<CertificateDer<'static>>,
    /// The common name of the certificate's subject, when it has one.
    pub common_name: Option<String>,
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.certificate.is_some() {
            return write!(f, "CN={}", self.common_name.as_deref().unwrap_or("?"));
        }
        match (self.id_type, self.id.len()) {
            (ID_IPV4_ADDR, 4) => write!(f, "{}", std::net::Ipv4Addr::new(self.id[0], self.id[1], self.id[2], self.id[3])),
            (ID_IPV6_ADDR, 16) => {
                let o: [u8; 16] = self.id.as_slice().try_into().expect("16 octets");
                write!(f, "{}", std::net::Ipv6Addr::from(o))
            }
            _ => write!(f, "{} (ID type {})", self.addr, self.id_type),
        }
    }
}

/// Decides whether a member may have a group's keys.
pub type AuthorizeFn = Arc<dyn Fn(&Peer, &super::GroupId) -> bool + Send + Sync>;

/// Decides whether a member takes keys from an authenticated key server.
pub type AuthorizeServerFn = Arc<dyn Fn(&Peer) -> std::result::Result<(), String> + Send + Sync>;

/// One phase 1 transform as offered.
pub(crate) struct Transform {
    /// The transform payload body, echoed by a responder.
    pub body: Vec<u8>,
    pub suite: Suite,
    pub auth: u16,
}

/// Builds the phase 1 SA payload body: the GDOI DOI, one ISAKMP proposal with
/// a transform per suite.
pub(crate) fn phase1_sa_body(suites: &[Suite], auth: u16) -> Vec<u8> {
    let ts: Vec<Payload> = suites
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut b = vec![(i + 1) as u8, TRANS_KEY_IKE, 0, 0];
            b.extend_from_slice(&encode_attrs(&s.attrs(auth, PHASE1_LIFE)));
            Payload::new(P_TRANS, b)
        })
        .collect();
    phase1_sa_with_doi(DOI_GDOI, &ts)
}

pub(crate) fn phase1_sa_with_doi(doi: u32, ts: &[Payload]) -> Vec<u8> {
    let mut prop = vec![1, PROTO_ISAKMP, 0, ts.len() as u8];
    prop.extend_from_slice(&encode_chain(ts, P_NONE));
    let mut b = doi.to_be_bytes().to_vec();
    b.extend_from_slice(&SIT_IDENTITY.to_be_bytes());
    b.extend_from_slice(&encode_chain(&[Payload::new(P_PROPOSAL, prop)], P_NONE));
    b
}

/// Reads a phase 1 SA payload body: its single proposal's transforms. The DOI
/// is GDOI by RFC 6407; the IPsec DOI, which some implementations put in phase
/// 1, is accepted too.
pub(crate) fn parse_phase1_sa(b: &[u8]) -> Result<Vec<Transform>> {
    if b.len() < 8 {
        return Err(malformed(format!("SA of {} octets", b.len())));
    }
    let doi = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    if doi != DOI_GDOI && doi != 1 {
        return Err(malformed(format!("phase 1 SA DOI {doi}")));
    }
    let (props, _) = parse_chain(&b[8..], P_PROPOSAL)?;
    if props.len() != 1 {
        return Err(malformed(format!("{} proposals in a phase 1 SA", props.len())));
    }
    let p = &props[0].body;
    if p.len() < 4 || p[1] != PROTO_ISAKMP || p[2] != 0 {
        return Err(malformed("phase 1 proposal is not an ISAKMP proposal without SPI"));
    }
    let (ts, _) = parse_chain(&p[4..], P_TRANS)?;
    let mut out = Vec::new();
    for t in ts {
        if t.body.len() < 4 || t.body[1] != TRANS_KEY_IKE {
            continue;
        }
        let attrs = parse_attrs(&t.body[4..])?;
        if let Some((suite, auth)) = suite_from_attrs(&attrs) {
            out.push(Transform {
                body: t.body,
                suite,
                auth,
            });
        }
    }
    Ok(out)
}

/// Builds a clear message.
pub(crate) fn message(mut h: Header, ps: &[Payload]) -> Vec<u8> {
    let body = encode_chain(ps, P_NONE);
    if let Some(p) = ps.first() {
        h.next = p.kind;
    }
    h.flags &= !FLAG_ENCRYPTED;
    h.length = (HEADER_LEN + body.len()) as u32;
    let mut b = Vec::with_capacity(h.length as usize);
    h.marshal(&mut b);
    b.extend_from_slice(&body);
    b
}

/// A message's payloads, the octets of the chain (which a HASH covers), and
/// the IV that follows it.
pub(crate) struct Opened {
    pub header: Header,
    pub payloads: Vec<Payload>,
    pub chain: Vec<u8>,
    pub next_iv: Vec<u8>,
}

impl Keys {
    /// Builds an encrypted message with `iv` and returns it with the IV for
    /// the next message of the exchange.
    pub(crate) fn sealed(&self, mut h: Header, ps: &[Payload], iv: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (ct, next) = self.encrypt(&encode_chain(ps, P_NONE), iv);
        if let Some(p) = ps.first() {
            h.next = p.kind;
        }
        h.flags |= FLAG_ENCRYPTED;
        h.length = (HEADER_LEN + ct.len()) as u32;
        let mut b = Vec::with_capacity(h.length as usize);
        h.marshal(&mut b);
        b.extend_from_slice(&ct);
        (b, next)
    }
}

/// Parses a message's payloads, decrypting them with `iv` when the message is
/// encrypted.
pub(crate) fn open(keys: Option<&Keys>, msg: &[u8], iv: &[u8]) -> Result<Opened> {
    let h = parse_header(msg)?;
    let mut body = msg[HEADER_LEN..h.length as usize].to_vec();
    let mut next_iv = iv.to_vec();
    if h.encrypted() {
        let Some(k) = keys else {
            return Err(malformed("encrypted message before keys exist"));
        };
        (body, next_iv) = k.decrypt(&body, iv)?;
    }
    let (payloads, n) = parse_chain(&body, h.next)?;
    body.truncate(n);
    Ok(Opened {
        header: h,
        payloads,
        chain: body,
        next_iv,
    })
}

/// Returns the payloads after a leading HASH payload and the octets they
/// occupy, which the HASH covers.
pub(crate) fn hashed(o: &Opened) -> Result<(&Payload, &[Payload], &[u8])> {
    match o.payloads.first() {
        Some(p) if p.kind == P_HASH => Ok((p, &o.payloads[1..], &o.chain[p.raw_len..])),
        _ => Err(malformed("message does not start with a HASH payload")),
    }
}

pub(crate) fn random_cookie() -> [u8; 8] {
    loop {
        let c: [u8; 8] = random_bytes(8).try_into().expect("8 octets");
        if c != [0; 8] {
            return c;
        }
    }
}

pub(crate) fn random_msg_id() -> u32 {
    loop {
        let v = u32::from_be_bytes(random_bytes(4).try_into().expect("4 octets"));
        if v != 0 {
            return v;
        }
    }
}

pub(crate) fn cert_payloads(chain: &[CertificateDer<'static>]) -> Vec<Payload> {
    chain
        .iter()
        .map(|c| {
            // Encoding 4: X.509 certificate, signature.
            let mut b = vec![4u8];
            b.extend_from_slice(c.as_ref());
            Payload::new(P_CERT, b)
        })
        .collect()
}

pub(crate) fn parse_certs(ps: &[Payload]) -> Result<Vec<CertificateDer<'static>>> {
    let mut out = Vec::new();
    for p in ps.iter().filter(|p| p.kind == P_CERT) {
        match p.body.split_first() {
            None => return Err(malformed("empty certificate payload")),
            Some((&4, der)) => out.push(CertificateDer::from(der.to_vec())),
            Some((&enc, _)) => return Err(malformed(format!("certificate payload of encoding {enc}"))),
        }
    }
    Ok(out)
}

/// Builds an informational exchange carrying a notification: protected with
/// HASH(1) = prf(SKEYID_a, M-ID | N) once keys exist, in the clear before
/// (RFC 2409 5.7).
pub(crate) fn informational(keys: Option<&Keys>, ic: [u8; 8], rc: [u8; 8], kind: u16) -> Vec<u8> {
    let n = Payload::new(P_NOTIFY, notify(DOI_GDOI, kind, &[]));
    let mut h = Header {
        ic,
        rc,
        exchange: XCHG_INFO,
        ..Default::default()
    };
    let Some(k) = keys else {
        return message(h, &[n]);
    };
    h.msg_id = random_msg_id();
    let hv = prf(k.hash, &k.a, &[&h.msg_id.to_be_bytes(), &encode_chain(std::slice::from_ref(&n), P_NONE)]);
    k.sealed(h, &[Payload::new(P_HASH, hv), n], &k.phase2_iv(h.msg_id)).0
}

/// Reads a notification from an informational message, verifying its hash
/// when it is protected.
pub(crate) fn read_informational(keys: Option<&Keys>, msg: &[u8]) -> Result<u16> {
    let h = parse_header(msg)?;
    let mut iv = Vec::new();
    if h.encrypted() {
        match keys {
            Some(k) if k.phase1_last.is_some() => iv = k.phase2_iv(h.msg_id),
            _ => return Err(malformed("protected informational before phase 1 completed")),
        }
    }
    let o = open(keys, msg, &iv)?;
    let mut ps: &[Payload] = &o.payloads;
    if h.encrypted() {
        let k = keys.expect("checked above");
        let (hp, rest, covered) = hashed(&o)?;
        if !constant_eq(&hp.body, &prf(k.hash, &k.a, &[&h.msg_id.to_be_bytes(), covered])) {
            return Err(Error::Auth("informational message with a bad hash".into()));
        }
        ps = rest;
    }
    let n = find(ps, P_NOTIFY).ok_or_else(|| malformed("informational message without a notification"))?;
    parse_notify(&n.body)
}
