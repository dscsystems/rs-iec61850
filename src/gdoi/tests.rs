//! GDOI tests: the RFC 5903 ECP-256 vectors, codec round trips, and
//! registrations with each credential type over loopback UDP, with
//! authorisation, loss and tampering.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose, SerialNumber};
use rustls::pki_types::CertificateDer;
use time::OffsetDateTime;
use tokio::net::UdpSocket;

use super::crypto::{Dh, Suite};
use super::isakmp::{Header, Payload, FLAG_ENCRYPTED, HEADER_LEN, P_SA, XCHG_MAIN};
use super::tek::{kd_body, parse_kd, parse_sa, sa_body};
use super::*;
use crate::asn1::Oid;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The ECP-256 key exchange against the test vectors of RFC 5903 8.1: the KE
/// value is x|y, the shared secret the x coordinate.
#[test]
fn ecp256_vectors() {
    let i = unhex("C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433");
    let gi = unhex(
        "DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180
         5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3",
    );
    let gr = unhex(
        "D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63
         56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB",
    );
    let gir = unhex("D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE");
    let d = Dh::from_p256(p256::SecretKey::from_slice(&i).unwrap());
    assert_eq!(d.public(), gi.as_slice());
    assert_eq!(d.shared(&gr).unwrap(), gir);
}

/// Both ends of every group agree on the secret, and degenerate MODP values
/// are refused.
#[test]
fn dh_agreement() {
    for g in [Suite::MODP_2048, Suite::ECP_256, Suite::ECP_384] {
        let (a, b) = (Dh::new(g).unwrap(), Dh::new(g).unwrap());
        assert_eq!(a.shared(b.public()).unwrap(), b.shared(a.public()).unwrap(), "group {g}");
    }
    let a = Dh::new(Suite::MODP_2048).unwrap();
    assert!(a.shared(&[0u8; 256]).is_err(), "g^y = 0 accepted");
    let mut one = [0u8; 256];
    one[255] = 1;
    assert!(a.shared(&one).is_err(), "g^y = 1 accepted");
}

fn test_oid() -> Oid {
    Oid::from([1, 2, 840, 10070, 61850, 1])
}

#[test]
fn tek_codec() {
    let sel = vec![0x04, 0x04, 239, 192, 0, 1];
    let mut tek = Tek::new(test_oid(), sel.clone(), AuthAlg::NONE, EncAlg::AES_GCM_128, Duration::from_secs(3600)).unwrap();
    tek.activation_delay = Duration::from_secs(30);
    tek.kda = Some(75);
    let got = parse_sa(&sa_body(std::slice::from_ref(&tek)).unwrap()).unwrap();
    assert_eq!(got.len(), 1);
    let g = &got[0];
    assert_eq!((g.spi, &g.oid, &g.selector), (tek.spi, &test_oid(), &sel));
    assert_eq!((g.auth, g.enc), (AuthAlg::NONE, EncAlg::AES_GCM_128));
    assert_eq!((g.lifetime, g.activation_delay, g.kda), (Duration::from_secs(3600), Duration::from_secs(30), Some(75)));
    let keys = parse_kd(&kd_body(std::slice::from_ref(&tek))).unwrap();
    assert_eq!(keys[&tek.spi].algorithm, tek.algorithm_key);
    assert!(keys[&tek.spi].integrity.is_empty());
    // The RFC 8052 key layouts.
    for (auth, enc, ilen, alen) in [
        (AuthAlg::HMAC_SHA256_128, EncAlg::NONE, 32, 0),
        (AuthAlg::HMAC_SHA256, EncAlg::NONE, 32, 0),
        (AuthAlg::NONE, EncAlg::AES_GCM_128, 0, 20),
        (AuthAlg::NONE, EncAlg::AES_GCM_256, 0, 36),
        (AuthAlg::HMAC_SHA256, EncAlg::AES_CBC_128, 32, 16),
        (AuthAlg::AES_GMAC_128, EncAlg::NONE, 20, 0),
    ] {
        let k = Tek::new(test_oid(), Vec::new(), auth, enc, Duration::ZERO).unwrap();
        assert_eq!((k.integrity_key.len(), k.algorithm_key.len()), (ilen, alen), "{auth}/{enc}");
    }
    // Combinations RFC 8052 forbids.
    for (auth, enc) in [
        (AuthAlg::HMAC_SHA256, EncAlg::AES_GCM_128),
        (AuthAlg::NONE, EncAlg::AES_CBC_128),
        (AuthAlg::NONE, EncAlg::NONE),
    ] {
        assert!(matches!(Tek::new(test_oid(), Vec::new(), auth, enc, Duration::ZERO), Err(Error::Policy(_))));
    }
    // The session layer's view of a TEK.
    let k = Tek::new(test_oid(), Vec::new(), AuthAlg::NONE, EncAlg::AES_GCM_256, Duration::ZERO).unwrap();
    let rk = k.rsession_key().unwrap();
    assert_eq!((rk.id, rk.material.as_slice()), (k.spi, &k.algorithm_key[..32]));
    let k = Tek::new(test_oid(), Vec::new(), AuthAlg::HMAC_SHA256, EncAlg::AES_CBC_256, Duration::ZERO).unwrap();
    assert!(matches!(k.rsession_key(), Err(Error::Unsupported(_))));
}

#[test]
fn group_id_codec() {
    for g in [
        GroupId::key_id(1234),
        GroupId::oid(test_oid()),
        GroupId {
            oid: Some(test_oid()),
            selector: vec![4, 2, 1, 2],
            key_id: 0,
        },
    ] {
        assert_eq!(GroupId::from_id(&g.id().unwrap()).unwrap(), g);
    }
    // RFC 8052 figure 2: OID length, DER OID, selector length.
    let id = GroupId::oid(test_oid()).id().unwrap();
    let der = crate::asn1::oid_elem(crate::asn1::TAG_OID, &test_oid()).encode();
    let mut want = vec![der.len() as u8];
    want.extend_from_slice(&der);
    want.extend_from_slice(&[0, 0]);
    assert_eq!((id.kind, id.data), (ID_OID, want));
}

// --- End to end ---

struct Pki {
    cert: rcgen::Certificate,
    key: KeyPair,
}

fn hour() -> time::Duration {
    time::Duration::hours(1)
}

static SERIAL: Mutex<u64> = Mutex::new(10);

impl Pki {
    fn new(name: &str) -> Pki {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        p.not_before = OffsetDateTime::now_utc() - hour();
        p.not_after = OffsetDateTime::now_utc() + hour();
        p.serial_number = Some(SerialNumber::from(1u64));
        let cert = p.self_signed(&key).unwrap();
        Pki { cert, key }
    }

    fn root(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    fn issue(&self, cn: &str, key: &KeyPair) -> Credentials {
        let serial = {
            let mut s = SERIAL.lock().unwrap();
            *s += 1;
            *s
        };
        let mut p = CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.distinguished_name.push(DnType::OrganizationName, "substation");
        p.not_before = OffsetDateTime::now_utc() - hour();
        p.not_after = OffsetDateTime::now_utc() + hour();
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.serial_number = Some(SerialNumber::from(serial));
        let cert = p.signed_by(key, &self.cert, &self.key).unwrap();
        Credentials {
            certificates: vec![cert.der().clone()],
            key: Some(PrivateKey::from_pkcs8_der(&key.serialize_der()).unwrap()),
            roots: vec![self.root()],
            psk: Vec::new(),
        }
    }
}

fn ec_key(alg: &'static rcgen::SignatureAlgorithm) -> KeyPair {
    KeyPair::generate_for(alg).unwrap()
}

fn p256() -> KeyPair {
    ec_key(&rcgen::PKCS_ECDSA_P256_SHA256)
}

/// RSA keys are slow to make; two serve every test.
fn rsa_key(i: usize) -> KeyPair {
    static KEYS: OnceLock<[Vec<u8>; 2]> = OnceLock::new();
    let keys = KEYS.get_or_init(|| {
        [0, 1].map(|_| {
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .unwrap()
                .serialize_der()
        })
    });
    let der = rustls::pki_types::PrivatePkcs8KeyDer::from(keys[i].clone());
    KeyPair::from_pkcs8_der_and_sign_algo(&der, &rcgen::PKCS_RSA_SHA256).unwrap()
}

struct Rig {
    addr: String,
    group: GroupId,
    g: Arc<Group>,
    events: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a key server with one group holding one TEK.
async fn rig(mut cfg: ServerConfig) -> Rig {
    let events: Arc<Mutex<Vec<String>>> = Arc::default();
    if cfg.authorize.is_none() {
        cfg.authorize = Some(Arc::new(|_: &Peer, _: &GroupId| true));
    }
    let (e1, e2) = (events.clone(), events.clone());
    cfg.on_reject = Some(Arc::new(move |_: SocketAddr, err: &Error| e1.lock().unwrap().push(format!("reject: {err}"))));
    cfg.on_register = Some(Arc::new(move |p: &Peer, _: &GroupId, _: &[Tek]| {
        e2.lock().unwrap().push(format!("register: {p}"))
    }));
    let s = Server::new(cfg).unwrap();
    let g = Arc::new(Group::new());
    g.add(Tek::new(test_oid(), Vec::new(), AuthAlg::NONE, EncAlg::AES_GCM_128, Duration::from_secs(3600)).unwrap())
        .unwrap();
    let group = GroupId::oid(test_oid());
    s.add_group(group.clone(), g.clone());
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let _ = s.serve(sock).await;
    });
    Rig { addr, group, g, events, task }
}

async fn register_with(r: &Rig, mut cfg: MemberConfig) -> Result<Registration> {
    cfg.server = r.addr.clone();
    if cfg.retransmit.is_zero() {
        cfg.retransmit = Duration::from_millis(300);
    }
    tokio::time::timeout(Duration::from_secs(5), register(&cfg, &r.group))
        .await
        .unwrap_or(Err(Error::Timeout))
}

fn check_registration(r: &Rig, reg: &Registration) {
    let want = r.g.snapshot(Instant::now());
    assert_eq!(reg.teks.len(), want.len());
    let got = &reg.teks[0];
    assert_eq!(got.spi, want[0].spi);
    assert_eq!(got.algorithm_key, want[0].algorithm_key);
    assert_eq!(got.enc, EncAlg::AES_GCM_128);
    assert!(got.lifetime > Duration::from_secs(59 * 60) && got.lifetime <= Duration::from_secs(3600));
}

fn any_server() -> Option<AuthorizeServerFn> {
    Some(Arc::new(|_: &Peer| Ok(())))
}

#[tokio::test]
async fn register_with_certificates() {
    let ca = Pki::new("substation CA");
    let s256 = Suite { key_bits: 256, hash: Suite::SHA2_384, group: Suite::ECP_384 };
    let modp = Suite { key_bits: 128, hash: Suite::SHA2_256, group: Suite::MODP_2048 };
    let cases: Vec<(&str, KeyPair, KeyPair, Vec<Suite>)> = vec![
        ("ECDSA-256", p256(), p256(), vec![]),
        ("ECDSA-384", ec_key(&rcgen::PKCS_ECDSA_P384_SHA384), ec_key(&rcgen::PKCS_ECDSA_P384_SHA384), vec![s256]),
        ("RSA", rsa_key(0), rsa_key(1), vec![]),
        ("MODP-2048", p256(), p256(), vec![modp]),
    ];
    for (name, ks_key, gm_key, suites) in cases {
        let mut accepted = suites.clone();
        accepted.extend_from_slice(DEFAULT_SUITES);
        let r = rig(ServerConfig {
            credentials: ca.issue("ks1", &ks_key),
            suites: accepted,
            ..Default::default()
        })
        .await;
        let authorised: Arc<Mutex<Option<Peer>>> = Arc::default();
        let a = authorised.clone();
        let reg = register_with(
            &r,
            MemberConfig {
                credentials: ca.issue("ied1", &gm_key),
                suites,
                authorize_server: Some(Arc::new(move |p: &Peer| {
                    *a.lock().unwrap() = Some(p.clone());
                    if p.common_name.as_deref() == Some("ks1") {
                        Ok(())
                    } else {
                        Err("not our key server".into())
                    }
                })),
                ..Default::default()
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        check_registration(&r, &reg);
        assert!(authorised.lock().unwrap().as_ref().is_some_and(|p| p.certificate.is_some()), "{name}");
        assert_eq!(reg.server.common_name.as_deref(), Some("ks1"));
        let ev = r.events.lock().unwrap().clone();
        assert!(ev.iter().any(|e| e == "register: CN=ied1"), "{name}: {ev:?}");
    }
}

#[tokio::test]
async fn register_with_psk() {
    let psk = b"substation pre-shared secret".to_vec();
    let p = psk.clone();
    let r = rig(ServerConfig {
        psk: Some(Arc::new(move |_| Some(p.clone()))),
        ..Default::default()
    })
    .await;
    let creds = |k: &[u8]| Credentials {
        psk: k.to_vec(),
        ..Default::default()
    };
    let reg = register_with(&r, MemberConfig { credentials: creds(&psk), ..Default::default() }).await.unwrap();
    check_registration(&r, &reg);

    // The wrong key fails authentication, and the member is told.
    let err = register_with(&r, MemberConfig { credentials: creds(b"wrong secret"), ..Default::default() })
        .await
        .unwrap_err();
    assert!(matches!(err, Error::Notify(NOTIFY_AUTH_FAILED)), "{err}");
}

#[tokio::test]
async fn authorization() {
    let ca = Pki::new("substation CA");
    let r = rig(ServerConfig {
        credentials: ca.issue("ks1", &p256()),
        authorize: Some(Arc::new(|p: &Peer, _: &GroupId| p.common_name.as_deref() == Some("ied1"))),
        ..Default::default()
    })
    .await;

    // A member the key server does not authorise gets no keys.
    let err = register_with(&r, MemberConfig {
        credentials: ca.issue("intruder", &p256()),
        authorize_server: any_server(),
        ..Default::default()
    })
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Notify(NOTIFY_INVALID_ID_INFO)), "unauthorised member: {err}");

    // Nor does one asking for a group the server does not have.
    let cred = ca.issue("ied1", &p256());
    let cfg = MemberConfig {
        credentials: cred.clone(),
        authorize_server: any_server(),
        server: r.addr.clone(),
        retransmit: Duration::from_millis(300),
        ..Default::default()
    };
    let err = register(&cfg, &GroupId::key_id(99)).await.unwrap_err();
    assert!(matches!(err, Error::Notify(NOTIFY_INVALID_ID_INFO)), "unknown group: {err}");

    // A member refuses a key server it has not been told to trust...
    let err = register_with(&r, MemberConfig {
        credentials: cred.clone(),
        authorize_server: Some(Arc::new(|_: &Peer| Err("no".into()))),
        ..Default::default()
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("not authorised"), "{err}");
    // ...and must be told, with certificates.
    assert!(register_with(&r, MemberConfig { credentials: cred.clone(), ..Default::default() }).await.is_err());

    // A member from another authority fails certificate verification.
    let other = Pki::new("other CA");
    let mut stranger = other.issue("ied1", &p256());
    stranger.roots = vec![ca.root()];
    let err = register_with(&r, MemberConfig {
        credentials: stranger,
        authorize_server: any_server(),
        ..Default::default()
    })
    .await
    .unwrap_err();
    assert!(matches!(err, Error::Notify(NOTIFY_INVALID_CERT)), "foreign member: {err}");

    // And a member refuses a key server from another authority.
    let r2 = rig(ServerConfig {
        credentials: other.issue("ks-evil", &p256()),
        ..Default::default()
    })
    .await;
    assert!(register_with(&r2, MemberConfig {
        credentials: cred,
        authorize_server: any_server(),
        ..Default::default()
    })
    .await
    .is_err());
}

/// A UDP relay between a member and a key server that drops the first copy of
/// every datagram, in both directions, so every message is only delivered on
/// retransmission. `mangle` alters what the key server sends.
async fn lossy(to: &str, mangle: Option<fn(&mut Vec<u8>)>) -> (String, tokio::task::JoinHandle<()>) {
    let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = front.local_addr().unwrap().to_string();
    let ks: SocketAddr = to.parse().unwrap();
    let task = tokio::spawn(async move {
        let mut seen = std::collections::HashSet::new();
        let mut member = None;
        let (mut a, mut b) = (vec![0u8; 65536], vec![0u8; 65536]);
        loop {
            tokio::select! {
                Ok((n, from)) = front.recv_from(&mut a) => {
                    member = Some(from);
                    if !seen.insert(a[..n].to_vec()) {
                        let _ = up.send_to(&a[..n], ks).await;
                    }
                }
                Ok((n, _)) = up.recv_from(&mut b) => {
                    let orig = b[..n].to_vec();
                    let mut out = orig.clone();
                    if let Some(f) = mangle {
                        f(&mut out);
                    }
                    if !seen.insert(orig) {
                        if let Some(m) = member {
                            let _ = front.send_to(&out, m).await;
                        }
                    }
                }
            }
        }
    });
    (addr, task)
}

fn psk_rig_config(psk: &[u8]) -> ServerConfig {
    let p = psk.to_vec();
    ServerConfig {
        psk: Some(Arc::new(move |_| Some(p.clone()))),
        ..Default::default()
    }
}

/// Every message lost once: the exchange completes on retransmissions, and
/// the key server answers a repeated request with the reply it gave.
#[tokio::test]
async fn retransmission() {
    let psk = b"substation pre-shared secret";
    let r = rig(psk_rig_config(psk)).await;
    let (relay, task) = lossy(&r.addr, None).await;
    let cfg = MemberConfig {
        credentials: Credentials { psk: psk.to_vec(), ..Default::default() },
        retransmit: Duration::from_millis(200),
        attempts: 5,
        server: relay,
        ..Default::default()
    };
    let reg = tokio::time::timeout(Duration::from_secs(10), register(&cfg, &r.group)).await.unwrap().unwrap();
    check_registration(&r, &reg);
    task.abort();
}

/// A key server reply altered on the way is refused.
#[tokio::test]
async fn a_tampered_reply_is_refused() {
    let psk = b"substation pre-shared secret";
    let r = rig(psk_rig_config(psk)).await;
    // Flip a bit in the last ciphertext block of every encrypted reply.
    let (relay, task) = lossy(
        &r.addr,
        Some(|b: &mut Vec<u8>| {
            if b.len() > HEADER_LEN && b[19] & FLAG_ENCRYPTED != 0 {
                *b.last_mut().unwrap() ^= 1;
            }
        }),
    )
    .await;
    let cfg = MemberConfig {
        credentials: Credentials { psk: psk.to_vec(), ..Default::default() },
        retransmit: Duration::from_millis(200),
        attempts: 3,
        server: relay,
        ..Default::default()
    };
    let res = tokio::time::timeout(Duration::from_secs(10), register(&cfg, &r.group)).await.unwrap();
    assert!(res.is_err(), "a tampered exchange completed");
    task.abort();
}

/// Nothing a peer sends makes the key server or the codec panic.
#[test]
fn arbitrary_input_never_panics() {
    let s = Server::new(ServerConfig {
        psk: Some(Arc::new(|_| Some(b"k".to_vec()))),
        authorize: Some(Arc::new(|_: &Peer, _: &GroupId| true)),
        ..Default::default()
    })
    .unwrap();
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let sa = super::exchange::phase1_sa_body(DEFAULT_SUITES, super::crypto::AUTH_PSK);
    let seed_msgs = [
        vec![0u8; 28],
        super::exchange::message(
            Header { ic: [1; 8], exchange: XCHG_MAIN, ..Default::default() },
            &[Payload::new(P_SA, sa)],
        ),
    ];
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for i in 0..20_000 {
        let mut b = seed_msgs[i % 2].clone();
        for _ in 0..(next() % 6) {
            let pos = (next() as usize) % b.len();
            b[pos] = next() as u8;
        }
        if next() % 3 == 0 {
            b.truncate((next() as usize) % (b.len() + 1));
        }
        let _ = s.handle(&b, addr);
        let _ = parse_sa(&b);
        let _ = parse_kd(&b);
        let _ = super::tek::parse_sat(&b);
        let _ = super::exchange::parse_phase1_sa(&b);
        if let Ok(id) = super::isakmp::parse_id(&b) {
            let _ = GroupId::from_id(&id);
        }
    }
}

/// Two members take the group's keys from the key server into their session
/// key stores and exchange R-GOOSE under them; the key server rotates the
/// key, and they follow it; the old key, withdrawn, stops being accepted; and
/// a member that stops removes its keys.
#[tokio::test(flavor = "multi_thread")]
async fn members_follow_key_rotation() {
    use crate::rsession::{self, Config, KeyStore, Payload as SPayload, PayloadType, Session, SessionId, Spdu};

    let ca = Pki::new("CA");
    let oid = Oid::from([1, 2, 840, 10070, 61850, 2]);
    let group = GroupId::oid(oid.clone());
    let g = Arc::new(Group::new());
    let tek1 = Tek::new(oid.clone(), Vec::new(), AuthAlg::NONE, EncAlg::AES_GCM_128, Duration::from_secs(3600)).unwrap();
    g.add(tek1.clone()).unwrap();
    let ks = Server::new(ServerConfig {
        credentials: ca.issue("ks1", &p256()),
        authorize: Some(Arc::new(|p: &Peer, _: &GroupId| p.common_name.as_deref() != Some("intruder"))),
        ..Default::default()
    })
    .unwrap();
    ks.add_group(group.clone(), g.clone());
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ks_addr = sock.local_addr().unwrap().to_string();
    let ks_task = tokio::spawn(async move {
        let _ = ks.serve(sock).await;
    });

    type Events = Arc<Mutex<Vec<Event>>>;
    let member = |name: &str, store: Arc<KeyStore>| -> (Events, tokio::sync::oneshot::Sender<()>) {
        let cfg = MemberConfig {
            server: ks_addr.clone(),
            credentials: ca.issue(name, &p256()),
            authorize_server: Some(Arc::new(|p: &Peer| {
                (p.common_name.as_deref() == Some("ks1")).then_some(()).ok_or_else(|| "unknown key server".to_string())
            })),
            retransmit: Duration::from_millis(300),
            ..Default::default()
        };
        let mut m = Member::new(cfg, group.clone(), store);
        m.refresh = Duration::from_millis(200);
        let events: Events = Arc::default();
        let e = events.clone();
        m.on_event(move |ev| e.lock().unwrap().push(ev.clone()));
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            m.run(async {
                let _ = stopped.await;
            })
            .await;
        });
        (events, stop)
    };
    let has = |evs: &Events, kind: EventKind, spi: u32| evs.lock().unwrap().iter().any(|e| e.kind == kind && e.spi == spi);
    async fn wait_for(what: &str, cond: impl Fn() -> bool) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {what}");
    }

    let (pub_keys, sub_keys) = (Arc::new(KeyStore::new()), Arc::new(KeyStore::new()));
    let (pub_ev, stop_pub) = member("ied-publisher", pub_keys.clone());
    let (sub_ev, stop_sub) = member("ied-subscriber", sub_keys.clone());
    wait_for("the first key", || has(&pub_ev, EventKind::Installed, tek1.spi) && has(&sub_ev, EventKind::Installed, tek1.spi)).await;

    let rx = Arc::new(Session::open(Config { listen: "127.0.0.1:0".into(), keys: Some(sub_keys.clone()), ..Default::default() }).unwrap());
    let tx = Session::open(Config { remote: rx.local_addr().unwrap().to_string(), keys: Some(pub_keys.clone()), ..Default::default() }).unwrap();
    let goose = || SPayload { kind: PayloadType::GOOSE, app_id: 1, apdu: vec![0x61, 0], ..Default::default() };
    let exchange = |tx: &Session| {
        tx.send(SessionId::GOOSE, vec![goose()]).unwrap();
        let rx = rx.clone();
        async move {
            tokio::task::spawn_blocking(move || rx.receive_timeout(Duration::from_secs(2)))
                .await
                .unwrap()
                .unwrap()
                .expect("nothing received")
                .0
        }
    };
    let s = exchange(&tx).await;
    assert_eq!(s.key_id, tek1.spi);
    assert!(s.encrypted);

    // Rotation: the next key is distributed a second before it is used.
    let mut tek2 = Tek::new(oid.clone(), Vec::new(), AuthAlg::NONE, EncAlg::AES_GCM_128, Duration::from_secs(3600)).unwrap();
    tek2.activation_delay = Duration::from_secs(1);
    g.add(tek2.clone()).unwrap();
    wait_for("the next key", || has(&pub_ev, EventKind::Installed, tek2.spi) && has(&sub_ev, EventKind::Installed, tek2.spi)).await;
    assert_eq!(exchange(&tx).await.key_id, tek2.spi, "after the rotation the publisher sends under the new key");

    // Withdrawal: members drop the old key at their next registration, and an
    // SPDU under it is refused.
    g.remove(tek1.spi);
    wait_for("the old key's removal", || has(&sub_ev, EventKind::Removed, tek1.spi)).await;
    let k1 = tek1.rsession_key().unwrap();
    let stale = rsession::marshal(
        &Spdu { si: SessionId::GOOSE, number: 1000, payloads: vec![goose()], ..Default::default() },
        Some(&k1),
    )
    .unwrap();
    let before = rx.stats().unknown_key;
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().send_to(&stale, rx.local_addr().unwrap()).unwrap();
    let r = rx.clone();
    let _ = tokio::task::spawn_blocking(move || r.receive_timeout(Duration::from_millis(500))).await;
    assert!(rx.stats().unknown_key > before, "the withdrawn key was accepted");

    // Stopping a member removes its keys.
    let _ = stop_sub.send(());
    wait_for("the subscriber's keys to go", || sub_keys.lookup(tek2.spi).is_none()).await;
    let _ = stop_pub.send(());
    rx.shutdown();
    ks_task.abort();
}
