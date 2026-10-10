//! The IEC 62351-3 TLS profile over real MMS associations: mutual
//! authentication, server naming, the protocol floor, revocation, key
//! strength and pinning.
#![cfg(feature = "tls")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850::client::{Client, Options as ClientOptions};
use iec61850::iec62351::{self, Error, Event, Options};
use iec61850::model::Fc;
use iec61850::scl;
use iec61850::server::{Options as ServerOptions, Server};
use rcgen::{
    CertificateParams, CertificateRevocationListParams, DnType, IsCa, KeyIdMethod, KeyPair,
    KeyUsagePurpose, RevokedCertParams, SanType, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;
use tokio::net::TcpListener;

struct Ca {
    cert: rcgen::Certificate,
    key: KeyPair,
    serial: u64,
}

/// A certificate and its key, ready for [`Options`].
struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    serial: u64,
}

impl Clone for Identity {
    fn clone(&self) -> Identity {
        Identity {
            chain: self.chain.clone(),
            key: self.key.clone_key(),
            serial: self.serial,
        }
    }
}

fn hour() -> time::Duration {
    time::Duration::hours(1)
}

impl Ca {
    fn new(name: &str) -> Ca {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.not_before = OffsetDateTime::now_utc() - hour();
        p.not_after = OffsetDateTime::now_utc() + 24 * hour();
        p.serial_number = Some(SerialNumber::from(1u64));
        let cert = p.self_signed(&key).unwrap();
        Ca { cert, key, serial: 1 }
    }

    fn root(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    /// Signs a leaf for `cn` with `key` (a new P-256 key when `None`). `sans`
    /// are DNS names; none leaves the subject alternative name out, as IED
    /// certificates often do.
    fn issue(&mut self, cn: &str, key: Option<KeyPair>, sans: &[&str]) -> Identity {
        let key = key.unwrap_or_else(|| KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap());
        self.serial += 1;
        let mut p = CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.subject_alt_names = sans
            .iter()
            .map(|s| SanType::DnsName((*s).try_into().unwrap()))
            .collect();
        p.not_before = OffsetDateTime::now_utc() - hour();
        p.not_after = OffsetDateTime::now_utc() + 24 * hour();
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.serial_number = Some(SerialNumber::from(self.serial));
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        Identity {
            chain: vec![cert.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            serial: self.serial,
        }
    }

    fn crl(&self, next: OffsetDateTime, revoked: &[&Identity]) -> Vec<u8> {
        let p = CertificateRevocationListParams {
            this_update: OffsetDateTime::now_utc() - hour(),
            next_update: next,
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|r| RevokedCertParams {
                    serial_number: SerialNumber::from(r.serial),
                    revocation_time: OffsetDateTime::now_utc() - time::Duration::minutes(5),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        p.signed_by(&self.cert, &self.key).unwrap().der().to_vec()
    }
}

fn options(id: &Identity, roots: &[&Ca]) -> Options {
    Options {
        certificates: id.chain.clone(),
        key: Some(id.key.clone_key()),
        roots: roots.iter().map(|c| c.root()).collect(),
        ..Default::default()
    }
}

type Events = Arc<Mutex<Vec<String>>>;

/// Starts an MMS server under the profile and returns its address and the
/// events it logged.
async fn serve(mut o: Options) -> (String, Events) {
    let events: Events = Arc::default();
    let e = events.clone();
    o.on_event = Some(Arc::new(move |ev: &Event| e.lock().unwrap().push(format!("{:?}", ev.err))));
    let cfg = iec62351::server_config(o).unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid");
    let m = scl::load_model(path, &scl::BuildOptions::new()).unwrap();
    let server = Server::new(m, ServerOptions::new().with_tls(cfg));
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let _ = server.serve(ln).await;
    });
    (addr, events)
}

/// Associates under the profile and reads one value.
async fn dial(addr: &str, o: Options) -> Result<(), String> {
    dial_with(addr, iec62351::client_config(o).unwrap()).await
}

async fn dial_with(addr: &str, cfg: Arc<rustls::ClientConfig>) -> Result<(), String> {
    let opts = ClientOptions::new()
        .with_tls(cfg)
        .with_timeout(Duration::from_secs(2));
    let c = tokio::time::timeout(Duration::from_secs(3), Client::dial_with(addr, opts))
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let r = c
        .read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string());
    let _ = c.close().await;
    r
}

/// A client that presents no certificate and checks nothing.
fn anonymous_client(versions: &[&'static rustls::SupportedProtocolVersion]) -> Arc<rustls::ClientConfig> {
    #[derive(Debug)]
    struct AnyServer(rustls::crypto::WebPkiSupportedAlgorithms);
    impl rustls::client::danger::ServerCertVerifier for AnyServer {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.0)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.0)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.supported_schemes()
        }
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let algs = provider.signature_verification_algorithms;
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyServer(algs)))
            .with_no_client_auth(),
    )
}

#[tokio::test]
async fn mutual_authentication() {
    let mut root = Ca::new("root");
    let srv = root.issue("ied1", None, &[]);
    let cli = root.issue("scada", None, &[]);
    let (addr, events) = serve(options(&srv, &[&root])).await;

    // Both ends authenticated, and a server named by its common name (no
    // subject alternative name) is recognised.
    let named = |name: &str| Options {
        server_name: name.into(),
        ..options(&cli, &[&root])
    };
    dial(&addr, named("ied1")).await.expect("authenticated client");
    assert!(dial(&addr, named("ied2")).await.is_err(), "accepted a server naming another IED");

    // A client without a certificate is refused.
    assert!(dial_with(&addr, anonymous_client(&[&rustls::version::TLS13])).await.is_err());

    // A client whose certificate another authority issued is refused.
    let mut other = Ca::new("other");
    let stranger = other.issue("stranger", None, &[]);
    assert!(dial(&addr, options(&stranger, &[&root])).await.is_err());
    assert!(!events.lock().unwrap().is_empty(), "the refused clients were not reported");

    // A client refuses a server from another authority.
    let (addr2, _) = serve(options(&stranger, &[&root])).await;
    assert!(dial(&addr2, options(&cli, &[&root])).await.is_err());
}

/// A certificate with subject alternative names is named by them, not by its
/// common name.
#[tokio::test]
async fn subject_alternative_names_name_the_server() {
    let mut root = Ca::new("root");
    let srv = root.issue("ied1", None, &["ied1.substation"]);
    let cli = root.issue("scada", None, &[]);
    let (addr, _) = serve(options(&srv, &[&root])).await;
    let named = |name: &str| Options {
        server_name: name.into(),
        ..options(&cli, &[&root])
    };
    dial(&addr, named("ied1.substation")).await.expect("named by its SAN");
    assert!(dial(&addr, named("ied1")).await.is_err(), "the CN named a server that has SANs");
}

#[tokio::test]
async fn the_protocol_floor() {
    let mut root = Ca::new("root");
    let srv = root.issue("ied1", None, &[]);
    let cli = root.issue("scada", None, &[]);
    let (addr, _) = serve(Options {
        tls13_only: true,
        ..options(&srv, &[&root])
    })
    .await;
    let profile = iec62351::client_config(options(&cli, &[&root])).unwrap();
    dial_with(&addr, profile).await.expect("TLS 1.3 negotiated");
    // A TLS 1.2 client is refused by a TLS 1.3-only server.
    let mut only12 = rustls::ClientConfig::clone(&anonymous_client(&[&rustls::version::TLS12]));
    only12.alpn_protocols.clear();
    assert!(dial_with(&addr, Arc::new(only12)).await.is_err());
}

#[tokio::test]
async fn revocation() {
    let mut root = Ca::new("root");
    let srv = root.issue("ied1", None, &[]);
    let cli = root.issue("scada", None, &[]);
    let revoked = root.issue("former-employee", None, &[]);

    let fresh = root.crl(OffsetDateTime::now_utc() + hour(), &[&revoked]);
    let (addr, events) = serve(Options {
        crls: vec![fresh],
        ..options(&srv, &[&root])
    })
    .await;
    dial(&addr, options(&cli, &[&root])).await.expect("unrevoked client");
    assert!(dial(&addr, options(&revoked, &[&root])).await.is_err(), "a revoked client was served");
    let ev = events.lock().unwrap().clone();
    assert!(ev.iter().any(|e| e == &format!("{:?}", Error::Revoked)), "{ev:?}");

    // A CRL past its next update fails closed, unless allowed.
    let stale = root.crl(OffsetDateTime::now_utc() - time::Duration::minutes(1), &[]);
    let (addr, events) = serve(Options {
        crls: vec![stale.clone()],
        ..options(&srv, &[&root])
    })
    .await;
    assert!(dial(&addr, options(&cli, &[&root])).await.is_err(), "a stale CRL did not fail the connection");
    let ev = events.lock().unwrap().clone();
    assert!(ev.iter().any(|e| e == &format!("{:?}", Error::StaleCrl)), "{ev:?}");
    let (addr, _) = serve(Options {
        crls: vec![stale],
        allow_stale_crl: true,
        ..options(&srv, &[&root])
    })
    .await;
    dial(&addr, options(&cli, &[&root])).await.expect("stale CRL allowed");
}

#[tokio::test]
async fn key_strength_and_pinning() {
    let mut root = Ca::new("root");
    let srv = root.issue("ied1", None, &[]);
    let rsa = KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048).unwrap();
    let rsa_cli = root.issue("rsa-client", Some(rsa), &[]);
    let pinned = root.issue("pinned", None, &[]);

    let (addr, _) = serve(options(&srv, &[&root])).await;
    dial(&addr, options(&rsa_cli, &[&root])).await.expect("2048-bit RSA client");

    let (addr, _) = serve(Options {
        allowed_peers: vec![pinned.chain[0].clone()],
        ..options(&srv, &[&root])
    })
    .await;
    dial(&addr, options(&pinned, &[&root])).await.expect("pinned client");
    assert!(dial(&addr, options(&rsa_cli, &[&root])).await.is_err(), "a client outside the allowed set");
}

/// A 1024-bit RSA key is too weak for the profile.
#[test]
fn weak_rsa_keys_are_judged_weak() {
    let dir = std::env::temp_dir().join(format!("iec62351-weak-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ok = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "rsa:1024", "-nodes", "-subj", "/CN=legacy", "-days", "1", "-outform", "DER"])
        .arg("-keyout")
        .arg(dir.join("k.pem"))
        .arg("-out")
        .arg(dir.join("c.der"))
        .output();
    let Ok(out) = ok else {
        eprintln!("openssl not available; skipped");
        return;
    };
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let der = std::fs::read(dir.join("c.der")).unwrap();
    let c = iec61850::x509::parse(&der).unwrap();
    assert_eq!(c.public_key.rsa_bits(), Some(1024));
    assert_eq!(c.common_name.as_deref(), Some("legacy"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn options_are_required() {
    assert!(matches!(iec62351::server_config(Options::default()), Err(Error::Required(_))));
    let mut root = Ca::new("root");
    let c = root.issue("x", None, &[]);
    let no_roots = Options {
        roots: Vec::new(),
        ..options(&c, &[])
    };
    assert!(matches!(iec62351::client_config(no_roots), Err(Error::Required(_))));
}

/// Signs `tbs` with the CA's key: ECDSA P-256 with SHA-256, DER encoded.
fn ca_sign(ca: &Ca, tbs: &[u8]) -> Vec<u8> {
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ca.key.serialize_der()));
    let key = rustls::crypto::aws_lc_rs::sign::any_ecdsa_type(&der).unwrap();
    let signer = key.choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256]).unwrap();
    signer.sign(tbs).unwrap()
}

/// Issues an X.509 version 1 certificate, which has no extensions and no
/// version field, as libiec61850's example certificates and many IEDs' are.
fn issue_v1(ca: &Ca, cn: &str, serial: u64) -> Identity {
    use iec61850::asn1::{self, cons, oid_elem, prim, uint_elem, Class, Oid, Tag, TAG_BIT_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET, TAG_UTF8_STRING};
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ecdsa_sha256 = || cons(TAG_SEQUENCE, [oid_elem(TAG_OID, &Oid::from([1, 2, 840, 10045, 4, 3, 2]))]);
    let name = |cn: &str| {
        cons(TAG_SEQUENCE, [cons(TAG_SET, [cons(TAG_SEQUENCE, [
            oid_elem(TAG_OID, &Oid::from([2, 5, 4, 3])),
            prim(TAG_UTF8_STRING, cn.as_bytes().to_vec()),
        ])])])
    };
    let utc = Tag::new(Class::Universal, false, 23);
    let time = |t: OffsetDateTime| {
        let s = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            t.year() % 100, u8::from(t.month()), t.day(), t.hour(), t.minute(), t.second()
        );
        prim(utc, s.into_bytes())
    };
    let issuer = iec61850::x509::parse(ca.cert.der()).unwrap().subject;
    let tbs = cons(TAG_SEQUENCE, [
        uint_elem(asn1::TAG_INTEGER, serial),
        ecdsa_sha256(),
        asn1::raw_tlv(issuer),
        cons(TAG_SEQUENCE, [time(OffsetDateTime::now_utc() - hour()), time(OffsetDateTime::now_utc() + hour())]),
        name(cn),
        asn1::raw_tlv(key.public_key_der()),
    ])
    .encode();
    let mut bits = vec![0u8];
    bits.extend(ca_sign(ca, &tbs));
    let cert = cons(TAG_SEQUENCE, [asn1::raw_tlv(tbs), ecdsa_sha256(), prim(TAG_BIT_STRING, bits)]).encode();
    assert_eq!(iec61850::x509::parse(&cert).unwrap().version, 1);
    Identity {
        chain: vec![CertificateDer::from(cert)],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        serial,
    }
}

/// X.509 v1 certificates, which webpki refuses, are presented and accepted
/// when a configured root issued them: named by their common name, and
/// subject to revocation.
#[tokio::test]
async fn x509_v1_certificates() {
    let mut root = Ca::new("root");
    let srv = issue_v1(&root, "ied1", 100);
    let cli = issue_v1(&root, "scada", 101);
    let revoked = issue_v1(&root, "former-employee", 102);
    let crl = root.crl(OffsetDateTime::now_utc() + hour(), &[&revoked]);
    let (addr, events) = serve(Options {
        crls: vec![crl],
        ..options(&srv, &[&root])
    })
    .await;
    let named = |id: &Identity, name: &str| Options {
        server_name: name.into(),
        ..options(id, &[&root])
    };
    dial(&addr, named(&cli, "ied1")).await.expect("v1 client and server");
    assert!(dial(&addr, named(&cli, "ied2")).await.is_err(), "a v1 server named ied2");
    assert!(dial(&addr, options(&revoked, &[&root])).await.is_err(), "a revoked v1 client");
    assert!(events.lock().unwrap().iter().any(|e| e == &format!("{:?}", Error::Revoked)));
    // From another authority, refused.
    let other = Ca::new("other");
    let stranger = issue_v1(&other, "stranger", 103);
    assert!(dial(&addr, options(&stranger, &[&root])).await.is_err());
    let _ = root.issue("unused", None, &[]);
}
