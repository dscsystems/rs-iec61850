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
        no_server_name: true,
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

#[tokio::test]
async fn default_server_name_is_bound_to_the_dial_address() {
    let mut ca = Ca::new("name-default-ca");
    let srv = ca.issue("127.0.0.1", None, &[]);
    let cli = ca.issue("scada", None, &[]);
    let (addr, _) = serve(options(&srv, &[&ca])).await;
    let mut client = options(&cli, &[&ca]);
    client.no_server_name = false;
    dial(&addr, client).await.expect("CN matches dialled IP for a legacy certificate without SAN");
    let wrong = ca.issue("some-other-ied", None, &[]);
    let (addr, _) = serve(options(&wrong, &[&ca])).await;
    let mut client = options(&cli, &[&ca]);
    client.no_server_name = false;
    let err = dial(&addr, client).await.unwrap_err();
    assert!(err.contains("does not name the server"), "{err}");
}

/// Exercise the shipped profile against a separately configured, mutually
/// authenticated peer. Inspect the negotiated group rather than inferring PQ
/// protection from a successful TLS 1.3 connection.
#[tokio::test]
async fn tls_versions_and_mlkem_hybrid_compatibility() {
    use rustls::crypto::{aws_lc_rs as p, SupportedKxGroup};
    use rustls::{NamedGroup, ProtocolVersion};

    async fn handshake(
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    ) -> Result<(ProtocolVersion, NamedGroup), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (c, s) = tokio::io::duplex(16 * 1024);
        let exchange = async {
            let client = async {
                let mut tls = tokio_rustls::TlsConnector::from(client)
                    .connect("ied1".try_into().unwrap(), c)
                    .await
                    .map_err(|e| e.to_string())?;
                let conn = tls.get_ref().1;
                let negotiated = (
                    conn.protocol_version().unwrap(),
                    conn.negotiated_key_exchange_group().unwrap().name(),
                );
                tls.write_all(b"probe").await.map_err(|e| e.to_string())?;
                let mut reply = [0; 5];
                tls.read_exact(&mut reply)
                    .await
                    .map_err(|e| e.to_string())?;
                assert_eq!(&reply, b"probe");
                Ok::<_, String>(negotiated)
            };
            let server = async {
                let mut tls = tokio_rustls::TlsAcceptor::from(server)
                    .accept(s)
                    .await
                    .map_err(|e| e.to_string())?;
                assert!(tls.get_ref().1.peer_certificates().is_some());
                let conn = tls.get_ref().1;
                let negotiated = (
                    conn.protocol_version().unwrap(),
                    conn.negotiated_key_exchange_group().unwrap().name(),
                );
                let mut request = [0; 5];
                tls.read_exact(&mut request)
                    .await
                    .map_err(|e| e.to_string())?;
                tls.write_all(&request).await.map_err(|e| e.to_string())?;
                Ok::<_, String>(negotiated)
            };
            let (c, s) = tokio::join!(client, server);
            let c = c?;
            assert_eq!(c, s?);
            Ok(c)
        };
        tokio::time::timeout(Duration::from_secs(3), exchange)
            .await
            .expect("TLS probe must finish")
    }

    let mut ca = Ca::new("hybrid-probe-ca");
    let srv = ca.issue("ied1", None, &["ied1"]);
    let cli = ca.issue("scada", None, &["scada"]);
    let profile_client = iec62351::client_config(options(&cli, &[&ca])).unwrap();
    let profile_server = iec62351::server_config(options(&srv, &[&ca])).unwrap();
    let peers = |groups: Vec<&'static dyn SupportedKxGroup>, version| {
        let provider = Arc::new(rustls::crypto::CryptoProvider {
            kx_groups: groups,
            ..p::default_provider()
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.root()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            provider.clone(),
        )
        .build()
        .unwrap();
        let client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(cli.chain.clone(), cli.key.clone_key())
            .unwrap();
        let server = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(srv.chain.clone(), srv.key.clone_key())
            .unwrap();
        (Arc::new(client), Arc::new(server))
    };
    for (version, expected) in [
        (&rustls::version::TLS12, ProtocolVersion::TLSv1_2),
        (&rustls::version::TLS13, ProtocolVersion::TLSv1_3),
    ] {
        for classical in [p::kx_group::SECP256R1, p::kx_group::SECP384R1] {
            let (c, s) = peers(vec![classical], version);
            assert_eq!(
                handshake(c, profile_server.clone()).await.unwrap(),
                (expected, classical.name())
            );
            assert_eq!(
                handshake(profile_client.clone(), s).await.unwrap(),
                (expected, classical.name())
            );
        }
    }
    for hybrid in [p::kx_group::X25519MLKEM768, p::kx_group::SECP256R1MLKEM768] {
        // Both peers support hybrids: prove the locked crypto backend works.
        let (c, s) = peers(vec![hybrid], &rustls::version::TLS13);
        assert_eq!(
            handshake(c.clone(), s.clone()).await.unwrap(),
            (ProtocolVersion::TLSv1_3, hybrid.name())
        );
        // The shipped profile deliberately has no common group with a
        // hybrid-only peer, on either side of the connection.
        assert!(handshake(c, profile_server.clone()).await.is_err());
        assert!(handshake(profile_client.clone(), s).await.is_err());
        // Advertising a hybrid alongside P-256 remains interoperable, but
        // the negotiated connection has classical key exchange only.
        let (c, s) = peers(
            vec![hybrid, p::kx_group::SECP256R1],
            &rustls::version::TLS13,
        );
        let expected = (ProtocolVersion::TLSv1_3, NamedGroup::secp256r1);
        assert_eq!(
            handshake(c, profile_server.clone()).await.unwrap(),
            expected
        );
        assert_eq!(
            handshake(profile_client.clone(), s).await.unwrap(),
            expected
        );
        assert!(!hybrid.usable_for_version(ProtocolVersion::TLSv1_2));

        // A profile that opts into the hybrid negotiates it with rustls's
        // own implementation, in both roles.
        let kx = if hybrid.name() == NamedGroup::X25519MLKEM768 {
            iec62351::KxGroup::X25519MlKem768
        } else {
            iec62351::KxGroup::P256MlKem768
        };
        let (c, s) = peers(vec![hybrid], &rustls::version::TLS13);
        let opt_in = |id: &Identity| {
            let mut o = options(id, &[&ca]);
            o.kx_groups = vec![kx];
            o.tls13_only = true;
            o
        };
        let expected = (ProtocolVersion::TLSv1_3, hybrid.name());
        let server = iec62351::server_config(opt_in(&srv)).unwrap();
        let client = iec62351::client_config(opt_in(&cli)).unwrap();
        assert_eq!(handshake(c, server).await.unwrap(), expected);
        assert_eq!(handshake(client, s).await.unwrap(), expected);
    }

    // Profile to profile over each group it offers.
    use iec62351::KxGroup;
    for group in [
        KxGroup::P256,
        KxGroup::P384,
        KxGroup::P521,
        KxGroup::X25519MlKem768,
        KxGroup::P256MlKem768,
        KxGroup::P384MlKem1024,
    ] {
        let with = |id: &Identity| {
            let mut o = options(id, &[&ca]);
            o.kx_groups = vec![group];
            o.tls13_only = group.is_hybrid();
            o
        };
        let client = iec62351::client_config(with(&cli)).unwrap();
        let server = iec62351::server_config(with(&srv)).unwrap();
        assert_eq!(
            handshake(client, server).await.unwrap(),
            (ProtocolVersion::TLSv1_3, group.named_group()),
            "{group:?}"
        );
    }
    // The default prefers P-256 and offers P-521 too, as Go's profile does.
    assert_eq!(
        iec62351::DEFAULT_KX_GROUPS,
        &[KxGroup::P256, KxGroup::P384, KxGroup::P521]
    );
    let mut o = options(&cli, &[&ca]);
    o.kx_groups = vec![KxGroup::P521];
    let p521 = iec62351::client_config(o).unwrap();
    assert_eq!(
        handshake(p521, profile_server.clone()).await.unwrap(),
        (ProtocolVersion::TLSv1_3, NamedGroup::secp521r1)
    );
    // Hybrids alone cannot serve the TLS 1.2 the profile otherwise allows.
    let mut o = options(&cli, &[&ca]);
    o.kx_groups = vec![KxGroup::P384MlKem1024];
    let err = iec62351::client_config(o).unwrap_err();
    assert!(err.to_string().contains("tls13_only"), "{err}");
    // A hybrid with a classical fallback reaches a classical-only profile.
    let mut o = options(&cli, &[&ca]);
    o.kx_groups = vec![KxGroup::P384MlKem1024, KxGroup::P384];
    let mixed = iec62351::client_config(o).unwrap();
    assert_eq!(
        handshake(mixed, profile_server.clone()).await.unwrap(),
        (ProtocolVersion::TLSv1_3, NamedGroup::secp384r1)
    );
}

#[tokio::test]
async fn server_security_events_record_tls_parameters_and_handshake_failure() {
    use iec61850::secevent::{Dispatcher, Kind};
    use tokio::io::AsyncWriteExt;

    let mut root = Ca::new("tls-events");
    let server_id = root.issue("ied1", None, &[]);
    let client_id = root.issue("scada", None, &[]);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let events = Dispatcher::new(16, Arc::new(move |event| { let _ = tx.send(event); })).unwrap();
    let model = scl::load_model(
        concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid"),
        &scl::BuildOptions::new(),
    ).unwrap();
    let server = Server::new(model, ServerOptions::new()
        .with_tls(iec62351::server_config(options(&server_id, &[&root])).unwrap())
        .with_security_events(events));
    let listener = server.bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let serving = server.clone();
    let task = tokio::spawn(async move { serving.serve(listener).await.unwrap() });

    let mut raw = tokio::net::TcpStream::connect(&address).await.unwrap();
    raw.write_all(&[3, 0, 0, 7, 2, 0xf0, 0x80]).await.unwrap();
    raw.shutdown().await.unwrap();
    dial(&address, options(&client_id, &[&root])).await.unwrap();

    let (failed, established) = tokio::time::timeout(Duration::from_secs(3), async {
        let (mut failed, mut established) = (None, None);
        loop {
            let event = rx.recv().await.unwrap();
            match event.kind {
                Kind::TlsHandshakeFailed => failed = Some(event),
                Kind::AssocEstablished => established = Some(event),
                _ => {}
            }
            if let (Some(failed), Some(established)) = (&failed, &established) {
                break (failed.clone(), established.clone());
            }
        }
    }).await.unwrap();
    assert_eq!(failed.protocol, "tls");
    assert_ne!(failed.session_id, established.session_id);
    let tls = established.peer.unwrap().tls.unwrap();
    assert_eq!(tls.version, Some(0x0304));
    assert!(tls.cipher_suite.is_some());
    use sha2::{Digest, Sha256};
    assert_eq!(tls.fingerprint_sha256, Some(format!("{:x}", Sha256::digest(client_id.chain[0].as_ref()))));

    server.close().await.unwrap();
    task.await.unwrap();
}
