//! Interoperability with go-iec61850's security layers, both ways: R-GOOSE
//! and R-SV (IEC 61850-90-5), GDOI key distribution (IEC 62351-9) and MMS
//! over TLS (IEC 62351-3). The MMS services themselves are checked against
//! the Go library by `interop/run.sh`.
//!
//! The Go side is `interop/go/peer`, which `interop/go-security.sh` builds
//! and names in `IEC61850_GO_PEER`; without it every test is skipped.

mod interop_common;

#[cfg(feature = "gdoi")]
use std::net::SocketAddr;
#[cfg(feature = "gdoi")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "tls")]
use std::time::Duration;

use interop_common::rsession::*;
use interop_common::*;
#[cfg(feature = "tls")]
use tokio::io::{AsyncBufReadExt, BufReader};

// ---------------------------------------------------------------------------
// R-GOOSE and R-SV.
// ---------------------------------------------------------------------------

/// Every mode, both ways: unlike libiec61850, the Go library sends
/// HMAC-SHA256-256 correctly and accepts unsecured SPDUs when told to.
fn all_modes() -> Vec<(&'static str, Option<iec61850::rsession::Key>)> {
    use iec61850::rsession::{SecAlgorithm as S, SigAlgorithm as G};
    vec![
        ("unsecured", None),
        ("HMAC-SHA256-80", key(S::NONE, G::HMAC_SHA256_80, KEY16)),
        ("HMAC-SHA256-128", key(S::NONE, G::HMAC_SHA256_128, KEY16)),
        ("HMAC-SHA256-256", key(S::NONE, G::HMAC_SHA256_256, &KEY32)),
        ("HMAC-SHA3-128", key(S::NONE, G::HMAC_SHA3_128, KEY16)),
        ("AES-128-GCM", key(S::AES_128_GCM, G::NONE, KEY16)),
        ("AES-256-GCM", key(S::AES_256_GCM, G::NONE, &KEY32)),
    ]
}

#[tokio::test(flavor = "multi_thread")]
async fn goose_from_go() {
    let Some(bin) = need("IEC61850_GO_PEER") else { return };
    goose_from(&bin, all_modes()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn goose_to_go() {
    let Some(bin) = need("IEC61850_GO_PEER") else { return };
    goose_to(&bin, all_modes()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sv_from_go() {
    let Some(bin) = need("IEC61850_GO_PEER") else { return };
    sv_from(&bin, all_modes()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sv_to_go() {
    let Some(bin) = need("IEC61850_GO_PEER") else { return };
    sv_to(&bin, all_modes()).await;
}

// ---------------------------------------------------------------------------
// A test PKI, written as PEM files the Go peer reads.
// ---------------------------------------------------------------------------

#[cfg(feature = "tls")]
struct Pki {
    dir: std::path::PathBuf,
    ca: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

#[cfg(feature = "tls")]
/// One end's files and the matching Rust credentials.
struct Identity {
    cert: String,
    key: String,
    root: String,
    der: Vec<u8>,
    key_der: Vec<u8>,
}

#[cfg(feature = "tls")]
impl Pki {
    fn new(name: &str) -> Pki {
        let dir = temp_dir(name);
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, "interop CA");
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = p.self_signed(&ca_key).unwrap();
        std::fs::write(dir.join("root.pem"), ca.pem()).unwrap();
        Pki { dir, ca, ca_key }
    }

    fn issue(&self, cn: &str) -> Identity {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, cn);
        p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let cert = p.signed_by(&key, &self.ca, &self.ca_key).unwrap();
        let (c, k) = (self.dir.join(format!("{cn}.pem")), self.dir.join(format!("{cn}.key")));
        std::fs::write(&c, cert.pem()).unwrap();
        std::fs::write(&k, key.serialize_pem()).unwrap();
        Identity {
            cert: c.display().to_string(),
            key: k.display().to_string(),
            root: self.dir.join("root.pem").display().to_string(),
            der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }

    fn root_der(&self) -> Vec<u8> {
        self.ca.der().to_vec()
    }
}

#[cfg(feature = "tls")]
/// A long-running Go peer: its output lines arrive on a channel, and it ends
/// when the test drops it (its stdin closes).
struct GoPeer {
    child: tokio::process::Child,
    lines: tokio::sync::mpsc::UnboundedReceiver<String>,
    seen: Vec<String>,
}

#[cfg(feature = "tls")]
impl GoPeer {
    fn start(bin: &str, args: &[&str]) -> GoPeer {
        let mut child = Command::new(bin)
            .args(args)
            .env("SIMPLEIO_CID", testdata("simpleIO_direct_control.cid"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (tx, lines) = tokio::sync::mpsc::unbounded_channel();
        let out = child.stdout.take().unwrap();
        let err = child.stderr.take().unwrap();
        for stream in [Box::new(out) as Box<dyn tokio::io::AsyncRead + Unpin + Send>, Box::new(err)] {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(stream).lines();
                while let Ok(Some(l)) = r.next_line().await {
                    let _ = tx.send(l);
                }
            });
        }
        GoPeer { child, lines, seen: Vec::new() }
    }

    /// Waits for a line starting with `prefix` and returns the rest of it.
    async fn expect(&mut self, prefix: &str) -> String {
        if let Some(i) = self.seen.iter().position(|l| l.starts_with(prefix)) {
            return self.seen.remove(i)[prefix.len()..].trim().to_string();
        }
        loop {
            match tokio::time::timeout(Duration::from_secs(10), self.lines.recv()).await {
                Ok(Some(l)) if l.starts_with(prefix) => return l[prefix.len()..].trim().to_string(),
                Ok(Some(l)) => self.seen.push(l),
                _ => panic!("the Go peer never printed {prefix:?}; it printed {:?}", self.seen),
            }
        }
    }

    /// Waits for the peer to exit and returns whether it succeeded, with
    /// everything it printed.
    async fn finish(mut self) -> (bool, Vec<String>) {
        drop(self.child.stdin.take());
        let ok = tokio::time::timeout(Duration::from_secs(15), self.child.wait())
            .await
            .ok()
            .and_then(Result::ok)
            .is_some_and(|s| s.success());
        tokio::time::sleep(Duration::from_millis(50)).await;
        while let Ok(l) = self.lines.try_recv() {
            self.seen.push(l);
        }
        (ok, self.seen)
    }
}

// ---------------------------------------------------------------------------
// GDOI.
// ---------------------------------------------------------------------------

#[cfg(feature = "gdoi")]
mod gdoi_interop {
    use super::*;
    use iec61850::asn1::Oid;
    use iec61850::gdoi::{self, AuthAlg, Credentials, EncAlg, GroupId, MemberConfig, Peer, PrivateKey, Tek};
    use rustls::pki_types::CertificateDer;

    fn group() -> GroupId {
        GroupId::oid(Oid::from([1, 2, 840, 10070, 61850, 1]))
    }

    fn rust_credentials(pki: &Pki, id: &Identity) -> Credentials {
        Credentials {
            certificates: vec![CertificateDer::from(id.der.clone())],
            key: Some(PrivateKey::from_pkcs8_der(&id.key_der).unwrap()),
            roots: vec![CertificateDer::from(pki.root_der())],
            psk: Vec::new(),
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// A Rust member registering with the Go key server takes the TEK it
    /// holds, with a pre-shared key and with certificates.
    #[tokio::test]
    async fn rust_member_go_key_server() {
        let Some(bin) = need("IEC61850_GO_PEER") else { return };
        let pki = Pki::new("gdoi-go-ks");
        let ks = pki.issue("ks-go");
        let gm = pki.issue("ied-rust");
        for mode in ["psk", "cert"] {
            let mut args = vec!["gdoi-server", "127.0.0.1:0"];
            match mode {
                "psk" => args.extend(["psk", "substation secret"]),
                _ => args.extend(["cert", ks.cert.as_str(), ks.key.as_str(), ks.root.as_str()]),
            }
            let mut go = GoPeer::start(&bin, &args);
            let tek = go.expect("tek ").await;
            let addr = go.expect("listening ").await;
            let credentials = match mode {
                "psk" => Credentials {
                    psk: b"substation secret".to_vec(),
                    ..Default::default()
                },
                _ => rust_credentials(&pki, &gm),
            };
            let cfg = MemberConfig {
                server: addr,
                credentials,
                authorize_server: Some(Arc::new(|p: &Peer| {
                    if p.certificate.is_none() || p.common_name.as_deref() == Some("ks-go") {
                        Ok(())
                    } else {
                        Err(format!("unexpected key server {p}"))
                    }
                })),
                retransmit: Duration::from_millis(500),
                ..Default::default()
            };
            let reg = tokio::time::timeout(Duration::from_secs(10), gdoi::register(&cfg, &group()))
                .await
                .expect("registration timed out")
                .unwrap_or_else(|e| panic!("{mode}: register with the Go key server: {e}"));
            assert_eq!(reg.teks.len(), 1, "{mode}");
            let t = &reg.teks[0];
            assert_eq!(format!("{} {}", t.spi, hex(&t.algorithm_key)), tek, "{mode}: the TEK");
            assert_eq!((t.enc, t.auth), (EncAlg::AES_GCM_128, AuthAlg::NONE));
            let registered = go.expect("register ").await;
            if mode == "cert" {
                assert!(registered.contains("ied-rust"), "{registered}");
                assert_eq!(reg.server.common_name.as_deref(), Some("ks-go"));
            }
            // The TEK is usable: it keys a session.
            t.rsession_key().unwrap();
            let (ok, out) = go.finish().await;
            assert!(ok, "{mode}: {out:?}");
        }
    }

    /// The Go member registering with the Rust key server takes the TEK it
    /// holds, with a pre-shared key and with certificates.
    #[tokio::test]
    async fn go_member_rust_key_server() {
        let Some(bin) = need("IEC61850_GO_PEER") else { return };
        let pki = Pki::new("gdoi-rust-ks");
        let ks = pki.issue("ks-rust");
        let gm = pki.issue("ied-go");
        for mode in ["psk", "cert"] {
            let registered: Arc<Mutex<Vec<String>>> = Arc::default();
            let r = registered.clone();
            let mut cfg = gdoi::ServerConfig {
                authorize: Some(Arc::new(|_: &Peer, _: &GroupId| true)),
                on_register: Some(Arc::new(move |p: &Peer, _: &GroupId, _: &[Tek]| r.lock().unwrap().push(p.to_string()))),
                ..Default::default()
            };
            match mode {
                "psk" => cfg.psk = Some(Arc::new(|_: SocketAddr| Some(b"substation secret".to_vec()))),
                _ => cfg.credentials = rust_credentials(&pki, &ks),
            }
            let server = gdoi::Server::new(cfg).unwrap();
            let group_keys = Arc::new(gdoi::Group::new());
            let tek = Tek::new(Oid::from([1, 2, 840, 10070, 61850, 1]), Vec::new(), AuthAlg::NONE, EncAlg::AES_GCM_128, Duration::from_secs(3600)).unwrap();
            group_keys.add(tek.clone()).unwrap();
            server.add_group(group(), group_keys);
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = sock.local_addr().unwrap().to_string();
            let task = tokio::spawn({
                let server = server.clone();
                async move {
                    let _ = server.serve(sock).await;
                }
            });
            let mut args = vec!["gdoi-member", addr.as_str()];
            match mode {
                "psk" => args.extend(["psk", "substation secret"]),
                _ => args.extend(["cert", gm.cert.as_str(), gm.key.as_str(), gm.root.as_str()]),
            }
            let (out, ok) = run(&bin, &args, None, Duration::from_secs(15)).await;
            task.abort();
            assert!(ok, "{mode}: the Go member failed:\n{out}");
            let want = format!("tek {} {} {} {}", tek.spi, tek.enc.0, tek.auth.0, hex(&tek.algorithm_key));
            assert!(out.contains(&want), "{mode}: the Go member printed\n{out}\nwant {want}");
            if mode == "cert" {
                assert!(out.contains("server CN=ks-rust"), "{out}");
                let reg = registered.lock().unwrap();
                assert!(reg.iter().any(|p| p == "CN=ied-go"), "{reg:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MMS over TLS.
// ---------------------------------------------------------------------------

#[cfg(feature = "tls")]
mod tls_interop {
    use super::*;
    use iec61850::client::{Client, Options as ClientOptions};
    use iec61850::iec62351::{self, Options as TlsOptions};
    use iec61850::model::Fc;
    use iec61850::server::{Options, Server};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

    fn options(pki: &Pki, id: &Identity, name: &str) -> TlsOptions {
        TlsOptions {
            certificates: vec![CertificateDer::from(id.der.clone())],
            key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone()))),
            roots: vec![CertificateDer::from(pki.root_der())],
            server_name: name.into(),
            ..Default::default()
        }
    }

    /// The Rust client under the profile against the Go server under it.
    #[tokio::test]
    async fn rust_client_go_tls_server() {
        let Some(bin) = need("IEC61850_GO_PEER") else { return };
        let pki = Pki::new("tls-go-server");
        let srv = pki.issue("ied1");
        let cli = pki.issue("scada");
        let mut go = GoPeer::start(&bin, &["tls-server", "127.0.0.1:0", &srv.cert, &srv.key, &srv.root]);
        let addr = go.expect("listening ").await;
        let cfg = iec62351::client_config(options(&pki, &cli, "ied1")).unwrap();
        let c = Client::dial_with(&addr, ClientOptions::new().with_tls(cfg).with_timeout(Duration::from_secs(5)))
            .await
            .expect("associate with the Go server over TLS");
        c.read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx).await.expect("read over TLS");
        c.close().await.unwrap();
        // Another name is refused.
        let bad = iec62351::client_config(options(&pki, &cli, "ied2")).unwrap();
        assert!(Client::dial_with(&addr, ClientOptions::new().with_tls(bad).with_timeout(Duration::from_secs(5))).await.is_err());
        // A client from another authority is refused by the Go server.
        let other = Pki::new("tls-go-other");
        let stranger = other.issue("stranger");
        let mut o = options(&other, &stranger, "ied1");
        o.roots = vec![CertificateDer::from(pki.root_der())];
        let cfg = iec62351::client_config(o).unwrap();
        let res = Client::dial_with(&addr, ClientOptions::new().with_tls(cfg).with_timeout(Duration::from_secs(5))).await;
        let refused = match res {
            Err(_) => true,
            Ok(c) => c.read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx).await.is_err(),
        };
        assert!(refused, "the Go server served a client from another authority");
        let (_, out) = go.finish().await;
        assert!(out.iter().any(|l| l.starts_with("event")), "the Go server reported no refusal: {out:?}");
    }

    /// The Go client under the profile against the Rust server under it.
    #[tokio::test]
    async fn go_client_rust_tls_server() {
        let Some(bin) = need("IEC61850_GO_PEER") else { return };
        let pki = Pki::new("tls-rust-server");
        let srv = pki.issue("ied1");
        let cli = pki.issue("scada");
        let cfg = iec62351::server_config(options(&pki, &srv, "")).unwrap();
        let server = Server::new(
            iec61850::scl::load_model(testdata("simpleIO_direct_control.cid"), &iec61850::scl::BuildOptions::new()).unwrap(),
            Options::new().with_tls(cfg),
        );
        let (host, port) = serve(&server).await;
        let addr = format!("{host}:{port}");
        let (out, ok) = run(&bin, &["tls-client", &addr, &cli.cert, &cli.key, &cli.root, "ied1"], None, Duration::from_secs(15)).await;
        assert!(ok && out.contains("read "), "the Go client:\n{out}");
        let (out, ok) = run(&bin, &["tls-client", &addr, &cli.cert, &cli.key, &cli.root, "ied2"], None, Duration::from_secs(15)).await;
        assert!(!ok, "the Go client accepted the Rust server as ied2:\n{out}");
    }
}
