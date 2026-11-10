#![cfg(feature = "tls")]
use iec61850::{
    iec62351::{
        aprofile::{Config, Credential, Error, Value, Verifier},
        pki::TrustStore,
    },
    mms, scl,
    server::{Options, Server},
};
use rcgen::{CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};

static CLOCK: AtomicU64 = AtomicU64::new(0);
fn clock() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(CLOCK.load(Ordering::SeqCst))
}

fn credentials() -> (CertificateDer<'static>, Credential, Credential) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let make = |name: &str| {
        let key = KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        Credential::new(
            cert.der().to_vec(),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap()
    };
    (ca.der().clone(), make("client"), make("server"))
}

fn configs() -> (Arc<Config>, Arc<Config>) {
    let (root, client, server) = credentials();
    let trust = Arc::new(TrustStore::new(vec![root]).unwrap());
    let mut client_config = Config::new(client, Arc::new(Verifier::new(trust.clone())));
    client_config.allow_without_tls = true;
    let mut server_config = Config::new(server, Arc::new(Verifier::new(trust)));
    server_config.allow_without_tls = true;
    (Arc::new(client_config), Arc::new(server_config))
}

#[test]
fn certificate_authentication_checks_signatures_time_and_replay() {
    let (root, client, _) = credentials();
    let trust = Arc::new(TrustStore::new(vec![root]).unwrap());
    let mut verifier = Verifier::new(trust);
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    CLOCK.store(now, Ordering::SeqCst);
    verifier.now = clock;
    let mut value = client.sign(clock()).unwrap();
    value.indirect_reference = Some(9);
    assert_eq!(Value::parse(&value.encode()).unwrap(), value);
    let mut forged = value.clone();
    forged.signature[0] ^= 1;
    assert!(matches!(verifier.verify(&forged), Err(Error::Signature)));
    verifier.verify(&value).unwrap(); // forgery must not poison replay state
    assert!(matches!(verifier.verify(&value), Err(Error::Replay)));
    let old = client.sign(clock() - Duration::from_secs(601)).unwrap();
    assert!(matches!(verifier.verify(&old), Err(Error::Time)));
    let future = client.sign(clock() + Duration::from_secs(599)).unwrap();
    verifier.verify(&future).unwrap();
    CLOCK.store(now + 601, Ordering::SeqCst);
    assert!(
        matches!(verifier.verify(&future), Err(Error::Replay)),
        "a future token remains replay-protected throughout its validity"
    );
    for n in 0..value.encode().len() {
        assert!(Value::parse(&value.encode()[..n]).is_err());
    }
}

struct Handle;
impl mms::Handler for Handle {
    async fn handle(
        &self,
        _: mms::Request,
        _: &mms::ServerConn,
    ) -> mms::Result<iec61850::asn1::Element> {
        Err(mms::DataAccessError::ObjectNonExistent.into())
    }
}

async fn endpoint(config: Arc<Config>, required: bool) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let config = config.clone();
            tokio::spawn(async move {
                let opts = mms::AcceptOptions {
                    a_profile: Some(config),
                    a_profile_required: required,
                    ..Default::default()
                };
                if let Ok(conn) = mms::accept_conn_opts(Box::new(stream), Some(peer), &opts).await {
                    let _ = conn.serve(&Handle).await;
                }
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn mutual_acse_authentication_and_required_optional_modes() {
    let (client, server) = configs();
    let (addr, task) = endpoint(server, true).await;
    assert!(mms::Conn::dial(&addr, mms::Options::default())
        .await
        .is_err());
    let opts = mms::Options {
        a_profile: Some(client),
        ..Default::default()
    };
    let conn = mms::Conn::dial(&addr, opts).await.unwrap();
    assert!(conn.peer_a_profile_certificate().is_some());
    conn.close().await.unwrap();
    task.abort();
    let (_, server) = configs();
    let (addr, task) = endpoint(server, false).await;
    mms::Conn::dial(&addr, mms::Options::default())
        .await
        .unwrap()
        .close()
        .await
        .unwrap();
    task.abort();
}

#[tokio::test]
async fn high_level_api_authenticates_and_reads() {
    let (client, server_config) = configs();
    let model = scl::load_model(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/simpleIO_direct_control.cid"
        ),
        &scl::BuildOptions::new(),
    )
    .unwrap();
    let server = Arc::new(Server::new(
        model,
        Options::new().with_a_profile(server_config, true),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let copy = server.clone();
    let task = tokio::spawn(async move {
        copy.serve(listener).await.unwrap();
    });
    let opts = iec61850::client::Options::new().with_a_profile(client);
    let conn = iec61850::client::Client::dial_with(&addr, opts)
        .await
        .unwrap();
    conn.read(
        "simpleIOGenericIO/GGIO1.AnIn1.mag.f",
        iec61850::model::Fc::Mx,
    )
    .await
    .unwrap();
    conn.close().await.unwrap();
    server.close().await.unwrap();
    task.abort();
}

#[tokio::test]
async fn profile_rejects_clear_transport_and_password_combination() {
    let (client, server) = configs();
    let (addr, task) = endpoint(server, false).await;
    let (root, credential, _) = credentials();
    let config = Arc::new(Config::new(
        credential,
        Arc::new(Verifier::new(Arc::new(
            TrustStore::new(vec![root]).unwrap(),
        ))),
    ));
    let err = mms::Conn::dial(
        &addr,
        mms::Options {
            a_profile: Some(config),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("requires TLS"));
    let err = mms::Conn::dial(
        &addr,
        mms::Options {
            a_profile: Some(client),
            password: Some("pw".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("password"));
    task.abort();
}
