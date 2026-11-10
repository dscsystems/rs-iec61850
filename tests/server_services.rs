//! The MMS services beyond reading and writing, over a real association:
//! authentication, Status, Abort, SetFile, DeleteFile, FileRename and the data
//! set deletion rules.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850::client::{Client, DataSetEntry, Options as ClientOptions};
use iec61850::mms::{self, service, ErrorClass, Value};
use iec61850::model::{self, Fc};
use iec61850::scl;
use iec61850::server::{ConnectionState, Options, Server};
use tokio::net::TcpListener;

const LD: &str = "simpleIOGenericIO";

fn simple_io() -> model::Model {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid");
    scl::load_model(path, &scl::BuildOptions::new()).expect("fixture loads")
}

async fn start(opts: Options) -> (Server, String) {
    let s = Server::new(simple_io(), opts);
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let serving = s.clone();
    tokio::spawn(async move {
        let _ = serving.serve(ln).await;
    });
    (s, addr)
}

fn copts() -> ClientOptions {
    ClientOptions::new().with_timeout(Duration::from_secs(3))
}

async fn dial(addr: &str) -> Client {
    Client::dial_with(addr, copts()).await.expect("dial")
}

/// The confirmed error's class and code, if the failure was one.
fn service_error(e: &iec61850::client::Error) -> Option<(ErrorClass, u8)> {
    e.as_service_error().map(|se| (se.class, se.code))
}

fn temp_dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("iec61850-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The server authenticates associations and refuses the ones that fail with
/// an ACSE rejection the client can read.
#[tokio::test]
async fn associations_are_authenticated() {
    let (_s, addr) = start(Options::new().with_password("s3cret")).await;
    let c = Client::dial_with(&addr, copts().with_password("s3cret")).await.unwrap();
    c.close().await.unwrap();

    let err = Client::dial_with(&addr, copts().with_password("guess")).await.unwrap_err();
    match &err {
        iec61850::client::Error::Mms(e @ mms::Error::Rejected(13)) => {
            assert!(e.is_authentication_failure())
        }
        other => panic!("wrong password: {other:?}, want authentication-failure"),
    }
    let err = Client::dial_with(&addr, copts()).await.unwrap_err();
    assert!(
        matches!(err, iec61850::client::Error::Mms(mms::Error::Rejected(14))),
        "no password: {err:?}, want authentication-required"
    );

    // An authenticator sees the association's details.
    let seen: Arc<Mutex<Option<mms::AssociationRequest>>> = Arc::default();
    let s2 = seen.clone();
    let (_s, addr2) = start(Options::new().with_authenticator(move |r| {
        *s2.lock().unwrap() = Some(r.clone());
        Ok(())
    }))
    .await;
    let c = Client::dial_with(&addr2, copts().with_password("pw")).await.unwrap();
    c.close().await.unwrap();
    let seen = seen.lock().unwrap().clone().expect("the authenticator was called");
    assert_eq!(seen.password.as_deref(), Some("pw"));
    assert!(seen.peer.is_some());
    assert!(seen.peer_certificates.is_empty());
}

#[tokio::test]
async fn status_follows_the_server() {
    let (s, addr) = start(Options::new()).await;
    let c = dial(&addr).await;
    let st = c.server_status(false).await.unwrap();
    assert_eq!(
        (st.logical, st.physical),
        (mms::logical::STATE_CHANGES_ALLOWED, mms::physical::OPERATIONAL)
    );
    s.set_status(mms::logical::NO_STATE_CHANGES_ALLOWED, mms::physical::NEEDS_COMMISSIONING);
    let st = c.server_status(true).await.unwrap();
    assert_eq!((st.logical, st.physical), (1, 3));
}

/// An abort ends the association at both ends, whichever end sends it.
#[tokio::test]
async fn an_abort_ends_the_association_at_both_ends() {
    let (s, addr) = start(Options::new()).await;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    s.on_connection(move |ev| {
        let _ = tx.send((ev.state, ev.conn));
    });

    let c = dial(&addr).await;
    assert_eq!(next_event(&mut rx).await.0, ConnectionState::Opened);
    c.abort().await.unwrap();
    assert_eq!(next_event(&mut rx).await.0, ConnectionState::Closed, "the server did not end it");
    let err = c.server_status(false).await.unwrap_err();
    assert!(
        matches!(err, iec61850::client::Error::Mms(mms::Error::Aborted(_) | mms::Error::Closed)),
        "request after abort: {err:?}"
    );

    // The server aborts; the client sees it.
    let c2 = dial(&addr).await;
    let (state, id) = next_event(&mut rx).await;
    assert_eq!(state, ConnectionState::Opened);
    assert!(s.abort(id.unwrap()).await);
    tokio::time::timeout(Duration::from_secs(3), c2.closed())
        .await
        .expect("the client did not see the server's abort");
    let err = c2.err().expect("an error after the abort");
    assert!(matches!(*err, mms::Error::Aborted(_)), "client error after the abort: {err:?}");
}

async fn next_event<T>(rx: &mut tokio::sync::mpsc::UnboundedReceiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("a connection event")
        .unwrap()
}

#[tokio::test]
async fn set_file_and_delete_file() {
    let dir = temp_dir("setfile");
    let (_s, addr) = start(Options::new().with_file_store(&dir)).await;
    let c = dial(&addr).await;

    // Larger than one fileRead chunk, so the server reads it in several.
    let data = b"COMTRADE ".repeat(5000);
    assert!(
        c.set_file("fault/record.cfg", Vec::new()).await.is_err(),
        "a file in a directory that does not exist was written"
    );
    c.set_file("record.cfg", data.clone()).await.unwrap();
    assert_eq!(std::fs::read(dir.join("record.cfg")).unwrap(), data);
    assert_eq!(c.read_file("record.cfg").await.unwrap(), data);
    // An existing name is not overwritten.
    let err = c.set_file("record.cfg", b"x".to_vec()).await.unwrap_err();
    assert_eq!(service_error(&err), Some((ErrorClass::FILE, 8)), "{err:?}");
    // Nothing outside the store.
    assert!(c.set_file("../escape.cfg", b"x".to_vec()).await.is_err());
    assert!(!dir.parent().unwrap().join("escape.cfg").exists());

    // From a local file.
    let local = temp_dir("setfile-src").join("local.bin");
    std::fs::write(&local, b"local content").unwrap();
    c.set_file_from(&local, "copy.bin").await.unwrap();
    assert_eq!(std::fs::read(dir.join("copy.bin")).unwrap(), b"local content");

    c.delete_file("/record.cfg").await.unwrap();
    assert!(!dir.join("record.cfg").exists());
    let err = c.delete_file("record.cfg").await.unwrap_err();
    assert_eq!(service_error(&err), Some((ErrorClass::FILE, 7)), "{err:?}");

    // A read-only store serves neither.
    let ro = temp_dir("setfile-ro");
    std::fs::write(ro.join("a.txt"), b"a").unwrap();
    let (_s, addr2) = start(Options::new().with_read_only_file_store(&ro)).await;
    let c2 = dial(&addr2).await;
    assert!(c2.set_file("b.txt", b"b".to_vec()).await.is_err());
    assert!(c2.delete_file("a.txt").await.is_err());
    assert!(ro.join("a.txt").exists());
}

/// fileRename renames within the store, never over an existing file nor
/// outside the store, and a read-only store refuses it.
#[tokio::test]
async fn rename_file() {
    let dir = temp_dir("rename");
    std::fs::write(dir.join("a.cfg"), b"A").unwrap();
    std::fs::write(dir.join("b.cfg"), b"B").unwrap();
    let (_s, addr) = start(Options::new().with_file_store(&dir)).await;
    let c = dial(&addr).await;
    assert!(c.mms().negotiated().services.has(service::FILE_RENAME));

    c.rename_file("a.cfg", "c.cfg").await.unwrap();
    assert_eq!(std::fs::read(dir.join("c.cfg")).unwrap(), b"A");
    assert!(!dir.join("a.cfg").exists());
    let err = c.rename_file("c.cfg", "b.cfg").await.unwrap_err();
    assert_eq!(service_error(&err), Some((ErrorClass::FILE, 8)), "{err:?}");
    assert_eq!(std::fs::read(dir.join("b.cfg")).unwrap(), b"B");
    let err = c.rename_file("missing.cfg", "d.cfg").await.unwrap_err();
    assert_eq!(service_error(&err), Some((ErrorClass::FILE, 7)), "{err:?}");
    assert!(c.rename_file("c.cfg", "../escape.cfg").await.is_err());

    let ro = temp_dir("rename-ro");
    std::fs::write(ro.join("a.txt"), b"a").unwrap();
    let (_s, addr2) = start(Options::new().with_read_only_file_store(&ro)).await;
    let c2 = dial(&addr2).await;
    assert!(!c2.mms().negotiated().services.has(service::FILE_RENAME));
    assert!(c2.rename_file("a.txt", "b.txt").await.is_err());
}

/// A configured data set, or one a control block uses, is not deleted.
#[tokio::test]
async fn data_set_deletion_rules() {
    let (_s, addr) = start(Options::new()).await;
    let c = dial(&addr).await;
    let not_deleted = |e: iec61850::client::Error| matches!(e, iec61850::client::Error::Mms(mms::Error::NotDeleted));

    let err = c.delete_data_set(format!("{LD}/LLN0.Events")).await.unwrap_err();
    assert!(not_deleted(err), "deleting a configured data set");
    let members = [DataSetEntry::new(format!("{LD}/GGIO1.SPCSO1.stVal"), Fc::St)];
    c.create_data_set(format!("{LD}/LLN0.Dyn1"), &members).await.unwrap();
    c.create_data_set(format!("{LD}/LLN0.Dyn2"), &members).await.unwrap();
    c.delete_data_set(format!("{LD}/LLN0.Dyn1")).await.unwrap();
    // Point a report control block at Dyn2: now it is in use.
    c.write(
        format!("{LD}/LLN0.EventsRCB01.DatSet"),
        Fc::Rp,
        Value::visible_string(format!("{LD}/LLN0$Dyn2")),
    )
    .await
    .unwrap();
    let err = c.delete_data_set(format!("{LD}/LLN0.Dyn2")).await.unwrap_err();
    assert!(not_deleted(err), "deleting a data set a report uses");
    assert!(c.delete_data_set(format!("{LD}/LLN0.Nope")).await.is_err());
}

/// Status runs alongside other requests on one association.
#[tokio::test]
async fn status_and_identify_survive_concurrent_use() {
    let (_s, addr) = start(Options::new()).await;
    let c = dial(&addr).await;
    let (a, b) = tokio::join!(c.server_status(false), c.mms().identify());
    a.unwrap();
    b.unwrap();
}

#[tokio::test]
async fn file_handles_are_scoped_bounded_and_released_with_the_association() {
    let root = temp_dir("file-handle-isolation");
    std::fs::write(root.join("data.bin"), b"private file").unwrap();
    let (server, addr) = start(Options::new().with_file_store(&root)).await;
    let first = dial(&addr).await;
    let second = dial(&addr).await;
    let (id, _) = first.mms().file_open("/data.bin").await.unwrap();
    assert!(second.mms().file_read(id).await.is_err());
    assert!(second.mms().file_close(id).await.is_err());
    // Large ids may not truncate to a valid handle on the wire.
    let err = second.mms().call(iec61850::asn1::int_elem(iec61850::asn1::context_primitive(service::FILE_READ as u32), i64::from(id) + (1i64 << 32))).await;
    assert!(err.is_err());
    assert_eq!(first.mms().file_read(id).await.unwrap().0, b"private file");
    let mut ids = vec![id];
    for _ in 1..16 { ids.push(first.mms().file_open("data.bin").await.unwrap().0); }
    assert!(first.mms().file_open("data.bin").await.is_err());
    // One full association cannot deny another its allowance.
    let other = second.mms().file_open("data.bin").await.unwrap().0;
    second.mms().file_close(other).await.unwrap();
    for id in ids { first.mms().file_close(id).await.unwrap(); }
    first.close().await.unwrap();
    second.close().await.unwrap();
    server.close().await.unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn missing_report_blocks_are_errors_and_disable_releases_reservation() {
    let (server, addr) = start(Options::new()).await;
    let first = dial(&addr).await;
    assert!(first.get_rcb(format!("{LD}/LLN0.RP.missing")).await.is_err());
    let blocks = first.logical_node_directory(format!("{LD}/LLN0"), iec61850::client::AcsiClass::Urcb).await.unwrap();
    assert!(!blocks.is_empty());
    let reference = format!("{LD}/LLN0.RP.{}", blocks[0]);
    let rcb = first.get_rcb(reference.clone()).await.unwrap();
    let subscription = first.enable_reporting(&rcb, |_| {}).await.unwrap();
    subscription.disable().await.unwrap();
    let second = dial(&addr).await;
    let rcb = second.get_rcb(reference).await.unwrap();
    second.enable_reporting(&rcb, |_| {}).await.unwrap().disable().await.unwrap();
    server.close().await.unwrap();
}
