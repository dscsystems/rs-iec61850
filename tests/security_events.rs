use std::sync::Arc;
use std::time::Duration;

use iec61850::client::{Client, Options as ClientOptions};
use iec61850::model::Fc;
use iec61850::scl;
use iec61850::secevent::{Action, Dispatcher, Event, Kind};
use iec61850::server::{Options, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

fn server(options: Options) -> (Server, mpsc::UnboundedReceiver<Event>) {
    let model = scl::load_model(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/simpleIO_direct_control.cid"
        ),
        &scl::BuildOptions::new(),
    )
    .unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let dispatcher = Dispatcher::new(
        16,
        Arc::new(move |event| {
            let _ = tx.send(event);
        }),
    )
    .unwrap();
    (
        Server::new(model, options.with_security_events(dispatcher)),
        rx,
    )
}

async fn event(rx: &mut mpsc::UnboundedReceiver<Event>, kind: Kind) -> Event {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let event = rx.recv().await.unwrap();
            if event.kind == kind {
                return event;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("missing {}", kind.code()))
}

async fn start(server: &Server) -> (String, tokio::task::JoinHandle<()>) {
    let listener = server.bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = server.clone();
    let running = tokio::spawn(async move { server.serve(listener).await.unwrap() });
    (address, running)
}

#[tokio::test]
async fn events_correlate_an_association_and_count_io() {
    let (server, mut rx) = server(Options::new());
    let (address, running) = start(&server).await;
    let client = Client::dial_with(&address, ClientOptions::new().with_password("private"))
        .await
        .unwrap();
    client
        .read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx)
        .await
        .unwrap();
    client.close().await.unwrap();

    let accepted = event(&mut rx, Kind::ConnAccepted).await;
    let associated = event(&mut rx, Kind::AssocEstablished).await;
    let closed = event(&mut rx, Kind::ConnClosed).await;
    assert!(accepted.session_id.is_some());
    assert_eq!(associated.session_id, accepted.session_id);
    assert_eq!(closed.session_id, accepted.session_id);
    assert!(
        associated
            .peer
            .as_ref()
            .unwrap()
            .acse
            .as_ref()
            .unwrap()
            .password_presented
    );
    let json = associated.json();
    assert_eq!(json["peer"]["local"], address);
    assert!(!json.to_string().contains("private"));
    let summary = closed.summary.unwrap();
    assert_eq!(summary.reason, "concluded");
    assert_eq!(summary.requests, 1);
    assert!(summary.octets_in > 0 && summary.octets_out > 0);
    assert_eq!(server.security_stats().reported, 3);
    server.close().await.unwrap();
    running.await.unwrap();
}

#[tokio::test]
async fn classifies_setup_failures_and_releases_slots_on_shutdown() {
    let (server, mut rx) = server(
        Options::new()
            .with_handshake_timeout(Duration::from_millis(150))
            .with_max_connections(1),
    );
    let (address, running) = start(&server).await;

    drop(TcpStream::connect(&address).await.unwrap());
    let no_data = event(&mut rx, Kind::ConnNoData).await;
    assert_eq!(no_data.stage, Some("cotp"));

    let mut raw = TcpStream::connect(&address).await.unwrap();
    raw.write_all(&[3, 0, 0, 7, 2, 0xf0, 0x80]).await.unwrap();
    let malformed = event(&mut rx, Kind::AssocSetupFailed).await;
    assert_eq!(malformed.stage, Some("cotp"));
    assert!(malformed.error.is_some());

    let silent = TcpStream::connect(&address).await.unwrap();
    let accepted = event(&mut rx, Kind::ConnAccepted).await;
    drop(TcpStream::connect(&address).await.unwrap());
    let refused = event(&mut rx, Kind::ConnRejectedLimit).await;
    assert_ne!(accepted.session_id, refused.session_id);
    assert_eq!(refused.action, Action::Rejected);
    let expired = event(&mut rx, Kind::ConnNeverAssociated).await;
    assert_eq!(expired.session_id, accepted.session_id);
    drop(silent);

    let mut setup = TcpStream::connect(&address).await.unwrap();
    let accepted = event(&mut rx, Kind::ConnAccepted).await;
    server.close().await.unwrap();
    let closed = event(&mut rx, Kind::ConnClosed).await;
    assert_eq!(closed.session_id, accepted.session_id);
    assert_eq!(closed.summary.unwrap().reason, "closed locally");
    assert_eq!(
        setup.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    running.await.unwrap();
    assert_eq!(server.open_connections(), 0);
}

#[tokio::test]
async fn a_trickled_tpkt_and_an_idle_association_report_distinct_reasons() {
    let (server, mut rx) = server(
        Options::new()
            .with_frame_timeout(Duration::from_millis(180))
            .with_idle_timeout(Duration::from_millis(320)),
    );
    let (address, running) = start(&server).await;
    let idle = Client::dial(&address).await.unwrap();
    event(&mut rx, Kind::AssocEstablished).await;
    let expired = event(&mut rx, Kind::ConnIdleTimeout).await;
    let closed = event(&mut rx, Kind::ConnClosed).await;
    assert_eq!(expired.session_id, closed.session_id);
    assert_eq!(closed.summary.unwrap().reason, "idle timeout");
    drop(idle);

    let mut socket = TcpStream::connect(&address).await.unwrap();
    let (client, mut proxy) = tokio::io::duplex(8192);
    let dial = tokio::spawn(Client::from_stream(Box::new(client), ClientOptions::new()));
    // Drive the client setup to completion on the real server. Cancelling
    // the bridge after the handshake lets the test send a partial TPKT.
    let client = tokio::select! {
        result = dial => result.unwrap().unwrap(),
        result = tokio::io::copy_bidirectional(&mut socket, &mut proxy) => panic!("bridge ended: {result:?}"),
    };
    event(&mut rx, Kind::AssocEstablished).await;
    socket.write_all(&[3]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    socket.write_all(&[0]).await.unwrap();
    let slow = event(&mut rx, Kind::DosSlowFrame).await;
    let closed = event(&mut rx, Kind::ConnClosed).await;
    assert_eq!(slow.session_id, closed.session_id);
    assert_eq!(closed.summary.unwrap().reason, "frame timeout");
    drop(client);
    server.close().await.unwrap();
    running.await.unwrap();
}
