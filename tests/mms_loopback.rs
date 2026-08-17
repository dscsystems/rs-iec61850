//! End-to-end tests driving the MMS client against the MMS server over an
//! in-memory transport.
//!
//! These exercise the whole stack in one go: TPKT framing, the COTP CR/CC
//! handshake, the session CONNECT/ACCEPT, the presentation CP/CPA context
//! negotiation, the ACSE AARQ/AARE, and the MMS initiate exchange, followed by
//! confirmed services and unconfirmed reports. A fault anywhere in that
//! layering shows up here rather than only against a real device.

use std::sync::Arc;

use iec61850::asn1::{
    cons, context_constructed, context_primitive, prim, uint_elem, Decoder, Element,
    TAG_VISIBLE_STRING,
};
use iec61850::mms::{
    self, BoxTransport, Conn, DataAccessError, Error, Handler, ObjectClass, Request, ServerConn,
    Value, VarRef,
};

/// Confirmed service CHOICE tag numbers, repeated here so the test asserts
/// against the wire numbering rather than against the crate's constants.
const SVC_GET_NAME_LIST: u32 = 1;
const SVC_IDENTIFY: u32 = 2;
const SVC_READ: u32 = 4;
const SVC_WRITE: u32 = 5;

/// A minimal MMS server: enough of the service set to prove the stack round
/// trips, plus a deliberate failure path.
struct TestServer;

impl Handler for TestServer {
    async fn handle(&self, req: Request, conn: &ServerConn) -> mms::Result<Element> {
        match req.service {
            SVC_IDENTIFY => Ok(cons(
                context_constructed(SVC_IDENTIFY),
                [
                    prim(context_primitive(0), b"DSC Systems".to_vec()),
                    prim(context_primitive(1), b"rs-iec61850".to_vec()),
                    prim(context_primitive(2), b"0.1.0".to_vec()),
                ],
            )),

            SVC_GET_NAME_LIST => Ok(cons(
                context_constructed(SVC_GET_NAME_LIST),
                [
                    cons(
                        context_constructed(0),
                        [
                            prim(TAG_VISIBLE_STRING, b"simpleIOGenericIO".to_vec()),
                            prim(TAG_VISIBLE_STRING, b"simpleIOProtection".to_vec()),
                        ],
                    ),
                    // moreFollows [1] FALSE, or the client loops forever.
                    prim(context_primitive(1), vec![0x00]),
                ],
            )),

            SVC_READ => {
                // Answer with one value per requested item, and a per-element
                // failure for the last, to prove partial results survive.
                let n = count_read_items(&req.content);
                let mut results = Vec::new();
                for i in 0..n {
                    let v = if i + 1 == n && n > 1 {
                        Value::access_error(DataAccessError::ObjectNonExistent)
                    } else {
                        Value::float32(230.4)
                    };
                    results.push(mms::data_element(&v).expect("encodable"));
                }
                Ok(cons(
                    context_constructed(SVC_READ),
                    [cons(context_constructed(1), results)],
                ))
            }

            SVC_WRITE => {
                // The first item succeeds, any others are denied.
                let mut out = cons(context_constructed(SVC_WRITE), []);
                out.push(prim(context_primitive(1), vec![])); // success [1] NULL
                out.push(uint_elem(
                    context_primitive(0),
                    u64::from(DataAccessError::ObjectAccessDenied.code()),
                ));
                Ok(out)
            }

            // An unknown service must come back as a typed error the client
            // can match on, not a dropped request.
            99 => {
                // Push a report before failing, to prove unconfirmed PDUs and
                // confirmed responses share the association safely.
                let report = cons(
                    context_constructed(0), // informationReport
                    [
                        cons(
                            context_constructed(1), // variableListName
                            [cons(
                                context_constructed(1),
                                [
                                    prim(TAG_VISIBLE_STRING, b"simpleIOGenericIO".to_vec()),
                                    prim(TAG_VISIBLE_STRING, b"RPT".to_vec()),
                                ],
                            )],
                        ),
                        cons(
                            context_constructed(0),
                            [mms::data_element(&Value::visible_string("EventsRCB01")).unwrap()],
                        ),
                    ],
                );
                conn.send_unconfirmed(report).expect("queue the report");
                Err(Error::Access(DataAccessError::ObjectNonExistent))
            }

            other => Err(Error::Access(DataAccessError::from_code(other as u8))),
        }
    }
}

/// Counts the entries of a ReadRequest's listOfVariable.
fn count_read_items(content: &[u8]) -> usize {
    let mut dec = Decoder::new(content);
    // variableAccessSpecification [1] EXPLICIT { listOfVariable [0] }
    let Ok(Some(vas)) = dec.optional(context_constructed(1)) else {
        return 1;
    };
    let mut vd = Decoder::new(vas);
    let Ok(Some(list)) = vd.optional(context_constructed(0)) else {
        return 1; // a variableListName read names no members here
    };
    let mut ld = Decoder::new(list);
    let mut n = 0;
    while ld.more() && ld.skip().is_ok() {
        n += 1;
    }
    n
}

/// Brings up a client and a server joined by an in-memory duplex stream.
async fn connected() -> (Arc<Conn>, tokio::task::JoinHandle<()>) {
    let (client_side, server_side) = tokio::io::duplex(256 * 1024);

    let server = tokio::spawn(async move {
        let sc = mms::accept_conn(Box::new(server_side) as BoxTransport, None)
            .await
            .expect("server accepts the association");
        let _ = sc.serve(&TestServer).await;
    });

    let client = Conn::from_stream(
        Box::new(client_side) as BoxTransport,
        mms::Options::default(),
    )
    .await
    .expect("client establishes the association");

    (Arc::new(client), server)
}

#[tokio::test]
async fn an_association_is_established_through_every_layer() {
    let (client, _server) = connected().await;
    assert_eq!(client.state(), mms::State::Connected);
    assert!(client.err().is_none());
    // The server echoes the client's proposal, so the negotiated bound is the
    // client's own.
    assert_eq!(client.max_serv_outstanding(), 10);
    client.close().await.unwrap();
    assert_eq!(client.state(), mms::State::Closed);
}

#[tokio::test]
async fn identify_round_trips_the_vendor_model_and_revision() {
    let (client, _server) = connected().await;
    let (vendor, model, revision) = client.identify().await.unwrap();
    assert_eq!(vendor, "DSC Systems");
    assert_eq!(model, "rs-iec61850");
    assert_eq!(revision, "0.1.0");
}

#[tokio::test]
async fn get_name_list_returns_the_servers_domains() {
    let (client, _server) = connected().await;
    let names = client.get_name_list(ObjectClass::Domain, "").await.unwrap();
    assert_eq!(names, ["simpleIOGenericIO", "simpleIOProtection"]);
}

#[tokio::test]
async fn a_read_returns_one_result_per_item_including_per_element_failures() {
    let (client, _server) = connected().await;
    let values = client
        .read(
            "simpleIOGenericIO",
            &["GGIO1$MX$AnIn1$mag$f", "GGIO1$MX$AnIn2$mag$f"],
        )
        .await
        .unwrap();
    assert_eq!(values.len(), 2);
    assert_eq!(values[0].as_f32(), 230.4);
    assert_eq!(
        values[1].as_access_error(),
        Some(DataAccessError::ObjectNonExistent),
        "a per-element failure must not fail the whole read"
    );
}

#[tokio::test]
async fn a_read_spanning_domains_uses_the_scoped_reference_form() {
    let (client, _server) = connected().await;
    let refs = [
        VarRef::new("simpleIOGenericIO", "GGIO1$MX$AnIn1$mag$f"),
        VarRef::new("simpleIOProtection", "PTOC1$ST$Str$general"),
    ];
    let values = client.read_refs(&refs).await.unwrap();
    assert_eq!(values.len(), 2);
}

#[tokio::test]
async fn a_write_returns_a_result_for_each_item() {
    let (client, _server) = connected().await;
    let results = client
        .write(
            "simpleIOGenericIO",
            &["GGIO1$CF$SPCSO1$ctlModel", "GGIO1$ST$Ind1$stVal"],
            &[Value::int32(1), Value::boolean(true)],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert_eq!(results[1], Err(DataAccessError::ObjectAccessDenied));
}

#[tokio::test]
async fn a_service_failure_surfaces_as_a_typed_error() {
    let (client, _server) = connected().await;
    let err = client
        .call(cons(context_constructed(99), []))
        .await
        .expect_err("the server rejects service 99");
    // The access class and code travel back through the ConfirmedErrorPDU.
    assert!(
        err.to_string().contains("access"),
        "expected an access-class service error, got: {err}"
    );
}

#[tokio::test]
async fn unconfirmed_reports_are_delivered_to_every_registered_handler() {
    let (client, _server) = connected().await;

    let (tx1, mut rx1) = tokio::sync::mpsc::unbounded_channel();
    let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel();
    // Two independent subscriptions share one association; a later
    // registration must never silence an earlier one.
    client.on_information_report(move |r| {
        let _ = tx1.send(r.list_name.clone());
    });
    client.on_information_report(move |r| {
        let _ = tx2.send(r.list_ref.domain.clone());
    });

    let raw_seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&raw_seen);
    client.on_raw_unconfirmed(move |_| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });

    // Service 99 emits a report and then fails; the report still arrives.
    let _ = client.call(cons(context_constructed(99), [])).await;

    let name = tokio::time::timeout(std::time::Duration::from_secs(5), rx1.recv())
        .await
        .expect("the first handler receives the report")
        .unwrap();
    let domain = tokio::time::timeout(std::time::Duration::from_secs(5), rx2.recv())
        .await
        .expect("the second handler receives the same report")
        .unwrap();
    assert_eq!(name, "RPT");
    assert_eq!(domain, "simpleIOGenericIO");
    assert_eq!(raw_seen.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_removed_handler_stops_receiving_reports() {
    let (client, _server) = connected().await;
    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let id = client.on_information_report(move |_| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    client.remove_handler(id);
    // Removing twice is harmless.
    client.remove_handler(id);

    let _ = client.call(cons(context_constructed(99), [])).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn concurrent_requests_are_matched_to_their_own_responses() {
    let (client, _server) = connected().await;
    // Responses are demultiplexed by invoke id, so interleaved calls must not
    // cross over.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let c = Arc::clone(&client);
        set.spawn(async move { c.identify().await });
    }
    let mut n = 0;
    while let Some(res) = set.join_next().await {
        let (vendor, _, _) = res.unwrap().unwrap();
        assert_eq!(vendor, "DSC Systems");
        n += 1;
    }
    assert_eq!(n, 32);
}

#[tokio::test]
async fn a_dropped_peer_ends_the_association_and_wakes_waiters() {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let sc = mms::accept_conn(Box::new(server_side) as BoxTransport, None)
            .await
            .unwrap();
        // Establish, then drop the association without concluding.
        drop(sc);
    });
    let client = Conn::from_stream(
        Box::new(client_side) as BoxTransport,
        mms::Options::default(),
    )
    .await
    .unwrap();
    server.await.unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), client.closed())
        .await
        .expect("closed() must resolve when the peer goes away");
    assert_eq!(client.state(), mms::State::Closed);
    assert!(client.err().is_some(), "the cause must be recorded");
    // A request on a dead association fails rather than hanging.
    assert!(client.identify().await.is_err());
}
