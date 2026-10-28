//! Server rules that depend on who is asking and when: report control block
//! reservations by client address, clock quality on the server's and the
//! client's timestamps, the operate checks of IEC 61850-7-2, and the shapes of
//! the Edition 2 classes.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use iec61850::client::{Client, ControlOptions, Options as ClientOptions};
use iec61850::mms::{BoxTransport, DataAccessError, TimeQuality, Type, Value};
use iec61850::model::{
    self, AddCause, CdcOptions, ClientReservation, CtlModel, Fc, OrCat, TrgOps,
};
use iec61850::scl;
use iec61850::server::{ControlCtx, Options, Server};
use tokio::net::{TcpListener, TcpSocket};

async fn serve(s: &Server) -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let serving = s.clone();
    tokio::spawn(async move {
        let _ = serving.serve(ln).await;
    });
    addr
}

async fn dial(addr: &str, opts: ClientOptions) -> Client {
    Client::dial_with(addr, opts.with_timeout(Duration::from_secs(3)))
        .await
        .expect("dial")
}

/// Dials `addr` from the loopback address `from`, so the server sees a client
/// of that IP.
async fn dial_from(addr: &str, from: &str) -> Client {
    let sock = TcpSocket::new_v4().unwrap();
    sock.bind(format!("{from}:0").parse().unwrap()).unwrap();
    let stream = sock.connect(addr.parse().unwrap()).await.unwrap();
    Client::from_stream(Box::new(stream) as BoxTransport, ClientOptions::new())
        .await
        .expect("associate")
}

// --- Reservations ---------------------------------------------------------

/// A buffered block whose first instance the configuration reserves for
/// 127.0.0.1 and whose second is free, and an unbuffered block reserved the
/// same way.
fn resv_model() -> model::Model {
    let resv = vec![Some(ClientReservation {
        ied_name: "HMI".into(),
        ip: Some("127.0.0.1".parse().unwrap()),
    })];
    let lln0 = model::LogicalNode {
        name: "LLN0".into(),
        class: "LLN0".into(),
        objects: vec![model::DataObject {
            name: "Ind".into(),
            attributes: vec![model::DataAttribute {
                name: "stVal".into(),
                fc: Fc::St,
                kind: Some(Type::Boolean),
                value: Some(Value::boolean(false)),
                ..Default::default()
            }],
            ..Default::default()
        }],
        data_sets: vec![model::DataSet {
            name: "DS".into(),
            entries: vec![model::Fcda::new("IEDLD0/LLN0.Ind.stVal", Fc::St)],
            ..Default::default()
        }],
        report_controls: vec![
            model::ReportControl {
                name: "brcb".into(),
                data_set: "DS".into(),
                buffered: true,
                rpt_enabled: 2,
                reservations: resv.clone(),
                ..Default::default()
            },
            model::ReportControl {
                name: "urcb".into(),
                data_set: "DS".into(),
                rpt_enabled: 1,
                reservations: resv,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    model::Model {
        name: "IED".into(),
        devices: vec![model::LogicalDevice {
            name: "IEDLD0".into(),
            inst: "LD0".into(),
            nodes: vec![lln0],
        }],
        ..Default::default()
    }
}

const BRCB1: &str = "LLN0$BR$brcb01";
const BRCB2: &str = "LLN0$BR$brcb02";
const URCB1: &str = "LLN0$RP$urcb01";

async fn rcb_write(c: &Client, item: &str, attr: &str, v: Value) -> Result<(), DataAccessError> {
    c.mms()
        .write("IEDLD0", &[&format!("{item}${attr}")], &[v])
        .await
        .unwrap()
        .remove(0)
}

async fn rcb_read(c: &Client, item: &str, attr: &str) -> Value {
    c.mms().read("IEDLD0", &[&format!("{item}${attr}")]).await.unwrap().remove(0)
}

/// Gives the server time to tear an association down.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// An instance the configuration reserves (ClientLN) is usable only from the
/// client's address, shows ResvTms -1 and the client as Owner from the start,
/// and keeps the reservation when that client leaves.
#[tokio::test]
async fn a_configured_reservation_holds_for_the_clients_address() {
    let s = Server::new(resv_model(), Options::new());
    let addr = serve(&s).await;
    let hmi = dial_from(&addr, "127.0.0.1").await;
    let other = dial_from(&addr, "127.0.0.2").await;

    assert_eq!(rcb_read(&other, BRCB1, "ResvTms").await.as_i64(), -1);
    assert_eq!(rcb_read(&other, BRCB1, "Owner").await.bytes(), [127, 0, 0, 1]);
    assert_eq!(rcb_read(&other, BRCB2, "ResvTms").await.as_i64(), 0);
    assert!(rcb_read(&other, URCB1, "Resv").await.as_bool());

    let gi = || TrgOps::GI.value();
    assert_eq!(
        rcb_write(&other, BRCB1, "TrgOps", gi()).await,
        Err(DataAccessError::TemporarilyUnavailable)
    );
    assert_eq!(rcb_write(&other, BRCB2, "TrgOps", gi()).await, Ok(()));
    assert_eq!(rcb_write(&hmi, BRCB1, "TrgOps", gi()).await, Ok(()));
    assert_eq!(
        rcb_write(&hmi, BRCB1, "ResvTms", Value::int16(5)).await,
        Err(DataAccessError::ObjectAccessDenied)
    );
    assert_eq!(
        rcb_write(&hmi, URCB1, "Resv", Value::boolean(false)).await,
        Err(DataAccessError::ObjectAccessDenied)
    );

    // The reservation outlives the client's association.
    hmi.close().await.unwrap();
    settle().await;
    assert_eq!(
        rcb_write(&other, BRCB1, "TrgOps", gi()).await,
        Err(DataAccessError::TemporarilyUnavailable)
    );
    let back = dial_from(&addr, "127.0.0.1").await;
    assert_eq!(rcb_write(&back, BRCB1, "TrgOps", gi()).await, Ok(()));
}

/// A BRCB whose client set ResvTms stays reserved for that client's address
/// for ResvTms seconds after its association ends, and is free after that.
#[tokio::test]
async fn resv_tms_outlives_the_association() {
    let s = Server::new(resv_model(), Options::new());
    let addr = serve(&s).await;
    let a = dial_from(&addr, "127.0.0.7").await;
    let other = dial_from(&addr, "127.0.0.8").await;

    assert_eq!(
        rcb_write(&a, BRCB2, "ResvTms", Value::int16(-1)).await,
        Err(DataAccessError::ObjectValueInvalid)
    );
    assert_eq!(rcb_write(&a, BRCB2, "ResvTms", Value::int16(1)).await, Ok(()));
    a.close().await.unwrap();
    settle().await;

    assert_eq!(
        rcb_write(&other, BRCB2, "TrgOps", TrgOps::GI.value()).await,
        Err(DataAccessError::TemporarilyUnavailable)
    );
    assert_eq!(rcb_read(&other, BRCB2, "Owner").await.bytes(), [127, 0, 0, 7]);
    for _ in 0..60 {
        if rcb_write(&other, BRCB2, "TrgOps", TrgOps::GI.value()).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the reservation outlived ResvTms");
}

/// Without a ResvTms the reservation ends with the association.
#[tokio::test]
async fn without_resv_tms_the_block_frees_on_disconnect() {
    let s = Server::new(resv_model(), Options::new());
    let addr = serve(&s).await;
    let a = dial_from(&addr, "127.0.0.7").await;
    let other = dial_from(&addr, "127.0.0.8").await;
    assert_eq!(rcb_write(&a, BRCB2, "TrgOps", TrgOps::GI.value()).await, Ok(()));
    assert_eq!(rcb_read(&other, BRCB2, "Owner").await.bytes(), [127, 0, 0, 7]);
    a.close().await.unwrap();
    settle().await;
    assert_eq!(rcb_write(&other, BRCB2, "TrgOps", TrgOps::GI.value()).await, Ok(()));
}

// --- Time quality ---------------------------------------------------------

/// The quality of a clock that has lost its time source.
const LOST_SYNC: TimeQuality = TimeQuality(
    TimeQuality::CLOCK_NOT_SYNCHRONIZED.0 | TimeQuality::CLOCK_FAILURE.0 | TimeQuality::ACCURACY_UNSPECIFIED.0,
);

fn tq_model() -> model::Model {
    model::Model {
        name: "IED".into(),
        devices: vec![model::LogicalDevice {
            name: "IEDLD0".into(),
            inst: "LD0".into(),
            nodes: vec![
                model::LogicalNode {
                    name: "LLN0".into(),
                    class: "LLN0".into(),
                    ..Default::default()
                },
                model::LogicalNode {
                    name: "GGIO1".into(),
                    class: "GGIO".into(),
                    objects: vec![
                        model::DataObject {
                            name: "Ind1".into(),
                            attributes: vec![model::DataAttribute {
                                name: "t".into(),
                                fc: Fc::St,
                                kind: Some(Type::UtcTime),
                                value: Some(Value::utc_time(SystemTime::now(), TimeQuality::DEFAULT)),
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                        model::DataObject {
                            name: "Set".into(),
                            attributes: vec![model::DataAttribute {
                                name: "setVal".into(),
                                fc: Fc::Sg,
                                kind: Some(Type::Integer),
                                value: Some(Value::int32(1)),
                                ..Default::default()
                            }],
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
        }],
        ..Default::default()
    }
}

/// The server stamps its times with its clock's quality, which can change
/// while it serves, and 0 is a quality like any other.
#[test]
fn the_server_stamps_its_clock_quality() {
    let s = Server::new(tq_model(), Options::new().with_time_quality(LOST_SYNC));
    let stamp = || {
        s.update(|tx| {
            tx.set_timestamp_now("IEDLD0/GGIO1.Ind1.t", Fc::St);
        });
        s.read("IEDLD0/GGIO1.Ind1.t", Fc::St).unwrap().time_quality()
    };
    assert_eq!(stamp(), LOST_SYNC);
    s.set_time_quality(TimeQuality(0));
    assert_eq!(stamp(), TimeQuality(0));
    s.update(|tx| assert_eq!(tx.now().time_quality(), TimeQuality(0)));
    assert_eq!(Server::new(tq_model(), Options::new()).time_quality(), TimeQuality::DEFAULT);
}

/// The setting group's LActTm carries the server's clock quality.
#[test]
fn the_sgcb_activation_time_carries_the_quality() {
    let s = Server::new(
        tq_model(),
        Options::new().with_setting_groups(2).with_time_quality(LOST_SYNC),
    );
    let t = s.read("IEDLD0/LLN0.SGCB.LActTm", Fc::Sp).expect("LActTm");
    assert_eq!(t.time_quality(), LOST_SYNC);
}

// --- Control rules --------------------------------------------------------

const RULE: &str = "RULE";

/// SPCSO1 direct-normal, SPCSO2 SBO-enhanced, SPCSO3 direct-enhanced.
fn rule_model() -> model::Model {
    let spc = |name: &str, cm: CtlModel| {
        model::new_data_object(name, model::Cdc::Spc, &CdcOptions::new().with_control_model(cm))
    };
    model::Model {
        name: RULE.into(),
        devices: vec![model::LogicalDevice {
            name: RULE.into(),
            inst: "LD0".into(),
            nodes: vec![
                model::LogicalNode {
                    name: "LLN0".into(),
                    class: "LLN0".into(),
                    ..Default::default()
                },
                model::LogicalNode {
                    name: "GGIO1".into(),
                    class: "GGIO".into(),
                    objects: vec![
                        spc("SPCSO1", CtlModel::DirectNormal),
                        spc("SPCSO2", CtlModel::SboEnhanced),
                        spc("SPCSO3", CtlModel::DirectEnhanced),
                    ],
                    ..Default::default()
                },
            ],
        }],
        ..Default::default()
    }
}

/// Serves the rule model, recording every command that reaches a handler.
async fn rule_fixture() -> (Arc<Mutex<Vec<ControlCtx>>>, String) {
    let s = Server::new(rule_model(), Options::new());
    let got: Arc<Mutex<Vec<ControlCtx>>> = Arc::default();
    for o in ["SPCSO1", "SPCSO2", "SPCSO3"] {
        let got = got.clone();
        s.on_control(format!("{RULE}/GGIO1.{o}"), move |cc| {
            got.lock().unwrap().push(cc.clone());
            AddCause::NONE
        });
    }
    let addr = serve(&s).await;
    // The server lives as long as its listener task holds it.
    (got, addr)
}

/// An Oper structure with the flags a rule test needs.
fn oper(ctl_num: u8, test: bool, or_ident_len: usize) -> Value {
    let mut check = Value::bit_string(2);
    check.set_bit(0, false);
    Value::structure(vec![
        Value::boolean(true),
        Value::structure(vec![
            Value::int8(OrCat::StationControl.code() as i8),
            Value::octet_string(vec![0; or_ident_len]),
        ]),
        Value::uint8(ctl_num),
        Value::utc_time(SystemTime::now(), TimeQuality::DEFAULT),
        Value::boolean(test),
        check,
    ])
}

/// Writes a control structure directly, so the server's own checking is
/// exercised rather than the client's sequence handling.
async fn write_oper(c: &Client, object: &str, v: Value) -> Result<(), DataAccessError> {
    c.mms()
        .write(RULE, &[&format!("GGIO1$CO${object}$Oper")], &[v])
        .await
        .unwrap()
        .remove(0)
}

/// The operate timestamp reaches the handler.
#[tokio::test]
async fn the_operate_timestamp_reaches_the_handler() {
    let (got, addr) = rule_fixture().await;
    let c = dial(&addr, ClientOptions::new()).await;
    write_oper(&c, "SPCSO1", oper(1, false, 4)).await.unwrap();
    let got = got.lock().unwrap();
    assert_eq!(got.len(), 1);
    let t = got[0].t.expect("the operate time");
    let age = SystemTime::now().duration_since(t).unwrap_or_default();
    assert!(age < Duration::from_secs(60), "operate timestamp {t:?} is not near now");
}

/// A test-flagged operate on an enhanced-security object is refused, with the
/// diagnosis 7-2 names; on a normal-security one it is accepted.
#[tokio::test]
async fn a_test_operate_is_refused_on_enhanced_security() {
    for (object, refuse) in [("SPCSO2", true), ("SPCSO3", true), ("SPCSO1", false)] {
        let (got, addr) = rule_fixture().await;
        let c = dial(&addr, ClientOptions::new()).await;
        let res = write_oper(&c, object, oper(9, true, 4)).await;
        if refuse {
            assert!(res.is_err(), "{object}: a test operate was accepted");
            assert!(got.lock().unwrap().is_empty(), "{object}: it reached the handler");
            let lae = c.last_appl_error().expect("a LastApplError");
            assert_eq!(lae.add_cause, AddCause::TEST_NOT_ALLOWED, "{object}");
        } else {
            assert_eq!(res, Ok(()), "{object}");
            assert_eq!(got.lock().unwrap().len(), 1, "{object}");
        }
    }
}

/// The originator identifier is bounded to its type, OctetString(0..64).
#[tokio::test]
async fn the_originator_length_is_bounded() {
    for (n, accept) in [(0, true), (1, true), (32, true), (64, true), (65, false), (200, false)] {
        let (got, addr) = rule_fixture().await;
        let c = dial(&addr, ClientOptions::new()).await;
        let res = write_oper(&c, "SPCSO1", oper(1, false, n)).await;
        assert_eq!(res.is_ok(), accept, "{n}-octet originator: {res:?}");
        if !accept {
            assert!(got.lock().unwrap().is_empty(), "{n}-octet originator reached the handler");
        }
    }
}

/// The operate timestamp T carries the client's clock quality, and one
/// command can state its own.
#[tokio::test]
async fn the_operate_time_carries_the_clients_quality() {
    let (got, addr) = rule_fixture().await;
    let c = dial(&addr, ClientOptions::new()).await;
    let co = c.control_for(format!("{RULE}/GGIO1.SPCSO1")).await.unwrap();
    co.operate(Value::boolean(true), &ControlOptions::default()).await.unwrap();
    c.set_time_quality(LOST_SYNC);
    co.operate(Value::boolean(false), &ControlOptions::default()).await.unwrap();
    co.operate(
        Value::boolean(true),
        &ControlOptions::default().with_time_quality(TimeQuality::accuracy(20)),
    )
    .await
    .unwrap();
    let got: Vec<TimeQuality> = got.lock().unwrap().iter().map(|cc| cc.t_quality).collect();
    assert_eq!(got, [TimeQuality::DEFAULT, LOST_SYNC, TimeQuality::accuracy(20)]);
}

/// A Cancel carries the operate's fields but not Check (IEC 61850-7-2), and
/// the server accepts it.
#[tokio::test]
async fn a_cancel_is_accepted() {
    let (_got, addr) = rule_fixture().await;
    let c = dial(&addr, ClientOptions::new()).await;
    let co = c.control_for(format!("{RULE}/GGIO1.SPCSO2")).await.unwrap();
    co.select_with_value(Value::boolean(true), &ControlOptions::default())
        .await
        .unwrap();
    co.cancel(&ControlOptions::default()).await.unwrap();
}

/// A client can propose the IEC 61850 ACSI application context, which the
/// server accepts and answers in kind.
#[tokio::test]
async fn the_acsi_application_context_is_accepted() {
    let (_got, addr) = rule_fixture().await;
    let c = dial(
        &addr,
        ClientOptions::new().with_application_context(iec61850::mms::ApplicationContext::Acsi),
    )
    .await;
    c.logical_nodes(RULE).await.unwrap();
}

// --- Edition 2 classes ----------------------------------------------------

/// The Edition 2 and 2.1 classes of the fixture are served with the shapes 7-3
/// and 8-1 give them: tracking objects under FC SR, a PhyComAddr as its
/// four-member structure, and arrays of a constructed type as arrays, both in
/// their values and in the type a client is told.
#[tokio::test]
async fn ed2_classes_are_served_in_shape() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/ed21_diverse.cid");
    let m = scl::load_model(path, &scl::BuildOptions::new()).unwrap();
    let s = Server::new(m, Options::new());
    let addr = serve(&s).await;
    let c = dial(&addr, ClientOptions::new()).await;
    let read = |r: &'static str, fc: Fc| {
        let c = &c;
        async move { c.read(r, fc).await.unwrap_or_else(|e| panic!("{r}: {e}")) }
    };

    let rc = read("ED21LD0/GAPC1.Hst.hstRangeC", Fc::Cf).await;
    assert_eq!((rc.type_of(), rc.len()), (Type::Array, 4));
    let e = &rc.children()[0];
    assert_eq!((e.type_of(), e.len()), (Type::Structure, 2));
    let pts = read("ED21LD0/GAPC1.Crv.crvPts", Fc::Sp).await;
    assert_eq!((pts.type_of(), pts.len()), (Type::Array, 5));
    let hv = read("ED21LD0/GAPC1.Hst.hstVal", Fc::St).await;
    assert_eq!((hv.type_of(), hv.len()), (Type::Array, 4));
    let dst = read("ED21LD0/LTRK1.GocbTrk.dstAddress", Fc::Sr).await;
    assert_eq!((dst.type_of(), dst.len()), (Type::Structure, 4));
    assert_eq!(read("ED21LD0/GAPC1.Cur.cur", Fc::Sp).await.text(), "EUR");

    let mc = c.mms();
    let spec = mc
        .get_variable_access_attributes("ED21LD0", "GAPC1$CF$Hst$hstRangeC")
        .await
        .unwrap();
    assert_eq!((spec.kind, spec.elements), (Some(Type::Array), 4));
    let el = spec.element.as_ref().expect("an element type");
    assert_eq!((el.kind, el.components.len()), (Some(Type::Structure), 2));
    let spec = mc
        .get_variable_access_attributes("ED21LD0", "GAPC1$ST$Hst$hstVal")
        .await
        .unwrap();
    assert_eq!((spec.kind, spec.elements), (Some(Type::Array), 4));
    assert_eq!(spec.element.as_ref().unwrap().kind, Some(Type::Integer));
    for item in ["GAPC1", "LTRK1", "LTRK1$SR"] {
        mc.get_variable_access_attributes("ED21LD0", item)
            .await
            .unwrap_or_else(|e| panic!("{item}: {e}"));
    }
}

// --- Control writes ---------------------------------------------------------

/// A control write names a control structure of the model. One spelled like
/// an `Oper`, `SBOw` or `Cancel` on an object that has none (a status-only
/// `Beh`, a `Health`) is a write to a variable that does not exist, and its
/// `stVal` stays what the process made it, whatever the writable FCs allow.
#[tokio::test]
async fn a_forged_control_write_is_refused() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid");
    let m = scl::load_model(path, &scl::BuildOptions::new()).unwrap();
    let s = Server::new(m, Options::new());
    let addr = serve(&s).await;
    let c = dial(&addr, ClientOptions::new()).await;

    let st = "simpleIOGenericIO/GGIO1.Beh.stVal";
    let before = c.read(st, Fc::St).await.unwrap();
    for attr in ["Oper", "SBOw", "Cancel"] {
        let forged = Value::structure(vec![Value::int8(2)]);
        let err = c
            .write(format!("simpleIOGenericIO/GGIO1.Beh.{attr}"), Fc::Co, forged)
            .await
            .expect_err("Beh has no control structure");
        assert!(err.to_string().contains("object-non-existent"), "{attr}: {err}");
    }
    assert_eq!(c.read(st, Fc::St).await.unwrap(), before, "stVal is untouched");

    // A real control still operates.
    let co = c.control_for("simpleIOGenericIO/GGIO1.SPCSO1").await.unwrap();
    co.operate(Value::boolean(true), &ControlOptions::new().with_model(CtlModel::DirectNormal))
        .await
        .expect("a real control operates");
    assert!(c
        .read("simpleIOGenericIO/GGIO1.SPCSO1.stVal", Fc::St)
        .await
        .unwrap()
        .as_bool());
}
