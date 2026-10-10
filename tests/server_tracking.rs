//! Service tracking (IEC 61850-7-2 Ed2.1, LTRK): every control, control block
//! write and setting group selection lands in the tracking object of its
//! class, with the request and its outcome.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850::client::{Client, Options as ClientOptions};
use iec61850::mms::Value;
use iec61850::model::{
    self, AddCause, CtlModel, Fc, LnOptions, ObjectReference, ServiceErrorCode, ServiceType,
};
use iec61850::scl;
use iec61850::server::{Options, Server};
use tokio::net::TcpListener;

const LD: &str = "simpleIOGenericIO";

fn load(name: &str) -> model::Model {
    let path = format!("{}/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
    scl::load_model(path, &scl::BuildOptions::new()).expect("fixture loads")
}

/// The simpleIO model with an LTRK holding the tracking objects of its
/// controls, report blocks and setting group block.
fn simple_io_with_ltrk() -> model::Model {
    let mut m = load("simpleIO_direct_control.cid");
    let ld = m.device_mut(LD).unwrap();
    ld.nodes.push(model::new_logical_node(
        "",
        "LTRK",
        "1",
        &LnOptions::new().with_objects(["SpcTrk", "UrcbTrk", "BrcbTrk", "SgcbTrk"]),
    ));
    m
}

fn set_ctl_model(m: &mut model::Model, object: &str, cm: CtlModel) {
    let r = ObjectReference::new(format!("{LD}/GGIO1.{object}.ctlModel"));
    m.attribute_mut(&r, Fc::Cf).unwrap().value = Some(Value::int32(i32::from(cm.code())));
}

async fn start(m: model::Model) -> (Server, String) {
    let s = Server::new(m, Options::new());
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let serving = s.clone();
    tokio::spawn(async move {
        let _ = serving.serve(ln).await;
    });
    (s, addr)
}

async fn dial(addr: &str) -> Client {
    Client::dial_with(addr, ClientOptions::new().with_timeout(Duration::from_secs(3)))
        .await
        .expect("dial")
}

async fn sr(c: &Client, ld: &str, obj: &str, attr: &str) -> Value {
    let r = format!("{ld}/LTRK1.{obj}.{attr}");
    c.read(r.as_str(), Fc::Sr).await.unwrap_or_else(|e| panic!("read {r}: {e}"))
}

/// Reads the tracked object reference, service and error.
async fn tracked(c: &Client, ld: &str, obj: &str) -> (String, ServiceType, ServiceErrorCode) {
    (
        sr(c, ld, obj, "objRef").await.text(),
        ServiceType(sr(c, ld, obj, "serviceType").await.as_i64() as i32),
        ServiceErrorCode(sr(c, ld, obj, "errorCode").await.as_i64() as i32),
    )
}

/// Every control service lands in the tracking object of its CDC, with the
/// command and its outcome.
#[tokio::test]
async fn controls_are_tracked() {
    let (s, addr) = start(simple_io_with_ltrk()).await;
    s.on_control(format!("{LD}/GGIO1.SPCSO2"), |_| AddCause::BLOCKED_BY_INTERLOCKING);
    let c = dial(&addr).await;

    let co = c.control_for(format!("{LD}/GGIO1.SPCSO1")).await.unwrap();
    co.operate(Value::boolean(true), &Default::default()).await.unwrap();
    assert_eq!(
        tracked(&c, LD, "SpcTrk").await,
        (format!("{LD}/GGIO1.SPCSO1"), ServiceType::OPERATE, ServiceErrorCode::NO_ERROR)
    );
    assert!(sr(&c, LD, "SpcTrk", "ctlVal").await.as_bool());
    assert_eq!(sr(&c, LD, "SpcTrk", "ctlNum").await.as_u64() as u8, co.ctl_num());
    assert!(sr(&c, LD, "SpcTrk", "t").await.time().is_some_and(|t| t != std::time::UNIX_EPOCH));

    let co2 = c.control_for(format!("{LD}/GGIO1.SPCSO2")).await.unwrap();
    co2.operate(Value::boolean(true), &Default::default())
        .await
        .expect_err("the interlocked operate succeeded");
    assert_eq!(
        tracked(&c, LD, "SpcTrk").await,
        (format!("{LD}/GGIO1.SPCSO2"), ServiceType::OPERATE, ServiceErrorCode::ACCESS_VIOLATION)
    );
    assert_eq!(
        sr(&c, LD, "SpcTrk", "respAddCause").await.as_i64(),
        i64::from(AddCause::BLOCKED_BY_INTERLOCKING.0)
    );
}

/// A write to a report control block is tracked as SetURCBValues or
/// SetBRCBValues, succeeded or refused, with the block's state after it.
#[tokio::test]
async fn rcb_writes_are_tracked() {
    let (_s, addr) = start(simple_io_with_ltrk()).await;
    let c = dial(&addr).await;

    c.write(format!("{LD}/LLN0.EventsRCB01.RptEna"), Fc::Rp, Value::boolean(true))
        .await
        .unwrap();
    assert_eq!(
        tracked(&c, LD, "UrcbTrk").await,
        (format!("{LD}/LLN0.EventsRCB01"), ServiceType::SET_URCB_VALUES, ServiceErrorCode::NO_ERROR)
    );
    assert_eq!(sr(&c, LD, "UrcbTrk", "rptID").await.text(), "Events1");
    assert_eq!(sr(&c, LD, "UrcbTrk", "datSet").await.text(), format!("{LD}/LLN0.Events"));
    assert!(sr(&c, LD, "UrcbTrk", "rptEna").await.as_bool());
    assert!(sr(&c, LD, "UrcbTrk", "resv").await.as_bool());

    c.write(format!("{LD}/LLN0.EventsBRCB01.ConfRev"), Fc::Br, Value::uint32(9))
        .await
        .expect_err("ConfRev was written");
    let (r, svc, err) = tracked(&c, LD, "BrcbTrk").await;
    assert_eq!((r.as_str(), svc), (format!("{LD}/LLN0.EventsBRCB01").as_str(), ServiceType::SET_BRCB_VALUES));
    assert_ne!(err, ServiceErrorCode::NO_ERROR);
    // The tracking object states what was asked for; the block keeps its own.
    assert_eq!(sr(&c, LD, "BrcbTrk", "confRev").await.as_u64(), 9);
    assert_eq!(
        c.read(format!("{LD}/LLN0.EventsBRCB01.ConfRev"), Fc::Br).await.unwrap().as_u64(),
        1
    );
}

/// The setting group block's selection is tracked, and so is a refused write
/// to a GoCB, which this server serves read-only.
#[tokio::test]
async fn sgcb_and_gocb_writes_are_tracked() {
    let mut m = load("ed21_diverse.cid");
    let ltrk = m.device_mut("ED21LD0").unwrap().node_mut("LTRK1").unwrap();
    ltrk.objects.push(model::new_data_object("SgcbTrk", model::Cdc::Sts, &Default::default()));
    let (_s, addr) = start(m).await;
    let c = dial(&addr).await;
    const ED: &str = "ED21LD0";

    c.write("ED21LD0/LLN0.SGCB.ActSG", Fc::Sp, Value::uint8(2)).await.unwrap();
    assert_eq!(
        tracked(&c, ED, "SgcbTrk").await,
        ("ED21LD0/LLN0.SGCB".to_string(), ServiceType::SELECT_ACTIVE_SG, ServiceErrorCode::NO_ERROR)
    );
    assert_eq!(sr(&c, ED, "SgcbTrk", "actSG").await.as_u64(), 2);
    assert_eq!(sr(&c, ED, "SgcbTrk", "numOfSG").await.as_u64(), 2);
    c.write("ED21LD0/LLN0.SGCB.ActSG", Fc::Sp, Value::uint8(7))
        .await
        .expect_err("ActSG 7 of 2 accepted");
    assert_eq!(
        tracked(&c, ED, "SgcbTrk").await,
        (
            "ED21LD0/LLN0.SGCB".to_string(),
            ServiceType::SELECT_ACTIVE_SG,
            ServiceErrorCode::PARAMETER_VALUE_INAPPROPRIATE
        )
    );

    c.write("ED21LD0/LLN0.gcb01.GoEna", Fc::Go, Value::boolean(true))
        .await
        .expect_err("GoEna written on a read-only GoCB");
    assert_eq!(
        tracked(&c, ED, "GocbTrk").await,
        ("ED21LD0/LLN0.gcb01".to_string(), ServiceType::SET_GOCB_VALUES, ServiceErrorCode::ACCESS_VIOLATION)
    );
    assert!(!sr(&c, ED, "GocbTrk", "goID").await.text().is_empty());
    assert!(!sr(&c, ED, "GocbTrk", "datSet").await.text().contains('$'));
}

/// A select by reading SBO is tracked as Select, a select another client holds
/// as one refused with instance-in-use, and an enhanced-security operate's
/// CommandTermination, sent at once or deferred, after it.
#[tokio::test]
async fn selects_and_terminations_are_tracked() {
    let mut m = simple_io_with_ltrk();
    set_ctl_model(&mut m, "SPCSO3", CtlModel::SboNormal);
    set_ctl_model(&mut m, "SPCSO4", CtlModel::DirectEnhanced);
    let (s, addr) = start(m).await;
    type Finish = Box<dyn Fn(AddCause) + Send + Sync>;
    let finish: Arc<Mutex<Option<Finish>>> = Arc::default();
    let defer_it = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (finish, defer_it) = (finish.clone(), defer_it.clone());
        s.on_control(format!("{LD}/GGIO1.SPCSO4"), move |cc| {
            if defer_it.load(std::sync::atomic::Ordering::SeqCst) {
                *finish.lock().unwrap() = Some(cc.defer_termination());
            }
            AddCause::NONE
        });
    }
    let (a, b) = (dial(&addr).await, dial(&addr).await);

    let co_a = a.control_for(format!("{LD}/GGIO1.SPCSO3")).await.unwrap();
    co_a.select().await.unwrap();
    assert_eq!(
        tracked(&a, LD, "SpcTrk").await,
        (format!("{LD}/GGIO1.SPCSO3"), ServiceType::SELECT, ServiceErrorCode::NO_ERROR)
    );
    let co_b = b.control_for(format!("{LD}/GGIO1.SPCSO3")).await.unwrap();
    co_b.select().await.expect_err("a second client selected a selected object");
    assert_eq!(
        tracked(&a, LD, "SpcTrk").await,
        (format!("{LD}/GGIO1.SPCSO3"), ServiceType::SELECT, ServiceErrorCode::INSTANCE_IN_USE)
    );

    let co4 = a.control_for(format!("{LD}/GGIO1.SPCSO4")).await.unwrap();
    co4.operate(Value::boolean(true), &Default::default()).await.unwrap();
    assert_eq!(
        tracked(&a, LD, "SpcTrk").await,
        (format!("{LD}/GGIO1.SPCSO4"), ServiceType::COMMAND_TERMINATION, ServiceErrorCode::NO_ERROR)
    );

    // Deferred and negative: tracked when the handler finishes it.
    defer_it.store(true, std::sync::atomic::Ordering::SeqCst);
    let finisher = finish.clone();
    tokio::spawn(async move {
        loop {
            if let Some(f) = finisher.lock().unwrap().take() {
                f(AddCause::BLOCKED_BY_PROCESS);
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    co4.operate(Value::boolean(false), &Default::default())
        .await
        .expect_err("CommandTermination- is an error to the client");
    let mut last = None;
    for _ in 0..150 {
        let got = tracked(&a, LD, "SpcTrk").await;
        if got.1 == ServiceType::COMMAND_TERMINATION
            && got.2 == ServiceErrorCode::FAILED_DUE_TO_SERVER_CONSTRAINT
        {
            last = None;
            break;
        }
        last = Some(got);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(last.is_none(), "SpcTrk after a negative deferred termination: {last:?}");
    assert_eq!(
        sr(&a, LD, "SpcTrk", "respAddCause").await.as_i64(),
        i64::from(AddCause::BLOCKED_BY_PROCESS.0)
    );
}
