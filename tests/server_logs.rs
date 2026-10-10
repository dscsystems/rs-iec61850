//! Logs over a real association: a log control block writes data changes and
//! integrity scans to its log, and clients read, page, inspect and clear it.

use std::time::{Duration, SystemTime};

use iec61850::client::{AcsiClass, Client, Options as ClientOptions};
use iec61850::mms::{self, service, DataAccessError, InitiateRequest, Type, Value};
use iec61850::model::{self, Fc, ReasonCode, TrgOps};
use iec61850::server::{Options, Server};
use tokio::net::TcpListener;

const LD: &str = "IEDLD0";
const LOG: &str = "IEDLD0/LLN0.EventLog";
const LCB: &str = "LLN0$LG$lcb";

/// One log, EventLog in LLN0, written by lcb from the Events data set of two
/// status points, logging data changes with their reasons.
fn log_model() -> model::Model {
    let ind = |name: &str| model::DataObject {
        name: name.into(),
        attributes: vec![model::DataAttribute {
            name: "stVal".into(),
            fc: Fc::St,
            kind: Some(Type::Boolean),
            value: Some(Value::boolean(false)),
            // dchg on the attribute, as its SCL type would give it.
            trg_ops: TrgOps::DATA_CHANGE,
            ..Default::default()
        }],
        ..Default::default()
    };
    let lln0 = model::LogicalNode {
        name: "LLN0".into(),
        class: "LLN0".into(),
        logs: vec!["EventLog".into()],
        data_sets: vec![model::DataSet {
            name: "Events".into(),
            entries: vec![
                model::Fcda::new(format!("{LD}/GGIO1.Ind1.stVal"), Fc::St),
                model::Fcda::new(format!("{LD}/GGIO1.Ind2.stVal"), Fc::St),
            ],
            ..Default::default()
        }],
        log_controls: vec![model::LogControl {
            name: "lcb".into(),
            data_set: "Events".into(),
            log_name: "EventLog".into(),
            trg_ops: TrgOps::DATA_CHANGE,
            log_ena: true,
            reason_code: true,
            ..Default::default()
        }],
        ..Default::default()
    };
    let ggio = model::LogicalNode {
        name: "GGIO1".into(),
        class: "GGIO".into(),
        objects: vec![ind("Ind1"), ind("Ind2")],
        ..Default::default()
    };
    model::Model {
        name: "IED".into(),
        devices: vec![model::LogicalDevice {
            name: LD.into(),
            inst: "LD0".into(),
            nodes: vec![lln0, ggio],
        }],
        ..Default::default()
    }
}

fn set_ind(s: &Server, name: &str, on: bool) {
    s.update(|tx| {
        tx.set_bool(format!("{LD}/GGIO1.{name}.stVal"), on);
    });
}

async fn serve(server: &Server) -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let s = server.clone();
    tokio::spawn(async move {
        let _ = s.serve(ln).await;
    });
    addr
}

async fn dial(addr: &str, opts: ClientOptions) -> Client {
    Client::dial_with(addr, opts.with_timeout(Duration::from_secs(3)))
        .await
        .expect("dial")
}

async fn start(m: model::Model, opts: Options) -> (Server, Client) {
    let s = Server::new(m, opts);
    let addr = serve(&s).await;
    let c = dial(&addr, ClientOptions::new()).await;
    (s, c)
}

async fn query_all(c: &Client) -> Vec<mms::JournalEntry> {
    let now = SystemTime::now();
    c.query_log_by_time(LOG, now - Duration::from_secs(3600), now + Duration::from_secs(3600))
        .await
        .expect("query_log_by_time")
}

async fn lcb(c: &Client, attr: &str) -> Value {
    c.mms().read(LD, &[&format!("{LCB}${attr}")]).await.unwrap().remove(0)
}

async fn write_lcb(c: &Client, attr: &str, v: Value) -> Result<(), DataAccessError> {
    c.mms()
        .write(LD, &[&format!("{LCB}${attr}")], &[v])
        .await
        .unwrap()
        .remove(0)
}

/// A log is browsable as an ACSI LOG, and the server offers ReadJournal
/// because it has one.
#[tokio::test]
async fn a_log_is_browseable() {
    let (_s, c) = start(log_model(), Options::new()).await;
    let names = c.logical_node_directory("IEDLD0/LLN0", AcsiClass::Log).await.unwrap();
    assert_eq!(names, ["EventLog"]);
    let entries = c.browse(LD, &[AcsiClass::Log]).await.unwrap();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].reference.as_str(), LOG);
    assert!(c.mms().negotiated().services.has(service::READ_JOURNAL));
}

/// A change of a data set member is logged with its reference, value and
/// reason, and the control block's entry range follows the log.
#[tokio::test]
async fn a_data_change_is_logged() {
    let (s, c) = start(log_model(), Options::new()).await;
    set_ind(&s, "Ind1", true);
    set_ind(&s, "Ind2", true);

    let entries = query_all(&c).await;
    assert_eq!(entries.len(), 2);
    let e = &entries[0];
    assert_eq!(e.variables.len(), 2, "the value and its reason: {e:?}");
    assert_eq!(e.variables[0].tag, "IEDLD0/GGIO1$ST$Ind1$stVal");
    assert!(e.variables[0].value.as_ref().unwrap().as_bool());
    assert_eq!(e.variables[1].tag, "ReasonCode");
    let reason = ReasonCode::from_value(e.variables[1].value.as_ref().unwrap());
    assert!(reason.has(ReasonCode::DATA_CHANGE), "{reason}");
    let t = e.occurrence_time.unwrap();
    assert!(SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(60));
    assert_ne!(entries[0].entry_id, entries[1].entry_id);
    assert_eq!(entries[0].entry_id.len(), 8);

    assert_eq!(lcb(&c, "OldEnt").await.bytes(), entries[0].entry_id);
    assert_eq!(lcb(&c, "NewEnt").await.bytes(), entries[1].entry_id);
    assert_eq!(lcb(&c, "NewEntrTm").await.time(), entries[1].occurrence_time);

    // Continuing after the first entry returns the second.
    let after = c
        .query_log_after(LOG, entries[0].occurrence_time.unwrap(), &entries[0].entry_id)
        .await
        .unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].entry_id, entries[1].entry_id);
}

/// A log larger than one PDU arrives whole: the server pages it with
/// moreFollows, and the client continues after the last entry of each page.
#[tokio::test]
async fn a_log_query_is_paged() {
    let s = Server::new(log_model(), Options::new());
    let addr = serve(&s).await;
    let mut opts = ClientOptions::new();
    opts.initiate = Some(InitiateRequest {
        local_detail: 300,
        ..Default::default()
    });
    let c = dial(&addr, opts).await;
    const N: usize = 40;
    for i in 0..N {
        set_ind(&s, "Ind1", i % 2 == 0);
    }
    let entries = query_all(&c).await;
    assert_eq!(entries.len(), N);
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.variables[0].value.as_ref().unwrap().as_bool(), i % 2 == 0, "entry {i}");
    }
}

/// A log keeps its capacity, discarding the oldest entries.
#[tokio::test]
async fn a_log_keeps_its_capacity() {
    let (s, c) = start(log_model(), Options::new().with_log_capacity(3)).await;
    for i in 0..5 {
        set_ind(&s, "Ind1", i % 2 == 0);
    }
    let entries = query_all(&c).await;
    assert_eq!(entries.len(), 3);
    for (k, e) in entries.iter().enumerate() {
        assert_eq!(e.variables[0].value.as_ref().unwrap().as_bool(), k % 2 == 0, "entry {k}");
    }
}

/// A client controls logging through LogEna, and may change the configuration
/// only while logging is off. The server's attributes are not writable.
#[tokio::test]
async fn lcb_writes_follow_the_rules() {
    let (s, c) = start(log_model(), Options::new()).await;
    assert_eq!(
        write_lcb(&c, "DatSet", Value::visible_string("IEDLD0/LLN0$Events")).await,
        Err(DataAccessError::TemporarilyUnavailable)
    );
    assert_eq!(
        write_lcb(&c, "LogRef", Value::visible_string("x")).await,
        Err(DataAccessError::ObjectAccessDenied)
    );
    write_lcb(&c, "LogEna", Value::boolean(false)).await.unwrap();
    set_ind(&s, "Ind1", true);
    assert_eq!(query_all(&c).await.len(), 0, "logged while disabled");
    assert_eq!(
        write_lcb(&c, "DatSet", Value::visible_string("IEDLD0/LLN0$Nope")).await,
        Err(DataAccessError::ObjectValueInvalid)
    );
    write_lcb(&c, "TrgOps", (TrgOps::DATA_CHANGE | TrgOps::DATA_UPDATE).value())
        .await
        .unwrap();
    write_lcb(&c, "LogEna", Value::boolean(true)).await.unwrap();
    set_ind(&s, "Ind2", true);
    assert_eq!(query_all(&c).await.len(), 1);
}

/// Reading a log the server does not have is an error, not an empty log.
#[tokio::test]
async fn an_unknown_log_is_an_error() {
    let (_s, c) = start(log_model(), Options::new()).await;
    assert!(c
        .query_log_by_time("IEDLD0/LLN0.Nope", SystemTime::UNIX_EPOCH, SystemTime::now())
        .await
        .is_err());
}

/// The integrity period logs every member, with reason integrity.
#[tokio::test]
async fn the_integrity_period_logs_every_member() {
    let mut m = log_model();
    let lc = &mut m.devices[0].nodes[0].log_controls[0];
    lc.trg_ops = TrgOps::INTEGRITY;
    lc.intg_pd = 50;
    let (_s, c) = start(m, Options::new()).await;
    for _ in 0..150 {
        let entries = query_all(&c).await;
        if let Some(e) = entries.first() {
            assert_eq!(e.variables.len(), 4, "both members and their reasons");
            let r = ReasonCode::from_value(e.variables[1].value.as_ref().unwrap());
            assert!(r.has(ReasonCode::INTEGRITY), "{r}");
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("no integrity entry logged");
}

/// ReportJournalStatus counts the entries and says whether clients may delete
/// them; InitializeJournal deletes them only when the server allows it.
#[tokio::test]
async fn log_status_and_clearing() {
    let (s, c) = start(log_model(), Options::new()).await;
    for i in 0..4 {
        set_ind(&s, "Ind1", i % 2 == 0);
    }
    let st = c.log_status(LOG).await.unwrap();
    assert_eq!((st.current_entries, st.deletable), (4, false));
    assert!(c.clear_log(LOG, None, &[]).await.is_err(), "cleared a log the server protects");
    assert_eq!(query_all(&c).await.len(), 4);

    let (s, c) = start(log_model(), Options::new().with_deletable_logs()).await;
    for i in 0..4 {
        set_ind(&s, "Ind1", i % 2 == 0);
    }
    assert!(c.log_status(LOG).await.unwrap().deletable);
    let entries = query_all(&c).await;
    // Up to and including the second entry.
    let n = c
        .clear_log(LOG, entries[1].occurrence_time, &entries[1].entry_id)
        .await
        .unwrap();
    assert_eq!(n, 2);
    let left = query_all(&c).await;
    assert_eq!(left.len(), 2);
    assert_eq!(left[0].entry_id, entries[2].entry_id);
    assert_eq!(lcb(&c, "OldEnt").await.bytes(), entries[2].entry_id);
    assert_eq!(c.clear_log(LOG, None, &[]).await.unwrap(), 2);
    assert_eq!(c.log_status(LOG).await.unwrap().current_entries, 0);
    assert!(c.log_status("IEDLD0/LLN0.Nope").await.is_err());
}
