//! The report control block rules of IEC 61850-7-2 clause 17, driven end to
//! end against the reference model.
//!
//! `EventsRCB01` is unbuffered and `EventsBRCB01` buffered, both over the
//! `Events` dataset of four `stVal` members, both configured with TrgOps
//! period only and a 50 ms buffer time.

use std::time::Duration;

use iec61850::client::{Client, Report};
use iec61850::mms::{BoxTransport, DataAccessError, InitiateRequest, Value};
use iec61850::model::{Fc, OptFlds, Quality, ReasonCode, TrgOps, Validity};
use iec61850::scl;
use iec61850::server::{self, Server};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

const LD: &str = "simpleIOGenericIO";
const URCB: &str = "LLN0$RP$EventsRCB01";
const BRCB: &str = "LLN0$BR$EventsBRCB01";

fn server() -> Server {
    let model = scl::load_model(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/simpleIO_direct_control.cid"
        ),
        &scl::BuildOptions::new(),
    )
    .expect("the reference CID loads");
    Server::new(model, server::Options::new())
}

async fn connect_with(srv: &Server, opts: iec61850::client::Options) -> Client {
    let (client_side, server_side) = tokio::io::duplex(256 * 1024);
    let serving = srv.clone();
    tokio::spawn(async move {
        serving
            .serve_stream(Box::new(server_side) as BoxTransport, None)
            .await;
    });
    Client::from_stream(Box::new(client_side) as BoxTransport, opts)
        .await
        .expect("the client associates")
}

async fn connect(srv: &Server) -> Client {
    connect_with(srv, iec61850::client::Options::new()).await
}

/// Writes one attribute of a control block and returns the server's per-item
/// result.
async fn write_rcb(c: &Client, item: &str, attr: &str, v: Value) -> Result<(), DataAccessError> {
    let res = c
        .mms()
        .write(LD, &[&format!("{item}${attr}")], &[v])
        .await
        .expect("the write is answered");
    res.into_iter().next().expect("one result")
}

async fn read_rcb(c: &Client, item: &str, attr: &str) -> Value {
    c.mms()
        .read(LD, &[&format!("{item}${attr}")])
        .await
        .expect("the read is answered")
        .remove(0)
}

fn rcb_ref(item: &str) -> String {
    let parts: Vec<&str> = item.split('$').collect();
    format!("{LD}/{}.{}.{}", parts[0], parts[1], parts[2])
}

/// Enables a block with the given triggers, fields and integrity period, and
/// returns the stream of its reports.
async fn subscribe(
    c: &Client,
    item: &str,
    trg: TrgOps,
    opt: OptFlds,
    intg: Duration,
) -> (UnboundedReceiver<Report>, iec61850::client::ReportSubscription) {
    let mut rcb = c.get_rcb(rcb_ref(item)).await.expect("the block exists");
    rcb.trg_ops = trg;
    rcb.opt_flds = opt;
    rcb.intg_pd = intg;
    let (tx, rx) = unbounded_channel();
    let sub = c
        .enable_reporting(&rcb, move |r| {
            let _ = tx.send(r.clone());
        })
        .await
        .expect("reporting is enabled");
    (rx, sub)
}

async fn next_report(rx: &mut UnboundedReceiver<Report>) -> Report {
    tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("a report arrives")
        .expect("the stream is open")
}

async fn no_report(rx: &mut UnboundedReceiver<Report>, d: Duration) {
    if let Ok(Some(r)) = tokio::time::timeout(d, rx.recv()).await {
        panic!(
            "unexpected report: seq {}, {} entries",
            r.seq_num,
            r.entries.len()
        );
    }
}

fn set_st_val(srv: &Server, name: &str, on: bool) {
    srv.update(|tx| {
        tx.set_bool(format!("{LD}/GGIO1.{name}.stVal"), on);
    });
}

/// The first client to write a block reserves it; nobody else may
/// reconfigure, enable or interrogate it until the owner leaves.
#[tokio::test]
async fn a_block_is_reserved_by_its_first_writer() {
    let srv = server();
    let (a, b) = (connect(&srv).await, connect(&srv).await);

    write_rcb(&a, URCB, "TrgOps", TrgOps::DATA_CHANGE.value())
        .await
        .expect("the owner writes");
    assert!(
        read_rcb(&b, URCB, "Resv").await.as_bool(),
        "Resv shows the implicit reservation"
    );
    for (attr, v) in [
        ("TrgOps", TrgOps::GI.value()),
        ("RptEna", Value::boolean(true)),
        ("Resv", Value::boolean(false)),
    ] {
        assert_eq!(
            write_rcb(&b, URCB, attr, v).await,
            Err(DataAccessError::TemporarilyUnavailable),
            "a second client writing {attr}"
        );
    }

    // The reservation ends with the owner's association.
    a.close().await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while write_rcb(&b, URCB, "TrgOps", TrgOps::GI.value()).await.is_err() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the reservation outlived its owner's association"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Settings are locked while the block is enabled; the server-maintained
/// attributes are never writable.
#[tokio::test]
async fn settings_are_locked_while_enabled() {
    let srv = server();
    let c = connect(&srv).await;
    let (_rx, sub) = subscribe(&c, URCB, TrgOps::GI, OptFlds::SEQ_NUM, Duration::ZERO).await;

    for (attr, v) in [
        ("IntgPd", Value::uint32(500)),
        ("DatSet", Value::visible_string(format!("{LD}/LLN0$Events2"))),
        ("RptEna", Value::boolean(true)),
    ] {
        assert_eq!(
            write_rcb(&c, URCB, attr, v).await,
            Err(DataAccessError::TemporarilyUnavailable),
            "writing {attr} while enabled"
        );
    }
    sub.disable().await.unwrap();
    for attr in ["ConfRev", "SqNum"] {
        let v = read_rcb(&c, URCB, attr).await;
        assert_eq!(
            write_rcb(&c, URCB, attr, v).await,
            Err(DataAccessError::ObjectAccessDenied),
            "writing {attr}"
        );
    }
}

/// A dataset reference must exist, and changing it changes ConfRev.
#[tokio::test]
async fn the_dataset_is_validated_and_counted_in_conf_rev() {
    let srv = server();
    let c = connect(&srv).await;

    assert_eq!(
        write_rcb(
            &c,
            URCB,
            "DatSet",
            Value::visible_string(format!("{LD}/LLN0$NoSuchSet"))
        )
        .await,
        Err(DataAccessError::ObjectValueInvalid)
    );
    let before = read_rcb(&c, URCB, "ConfRev").await.as_u32();
    write_rcb(
        &c,
        URCB,
        "DatSet",
        Value::visible_string(format!("{LD}/LLN0$Events2")),
    )
    .await
    .expect("an existing dataset");
    assert_eq!(read_rcb(&c, URCB, "ConfRev").await.as_u32(), before + 1);
}

/// Only the triggers in TrgOps produce reports; GI reads FALSE once done.
#[tokio::test]
async fn only_the_configured_triggers_produce_reports() {
    let srv = server();
    let c = connect(&srv).await;
    let (mut rx, _sub) =
        subscribe(&c, URCB, TrgOps::GI, OptFlds::REASON_CODE, Duration::ZERO).await;

    set_st_val(&srv, "SPCSO1", true);
    no_report(&mut rx, Duration::from_millis(300)).await; // dchg is not a trigger

    write_rcb(&c, URCB, "GI", Value::boolean(true))
        .await
        .expect("GI");
    let r = next_report(&mut rx).await;
    assert_eq!(r.entries.len(), 4);
    assert_eq!(r.entries[0].reason, ReasonCode::GI);
    assert!(
        !read_rcb(&c, URCB, "GI").await.as_bool(),
        "GI reads FALSE after the interrogation"
    );
}

/// A GI on a disabled block is refused: interrogation is a service of an
/// enabled block.
#[tokio::test]
async fn a_gi_needs_an_enabled_block() {
    let srv = server();
    let c = connect(&srv).await;
    assert_eq!(
        write_rcb(&c, URCB, "GI", Value::boolean(true)).await,
        Err(DataAccessError::TemporarilyUnavailable)
    );
}

/// A quality change is reported as qchg, and rewriting an unchanged value is
/// no data change.
#[tokio::test]
async fn a_quality_change_reports_qchg() {
    let srv = server();
    let c = connect(&srv).await;
    // Events2 names whole data objects, so q is a member too.
    write_rcb(
        &c,
        URCB,
        "DatSet",
        Value::visible_string(format!("{LD}/LLN0$Events2")),
    )
    .await
    .unwrap();
    let (mut rx, _sub) = subscribe(
        &c,
        URCB,
        TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE,
        OptFlds::REASON_CODE,
        Duration::ZERO,
    )
    .await;

    srv.update(|tx| {
        tx.set_quality(
            format!("{LD}/GGIO1.SPCSO1.q"),
            Fc::St,
            Quality::GOOD.with_validity(Validity::Invalid),
        );
    });
    let r = next_report(&mut rx).await;
    assert_eq!(r.entries.len(), 1);
    assert_eq!(r.entries[0].reason, ReasonCode::QUALITY_CHANGE);

    set_st_val(&srv, "SPCSO2", false); // already false
    no_report(&mut rx, Duration::from_millis(300)).await;
}

/// An unbuffered block's SqNum is INT8U: it wraps to 0 after 255, and the
/// attribute follows the reports.
#[tokio::test]
async fn an_unbuffered_sq_num_wraps_at_256() {
    let srv = server();
    let c = connect(&srv).await;
    let (mut rx, _sub) = subscribe(&c, URCB, TrgOps::GI, OptFlds::SEQ_NUM, Duration::ZERO).await;

    for i in 0..=256u32 {
        write_rcb(&c, URCB, "GI", Value::boolean(true))
            .await
            .expect("GI");
        let r = next_report(&mut rx).await;
        assert_eq!(r.seq_num, i % 256, "report {i}");
    }
    assert_eq!(
        read_rcb(&c, URCB, "SqNum").await.as_u32(),
        1,
        "the attribute holds the next report's number"
    );
}

/// Reports a buffered block has delivered are not delivered again when it is
/// re-enabled, and a re-enabled block numbers from zero.
#[tokio::test]
async fn a_buffered_block_does_not_replay_delivered_reports() {
    let srv = server();
    let c = connect(&srv).await;
    let opt = OptFlds::SEQ_NUM | OptFlds::ENTRY_ID;
    let (mut rx, sub) = subscribe(&c, BRCB, TrgOps::DATA_CHANGE, opt, Duration::ZERO).await;

    set_st_val(&srv, "SPCSO1", true);
    next_report(&mut rx).await;
    sub.disable().await.unwrap();

    let (mut rx2, _sub2) = subscribe(&c, BRCB, TrgOps::DATA_CHANGE, opt, Duration::ZERO).await;
    no_report(&mut rx2, Duration::from_millis(400)).await;

    set_st_val(&srv, "SPCSO1", false);
    assert_eq!(next_report(&mut rx2).await.seq_num, 0);
}

/// Resynchronisation needs an EntryID the buffer holds; all zeros asks for
/// the whole buffer and is no overflow.
#[tokio::test]
async fn resynchronisation_needs_an_entry_the_buffer_holds() {
    let srv = server();
    let c = connect(&srv).await;
    write_rcb(&c, BRCB, "TrgOps", TrgOps::DATA_CHANGE.value())
        .await
        .unwrap();
    set_st_val(&srv, "SPCSO1", true);
    set_st_val(&srv, "SPCSO2", true);
    tokio::time::sleep(Duration::from_millis(150)).await; // let the buffer time close

    assert_eq!(
        write_rcb(&c, BRCB, "EntryID", Value::octet_string(vec![0xaa; 8])).await,
        Err(DataAccessError::ObjectValueInvalid),
        "an unknown EntryID"
    );
    write_rcb(&c, BRCB, "EntryID", Value::octet_string(vec![0; 8]))
        .await
        .expect("a zero EntryID");
    let (mut rx, _sub) = subscribe(
        &c,
        BRCB,
        TrgOps::DATA_CHANGE,
        OptFlds::ENTRY_ID | OptFlds::BUF_OVFL,
        Duration::ZERO,
    )
    .await;
    assert!(
        !next_report(&mut rx).await.buf_ovfl,
        "a resync from the start is no buffer overflow"
    );
}

/// An empty RptID means the block's own reference, which the client matches
/// its reports against.
#[tokio::test]
async fn an_empty_rpt_id_uses_the_blocks_reference() {
    let srv = server();
    let c = connect(&srv).await;
    write_rcb(&c, URCB, "RptID", Value::visible_string(""))
        .await
        .unwrap();
    let (mut rx, _sub) = subscribe(&c, URCB, TrgOps::GI, OptFlds::SEQ_NUM, Duration::ZERO).await;
    write_rcb(&c, URCB, "GI", Value::boolean(true))
        .await
        .unwrap();
    assert_eq!(next_report(&mut rx).await.rpt_id, format!("{LD}/{URCB}"));
}

/// Integrity reports need the integrity trigger as well as a period.
#[tokio::test]
async fn integrity_reports_need_the_integrity_trigger() {
    let srv = server();
    let c = connect(&srv).await;
    let period = Duration::from_millis(100);
    let (mut rx, sub) = subscribe(&c, URCB, TrgOps::GI, OptFlds::REASON_CODE, period).await;
    no_report(&mut rx, Duration::from_millis(400)).await;
    sub.disable().await.unwrap();

    let (mut rx2, _sub2) = subscribe(
        &c,
        URCB,
        TrgOps::GI | TrgOps::INTEGRITY,
        OptFlds::REASON_CODE,
        period,
    )
    .await;
    assert_eq!(
        next_report(&mut rx2).await.entries[0].reason,
        ReasonCode::INTEGRITY
    );
}

/// Within the buffer time, changes of different members share one report; a
/// member changing twice closes the window so neither value is lost.
#[tokio::test]
async fn the_buffer_time_collects_events() {
    let srv = server();
    let c = connect(&srv).await;
    write_rcb(&c, URCB, "BufTm", Value::uint32(300))
        .await
        .unwrap();
    let (mut rx, _sub) = subscribe(
        &c,
        URCB,
        TrgOps::DATA_CHANGE,
        OptFlds::REASON_CODE,
        Duration::ZERO,
    )
    .await;

    set_st_val(&srv, "SPCSO1", true);
    set_st_val(&srv, "SPCSO2", true);
    assert_eq!(next_report(&mut rx).await.entries.len(), 2, "one window");

    set_st_val(&srv, "SPCSO3", true);
    set_st_val(&srv, "SPCSO3", false);
    let (first, second) = (next_report(&mut rx).await, next_report(&mut rx).await);
    assert!(first.entries[0].value.as_bool(), "the earlier value is kept");
    assert!(!second.entries[0].value.as_bool());
}

/// A report larger than the association's PDU size is segmented
/// (IEC 61850-8-1): one SqNum, SubSeqNum counting up, MoreSegmentsFollow on
/// all but the last.
#[tokio::test]
async fn a_report_is_segmented_to_the_pdu_size() {
    let srv = server();
    let mut opts = iec61850::client::Options::new();
    opts.initiate = Some(InitiateRequest {
        local_detail: 200,
        ..Default::default()
    });
    let c = connect_with(&srv, opts).await;
    let (mut rx, _sub) = subscribe(
        &c,
        URCB,
        TrgOps::GI,
        OptFlds::SEQ_NUM | OptFlds::DATA_REF | OptFlds::REASON_CODE | OptFlds::DATA_SET_NAME,
        Duration::ZERO,
    )
    .await;
    write_rcb(&c, URCB, "GI", Value::boolean(true))
        .await
        .unwrap();

    let mut segments = Vec::new();
    loop {
        let r = next_report(&mut rx).await;
        let more = r.more_follows;
        segments.push(r);
        if !more {
            break;
        }
    }
    assert!(segments.len() >= 2, "the report was not segmented");
    let mut entries = 0;
    for (i, s) in segments.iter().enumerate() {
        assert_eq!(s.seq_num, segments[0].seq_num, "segment {i}");
        assert_eq!(s.sub_seq_num, i as u32, "segment {i}");
        entries += s.entries.len();
    }
    assert_eq!(entries, 4, "the segments carry every member");
}

/// Operating a control reports the status change like any other.
#[tokio::test]
async fn an_operate_reports_the_status_change() {
    let srv = server();
    let c = connect(&srv).await;
    let (mut rx, _sub) = subscribe(
        &c,
        URCB,
        TrgOps::DATA_CHANGE,
        OptFlds::REASON_CODE,
        Duration::ZERO,
    )
    .await;

    let co = c.control_for(format!("{LD}/GGIO1.SPCSO1")).await.unwrap();
    co.operate(Value::boolean(true), &Default::default())
        .await
        .expect("operate");
    let r = next_report(&mut rx).await;
    assert_eq!(r.entries.len(), 1);
    assert_eq!(r.entries[0].index, 0);
    assert!(r.entries[0].value.as_bool());
}

fn small_pdu(n: i32) -> iec61850::client::Options {
    let mut opts = iec61850::client::Options::new();
    opts.initiate = Some(InitiateRequest {
        local_detail: n,
        ..Default::default()
    });
    opts
}

/// GetNameList pages to the association's PDU size, and the pages add up to
/// the whole list. A page over the negotiated size would be refused as a
/// resource error, so a complete list is proof the pages fit.
#[tokio::test]
async fn the_name_list_pages_to_the_pdu_size() {
    use iec61850::mms::ObjectClass;
    let srv = server();
    let full = connect(&srv)
        .await
        .mms()
        .get_name_list(ObjectClass::NamedVariable, LD)
        .await
        .unwrap();
    let paged = connect_with(&srv, small_pdu(300))
        .await
        .mms()
        .get_name_list(ObjectClass::NamedVariable, LD)
        .await
        .unwrap();
    assert!(full.len() > 20, "the model has several pages of names");
    assert_eq!(paged, full);
}

/// A response that would exceed the PDU size is a resource error instead.
#[tokio::test]
async fn an_oversized_response_is_a_resource_error() {
    let srv = server();
    let c = connect_with(&srv, small_pdu(200)).await;
    // Every status attribute of GGIO1 at once is far over 200 octets.
    let err = c
        .mms()
        .read(LD, &["GGIO1$ST"])
        .await
        .expect_err("the response does not fit");
    assert!(err.to_string().contains("resource"), "got: {err}");
}

/// File reads are chunked to the association's PDU size, and the chunks add
/// up to the file.
#[tokio::test]
async fn a_file_is_read_in_chunks_that_fit_the_pdu() {
    let dir = std::env::temp_dir().join(format!("rcb-rules-files-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("rec.dat"), &data).unwrap();

    let model = scl::load_model(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/simpleIO_direct_control.cid"
        ),
        &scl::BuildOptions::new(),
    )
    .unwrap();
    let srv = Server::new(model, server::Options::new().with_file_store(&dir));
    let c = connect_with(&srv, small_pdu(300)).await;
    assert_eq!(c.read_file("rec.dat").await.unwrap(), data);
    let _ = std::fs::remove_dir_all(&dir);
}
