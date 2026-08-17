//! End-to-end tests driving the ACSI client against the ACSI server over an
//! in-memory transport, using the `simpleIO_direct_control.cid` model from
//! `testdata`.
//!
//! Where `mms_loopback.rs` proves the protocol stack, these prove the object
//! model on top of it: browsing, functionally-constrained reads and writes,
//! datasets, reporting with its inclusion bitstring and optional fields, and
//! the four control models with their select reservations.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850::client::{AcsiClass, Client, DataSetEntry};
use iec61850::mms::{BoxTransport, DataAccessError, Value};
use iec61850::model::{AddCause, CtlModel, Fc, OptFlds, Quality, TrgOps};
use iec61850::scl;
use iec61850::server::{self, Identity, Server};

/// The single logical device of the reference model.
const LD: &str = "simpleIOGenericIO";

fn reference_model() -> iec61850::model::Model {
    scl::load_model(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/simpleIO_direct_control.cid"
        ),
        &scl::BuildOptions::new(),
    )
    .expect("the reference CID loads")
}

/// Brings up a server on the reference model and a client joined to it by an
/// in-memory duplex stream.
async fn connected() -> (Client, Server) {
    connected_with(server::Options::new().with_identity(Identity {
        vendor: "DSC Systems".into(),
        model: "simpleIO".into(),
        revision: "1.0".into(),
    }))
    .await
}

async fn connected_with(opts: server::Options) -> (Client, Server) {
    let srv = Server::new(reference_model(), opts);
    let (client_side, server_side) = tokio::io::duplex(256 * 1024);

    let serving = srv.clone();
    tokio::spawn(async move {
        serving
            .serve_stream(Box::new(server_side) as BoxTransport, None)
            .await;
    });

    let client = Client::from_stream(
        Box::new(client_side) as BoxTransport,
        iec61850::client::Options::new(),
    )
    .await
    .expect("the client associates");
    (client, srv)
}

#[tokio::test]
async fn a_client_browses_the_servers_devices_and_nodes() {
    let (c, _s) = connected().await;

    assert_eq!(c.logical_devices().await.unwrap(), [LD]);
    let nodes = c.logical_nodes(LD).await.unwrap();
    for want in ["LLN0", "LPHD1", "GGIO1"] {
        assert!(nodes.contains(&want.to_string()), "{want} missing: {nodes:?}");
    }
}

#[tokio::test]
async fn a_client_reads_values_under_their_functional_constraints() {
    let (c, s) = connected().await;

    // Push a measurand and a status point from the process side.
    s.update(|tx| {
        tx.set_float32(format!("{LD}/GGIO1.AnIn1.mag.f"), 230.4);
        tx.set_quality(
            format!("{LD}/GGIO1.AnIn1.q"),
            Fc::Mx,
            Quality::GOOD | Quality::OLD_DATA,
        );
        tx.set_bool(format!("{LD}/GGIO1.Ind1.stVal"), true);
    });

    let v = c
        .read(format!("{LD}/GGIO1.AnIn1.mag.f"), Fc::Mx)
        .await
        .unwrap();
    assert_eq!(v.as_f32(), 230.4);

    let q = c.read(format!("{LD}/GGIO1.AnIn1.q"), Fc::Mx).await.unwrap();
    assert!(Quality::from_value(&q).is(Quality::OLD_DATA));

    let v = c
        .read(format!("{LD}/GGIO1.Ind1.stVal"), Fc::St)
        .await
        .unwrap();
    assert!(v.as_bool());

    // Reading a whole data object composes the structure of its members.
    let v = c.read(format!("{LD}/GGIO1.AnIn1"), Fc::Mx).await.unwrap();
    assert_eq!(v.type_of(), iec61850::mms::Type::Structure);
    assert_eq!(v.index(0).unwrap().index(0).unwrap().as_f32(), 230.4);
}

#[tokio::test]
async fn reading_under_the_wrong_constraint_is_an_access_error() {
    let (c, _s) = connected().await;
    let err = c
        .read(format!("{LD}/GGIO1.Ind1.stVal"), Fc::Mx)
        .await
        .expect_err("stVal is not a measurand");
    assert!(err.to_string().contains("non-existent"), "got: {err}");
}

#[tokio::test]
async fn a_batch_read_returns_the_values_in_order() {
    let (c, s) = connected().await;
    s.update(|tx| {
        tx.set_float32(format!("{LD}/GGIO1.AnIn1.mag.f"), 1.0);
        tx.set_float32(format!("{LD}/GGIO1.AnIn2.mag.f"), 2.0);
        tx.set_float32(format!("{LD}/GGIO1.AnIn3.mag.f"), 3.0);
    });
    let refs: Vec<_> = (1..=3)
        .map(|i| format!("{LD}/GGIO1.AnIn{i}.mag.f").into())
        .collect();
    let vals = c.read_values(Fc::Mx, &refs).await.unwrap();
    assert_eq!(vals.len(), 3);
    assert_eq!(vals[0].as_f32(), 1.0);
    assert_eq!(vals[2].as_f32(), 3.0);

    // And the concurrent form gives the same answers.
    let many = c.read_many(Fc::Mx, &refs).await;
    assert_eq!(many.len(), 3);
    assert_eq!(many[1].as_ref().unwrap().as_f32(), 2.0);
}

#[tokio::test]
async fn a_client_write_reaches_the_servers_model() {
    let (c, s) = connected().await;
    c.write(
        format!("{LD}/GGIO1.AnIn1.mag.f"),
        Fc::Mx,
        Value::float32(400.5),
    )
    .await
    .unwrap();
    assert_eq!(
        s.read(format!("{LD}/GGIO1.AnIn1.mag.f"), Fc::Mx)
            .unwrap()
            .as_f32(),
        400.5
    );
}

/// The write hook is what an IED uses to protect configuration; a refusal has
/// to reach the client as the access error it chose.
#[tokio::test]
async fn the_write_hook_can_refuse_a_write() {
    let (c, s) = connected().await;
    s.on_write(|da, _v| {
        if da.name == "ctlModel" {
            return Err(server::ERR_ACCESS_DENIED);
        }
        Ok(())
    });

    let err = c
        .write(
            format!("{LD}/GGIO1.SPCSO1.ctlModel"),
            Fc::Cf,
            Value::int32(1),
        )
        .await
        .expect_err("the hook refuses it");
    assert!(err.to_string().contains("object-access-denied"), "got: {err}");

    // Everything else still goes through.
    c.write(
        format!("{LD}/GGIO1.AnIn1.mag.f"),
        Fc::Mx,
        Value::float32(1.0),
    )
    .await
    .expect("an unprotected write is allowed");
}

#[tokio::test]
async fn identify_reports_the_servers_configured_identity() {
    let (c, _s) = connected().await;
    let (vendor, model, revision) = c.mms().identify().await.unwrap();
    assert_eq!(vendor, "DSC Systems");
    assert_eq!(model, "simpleIO");
    assert_eq!(revision, "1.0");
}

#[tokio::test]
async fn a_client_reads_a_configured_dataset_with_its_member_references() {
    let (c, s) = connected().await;
    s.update(|tx| {
        tx.set_bool(format!("{LD}/GGIO1.Ind1.stVal"), true);
    });

    let ds = c.read_data_set(format!("{LD}/LLN0.Events")).await.unwrap();
    assert!(!ds.members.is_empty(), "the reference model defines Events");
    // Every member is labelled with the reference the server holds, not with
    // whatever the caller guessed.
    for m in &ds.members {
        assert!(m.reference.as_str().starts_with(LD), "{}", m.reference);
        assert!(m.value.is_some(), "{} has no value", m.reference);
    }
}

#[tokio::test]
async fn a_client_creates_reads_and_deletes_a_dynamic_dataset() {
    let (c, _s) = connected().await;
    let name = format!("{LD}/LLN0.MyDS");

    c.create_data_set(
        name.clone(),
        &[
            DataSetEntry::new(format!("{LD}/GGIO1.AnIn1.mag.f"), Fc::Mx),
            DataSetEntry::new(format!("{LD}/GGIO1.Ind1.stVal"), Fc::St),
        ],
    )
    .await
    .expect("the dataset is created");

    let ds = c.read_data_set(name.clone()).await.unwrap();
    assert_eq!(ds.members.len(), 2);
    assert_eq!(
        ds.members[0].reference.as_str(),
        format!("{LD}/GGIO1.AnIn1.mag.f")
    );
    assert_eq!(ds.members[0].fc, Fc::Mx);
    assert_eq!(ds.members[1].fc, Fc::St);

    // It shows up in the browse.
    let sets = c
        .logical_node_directory(format!("{LD}/LLN0"), AcsiClass::DataSet)
        .await
        .unwrap();
    assert!(sets.contains(&"MyDS".to_string()), "{sets:?}");

    c.delete_data_set(name.clone()).await.unwrap();
    let sets = c
        .logical_node_directory(format!("{LD}/LLN0"), AcsiClass::DataSet)
        .await
        .unwrap();
    assert!(!sets.contains(&"MyDS".to_string()), "{sets:?}");
}

#[tokio::test]
async fn the_browse_separates_control_blocks_from_data() {
    let (c, _s) = connected().await;

    let urcbs = c
        .logical_node_directory(format!("{LD}/LLN0"), AcsiClass::Urcb)
        .await
        .unwrap();
    assert!(
        urcbs.iter().any(|n| n.starts_with("EventsRCB")),
        "unbuffered blocks: {urcbs:?}"
    );

    let brcbs = c
        .logical_node_directory(format!("{LD}/LLN0"), AcsiClass::Brcb)
        .await
        .unwrap();
    assert!(
        brcbs.iter().any(|n| n.starts_with("EventsBRCB")),
        "buffered blocks: {brcbs:?}"
    );

    // A control block is never reported as data.
    let data = c
        .logical_node_directory(format!("{LD}/LLN0"), AcsiClass::DataObject)
        .await
        .unwrap();
    for cb in urcbs.iter().chain(brcbs.iter()) {
        assert!(!data.contains(cb), "{cb} was reported as data");
    }
    assert!(data.contains(&"Mod".to_string()), "data objects: {data:?}");
}

#[tokio::test]
async fn a_device_wide_browse_finds_every_class_in_one_pass() {
    let (c, _s) = connected().await;
    let entries = c.browse(LD, &[]).await.unwrap();

    let of = |class: AcsiClass| -> Vec<String> {
        entries
            .iter()
            .filter(|e| e.class == class)
            .map(|e| e.reference.to_string())
            .collect()
    };
    assert!(!of(AcsiClass::DataObject).is_empty());
    assert!(!of(AcsiClass::Urcb).is_empty());
    assert!(!of(AcsiClass::Brcb).is_empty());
    assert!(!of(AcsiClass::DataSet).is_empty());

    // A control block reference keeps its constraint so it can be used
    // directly with get_rcb; a data object does not.
    let urcb = &of(AcsiClass::Urcb)[0];
    assert!(urcb.contains(".RP."), "{urcb}");
    assert!(!of(AcsiClass::DataObject)[0].contains(".RP."));
}

#[tokio::test]
async fn the_data_directory_walks_one_level_of_the_tree() {
    let (c, _s) = connected().await;

    let children = c
        .data_directory(format!("{LD}/GGIO1.AnIn1"), Fc::Mx)
        .await
        .unwrap();
    assert!(children.contains(&"mag".to_string()), "{children:?}");
    assert!(children.contains(&"q".to_string()));
    assert!(!children.contains(&"f".to_string()), "f is one level deeper");

    let deeper = c
        .data_directory(format!("{LD}/GGIO1.AnIn1.mag"), Fc::Mx)
        .await
        .unwrap();
    assert_eq!(deeper, ["f"]);

    // The wildcard unions the constraints, which is how a controllable object
    // shows both its status and its control attributes.
    let all = c
        .data_directory(format!("{LD}/GGIO1.SPCSO1"), Fc::All)
        .await
        .unwrap();
    assert!(all.contains(&"stVal".to_string()), "{all:?}");
    assert!(all.contains(&"Oper".to_string()), "{all:?}");
}

#[tokio::test]
async fn the_model_can_be_retrieved_online_without_scl() {
    let (c, _s) = connected().await;
    let m = c.retrieve_model().await.expect("the model is retrievable");

    let ld = m.device(LD).expect("the device is there");
    let ggio = ld.node("GGIO1").expect("GGIO1 is there");
    let anin1 = ggio.object("AnIn1").expect("AnIn1 is there");

    // The measurand's structure came back from the type specifications.
    let mag = anin1.attribute("mag").expect("mag is there");
    assert_eq!(mag.fc, Fc::Mx);
    assert_eq!(mag.children.len(), 1);
    assert_eq!(mag.children[0].name, "f");

    // A controllable object shows both of its constraints.
    let spcso = ggio.object("SPCSO1").expect("SPCSO1 is there");
    assert!(spcso.fcs().contains(&Fc::St));
    assert!(spcso.fcs().contains(&Fc::Co));
}

#[tokio::test]
async fn a_data_change_report_carries_only_the_members_that_changed() {
    let (c, s) = connected().await;

    let mut rcb = c
        .get_rcb(format!("{LD}/LLN0.RP.EventsRCB01"))
        .await
        .expect("the block is materialised");
    assert!(!rcb.buffered);
    assert!(!rcb.rpt_id.is_empty(), "the block reports an identity");
    rcb.opt_flds = OptFlds::DEFAULT;
    rcb.trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sub = c
        .enable_reporting(&rcb, move |r| {
            let _ = tx.send((
                r.rpt_id.clone(),
                r.entries
                    .iter()
                    .map(|e| (e.reference.to_string(), e.value.clone()))
                    .collect::<Vec<_>>(),
            ));
        })
        .await
        .expect("reporting is enabled");

    // Change exactly one dataset member. The Events dataset of the reference
    // model holds SPCSO1..SPCSO4 stVal.
    s.update(|tx| {
        tx.set_bool(format!("{LD}/GGIO1.SPCSO1.stVal"), true);
    });

    let (rpt_id, entries) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("a report arrives")
        .unwrap();
    assert_eq!(rpt_id, rcb.rpt_id);
    assert_eq!(entries.len(), 1, "only the changed member is included");
    assert!(
        entries[0].0.contains("SPCSO1"),
        "the wrong member was reported: {entries:?}"
    );
    assert!(entries[0].1.as_bool());

    sub.disable().await.unwrap();
}

/// A change to something outside the dataset must not fire a data-change
/// report, or every subscriber sees traffic it did not ask for.
#[tokio::test]
async fn a_change_outside_the_dataset_fires_no_data_change_report() {
    let (c, s) = connected().await;
    let mut rcb = c.get_rcb(format!("{LD}/LLN0.RP.EventsRCB01")).await.unwrap();
    // The reference block configures a 1s integrity period; switch it off so
    // only data-change reports can arrive.
    rcb.intg_pd = Duration::ZERO;

    let seen = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&seen);
    let sub = c
        .enable_reporting(&rcb, move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .unwrap();

    // Ind1 is not a member of the Events dataset.
    s.update(|tx| {
        tx.set_bool(format!("{LD}/GGIO1.Ind1.stVal"), true);
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(seen.load(Ordering::SeqCst), 0, "a non-member fired a report");

    // A real member still does.
    s.update(|tx| {
        tx.set_bool(format!("{LD}/GGIO1.SPCSO2.stVal"), true);
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(seen.load(Ordering::SeqCst), 1);

    sub.disable().await.unwrap();
}

/// The reference block configures a 1s integrity period, which has to produce
/// a periodic report of every member with no change at all.
#[tokio::test]
async fn an_integrity_period_reports_every_member_periodically() {
    let (c, _s) = connected().await;
    let rcb = c.get_rcb(format!("{LD}/LLN0.RP.EventsRCB01")).await.unwrap();
    assert_eq!(
        rcb.intg_pd,
        Duration::from_millis(1000),
        "the reference model configures an integrity period"
    );

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sub = c
        .enable_reporting(&rcb, move |r| {
            let _ = tx.send(r.entries.len());
        })
        .await
        .unwrap();

    // Nothing changes; the report is due purely on the period.
    let n = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("an integrity report arrives")
        .unwrap();
    assert_eq!(n, 4, "an integrity report carries every member");

    sub.disable().await.unwrap();
}

/// A general interrogation is how a client fills its cache on connect; every
/// member has to come back, not just the changed ones.
#[tokio::test]
async fn a_general_interrogation_reports_every_dataset_member() {
    let (c, _s) = connected().await;
    let rcb = c.get_rcb(format!("{LD}/LLN0.RP.EventsRCB01")).await.unwrap();

    let members = c
        .data_set_members(format!("{LD}/LLN0.Events"))
        .await
        .unwrap();
    assert!(members.len() > 1, "the dataset has several members");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sub = c
        .enable_reporting(&rcb, move |r| {
            let _ = tx.send(r.entries.len());
        })
        .await
        .unwrap();

    c.trigger_gi(&rcb).await.expect("the GI is accepted");
    let n = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("the GI report arrives")
        .unwrap();
    assert_eq!(n, members.len(), "a GI includes every member");

    sub.disable().await.unwrap();
}

/// Two clients subscribing to different blocks must each see only their own
/// reports, since a report carries no identification but its RptID.
#[tokio::test]
async fn concurrent_subscriptions_receive_only_their_own_reports() {
    let (c, s) = connected().await;

    // A report carries no identification but its RptID, so the two blocks have
    // to be ones the reference model gives distinct ids: EventsRCB watches
    // Events, Measurements watches Measurements.
    let rcb_a = c.get_rcb(format!("{LD}/LLN0.RP.EventsRCB01")).await.unwrap();
    let rcb_b = c
        .get_rcb(format!("{LD}/LLN0.BR.Measurements01"))
        .await
        .unwrap();
    assert_ne!(rcb_a.rpt_id, rcb_b.rpt_id, "the blocks are distinguishable");

    let count_a = Arc::new(AtomicUsize::new(0));
    let count_b = Arc::new(AtomicUsize::new(0));
    let seen_a = Arc::new(Mutex::new(Vec::new()));

    let (ca, sa) = (Arc::clone(&count_a), Arc::clone(&seen_a));
    let sub_a = c
        .enable_reporting(&rcb_a, move |r| {
            ca.fetch_add(1, Ordering::SeqCst);
            sa.lock().unwrap().push(r.rpt_id.clone());
        })
        .await
        .unwrap();
    let cb = Arc::clone(&count_b);
    let sub_b = c
        .enable_reporting(&rcb_b, move |_| {
            cb.fetch_add(1, Ordering::SeqCst);
        })
        .await
        .unwrap();

    // Change a member of the Events dataset only.
    s.update(|tx| {
        tx.set_bool(format!("{LD}/GGIO1.SPCSO1.stVal"), true);
    });
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        count_a.load(Ordering::SeqCst) >= 1,
        "the block watching the changed dataset must fire"
    );
    for id in seen_a.lock().unwrap().iter() {
        assert_eq!(*id, rcb_a.rpt_id, "a subscription saw another's report");
    }
    // The other block watches a different dataset, so its only traffic can be
    // its own integrity period, never this data change.
    assert_eq!(
        count_b.load(Ordering::SeqCst),
        0,
        "a subscription received another dataset's report"
    );

    sub_a.disable().await.unwrap();
    sub_b.disable().await.unwrap();
}

/// A buffered block captures events while nobody is listening, which is the
/// whole reason it exists.
#[tokio::test]
async fn a_buffered_block_delivers_what_it_captured_while_disabled() {
    let (c, s) = connected().await;
    let rcb = c
        .get_rcb(format!("{LD}/LLN0.BR.EventsBRCB01"))
        .await
        .unwrap();
    assert!(rcb.buffered);

    // Change values before anyone subscribes.
    for i in 0..3 {
        s.update(|tx| {
            tx.set_bool(format!("{LD}/GGIO1.Ind1.stVal"), i % 2 == 0);
        });
    }

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sub = c
        .enable_reporting(&rcb, move |r| {
            let _ = tx.send(r.entry_id.clone());
        })
        .await
        .expect("reporting is enabled");

    // The buffered reports are flushed on enable, each with its own EntryID.
    let mut ids = Vec::new();
    for _ in 0..3 {
        let id = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a buffered report arrives")
            .unwrap();
        assert_eq!(id.len(), 8, "a buffered report carries an 8-octet EntryID");
        ids.push(id);
    }
    assert!(ids[0] < ids[1] && ids[1] < ids[2], "EntryIDs are monotonic");

    sub.disable().await.unwrap();
}

#[tokio::test]
async fn a_direct_control_operates_and_updates_the_status_value() {
    let (c, s) = connected().await;
    let object = format!("{LD}/GGIO1.SPCSO1");

    let co = c.control_for(object.clone()).await.unwrap();
    assert_eq!(
        co.model(),
        CtlModel::DirectNormal,
        "the reference CID configures direct control"
    );

    co.operate(Value::boolean(true), &Default::default())
        .await
        .expect("the operate is accepted");

    assert!(
        s.read(format!("{object}.stVal"), Fc::St).unwrap().as_bool(),
        "an accepted operate sets stVal"
    );
    // And the client sees it too.
    assert!(c.read(format!("{object}.stVal"), Fc::St).await.unwrap().as_bool());
}

/// The control handler is where interlocking lives; its refusal has to reach
/// the client as the additional cause it named.
#[tokio::test]
async fn a_control_handler_can_refuse_with_an_additional_cause() {
    let (c, s) = connected().await;
    let object = format!("{LD}/GGIO1.SPCSO1");

    s.on_control(object.clone(), |_ctx| AddCause::BLOCKED_BY_INTERLOCKING);

    let co = c.control_for(object.clone()).await.unwrap();
    let err = co
        .operate(Value::boolean(true), &Default::default())
        .await
        .expect_err("the handler refuses it");
    assert!(
        err.to_string().contains("blocked-by-interlocking"),
        "the cause did not reach the client: {err}"
    );
    assert!(
        !s.read(format!("{object}.stVal"), Fc::St).unwrap().as_bool(),
        "a refused operate must not change stVal"
    );
}

#[tokio::test]
async fn a_control_handler_sees_what_the_client_sent() {
    let (c, s) = connected().await;
    let object = format!("{LD}/GGIO1.SPCSO2");

    let seen = Arc::new(Mutex::new(None));
    let capture = Arc::clone(&seen);
    s.on_control(object.clone(), move |ctx| {
        *capture.lock().unwrap() = Some((
            ctx.value.as_bool(),
            ctx.origin,
            ctx.or_ident.clone(),
            ctx.test,
            ctx.interlock_check,
            ctx.select,
        ));
        AddCause::NONE
    });

    let co = c.control_for(object).await.unwrap();
    co.operate(
        Value::boolean(true),
        &iec61850::client::ControlOptions::new()
            .with_originator(iec61850::model::OrCat::RemoteControl, "scada-1")
            .with_interlock_check(true)
            .with_test(true),
    )
    .await
    .unwrap();

    let (value, origin, ident, test, interlock, select) =
        seen.lock().unwrap().clone().expect("the handler ran");
    assert!(value);
    assert_eq!(origin, iec61850::model::OrCat::RemoteControl);
    assert_eq!(ident, "scada-1");
    assert!(test);
    assert!(interlock);
    assert!(!select, "a direct control has no select phase");
}

/// Select-before-operate exists to stop a second client operating an object a
/// first one has reserved.
#[tokio::test]
async fn an_sbo_control_requires_a_matching_select() {
    let (c, s) = connected().await;
    let object = format!("{LD}/GGIO1.SPCSO3");

    // Reconfigure the object as SBO-with-enhanced-security.
    s.update(|tx| {
        tx.set_int32(
            format!("{object}.ctlModel"),
            Fc::Cf,
            i32::from(CtlModel::SboEnhanced.code()),
        );
    });

    let co = c.control_for(object.clone()).await.unwrap();
    assert_eq!(co.model(), CtlModel::SboEnhanced);

    // Operate() selects first, so the whole sequence goes through.
    co.operate(Value::boolean(true), &Default::default())
        .await
        .expect("select then operate succeeds");
    assert!(s.read(format!("{object}.stVal"), Fc::St).unwrap().as_bool());
}

#[tokio::test]
async fn an_unselected_operate_on_an_sbo_object_is_refused() {
    let (c, s) = connected().await;
    let object = format!("{LD}/GGIO1.SPCSO4");
    s.update(|tx| {
        tx.set_int32(
            format!("{object}.ctlModel"),
            Fc::Cf,
            i32::from(CtlModel::SboEnhanced.code()),
        );
    });

    let co = c.control_for(object.clone()).await.unwrap();
    // Force the direct model on the client so it skips the select the server
    // is expecting.
    let err = co
        .operate(
            Value::boolean(true),
            &iec61850::client::ControlOptions::new().with_model(CtlModel::DirectNormal),
        )
        .await
        .expect_err("the server requires a select");
    assert!(
        err.to_string().contains("not-selected"),
        "expected an object-not-selected diagnosis, got: {err}"
    );
    assert!(!s.read(format!("{object}.stVal"), Fc::St).unwrap().as_bool());
}

#[tokio::test]
async fn the_server_reports_its_connections() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let srv = Server::new(reference_model(), server::Options::new());
    let sink = Arc::clone(&events);
    srv.on_connection(move |ev| {
        sink.lock().unwrap().push((ev.state, ev.open));
    });

    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let serving = srv.clone();
    let task = tokio::spawn(async move {
        serving
            .serve_stream(Box::new(server_side) as BoxTransport, None)
            .await;
    });

    let client = Client::from_stream(
        Box::new(client_side) as BoxTransport,
        iec61850::client::Options::new(),
    )
    .await
    .unwrap();
    assert_eq!(client.logical_devices().await.unwrap(), [LD]);
    assert_eq!(srv.open_connections(), 1);

    client.close().await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;

    let seen = events.lock().unwrap().clone();
    assert_eq!(seen[0].0, server::ConnectionState::Opened);
    assert_eq!(seen[0].1, 1);
    assert_eq!(
        seen.last().unwrap().0,
        server::ConnectionState::Closed,
        "the close has to be reported too: {seen:?}"
    );
    assert_eq!(srv.open_connections(), 0);
}

#[tokio::test]
async fn a_write_to_an_unknown_object_is_refused_without_disturbing_the_others() {
    let (c, _s) = connected().await;

    // A batch where one item does not exist: the others must still apply.
    let results = c
        .mms()
        .write(
            LD,
            &["GGIO1$MX$AnIn1$mag$f", "GGIO1$MX$Nope$mag$f"],
            &[Value::float32(7.5), Value::float32(1.0)],
        )
        .await
        .unwrap();
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert_eq!(results[1], Err(DataAccessError::ObjectAccessUnsupported));
    assert_eq!(
        c.read(format!("{LD}/GGIO1.AnIn1.mag.f"), Fc::Mx)
            .await
            .unwrap()
            .as_f32(),
        7.5
    );
}

#[tokio::test]
async fn the_name_list_pages_through_a_large_model() {
    let (c, _s) = connected().await;
    // The reference model has well over one page of variables, so this only
    // returns them all if the continuation works.
    let names = c
        .mms()
        .get_name_list(iec61850::mms::ObjectClass::NamedVariable, LD)
        .await
        .unwrap();
    assert!(
        names.len() > 100,
        "the continuation stopped early: {} names",
        names.len()
    );
    // And there are no duplicates across page boundaries.
    let mut sorted = names.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "a name was repeated across pages");
}

/// The file services are reached through a different code path from the
/// variable services (high MMS tag numbers, a filestore rather than the
/// model), so they need their own end-to-end coverage.
#[tokio::test]
async fn the_file_services_list_and_stream_a_filestore() {
    let dir = std::env::temp_dir().join(format!("rs-iec61850-acsi-files-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("COMTRADE")).unwrap();
    std::fs::write(dir.join("readme.txt"), b"readme").unwrap();
    // Larger than one chunk, so the streaming path is exercised.
    std::fs::write(dir.join("COMTRADE/rec001.dat"), vec![b'x'; 20_000]).unwrap();

    let (c, _s) = connected_with(server::Options::new().with_file_store(&dir)).await;

    let entries = c
        .file_directory("")
        .await
        .expect("the filestore root lists");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"readme.txt"), "{names:?}");
    assert!(
        names.contains(&"COMTRADE/"),
        "a directory is marked with a trailing separator: {names:?}"
    );

    // A listing one level down reports names that are openable as given.
    let sub = c.file_directory("COMTRADE").await.expect("the subdirectory lists");
    assert_eq!(sub.len(), 1);
    assert_eq!(sub[0].name, "COMTRADE/rec001.dat");
    assert_eq!(sub[0].size, 20_000);

    // Streaming a file larger than one chunk reassembles exactly.
    let data = c.read_file(&sub[0].name).await.expect("the file reads");
    assert_eq!(data.len(), 20_000);
    assert!(data.iter().all(|b| *b == b'x'));

    let small = c.read_file("readme.txt").await.unwrap();
    assert_eq!(small, b"readme");

    // A client that picked a directory out of a listing is told which mistake
    // it made, rather than being sent looking for a name it was just given.
    // In a service error the access class numbers its own codes, so
    // object-access-unsupported is access(1) and object-non-existent access(2);
    // they are a different enum from the DataAccessError used inline in read
    // results, and conflating them would report the wrong fault.
    let err = c
        .read_file("COMTRADE")
        .await
        .expect_err("a directory is not a file");
    assert!(
        err.to_string().contains("access(1)"),
        "expected object-access-unsupported, got: {err}"
    );

    // And a genuinely missing file is still reported as non-existent.
    let err = c.read_file("nope.txt").await.expect_err("no such file");
    assert!(
        err.to_string().contains("access(2)"),
        "expected object-non-existent, got: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
