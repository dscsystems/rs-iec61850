//! The server's Edition 2 and 2.1 objects and services, over a real
//! association: the GOOSE, sampled-value and log control blocks, sampled-value
//! control, configured report reservations, declared setting groups, and the
//! handling of types and constraints the crate does not know.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850::client::{Client, Options as ClientOptions};
use iec61850::mms::{DataAccessError, Type, Value};
use iec61850::model::{self, Fc, ObjectReference};
use iec61850::scl;
use iec61850::server::{Options, Server, SvControlEvent};
use tokio::net::TcpListener;

const ED21: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/ed21_diverse.cid");

fn ed21() -> model::Model {
    scl::load_model(ED21, &scl::BuildOptions::new()).expect("fixture loads")
}

/// Serves `server` on a loopback port and returns the address.
async fn serve(server: &Server) -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    let s = server.clone();
    tokio::spawn(async move {
        let _ = s.serve(ln).await;
    });
    addr
}

async fn dial(addr: &str) -> Client {
    Client::dial_with(addr, ClientOptions::new().with_timeout(Duration::from_secs(3)))
        .await
        .expect("dial")
}

async fn start(m: model::Model, opts: Options) -> (Client, Server, String) {
    let server = Server::new(m, opts);
    let addr = serve(&server).await;
    (dial(&addr).await, server, addr)
}

async fn read(c: &Client, r: &str, fc: Fc) -> Value {
    c.read(r, fc).await.unwrap_or_else(|e| panic!("read {r}: {e}"))
}

fn access(e: iec61850::client::Error) -> Option<DataAccessError> {
    e.as_access_error()
}

/// The GOOSE, sampled-value and log control blocks the SCL loader carries are
/// visible to a client browsing the server.
#[tokio::test]
async fn control_blocks_are_browseable() {
    use iec61850::client::AcsiClass;
    let (c, _s, _) = start(ed21(), Options::new()).await;
    for (class, want) in [
        (AcsiClass::GoCb, "ED21LD0/LLN0.GO.gcb01"),
        (AcsiClass::GsCb, "ED21LD0/LLN0.GS.gscb01"),
        (AcsiClass::Msvcb, "ED21LD0/LLN0.MS.msvcb01"),
        (AcsiClass::Lcb, "ED21LD0/LLN0.LG.lcb01"),
        (AcsiClass::Usvcb, "ED21LD0/LLN0.US.usvcb01"),
    ] {
        let got = c.browse("ED21LD0", &[class]).await.unwrap();
        assert!(
            got.iter().any(|e| e.reference.as_str() == want),
            "{class:?} = {got:?}, want {want}"
        );
    }
}

/// A GOOSE control block serves its SCL configuration under the component
/// names of IEC 61850-8-1.
#[tokio::test]
async fn a_gocb_reads_back_its_configuration() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    assert!(!read(&c, "ED21LD0/LLN0.gcb01.GoEna", Fc::Go).await.as_bool());
    assert_eq!(read(&c, "ED21LD0/LLN0.gcb01.GoID", Fc::Go).await.text(), "ED21LD0/LLN0.gcb01");
    assert_eq!(
        read(&c, "ED21LD0/LLN0.gcb01.DatSet", Fc::Go).await.text(),
        "ED21LD0/LLN0$Measurements"
    );
    assert_eq!(read(&c, "ED21LD0/LLN0.gcb01.ConfRev", Fc::Go).await.as_i64(), 1);
    let mac = read(&c, "ED21LD0/LLN0.gcb01.DstAddress.Addr", Fc::Go).await;
    assert_eq!(mac.bytes(), [0x01, 0x0c, 0xcd, 0x03, 0x00, 0x01]);
    assert_eq!(read(&c, "ED21LD0/LLN0.gcb01.DstAddress.APPID", Fc::Go).await.as_i64(), 0x2000);
    assert_eq!(read(&c, "ED21LD0/LLN0.gcb01.DstAddress", Fc::Go).await.len(), 4);
    assert!(read(&c, "ED21LD0/LLN0.gcb01.FixedOffs", Fc::Go).await.as_bool());
    // The GSSE variant is served under GS, not GO.
    assert_eq!(read(&c, "ED21LD0/LLN0.gscb01.GsID", Fc::Gs).await.text(), "ED21LD0/LLN0.gscb01");
}

/// The components of each control block are exactly those IEC 61850-8-1
/// defines, in its order.
#[test]
fn control_block_components_follow_8_1() {
    let s = Server::new(ed21(), Options::new());
    s.with_model(|m| {
        let lln0 = m.device("ED21LD0").unwrap().node("LLN0").unwrap();
        for (name, want) in [
            ("gcb01", "GoEna,GoID,DatSet,ConfRev,NdsCom,DstAddress,MinTime,MaxTime,FixedOffs"),
            ("gscb01", "GsEna,GsID"),
            ("msvcb01", "SvEna,MsvID,DatSet,ConfRev,SmpRate,OptFlds,SmpMod,DstAddress,noASDU"),
            ("usvcb01", "SvEna,Resv,UsvID,DatSet,ConfRev,SmpRate,OptFlds,SmpMod,DstAddress,noASDU"),
            ("lcb01", "LogEna,LogRef,DatSet,OldEntrTm,NewEntrTm,OldEnt,NewEnt,TrgOps,IntgPd"),
        ] {
            let o = lln0.object(name).unwrap_or_else(|| panic!("{name} not materialised"));
            let got: Vec<&str> = o.attributes.iter().map(|a| a.name.as_str()).collect();
            assert_eq!(got.join(","), want, "{name}");
        }
    });
}

/// The sampled-value control block serves SmvOpts as the OptFlds bit string
/// and SmpMod as the enumeration.
#[tokio::test]
async fn an_msvcb_serves_its_options() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    let v = read(&c, "ED21LD0/LLN0.msvcb01.OptFlds", Fc::Ms).await;
    assert_eq!(v.bit_len(), 10);
    for bit in [0, 1, 2, 5, 6] {
        assert!(v.bit(bit), "OptFlds bit {bit}");
    }
    for bit in [3, 4] {
        assert!(!v.bit(bit), "OptFlds bit {bit}");
    }
    assert_eq!(read(&c, "ED21LD0/LLN0.msvcb01.SmpMod", Fc::Ms).await.as_i64(), 1);
    assert_eq!(read(&c, "ED21LD0/LLN0.msvcb01.MsvID", Fc::Ms).await.text(), "ED21MSVCB01");
    assert_eq!(read(&c, "ED21LD0/LLN0.usvcb01.UsvID", Fc::Us).await.text(), "ED21USVCB01");
}

/// A log control block serves its dataset and log reference.
#[tokio::test]
async fn an_lcb_reads_back() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    assert!(read(&c, "ED21LD0/LLN0.lcb01.LogEna", Fc::Lg).await.as_bool());
    assert_eq!(read(&c, "ED21LD0/LLN0.lcb01.LogRef", Fc::Lg).await.text(), "ED21LD0/LLN0$EventLog");
    assert_eq!(
        read(&c, "ED21LD0/LLN0.lcb01.DatSet", Fc::Lg).await.text(),
        "ED21LD0/LLN0$Measurements"
    );
    assert_eq!(read(&c, "ED21LD0/LLN0.lcb01.OldEnt", Fc::Lg).await.bytes().len(), 8);
}

/// A log placed in another logical node or device is referenced there.
#[test]
fn an_lcb_references_a_log_elsewhere() {
    let lc = model::LogControl {
        name: "lcb".into(),
        log_name: "Events".into(),
        log_ld_inst: "LD1".into(),
        log_ln: "PRE_GAPC1".into(),
        ..Default::default()
    };
    let m = model::Model {
        name: "IED".into(),
        devices: vec![model::LogicalDevice {
            name: "IEDLD0".into(),
            inst: "LD0".into(),
            nodes: vec![model::LogicalNode {
                name: "LLN0".into(),
                class: "LLN0".into(),
                log_controls: vec![lc],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let s = Server::new(m, Options::new());
    let got = s.read("IEDLD0/LLN0.lcb.LogRef", Fc::Lg).unwrap();
    assert_eq!(got.text(), "IEDLD1/PRE_GAPC1$Events");
}

/// A BRCB has an Owner, empty while the block is unreserved.
#[tokio::test]
async fn a_brcb_has_an_owner() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    // Instance 03: 01 is reserved for a client by the configuration.
    let v = read(&c, "ED21LD0/LLN0.brcb0103.Owner", Fc::Br).await;
    assert!(v.bytes().is_empty(), "{v:?}");
}

/// A device whose SCL declares its setting groups gets an SGCB with that
/// count, active group and reservation time, and each group serves its own
/// values.
#[tokio::test]
async fn declared_setting_groups_are_served() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    assert_eq!(read(&c, "ED21LD0/LLN0.SGCB.NumOfSG", Fc::Sp).await.as_i64(), 2);
    assert_eq!(read(&c, "ED21LD0/LLN0.SGCB.ActSG", Fc::Sp).await.as_i64(), 1);
    assert_eq!(read(&c, "ED21LD0/LLN0.SGCB.ResvTms", Fc::Sp).await.as_i64(), 30000);
    assert_eq!(read(&c, "ED21LD0/GGIO1.IntRange.setVal", Fc::Sg).await.as_f64(), 50.5);
    c.write("ED21LD0/LLN0.SGCB.ActSG", Fc::Sp, Value::uint8(2)).await.unwrap();
    assert_eq!(read(&c, "ED21LD0/GGIO1.IntRange.setVal", Fc::Sg).await.as_f64(), 60.5);
    assert_eq!(read(&c, "ED21LD0/LLN0.SGCB.ActSG", Fc::Sp).await.as_i64(), 2);
    c.write("ED21LD0/LLN0.SGCB.ActSG", Fc::Sp, Value::uint8(1)).await.unwrap();
    assert_eq!(read(&c, "ED21LD0/GGIO1.IntRange.setVal", Fc::Sg).await.as_f64(), 50.5);
}

/// Exactly one SGCB per logical device, even when both the options and the
/// SCL configure the groups, so a write is visible in the read that follows.
#[tokio::test]
async fn only_one_sgcb_per_device() {
    let s = Server::new(ed21(), Options::new().with_setting_groups(2));
    s.with_model(|m| {
        let lln0 = m.device("ED21LD0").unwrap().node("LLN0").unwrap();
        assert_eq!(lln0.objects.iter().filter(|o| o.name == "SGCB").count(), 1);
    });
    let addr = serve(&s).await;
    let c = dial(&addr).await;
    c.write("ED21LD0/LLN0.SGCB.ActSG", Fc::Sp, Value::uint8(2)).await.unwrap();
    assert_eq!(read(&c, "ED21LD0/LLN0.SGCB.ActSG", Fc::Sp).await.as_i64(), 2);
}

/// An attribute under a functional constraint the crate does not know stays
/// readable over MMS, under the peer's own mnemonic, and is not writable.
#[tokio::test]
async fn an_unknown_fc_is_readable_over_mms() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    let v = c
        .mms()
        .read("ED21LD0", &["GGIO1$ZX$Beh$vendorFCAttr"])
        .await
        .unwrap();
    assert_eq!(v[0].type_of(), Type::Integer, "{:?}", v[0]);
    let res = c
        .mms()
        .write("ED21LD0", &["GGIO1$ZX$Beh$vendorFCAttr"], &[Value::int32(7)])
        .await
        .unwrap();
    assert!(res[0].is_err(), "a write under an unknown constraint was accepted");
    // The name list carries the verbatim mnemonic too.
    let names = c
        .mms()
        .get_name_list(iec61850::mms::ObjectClass::NamedVariable, "ED21LD0")
        .await
        .unwrap();
    assert!(names.iter().any(|n| n == "GGIO1$ZX$Beh$vendorFCAttr"), "{names:?}");
}

/// An attribute whose basic type the crate does not know is reported with an
/// access error, not served as a zero of some invented type.
#[tokio::test]
async fn an_unknown_basic_type_reads_as_type_inconsistent() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    let err = c.read("ED21LD0/GGIO1.VendorDO.stVal", Fc::St).await.unwrap_err();
    assert_eq!(access(err), Some(DataAccessError::TypeInconsistent));
    let v = read(&c, "ED21LD0/GGIO1.VendorDO.opts", Fc::St).await;
    assert_eq!(v.bit_len(), 10);
}

/// An attribute of an unknown basic type inside a structure fails the whole
/// read: the rest would be a structure with fewer components than the type
/// specification declares.
#[tokio::test]
async fn an_unknown_typed_member_fails_the_object_read() {
    let leaf = |name: &str, v: Option<Value>, kind: Option<Type>| model::DataAttribute {
        name: name.into(),
        fc: Fc::St,
        kind,
        value: v,
        ..Default::default()
    };
    let m = model::Model {
        name: "I".into(),
        devices: vec![model::LogicalDevice {
            name: "ILD0".into(),
            inst: "LD0".into(),
            nodes: vec![model::LogicalNode {
                name: "GGIO1".into(),
                class: "GGIO".into(),
                objects: vec![model::DataObject {
                    name: "Weird".into(),
                    cdc: "VEND".into(),
                    attributes: vec![
                        leaf("a", Some(Value::int32(1)), Some(Type::Integer)),
                        leaf("b", None, None),
                        leaf("c", Some(Value::int32(3)), Some(Type::Integer)),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let (c, _s, _) = start(m, Options::new()).await;
    assert!(c.read("ILD0/GGIO1.Weird", Fc::St).await.is_err());
    assert_eq!(read(&c, "ILD0/GGIO1.Weird.a", Fc::St).await.as_i64(), 1);
}

/// A data object not exposed under the constraint named in the item does not
/// exist under it: object-non-existent, a defined DataAccessError.
#[tokio::test]
async fn a_read_under_an_unrelated_constraint_is_object_non_existent() {
    let spc = model::new_data_object(
        "SPCSO1",
        model::Cdc::Spc,
        &model::CdcOptions::new().with_control_model(model::CtlModel::DirectNormal),
    );
    let m = model::Model {
        name: "I".into(),
        devices: vec![model::LogicalDevice {
            name: "ILD0".into(),
            inst: "LD0".into(),
            nodes: vec![model::LogicalNode {
                name: "GGIO1".into(),
                class: "GGIO".into(),
                objects: vec![spc],
                ..Default::default()
            }],
        }],
        ..Default::default()
    };
    let (c, _s, _) = start(m, Options::new()).await;
    let err = c.read("ILD0/GGIO1.SPCSO1", Fc::Mx).await.unwrap_err();
    assert_eq!(access(err), Some(DataAccessError::ObjectNonExistent));
}

/// A ClientLN reservation reaches the wire: the reserved instance shows
/// ResvTms -1 and its client as Owner, and a client from any other address is
/// refused it, while the unreserved instances stay open.
#[tokio::test]
async fn a_client_ln_reservation_is_served() {
    let (c, _s, _) = start(ed21(), Options::new()).await;
    assert_eq!(read(&c, "ED21LD0/LLN0.brcb0101.ResvTms", Fc::Br).await.as_i64(), -1);
    assert_eq!(read(&c, "ED21LD0/LLN0.brcb0101.Owner", Fc::Br).await.bytes(), [10, 0, 0, 50]);
    assert_eq!(read(&c, "ED21LD0/LLN0.brcb0102.ResvTms", Fc::Br).await.as_i64(), 0);
    let write = |item: &'static str| {
        let c = &c;
        async move {
            c.mms()
                .write("ED21LD0", &[item], &[model::TrgOps::GI.value()])
                .await
                .unwrap()
                .remove(0)
        }
    };
    assert_eq!(
        write("LLN0$BR$brcb0101$TrgOps").await,
        Err(DataAccessError::TemporarilyUnavailable)
    );
    assert_eq!(write("LLN0$BR$brcb0103$TrgOps").await, Ok(()));
}

/// Records sampled-value control block events.
#[derive(Clone, Default)]
struct SvEvents(Arc<Mutex<Vec<SvControlEvent>>>);

impl SvEvents {
    async fn next(&self) -> SvControlEvent {
        for _ in 0..500 {
            {
                let mut evs = self.0.lock().unwrap();
                if !evs.is_empty() {
                    return evs.remove(0);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no sampled-value control event");
    }

    fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_empty()
    }
}

/// A USVCB is reserved by one association at a time: the others may read it
/// but not change it, only SvEna and Resv are writable, the configuration not
/// at all while the block is enabled, and the reservation and the stream end
/// with the association.
#[tokio::test]
async fn a_usvcb_is_reserved_by_one_association() {
    let server = Server::new(ed21(), Options::new());
    let rec = SvEvents::default();
    let r = rec.clone();
    server.on_sv_control(move |ev| r.0.lock().unwrap().push(ev.clone()));
    let addr = serve(&server).await;
    let (a, b) = (dial(&addr).await, dial(&addr).await);
    let usvcb = ObjectReference::new("ED21LD0/LLN0.usvcb01");

    a.reserve_usvcb(usvcb.clone(), true).await.unwrap();
    let ev = rec.next().await;
    assert!(ev.unicast && ev.reserved && !ev.enabled && ev.conn.is_some());
    assert_eq!((ev.block.name.as_str(), ev.device.as_str()), ("usvcb01", "ED21LD0"));

    // Another association reads the reservation and is refused.
    assert!(read(&b, "ED21LD0/LLN0.usvcb01.Resv", Fc::Us).await.as_bool());
    for attr in ["SvEna", "Resv"] {
        let err = b
            .write(usvcb.child(attr), Fc::Us, Value::boolean(true))
            .await
            .unwrap_err();
        assert_eq!(access(err), Some(DataAccessError::TemporarilyUnavailable), "{attr}");
    }

    // The configuration is not writable, and not at all while enabled.
    let err = a
        .write(usvcb.child("UsvID"), Fc::Us, Value::visible_string("X"))
        .await
        .unwrap_err();
    assert_eq!(access(err), Some(DataAccessError::ObjectAccessDenied));
    let err = a.write(usvcb.child("SvEna"), Fc::Us, Value::int32(1)).await.unwrap_err();
    assert_eq!(access(err), Some(DataAccessError::TypeInconsistent));
    a.enable_svcb(usvcb.clone(), true, true).await.unwrap();
    let ev = rec.next().await;
    assert!(ev.enabled && ev.reserved);
    let err = a.write(usvcb.child("SmpRate"), Fc::Us, Value::uint16(4000)).await.unwrap_err();
    assert_eq!(access(err), Some(DataAccessError::TemporarilyUnavailable));
    // Writing what is already set changes nothing and reports nothing.
    a.enable_svcb(usvcb.clone(), true, true).await.unwrap();

    // The association ends: the block is released and disabled.
    a.close().await.unwrap();
    let ev = rec.next().await;
    assert!(!ev.enabled && !ev.reserved && ev.conn.is_none(), "{ev:?}");
    assert!(!read(&b, "ED21LD0/LLN0.usvcb01.SvEna", Fc::Us).await.as_bool());
    b.reserve_usvcb(usvcb.clone(), true).await.unwrap();
    assert!(rec.next().await.reserved);
    b.reserve_usvcb(usvcb.clone(), false).await.unwrap();
    let ev = rec.next().await;
    assert!(!ev.reserved && ev.conn.is_none());
}

/// An MSVCB has no reservation: any client enables it, and its stream
/// outlives the association that enabled it.
#[tokio::test]
async fn an_msvcb_is_enabled_by_any_client() {
    let server = Server::new(ed21(), Options::new());
    let rec = SvEvents::default();
    let r = rec.clone();
    server.on_sv_control(move |ev| r.0.lock().unwrap().push(ev.clone()));
    let addr = serve(&server).await;
    let c = dial(&addr).await;
    c.enable_svcb("ED21LD0/LLN0.msvcb01", false, true).await.unwrap();
    let ev = rec.next().await;
    assert!(!ev.unicast && ev.enabled && !ev.reserved);
    assert_eq!(ev.block.name, "msvcb01");
    assert!(read(&c, "ED21LD0/LLN0.msvcb01.SvEna", Fc::Ms).await.as_bool());
    c.close().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rec.is_empty(), "the end of the association disabled an MSVCB");
}

/// GetSVCB reads a block's configuration in one request, telling a USVCB from
/// an MSVCB by its functional constraint.
#[tokio::test]
async fn get_svcb_reads_the_configuration() {
    let m = ed21();
    let lln0 = m.device("ED21LD0").unwrap().node("LLN0").unwrap().clone();
    let (c, _s, _) = start(m, Options::new()).await;
    for name in ["msvcb01", "usvcb01"] {
        let sc = lln0.sv_controls.iter().find(|s| s.name == name).unwrap();
        let reference = format!("ED21LD0/LLN0.{name}");
        let unicast = name == "usvcb01";
        if unicast {
            c.reserve_usvcb(reference.as_str(), true).await.unwrap();
        }
        let cb = c.get_svcb(reference.as_str()).await.unwrap();
        assert_eq!((cb.unicast, cb.resv, cb.sv_ena), (unicast, unicast, false), "{name}");
        assert_eq!(cb.sv_id, sc.sv_id);
        assert_eq!(cb.conf_rev, sc.conf_rev);
        assert_eq!(cb.smp_rate, sc.smp_rate);
        assert_eq!(cb.smp_mod, sc.smp_mod);
        assert_eq!(cb.opt_flds, sc.opts);
        assert_eq!(cb.dst_address.addr, sc.dst_mac);
        assert_eq!(cb.dst_address.app_id, sc.app_id);
        assert_eq!(cb.dst_address.vid, sc.vlan_id);
        assert_eq!(cb.no_asdu, sc.no_asdu);
        if !sc.data_set.is_empty() {
            assert_eq!(cb.data_set, format!("ED21LD0/LLN0${}", sc.data_set));
        }
    }
    assert!(c.get_svcb("ED21LD0/LLN0.nosuch").await.is_err());
}
