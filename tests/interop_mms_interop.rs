//! Interoperability against the adapter images of otfabric/mms-interop:
//! libiec61850, iec61850bean, dscsystems/go-iec61850 and csp0924/iec61850-rust,
//! each packaged as one container per role over one shared fixture
//! (`testdata/mms-interop/`, copied from mms-interop v0.4.0).
//!
//! Both directions run against every stack:
//!
//! - this crate's client against `<stack>-ied-server` (directory, the
//!   fixture's values, a setting write, datasets, URCB and BRCB with GI, the
//!   three control models) and `<stack>-mms-server` (Identify, Status, name
//!   lists, every fixture type read, writes read back);
//! - `<stack>-ied-client`, `-ied-controller` and `-ied-reporter` against this
//!   crate's server, serving the same model.
//!
//! The tests need Docker and are skipped unless `MMS_INTEROP_STACKS` names
//! the stacks to run (`all`, or e.g. `libiec61850,dscsystems`);
//! `interop/mms-interop.sh` sets it. The images default to the digests
//! mms-interop v0.4.0 published, overridable with the variables the Go suites
//! use (`LIBIEC61850_IMAGE`, `IEC61850BEAN_IMAGE`, `DSCSYSTEMS_IMAGE`,
//! `IEC61850RUST_IMAGE`).

mod interop_common;

use interop_common::adapter::*;
use interop_common::*;
use serde_json::Value as Json;

/// The functional constraints a fixture value can sit under.
const FCS: [Fc; 5] = [Fc::St, Fc::Mx, Fc::Cf, Fc::Dc, Fc::Sp];

/// The fixture's runtime values, keyed by `InteropLD/...` reference.
fn fixture_values() -> Vec<(String, Json)> {
    let v = read_json(&fixture("iec61850/values.json"));
    v["values"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// The fixture model with its logical device named plainly `InteropLD`, as
/// the client adapters address it (they were written against go-iec61850,
/// which names devices by `inst` alone), and its report control blocks
/// unindexed, so the single instance is `urcb01` as the reporter adapter
/// expects rather than the `urcb0101` IEC 61850-6 gives an indexed block
/// (libiec61850's own server uses the latter).
fn fixture_model() -> model::Model {
    let icd = std::fs::read_to_string(fixture("iec61850/interop.icd")).unwrap();
    let icd = icd
        .replace(r#"<IED name="InteropIED""#, r#"<IED name="""#)
        .replace(r#"iedName="InteropIED""#, r#"iedName="""#)
        .replace("<ReportControl ", r#"<ReportControl indexed="false" "#);
    let scl = scl::parse(&icd).expect("fixture parses");
    scl::build_model(&scl, &scl::BuildOptions::new()).expect("fixture builds")
}

/// The functional constraint of a fixture attribute, from the model.
fn fc_of(m: &model::Model, reference: &str) -> Fc {
    let r = model::ObjectReference::new(reference);
    *FCS.iter()
        .find(|fc| m.attribute(&r, **fc).is_some())
        .unwrap_or_else(|| panic!("{reference} is not in the fixture model"))
}

/// A fixture value as the attribute's type wants it.
fn to_value(like: &Value, j: &Json) -> Value {
    match like.type_of() {
        Type::Boolean => Value::boolean(j.as_bool().unwrap()),
        Type::Integer => Value::Integer(j.as_i64().unwrap()),
        Type::Unsigned => Value::Unsigned(j.as_u64().unwrap()),
        Type::Float32 => Value::float32(j.as_f64().unwrap() as f32),
        Type::VisibleString => Value::visible_string(j.as_str().unwrap()),
        Type::MmsString => Value::mms_string(j.as_str().unwrap()),
        // A Dbpos, given as its integer: 2 is on, bits 1 0.
        Type::BitString => Value::bit_string_bits(&[(j.as_u64().unwrap() as u8 & 3) << 6], 2),
        t => panic!("no fixture conversion to {t}"),
    }
}

/// Whether a value read back matches the fixture's.
fn matches(v: &Value, j: &Json) -> bool {
    match v.type_of() {
        Type::Boolean => j.as_bool() == Some(v.as_bool()),
        Type::Float32 | Type::Float64 => j.as_f64().is_some_and(|f| (f - v.as_f64()).abs() < 1e-3),
        Type::VisibleString | Type::MmsString => j.as_str() == Some(v.text().as_str()),
        Type::BitString => j.as_u64() == Some(((v.bit(0) as u64) << 1) | v.bit(1) as u64),
        _ => j.as_i64() == Some(v.as_i64()),
    }
}

/// The peers' own limitations, and why: a step that hits one is reported
/// and passed over rather than failed. Each was checked against the peer
/// itself; the first two are on mms-interop's list (`fixtures/capabilities.json`).
fn known(stack: Stack, what: &str) -> Option<&'static str> {
    Some(match (stack.name, what) {
        ("libiec61850" | "iec61850bean", "InteropLD/GGIO1.DPS1.stVal" | "InteropLD/MMTR1.TotVAh.actVal") => {
            "the server does not apply this fixture value"
        }
        ("iec61850bean", "identify") => "the server cannot decode an Identify request and does not answer it",
        ("iec61850bean", "nvl-read") => "the server reads a dataset only when specificationWithResult is set",
        ("iec61850bean", "sbow") => "the server refuses SelectWithValue on SBOw",
        ("iec61850bean" | "iec61850-rust", "brcb") => {
            "the server accepts RptEna and GI on a BRCB and sends no report"
        }
        _ => return None,
    })
}

/// This crate's server with the fixture model and values, as the mms-interop
/// servers start.
async fn rust_server() -> (Server, u16) {
    let m = fixture_model();
    let values: Vec<_> = fixture_values().into_iter().map(|(k, j)| (fc_of(&m, &k), k, j)).collect();
    let server = Server::new(
        m,
        Options::new().with_identity(iec61850::server::Identity {
            vendor: "OTFabric".into(),
            model: "rs-iec61850-interop".into(),
            revision: "1.0".into(),
        }),
    );
    server.update(|tx| {
        for (fc, key, j) in values {
            let like = tx.get(key.as_str(), fc).cloned().unwrap_or_else(|| panic!("{key} has no value"));
            assert!(tx.set(key.as_str(), fc, to_value(&like, &j)), "{key}");
        }
    });
    let (_, port) = serve(&server).await;
    (server, port)
}

// ---------------------------------------------------------------------------
// This crate's client against the adapters' IED servers.
// ---------------------------------------------------------------------------

/// Directory, the fixture's values, a setting write read back, and the
/// dataset.
async fn client_ied_services(stack: Stack) {
    let srv = AdapterServer::start(stack, "ied-server", &[]).await;
    assert_eq!(srv.ready["fixture"], "iec61850-v3", "{}", srv.ready);
    let ld = format!("{}InteropLD", srv.ied_name());
    let c = dial(&srv.addr).await;

    match (c.mms().identify().await, known(stack, "identify")) {
        (Ok((vendor, model_name, rev)), _) => {
            assert!(!(vendor.is_empty() && model_name.is_empty() && rev.is_empty()), "Identify is empty");
        }
        (Err(iec61850::mms::Error::Timeout), Some(why)) => eprintln!("known: {} Identify: {why}", stack.name),
        (Err(e), _) => panic!("Identify: {e}"),
    }

    let lds = c.logical_devices().await.unwrap();
    assert!(lds.contains(&ld), "{ld} not in {lds:?}");
    let lns = c.logical_nodes(&ld).await.unwrap();
    for ln in ["LLN0", "GGIO1", "MMXU1", "MMTR1"] {
        assert!(lns.iter().any(|n| n == ln), "{ln} not in {lns:?}");
    }

    let m = fixture_model();
    let mut wrong = Vec::new();
    for (key, j) in fixture_values() {
        let fc = fc_of(&m, &key);
        let r = key.replacen("InteropLD", &ld, 1);
        let like = m.attribute(&model::ObjectReference::new(key.as_str()), fc).and_then(|a| a.value.clone());
        match c.read(r.as_str(), fc).await {
            Ok(v) if matches(&v, &j) => {}
            Ok(v) if known(stack, &key).is_some() && like.as_ref().is_some_and(|l| l.type_of() == v.type_of()) => {
                eprintln!("known: {} {key}: {} (reads {v:?})", stack.name, known(stack, &key).unwrap());
            }
            Ok(v) => wrong.push(format!("{r}[{fc}] = {v:?}, fixture {j}")),
            Err(e) => wrong.push(format!("{r}[{fc}]: {e}")),
        }
    }
    assert!(wrong.is_empty(), "fixture values:\n  {}", wrong.join("\n  "));

    let set = format!("{ld}/GGIO1.SetInt1.setVal");
    c.write(set.as_str(), Fc::Sp, Value::int32(42)).await.expect("write the setting");
    assert_eq!(c.read(set.as_str(), Fc::Sp).await.unwrap().as_i64(), 42);

    // The dataset's values, then its directory.
    let vals = match (c.mms().read_named_variable_list(&ld, "LLN0$dsInterop").await, known(stack, "nvl-read")) {
        (Ok(v), _) => v,
        (Err(e), Some(why)) => {
            eprintln!("known: {} dsInterop read: {why} ({e})", stack.name);
            c.mms().read_named_variable_list_with_spec(&ld, "LLN0$dsInterop").await.expect("read dsInterop").1
        }
        (Err(e), None) => panic!("read dsInterop: {e}"),
    };
    assert_eq!(vals.len(), 2, "{vals:?}");
    assert!(matches(&vals[0], &serde_json::json!(false)), "SPS1.stVal in dsInterop: {vals:?}");
    match (c.mms().get_named_variable_list_attributes(&ld, "LLN0$dsInterop").await, known(stack, "nvl-attributes")) {
        (Ok(refs), _) => {
            let items: Vec<_> = refs.iter().map(|r| r.item.as_str()).collect();
            assert_eq!(items, ["GGIO1$ST$SPS1$stVal", "LLN0$ST$Mod$stVal"]);
        }
        (Err(e), Some(why)) => eprintln!("known: {} dsInterop directory: {why} ({e})", stack.name),
        (Err(e), None) => panic!("dsInterop directory: {e}"),
    }
    c.close().await.unwrap();
}

/// The URCB and the BRCB: enabled, a general interrogation reported with
/// both members, disabled.
async fn client_reports(stack: Stack) {
    let srv = AdapterServer::start(stack, "ied-server", &[]).await;
    let ld = format!("{}InteropLD", srv.ied_name());
    let c = dial(&srv.addr).await;
    for (class, name, rpt_id) in [
        (AcsiClass::Urcb, "urcb01", "interop_urcb01"),
        (AcsiClass::Brcb, "brcb01", "interop_brcb01"),
    ] {
        let rcbs = c.browse(&ld, &[class]).await.unwrap();
        // urcb01, or urcb0101 where the block is indexed.
        let entry = rcbs
            .iter()
            .find(|e| e.reference.as_str().rsplit('.').next().is_some_and(|n| n.starts_with(name)))
            .unwrap_or_else(|| panic!("no {name} in {rcbs:?}"));
        let mut rcb = c.get_rcb(entry.reference.clone()).await.unwrap();
        assert_eq!(rcb.rpt_id, rpt_id);
        rcb.trg_ops = TrgOps::GI | TrgOps::DATA_CHANGE;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sub = c
            .enable_reporting(&rcb, move |r| {
                let _ = tx.send(r.clone());
            })
            .await
            .unwrap_or_else(|e| panic!("enable {name}: {e}"));
        c.trigger_gi(&rcb).await.unwrap();
        let gi = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let r = rx.recv().await.expect("the subscription is open");
                if r.entries.iter().any(|e| e.reason.0 & model::ReasonCode::GI.0 != 0) {
                    return r;
                }
            }
        })
        .await;
        let r = match (gi, known(stack, if rcb.buffered { "brcb" } else { "urcb" })) {
            (Ok(r), _) => r,
            (Err(_), Some(why)) => {
                eprintln!("known: {} {name}: {why}", stack.name);
                sub.disable().await.unwrap();
                continue;
            }
            (Err(_), None) => panic!("no GI report from {name}"),
        };
        assert_eq!(r.rpt_id, rpt_id);
        assert_eq!(r.entries.len(), 2, "a GI reports every member: {r:?}");
        assert!(!r.entries[0].value.as_bool(), "SPS1.stVal: {r:?}");
        sub.disable().await.unwrap();
    }
    c.close().await.unwrap();
}

/// SPCSO1 direct, SPCSO2 select-before-operate, SPCSO3 SBO with enhanced
/// security, each followed by its status.
async fn client_controls(stack: Stack) {
    let srv = AdapterServer::start(stack, "ied-server", &[]).await;
    let ld = format!("{}InteropLD", srv.ied_name());
    let c = dial(&srv.addr).await;
    let opts = ControlOptions::default().with_termination_timeout(Duration::from_secs(3));
    for (obj, ctl_model) in [
        ("SPCSO1", CtlModel::DirectNormal),
        ("SPCSO2", CtlModel::SboNormal),
        ("SPCSO3", CtlModel::SboEnhanced),
    ] {
        let r = format!("{ld}/GGIO1.{obj}");
        let co = c.control_for(r.as_str()).await.unwrap();
        assert_eq!(co.model(), ctl_model, "{obj}");
        match (co.operate(Value::boolean(true), &opts).await, known(stack, "sbow")) {
            (Ok(()), _) => {}
            (Err(e), Some(why)) if ctl_model == CtlModel::SboEnhanced => {
                eprintln!("known: {} {obj}: {why} ({e})", stack.name);
                continue;
            }
            (Err(e), _) => panic!("{obj}: {e}"),
        }
        let st = c.read(format!("{r}.stVal"), Fc::St).await.unwrap();
        assert!(st.as_bool(), "{obj}.stVal did not follow the operate");
    }
    c.close().await.unwrap();
}

// ---------------------------------------------------------------------------
// This crate's MMS client against the adapters' generic MMS servers.
// ---------------------------------------------------------------------------

/// Identify, Status, the name lists, every variable of the fixture read, and
/// the writable scalars written and read back.
async fn client_mms_services(stack: Stack) {
    let srv = AdapterServer::start(stack, "mms-server", &["--fixture", "/fixtures/mms/interop.json"]).await;
    let fx = read_json(&fixture("mms/interop.json"));
    assert_eq!(srv.ready["fixture"], fx["revision"], "{}", srv.ready);
    let c = dial(&srv.addr).await;
    let mc = c.mms();

    let (vendor, _, _) = mc.identify().await.unwrap();
    assert_eq!(vendor, fx["identity"]["vendor"].as_str().unwrap());
    let st = c.server_status(false).await.unwrap();
    assert_eq!((st.logical, st.physical), (1, 1), "the fixture's status");

    let domains = mc.get_name_list(ObjectClass::Domain, "").await.unwrap();
    assert!(domains.iter().any(|d| d == "interop"), "{domains:?}");
    let names = mc.get_name_list(ObjectClass::NamedVariable, "interop").await.unwrap();
    let vars = fx["domains"]["interop"]["variables"].as_object().unwrap();
    for name in vars.keys() {
        assert!(names.contains(name), "{name} not in {names:?}");
    }

    let mut wrong = Vec::new();
    for (name, spec) in vars {
        let v = mc.read("interop", &[name]).await.unwrap().remove(0);
        if let Err(e) = check_mms(&v, spec) {
            wrong.push(format!("{name}: {e} (read {v:?})"));
        }
    }
    assert!(wrong.is_empty(), "fixture values:\n  {}", wrong.join("\n  "));

    let writes = [
        ("boolean", Value::boolean(false)),
        ("integer", Value::int32(-7)),
        ("unsigned", Value::uint32(7)),
        ("float32", Value::float32(-1.25)),
        ("visible-string", Value::visible_string("rs-iec61850")),
    ];
    for (name, v) in writes {
        let res = mc.write("interop", &[name], std::slice::from_ref(&v)).await.unwrap();
        assert!(res[0].is_ok(), "write {name}: {:?}", res[0]);
        let back = mc.read("interop", &[name]).await.unwrap().remove(0);
        assert_eq!(format!("{back:?}"), format!("{v:?}"), "{name} read back");
    }

    let ts = mc.get_variable_access_attributes("interop", "structure").await.unwrap();
    assert_eq!(ts.kind, Some(Type::Structure));
    c.close().await.unwrap();
}

/// Compares a value read from the MMS fixture server with its declaration.
fn check_mms(v: &Value, spec: &Json) -> Result<(), String> {
    let want = &spec["value"];
    let ok = match spec["type"].as_str().unwrap() {
        "boolean" => v.type_of() == Type::Boolean && want.as_bool() == Some(v.as_bool()),
        "integer" => v.type_of() == Type::Integer && want.as_i64() == Some(v.as_i64()),
        "unsigned" => {
            matches!(v.type_of(), Type::Unsigned | Type::Integer) && want.as_u64() == Some(v.as_u64())
        }
        "float32" => v.type_of() == Type::Float32 && want.as_f64() == Some(v.as_f64()),
        "visible-string" => v.type_of() == Type::VisibleString && want.as_str() == Some(v.text().as_str()),
        "octet-string" => {
            let hex: String = v.bytes().iter().map(|b| format!("{b:02x}")).collect();
            v.type_of() == Type::OctetString && want.as_str().is_some_and(|w| w.eq_ignore_ascii_case(&hex))
        }
        "bit-string" => {
            let bits: String = (0..v.bit_len()).map(|i| if v.bit(i) { '1' } else { '0' }).collect();
            v.type_of() == Type::BitString && want.as_str() == Some(bits.as_str())
        }
        "utc-time" => {
            let t = v.time().ok_or("not a time")?;
            let secs = t.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
            // 2024-01-01T00:00:00Z.
            v.type_of() == Type::UtcTime && want.as_str() == Some("2024-01-01T00:00:00.000Z") && secs == 1_704_067_200
        }
        "array" | "structure" => {
            let parts = want.as_array().unwrap();
            let kind = if spec["type"] == "array" { Type::Array } else { Type::Structure };
            v.type_of() == kind
                && v.len() == parts.len()
                && v.children().iter().zip(parts).all(|(c, p)| match p {
                    Json::Object(_) => check_mms(c, p).is_ok(),
                    _ => p.as_i64() == Some(c.as_i64()),
                })
        }
        t => return Err(format!("no check for {t}")),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("fixture {spec}"))
    }
}

// ---------------------------------------------------------------------------
// The adapters' clients against this crate's server.
// ---------------------------------------------------------------------------

/// The fixed `ied-client` sequence: directories, reads, a write, the dataset.
async fn server_ied_client(stack: Stack) {
    let (server, port) = rust_server().await;
    let run = AdapterClient::run(stack, "ied-client", port, &[]).await;
    if let Some(u) = run.unsupported() {
        eprintln!("skipped: {} reports {u}", stack.name);
        return;
    }
    let names = &run.ok("get-server-directory", None)["names"];
    assert!(names.as_array().unwrap().iter().any(|n| n == "InteropLD"), "{run}");
    let lns = &run.ok("get-ld-directory", Some("InteropLD"))["names"];
    for ln in ["LLN0", "GGIO1", "MMXU1", "MMTR1"] {
        assert!(lns.as_array().unwrap().iter().any(|n| n == ln), "{ln}: {run}");
    }
    let dos = &run.ok("get-ln-directory", Some("InteropLD/GGIO1"))["names"];
    for d in ["SPS1", "SPCSO1"] {
        assert!(dos.as_array().unwrap().iter().any(|n| n == d), "{d}: {run}");
    }

    let values: std::collections::HashMap<_, _> = fixture_values().into_iter().collect();
    for (r, fc) in [
        ("InteropLD/GGIO1.SPS1.stVal", "ST"),
        ("InteropLD/MMXU1.TotW.mag.f", "MX"),
        ("InteropLD/LLN0.Mod.ctlModel", "CF"),
        ("InteropLD/LLN0.Mod.d", "DC"),
    ] {
        let got = &run.ok("read", Some(&format!("{r}[{fc}]")))["value"];
        let want = &values[r];
        let same = match (got.as_f64(), want.as_f64()) {
            (Some(a), Some(b)) => (a - b).abs() < 1e-3,
            _ => got == want,
        };
        assert!(same, "{r}: read {got}, fixture {want}\n{run}");
    }

    // The adapter writes Mod.stVal under ST. IEC 61850-7-2 makes status
    // read-only, so this server refuses it (as iec61850-rust does), and the
    // dataset read after it still holds the fixture's value.
    let w = run.op("write", Some("InteropLD/LLN0.Mod.stVal[ST]"));
    assert_eq!(w["ok"], false, "a write to ST was accepted: {run}");
    assert_eq!(server.read("InteropLD/LLN0.Mod.stVal", Fc::St).unwrap().as_i64(), 1);
    let ds = &run.ok("read-dataset", Some("InteropLD/LLN0$dsInterop"))["values"];
    assert_eq!(ds, &serde_json::json!([false, 1]), "{run}");

    run.ok("conclude", None);
    assert_eq!(run.code, Some(3), "exit 3 for the refused write, and only that: {run}");
}

/// `ied-controller` on each control model, then the status it reads back.
async fn server_controller(stack: Stack) {
    let (server, port) = rust_server().await;
    for (obj, ctl_model) in [("SPCSO1", 1), ("SPCSO2", 2), ("SPCSO3", 4)] {
        let run = AdapterClient::run(stack, "ied-controller", port, &["--do", obj, "--ctlval", "1"]).await;
        if let Some(u) = run.unsupported() {
            eprintln!("skipped: {} {obj} reports {u}", stack.name);
            continue;
        }
        let r = format!("InteropLD/GGIO1.{obj}");
        assert_eq!(run.ok("read-ctlmodel", None)["value"], ctl_model, "{run}");
        match ctl_model {
            2 => drop(run.ok("select", Some(&r))),
            4 => drop(run.ok("select-with-value", Some(&r))),
            _ => {}
        }
        assert_eq!(run.ok("operate", Some(&r))["ctlval"], true, "{run}");
        assert_eq!(run.ok("read-stval", None)["value"], true, "{run}");
        run.ok("conclude", None);
        assert!(server.read(format!("{r}.stVal"), Fc::St).unwrap().as_bool(), "{obj}.stVal: {run}");
    }
}

/// `ied-reporter` on urcb01: the block read and enabled, a data change
/// reported, the block disabled.
async fn server_reporter(stack: Stack) {
    let (server, port) = rust_server().await;
    let mut client = AdapterClient::start(stack, "ied-reporter", port, &["--sps1-initial", "0"]);
    // The adapter triggers the change with a write under ST, which this server
    // refuses as IEC 61850-7-2 requires; the process side changes the value
    // instead, as a device would.
    let enabled = client.wait_for("enable-rcb", Duration::from_secs(60)).await;
    if enabled.as_ref().is_some_and(|e| e["ok"] == true) {
        server.update(|tx| {
            tx.set_bool("InteropLD/GGIO1.SPS1.stVal", true);
            tx.set_timestamp_now("InteropLD/GGIO1.SPS1.t", Fc::St);
        });
    }
    let run = client.finish(Duration::from_secs(60)).await;
    if let Some(u) = run.unsupported() {
        eprintln!("skipped: {} reports {u}", stack.name);
        return;
    }
    let rcb = run.ok("get-rcb", None);
    assert_eq!(rcb["rptID"], "interop_urcb01", "{run}");
    run.ok("enable-rcb", None);
    let r = run.ok("receive-report", None);
    assert_eq!(r["rptID"], "interop_urcb01", "{run}");
    assert_eq!(r["inclusion"][0], true, "SPS1.stVal is included: {run}");
    assert_eq!(r["values"][0], true, "{run}");
    assert!(r["reasons"].as_array().unwrap().iter().any(|x| x == "data-change"), "{run}");
    run.ok("disable-rcb", None);
    run.ok("conclude", None);
}

// ---------------------------------------------------------------------------
// One module per stack, so `cargo test dscsystems::` selects one.
// ---------------------------------------------------------------------------

macro_rules! stack_tests {
    ($module:ident, $stack:expr, [$($test:ident),* $(,)?]) => {
        mod $module {
            use super::*;
            $(
                #[tokio::test]
                async fn $test() {
                    if $stack.selected() {
                        super::$test($stack).await;
                    }
                }
            )*
        }
    };
}

stack_tests!(libiec61850, LIBIEC61850, [
    client_ied_services, client_reports, client_controls, client_mms_services,
    server_ied_client, server_controller, server_reporter,
]);
// iec61850bean is used at the IEC 61850 layer only: it has no MMS server.
stack_tests!(iec61850bean, IEC61850BEAN, [
    client_ied_services, client_reports, client_controls,
    server_ied_client, server_controller, server_reporter,
]);
stack_tests!(dscsystems, DSCSYSTEMS, [
    client_ied_services, client_reports, client_controls, client_mms_services,
    server_ied_client, server_controller, server_reporter,
]);
stack_tests!(iec61850_rust, IEC61850_RUST, [
    client_ied_services, client_reports, client_controls, client_mms_services,
    server_ied_client, server_controller, server_reporter,
]);
