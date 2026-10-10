//! Interoperability with libiec61850, both ways: this crate's client against
//! its example servers, its example clients against this crate's server, and
//! its R-GOOSE/R-SV and TLS against this crate's.
//!
//! Every test is skipped unless the environment names the C program it runs,
//! so a checkout without a C toolchain stays green; `interop/libiec.sh` builds
//! libiec61850 and supplies the variables (the same ones the Go library's
//! interop suite uses).

mod interop_common;

use interop_common::*;

// ---------------------------------------------------------------------------
// This crate's client against libiec61850's servers.
// ---------------------------------------------------------------------------

/// The ACSI and MMS client against `server_example_basic_io`.
#[tokio::test]
async fn client_against_libiec_basic_io() {
    let Some(addr) = need("IEC61850_TEST_SERVER") else { return };
    let c = dial(&addr).await;
    let mc = c.mms();

    let (vendor, model_name, rev) = mc.identify().await.unwrap();
    assert!(!(vendor.is_empty() && model_name.is_empty() && rev.is_empty()), "Identify is empty");

    let lds = c.logical_devices().await.unwrap();
    assert!(!lds.is_empty());
    let ld = lds[0].clone();
    assert!(!c.logical_nodes(&ld).await.unwrap().is_empty());
    let vars = mc.get_name_list(ObjectClass::NamedVariable, &ld).await.unwrap();
    assert!(vars.iter().any(|v| v.contains('$')), "no variables in {ld}");

    let v = c.read(format!("{ld}/GGIO1.SPCSO1.ctlModel"), Fc::Cf).await.unwrap();
    assert_eq!(v.type_of(), Type::Integer);
    let ts = mc.get_variable_access_attributes(&ld, "GGIO1$MX$AnIn1").await.unwrap();
    assert_eq!(ts.kind, Some(Type::Structure));

    let m = c.retrieve_model().await.unwrap();
    let r = model::ObjectReference::new(format!("{ld}/GGIO1.AnIn1.mag.f"));
    assert!(m.attribute(&r, Fc::Mx).is_some(), "AnIn1.mag.f missing from the retrieved model");

    let ds = c.read_data_set(format!("{ld}/LLN0.Measurements")).await.unwrap();
    assert!(!ds.members.is_empty());
    let vals = mc.read_named_variable_list(&ld, "LLN0$Measurements").await.unwrap();
    let refs = mc.get_named_variable_list_attributes(&ld, "LLN0$Measurements").await.unwrap();
    assert_eq!(vals.len(), refs.len());

    // Reporting: enable an unbuffered block and receive the GI report.
    let rcbs = c.browse(&ld, &[AcsiClass::Urcb]).await.unwrap();
    assert!(!rcbs.is_empty(), "no URCB");
    let mut rcb = c.get_rcb(rcbs[0].reference.clone()).await.unwrap();
    rcb.trg_ops = TrgOps::GI | TrgOps::DATA_CHANGE;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sub = c.enable_reporting(&rcb, move |r| {
        let _ = tx.send(r.entries.len());
    })
    .await
    .unwrap();
    c.trigger_gi(&rcb).await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("a report").unwrap();
    assert!(n > 0, "an empty GI report");
    sub.disable().await.unwrap();
    c.close().await.unwrap();
}

/// The control services against `server_example_control`: SPCSO3 direct
/// with enhanced security, SPCSO4 SBO with enhanced security, SPCSO9
/// direct-enhanced whose execution fails.
#[tokio::test]
async fn client_controls_against_libiec() {
    let Some(addr) = need("IEC61850_TEST_CONTROL_SERVER") else { return };
    let c = dial(&addr).await;
    let ld = c.logical_devices().await.unwrap().remove(0);
    let obj = |n: &str| format!("{ld}/GGIO1.{n}");
    let opts = ControlOptions::default().with_termination_timeout(Duration::from_secs(3));

    let co = c.control_for(obj("SPCSO3")).await.unwrap();
    co.operate(Value::boolean(true), &opts).await.expect("direct-enhanced terminates");
    let co = c.control_for(obj("SPCSO4")).await.unwrap();
    co.operate(Value::boolean(true), &opts).await.expect("SBO-enhanced terminates");

    // Operating without the select is refused, with the device's cause.
    let err = co
        .operate(Value::boolean(true), &opts.clone().with_model(CtlModel::DirectEnhanced))
        .await
        .unwrap_err();
    let iec61850::client::Error::Control(ce) = err else { panic!("{err}") };
    assert_eq!(ce.stage, Stage::Operate, "{ce}");
    assert_ne!(ce.add_cause, AddCause::UNKNOWN, "the LastApplError was not received");

    // A failed execution ends in a negative CommandTermination.
    let co = c.control_for(obj("SPCSO9")).await.unwrap();
    let err = co.operate(Value::boolean(true), &opts).await.unwrap_err();
    let iec61850::client::Error::Control(ce) = err else { panic!("{err}") };
    assert_eq!(ce.stage, Stage::Termination, "{ce}");
    c.close().await.unwrap();
}

/// The log queries against `server_example_logging`, which writes one entry
/// at startup: INT32 123 under its own (misspelt) data reference, then a
/// timestamp, each with a reason code.
#[tokio::test]
async fn client_logs_against_libiec() {
    let Some(addr) = need("IEC61850_TEST_LOG_SERVER") else { return };
    let c = dial(&addr).await;
    let ld = c.logical_devices().await.unwrap().remove(0);
    let log_ref = format!("{ld}/LLN0.EventLog");

    let names = c.logical_node_directory(format!("{ld}/LLN0"), AcsiClass::Log).await.unwrap();
    assert!(names.iter().any(|n| n == "EventLog"), "{names:?}");
    let entries = c.browse(&ld, &[AcsiClass::Log, AcsiClass::Lcb]).await.unwrap();
    assert!(entries.iter().any(|e| e.reference.as_str() == log_ref), "{entries:?}");
    assert!(entries.iter().any(|e| e.reference.as_str() == format!("{ld}/LLN0.LG.EventLog")), "{entries:?}");

    let now = SystemTime::now();
    let all = c
        .query_log_by_time(log_ref.as_str(), now - Duration::from_secs(3600), now + Duration::from_secs(60))
        .await
        .unwrap();
    assert!(!all.is_empty(), "the example writes an entry at startup");
    let first = &all[0];
    assert_eq!(first.entry_id.len(), 8);
    let age = now.duration_since(first.occurrence_time.unwrap()).unwrap_or_default();
    assert!(age < Duration::from_secs(3600), "occurrence time {:?} is not recent", first.occurrence_time);
    assert!(first.variables.iter().any(|v| v.tag == "simpleIOGenerioIO/GPIO1$ST$SPCSO1$stVal"
        && v.value.as_ref().is_some_and(|x| x.as_i64() == 123)), "{:?}", first.variables);
    assert!(first.variables.iter().any(|v| v.tag == "ReasonCode"));

    let lcb = c.mms().read(&ld, &["LLN0$LG$EventLog"]).await.unwrap().remove(0);
    assert_eq!(lcb.len(), 9, "LCB components");
    let parts = lcb.children();
    assert_eq!(parts[1].text(), format!("{ld}/LLN0$EventLog"));
    assert_eq!(parts[5].bytes(), first.entry_id.as_slice(), "OldEnt");
    let after = c
        .query_log_after(log_ref.as_str(), parts[3].time().unwrap(), parts[5].bytes())
        .await
        .unwrap();
    assert!(after.iter().all(|e| e.entry_id != first.entry_id), "QueryLogAfter returned its start");
    c.close().await.unwrap();
}

/// Status, SetFile, GetFile, DeleteFile, abort against
/// `server_example_files`.
#[tokio::test]
async fn client_files_against_libiec() {
    let Some(bin) = need("IEC61850_C_FILE_SERVER") else { return };
    let Some(src) = need("IEC61850_C_FILE_SERVER_STORE") else { return };
    let work = temp_dir("files");
    let store = work.join("vmd-filestore");
    copy_dir(Path::new(&src), &store);
    let port = free_port();
    let srv = CServer::start(&bin, &[&port.to_string()], &work);
    let addr = format!("127.0.0.1:{port}");
    let c = dial(&addr).await;

    let st = c.server_status(false).await.unwrap();
    eprintln!("status: logical {} physical {}", st.logical, st.physical);
    let data = b"rs-iec61850 SetFile ".repeat(3000);
    c.set_file("upload.bin", data.clone()).await.expect("SetFile");
    assert_eq!(std::fs::read(store.join("upload.bin")).unwrap(), data);
    assert_eq!(c.read_file("upload.bin").await.unwrap(), data);
    c.delete_file("upload.bin").await.expect("DeleteFile");
    assert!(!store.join("upload.bin").exists());
    let err = c.delete_file("IEDSERVER.BIN").await.unwrap_err();
    assert!(err.as_service_error().is_some(), "the server's refusal: {err}");

    let c2 = dial(&addr).await;
    c2.abort().await.unwrap();
    c.server_status(true).await.expect("serving after another association's abort");
    c.close().await.unwrap();
    srv.stop().await;
}

/// MMS fileRename against libiec61850's file server built with the service.
#[tokio::test]
async fn client_rename_against_libiec() {
    let Some(bin) = need("IEC61850_C_RENAME_FILE_SERVER") else { return };
    let Some(src) = need("IEC61850_C_FILE_SERVER_STORE") else { return };
    let work = temp_dir("rename");
    let store = work.join("vmd-filestore");
    copy_dir(Path::new(&src), &store);
    let port = free_port();
    let srv = CServer::start(&bin, &[&port.to_string()], &work);
    let c = dial(&format!("127.0.0.1:{port}")).await;
    assert!(c.mms().negotiated().services.has(iec61850::mms::service::FILE_RENAME));
    std::fs::write(store.join("before.txt"), b"rs-iec61850 rename").unwrap();
    c.rename_file("before.txt", "after.txt").await.expect("fileRename");
    assert_eq!(std::fs::read(store.join("after.txt")).unwrap(), b"rs-iec61850 rename");
    assert!(!store.join("before.txt").exists());
    let err = c.rename_file("missing.txt", "other.txt").await.unwrap_err();
    assert_eq!(err.as_service_error().map(|e| e.class.0), Some(11), "{err}");
    c.close().await.unwrap();
    let out = srv.stop().await;
    assert!(out.contains("local-file: before.txt other-file: after.txt"), "{out}");
}

// ---------------------------------------------------------------------------
// libiec61850's clients against this crate's server.
// ---------------------------------------------------------------------------

/// `client_example1`: connect, read, read a dataset, enable reporting and
/// receive reports.
#[tokio::test]
async fn libiec_client_example1() {
    let Some(bin) = need("IEC61850_C_CLIENT") else { return };
    let s = Server::new(load("simpleIO_direct_control.cid"), Options::new());
    let (host, port) = serve(&s).await;
    // Change a status point so a data-change report follows the GI one.
    let toggler = {
        let s = s.clone();
        tokio::spawn(async move {
            let mut on = false;
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                on = !on;
                s.update(|tx| {
                    tx.set_bool("simpleIOGenericIO/GGIO1.SPCSO1.stVal", on);
                });
            }
        })
    };
    // The example waits a minute for reports; a few seconds is enough.
    let (out, _) = run(&bin, &[&host, &port.to_string()], None, Duration::from_secs(6)).await;
    toggler.abort();
    eprintln!("{out}");
    assert!(out.contains("Connected"), "{out}");
    assert!(out.contains("read float value"), "{out}");
    assert!(!out.contains("failed to read dataset"), "{out}");
    assert!(out.contains("received report"), "{out}");
}

/// The part of the logging example's model the C log client uses.
fn c_log_model() -> model::Model {
    const LD: &str = "TestIEDGenericIO";
    let spc = |name: &str| model::DataObject {
        name: name.into(),
        attributes: vec![model::DataAttribute {
            name: "stVal".into(),
            fc: Fc::St,
            kind: Some(Type::Boolean),
            value: Some(Value::boolean(false)),
            trg_ops: TrgOps::DATA_CHANGE,
            ..Default::default()
        }],
        ..Default::default()
    };
    model::Model {
        name: "TestIED".into(),
        devices: vec![model::LogicalDevice {
            name: LD.into(),
            inst: "GenericIO".into(),
            nodes: vec![
                model::LogicalNode {
                    name: "LLN0".into(),
                    class: "LLN0".into(),
                    logs: vec!["EventLog".into()],
                    data_sets: vec![model::DataSet {
                        name: "Events".into(),
                        entries: vec![
                            model::Fcda::new(format!("{LD}/GGIO1.SPCSO1.stVal"), Fc::St),
                            model::Fcda::new(format!("{LD}/GGIO1.SPCSO2.stVal"), Fc::St),
                        ],
                        ..Default::default()
                    }],
                    log_controls: vec![model::LogControl {
                        name: "EventLog".into(),
                        data_set: "Events".into(),
                        log_name: "EventLog".into(),
                        trg_ops: TrgOps::DATA_CHANGE,
                        reason_code: true,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                model::LogicalNode {
                    name: "GGIO1".into(),
                    class: "GGIO".into(),
                    objects: vec![spc("SPCSO1"), spc("SPCSO2")],
                    ..Default::default()
                },
            ],
        }],
        ..Default::default()
    }
}

/// `client_example_log`: list the logs, enable the LCB, read it and query
/// the log after its oldest entry.
#[tokio::test]
async fn libiec_log_client() {
    let Some(bin) = need("IEC61850_C_LOG_CLIENT") else { return };
    let s = Server::new(c_log_model(), Options::new());
    let (host, port) = serve(&s).await;
    let toggler = {
        let s = s.clone();
        tokio::spawn(async move {
            let mut on = false;
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                on = !on;
                s.update(|tx| {
                    tx.set_bool("TestIEDGenericIO/GGIO1.SPCSO1.stVal", on);
                });
            }
        })
    };
    let (out, ok) = run(&bin, &[&host, &port.to_string()], None, Duration::from_secs(10)).await;
    toggler.abort();
    eprintln!("{out}");
    assert!(ok, "the C log client failed");
    assert!(out.lines().any(|l| l.trim() == "EventLog"), "EventLog not listed");
    assert!(out.contains("Enabled log."));
    assert!(!out.contains("Read LCB failed"));
    let n: usize = out
        .split("Received ")
        .nth(1)
        .and_then(|s| s.split(' ').next())
        .and_then(|n| n.parse().ok())
        .expect("the log query result");
    assert!(n >= 2, "{n} entries");
    assert!(out.contains("variable-tag: TestIEDGenericIO/GGIO1$ST$SPCSO1$stVal"));
    assert!(out.contains("variable-tag: ReasonCode"));
}

/// `mms_utility` reads the Edition 2 and 2.1 classes of the fixture.
#[tokio::test]
async fn libiec_mms_utility_ed2_classes() {
    let Some(bin) = need("IEC61850_C_MMS_UTILITY") else { return };
    let s = Server::new(load("ed21_diverse.cid"), Options::new());
    let (host, port) = serve(&s).await;
    let port = port.to_string();
    let util = |args: Vec<&'static str>| {
        let (bin, host, port) = (bin.clone(), host.clone(), port.clone());
        async move {
            let mut a = vec!["-h", host.as_str(), "-p", port.as_str()];
            a.extend(args);
            let (out, ok) = run(&bin, &a, None, Duration::from_secs(5)).await;
            assert!(ok, "mms_utility {a:?}:\n{out}");
            out
        }
    };
    let dir = util(vec!["-t", "ED21LD0"]).await;
    for name in [
        "GAPC1$ST$Hst$hstVal",
        "GAPC1$CF$Hst$hstRangeC",
        "GAPC1$MX$ColChg$mxVal",
        "GAPC1$CO$ColChg$Oper$ctlVal",
        "GAPC1$SP$InRef1$setTstRef",
        "GAPC1$SP$StrTm$setTm",
        "GAPC1$SP$Cur$cur",
        "GAPC1$SP$Txt$setVal",
        "GAPC1$SP$Crv$crvPts",
        "LTRK1$SR$SpcTrk$respAddCause",
        "LTRK1$SR$GocbTrk$dstAddress$APPID",
    ] {
        assert!(dir.contains(name), "the domain directory lacks {name}");
    }
    for (var, want) in [
        ("GAPC1$SP$Cur$cur", "EUR"),
        ("GAPC1$SP$InRef1$setSrcRef", "ED21LD0/GGIO1.Ind1"),
        ("GAPC1$SP$Crv$numPts", "2"),
    ] {
        let out = util(vec!["-a", "ED21LD0", "-r", var]).await;
        assert!(out.contains(want), "read {var}: want {want} in\n{out}");
    }
    for var in ["LTRK1$SR$GocbTrk", "GAPC1$CF$Hst$hstRangeC", "GAPC1$ST$Hst$hstVal"] {
        let out = util(vec!["-a", "ED21LD0", "-r", var]).await.to_lowercase();
        assert!(!out.contains("error") && !out.contains("failed"), "read {var}:\n{out}");
    }
}

/// libiec61850's client through `mms_peer`: password authentication, Status,
/// SetFile, fileRename, the directory, DeleteFile, release and abort.
#[tokio::test]
async fn libiec_mms_peer_services() {
    let Some(bin) = need("IEC61850_C_MMS_PEER") else { return };
    let store = temp_dir("peer-store");
    let s = Server::new(
        load("simpleIO_direct_control.cid"),
        Options::new().with_file_store(&store).with_password("s3cret"),
    );
    let (tx, mut closed) = tokio::sync::mpsc::unbounded_channel();
    s.on_connection(move |ev| {
        if ev.state == ConnectionState::Closed {
            let _ = tx.send(());
        }
    });
    let (host, port) = serve(&s).await;
    let port = port.to_string();
    // The C client serves the file SetFile sends from ./vmd-filestore.
    let work = temp_dir("peer-work");
    std::fs::create_dir_all(work.join("vmd-filestore")).unwrap();
    let data = b"libiec61850 SetFile ".repeat(3000);
    std::fs::write(work.join("vmd-filestore/upload.src"), &data).unwrap();
    let peer = |args: &[&str]| {
        let mut a = vec![host.as_str(), port.as_str()];
        a.extend_from_slice(args);
        let a: Vec<String> = a.iter().map(|s| s.to_string()).collect();
        let (bin, work) = (bin.clone(), work.clone());
        async move {
            let a: Vec<&str> = a.iter().map(String::as_str).collect();
            run(&bin, &a, Some(&work), Duration::from_secs(20)).await
        }
    };

    let (out, ok) = peer(&[
        "-p", "s3cret", "status", "setfile", "upload.src", "upload.bin", "rename", "upload.bin", "renamed.bin",
        "dir", "deletefile", "renamed.bin", "release",
    ])
    .await;
    eprintln!("{out}");
    assert!(ok, "mms_peer failed");
    for want in [
        "connect err=0",
        "status logical=0 physical=0 err=0",
        "setfile err=0",
        "rename err=0",
        "file renamed.bin 60000",
        "deletefile err=0",
        "release err=0",
    ] {
        assert!(out.contains(want), "mms_peer output lacks {want:?}");
    }
    assert!(!store.join("upload.bin").exists() && !store.join("renamed.bin").exists());

    let (out, ok) = peer(&["-p", "guess", "status"]).await;
    assert!(!ok && !out.contains("connect err=0"), "wrong password accepted:\n{out}");

    while closed.try_recv().is_ok() {}
    let (out, ok) = peer(&["-p", "s3cret", "abort"]).await;
    assert!(ok, "abort: {out}");
    tokio::time::timeout(Duration::from_secs(5), closed.recv())
        .await
        .expect("the server did not end the aborted association");
}

/// libiec61850's ClientSVControlBlock against the sampled-value control
/// blocks: telling the USVCB from the MSVCB, reservation, exclusivity, and
/// release when the C client leaves.
#[tokio::test]
async fn libiec_mms_peer_svcb() {
    let Some(bin) = need("IEC61850_C_MMS_PEER") else { return };
    let s = Server::new(load("ed21_diverse.cid"), Options::new());
    let events: Arc<Mutex<Vec<SvControlEvent>>> = Arc::default();
    let e = events.clone();
    s.on_sv_control(move |ev| e.lock().unwrap().push(ev.clone()));
    let next = || {
        let events = events.clone();
        async move {
            for _ in 0..500 {
                if let Some(ev) = {
                    let mut evs = events.lock().unwrap();
                    (!evs.is_empty()).then(|| evs.remove(0))
                } {
                    return ev;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("no sampled-value control event");
        }
    };
    let (host, port) = serve(&s).await;
    let port_s = port.to_string();
    let peer = |args: Vec<&str>| {
        let mut a = vec![host.clone(), port_s.clone()];
        a.extend(args.into_iter().map(String::from));
        let bin = bin.clone();
        async move {
            let a: Vec<&str> = a.iter().map(String::as_str).collect();
            run(&bin, &a, None, Duration::from_secs(20)).await
        }
    };
    const USVCB: &str = "ED21LD0/LLN0.usvcb01";
    const MSVCB: &str = "ED21LD0/LLN0.msvcb01";

    // Reserved here, the C client reads the block and is refused it.
    let c = dial(&format!("{host}:{port}")).await;
    c.reserve_usvcb(USVCB, true).await.unwrap();
    next().await;
    let (out, _) = peer(vec!["svcb", USVCB, "svcb", MSVCB, "svresv", USVCB, "1"]).await;
    eprintln!("{out}");
    assert!(out.contains(&format!("svcb {USVCB} multicast=0 svena=0 resv=1 id=ED21USVCB01 err=0")), "{out}");
    assert!(out.contains(&format!("svcb {MSVCB} multicast=1 svena=0 resv=0 id=ED21MSVCB01 err=0")), "{out}");
    // 26 is IED_ERROR_TEMPORARILY_UNAVAILABLE.
    assert!(out.contains("svresv err=26"), "the C client was not refused a block another holds");
    c.reserve_usvcb(USVCB, false).await.unwrap();
    next().await;

    // Free, the C client reserves and enables it, and leaving ends both.
    let (out, ok) = peer(vec!["svresv", USVCB, "1", "svena", USVCB, "1", "svcb", USVCB]).await;
    eprintln!("{out}");
    assert!(ok, "mms_peer failed");
    assert!(out.contains(&format!("svcb {USVCB} multicast=0 svena=1 resv=1 id=ED21USVCB01 err=0")));
    let ev = next().await;
    assert!(ev.reserved && !ev.enabled && ev.conn.is_some(), "{ev:?}");
    assert!(next().await.enabled);
    let ev = next().await;
    assert!(!ev.enabled && !ev.reserved, "at the C client's departure: {ev:?}");
    c.close().await.unwrap();
}

// ---------------------------------------------------------------------------
// R-GOOSE and R-SV (IEC 61850-90-5) with libiec61850's session layer.
// ---------------------------------------------------------------------------

mod rsession_interop {
    use super::interop_common::rsession::*;
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn goose_from_libiec() {
        let Some(bin) = need("IEC61850_C_RSESSION_PEER") else { return };
        goose_from(&bin, from_libiec()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn goose_to_libiec() {
        let Some(bin) = need("IEC61850_C_RSESSION_PEER") else { return };
        goose_to(&bin, to_libiec()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sv_from_libiec() {
        let Some(bin) = need("IEC61850_C_RSESSION_PEER") else { return };
        sv_from(&bin, from_libiec()).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sv_to_libiec() {
        let Some(bin) = need("IEC61850_C_RSESSION_PEER") else { return };
        sv_to(&bin, to_libiec()).await;
    }
}

// ---------------------------------------------------------------------------
// MMS over TLS (IEC 62351-3) with libiec61850's TLS examples, port 3782.
// ---------------------------------------------------------------------------

#[cfg(feature = "tls")]
mod tls_interop {
    use super::*;
    use iec61850::iec62351::{self, Options as TlsOptions};
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    fn cert(path: &Path) -> CertificateDer<'static> {
        CertificateDer::from_pem_file(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    fn key(path: &Path) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_file(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    async fn wait_listening(addr: &str) {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("nothing listening on {addr}");
    }

    /// This crate's client, under the profile, against libiec61850's TLS
    /// server: the server knows the example client certificate, and the
    /// client verifies the server to the example root and by its name.
    #[tokio::test]
    async fn client_against_libiec_tls_server() {
        let Some(bin) = need("IEC61850_C_TLS_SERVER") else { return };
        let Some(certs) = need("IEC61850_C_TLS_CERTS") else { return };
        let src = Path::new(&certs).join("tls_server_example");
        let cli = Path::new(&certs).join("tls_client_example");
        let work = temp_dir("tls-server");
        for f in ["server_CA1_1.key", "server_CA1_1.pem", "root_CA1.pem", "client_CA1_1.pem", "client_CA1_2.pem"] {
            std::fs::copy(src.join(f), work.join(f)).unwrap();
        }
        let srv = CServer::start(&bin, &[], &work);
        let addr = "127.0.0.1:3782";
        wait_listening(addr).await;

        let options = |name: &str| TlsOptions {
            certificates: vec![cert(&cli.join("client_CA1_1.pem"))],
            key: Some(key(&cli.join("client_CA1_1.key"))),
            roots: vec![cert(&src.join("root_CA1.pem"))],
            server_name: name.into(),
            ..Default::default()
        };
        let cfg = iec62351::client_config(options("server1")).unwrap();
        let c = Client::dial_with(addr, ClientOptions::new().with_tls(cfg).with_timeout(Duration::from_secs(5)))
            .await
            .expect("associate over TLS");
        let v = c.read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx).await.expect("read over TLS");
        eprintln!("GGIO1.AnIn1.mag.f = {v} over TLS");
        c.close().await.unwrap();

        // The profile refuses the same server under a name it does not carry.
        let bad = iec62351::client_config(options("server2")).unwrap();
        let res = Client::dial_with(addr, ClientOptions::new().with_tls(bad).with_timeout(Duration::from_secs(5))).await;
        assert!(res.is_err(), "a certificate for server1 was accepted as server2");
        srv.stop().await;
    }

    /// libiec61850's TLS client against this crate's server under the
    /// profile: the server presents the example server certificate, which
    /// the C client verifies to the example root; the C client presents one
    /// a test authority issued, which the server verifies to that authority.
    #[tokio::test]
    async fn libiec_tls_client_against_server() {
        let Some(bin) = need("IEC61850_C_TLS_CLIENT") else { return };
        let Some(certs) = need("IEC61850_C_TLS_CERTS") else { return };
        let src = Path::new(&certs).join("tls_server_example");
        let work = temp_dir("tls-client");
        std::fs::copy(src.join("root_CA1.pem"), work.join("root_CA1.pem")).unwrap();

        // A test authority, and the RSA client certificate the C client
        // loads from client.crt and client.key.
        let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, "scada-ca");
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
        let ca = p.self_signed(&ca_key).unwrap();
        let cli_key = rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048).unwrap();
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(rcgen::DnType::CommonName, "c-client");
        p.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let cli = p.signed_by(&cli_key, &ca, &ca_key).unwrap();
        std::fs::write(work.join("client.crt"), cli.pem()).unwrap();
        std::fs::write(work.join("client.key"), cli_key.serialize_pem()).unwrap();

        let events: Arc<Mutex<Vec<String>>> = Arc::default();
        let e = events.clone();
        let cfg = iec62351::server_config(TlsOptions {
            certificates: vec![cert(&src.join("server_CA1_1.pem"))],
            key: Some(key(&src.join("server_CA1_1.key"))),
            roots: vec![ca.der().clone()],
            on_event: Some(Arc::new(move |ev: &iec62351::Event| e.lock().unwrap().push(format!("{:?}", ev.err)))),
            ..Default::default()
        })
        .unwrap();
        let Ok(ln) = TcpListener::bind("127.0.0.1:3782").await else {
            eprintln!("skipped: port 3782 is not free");
            return;
        };
        let server = Server::new(load("simpleIO_direct_control.cid"), Options::new().with_tls(cfg));
        let task = tokio::spawn(async move {
            let _ = server.serve(ln).await;
        });
        let (out, _) = run(&bin, &["127.0.0.1"], Some(&work), Duration::from_secs(20)).await;
        task.abort();
        eprintln!("{out}");
        assert!(
            out.contains("read float value") && !out.contains("ERROR") && !out.contains("failed to read server directory"),
            "the C client did not associate and read over TLS; events {:?}",
            events.lock().unwrap()
        );
    }
}

// ---------------------------------------------------------------------------
// Port 102: libiec61850's 9-2LE and service tracking examples listen there,
// and the 9-2LE one publishes on a raw socket. interop/libiec.sh runs these
// in an unprivileged network namespace (unshare -rn), on its loopback.
// ---------------------------------------------------------------------------

/// GetSVCB of libiec61850's 9-2LE example block, reserving and enabling it,
/// and receiving the stream it starts.
#[tokio::test(flavor = "multi_thread")]
async fn port102_svcb_against_libiec_9_2le() {
    use iec61850::client::PhyComAddr;
    use iec61850::{ethernet, sv};
    let Some(bin) = need("IEC61850_C_SV_SERVER") else { return };
    let mut child = Command::new(&bin).arg("lo").stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
    let c = dial("127.0.0.1:102").await;
    const REF: &str = "TEMPLATEMUnn/LLN0.MSVCB01";
    let cb = c.get_svcb(REF).await.unwrap();
    eprintln!("{cb:?}");
    // The SCL omits SampledValueControl@multicast, whose IEC 61850-6 default
    // is true, but libiec61850's model generator defaults it to false: the
    // example serves MSVCB01 under FC US, and GetSVCB reports it so.
    assert!(cb.unicast, "MSVCB01 read as an MSVCB; libiec61850 serves it under FC US");
    let want = PhyComAddr { addr: [1, 0x0c, 0xcd, 4, 0, 1], priority: 4, vid: 1, app_id: 0x1001 };
    assert!(!cb.sv_ena && !cb.resv);
    assert_eq!((cb.sv_id.as_str(), cb.data_set.as_str()), ("xxxxMUnn01", "TEMPLATEMUnn/LLN0$PhsMeas1"));
    assert_eq!((cb.conf_rev, cb.smp_rate, cb.smp_mod), (1, 80, model::SmpMod::SmpPerPeriod));
    assert_eq!(cb.dst_address, want);
    assert!(cb.opt_flds.sample_synchronized && !cb.opt_flds.refresh_time);

    let eth: Arc<dyn ethernet::Interface> = ethernet::open("lo", &[ethernet::ETHER_TYPE_SV]).expect("raw socket on lo").into();
    let (tx, rx) = std::sync::mpsc::channel();
    let tx = Mutex::new(tx);
    let sub = sv::Subscriber::new(eth.clone()).subscribe_le(
        sv::Filter { sv_id: "xxxxMUnn01".into(), ..Default::default() },
        move |s| {
            let _ = tx.lock().unwrap().send(s.smp_cnt);
        },
    );
    c.reserve_usvcb(REF, true).await.unwrap();
    c.enable_svcb(REF, cb.unicast, true).await.unwrap();
    let after = c.get_svcb(REF).await.unwrap();
    assert!(after.sv_ena && after.resv, "{after:?}");
    let n = tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("no sample from the enabled block");
    eprintln!("received smpCnt {n}");
    c.enable_svcb(REF, cb.unicast, false).await.unwrap();
    sub.stop();
    let _ = eth.close();
    c.close().await.unwrap();
    let _ = child.kill().await;
}

/// The same services against libiec61850's service tracking example and
/// against this server loaded with its ICD, comparing what each recorded in
/// its LTRK and the tracking reports each sent.
#[tokio::test(flavor = "multi_thread")]
async fn port102_ltrk_against_libiec() {
    let Some(bin) = need("IEC61850_C_LTRK_SERVER") else { return };
    let Some(icd) = need("IEC61850_C_LTRK_ICD") else { return };
    let m = scl::load_model(&icd, &scl::BuildOptions::new()).unwrap();
    let ltrk = m.device("simpleIOGenericIO").unwrap().node("LTRK1").unwrap().clone();
    let s = Server::new(m, Options::new());
    let (host, port) = serve(&s).await;
    let mut child = Command::new(&bin).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
    let who = ["libiec61850", "rs-iec61850"];
    let cs = [dial("127.0.0.1:102").await, dial(&format!("{host}:{port}")).await];

    // Attributes that differ by nature: when the service ran, the time the
    // client stamped the command with, and the report bookkeeping of each
    // server. libiec61850 copies a URCB's Resv into rptEna of UrcbTrk, never
    // into resv, and records a resvTms in BrcbTrk its BRCB does not serve.
    let mut skip: Vec<&str> = vec!["t", "T", "operTm", "timeOfEntry", "entryID", "sqNum", "lActTm", "owner", "resv", "resvTms"];
    fn leaves(prefix: &str, attrs: &[model::DataAttribute], skip: &[&str], out: &mut Vec<String>) {
        for a in attrs.iter().filter(|a| a.fc == Fc::Sr && !skip.contains(&a.name.as_str())) {
            if a.children.is_empty() {
                out.push(format!("{prefix}{}", a.name));
            } else {
                leaves(&format!("{prefix}{}.", a.name), &a.children, skip, out);
            }
        }
    }
    let failures = std::cell::RefCell::new(Vec::new());
    let compare = async |step: &str, obj: &str, skip: &[&str]| {
        let d = ltrk.object(obj).unwrap_or_else(|| panic!("the ICD has no {obj}"));
        let mut names = Vec::new();
        leaves("", &d.attributes, skip, &mut names);
        for n in names {
            let r = format!("simpleIOGenericIO/LTRK1.{obj}.{n}");
            let a = cs[0].read(r.as_str(), Fc::Sr).await;
            let b = cs[1].read(r.as_str(), Fc::Sr).await;
            match (a, b) {
                (Ok(a), Ok(b)) if a == b => {}
                (a, b) => failures.borrow_mut().push(format!("{step}: {obj}.{n}: libiec61850 {a:?}, rs-iec61850 {b:?}")),
            }
        }
    };

    // Each server reports its tracking objects through the example's BRCB.
    let mut receivers = Vec::new();
    let mut subs = Vec::new();
    for c in &cs {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut rcb = c.get_rcb("simpleIOGenericIO/LLN0.BR.brcbServiceTracking01").await.unwrap();
        rcb.trg_ops |= TrgOps::DATA_UPDATE;
        subs.push(
            c.enable_reporting(&rcb, move |r| {
                for e in &r.entries {
                    let _ = tx.send(format!("{}/{}", e.reference, e.reason));
                }
            })
            .await
            .unwrap(),
        );
        receivers.push(rx);
    }

    for c in &cs {
        let _ = c.write("simpleIOGenericIO/LLN0.EventsRCB01.RptEna", Fc::Rp, Value::boolean(true)).await;
    }
    compare("URCB enable", "UrcbTrk", &skip).await;
    for c in &cs {
        let _ = c.write("simpleIOGenericIO/LLN0.EventsRCB01.RptID", Fc::Rp, Value::visible_string("changed")).await;
    }
    compare("URCB RptID while enabled", "UrcbTrk", &skip).await;
    for c in &cs {
        let _ = c.write("simpleIOGenericIO/LLN0.Measurements01.IntgPd", Fc::Br, Value::uint32(2000)).await;
    }
    compare("BRCB IntgPd", "BrcbTrk", &skip).await;
    for c in &cs {
        let co = c.control_for("simpleIOGenericIO/GGIO1.SPCSO1").await.unwrap();
        let _ = co.operate(Value::boolean(true), &ControlOptions::default()).await;
    }
    compare("operate", "SpcTrk", &skip).await;

    // Up to the operate's, both servers sent the same reports: one per
    // tracked service, of the tracking object it updated.
    let mut seqs = [Vec::new(), Vec::new()];
    for (i, rx) in receivers.iter_mut().enumerate() {
        loop {
            match tokio::time::timeout(Duration::from_secs(3), rx.recv()).await {
                Ok(Some(e)) => {
                    let done = e.contains("LTRK1.SpcTrk/");
                    seqs[i].push(e);
                    if done {
                        break;
                    }
                }
                _ => {
                    failures.borrow_mut().push(format!("{} sent no report of SpcTrk after the operate: {:?}", who[i], seqs[i]));
                    break;
                }
            }
        }
    }
    if seqs[0] != seqs[1] {
        failures.borrow_mut().push(format!("tracking reports differ:\n libiec61850 {:?}\n rs-iec61850 {:?}", seqs[0], seqs[1]));
    } else {
        eprintln!("tracking reports of both: {:?}", seqs[0]);
    }

    for c in &cs {
        let _ = c.write("simpleIOGenericIO/LLN0.SGCB.ActSG", Fc::Sp, Value::uint8(2)).await;
    }
    compare("ActSG", "SgcbTrk", &skip).await;
    for c in &cs {
        let _ = c.write("simpleIOGenericIO/LLN0.SGCB.ActSG", Fc::Sp, Value::uint8(9)).await;
    }
    compare("ActSG out of range", "SgcbTrk", &skip).await;
    for c in &cs {
        let _ = c.write("simpleIOGenericIO/LLN0.EventLog.LogEna", Fc::Lg, Value::boolean(false)).await;
    }
    // The two LCBs differ in TrgOps: the SCL schema defaults TrgOps@gi to
    // true, which this crate's loader follows and libiec61850's does not.
    // Each server's LocbTrk has to state its own block's.
    skip.push("trgOps");
    compare("LogEna", "LocbTrk", &skip).await;
    for (i, c) in cs.iter().enumerate() {
        let lcb = c.read("simpleIOGenericIO/LLN0.EventLog.TrgOps", Fc::Lg).await;
        let trk = c.read("simpleIOGenericIO/LTRK1.LocbTrk.trgOps", Fc::Sr).await;
        match (lcb, trk) {
            (Ok(a), Ok(b)) if a == b => {}
            (a, b) => failures.borrow_mut().push(format!("{}: LocbTrk.trgOps {b:?}, the LCB's {a:?}", who[i])),
        }
    }
    drop(subs);
    let _ = child.kill().await;
    let failures = failures.into_inner();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
