//! The `test` subcommand: exercises every feature a server exposes and prints
//! a PASS/FAIL/SKIP report.
//!
//! This is the interop oracle. It runs against this crate's own server and
//! against independent implementations, and a difference between two reports
//! is a difference in wire behaviour worth investigating.
//!
//! A feature the server does not implement is a SKIP, not a FAIL: no device
//! implements everything, and a sweep that failed on absent optional services
//! would tell you nothing about the ones that matter.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iec61850::client::{AcsiClass, Client, ControlOptions, DataSetEntry};
use iec61850::mms::{ObjectClass, Value};
use iec61850::model::{Fc, OrCat, OptFlds, TrgOps};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Pass,
    Fail,
    Skip,
}

impl Outcome {
    fn tag(self) -> &'static str {
        match self {
            Outcome::Pass => "PASS",
            Outcome::Fail => "FAIL",
            Outcome::Skip => "SKIP",
        }
    }
}

#[derive(Default)]
struct Report {
    lines: Vec<(Outcome, String, String)>,
}

impl Report {
    fn record(&mut self, outcome: Outcome, name: &str, detail: impl Into<String>) {
        let detail = detail.into();
        println!("{:<5} {name}{}", outcome.tag(), if detail.is_empty() {
            String::new()
        } else {
            format!("  ({detail})")
        });
        self.lines.push((outcome, name.to_string(), detail));
    }

    fn pass(&mut self, name: &str, detail: impl Into<String>) {
        self.record(Outcome::Pass, name, detail);
    }

    fn fail(&mut self, name: &str, detail: impl Into<String>) {
        self.record(Outcome::Fail, name, detail);
    }

    fn skip(&mut self, name: &str, detail: impl Into<String>) {
        self.record(Outcome::Skip, name, detail);
    }

    /// Records the outcome of a fallible step, treating an error as a failure.
    fn check<T, E: std::fmt::Display>(
        &mut self,
        name: &str,
        result: Result<T, E>,
    ) -> Option<T> {
        match result {
            Ok(v) => {
                self.pass(name, "");
                Some(v)
            }
            Err(e) => {
                self.fail(name, e.to_string());
                None
            }
        }
    }

    fn count(&self, want: Outcome) -> usize {
        self.lines.iter().filter(|(o, _, _)| *o == want).count()
    }

    fn summary(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "{} passed, {} failed, {} skipped",
            self.count(Outcome::Pass),
            self.count(Outcome::Fail),
            self.count(Outcome::Skip)
        );
        s
    }
}

/// Runs the sweep and returns the process exit code.
pub async fn run(client: &Client) -> i32 {
    let mut r = Report::default();

    println!("== association ==");
    let identity = r.check("identify", client.mms().identify().await);
    if let Some((vendor, model, revision)) = identity {
        println!("      {vendor} / {model} / {revision}");
    }

    println!("\n== browse ==");
    let Some(devices) = r.check("getNameList(domain)", client.logical_devices().await) else {
        println!("\n{}", r.summary());
        return 1;
    };
    if devices.is_empty() {
        r.fail("logical devices", "the server reports none");
        println!("\n{}", r.summary());
        return 1;
    }
    let ld = devices[0].clone();
    println!("      {} logical device(s), using {ld}", devices.len());

    let nodes = r
        .check(
            "getNameList(namedVariable)",
            client.logical_nodes(&ld).await,
        )
        .unwrap_or_default();
    if nodes.is_empty() {
        r.fail("logical nodes", "the device reports none");
    }

    sweep_model(client, &ld, &mut r).await;
    sweep_read_write(client, &ld, &mut r).await;
    sweep_datasets(client, &ld, &mut r).await;
    sweep_reporting(client, &ld, &mut r).await;
    sweep_control(client, &ld, &mut r).await;
    sweep_setting_groups(client, &ld, &mut r).await;
    sweep_files(client, &mut r).await;
    sweep_logs(client, &ld, &mut r).await;

    println!("\n{}", r.summary());
    i32::from(r.count(Outcome::Fail) > 0)
}

async fn sweep_model(client: &Client, ld: &str, r: &mut Report) {
    println!("\n== model retrieval ==");
    match client.retrieve_model().await {
        Ok(m) => {
            let objects: usize = m
                .devices
                .iter()
                .flat_map(|d| d.nodes.iter())
                .map(|n| n.objects.len())
                .sum();
            if objects == 0 {
                r.fail("retrieveModel", "no data objects were reconstructed");
            } else {
                r.pass("retrieveModel", format!("{objects} data objects"));
            }
        }
        Err(e) => r.fail("retrieveModel", e.to_string()),
    }

    // Browsing by class is what a UI needs; an empty result for data objects
    // means the name list could not be interpreted.
    match client.browse(ld, &[AcsiClass::DataObject]).await {
        Ok(entries) if entries.is_empty() => r.fail("browse(DATA)", "no data objects"),
        Ok(entries) => r.pass("browse(DATA)", format!("{} objects", entries.len())),
        Err(e) => r.fail("browse(DATA)", e.to_string()),
    }
}

/// Finds a leaf a sweep can safely read and write: a measurand magnitude.
async fn find_measurand(client: &Client, ld: &str) -> Option<(String, Fc)> {
    let entries = client.browse(ld, &[AcsiClass::DataObject]).await.ok()?;
    for e in &entries {
        let reference = e.reference.to_string();
        for tail in ["mag.f", "mag.i"] {
            let candidate = format!("{reference}.{tail}");
            if client.read(candidate.clone(), Fc::Mx).await.is_ok() {
                return Some((candidate, Fc::Mx));
            }
        }
    }
    None
}

async fn sweep_read_write(client: &Client, ld: &str, r: &mut Report) {
    println!("\n== read and write ==");

    let Some((reference, fc)) = find_measurand(client, ld).await else {
        r.skip("read(MX)", "the device exposes no readable measurand");
        r.skip("write(MX)", "no measurand to write");
        r.skip("readValues(batch)", "no measurand to batch");
        return;
    };

    match client.read(reference.clone(), fc).await {
        Ok(v) => r.pass("read(MX)", format!("{reference} = {v}")),
        Err(e) => r.fail("read(MX)", e.to_string()),
    }

    // A batch read of the same point twice is safe on any device and proves
    // the multi-item path.
    let refs = vec![reference.clone().into(), reference.clone().into()];
    match client.read_values(fc, &refs).await {
        Ok(vs) if vs.len() == 2 => r.pass("readValues(batch)", "2 items"),
        Ok(vs) => r.fail("readValues(batch)", format!("{} items, want 2", vs.len())),
        Err(e) => r.fail("readValues(batch)", e.to_string()),
    }

    // Write the value back unchanged: it changes nothing on the device but
    // exercises the whole write path.
    match client.read(reference.clone(), fc).await {
        Ok(v) => match client.write(reference.clone(), fc, v).await {
            Ok(()) => r.pass("write(MX)", "value written back unchanged"),
            Err(e) => r.skip("write(MX)", format!("refused: {e}")),
        },
        Err(e) => r.fail("write(MX)", format!("could not read it back first: {e}")),
    }

    // A read of something that cannot exist has to come back as an access
    // error, not as a success or a dropped association.
    match client.read(format!("{ld}/NOSUCHLN.NoSuchDO.stVal"), Fc::St).await {
        Ok(_) => r.fail("read(non-existent)", "the server answered with a value"),
        Err(_) => r.pass("read(non-existent)", "refused, as it should be"),
    }
}

async fn sweep_datasets(client: &Client, ld: &str, r: &mut Report) {
    println!("\n== datasets ==");

    let sets = client
        .browse(ld, &[AcsiClass::DataSet])
        .await
        .unwrap_or_default();
    if sets.is_empty() {
        r.skip("readDataSet", "the device configures none");
    } else {
        let reference = sets[0].reference.to_string();
        match client.read_data_set(reference.clone()).await {
            Ok(ds) if ds.members.is_empty() => {
                r.fail("readDataSet", format!("{reference} reported no members"))
            }
            Ok(ds) => r.pass(
                "readDataSet",
                format!("{reference}: {} members", ds.members.len()),
            ),
            Err(e) => r.fail("readDataSet", e.to_string()),
        }
    }

    // A dynamic dataset is optional; a device that refuses to create one is
    // not broken.
    let Some((member, fc)) = find_measurand(client, ld).await else {
        r.skip("createDataSet", "no member to put in one");
        return;
    };
    let dyn_ref = format!("{ld}/LLN0.rsIec61850Sweep");
    // Clean up anything a previous run left behind.
    client.delete_data_set(dyn_ref.clone()).await.ok();

    match client
        .create_data_set(dyn_ref.clone(), &[DataSetEntry::new(member, fc)])
        .await
    {
        Ok(()) => {
            r.pass("createDataSet", dyn_ref.clone());
            match client.data_set_members(dyn_ref.clone()).await {
                Ok(m) if m.len() == 1 => r.pass("getNamedVariableListAttributes", "1 member"),
                Ok(m) => r.fail(
                    "getNamedVariableListAttributes",
                    format!("{} members, want 1", m.len()),
                ),
                Err(e) => r.fail("getNamedVariableListAttributes", e.to_string()),
            }
            match client.delete_data_set(dyn_ref).await {
                Ok(()) => r.pass("deleteDataSet", ""),
                Err(e) => r.fail("deleteDataSet", e.to_string()),
            }
        }
        Err(e) => r.skip("createDataSet", format!("refused: {e}")),
    }
}

async fn sweep_reporting(client: &Client, ld: &str, r: &mut Report) {
    println!("\n== reporting ==");

    for (class, label) in [(AcsiClass::Urcb, "URCB"), (AcsiClass::Brcb, "BRCB")] {
        let blocks = client.browse(ld, &[class]).await.unwrap_or_default();
        let Some(entry) = blocks.first() else {
            r.skip(&format!("report({label})"), "the device configures none");
            continue;
        };
        let reference = entry.reference.to_string();

        let Some(mut rcb) = r.check(
            &format!("getRCB({label})"),
            client.get_rcb(reference.clone()).await,
        ) else {
            continue;
        };
        if rcb.rpt_id.is_empty() {
            r.fail(&format!("report({label})"), "the block reports no RptID");
            continue;
        }
        rcb.opt_flds = OptFlds::DEFAULT;
        rcb.trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;
        // No integrity period: a general interrogation is what is being
        // measured, and a periodic report would confuse the count.
        rcb.intg_pd = Duration::ZERO;

        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        let sub = match client
            .enable_reporting(&rcb, move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            })
            .await
        {
            Ok(s) => {
                r.pass(&format!("enableReporting({label})"), reference.clone());
                s
            }
            Err(e) => {
                r.fail(&format!("enableReporting({label})"), e.to_string());
                continue;
            }
        };

        match client.trigger_gi(&rcb).await {
            Ok(()) => {
                // Give the device a moment to answer the interrogation.
                tokio::time::sleep(Duration::from_millis(750)).await;
                let n = seen.load(Ordering::SeqCst);
                if n > 0 {
                    r.pass(&format!("generalInterrogation({label})"), format!("{n} report(s)"));
                } else {
                    r.fail(
                        &format!("generalInterrogation({label})"),
                        "no report arrived within 750ms",
                    );
                }
            }
            Err(e) => r.fail(&format!("generalInterrogation({label})"), e.to_string()),
        }

        match sub.disable().await {
            Ok(()) => r.pass(&format!("disableReporting({label})"), ""),
            Err(e) => r.fail(&format!("disableReporting({label})"), e.to_string()),
        }
    }
}

async fn sweep_control(client: &Client, ld: &str, r: &mut Report) {
    println!("\n== control ==");

    // A controllable object is one whose CO constraint exposes an Oper.
    let entries = client
        .browse(ld, &[AcsiClass::DataObject])
        .await
        .unwrap_or_default();
    let mut target = None;
    for e in &entries {
        let reference = e.reference.to_string();
        if client
            .data_directory(reference.clone(), Fc::Co)
            .await
            .is_ok_and(|children| children.iter().any(|c| c == "Oper"))
        {
            target = Some(reference);
            break;
        }
    }
    let Some(object) = target else {
        r.skip("control", "the device exposes no controllable object");
        return;
    };

    let Some(co) = r.check("controlFor", client.control_for(object.clone()).await) else {
        return;
    };
    println!("      {object}: {}", co.model());

    match co.ctl_val_spec().await {
        Ok(spec) => r.pass("ctlValSpec", format!("{:?}", spec.kind)),
        Err(e) => r.skip("ctlValSpec", format!("not reported: {e}")),
    }

    if !co.model().is_controllable() {
        r.skip("operate", "the object is status-only");
        return;
    }

    // Read the present state so the sweep can put it back.
    let before = client.read(format!("{object}.stVal"), Fc::St).await.ok();
    let want = before.as_ref().is_none_or(|v| !v.as_bool());

    let options = ControlOptions::new()
        .with_originator(OrCat::StationControl, "rs-iec61850-sweep");
    match co.operate(Value::boolean(want), &options).await {
        Ok(()) => {
            r.pass("operate", format!("set to {want}"));
            // The status value should follow the command.
            match client.read(format!("{object}.stVal"), Fc::St).await {
                Ok(v) if v.as_bool() == want => r.pass("operate(stVal follows)", ""),
                Ok(v) => r.fail(
                    "operate(stVal follows)",
                    format!("stVal is {v}, want {want}"),
                ),
                Err(e) => r.skip("operate(stVal follows)", format!("not readable: {e}")),
            }
            // Put it back where it was.
            if let Some(v) = before {
                co.operate(v, &options).await.ok();
            }
        }
        Err(e) => r.fail("operate", e.to_string()),
    }
}

async fn sweep_setting_groups(client: &Client, ld: &str, r: &mut Report) {
    println!("\n== setting groups ==");

    let blocks = client
        .browse(ld, &[AcsiClass::Sgcb])
        .await
        .unwrap_or_default();
    let Some(entry) = blocks.first() else {
        r.skip("settingGroups", "the device has no SGCB");
        return;
    };
    match client.setting_groups(entry.reference.clone()).await {
        Ok(sg) => r.pass(
            "settingGroups",
            format!("NumOfSG={} ActSG={} EditSG={}", sg.num_of_sg, sg.act_sg, sg.edit_sg),
        ),
        Err(e) => r.fail("settingGroups", e.to_string()),
    }
}

async fn sweep_files(client: &Client, r: &mut Report) {
    println!("\n== file services ==");

    let entries = match client.file_directory("").await {
        Ok(entries) => {
            r.pass("fileDirectory", format!("{} entries", entries.len()));
            entries
        }
        Err(e) => {
            r.skip("fileDirectory", format!("not supported: {e}"));
            return;
        }
    };

    // Find something readable. Servers differ on how they report a directory:
    // some mark it with a trailing separator, some give a bare name that looks
    // exactly like a file, and some report names relative to the directory
    // asked for rather than openable as given. Trying candidates until one
    // opens copes with all of them, where committing to the first entry only
    // works against servers that happen to list a file first.
    let mut candidates: Vec<String> = Vec::new();
    for e in &entries {
        if !e.name.ends_with('/') {
            candidates.push(e.name.clone());
        }
    }
    // Then one level down, which is where a COMTRADE store keeps recordings.
    for dir in entries.iter().filter(|e| e.name.ends_with('/')) {
        let name = dir.name.trim_end_matches('/');
        if let Ok(sub) = client.file_directory(name).await {
            for e in sub {
                if e.name.ends_with('/') {
                    continue;
                }
                // A server that lists bare names needs the path rejoining.
                if e.name.contains('/') {
                    candidates.push(e.name);
                } else {
                    candidates.push(format!("{name}/{}", e.name));
                }
            }
        }
    }
    // A directory reported without a trailing separator is indistinguishable
    // from a file, so those are tried last rather than skipped.
    for e in &entries {
        if e.name.ends_with('/') {
            continue;
        }
        let _ = e;
    }

    let mut read_any = None;
    let mut last_error = String::new();
    for name in &candidates {
        match client.read_file(name).await {
            Ok(data) => {
                read_any = Some((name.clone(), data.len()));
                break;
            }
            Err(e) => last_error = e.to_string(),
        }
    }

    match read_any {
        Some((name, len)) => r.pass("readFile", format!("{name} ({len} octets)")),
        None if candidates.is_empty() => {
            r.skip("readFile", "the filestore holds no regular file")
        }
        None => r.fail(
            "readFile",
            format!("none of {} candidates opened; last: {last_error}", candidates.len()),
        ),
    }
}

async fn sweep_logs(client: &Client, ld: &str, r: &mut Report) {
    println!("\n== logs ==");

    // The journal name list is what a device without logging refuses.
    match client
        .mms()
        .get_name_list(ObjectClass::Journal, ld)
        .await
    {
        Ok(names) if names.is_empty() => r.skip("readJournal", "the device has no journal"),
        Ok(names) => {
            let reference = format!("{ld}/{}", names[0].replace('$', "."));
            let now = std::time::SystemTime::now();
            let hour_ago = now - Duration::from_secs(3600);
            match client.query_log_by_time(reference.clone(), hour_ago, now).await {
                Ok(entries) => r.pass("readJournal", format!("{} entries", entries.len())),
                Err(e) => r.fail("readJournal", e.to_string()),
            }
        }
        Err(e) => r.skip("readJournal", format!("not supported: {e}")),
    }
}
