use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::mms::{self, HandlerId, InformationReport, VarRef, Value};
use crate::model::{self, Fc, ObjectReference, OptFlds, ReasonCode, TrgOps};

use super::{Client, Error, Result};

/// The configuration of a report control block.
///
/// Fields read from the server are populated by [`Client::get_rcb`]; fields set
/// before [`Client::enable_reporting`] are written to the server.
#[derive(Debug, Clone, Default)]
pub struct Rcb {
    /// `LD/LN.RP.name` for an unbuffered block, `LD/LN.BR.name` for a buffered
    /// one.
    pub reference: ObjectReference,
    pub buffered: bool,

    pub rpt_id: String,
    /// The dataset in MMS notation, for example `LD/LN$DataSet`.
    pub data_set: String,
    pub conf_rev: u32,
    pub opt_flds: OptFlds,
    pub trg_ops: TrgOps,
    /// The buffer time in milliseconds.
    pub buf_tm: u32,
    /// The integrity period.
    pub intg_pd: Duration,

    /// When set on a buffered block before enabling, requests delivery of the
    /// buffered reports after this entry, so a subscriber resumes gap-free
    /// after a disconnect.
    pub resync_entry_id: Option<Vec<u8>>,

    domain: String,
    /// `LN$RP$name`.
    item: String,
}

/// Converts `LD/LN.RP.name` to the domain `LD` and item `LN$RP$name`.
fn rcb_ref_to_mms(reference: &ObjectReference) -> (String, String) {
    (reference.ld().to_string(), reference.path().join("$"))
}

/// One decoded report delivered to a subscriber.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub rpt_id: String,
    pub seq_num: u32,
    pub data_set: String,
    pub conf_rev: u32,
    pub entry_id: Vec<u8>,
    pub buf_ovfl: bool,
    pub sub_seq_num: u32,
    pub more_follows: bool,
    pub time_of_entry: Option<SystemTime>,
    pub entries: Vec<ReportEntry>,
}

/// One included dataset member in a report.
#[derive(Debug, Clone)]
pub struct ReportEntry {
    /// The member's position in the dataset.
    pub index: usize,
    /// Resolved from the dataset definition, when known.
    pub reference: ObjectReference,
    pub fc: Fc,
    pub reason: ReasonCode,
    pub value: Value,
}

/// An active report subscription.
///
/// Several may be live on one connection at a time; each holds its own report
/// handler, released by [`disable`](ReportSubscription::disable).
#[derive(Debug)]
pub struct ReportSubscription {
    conn: Arc<mms::Conn>,
    handler: HandlerId,
    domain: String,
    item: String,
    closed: AtomicBool,
}

impl ReportSubscription {
    /// Turns the report control block off and unregisters the subscription's
    /// callback, which stops receiving reports even if the write to the server
    /// fails.
    ///
    /// Calling it twice is harmless.
    pub async fn disable(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // Unregister first: a failed write must not leave reports arriving at
        // a caller that believes it has unsubscribed.
        self.conn.remove_handler(self.handler);
        let item = format!("{}$RptEna", self.item);
        let results = self
            .conn
            .write(&self.domain, &[&item], &[Value::boolean(false)])
            .await?;
        match results.into_iter().next() {
            Some(Err(code)) => Err(Error::client(format!("RCB write RptEna: {code}"))),
            _ => Ok(()),
        }
    }
}

impl Drop for ReportSubscription {
    fn drop(&mut self) {
        // The handler holds an Arc to the callback; dropping the subscription
        // without disabling must at least stop the delivery.
        if !self.closed.load(Ordering::SeqCst) {
            self.conn.remove_handler(self.handler);
        }
    }
}

impl Client {
    /// Reads a report control block's current configuration.
    ///
    /// Attributes the server does not expose are left at their default rather
    /// than failing the call, since which optional attributes a block carries
    /// varies by device.
    pub async fn get_rcb(&self, reference: impl Into<ObjectReference>) -> Result<Rcb> {
        let reference = reference.into();
        let (domain, item) = rcb_ref_to_mms(&reference);
        let mut rcb = Rcb {
            buffered: item.contains("$BR$"),
            reference,
            domain,
            item,
            ..Default::default()
        };

        if let Ok(v) = self.read_rcb_attr(&rcb, "RptID").await {
            rcb.rpt_id = v.text();
        }
        if let Ok(v) = self.read_rcb_attr(&rcb, "DatSet").await {
            rcb.data_set = v.text();
        }
        if let Ok(v) = self.read_rcb_attr(&rcb, "ConfRev").await {
            rcb.conf_rev = v.as_u32();
        }
        if let Ok(v) = self.read_rcb_attr(&rcb, "OptFlds").await {
            rcb.opt_flds = OptFlds::from_value(&v);
        }
        if let Ok(v) = self.read_rcb_attr(&rcb, "TrgOps").await {
            rcb.trg_ops = TrgOps::from_value(&v);
        }
        if let Ok(v) = self.read_rcb_attr(&rcb, "BufTm").await {
            rcb.buf_tm = v.as_u32();
        }
        if let Ok(v) = self.read_rcb_attr(&rcb, "IntgPd").await {
            rcb.intg_pd = Duration::from_millis(v.as_u64());
        }
        Ok(rcb)
    }

    async fn read_rcb_attr(&self, rcb: &Rcb, attr: &str) -> Result<Value> {
        let item = format!("{}${attr}", rcb.item);
        let vals = self.mms().read(&rcb.domain, &[&item]).await?;
        let Some(v) = vals.into_iter().next() else {
            return Err(Error::client(format!("RCB attribute {attr} missing")));
        };
        if let Some(code) = v.as_access_error() {
            return Err(code.into());
        }
        Ok(v)
    }

    async fn write_rcb(&self, rcb: &Rcb, attr: &str, v: Value) -> Result<()> {
        let item = format!("{}${attr}", rcb.item);
        let results = self.mms().write(&rcb.domain, &[&item], &[v]).await?;
        match results.into_iter().next() {
            Some(Err(code)) => Err(Error::client(format!("RCB write {attr}: {code}"))),
            _ => Ok(()),
        }
    }

    /// Configures and enables the report control block, then delivers decoded
    /// reports to `callback` until the subscription is disabled.
    ///
    /// The block's `opt_flds` and `trg_ops` are written to the server when
    /// non-zero, and its `intg_pd` always: zero is a meaningful integrity
    /// period (none at all), so it cannot also mean "leave it alone".
    /// [`get_rcb`](Client::get_rcb) fills the field in from the server, so a
    /// caller that does not touch it writes the value back unchanged.
    ///
    /// Several report control blocks may be enabled concurrently on one
    /// connection; each subscription keeps its own callback and receives only
    /// the reports whose `RptID` matches its block. A report carries no other
    /// identification, so blocks configured with the same `RptID` (which the
    /// standard permits) cannot be told apart, and both callbacks see both
    /// streams. Populate the block with [`get_rcb`](Client::get_rcb) so its
    /// `RptID` is known.
    ///
    /// The callback runs on the connection's reader task and **must not
    /// block**; hand heavy work to your own task.
    pub async fn enable_reporting(
        &self,
        rcb: &Rcb,
        callback: impl Fn(&Report) + Send + Sync + 'static,
    ) -> Result<ReportSubscription> {
        // Learn the dataset members so report entries can be labelled. A
        // server that will not describe its own dataset still reports; the
        // entries just carry no reference.
        let members = self.dataset_members_for_rcb(rcb).await.unwrap_or_default();

        if rcb.opt_flds != OptFlds::default() {
            self.write_rcb(rcb, "OptFlds", rcb.opt_flds.value()).await?;
        }
        if rcb.trg_ops != TrgOps::default() {
            self.write_rcb(rcb, "TrgOps", rcb.trg_ops.value()).await?;
        }
        // The integrity period is written whatever its value: zero means "no
        // integrity reports", which a caller has to be able to ask for, so it
        // cannot double as "leave the server's setting alone".
        let ms = rcb.intg_pd.as_millis().min(u128::from(u32::MAX)) as u32;
        self.write_rcb(rcb, "IntgPd", Value::uint32(ms)).await?;
        // On a buffered block a resync entry id requests redelivery of the
        // buffered reports after that point, and must be written before
        // enabling.
        if rcb.buffered {
            if let Some(id) = &rcb.resync_entry_id {
                if !id.is_empty() {
                    self.write_rcb(rcb, "EntryID", Value::octet_string(id.clone()))
                        .await?;
                }
            }
        }

        // Register the handler before enabling, or the first report races the
        // registration. The registration is additive, so other subscriptions
        // on this connection keep theirs; each filters on its own RptID.
        let want_rpt_id = rcb.rpt_id.clone();
        let members = Arc::new(members);
        let handler = self.mms().on_information_report(move |ir| {
            if let Some(rep) = decode_report(ir, &members) {
                if rep.rpt_id == want_rpt_id {
                    callback(&rep);
                }
            }
        });

        let sub = ReportSubscription {
            conn: Arc::clone(self.mms()),
            handler,
            domain: rcb.domain.clone(),
            item: rcb.item.clone(),
            closed: AtomicBool::new(false),
        };

        if let Err(e) = self.write_rcb(rcb, "RptEna", Value::boolean(true)).await {
            // Dropping the subscription unregisters the handler.
            drop(sub);
            return Err(e);
        }
        Ok(sub)
    }

    /// Requests a general interrogation: the server sends a report containing
    /// every dataset member.
    pub async fn trigger_gi(&self, rcb: &Rcb) -> Result<()> {
        self.write_rcb(rcb, "GI", Value::boolean(true)).await
    }

    async fn dataset_members_for_rcb(&self, rcb: &Rcb) -> Result<Vec<VarRef>> {
        let mut ds = rcb.data_set.clone();
        if ds.is_empty() {
            if let Ok(v) = self.read_rcb_attr(rcb, "DatSet").await {
                ds = v.text();
            }
        }
        // DatSet is "LD/LN$Name"; the domain is the block's own.
        let Some((_, list)) = ds.split_once('/') else {
            return Err(Error::client(format!("RCB dataset reference {ds:?}")));
        };
        Ok(self
            .mms()
            .get_named_variable_list_attributes(&rcb.domain, list)
            .await?)
    }
}

/// Interprets a flat InformationReport value list per the IEC 61850-8-1 report
/// format, driven by the `OptFlds` present in the report itself.
///
/// The layout is: RptID, OptFlds, then exactly the optional fields those flags
/// name, then the inclusion bit string, then one value per included member,
/// then one reason per included member. Reading a field the flags did not
/// select shifts everything after it, so the order here is the whole
/// correctness of report decoding.
pub(crate) fn decode_report(ir: &InformationReport, members: &[VarRef]) -> Option<Report> {
    let v = &ir.values;
    if v.len() < 3 {
        return None;
    }
    let mut i = 0usize;
    let mut next = || {
        let out = v.get(i);
        i += 1;
        out
    };

    let mut rep = Report {
        rpt_id: next()?.text(),
        ..Default::default()
    };
    let opt = OptFlds::from_value(next()?);

    if opt.has(OptFlds::SEQ_NUM) {
        rep.seq_num = next()?.as_u32();
    }
    if opt.has(OptFlds::TIME_OF_ENTRY) {
        rep.time_of_entry = next()?.time();
    }
    if opt.has(OptFlds::DATA_SET_NAME) {
        rep.data_set = next()?.text();
    }
    if opt.has(OptFlds::BUF_OVFL) {
        rep.buf_ovfl = next()?.as_bool();
    }
    if opt.has(OptFlds::ENTRY_ID) {
        rep.entry_id = next()?.bytes().to_vec();
    }
    if opt.has(OptFlds::CONF_REV) {
        rep.conf_rev = next()?.as_u32();
    }
    if opt.has(OptFlds::SEGMENTATION) {
        rep.sub_seq_num = next()?.as_u32();
        rep.more_follows = next()?.as_bool();
    }

    let inclusion = next()?;
    let included: Vec<usize> = (0..inclusion.bit_len())
        .filter(|b| inclusion.bit(*b))
        .collect();

    // Optional data-reference strings precede the values, one per included
    // member. The positions are already known from the dataset, so they are
    // skipped rather than parsed.
    if opt.has(OptFlds::DATA_REF) {
        for _ in &included {
            next();
        }
    }

    let mut entries = Vec::with_capacity(included.len());
    for idx in &included {
        let value = next().cloned().unwrap_or(Value::None);
        let (reference, fc) = match members.get(*idx) {
            Some(m) => model::from_mms(&m.domain, &m.item),
            None => (ObjectReference::default(), Fc::None),
        };
        entries.push(ReportEntry {
            index: *idx,
            reference,
            fc,
            reason: ReasonCode::default(),
            value,
        });
    }
    if opt.has(OptFlds::REASON_CODE) {
        for e in &mut entries {
            if let Some(v) = next() {
                e.reason = ReasonCode::from_value(v);
            }
        }
    }
    rep.entries = entries;
    Some(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::TimeQuality;

    /// Builds an InformationReport whose values are the flat field list a
    /// server sends for the given optional fields.
    fn report_values(opt: OptFlds, included: &[usize], values: Vec<Value>) -> InformationReport {
        let mut v = vec![Value::visible_string("EventsRCB01"), opt.value()];
        if opt.has(OptFlds::SEQ_NUM) {
            v.push(Value::uint32(7));
        }
        if opt.has(OptFlds::TIME_OF_ENTRY) {
            v.push(Value::utc_time_parts(
                1_786_838_400,
                0,
                TimeQuality::accuracy(10),
            ));
        }
        if opt.has(OptFlds::DATA_SET_NAME) {
            v.push(Value::visible_string("ied1LD0/LLN0$Events"));
        }
        if opt.has(OptFlds::BUF_OVFL) {
            v.push(Value::boolean(true));
        }
        if opt.has(OptFlds::ENTRY_ID) {
            v.push(Value::octet_string(vec![0xde, 0xad, 0xbe, 0xef]));
        }
        if opt.has(OptFlds::CONF_REV) {
            v.push(Value::uint32(3));
        }
        if opt.has(OptFlds::SEGMENTATION) {
            v.push(Value::uint32(1));
            v.push(Value::boolean(true));
        }
        // The inclusion bit string covers the whole dataset.
        let mut inclusion = Value::bit_string(4);
        for i in included {
            inclusion.set_bit(*i, true);
        }
        v.push(inclusion);
        if opt.has(OptFlds::DATA_REF) {
            for i in included {
                v.push(Value::visible_string(format!("ref{i}")));
            }
        }
        v.extend(values);
        if opt.has(OptFlds::REASON_CODE) {
            for _ in included {
                v.push(ReasonCode::DATA_CHANGE.value());
            }
        }
        InformationReport {
            values: v,
            ..Default::default()
        }
    }

    fn members() -> Vec<VarRef> {
        vec![
            VarRef::new("ied1LD0", "GGIO1$ST$Ind1$stVal"),
            VarRef::new("ied1LD0", "GGIO1$ST$Ind2$stVal"),
            VarRef::new("ied1LD0", "GGIO1$MX$AnIn1$mag$f"),
            VarRef::new("ied1LD0", "GGIO1$MX$AnIn2$mag$f"),
        ]
    }

    #[test]
    fn a_report_with_the_default_fields_decodes() {
        let opt = OptFlds::DEFAULT;
        let ir = report_values(
            opt,
            &[0, 2],
            vec![Value::boolean(true), Value::float32(230.4)],
        );
        let rep = decode_report(&ir, &members()).expect("decodes");

        assert_eq!(rep.rpt_id, "EventsRCB01");
        assert_eq!(rep.seq_num, 7);
        assert_eq!(rep.data_set, "ied1LD0/LLN0$Events");
        assert_eq!(rep.conf_rev, 3);
        assert!(rep.time_of_entry.is_some());

        assert_eq!(rep.entries.len(), 2);
        assert_eq!(rep.entries[0].index, 0);
        assert_eq!(
            rep.entries[0].reference.as_str(),
            "ied1LD0/GGIO1.Ind1.stVal"
        );
        assert_eq!(rep.entries[0].fc, Fc::St);
        assert!(rep.entries[0].value.as_bool());
        assert_eq!(rep.entries[0].reason, ReasonCode::DATA_CHANGE);

        assert_eq!(rep.entries[1].index, 2, "the second included member is #2");
        assert_eq!(
            rep.entries[1].reference.as_str(),
            "ied1LD0/GGIO1.AnIn1.mag.f"
        );
        assert_eq!(rep.entries[1].fc, Fc::Mx);
        assert_eq!(rep.entries[1].value.as_f32(), 230.4);
    }

    /// Every optional field shifts the ones after it, so a decoder that reads
    /// a field the flags did not select misattributes the whole rest of the
    /// report. Each combination has to line up.
    #[test]
    fn the_field_layout_follows_the_optional_fields_bit_string() {
        let combinations = [
            OptFlds::default(),
            OptFlds::SEQ_NUM,
            OptFlds::SEQ_NUM | OptFlds::CONF_REV,
            OptFlds::DEFAULT,
            OptFlds::DEFAULT | OptFlds::ENTRY_ID | OptFlds::BUF_OVFL,
            OptFlds::DEFAULT | OptFlds::DATA_REF,
            OptFlds::DEFAULT | OptFlds::SEGMENTATION | OptFlds::ENTRY_ID,
        ];
        for opt in combinations {
            let ir = report_values(opt, &[1, 3], vec![Value::boolean(true), Value::float32(1.5)]);
            let rep = decode_report(&ir, &members())
                .unwrap_or_else(|| panic!("failed to decode with {opt}"));

            assert_eq!(rep.rpt_id, "EventsRCB01", "with {opt}");
            assert_eq!(rep.entries.len(), 2, "with {opt}");
            // The values must still land on the right members whatever the
            // preceding fields were.
            assert!(rep.entries[0].value.as_bool(), "with {opt}");
            assert_eq!(rep.entries[1].value.as_f32(), 1.5, "with {opt}");
            assert_eq!(
                rep.entries[1].reference.as_str(),
                "ied1LD0/GGIO1.AnIn2.mag.f",
                "with {opt}"
            );

            assert_eq!(rep.seq_num, if opt.has(OptFlds::SEQ_NUM) { 7 } else { 0 });
            assert_eq!(rep.conf_rev, if opt.has(OptFlds::CONF_REV) { 3 } else { 0 });
            assert_eq!(rep.buf_ovfl, opt.has(OptFlds::BUF_OVFL));
            assert_eq!(rep.more_follows, opt.has(OptFlds::SEGMENTATION));
            if opt.has(OptFlds::ENTRY_ID) {
                assert_eq!(rep.entry_id, [0xde, 0xad, 0xbe, 0xef], "with {opt}");
            } else {
                assert!(rep.entry_id.is_empty(), "with {opt}");
            }
            if opt.has(OptFlds::REASON_CODE) {
                assert_eq!(rep.entries[0].reason, ReasonCode::DATA_CHANGE);
            } else {
                assert_eq!(rep.entries[0].reason, ReasonCode::default());
            }
        }
    }

    #[test]
    fn a_general_interrogation_report_includes_every_member() {
        let ir = report_values(
            OptFlds::DEFAULT,
            &[0, 1, 2, 3],
            vec![
                Value::boolean(true),
                Value::boolean(false),
                Value::float32(1.0),
                Value::float32(2.0),
            ],
        );
        let rep = decode_report(&ir, &members()).unwrap();
        assert_eq!(rep.entries.len(), 4);
        assert_eq!(
            rep.entries.iter().map(|e| e.index).collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
    }

    /// A server may report a dataset the client could not describe; the values
    /// must still arrive, just unlabelled.
    #[test]
    fn entries_beyond_the_known_members_carry_no_reference() {
        let ir = report_values(OptFlds::DEFAULT, &[0, 3], vec![Value::boolean(true), Value::int32(9)]);
        let rep = decode_report(&ir, &[]).unwrap();
        assert_eq!(rep.entries.len(), 2);
        assert_eq!(rep.entries[0].index, 0);
        assert!(rep.entries[0].reference.as_str().is_empty());
        assert_eq!(rep.entries[0].fc, Fc::None);
        assert!(rep.entries[0].value.as_bool());
        assert_eq!(rep.entries[1].value.as_i32(), 9);
    }

    #[test]
    fn a_report_with_no_included_members_is_still_a_report() {
        let ir = report_values(OptFlds::DEFAULT, &[], vec![]);
        let rep = decode_report(&ir, &members()).unwrap();
        assert_eq!(rep.rpt_id, "EventsRCB01");
        assert!(rep.entries.is_empty());
    }

    #[test]
    fn a_truncated_report_is_rejected_rather_than_misread() {
        // Fewer than the mandatory RptID, OptFlds and inclusion fields.
        let ir = InformationReport {
            values: vec![Value::visible_string("x"), OptFlds::DEFAULT.value()],
            ..Default::default()
        };
        assert!(decode_report(&ir, &members()).is_none());

        // The flags promise a sequence number that is not there.
        let ir = InformationReport {
            values: vec![
                Value::visible_string("x"),
                OptFlds::DEFAULT.value(),
                Value::uint32(1),
            ],
            ..Default::default()
        };
        assert!(decode_report(&ir, &members()).is_none());
    }

    #[test]
    fn rcb_references_convert_to_the_mms_item_form() {
        let (domain, item) = rcb_ref_to_mms(&"ied1LD0/LLN0.RP.urcb01".into());
        assert_eq!(domain, "ied1LD0");
        assert_eq!(item, "LLN0$RP$urcb01");
        assert!(!item.contains("$BR$"), "this one is unbuffered");

        let (_, item) = rcb_ref_to_mms(&"ied1LD0/LLN0.BR.brcb01".into());
        assert_eq!(item, "LLN0$BR$brcb01");
        assert!(item.contains("$BR$"), "buffered blocks are detected by name");
    }
}
