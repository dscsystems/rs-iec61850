//! Drives report control blocks (IEC 61850-7-2 clause 17, mapped by
//! IEC 61850-8-1): reservation, enabling, general interrogation, triggered and
//! integrity reports, buffer time, segmentation and the report buffer of
//! buffered control blocks.
//!
//! Lock order: the server model lock, then the connection table, then a
//! block's state. Every entry point is called with the first two held, or takes
//! them first.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{OnceLock, Weak};
use std::time::{Duration, SystemTime};

use crate::asn1::{cons, context_constructed, context_primitive, prim, Element};
use crate::mms::{data_element, DataAccessError, Value};
use crate::model::{self, Model, OptFlds, ReasonCode, TrgOps};

use super::access;
use super::rcb::{self, RcbRuntime, RcbState, ReportEntry};
use super::server::Inner;
use super::tx::ChangeSet;
use super::{ConnId, ConnMap};

/// One dataset member, in MMS terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsMember {
    pub domain: String,
    pub item: String,
}

/// The report fields a client may ask for.
///
/// The segmentation bit is not among them: the server sets it on the reports
/// it has to segment.
const SUPPORTED_OPT_FLDS: OptFlds = OptFlds(
    OptFlds::SEQ_NUM.0
        | OptFlds::TIME_OF_ENTRY.0
        | OptFlds::REASON_CODE.0
        | OptFlds::DATA_SET_NAME.0
        | OptFlds::DATA_REF.0
        | OptFlds::BUF_OVFL.0
        | OptFlds::ENTRY_ID.0
        | OptFlds::CONF_REV.0,
);

/// The attributes a client configures. IEC 61850-7-2 lets them change only
/// while the block is disabled.
const RCB_SETTINGS: &[&str] = &[
    "RptID", "DatSet", "OptFlds", "BufTm", "TrgOps", "IntgPd", "PurgeBuf", "EntryID",
    "ResvTms",
];

/// The attributes the server maintains.
const RCB_READ_ONLY: &[&str] = &["ConfRev", "SqNum", "TimeofEntry", "Owner"];

/// The triggers a change set can raise.
const CHANGE_TRIGGERS: u8 =
    TrgOps::DATA_CHANGE.0 | TrgOps::QUALITY_CHANGE.0 | TrgOps::DATA_UPDATE.0;

/// Reduces a client's requested optional fields to what the report will really
/// carry.
///
/// The value is echoed as the report's second field and is what tells a client
/// which optional fields follow, so a bit set there without its field shifts
/// every value after it: the flags have to describe the report as built, not
/// as asked for. `BufOvfl` and `EntryID` belong to buffered reports only.
pub fn effective_opt_flds(opt: OptFlds, buffered: bool) -> OptFlds {
    let mut opt = OptFlds(opt.0 & SUPPORTED_OPT_FLDS.0);
    if !buffered {
        opt = OptFlds(opt.0 & !(OptFlds::BUF_OVFL.0 | OptFlds::ENTRY_ID.0));
    }
    opt
}

/// Returns the trigger reasons `changes` raised for a dataset member.
///
/// A member may name any level of the tree, commonly a data object with an
/// FC, and a change to anything below it under the same functional constraint
/// is a change of the member; so is a change to something above it. TrgOps and
/// ReasonCode share their bit positions, so the result is also the reason code.
pub(crate) fn member_reason(changes: &ChangeSet, member: &DsMember) -> TrgOps {
    let (reference, fc) = model::from_mms(&member.domain, &member.item);
    let below = format!("{reference}.");
    let mut r = 0u8;
    for ((changed, cfc), t) in changes {
        if *cfc != fc {
            continue;
        }
        // The trailing separator keeps "Pos" from matching a sibling called
        // "PosSomething".
        if *changed == reference
            || changed.as_str().starts_with(&below)
            || reference.as_str().starts_with(&format!("{changed}."))
        {
            r |= t.0;
        }
    }
    TrgOps(r)
}

/// The report engine.
#[derive(Debug)]
pub struct ReportManager {
    registry: HashMap<String, RcbState>,
    /// The server, for the timer tasks that reach back into it.
    owner: OnceLock<Weak<Inner>>,
    /// The runtime the timer tasks run on, remembered so that an update from a
    /// thread outside it can still open a buffer-time window.
    runtime: OnceLock<tokio::runtime::Handle>,
}

impl ReportManager {
    /// Materialises every control block in the model and returns the engine.
    pub fn new(model: &mut Model, buf_default: usize) -> ReportManager {
        ReportManager {
            registry: rcb::materialise_rcbs(model, buf_default),
            owner: OnceLock::new(),
            runtime: OnceLock::new(),
        }
    }

    /// Ties the engine to its server, once it exists.
    pub(crate) fn set_owner(&self, owner: Weak<Inner>) {
        let _ = self.owner.set(owner);
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let _ = self.runtime.set(h);
        }
    }

    /// Returns the control block registered under a key, if any.
    pub fn get(&self, key: &str) -> Option<&RcbState> {
        self.registry.get(key)
    }

    /// Spawns a timer task on the server's runtime, or reports that there is
    /// none to spawn on.
    fn spawn(
        &self,
        f: impl Future<Output = ()> + Send + 'static,
    ) -> Option<tokio::task::AbortHandle> {
        let handle = tokio::runtime::Handle::try_current()
            .ok()
            .or_else(|| self.runtime.get().cloned())?;
        let _ = self.runtime.set(handle.clone());
        Some(handle.spawn(f).abort_handle())
    }

    /// Decides whether a client may write `attr` of a report control block,
    /// before anything is stored.
    pub fn check_rcb_write(
        &self,
        model: &Model,
        domain: &str,
        item: &str,
        attr: &str,
        v: &Value,
        conn: ConnId,
    ) -> Result<(), DataAccessError> {
        let Some(rs) = rcb::rcb_key(domain, item).and_then(|(key, _)| self.registry.get(&key))
        else {
            return Err(DataAccessError::ObjectNonExistent);
        };
        let st = rs.state.lock().unwrap();
        // A block another client holds is not this one's to change.
        if st.owner.is_some_and(|o| o != conn) {
            return Err(DataAccessError::TemporarilyUnavailable);
        }
        match attr {
            a if RCB_READ_ONLY.contains(&a) => Err(DataAccessError::ObjectAccessDenied),
            "RptEna" if v.as_bool() => {
                if st.enabled {
                    return Err(DataAccessError::TemporarilyUnavailable);
                }
                // A block without a dataset has nothing to report.
                if resolve_data_set(model, &attr_text(model, rs, "DatSet")).is_none() {
                    return Err(DataAccessError::TemporarilyUnavailable);
                }
                Ok(())
            }
            // Interrogation is a service of an enabled block.
            "GI" if v.as_bool() && !st.enabled => Err(DataAccessError::TemporarilyUnavailable),
            "Resv" if !v.as_bool() && st.enabled => Err(DataAccessError::TemporarilyUnavailable),
            a if RCB_SETTINGS.contains(&a) => {
                if st.enabled {
                    return Err(DataAccessError::TemporarilyUnavailable);
                }
                match a {
                    "DatSet" => {
                        let r = v.text();
                        if !r.is_empty() && resolve_data_set(model, &r).is_none() {
                            return Err(DataAccessError::ObjectValueInvalid);
                        }
                    }
                    "EntryID" => {
                        // Resynchronisation needs an entry the buffer still
                        // holds; all zeros asks for everything it holds.
                        let id = v.bytes();
                        if id.len() != 8 || (!is_zero_entry_id(id) && st.buffer_index(id).is_none())
                        {
                            return Err(DataAccessError::ObjectValueInvalid);
                        }
                    }
                    _ => {}
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Applies the effect of a stored control-block write that
    /// [`check_rcb_write`](ReportManager::check_rcb_write) allowed.
    // The engine needs the model, the connection table, the address of the
    // block and what was written to it; bundling them would only move the list
    // to a struct nothing else constructs.
    #[allow(clippy::too_many_arguments)]
    pub fn on_rcb_write(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        domain: &str,
        item: &str,
        attr: &str,
        v: &Value,
        conn: ConnId,
    ) {
        if let Ok(h) = tokio::runtime::Handle::try_current() {
            let _ = self.runtime.set(h);
        }
        let Some(rs) = rcb::rcb_key(domain, item).and_then(|(key, _)| self.registry.get(&key))
        else {
            return;
        };
        let mut st = rs.state.lock().unwrap();
        if attr == "Resv" {
            st.owner = v.as_bool().then_some(conn);
            sync_resv(model, rs, &st);
            return;
        }
        // Writing a block reserves it for the writer (IEC 61850-7-2 implicit
        // reservation), so a second client cannot reconfigure or take it.
        if st.owner.is_none() {
            st.owner = Some(conn);
            sync_resv(model, rs, &st);
        }
        match attr {
            "RptEna" => {
                if v.as_bool() {
                    self.enable(model, conns, rs, &mut st, conn);
                } else {
                    self.disable(model, conns, rs, &mut st);
                }
            }
            "GI" => {
                if v.as_bool() && trg_ops(model, rs).has(TrgOps::GI) {
                    self.report_all(model, conns, rs, &mut st, ReasonCode::GI);
                }
                // GI is a trigger, not a state: it reads FALSE once performed.
                set_attr(model, rs, "GI", Value::boolean(false));
            }
            "PurgeBuf" => {
                if v.as_bool() {
                    st.purge();
                }
                set_attr(model, rs, "PurgeBuf", Value::boolean(false));
            }
            "EntryID" => st.resync_id = Some(v.bytes().to_vec()),
            "DatSet" => {
                // A different dataset is a different configuration: ConfRev
                // counts it, and buffered reports of the old one are void.
                let rev = attr_value(model, rs, "ConfRev").map_or(0, |v| v.as_u32());
                set_attr(model, rs, "ConfRev", Value::uint32(rev.wrapping_add(1)));
                st.purge();
            }
            _ => {}
        }
    }

    fn enable(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        rs: &RcbState,
        st: &mut RcbRuntime,
        conn: ConnId,
    ) {
        st.enabled = true;
        st.conn = Some(conn);
        st.owner = Some(conn);
        sync_resv(model, rs, st);
        set_sq_num(model, rs, st, 0);
        st.stop_integrity();

        if rs.buffered {
            // Delivery resumes after the resync point, from the oldest entry
            // for all zeros, and otherwise where it left off: entries already
            // sent are not sent again.
            if let Some(id) = st.resync_id.take() {
                st.next = if is_zero_entry_id(&id) {
                    0
                } else if let Some(i) = st.buffer_index(&id) {
                    i + 1
                } else {
                    // Purged between the EntryID write and the enable.
                    st.buf_overflow = true;
                    0
                };
            }
            self.transmit_buffered(model, conns, rs, st);
        }

        let period = Duration::from_millis(attr_value(model, rs, "IntgPd").map_or(0, |v| v.as_u64()));
        if !period.is_zero() && trg_ops(model, rs).has(TrgOps::INTEGRITY) {
            let generation = st.integrity_gen;
            if let Some(owner) = self.owner.get().cloned() {
                st.integrity = self.spawn(integrity_loop(
                    owner,
                    RcbState::key(&rs.domain, &rs.item),
                    generation,
                    period,
                ));
            }
        }
    }

    fn disable(&self, model: &mut Model, conns: &ConnMap, rs: &RcbState, st: &mut RcbRuntime) {
        // Events already collected in a buffer-time window are reported, not
        // lost with the subscription.
        self.flush_pending(model, conns, rs, st);
        st.enabled = false;
        st.conn = None;
        st.stop_integrity();
        // A buffered block keeps buffering for whoever enables it next; the
        // reservation of an unbuffered block lasts until released.
        if rs.buffered {
            st.owner = None;
        }
    }

    /// Releases every block a closing connection had enabled or reserved.
    pub fn disable_conn(&self, model: &mut Model, conns: &ConnMap, conn: ConnId) {
        for rs in self.registry.values() {
            let mut st = rs.state.lock().unwrap();
            if st.conn == Some(conn) {
                self.disable(model, conns, rs, &mut st);
            }
            if st.owner == Some(conn) {
                st.owner = None;
                sync_resv(model, rs, &st);
            }
        }
    }

    /// Stops every timer task, for server shutdown.
    pub fn shutdown(&self) {
        for rs in self.registry.values() {
            let mut st = rs.state.lock().unwrap();
            st.enabled = false;
            st.conn = None;
            st.stop_integrity();
            if let Some(t) = st.pending_timer.take() {
                t.abort();
            }
            st.pending_gen += 1;
        }
    }

    /// Reports the changes of an update or a client write to every block whose
    /// dataset they touch. A member is included for the reasons its written
    /// attributes raised that the block's TrgOps asks for.
    pub(crate) fn on_update(&self, model: &mut Model, conns: &ConnMap, changes: &ChangeSet) {
        if changes.is_empty() {
            return;
        }
        for rs in self.registry.values() {
            let mut st = rs.state.lock().unwrap();
            // Unbuffered blocks only report while enabled; buffered blocks
            // capture events for delivery on a later enable.
            if !rs.buffered && !st.enabled {
                continue;
            }
            let want = trg_ops(model, rs).0 & CHANGE_TRIGGERS;
            let Some(members) = resolve_data_set(model, &attr_text(model, rs, "DatSet")) else {
                continue;
            };
            let mut e = ReportEntry::new();
            for (i, m) in members.iter().enumerate() {
                let r = member_reason(changes, m).0 & want;
                if r == 0 {
                    continue;
                }
                let Some(v) = item_value(model, &m.domain, &m.item) else {
                    continue;
                };
                e.members.push(i);
                e.values.push(v);
                e.reasons.push(ReasonCode(r));
            }
            if !e.members.is_empty() {
                self.event(model, conns, rs, &mut st, e);
            }
        }
    }

    /// Reports every dataset member, for a general interrogation or an
    /// integrity period. Events waiting in a buffer-time window go first, so
    /// the report reflects them in order.
    fn report_all(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        rs: &RcbState,
        st: &mut RcbRuntime,
        reason: ReasonCode,
    ) {
        self.flush_pending(model, conns, rs, st);
        let members = resolve_data_set(model, &attr_text(model, rs, "DatSet")).unwrap_or_default();
        let mut e = ReportEntry::new();
        for (i, m) in members.iter().enumerate() {
            if let Some(v) = item_value(model, &m.domain, &m.item) {
                e.members.push(i);
                e.values.push(v);
                e.reasons.push(reason);
            }
        }
        if !e.members.is_empty() {
            self.emit(model, conns, rs, st, e);
        }
    }

    /// Takes a triggered report entry through the buffer time (BufTm).
    ///
    /// With none it is reported at once; otherwise events collect in one
    /// report until the window closes. A member that changes again inside the
    /// window closes it first, so its earlier value is reported rather than
    /// overwritten (IEC 61850-7-2).
    fn event(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        rs: &RcbState,
        st: &mut RcbRuntime,
        e: ReportEntry,
    ) {
        let buf_tm = Duration::from_millis(attr_value(model, rs, "BufTm").map_or(0, |v| v.as_u64()));
        if buf_tm.is_zero() {
            self.emit(model, conns, rs, st, e);
            return;
        }
        if st.pending.as_ref().is_some_and(|p| p.overlaps(&e)) {
            self.flush_pending(model, conns, rs, st);
        }
        if st.pending.is_none() {
            let generation = st.pending_gen;
            let timer = self.owner.get().cloned().and_then(|owner| {
                self.spawn(buffer_time_window(
                    owner,
                    RcbState::key(&rs.domain, &rs.item),
                    generation,
                    buf_tm,
                ))
            });
            let Some(timer) = timer else {
                // No runtime to close the window on: report at once.
                self.emit(model, conns, rs, st, e);
                return;
            };
            st.pending = Some(ReportEntry::new());
            st.pending_timer = Some(timer);
        }
        if let Some(p) = &mut st.pending {
            p.merge(e);
        }
    }

    fn flush_pending(&self, model: &mut Model, conns: &ConnMap, rs: &RcbState, st: &mut RcbRuntime) {
        let Some(p) = st.pending.take() else {
            return;
        };
        st.pending_gen += 1;
        if let Some(t) = st.pending_timer.take() {
            t.abort();
        }
        if !p.members.is_empty() {
            self.emit(model, conns, rs, st, p);
        }
    }

    /// Commits a report: an unbuffered block sends it if enabled; a buffered
    /// block numbers it, keeps it in the buffer (discarding the oldest past the
    /// buffer depth) and sends it if enabled.
    fn emit(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        rs: &RcbState,
        st: &mut RcbRuntime,
        mut e: ReportEntry,
    ) {
        e.time = SystemTime::now();
        if !rs.buffered {
            if st.enabled {
                self.transmit(model, conns, rs, st, &e);
            }
            return;
        }
        st.entry_counter += 1;
        e.id = rcb::make_entry_id(st.entry_counter);
        set_attr(model, rs, "EntryID", Value::octet_string(e.id.clone()));
        set_attr(model, rs, "TimeofEntry", Value::binary_time(e.time));
        st.buffer.push(e);
        while st.buffer.len() > rs.max_buffer {
            st.buffer.remove(0);
            if st.next > 0 {
                st.next -= 1; // the discarded entry had been sent
            } else {
                st.buf_overflow = true; // it had not: the client will miss it
            }
        }
        if st.enabled {
            self.transmit_buffered(model, conns, rs, st);
        }
    }

    /// Sends the buffered entries not yet sent.
    fn transmit_buffered(&self, model: &mut Model, conns: &ConnMap, rs: &RcbState, st: &mut RcbRuntime) {
        while st.next < st.buffer.len() {
            let e = st.buffer[st.next].clone();
            self.transmit(model, conns, rs, st, &e);
            st.next += 1;
        }
    }

    /// Sends one report with the next sequence number, segmented to the
    /// association's maximum PDU size when it does not fit.
    fn transmit(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        rs: &RcbState,
        st: &mut RcbRuntime,
        e: &ReportEntry,
    ) {
        let Some(sc) = st.conn.and_then(|c| conns.get(&c)) else {
            return;
        };
        let seq = st.sq_num;
        set_sq_num(model, rs, st, seq + 1);
        let buf_ovfl = std::mem::take(&mut st.buf_overflow);

        for pdu in report_pdus(model, rs, e, seq, buf_ovfl, sc.max_pdu) {
            if sc.send_unconfirmed(pdu).is_err() {
                // The queue is saturated, which is the buffer-overflow
                // condition the protocol models; a buffered block records it
                // so the client learns it missed entries.
                tracing::debug!(rcb = %rs.item, "server: report send failed");
                if rs.buffered {
                    st.buf_overflow = true;
                }
                return;
            }
        }
    }
}

/// Sets the sequence number the next report carries, wrapping at the width of
/// the block's SqNum: INT8U for an unbuffered block, INT16U for a buffered one
/// (IEC 61850-7-2).
fn set_sq_num(model: &mut Model, rs: &RcbState, st: &mut RcbRuntime, n: u32) {
    if rs.buffered {
        st.sq_num = n & 0xffff;
        set_attr(model, rs, "SqNum", Value::uint16(st.sq_num as u16));
    } else {
        st.sq_num = n & 0xff;
        set_attr(model, rs, "SqNum", Value::uint8(st.sq_num as u8));
    }
}

/// Reflects the reservation into an unbuffered block's Resv.
fn sync_resv(model: &mut Model, rs: &RcbState, st: &RcbRuntime) {
    if !rs.buffered {
        set_attr(model, rs, "Resv", Value::boolean(st.owner.is_some()));
    }
}

/// Builds the InformationReport(s) for `e` (IEC 61850-8-1).
///
/// One when it fits in `max_pdu` octets, otherwise segments that each carry a
/// run of the included members, SubSeqNum counting from zero and
/// MoreSegmentsFollow set on all but the last. A single member too large for
/// any PDU is sent in a segment of its own.
fn report_pdus(
    model: &Model,
    rs: &RcbState,
    e: &ReportEntry,
    seq: u32,
    buf_ovfl: bool,
    max_pdu: usize,
) -> Vec<Element> {
    let opt = effective_opt_flds(
        attr_value(model, rs, "OptFlds").map_or(OptFlds(0), |v| OptFlds::from_value(&v)),
        rs.buffered,
    );
    let members = resolve_data_set(model, &attr_text(model, rs, "DatSet")).unwrap_or_default();
    let fixed = ReportFields {
        rpt_id: rcb::rpt_id_of(&attr_text(model, rs, "RptID"), &rs.domain, &rs.item),
        dat_set: attr_text(model, rs, "DatSet"),
        conf_rev: attr_value(model, rs, "ConfRev").map_or(0, |v| v.as_u32()),
        opt,
        seq,
        buf_ovfl,
        buffered: rs.buffered,
    };
    let build = |from: usize, to: usize, segment: Option<(u16, bool)>| {
        report_element(&fixed, e, &members, from, to, segment)
    };
    // The unconfirmed PDU adds its own tag and length to the report.
    let fits = |el: &Element| max_pdu == 0 || el.size() + 4 <= max_pdu;

    let n = e.members.len();
    let whole = build(0, n, None);
    if fits(&whole) {
        return vec![whole];
    }
    let mut out = Vec::new();
    let (mut from, mut sub_seq) = (0, 0u16);
    while from < n {
        let mut to = from + 1;
        while to < n && fits(&build(from, to + 1, Some((sub_seq, true)))) {
            to += 1;
        }
        out.push(build(from, to, Some((sub_seq, to < n))));
        from = to;
        sub_seq = sub_seq.wrapping_add(1);
    }
    out
}

/// What every segment of one report carries.
struct ReportFields {
    rpt_id: String,
    dat_set: String,
    conf_rev: u32,
    opt: OptFlds,
    seq: u32,
    buf_ovfl: bool,
    buffered: bool,
}

/// Encodes the report of `e`'s members `[from, to)`, as a segment when
/// `segment` carries its SubSeqNum and MoreSegmentsFollow.
fn report_element(
    f: &ReportFields,
    e: &ReportEntry,
    members: &[DsMember],
    from: usize,
    to: usize,
    segment: Option<(u16, bool)>,
) -> Element {
    let mut opt = f.opt;
    if segment.is_some() {
        opt = OptFlds(opt.0 | OptFlds::SEGMENTATION.0);
    }
    let mut fields: Vec<Element> = Vec::new();
    let mut add = |v: Value| fields.extend(data_element(&v));

    add(Value::visible_string(&f.rpt_id));
    add(opt.value());
    if opt.has(OptFlds::SEQ_NUM) {
        add(if f.buffered {
            Value::uint16(f.seq as u16)
        } else {
            Value::uint8(f.seq as u8)
        });
    }
    if opt.has(OptFlds::TIME_OF_ENTRY) {
        add(Value::binary_time(e.time));
    }
    if opt.has(OptFlds::DATA_SET_NAME) {
        add(Value::visible_string(&f.dat_set));
    }
    if opt.has(OptFlds::BUF_OVFL) {
        add(Value::boolean(f.buf_ovfl));
    }
    if opt.has(OptFlds::ENTRY_ID) {
        add(Value::octet_string(e.id.clone()));
    }
    if opt.has(OptFlds::CONF_REV) {
        add(Value::uint32(f.conf_rev));
    }
    if let Some((sub_seq, more)) = segment {
        add(Value::uint16(sub_seq));
        add(Value::boolean(more));
    }

    // The inclusion bit string carries one bit per dataset member.
    let mut inclusion = Value::bit_string(members.len());
    for &idx in &e.members[from..to] {
        inclusion.set_bit(idx, true);
    }
    add(inclusion);
    // Data references precede the values: the MMS form of each included
    // member's reference.
    if opt.has(OptFlds::DATA_REF) {
        for &idx in &e.members[from..to] {
            if let Some(m) = members.get(idx) {
                add(Value::visible_string(format!("{}/{}", m.domain, m.item)));
            }
        }
    }
    for v in &e.values[from..to] {
        add(v.clone());
    }
    if opt.has(OptFlds::REASON_CODE) {
        for r in &e.reasons[from..to] {
            add(r.value());
        }
    }

    // InformationReport [0] {
    //   variableListName [1] { vmd-specific "RPT" },
    //   listOfAccessResult [0] }
    cons(
        context_constructed(0),
        [
            cons(
                context_constructed(1),
                [prim(context_primitive(0), b"RPT".to_vec())],
            ),
            cons(context_constructed(0), fields),
        ],
    )
}

fn is_zero_entry_id(id: &[u8]) -> bool {
    id.len() == 8 && id.iter().all(|b| *b == 0)
}

fn attr_value(model: &Model, rs: &RcbState, name: &str) -> Option<Value> {
    model
        .device(&rs.domain)?
        .node(&rs.ln_name)?
        .object(&rs.object_name)?
        .attribute(name)?
        .value
        .clone()
}

fn attr_text(model: &Model, rs: &RcbState, name: &str) -> String {
    attr_value(model, rs, name).map(|v| v.text()).unwrap_or_default()
}

fn set_attr(model: &mut Model, rs: &RcbState, name: &str, v: Value) {
    if let Some(a) = model
        .device_mut(&rs.domain)
        .and_then(|ld| ld.node_mut(&rs.ln_name))
        .and_then(|ln| ln.object_mut(&rs.object_name))
        .and_then(|o| o.attribute_mut(name))
    {
        a.value = Some(v);
    }
}

fn trg_ops(model: &Model, rs: &RcbState) -> TrgOps {
    attr_value(model, rs, "TrgOps").map_or(TrgOps(0), |v| TrgOps::from_value(&v))
}

/// Resolves a DatSet value (`LD/LN$DataSet`) to its members, or `None` when
/// the dataset does not exist.
fn resolve_data_set(model: &Model, reference: &str) -> Option<Vec<DsMember>> {
    let (domain, list) = reference.split_once('/')?;
    let (ln_name, ds_name) = list.split_once('$')?;
    model.device(domain)?.node(ln_name)?.data_set(ds_name)?;
    Some(dataset_members(model, domain, list))
}

/// Resolves a dataset member item to its current value.
fn item_value(model: &Model, domain: &str, item: &str) -> Option<Value> {
    let ld = model.device(domain)?;
    let ln_name = item.split('$').next()?;
    let ln = ld.node(ln_name)?;
    access::resolve_read(ln, item)
}

/// Returns the members of a named dataset, in MMS terms.
pub fn dataset_members(model: &Model, domain: &str, list: &str) -> Vec<DsMember> {
    let Some(ld) = model.device(domain) else {
        return Vec::new();
    };
    let Some((ln_name, ds_name)) = list.split_once('$') else {
        return Vec::new();
    };
    let Some(ds) = ld.node(ln_name).and_then(|ln| ln.data_set(ds_name)) else {
        return Vec::new();
    };
    ds.entries
        .iter()
        .map(|e| {
            let (domain, item) = e.reference.to_mms(e.fc);
            DsMember { domain, item }
        })
        .collect()
}

/// Runs `f` against a block with the model and connection locks held, as the
/// timer tasks must.
fn with_block(owner: &Weak<Inner>, key: &str, f: impl FnOnce(&Inner, &mut Model, &ConnMap, &RcbState)) -> bool {
    let Some(inner) = owner.upgrade() else {
        return false; // the server is gone
    };
    let mut model = inner.model.write().unwrap();
    let conns = inner.conns.lock().unwrap();
    let Some(rs) = inner.reports.get(key) else {
        return false;
    };
    f(&inner, &mut model, &conns, rs);
    true
}

/// Emits an integrity report every `period`, while the subscription it was
/// started for lasts.
async fn integrity_loop(owner: Weak<Inner>, key: String, generation: u64, period: Duration) {
    let mut ticker = tokio::time::interval(period);
    // The first tick fires immediately; an integrity report is due after one
    // period, not at enable time.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let mut live = true;
        let found = with_block(&owner, &key, |inner, model, conns, rs| {
            let mut st = rs.state.lock().unwrap();
            if st.integrity_gen != generation || !st.enabled {
                live = false;
                return;
            }
            inner
                .reports
                .report_all(model, conns, rs, &mut st, ReasonCode::INTEGRITY);
        });
        if !found || !live {
            return;
        }
    }
}

/// Closes a buffer-time window after `buf_tm`, unless it was closed first.
async fn buffer_time_window(owner: Weak<Inner>, key: String, generation: u64, buf_tm: Duration) {
    tokio::time::sleep(buf_tm).await;
    with_block(&owner, &key, |inner, model, conns, rs| {
        let mut st = rs.state.lock().unwrap();
        if st.pending_gen == generation {
            st.pending_timer = None;
            inner.reports.flush_pending(model, conns, rs, &mut st);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Fc, ObjectReference};

    fn changes(entries: &[(&str, Fc, TrgOps)]) -> ChangeSet {
        entries
            .iter()
            .map(|(r, fc, t)| ((ObjectReference::new(*r), *fc), *t))
            .collect()
    }

    fn member(domain: &str, item: &str) -> DsMember {
        DsMember {
            domain: domain.into(),
            item: item.into(),
        }
    }

    const DCHG: TrgOps = TrgOps::DATA_CHANGE;

    #[test]
    fn a_member_is_touched_by_a_change_to_itself() {
        let c = changes(&[("LD/GGIO1.Ind1.stVal", Fc::St, DCHG)]);
        assert_eq!(member_reason(&c, &member("LD", "GGIO1$ST$Ind1$stVal")), DCHG);
        assert_eq!(member_reason(&c, &member("LD", "GGIO1$ST$Ind2$stVal")), TrgOps(0));
    }

    /// An FCDA that names a whole data object is the common dataset form, and
    /// updates arrive as the leaves that were written.
    #[test]
    fn a_member_naming_an_object_is_touched_by_a_change_below_it() {
        let c = changes(&[("LD/GGIO1.AnIn1.mag.f", Fc::Mx, DCHG)]);
        assert_eq!(member_reason(&c, &member("LD", "GGIO1$MX$AnIn1")), DCHG);
        assert_eq!(member_reason(&c, &member("LD", "GGIO1$MX$AnIn1$mag")), DCHG);
        assert_eq!(member_reason(&c, &member("LD", "GGIO1$MX$AnIn2")), TrgOps(0));
    }

    /// A member naming a leaf is also touched when a whole object above it is
    /// marked changed.
    #[test]
    fn a_member_naming_a_leaf_is_touched_by_a_change_above_it() {
        let c = changes(&[("LD/GGIO1.AnIn1", Fc::Mx, DCHG)]);
        assert_eq!(member_reason(&c, &member("LD", "GGIO1$MX$AnIn1$mag$f")), DCHG);
    }

    /// Matching on a bare prefix would fire a report for a sibling whose name
    /// merely starts the same way.
    #[test]
    fn a_sibling_with_a_longer_name_does_not_match() {
        let c = changes(&[("LD/XCBR1.PosSomething.stVal", Fc::St, DCHG)]);
        assert_eq!(member_reason(&c, &member("LD", "XCBR1$ST$Pos")), TrgOps(0));
        let c = changes(&[("LD/XCBR1.Pos.stVal", Fc::St, DCHG)]);
        assert_eq!(member_reason(&c, &member("LD", "XCBR1$ST$Pos")), DCHG);
    }

    /// The same reference exists under several functional constraints, and a
    /// change under CF is no change to a member under ST.
    #[test]
    fn a_change_under_another_constraint_does_not_touch_a_member() {
        let c = changes(&[("LD/XCBR1.Pos.ctlModel", Fc::Cf, DCHG)]);
        assert_eq!(member_reason(&c, &member("LD", "XCBR1$ST$Pos")), TrgOps(0));
    }

    /// The reasons of several changes to one member combine.
    #[test]
    fn the_reasons_of_several_changes_combine() {
        let c = changes(&[
            ("LD/GGIO1.Ind1.stVal", Fc::St, DCHG),
            ("LD/GGIO1.Ind1.q", Fc::St, TrgOps::QUALITY_CHANGE),
        ]);
        assert_eq!(
            member_reason(&c, &member("LD", "GGIO1$ST$Ind1")),
            TrgOps(DCHG.0 | TrgOps::QUALITY_CHANGE.0)
        );
    }

    /// The optional-fields value is echoed in the report and tells the client
    /// which fields follow; advertising one the server does not emit shifts
    /// every value after it.
    #[test]
    fn the_optional_fields_are_reduced_to_what_is_actually_emitted() {
        // Segmentation is the server's to set, never the client's to ask for.
        let asked = OptFlds::DEFAULT | OptFlds::SEGMENTATION;
        let got = effective_opt_flds(asked, false);
        assert!(!got.has(OptFlds::SEGMENTATION));
        assert!(got.has(OptFlds::SEQ_NUM));
        assert!(got.has(OptFlds::REASON_CODE));
    }

    /// EntryID and BufOvfl belong to buffered reports; an unbuffered one that
    /// claimed them would misalign every field after the flags.
    #[test]
    fn buffered_only_fields_are_dropped_from_an_unbuffered_report() {
        let asked = OptFlds::DEFAULT | OptFlds::ENTRY_ID | OptFlds::BUF_OVFL;

        let unbuffered = effective_opt_flds(asked, false);
        assert!(!unbuffered.has(OptFlds::ENTRY_ID));
        assert!(!unbuffered.has(OptFlds::BUF_OVFL));

        let buffered = effective_opt_flds(asked, true);
        assert!(buffered.has(OptFlds::ENTRY_ID));
        assert!(buffered.has(OptFlds::BUF_OVFL));
    }

    /// Events merged into one buffer-time report keep dataset order.
    #[test]
    fn merged_events_keep_dataset_order() {
        let entry = |ms: &[usize]| ReportEntry {
            members: ms.to_vec(),
            values: ms.iter().map(|m| Value::int32(*m as i32)).collect(),
            reasons: ms.iter().map(|_| ReasonCode::DATA_CHANGE).collect(),
            ..ReportEntry::new()
        };
        let mut p = entry(&[1, 4]);
        assert!(!p.overlaps(&entry(&[0, 3])));
        assert!(p.overlaps(&entry(&[4])));
        p.merge(entry(&[0, 3]));
        assert_eq!(p.members, [0, 1, 3, 4]);
        let vals: Vec<i64> = p.values.iter().map(Value::as_i64).collect();
        assert_eq!(vals, [0, 1, 3, 4]);
    }
}
