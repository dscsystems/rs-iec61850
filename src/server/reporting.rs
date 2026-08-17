//! Drives report control blocks: enabling, general interrogation,
//! data-change reports on update, buffering and integrity reports.

use std::collections::{BTreeSet, HashMap};
use std::sync::Weak;
use std::time::{Duration, SystemTime};

use crate::asn1::{cons, context_constructed, context_primitive, prim, Element};
use crate::mms::{data_element, Value};
use crate::model::{self, Model, ObjectReference, OptFlds, ReasonCode};

use super::access;
use super::rcb::{self, BufEntry, RcbState};
use super::{ConnId, ConnMap};

/// One dataset member, in MMS terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsMember {
    pub domain: String,
    pub item: String,
}

/// The report fields this server can actually produce.
///
/// Segmentation is absent: reports are sent whole, so `SubSeqNum` and
/// `MoreFollows` are never emitted.
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

/// Reports whether an update touched a dataset member.
///
/// A member may name any level of the tree, so the change has to be matched in
/// both directions. A member naming a leaf is touched by a change to that leaf
/// or to something it sits under. A member naming a data object (the FCDA form
/// that omits the attribute name) is touched by a change to any attribute
/// below it, which is how updates normally arrive, since an update records the
/// leaves it wrote.
pub fn member_changed(changed: &BTreeSet<ObjectReference>, member: &ObjectReference) -> bool {
    // The member itself and every level above it.
    let mut r = Some(member.clone());
    while let Some(current) = r {
        if changed.contains(&current) {
            return true;
        }
        r = current.parent();
    }
    // Anything below it. The trailing separator keeps "Pos" from matching a
    // sibling called "PosSomething".
    let prefix = format!("{member}.");
    changed.iter().any(|c| c.as_str().starts_with(&prefix))
}

/// The report engine.
#[derive(Debug)]
pub struct ReportManager {
    registry: HashMap<String, RcbState>,
}

impl ReportManager {
    /// Materialises every control block in the model and returns the engine.
    pub fn new(model: &mut Model, buf_default: usize) -> ReportManager {
        ReportManager {
            registry: rcb::materialise_rcbs(model, buf_default),
        }
    }

    /// Returns the control block registered under a key, if any.
    pub fn get(&self, key: &str) -> Option<&RcbState> {
        self.registry.get(key)
    }

    /// Reacts to a client write of a control-block attribute.
    ///
    /// `owner` is the server, needed only to schedule the integrity task.
    // The engine needs the model, the connection table, the address of the
    // block and what was written to it; bundling them would only move the list
    // to a struct nothing else constructs.
    #[allow(clippy::too_many_arguments)]
    pub fn on_rcb_write(
        &self,
        owner: &Weak<super::Inner>,
        model: &mut Model,
        conns: &ConnMap,
        domain: &str,
        item: &str,
        attr: &str,
        v: &Value,
        conn: ConnId,
    ) {
        let Some((key, _)) = rcb::rcb_key(domain, item) else {
            return;
        };
        let Some(rs) = self.registry.get(&key) else {
            return;
        };
        match attr {
            "RptEna" => {
                if v.as_bool() {
                    self.enable(owner, model, conns, rs, conn);
                } else {
                    disable(rs);
                }
            }
            "GI" => {
                if v.as_bool() {
                    let all = self.all_indices(model, rs);
                    self.send_report(model, conns, rs, Some(conn), &all, ReasonCode::GI);
                }
            }
            // A buffered resync: remember the requested EntryID, and on the
            // next enable delivery resumes after it.
            "EntryID" => {
                rs.state.lock().unwrap().resync_id = Some(v.bytes().to_vec());
            }
            "PurgeBuf"
                if v.as_bool() => {
                    let mut st = rs.state.lock().unwrap();
                    st.buffer.clear();
                    st.buf_overflow = false;
                }
            _ => {}
        }
    }

    fn enable(
        &self,
        owner: &Weak<super::Inner>,
        model: &mut Model,
        conns: &ConnMap,
        rs: &RcbState,
        conn: ConnId,
    ) {
        let (flush, intg) = {
            let mut st = rs.state.lock().unwrap();
            st.enabled = true;
            st.conn = Some(conn);
            st.seq_num = 0;
            if let Some(h) = st.integrity.take() {
                h.abort();
            }
            let flush = pending(&mut st, rs.max_buffer);
            drop(st);
            let intg = self.intg_pd(model, rs);
            (flush, intg)
        };

        if !intg.is_zero() {
            let handle = tokio::spawn(integrity_loop(
                owner.clone(),
                rs.domain.clone(),
                rs.item.clone(),
                conn,
                intg,
            ));
            rs.state.lock().unwrap().integrity = Some(handle.abort_handle());
        }

        // Flush the buffered reports the subscriber missed.
        if let Some(sc) = conns.get(&conn) {
            for e in flush {
                if sc.send_unconfirmed(e.element).is_err() {
                    tracing::debug!(rcb = %rs.item, "server: buffered report send failed");
                    break;
                }
            }
        }
    }

    /// Disables every control block bound to a closing connection.
    pub fn disable_conn(&self, conn: ConnId) {
        for rs in self.registry.values() {
            let mut st = rs.state.lock().unwrap();
            if st.conn == Some(conn) {
                st.enabled = false;
                st.conn = None;
                if let Some(h) = st.integrity.take() {
                    h.abort();
                }
            }
        }
    }

    /// Stops every integrity task, for server shutdown.
    pub fn shutdown(&self) {
        for rs in self.registry.values() {
            let mut st = rs.state.lock().unwrap();
            st.enabled = false;
            st.conn = None;
            if let Some(h) = st.integrity.take() {
                h.abort();
            }
        }
    }

    /// Emits data-change reports for enabled blocks whose dataset includes any
    /// changed member.
    pub fn on_update(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        changed: &BTreeSet<ObjectReference>,
    ) {
        if changed.is_empty() {
            return;
        }
        // Collect first, so the model borrow is not held across the sends.
        let mut work: Vec<(&RcbState, Option<ConnId>, Vec<usize>)> = Vec::new();
        for rs in self.registry.values() {
            let (enabled, conn) = {
                let st = rs.state.lock().unwrap();
                (st.enabled, st.conn)
            };
            // An unbuffered block only reports while enabled; a buffered one
            // always captures events so they can be delivered on a later
            // enable.
            if !rs.buffered && (!enabled || conn.is_none()) {
                continue;
            }
            let members = self.members(model, rs);
            let included: Vec<usize> = members
                .iter()
                .enumerate()
                .filter(|(_, m)| {
                    let (reference, _) = model::from_mms(&m.domain, &m.item);
                    member_changed(changed, &reference)
                })
                .map(|(i, _)| i)
                .collect();
            if !included.is_empty() {
                work.push((rs, conn, included));
            }
        }
        for (rs, conn, included) in work {
            self.send_report(model, conns, rs, conn, &included, ReasonCode::DATA_CHANGE);
        }
    }

    fn all_indices(&self, model: &Model, rs: &RcbState) -> Vec<usize> {
        (0..self.members(model, rs).len()).collect()
    }

    /// Encodes a report for the included members.
    ///
    /// Unbuffered reports are transmitted immediately. Buffered reports are
    /// always appended to the block's buffer with an EntryID and, when a
    /// subscriber is enabled, also transmitted.
    pub fn send_report(
        &self,
        model: &mut Model,
        conns: &ConnMap,
        rs: &RcbState,
        conn: Option<ConnId>,
        included: &[usize],
        reason: ReasonCode,
    ) {
        if included.is_empty() {
            return;
        }
        let members = self.members(model, rs);
        let buffered = rs.buffered;
        let opt = effective_opt_flds(
            OptFlds::from_value(&self.attr_value(model, rs, "OptFlds")),
            buffered,
        );

        let (seq, entry_id, buf_ovfl) = {
            let mut st = rs.state.lock().unwrap();
            let seq = st.seq_num;
            st.seq_num = st.seq_num.wrapping_add(1);
            if buffered {
                st.entry_counter += 1;
                let id = rcb::make_entry_id(st.entry_counter);
                let ovfl = st.buf_overflow;
                st.buf_overflow = false;
                (seq, id, ovfl)
            } else {
                (seq, Vec::new(), false)
            }
        };

        let now = SystemTime::now();
        let mut fields: Vec<Element> = Vec::new();
        let mut add = |v: Value| {
            if let Some(el) = data_element(&v) {
                fields.push(el);
            }
        };

        add(self.attr_value(model, rs, "RptID"));
        add(opt.value());
        if opt.has(OptFlds::SEQ_NUM) {
            add(Value::uint32(seq));
        }
        if opt.has(OptFlds::TIME_OF_ENTRY) {
            add(Value::binary_time(now));
        }
        if opt.has(OptFlds::DATA_SET_NAME) {
            add(self.attr_value(model, rs, "DatSet"));
        }
        if opt.has(OptFlds::BUF_OVFL) {
            add(Value::boolean(buf_ovfl));
        }
        if opt.has(OptFlds::ENTRY_ID) {
            add(Value::octet_string(entry_id.clone()));
        }
        if opt.has(OptFlds::CONF_REV) {
            add(self.attr_value(model, rs, "ConfRev"));
        }

        // The inclusion bit string carries one bit per dataset member.
        let mut inclusion = Value::bit_string(members.len());
        for idx in included {
            inclusion.set_bit(*idx, true);
        }
        add(inclusion);

        // Data references, one per included member, precede the values
        // (IEC 61850-8-1): the MMS form of the member's reference.
        if opt.has(OptFlds::DATA_REF) {
            for idx in included {
                if let Some(m) = members.get(*idx) {
                    add(Value::visible_string(format!("{}/{}", m.domain, m.item)));
                }
            }
        }
        // Member values, in dataset order, for the included members only.
        for idx in included {
            let v = members
                .get(*idx)
                .and_then(|m| item_value(model, &m.domain, &m.item))
                .unwrap_or(Value::boolean(false));
            add(v);
        }
        if opt.has(OptFlds::REASON_CODE) {
            for _ in included {
                add(reason.value());
            }
        }

        // InformationReport [0] {
        //   variableListName [1] { vmd-specific "RPT" },
        //   listOfAccessResult [0] }
        let report = cons(
            context_constructed(0),
            [
                cons(
                    context_constructed(1),
                    [prim(context_primitive(0), b"RPT".to_vec())],
                ),
                cons(context_constructed(0), fields),
            ],
        );

        if buffered {
            {
                let mut st = rs.state.lock().unwrap();
                st.buffer.push(BufEntry {
                    id: entry_id.clone(),
                    element: report.clone(),
                });
                // The oldest entries go first, and their loss is what BufOvfl
                // tells the next subscriber about.
                while st.buffer.len() > rs.max_buffer {
                    st.buffer.remove(0);
                    st.buf_overflow = true;
                }
            }
            // Reflect the latest entry into the model, so a client reading the
            // block sees where the buffer has reached.
            if let Some(object) = model
                .device_mut(&rs.domain)
                .and_then(|ld| ld.node_mut(&rs.ln_name))
                .and_then(|ln| ln.object_mut(&rs.object_name))
            {
                if let Some(a) = object.attribute_mut("EntryID") {
                    a.value = Some(Value::octet_string(entry_id));
                }
                if let Some(a) = object.attribute_mut("TimeofEntry") {
                    a.value = Some(Value::binary_time(now));
                }
            }
        }

        // A buffered report with no subscriber stays in the buffer and is
        // flushed on the next enable.
        let Some(conn) = conn else { return };
        if let Some(sc) = conns.get(&conn) {
            if sc.send_unconfirmed(report).is_err() {
                // The queue is saturated, which is the buffer-overflow
                // condition the protocol models; a buffered block records it
                // so the next subscriber learns it missed entries.
                tracing::debug!(rcb = %rs.item, "server: report send failed");
                if buffered {
                    rs.state.lock().unwrap().buf_overflow = true;
                }
            }
        }
    }

    /// Returns the dataset members of a control block.
    pub fn members(&self, model: &Model, rs: &RcbState) -> Vec<DsMember> {
        if rs.data_set.is_empty() {
            return Vec::new();
        }
        dataset_members(model, &rs.domain, &format!("{}${}", rs.ln_name, rs.data_set))
    }

    fn attr_value(&self, model: &Model, rs: &RcbState, name: &str) -> Value {
        model
            .device(&rs.domain)
            .and_then(|ld| ld.node(&rs.ln_name))
            .map(|ln| rcb::rcb_attr_value(ln, &rs.object_name, name))
            .unwrap_or(Value::boolean(false))
    }

    fn intg_pd(&self, model: &Model, rs: &RcbState) -> Duration {
        Duration::from_millis(self.attr_value(model, rs, "IntgPd").as_u64())
    }
}

fn disable(rs: &RcbState) {
    let mut st = rs.state.lock().unwrap();
    st.enabled = false;
    st.conn = None;
    if let Some(h) = st.integrity.take() {
        h.abort();
    }
}

/// Returns the buffered entries to deliver on enable and clears the resync
/// request.
///
/// With a resync EntryID set, only entries after it are returned; when that
/// EntryID is no longer in the buffer the whole buffer is sent and the
/// overflow flag is raised, which is how the client learns it lost entries.
fn pending(st: &mut super::rcb::RcbRuntime, _max: usize) -> Vec<BufEntry> {
    if st.buffer.is_empty() {
        st.resync_id = None;
        return Vec::new();
    }
    let mut start = 0;
    if let Some(id) = st.resync_id.take() {
        if id.len() == 8 {
            match st.buffer.iter().position(|e| e.id == id) {
                Some(i) => start = i + 1,
                None => st.buf_overflow = true, // the resync point was purged
            }
        }
    }
    st.buffer[start..].to_vec()
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

/// Emits an integrity report every `period` until the task is aborted.
async fn integrity_loop(
    owner: Weak<super::Inner>,
    domain: String,
    item: String,
    conn: ConnId,
    period: Duration,
) {
    let mut ticker = tokio::time::interval(period);
    // The first tick fires immediately; an integrity report is due after one
    // period, not at enable time.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        let Some(inner) = owner.upgrade() else {
            return; // the server is gone
        };
        let key = RcbState::key(&domain, &item);
        // The whole emission is done under the model write lock, since a
        // buffered block records its EntryID back into the model.
        let mut model = inner.model.write().unwrap();
        let conns = inner.conns.lock().unwrap();
        let Some(rs) = inner.reports.get(&key) else {
            return;
        };
        if !rs.state.lock().unwrap().enabled {
            return;
        }
        let all = inner.reports.all_indices(&model, rs);
        inner.reports.send_report(
            &mut model,
            &conns,
            rs,
            Some(conn),
            &all,
            ReasonCode::INTEGRITY,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn changed(refs: &[&str]) -> BTreeSet<ObjectReference> {
        refs.iter().map(|r| ObjectReference::new(*r)).collect()
    }

    #[test]
    fn a_member_is_touched_by_a_change_to_itself() {
        let c = changed(&["LD/GGIO1.Ind1.stVal"]);
        assert!(member_changed(&c, &"LD/GGIO1.Ind1.stVal".into()));
        assert!(!member_changed(&c, &"LD/GGIO1.Ind2.stVal".into()));
    }

    /// An FCDA that names a whole data object is the common dataset form, and
    /// updates arrive as the leaves that were written.
    #[test]
    fn a_member_naming_an_object_is_touched_by_a_change_below_it() {
        let c = changed(&["LD/GGIO1.AnIn1.mag.f"]);
        assert!(member_changed(&c, &"LD/GGIO1.AnIn1".into()));
        assert!(member_changed(&c, &"LD/GGIO1.AnIn1.mag".into()));
        assert!(!member_changed(&c, &"LD/GGIO1.AnIn2".into()));
    }

    /// A member naming a leaf is also touched when a whole object above it is
    /// marked changed.
    #[test]
    fn a_member_naming_a_leaf_is_touched_by_a_change_above_it() {
        let c = changed(&["LD/GGIO1.AnIn1"]);
        assert!(member_changed(&c, &"LD/GGIO1.AnIn1.mag.f".into()));
    }

    /// Matching on a bare prefix would fire a report for a sibling whose name
    /// merely starts the same way.
    #[test]
    fn a_sibling_with_a_longer_name_does_not_match() {
        let c = changed(&["LD/XCBR1.PosSomething.stVal"]);
        assert!(!member_changed(&c, &"LD/XCBR1.Pos".into()));

        let c = changed(&["LD/XCBR1.Pos.stVal"]);
        assert!(member_changed(&c, &"LD/XCBR1.Pos".into()));
    }

    #[test]
    fn nothing_changed_touches_nothing() {
        let c = BTreeSet::new();
        assert!(!member_changed(&c, &"LD/GGIO1.Ind1.stVal".into()));
    }

    /// The optional-fields value is echoed in the report and tells the client
    /// which fields follow; advertising one the server does not emit shifts
    /// every value after it.
    #[test]
    fn the_optional_fields_are_reduced_to_what_is_actually_emitted() {
        // Segmentation is never produced.
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

    #[test]
    fn a_resync_point_in_the_buffer_delivers_only_what_follows_it() {
        let mut st = super::super::rcb::RcbRuntime {
            buffer: (1..=5)
                .map(|i| BufEntry {
                    id: rcb::make_entry_id(i),
                    element: prim(context_primitive(0), vec![i as u8]),
                })
                .collect(),
            ..Default::default()
        };
        st.resync_id = Some(rcb::make_entry_id(3));

        let out = pending(&mut st, 256);
        assert_eq!(out.len(), 2, "entries 4 and 5 follow entry 3");
        assert_eq!(out[0].id, rcb::make_entry_id(4));
        assert!(!st.buf_overflow, "nothing was lost");
        assert!(st.resync_id.is_none(), "the request is consumed");
    }

    /// A resync point the buffer has already discarded means the client
    /// missed entries, which is exactly what BufOvfl reports.
    #[test]
    fn a_purged_resync_point_flushes_everything_and_flags_the_overflow() {
        let mut st = super::super::rcb::RcbRuntime {
            buffer: (10..=12)
                .map(|i| BufEntry {
                    id: rcb::make_entry_id(i),
                    element: prim(context_primitive(0), vec![i as u8]),
                })
                .collect(),
            ..Default::default()
        };
        st.resync_id = Some(rcb::make_entry_id(3));

        let out = pending(&mut st, 256);
        assert_eq!(out.len(), 3, "the whole buffer is sent");
        assert!(st.buf_overflow, "the client must learn it lost entries");
    }

    #[test]
    fn enabling_with_no_resync_point_flushes_the_whole_buffer() {
        let mut st = super::super::rcb::RcbRuntime {
            buffer: (1..=3)
                .map(|i| BufEntry {
                    id: rcb::make_entry_id(i),
                    element: prim(context_primitive(0), vec![i as u8]),
                })
                .collect(),
            ..Default::default()
        };
        assert_eq!(pending(&mut st, 256).len(), 3);
        assert!(!st.buf_overflow);
    }

    #[test]
    fn an_empty_buffer_flushes_nothing_and_clears_any_request() {
        let mut st = super::super::rcb::RcbRuntime {
            resync_id: Some(rcb::make_entry_id(1)),
            ..Default::default()
        };
        assert!(pending(&mut st, 256).is_empty());
        assert!(st.resync_id.is_none());
    }
}
