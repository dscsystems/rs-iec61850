//! Logs (IEC 61850-7-2 clause 14), served as MMS journals (IEC 61850-8-1
//! clause 17).
//!
//! A log named `Name` in logical node `LN` of device `LD` is the journal
//! `LN$Name` in domain `LD`. A log control block writes into one log the
//! members of its dataset that change, and periodically all of them when it
//! has an integrity period. A client finds the logs with GetNameList (class
//! journal) and reads them with ReadJournal.
//!
//! Everything here runs under the server's model lock: a log is written where
//! the model changes, under the write lock, and read under the read lock, so an
//! entry is never seen half-written and a log's control blocks always describe
//! what it holds.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, Weak};
use std::time::{Duration, SystemTime};

use crate::asn1::{self, bool_elem, cons, context_constructed, context_primitive, prim, Decoder, Element, TAG_SEQUENCE};
use crate::mms::{self, data_element, DataAccessError, Value};
use crate::model::{Fc, Model, ReasonCode, TrgOps};

use super::cb;
use super::reporting::{self, DsMember, ReportManager};
use super::server::Inner;
use super::tx::ChangeSet;

/// How many entries a log keeps when the server sets no capacity: the oldest
/// are discarded past it.
pub const DEFAULT_LOG_CAPACITY: usize = 1024;

/// The variable tag of the reason code that follows each logged value when the
/// log control block asks for reasons.
pub(crate) const REASON_CODE_TAG: &str = "ReasonCode";

/// One log entry: the members that were logged together, with the reason each
/// was logged when the control block asks for it.
#[derive(Debug, Clone)]
pub(crate) struct LogEntry {
    /// The 8-octet EntryID, unique within the server.
    pub id: Vec<u8>,
    /// At millisecond precision, as it goes on the wire.
    pub time: SystemTime,
    pub vars: Vec<(String, Value)>,
}

/// One log.
#[derive(Debug, Default)]
pub(crate) struct Journal {
    pub entries: Vec<LogEntry>,
}

/// The runtime state of one log control block.
#[derive(Debug)]
struct LcbState {
    domain: String,
    ln: String,
    name: String,
    reason_code: bool,
    /// The log it writes, `None` when it names none.
    journal: Option<(String, String)>,
    /// Cancels the integrity task, when one runs.
    intg: Option<tokio::task::AbortHandle>,
    intg_gen: u64,
}

#[derive(Debug, Default)]
struct LogState {
    /// By domain and journal name.
    journals: BTreeMap<(String, String), Journal>,
    lcbs: BTreeMap<String, LcbState>,
}

/// Holds a server's logs and the control blocks that write them.
#[derive(Debug)]
pub struct LogManager {
    capacity: usize,
    state: Mutex<LogState>,
    owner: OnceLock<Weak<Inner>>,
}

fn lcb_key_of(domain: &str, item: &str) -> String {
    format!("{domain}\u{0}{item}")
}

impl LogManager {
    /// Creates the logs the model declares or its log control blocks write to.
    pub(crate) fn new(model: &Model, capacity: usize) -> LogManager {
        let mut st = LogState::default();
        for ld in &model.devices {
            for ln in &ld.nodes {
                for name in &ln.logs {
                    st.journals
                        .entry((ld.name.clone(), format!("{}${name}", ln.name)))
                        .or_default();
                }
            }
        }
        for ld in &model.devices {
            for ln in &ld.nodes {
                for lc in &ln.log_controls {
                    if cb::cb_object(ld, &ln.name, "LG", &lc.name).is_none() {
                        continue;
                    }
                    let journal = cb::log_target(&ld.name, &ld.inst, lc);
                    if let Some(j) = &journal {
                        st.journals.entry(j.clone()).or_default();
                    }
                    let item = format!("{}$LG${}", ln.name, lc.name);
                    st.lcbs.insert(
                        lcb_key_of(&ld.name, &item),
                        LcbState {
                            domain: ld.name.clone(),
                            ln: ln.name.clone(),
                            name: lc.name.clone(),
                            reason_code: lc.reason_code,
                            journal,
                            intg: None,
                            intg_gen: 0,
                        },
                    );
                }
            }
        }
        LogManager {
            capacity: if capacity == 0 { DEFAULT_LOG_CAPACITY } else { capacity },
            state: Mutex::new(st),
            owner: OnceLock::new(),
        }
    }

    /// Ties the manager to its server and starts the blocks the configuration
    /// enables.
    pub(crate) fn start(&self, owner: Weak<Inner>, model: &Model) {
        let _ = self.owner.set(owner);
        let mut st = self.state.lock().unwrap();
        let keys: Vec<String> = st.lcbs.keys().cloned().collect();
        for k in keys {
            let lcb = st.lcbs.get_mut(&k).expect("listed");
            if enabled(model, lcb) {
                self.start_integrity(model, &k, lcb);
            }
        }
    }

    /// Reports whether the model has any log.
    pub(crate) fn has_logs(&self) -> bool {
        !self.state.lock().unwrap().journals.is_empty()
    }

    /// Lists the logs of a domain, for GetNameList.
    pub(crate) fn names(&self, domain: &str) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .journals
            .keys()
            .filter(|(d, _)| d == domain)
            .map(|(_, n)| n.clone())
            .collect()
    }

    /// Runs `f` on a journal, `None` when there is none of that name.
    pub(crate) fn with_journal<R>(
        &self,
        domain: &str,
        name: &str,
        f: impl FnOnce(&mut Journal) -> R,
    ) -> Option<R> {
        let mut st = self.state.lock().unwrap();
        st.journals
            .get_mut(&(domain.to_string(), name.to_string()))
            .map(f)
    }

    /// Logs the changes of an update or a client write into every enabled
    /// block's log, one entry per block holding the members whose changes its
    /// TrgOps asks for. Called with the model write lock held.
    pub(crate) fn on_update(&self, model: &mut Model, reports: &ReportManager, changes: &ChangeSet) {
        if changes.is_empty() {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let triggers = TrgOps::DATA_CHANGE.0 | TrgOps::QUALITY_CHANGE.0 | TrgOps::DATA_UPDATE.0;
        let mut writes = Vec::new();
        for lcb in st.lcbs.values() {
            let Some(j) = &lcb.journal else { continue };
            if !enabled(model, lcb) {
                continue;
            }
            let want = trg_ops(model, lcb).0 & triggers;
            let Some(members) = reporting::resolve_data_set(model, &dat_set(model, lcb)) else {
                continue;
            };
            let mut vars = Vec::new();
            for m in &members {
                let r = reporting::member_reason(changes, m).0 & want;
                if r != 0 {
                    append_member(model, &mut vars, lcb, m, ReasonCode(r));
                }
            }
            if !vars.is_empty() {
                writes.push((j.clone(), vars));
            }
        }
        for (j, vars) in writes {
            self.append(&mut st, model, reports, &j, vars);
        }
    }

    /// Logs every member of the block's dataset, for an integrity period.
    fn log_all(&self, model: &mut Model, reports: &ReportManager, key: &str, generation: u64) -> bool {
        let mut st = self.state.lock().unwrap();
        let Some(lcb) = st.lcbs.get(key) else {
            return false;
        };
        if lcb.intg_gen != generation {
            return false;
        }
        let Some(j) = lcb.journal.clone() else {
            return false;
        };
        let members = reporting::resolve_data_set(model, &dat_set(model, lcb)).unwrap_or_default();
        let mut vars = Vec::new();
        for m in &members {
            append_member(model, &mut vars, lcb, m, ReasonCode::INTEGRITY);
        }
        self.append(&mut st, model, reports, &j, vars);
        true
    }

    /// Adds an entry to a log, discards the oldest past its capacity, and
    /// brings the control blocks that describe it up to date.
    fn append(
        &self,
        st: &mut LogState,
        model: &mut Model,
        reports: &ReportManager,
        j: &(String, String),
        vars: Vec<(String, Value)>,
    ) {
        if vars.is_empty() {
            return;
        }
        let Some(journal) = st.journals.get_mut(j) else {
            return;
        };
        let (secs, nanos) = crate::time_util::unix_parts(SystemTime::now());
        journal.entries.push(LogEntry {
            id: reports.next_entry_id(),
            time: crate::time_util::from_unix(secs, nanos / 1_000_000 * 1_000_000),
            vars,
        });
        let over = journal.entries.len().saturating_sub(self.capacity);
        if over > 0 {
            journal.entries.drain(..over);
        }
        sync(st, model, j);
    }

    /// Sets the entry range of every block writing to `j` after its entries
    /// changed.
    pub(crate) fn sync_journal(&self, model: &mut Model, domain: &str, name: &str) {
        let st = self.state.lock().unwrap();
        sync(&st, model, &(domain.to_string(), name.to_string()));
    }

    /// Reports whether `item` (`LN$LG$name[$attr]`) addresses a log control
    /// block this server runs, returning its key and the attribute.
    pub(crate) fn lcb_key(&self, domain: &str, item: &str) -> Option<(String, String)> {
        let parts: Vec<&str> = item.split('$').collect();
        if parts.len() < 3 || parts[1] != "LG" {
            return None;
        }
        let key = lcb_key_of(domain, &format!("{}$LG${}", parts[0], parts[2]));
        if !self.state.lock().unwrap().lcbs.contains_key(&key) {
            return None;
        }
        Some((key, parts.get(3).copied().unwrap_or("").to_string()))
    }

    /// Decides whether a client may write `attr` of a log control block,
    /// before anything is stored.
    ///
    /// `LogEna`, `DatSet`, `TrgOps` and `IntgPd` are the client's to set
    /// (IEC 61850-7-2 SetLCBValues); the configuration only while logging is
    /// off, so an entry is never logged under a configuration the log does not
    /// describe. The rest is the server's.
    pub(crate) fn check_lcb_write(
        &self,
        model: &Model,
        key: &str,
        attr: &str,
        v: &Value,
    ) -> Result<(), DataAccessError> {
        let st = self.state.lock().unwrap();
        let lcb = st.lcbs.get(key).ok_or(DataAccessError::ObjectNonExistent)?;
        match attr {
            "LogEna" => {
                if v.as_bool()
                    && (lcb.journal.is_none()
                        || reporting::resolve_data_set(model, &dat_set(model, lcb)).is_none())
                {
                    return Err(DataAccessError::TemporarilyUnavailable);
                }
                Ok(())
            }
            "DatSet" | "TrgOps" | "IntgPd" => {
                if enabled(model, lcb) {
                    return Err(DataAccessError::TemporarilyUnavailable);
                }
                if attr == "DatSet"
                    && !v.text().is_empty()
                    && reporting::resolve_data_set(model, &v.text()).is_none()
                {
                    return Err(DataAccessError::ObjectValueInvalid);
                }
                Ok(())
            }
            _ => Err(DataAccessError::ObjectAccessDenied),
        }
    }

    /// Applies a stored LCB write: enabling starts the integrity task and
    /// disabling stops it. Called with the model write lock held.
    pub(crate) fn on_lcb_write(&self, model: &Model, key: &str, attr: &str) {
        if attr != "LogEna" {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let Some(lcb) = st.lcbs.get_mut(key) else {
            return;
        };
        if enabled(model, lcb) {
            self.start_integrity(model, key, lcb);
        } else {
            stop_integrity(lcb);
        }
    }

    /// Reports whether a log control block names the data set `reference`
    /// (`LD/LN$DS`) as its DatSet.
    pub(crate) fn uses_data_set(&self, model: &Model, reference: &str) -> bool {
        self.state
            .lock()
            .unwrap()
            .lcbs
            .values()
            .any(|lcb| dat_set(model, lcb) == reference)
    }

    /// Stops every integrity task, for server shutdown.
    pub(crate) fn close(&self) {
        for lcb in self.state.lock().unwrap().lcbs.values_mut() {
            stop_integrity(lcb);
        }
    }

    fn start_integrity(&self, model: &Model, key: &str, lcb: &mut LcbState) {
        stop_integrity(lcb);
        let pd = Duration::from_millis(
            lcb_attr(model, lcb, "IntgPd").map_or(0, |v| v.as_u64()),
        );
        if pd.is_zero() || !trg_ops(model, lcb).has(TrgOps::INTEGRITY) || lcb.journal.is_none() {
            return;
        }
        let Some(owner) = self.owner.get().cloned() else {
            return;
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let generation = lcb.intg_gen;
        let key = key.to_string();
        lcb.intg = Some(
            rt.spawn(async move {
                let mut ticker = tokio::time::interval(pd);
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    let Some(inner) = owner.upgrade() else { return };
                    let mut model = inner.model.write().unwrap();
                    if !inner.logs.log_all(&mut model, &inner.reports, &key, generation) {
                        return;
                    }
                }
            })
            .abort_handle(),
        );
    }
}

fn stop_integrity(lcb: &mut LcbState) {
    if let Some(h) = lcb.intg.take() {
        h.abort();
    }
    lcb.intg_gen += 1;
}

fn lcb_attr(model: &Model, lcb: &LcbState, name: &str) -> Option<Value> {
    model
        .device(&lcb.domain)?
        .node(&lcb.ln)?
        .object(&lcb.name)?
        .attributes
        .iter()
        .find(|a| a.name == name && a.fc == Fc::Lg)?
        .value
        .clone()
}

fn set_lcb_attr(model: &mut Model, lcb: &LcbState, name: &str, v: Value) {
    if let Some(a) = model
        .device_mut(&lcb.domain)
        .and_then(|ld| ld.node_mut(&lcb.ln))
        .and_then(|ln| ln.object_mut(&lcb.name))
        .and_then(|o| o.attribute_mut(name))
    {
        a.value = Some(v);
    }
}

fn enabled(model: &Model, lcb: &LcbState) -> bool {
    lcb_attr(model, lcb, "LogEna").is_some_and(|v| v.as_bool())
}

fn trg_ops(model: &Model, lcb: &LcbState) -> TrgOps {
    lcb_attr(model, lcb, "TrgOps").map_or(TrgOps(0), |v| TrgOps::from_value(&v))
}

fn dat_set(model: &Model, lcb: &LcbState) -> String {
    lcb_attr(model, lcb, "DatSet").map(|v| v.text()).unwrap_or_default()
}

/// Adds one member's value, and its reason when the block logs reasons, to an
/// entry's variables.
fn append_member(
    model: &Model,
    vars: &mut Vec<(String, Value)>,
    lcb: &LcbState,
    m: &DsMember,
    reason: ReasonCode,
) {
    let Some(v) = reporting::item_value(model, &m.domain, &m.item) else {
        return;
    };
    vars.push((format!("{}/{}", m.domain, m.item), v));
    if lcb.reason_code {
        vars.push((REASON_CODE_TAG.to_string(), reason.value()));
    }
}

/// Sets the entry range of every block writing to `j`: the oldest and newest
/// entry and their times (IEC 61850-8-1 OldEntrTm, NewEntrTm, OldEnt,
/// NewEnt).
fn sync(st: &LogState, model: &mut Model, j: &(String, String)) {
    let Some(journal) = st.journals.get(j) else {
        return;
    };
    let (Some(oldest), Some(newest)) = (journal.entries.first(), journal.entries.last()) else {
        return;
    };
    for lcb in st.lcbs.values() {
        if lcb.journal.as_ref() != Some(j) {
            continue;
        }
        set_lcb_attr(model, lcb, "OldEntrTm", Value::binary_time(oldest.time));
        set_lcb_attr(model, lcb, "NewEntrTm", Value::binary_time(newest.time));
        set_lcb_attr(model, lcb, "OldEnt", Value::octet_string(oldest.id.clone()));
        set_lcb_attr(model, lcb, "NewEnt", Value::octet_string(newest.id.clone()));
    }
}

/// A parsed ReadJournal request (ISO 9506-2).
#[derive(Debug, Default)]
pub(crate) struct JournalQuery {
    pub domain: String,
    pub name: String,
    start_time: Option<SystemTime>,
    start_entry: Option<Vec<u8>>,
    stop_time: Option<SystemTime>,
    count: usize,
    after_time: Option<SystemTime>,
    after_entry: Option<Vec<u8>>,
    variables: Option<Vec<String>>,
}

fn time_of(b: &[u8]) -> mms::Result<SystemTime> {
    Value::binary_time_raw(b)?
        .time()
        .ok_or_else(|| mms::Error::protocol("undecodable TimeOfDay"))
}

/// Decodes a ReadJournal-Request:
///
/// ```text
/// journalName [0] ObjectName,
/// rangeStartSpecification [1] CHOICE { startingTime [0], startingEntry [1] } OPTIONAL,
/// rangeStopSpecification [2] CHOICE { endingTime [0], numberOfEntries [1] } OPTIONAL,
/// listOfVariables [4] SEQUENCE OF VisibleString OPTIONAL,
/// entryToStartAfter [5] SEQUENCE { timeSpecification [0], entrySpecification [1] } OPTIONAL
/// ```
///
/// Earlier versions of this crate's client sent entryToStartAfter as [3],
/// which is accepted too rather than refusing them.
pub(crate) fn parse_journal_query(content: &[u8]) -> mms::Result<JournalQuery> {
    let mut dec = Decoder::new(content);
    let name = dec.expect(context_constructed(0))?;
    let (domain, item) = super::handler::parse_object_name(name)?;
    let mut q = JournalQuery {
        domain,
        name: item,
        ..Default::default()
    };
    while dec.more() {
        let (tag, c) = dec.read_tlv()?;
        if tag == context_constructed(1) || tag == context_constructed(2) {
            let start = tag == context_constructed(1);
            let (ct, cv) = Decoder::new(c).read_tlv()?;
            if ct == context_primitive(0) {
                if start {
                    q.start_time = Some(time_of(cv)?);
                } else {
                    q.stop_time = Some(time_of(cv)?);
                }
            } else if ct == context_primitive(1) {
                if start {
                    q.start_entry = Some(cv.to_vec());
                } else {
                    q.count = asn1::decode_int(cv)?.max(0) as usize;
                }
            }
        } else if tag == context_constructed(4) {
            let mut vars = Vec::new();
            let mut ld = Decoder::new(c);
            while ld.more() {
                let (_, s) = ld.read_tlv()?;
                vars.push(String::from_utf8_lossy(s).into_owned());
            }
            q.variables = Some(vars);
        } else if tag == context_constructed(5) || tag == context_constructed(3) {
            let mut ad = Decoder::new(c);
            while ad.more() {
                let (at, av) = ad.read_tlv()?;
                if at == context_primitive(0) {
                    q.after_time = Some(time_of(av)?);
                } else if at == context_primitive(1) {
                    q.after_entry = Some(av.to_vec());
                }
            }
        }
    }
    Ok(q)
}

impl JournalQuery {
    /// Returns the entries of `j` the query asks for, in order.
    pub(crate) fn select<'a>(&self, j: &'a Journal) -> Vec<&'a LogEntry> {
        let index_of = |id: &[u8]| j.entries.iter().position(|e| e.id == id);
        let mut from = 0;
        if let Some(after) = &self.after_entry {
            // Continue after an entry the client has; an entry the log no
            // longer holds continues after its time instead.
            if let Some(i) = index_of(after) {
                from = i + 1;
            } else if let Some(t) = self.after_time {
                from = j
                    .entries
                    .iter()
                    .position(|e| e.time > t)
                    .unwrap_or(j.entries.len());
            }
        } else if let Some(start) = &self.start_entry {
            match index_of(start) {
                Some(i) => from = i,
                None => return Vec::new(),
            }
        } else if let Some(t) = self.start_time {
            from = j
                .entries
                .iter()
                .position(|e| e.time >= t)
                .unwrap_or(j.entries.len());
        }
        let mut out = Vec::new();
        for e in &j.entries[from..] {
            if self.stop_time.is_some_and(|t| e.time > t) {
                break;
            }
            if self.count > 0 && out.len() >= self.count {
                break;
            }
            out.push(e);
        }
        out
    }

    /// Encodes one JournalEntry (ISO 9506-2):
    ///
    /// ```text
    /// SEQUENCE { entryIdentifier [0] OCTET STRING,
    ///            originatingApplication [1] ApplicationReference,
    ///            entryContent [2] SEQUENCE {
    ///                occurrenceTime [0] TimeOfDay,
    ///                data [2] SEQUENCE { listOfVariables [1] SEQUENCE OF
    ///                    SEQUENCE { variableTag [0] VisibleString, valueSpecification [1] Data } } } }
    /// ```
    ///
    /// A query naming variables keeps only those and the reason code that
    /// follows each.
    pub(crate) fn entry_element(&self, e: &LogEntry) -> Element {
        let mut list = Element::seq(context_constructed(1));
        let mut keep = true;
        for (tag, v) in &e.vars {
            if tag != REASON_CODE_TAG {
                keep = self.variables.as_ref().is_none_or(|vs| vs.contains(tag));
            }
            if !keep {
                continue;
            }
            list.push(cons(
                TAG_SEQUENCE,
                [
                    prim(context_primitive(0), tag.as_bytes().to_vec()),
                    cons(context_constructed(1), data_element(v)),
                ],
            ));
        }
        cons(
            TAG_SEQUENCE,
            [
                prim(context_primitive(0), e.id.clone()),
                cons(context_constructed(1), []), // originatingApplication: this server
                cons(
                    context_constructed(2),
                    [
                        prim(context_primitive(0), Value::binary_time(e.time).bytes().to_vec()),
                        cons(context_constructed(2), [list]),
                    ],
                ),
            ],
        )
    }
}

/// Encodes a ReadJournal response from the selected entries, as many as fit
/// in `max_pdu` (zero for no limit), with moreFollows when the client has to
/// continue after the last one.
pub(crate) fn read_journal_response(q: &JournalQuery, j: &Journal, max_pdu: usize) -> Element {
    let (page, more) = super::handler::fill_page(
        q.select(j).into_iter().map(|e| q.entry_element(e)),
        max_pdu,
    );
    cons(
        context_constructed(crate::mms::service::READ_JOURNAL as u32),
        [
            cons(context_constructed(0), page),
            bool_elem(context_primitive(1), more),
        ],
    )
}
