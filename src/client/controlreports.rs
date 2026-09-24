//! Follows the control-related reports of an association: the LastApplError
//! that precedes a negative control response, and the CommandTermination that
//! concludes an enhanced-security operate.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use crate::mms::{InformationReport, Type, Value};
use crate::model::{AddCause, OrCat};

/// The diagnosis a server reports when it refuses a control, ahead of the
/// negative response (IEC 61850-8-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LastApplError {
    /// The control variable, `LD/LN$CO$DO$Oper`.
    pub cntrl_obj: String,
    /// 0 no error, 1 unknown, 2 timeout test not ok, 3 operator test not ok.
    /// The reason for a refusal is in [`add_cause`](LastApplError::add_cause).
    pub error: i64,
    pub origin: OrCat,
    pub or_ident: Vec<u8>,
    pub ctl_num: u8,
    pub add_cause: AddCause,
}

impl LastApplError {
    /// Decodes `{ CntrlObj, Error, Origin { orCat, orIdent }, ctlNum,
    /// AddCause }`.
    fn parse(v: &Value) -> Option<LastApplError> {
        if v.type_of() != Type::Structure || v.len() < 5 {
            return None;
        }
        let mut e = LastApplError {
            cntrl_obj: v.index(0)?.text(),
            error: v.index(1)?.as_i64(),
            origin: OrCat::NotSupported,
            or_ident: Vec::new(),
            ctl_num: v.index(3)?.as_u64() as u8,
            add_cause: AddCause(v.index(4)?.as_i64() as u8),
        };
        if let Some(o) = v.index(2) {
            if o.type_of() == Type::Structure && o.len() >= 2 {
                e.origin = OrCat::from_code(o.index(0).map_or(0, Value::as_i64) as u8);
                e.or_ident = o.index(1).map(|b| b.bytes().to_vec()).unwrap_or_default();
            }
        }
        Some(e)
    }
}

/// Names one operate: the `Oper` variable and its control number.
type TerminationKey = (String, u8);

#[derive(Debug, Default)]
struct State {
    /// The most recent LastApplError of each control variable.
    last: HashMap<String, LastApplError>,
    /// The most recent LastApplError of any object.
    latest: Option<LastApplError>,
    /// The CommandTerminations awaited.
    waiters: HashMap<TerminationKey, oneshot::Sender<AddCause>>,
}

/// Tracks the control reports of one association.
///
/// Reports are handled on the reader task in the order the server sent them,
/// and a server sends a LastApplError before the negative response it
/// explains, so the diagnosis is recorded by the time that response is
/// returned to the caller.
#[derive(Debug, Default)]
pub(crate) struct ControlReports {
    state: Mutex<State>,
}

impl ControlReports {
    /// Inspects an information report for control reports:
    ///
    /// ```text
    /// LastApplError              a refused select, operate or cancel
    /// Oper                       CommandTermination+
    /// LastApplError, Oper        CommandTermination-
    /// ```
    pub(crate) fn handle(&self, ir: &InformationReport) {
        if ir.is_vmd_named || ir.var_refs.is_empty() || ir.var_refs.len() != ir.values.len() {
            return;
        }
        let mut lae = None;
        let mut oper_at = None;
        for (i, r) in ir.var_refs.iter().enumerate() {
            if r.domain.is_empty() && r.item == "LastApplError" {
                lae = LastApplError::parse(&ir.values[i]);
            } else if !r.domain.is_empty() && r.item.ends_with("$Oper") {
                oper_at = Some(i);
            }
        }

        let mut st = self.state.lock().unwrap();
        if let Some(e) = &lae {
            st.last.insert(e.cntrl_obj.clone(), e.clone());
            st.latest = Some(e.clone());
        }
        let Some(i) = oper_at else {
            return;
        };
        let oper = &ir.values[i];
        if oper.type_of() != Type::Structure || oper.len() < 3 {
            return;
        }
        let ctl_num = oper.index(2).map_or(0, Value::as_u64) as u8;
        let key = (ir.var_refs[i].to_string(), ctl_num);
        if let Some(tx) = st.waiters.remove(&key) {
            let _ = tx.send(lae.map_or(AddCause::NONE, |e| e.add_cause));
        }
    }

    /// Returns the cause a server gave for refusing the control variable
    /// `cntrl_obj` (`LD/LN$CO$DO$Oper`) with `ctl_num`, or
    /// [`AddCause::UNKNOWN`] when it gave none.
    pub(crate) fn cause_for(&self, cntrl_obj: &str, ctl_num: u8) -> AddCause {
        let st = self.state.lock().unwrap();
        match st.last.get(cntrl_obj) {
            Some(e) if e.ctl_num == ctl_num => e.add_cause,
            _ => AddCause::UNKNOWN,
        }
    }

    pub(crate) fn latest(&self) -> Option<LastApplError> {
        self.state.lock().unwrap().latest.clone()
    }

    /// Registers interest in the CommandTermination of the operate of `oper`
    /// (`LD/LN$CO$DO$Oper`) with `ctl_num`. It must be called before the
    /// operate is sent; dropping the returned guard releases the
    /// registration.
    pub(crate) fn await_termination(
        self: &Arc<Self>,
        oper: &str,
        ctl_num: u8,
    ) -> (oneshot::Receiver<AddCause>, TerminationGuard) {
        let (tx, rx) = oneshot::channel();
        let key = (oper.to_string(), ctl_num);
        self.state.lock().unwrap().waiters.insert(key.clone(), tx);
        (
            rx,
            TerminationGuard {
                reports: Arc::clone(self),
                key,
            },
        )
    }
}

/// Releases an awaited CommandTermination when dropped.
#[derive(Debug)]
pub(crate) struct TerminationGuard {
    reports: Arc<ControlReports>,
    key: TerminationKey,
}

impl Drop for TerminationGuard {
    fn drop(&mut self) {
        self.reports.state.lock().unwrap().waiters.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::VarRef;

    fn lae_value(obj: &str, ctl_num: u8, cause: AddCause) -> Value {
        Value::structure(vec![
            Value::visible_string(obj),
            Value::int8(0),
            Value::structure(vec![Value::int8(2), Value::octet_string(b"scada".to_vec())]),
            Value::uint8(ctl_num),
            Value::int8(cause.0 as i8),
        ])
    }

    fn oper_value(ctl_num: u8) -> Value {
        Value::structure(vec![
            Value::boolean(true),
            Value::structure(vec![Value::int8(2), Value::octet_string(Vec::new())]),
            Value::uint8(ctl_num),
        ])
    }

    fn report(entries: Vec<(VarRef, Value)>) -> InformationReport {
        let (refs, values): (Vec<_>, Vec<_>) = entries.into_iter().unzip();
        InformationReport {
            var_names: refs.iter().map(|r: &VarRef| r.item.clone()).collect(),
            var_refs: refs,
            values,
            ..Default::default()
        }
    }

    const OBJ: &str = "LD/GGIO1$CO$SPCSO1$Oper";

    #[test]
    fn a_last_appl_error_is_recorded_by_control_variable_and_number() {
        let cr = ControlReports::default();
        cr.handle(&report(vec![(
            VarRef::new("", "LastApplError"),
            lae_value(OBJ, 7, AddCause::BLOCKED_BY_INTERLOCKING),
        )]));
        assert_eq!(cr.cause_for(OBJ, 7), AddCause::BLOCKED_BY_INTERLOCKING);
        assert_eq!(cr.cause_for(OBJ, 8), AddCause::UNKNOWN, "another sequence");
        let latest = cr.latest().expect("recorded");
        assert_eq!(latest.or_ident, b"scada");
        assert_eq!(latest.origin, OrCat::StationControl);
    }

    #[tokio::test]
    async fn terminations_resolve_their_own_waiter_only() {
        let cr = Arc::new(ControlReports::default());
        let (pos, _g1) = cr.await_termination(OBJ, 1);
        let (neg, _g2) = cr.await_termination(OBJ, 2);

        cr.handle(&report(vec![(VarRef::new("LD", "GGIO1$CO$SPCSO1$Oper"), oper_value(1))]));
        assert_eq!(pos.await.unwrap(), AddCause::NONE, "CommandTermination+");

        cr.handle(&report(vec![
            (
                VarRef::new("", "LastApplError"),
                lae_value(OBJ, 2, AddCause::TIME_LIMIT_OVER),
            ),
            (VarRef::new("LD", "GGIO1$CO$SPCSO1$Oper"), oper_value(2)),
        ]));
        assert_eq!(neg.await.unwrap(), AddCause::TIME_LIMIT_OVER, "CommandTermination-");
    }

    #[test]
    fn a_dropped_guard_releases_the_registration() {
        let cr = Arc::new(ControlReports::default());
        drop(cr.await_termination(OBJ, 1));
        assert!(cr.state.lock().unwrap().waiters.is_empty());
    }
}
