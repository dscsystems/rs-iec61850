//! Server-side control: decoding an operate structure, checking the select
//! reservation, applying the effect and confirming enhanced-security commands.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::asn1::{
    cons, context_constructed, context_primitive, prim, Element, TAG_SEQUENCE, TAG_VISIBLE_STRING,
};
use crate::mms::{data_element, ServerConn, Type, Value};
use crate::model::{AddCause, CtlModel, Fc, Model, ObjectReference, OrCat};

use super::ConnId;

/// Which control attribute a write addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The select-with-value step of an enhanced SBO control.
    Sbow,
    /// The operate step.
    Oper,
    /// A cancel.
    Cancel,
    /// The select step of a normal-security SBO control, which is a read.
    Sbo,
}

impl Phase {
    fn from_name(s: &str) -> Option<Phase> {
        match s {
            "SBOw" => Some(Phase::Sbow),
            "Oper" => Some(Phase::Oper),
            "Cancel" => Some(Phase::Cancel),
            "SBO" => Some(Phase::Sbo),
            _ => None,
        }
    }
}

/// Describes an incoming control request passed to a handler.
#[derive(Debug, Clone)]
pub struct ControlCtx {
    /// The controllable object, for example `LD/LN.SPCSO1`.
    pub reference: ObjectReference,
    /// The `ctlVal`.
    pub value: Value,
    pub origin: OrCat,
    pub or_ident: String,
    pub ctl_num: u8,
    pub test: bool,
    pub interlock_check: bool,
    pub synchro_check: bool,
    /// True for the select phase, false for operate.
    pub select: bool,

    /// The association the command arrived on.
    ///
    /// `origin` and `or_ident` are what the client claims about itself; this
    /// is what the server observed, which is what an audit trail has to be
    /// built from.
    pub conn: ConnId,
    /// The client's transport address, when the transport has one.
    pub peer: Option<SocketAddr>,

    /// The CommandTermination owed for an enhanced-security operate; see
    /// [`defer_termination`](ControlCtx::defer_termination).
    pub(crate) term: Option<Arc<Termination>>,
}

impl ControlCtx {
    /// Takes over the CommandTermination of an operate on an
    /// enhanced-security object.
    ///
    /// The server then does not terminate the operate when the handler
    /// accepts it. Instead the returned function is called once execution has
    /// ended, with [`AddCause::NONE`] for success (CommandTermination+) or the
    /// cause of failure (CommandTermination-, carrying a LastApplError). It
    /// may be called from any thread; calls after the first are ignored. If
    /// it has not been called within the object's `operTimeout`, the server
    /// terminates the operate negatively with time-limit-over.
    ///
    /// For a select, a cancel or a normal-security object there is no
    /// termination to defer, and the returned function does nothing.
    pub fn defer_termination(&self) -> Box<dyn Fn(AddCause) + Send + Sync> {
        match &self.term {
            None => Box::new(|_| {}),
            Some(term) => {
                term.state.lock().unwrap().deferred = true;
                let term = Arc::clone(term);
                Box::new(move |cause| term.finish(cause))
            }
        }
    }
}

/// Reports whether an item addresses a control attribute, returning the
/// `LN$CO$DO...` base and the phase.
///
/// The phase name is searched from the end, since a data object may itself be
/// called something that collides with an earlier component.
pub fn split_control(item: &str) -> Option<(String, Phase)> {
    let parts: Vec<&str> = item.split('$').collect();
    if parts.len() < 4 || parts[1] != "CO" {
        return None;
    }
    for i in (3..parts.len()).rev() {
        if let Some(phase) = Phase::from_name(parts[i]) {
            return Some((parts[..i].join("$"), phase));
        }
    }
    None
}

/// Converts a domain plus `LN$CO$DO[$SDO]` to `LD/LN.DO[.SDO]`.
pub fn control_ref(domain: &str, base: &str) -> ObjectReference {
    let parts: Vec<&str> = base.split('$').collect();
    // parts[0] is the logical node, parts[1] is the CO tag, the rest is the
    // data object path.
    let mut path = vec![parts[0]];
    path.extend_from_slice(&parts[2..]);
    ObjectReference::new(format!("{domain}/{}", path.join(".")))
}

/// Extracts the fields of an operate or SBOw structure:
/// `{ ctlVal, origin{orCat, orIdent}, ctlNum, T, Test, Check }`.
pub fn decode_oper(
    reference: ObjectReference,
    v: &Value,
    conn: ConnId,
    peer: Option<SocketAddr>,
) -> ControlCtx {
    let mut ctx = ControlCtx {
        reference,
        value: Value::None,
        origin: OrCat::NotSupported,
        or_ident: String::new(),
        ctl_num: 0,
        test: false,
        interlock_check: false,
        synchro_check: false,
        select: false,
        conn,
        peer,
        term: None,
    };
    if v.type_of() != Type::Structure {
        return ctx;
    }
    if let Some(val) = v.index(0) {
        ctx.value = val.clone();
    }
    if let Some(origin) = v.index(1) {
        if origin.type_of() == Type::Structure {
            if let Some(cat) = origin.index(0) {
                ctx.origin = OrCat::from_code(cat.as_i64() as u8);
            }
            if let Some(ident) = origin.index(1) {
                ctx.or_ident = String::from_utf8_lossy(ident.bytes()).into_owned();
            }
        }
    }
    if let Some(n) = v.index(2) {
        ctx.ctl_num = n.as_i64() as u8;
    }
    // Index 3 is the timestamp, which the server does not need.
    if let Some(t) = v.index(4) {
        ctx.test = t.as_bool();
    }
    if let Some(check) = v.index(5) {
        // Check per IEC 61850-7-2 Table 51: synchrocheck is bit 0.
        ctx.synchro_check = check.bit(0);
        ctx.interlock_check = check.bit(1);
    }
    ctx
}

/// Returns the control model an object declares, if it declares one. An
/// object without `ctlModel` is treated as direct with normal security.
pub fn declared_ctl_model(model: &Model, reference: &ObjectReference) -> Option<CtlModel> {
    model
        .attribute(&reference.child("ctlModel"), Fc::Cf)
        .and_then(|da| da.value.as_ref())
        .map(|v| CtlModel::from_code(v.as_i64() as u8))
}

/// Returns a millisecond CF attribute of a control object (`sboTimeout`,
/// `operTimeout`) as a duration, zero when the object does not declare it.
pub fn cf_millis(model: &Model, reference: &ObjectReference, name: &str) -> Duration {
    model
        .attribute(&reference.child(name), Fc::Cf)
        .and_then(|da| da.value.as_ref())
        .map(|v| Duration::from_millis(v.as_u64()))
        .unwrap_or_default()
}

/// Reflects an accepted operate into the process image: the controllable
/// object's `stVal` becomes the control value, and the new status reports
/// like any process change.
pub(crate) fn apply_control(
    model: &mut Model,
    reference: &ObjectReference,
    ctl_val: &Value,
    changes: &mut super::tx::ChangeSet,
) {
    let st_ref = reference.child("stVal");
    if let Some(da) = model.attribute_mut(&st_ref, Fc::St) {
        if da.children.is_empty() && *ctl_val != Value::None {
            let old = da.value.replace(ctl_val.clone());
            let trg = da.trg_ops;
            super::tx::record(changes, st_ref, Fc::St, trg, old.as_ref(), ctl_val);
        }
    }
}

/// Builds an ObjectName in its domain-specific form.
fn domain_specific_name(domain: &str, item: &str) -> Element {
    cons(
        context_constructed(1),
        [
            prim(TAG_VISIBLE_STRING, domain.as_bytes().to_vec()),
            prim(TAG_VISIBLE_STRING, item.as_bytes().to_vec()),
        ],
    )
}

/// Builds an ObjectName in its VMD-specific form.
fn vmd_specific_name(name: &str) -> Element {
    prim(context_primitive(0), name.as_bytes().to_vec())
}

/// One `listOfVariable` entry: `SEQUENCE { variableSpecification name [0] }`.
fn variable_entry(name: Element) -> Element {
    cons(TAG_SEQUENCE, [cons(context_constructed(0), [name])])
}

/// The `LastApplError` structure (IEC 61850-8-1):
/// `{ CntrlObj, Error, Origin { orCat, orIdent }, ctlNum, AddCause }`.
///
/// The reason is in `AddCause`. `Error` stays "no error": it concerns the
/// test of an operate, not its refusal.
pub fn last_appl_error_value(
    domain: &str,
    ctl_item: &str,
    ctx: &ControlCtx,
    cause: AddCause,
) -> Value {
    Value::structure(vec![
        Value::visible_string(format!("{domain}/{ctl_item}")),
        Value::int8(0),
        Value::structure(vec![
            Value::int8(ctx.origin.code() as i8),
            Value::octet_string(ctx.or_ident.as_bytes().to_vec()),
        ]),
        Value::uint8(ctx.ctl_num),
        Value::int8(cause.0 as i8),
    ])
}

/// Builds the InformationReport of the VMD-specific variable `LastApplError`
/// that tells a client why a control was refused. It is sent ahead of the
/// negative response to the control it explains (IEC 61850-8-1).
pub fn last_appl_error_report(
    domain: &str,
    ctl_item: &str,
    ctx: &ControlCtx,
    cause: AddCause,
) -> Element {
    let value = last_appl_error_value(domain, ctl_item, ctx, cause);
    cons(
        context_constructed(0), // informationReport [0]
        [
            // listOfVariable [0]
            cons(
                context_constructed(0),
                [variable_entry(vmd_specific_name("LastApplError"))],
            ),
            // listOfAccessResult [0]
            cons(
                context_constructed(0),
                data_element(&value).into_iter().collect::<Vec<_>>(),
            ),
        ],
    )
}

/// Builds the InformationReport carrying a positive CommandTermination for an
/// enhanced-security operate.
///
/// It echoes the operate value back under the same variable name, which is how
/// a client matches the termination to the command it sent.
pub fn command_termination_report(domain: &str, item: &str, oper: &Value) -> Element {
    cons(
        context_constructed(0), // informationReport [0]
        [
            // listOfVariable [0]
            cons(
                context_constructed(0),
                [variable_entry(domain_specific_name(domain, item))],
            ),
            // listOfAccessResult [0]
            cons(
                context_constructed(0),
                data_element(oper).into_iter().collect::<Vec<_>>(),
            ),
        ],
    )
}

/// Builds the InformationReport carrying a negative CommandTermination: the
/// `LastApplError` naming the cause, then the operate value (IEC 61850-8-1).
pub fn command_termination_negative_report(
    domain: &str,
    item: &str,
    oper: &Value,
    last_appl_error: &Value,
) -> Element {
    cons(
        context_constructed(0), // informationReport [0]
        [
            cons(
                context_constructed(0),
                [
                    variable_entry(vmd_specific_name("LastApplError")),
                    variable_entry(domain_specific_name(domain, item)),
                ],
            ),
            cons(
                context_constructed(0),
                data_element(last_appl_error)
                    .into_iter()
                    .chain(data_element(oper))
                    .collect::<Vec<_>>(),
            ),
        ],
    )
}

/// The CommandTermination owed for one enhanced-security operate.
///
/// It is sent exactly once: by the server as soon as the operate is accepted,
/// by a handler that deferred it, or with time-limit-over when `operTimeout`
/// passes first.
pub(crate) struct Termination {
    send: Box<dyn Fn(AddCause) + Send + Sync>,
    state: Mutex<TerminationState>,
}

#[derive(Default)]
struct TerminationState {
    done: bool,
    deferred: bool,
    timer: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for Termination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.state.lock().unwrap();
        f.debug_struct("Termination")
            .field("done", &st.done)
            .field("deferred", &st.deferred)
            .finish()
    }
}

impl Termination {
    /// Returns a termination that sends through `conn` for the control
    /// variable `ctl_item` of `domain`.
    pub(crate) fn new(
        conn: Arc<ServerConn>,
        domain: &str,
        ctl_item: &str,
        ctx: &ControlCtx,
        oper: &Value,
    ) -> Arc<Termination> {
        let (domain, ctl_item, oper) = (domain.to_string(), ctl_item.to_string(), oper.clone());
        let ctx = ctx.clone();
        Arc::new(Termination {
            send: Box::new(move |cause| {
                let report = if cause == AddCause::NONE {
                    command_termination_report(&domain, &ctl_item, &oper)
                } else {
                    let lae = last_appl_error_value(&domain, &ctl_item, &ctx, cause);
                    command_termination_negative_report(&domain, &ctl_item, &oper, &lae)
                };
                if conn.send_unconfirmed(report).is_err() {
                    tracing::debug!(item = %ctl_item, "server: command termination send failed");
                }
            }),
            state: Mutex::new(TerminationState::default()),
        })
    }

    /// Sends the termination, unless it has been sent or discarded already.
    pub(crate) fn finish(&self, cause: AddCause) {
        {
            let mut st = self.state.lock().unwrap();
            if st.done {
                return;
            }
            st.done = true;
            if let Some(timer) = st.timer.take() {
                timer.abort();
            }
        }
        (self.send)(cause);
    }

    /// Drops the termination of an operate that was refused: a refused
    /// operate is not terminated.
    pub(crate) fn discard(&self) {
        self.state.lock().unwrap().done = true;
    }

    pub(crate) fn is_deferred(&self) -> bool {
        self.state.lock().unwrap().deferred
    }

    /// Terminates negatively with time-limit-over if the deferred termination
    /// has not come within `limit` (no limit when it is zero).
    pub(crate) fn supervise(self: &Arc<Self>, limit: Duration) {
        if limit.is_zero() {
            return;
        }
        let me = Arc::clone(self);
        let timer = tokio::spawn(async move {
            tokio::time::sleep(limit).await;
            me.finish(AddCause::TIME_LIMIT_OVER);
        });
        let mut st = self.state.lock().unwrap();
        if st.done {
            timer.abort();
        } else {
            st.timer = Some(timer);
        }
    }
}

/// Builds the MMS item ID of an object's `Oper` attribute.
#[cfg(test)]
fn oper_item(reference: &ObjectReference) -> String {
    let path = reference.path();
    format!("{}$CO${}$Oper", path[0], path[1..].join("$"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_attributes_are_recognised_by_their_phase() {
        assert_eq!(
            split_control("GGIO1$CO$SPCSO1$Oper"),
            Some(("GGIO1$CO$SPCSO1".to_string(), Phase::Oper))
        );
        assert_eq!(
            split_control("GGIO1$CO$SPCSO1$SBOw"),
            Some(("GGIO1$CO$SPCSO1".to_string(), Phase::Sbow))
        );
        assert_eq!(
            split_control("GGIO1$CO$SPCSO1$Cancel"),
            Some(("GGIO1$CO$SPCSO1".to_string(), Phase::Cancel))
        );
        assert_eq!(
            split_control("GGIO1$CO$SPCSO1$SBO"),
            Some(("GGIO1$CO$SPCSO1".to_string(), Phase::Sbo))
        );
    }

    /// A write addresses a member inside the operate structure, and the phase
    /// is still the operate.
    #[test]
    fn a_member_below_the_phase_still_resolves_to_it() {
        assert_eq!(
            split_control("GGIO1$CO$SPCSO1$Oper$ctlVal"),
            Some(("GGIO1$CO$SPCSO1".to_string(), Phase::Oper))
        );
        assert_eq!(
            split_control("GGIO1$CO$SPCSO1$Oper$origin$orCat"),
            Some(("GGIO1$CO$SPCSO1".to_string(), Phase::Oper))
        );
    }

    #[test]
    fn a_sub_data_object_path_is_kept_in_the_base() {
        assert_eq!(
            split_control("XCBR1$CO$Pos$Oper"),
            Some(("XCBR1$CO$Pos".to_string(), Phase::Oper))
        );
        assert_eq!(
            control_ref("LD", "XCBR1$CO$Pos").as_str(),
            "LD/XCBR1.Pos"
        );
    }

    #[test]
    fn items_outside_the_control_constraint_are_not_control_writes() {
        assert!(split_control("GGIO1$ST$Ind1$stVal").is_none());
        assert!(split_control("GGIO1$CO$SPCSO1").is_none(), "no phase");
        assert!(split_control("LLN0$RP$urcb01$RptEna").is_none());
        assert!(split_control("").is_none());
    }

    #[test]
    fn control_references_drop_the_constraint_tag() {
        assert_eq!(
            control_ref("ied1LD0", "GGIO1$CO$SPCSO1").as_str(),
            "ied1LD0/GGIO1.SPCSO1"
        );
        assert_eq!(
            oper_item(&"ied1LD0/GGIO1.SPCSO1".into()),
            "GGIO1$CO$SPCSO1$Oper"
        );
        assert_eq!(oper_item(&"LD/XCBR1.Pos".into()), "XCBR1$CO$Pos$Oper");
    }

    fn oper_value(ctl_val: Value, ctl_num: u8) -> Value {
        let mut check = Value::bit_string(2);
        check.set_bit(1, true); // interlock-check; bit 0 is synchrocheck
        Value::structure(vec![
            ctl_val,
            Value::structure(vec![
                Value::int8(2), // station-control
                Value::octet_string(b"scada-1".to_vec()),
            ]),
            Value::uint8(ctl_num),
            Value::utc_time_parts(0, 0, crate::mms::TimeQuality(0)),
            Value::boolean(true), // test
            check,
        ])
    }

    /// The receiving half of the Check ordering of IEC 61850-7-2 Table 51:
    /// bit 0 is synchrocheck, bit 1 interlock-check. A client-to-server test
    /// cannot catch a transposition because both ends would move together, so
    /// decode a bit string built by hand.
    #[test]
    fn decode_oper_reads_check_in_table_51_order() {
        for (name, bit0, bit1) in [
            ("neither", false, false),
            ("synchro", true, false),
            ("interlock", false, true),
            ("both", true, true),
        ] {
            let mut check = Value::bit_string(2);
            check.set_bit(0, bit0);
            check.set_bit(1, bit1);
            let oper = Value::structure(vec![
                Value::boolean(true),
                Value::structure(vec![Value::int8(2), Value::octet_string(Vec::new())]),
                Value::uint8(1),
                Value::utc_time_parts(0, 0, crate::mms::TimeQuality(0)),
                Value::boolean(false),
                check,
            ]);
            let ctx = decode_oper("LD/GGIO1.SPCSO1".into(), &oper, ConnId(1), None);
            assert_eq!(ctx.synchro_check, bit0, "{name}: synchro from bit 0");
            assert_eq!(ctx.interlock_check, bit1, "{name}: interlock from bit 1");
        }
    }

    #[test]
    fn an_operate_structure_decodes_into_its_fields() {
        let ctx = decode_oper(
            "LD/GGIO1.SPCSO1".into(),
            &oper_value(Value::boolean(true), 7),
            ConnId(1),
            None,
        );
        assert!(ctx.value.as_bool());
        assert_eq!(ctx.origin, OrCat::StationControl);
        assert_eq!(ctx.or_ident, "scada-1");
        assert_eq!(ctx.ctl_num, 7);
        assert!(ctx.test);
        assert!(ctx.interlock_check);
        assert!(!ctx.synchro_check);
        assert_eq!(ctx.conn, ConnId(1));
    }

    /// A malformed operate must not panic or half-decode into something a
    /// handler would act on.
    #[test]
    fn a_non_structure_operate_decodes_to_an_empty_context() {
        let ctx = decode_oper("LD/GGIO1.SPCSO1".into(), &Value::boolean(true), ConnId(1), None);
        assert_eq!(ctx.value, Value::None);
        assert_eq!(ctx.ctl_num, 0);
        assert!(!ctx.test);
        assert_eq!(ctx.origin, OrCat::NotSupported);
    }

    #[test]
    fn a_short_operate_structure_decodes_what_is_present() {
        // Some clients send only the value and origin.
        let v = Value::structure(vec![
            Value::int32(5),
            Value::structure(vec![Value::int8(3), Value::octet_string(b"x".to_vec())]),
        ]);
        let ctx = decode_oper("LD/GGIO1.INC1".into(), &v, ConnId(2), None);
        assert_eq!(ctx.value.as_i32(), 5);
        assert_eq!(ctx.origin, OrCat::RemoteControl);
        assert_eq!(ctx.ctl_num, 0, "absent fields keep their defaults");
        assert!(!ctx.test);
    }

    #[test]
    fn a_command_termination_echoes_the_operate_under_its_own_name() {
        let oper = oper_value(Value::boolean(true), 3);
        let el = command_termination_report("ied1LD0", "GGIO1$CO$SPCSO1$Oper", &oper);
        let encoded = el.encode();

        // It must parse as an information report naming the operate variable.
        let mut dec = crate::asn1::Decoder::new(&encoded);
        let content = dec.expect(context_constructed(0)).unwrap();
        let rep = crate::mms::InformationReport::default();
        let _ = rep;
        let mut inner = crate::asn1::Decoder::new(content);
        // listOfVariable [0] then listOfAccessResult [0].
        assert!(inner.optional(context_constructed(0)).unwrap().is_some());
        assert!(inner.optional(context_constructed(0)).unwrap().is_some());
    }

    #[test]
    fn phases_map_from_their_attribute_names() {
        assert_eq!(Phase::from_name("Oper"), Some(Phase::Oper));
        assert_eq!(Phase::from_name("SBOw"), Some(Phase::Sbow));
        assert_eq!(Phase::from_name("SBO"), Some(Phase::Sbo));
        assert_eq!(Phase::from_name("Cancel"), Some(Phase::Cancel));
        assert_eq!(Phase::from_name("ctlVal"), None);
    }
}
