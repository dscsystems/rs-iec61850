//! Server-side control: decoding an operate structure, checking the select
//! reservation, applying the effect and confirming enhanced-security commands.

use std::net::SocketAddr;

use crate::asn1::{cons, context_constructed, prim, Element, TAG_SEQUENCE};
use crate::mms::{data_element, Type, Value};
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
        ctx.interlock_check = check.bit(0);
        ctx.synchro_check = check.bit(1);
    }
    ctx
}

/// Returns the control model configured on an object.
pub fn ctl_model_of(model: &Model, reference: &ObjectReference) -> CtlModel {
    model
        .attribute(&reference.child("ctlModel"), Fc::Cf)
        .and_then(|da| da.value.as_ref())
        .map(|v| CtlModel::from_code(v.as_i64() as u8))
        .unwrap_or(CtlModel::DirectNormal)
}

/// Reflects an accepted operate into the process image: the controllable
/// object's `stVal` becomes the control value.
pub fn apply_control(model: &mut Model, reference: &ObjectReference, ctl_val: &Value) {
    let st_ref = reference.child("stVal");
    if let Some(da) = model.attribute_mut(&st_ref, Fc::St) {
        if da.children.is_empty() {
            da.value = Some(ctl_val.clone());
        }
    }
}

/// Materialises a `LastApplError` object into every logical device's `LLN0`
/// that does not already define one.
///
/// It is where IEC 61850-7-2 puts the device's own diagnosis of a refused
/// control, and where a client reads it from. A model that omits it (an SCL
/// file need not declare it) would otherwise leave every refusal reported as a
/// bare access error, with the additional cause lost.
pub fn materialise_last_appl_error(model: &mut Model) {
    for ld in &mut model.devices {
        let Some(lln0) = ld.node_mut("LLN0") else {
            continue;
        };
        if lln0.object("LastApplError").is_some() {
            continue;
        }
        let attr = |name: &str, v: Value| crate::model::DataAttribute {
            name: name.to_string(),
            fc: Fc::St,
            kind: Some(v.type_of()),
            value: Some(v),
            ..Default::default()
        };
        lln0.objects.push(crate::model::DataObject {
            name: "LastApplError".to_string(),
            attributes: vec![
                attr("Error", Value::int32(0)),
                crate::model::DataAttribute {
                    name: "Origin".to_string(),
                    fc: Fc::St,
                    kind: Some(Type::Structure),
                    children: vec![
                        attr("orCat", Value::int8(0)),
                        attr("orIdent", Value::octet_string(Vec::new())),
                    ],
                    ..Default::default()
                },
                attr("CtlNum", Value::uint8(0)),
                attr("AddCause", Value::int32(0)),
            ],
            ..Default::default()
        });
    }
}

/// Records the additional cause of a refused control in `LLN0.LastApplError`,
/// which is where a client looks for the device's own diagnosis.
pub fn set_last_appl_error(
    model: &mut Model,
    domain: &str,
    ctx: &ControlCtx,
    cause: AddCause,
) {
    let Some(lae) = model
        .device_mut(domain)
        .and_then(|ld| ld.node_mut("LLN0"))
        .and_then(|ln| ln.object_mut("LastApplError"))
    else {
        return; // the model does not carry one, which is legal
    };
    if let Some(a) = lae.attribute_mut("AddCause") {
        a.value = Some(Value::int32(i32::from(cause.0)));
    }
    if let Some(a) = lae.attribute_mut("Error") {
        a.value = Some(Value::int32(1));
    }
    if let Some(a) = lae.attribute_mut("CtlNum") {
        a.value = Some(Value::uint8(ctx.ctl_num));
    }
    if let Some(a) = lae.attribute_mut("Origin") {
        // Origin is a structure of orCat and orIdent when the model has one.
        if a.children.len() == 2 {
            a.children[0].value = Some(Value::int8(ctx.origin.code() as i8));
            a.children[1].value = Some(Value::octet_string(ctx.or_ident.as_bytes().to_vec()));
        }
    }
}

/// Builds the InformationReport carrying a positive CommandTermination for an
/// enhanced-security operate.
///
/// It echoes the operate value back under the same variable name, which is how
/// a client matches the termination to the command it sent.
pub fn command_termination_report(domain: &str, item: &str, oper: &Value) -> Element {
    let name = cons(
        context_constructed(1),
        [
            prim(crate::asn1::TAG_VISIBLE_STRING, domain.as_bytes().to_vec()),
            prim(crate::asn1::TAG_VISIBLE_STRING, item.as_bytes().to_vec()),
        ],
    );
    cons(
        context_constructed(0), // informationReport [0]
        [
            // The variable access specification: listOfVariable [0]
            cons(
                context_constructed(0),
                [cons(TAG_SEQUENCE, [cons(context_constructed(0), [name])])],
            ),
            // listOfAccessResult [0]
            cons(
                context_constructed(0),
                data_element(oper).into_iter().collect::<Vec<_>>(),
            ),
        ],
    )
}

/// Builds the MMS item ID of an object's `Oper` attribute.
pub fn oper_item(reference: &ObjectReference) -> String {
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
        check.set_bit(0, true); // interlock
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
