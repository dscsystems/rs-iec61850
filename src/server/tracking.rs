//! Service tracking (IEC 61850-7-2 Edition 2, the LTRK logical node).
//!
//! An LTRK carries one tracking object per kind of service: `BrcbTrk`,
//! `UrcbTrk`, `LocbTrk`, `GocbTrk`, `MsvcbTrk`, `UsvcbTrk` and `SgcbTrk` for the
//! control blocks, `SpcTrk`, `DpcTrk`, `IncTrk`, `EncTrk`, `ApcFTrk`,
//! `ApcIntTrk`, `BscTrk`, `IscTrk` and `BacTrk` for the controls. Each time a
//! client runs a tracked service the server records in the matching object
//! which object it addressed (`objRef`), which service it was
//! (`serviceType`), how it ended (`errorCode`) and when (`t`), with a copy of
//! the block's state after it, or of the command. A client subscribes to a
//! tracking object like to any data: its `objRef` raises data-update, so a
//! data set holding it reports every service, even one that changed nothing.
//!
//! The services tracked and the error codes follow libiec61850, which the
//! interop suite compares this server with: a SetDataValues on a control block
//! attribute is tracked as the block's Set...Values, each attribute written
//! counting as one, and a data access error maps to a service error as there.
//! An LTRK in the addressed object's own logical device tracks it; failing one
//! there, the first in the server does.

use std::collections::HashMap;

use crate::mms::{DataAccessError, Type, Value};
use crate::model::{
    AddCause, DataAttribute, DataObject, Fc, Model, Node, ObjectReference, ServiceErrorCode,
    ServiceType,
};

use super::control::ControlCtx;
use super::handler::value_fits;
use super::tx::{self, ChangeSet};

/// The tracking object names this server writes; an object named with an
/// instance number (`EncTrk1`) counts as its kind.
const TRACKING_KINDS: &[&str] = &[
    "SpcTrk", "DpcTrk", "IncTrk", "EncTrk", "ApcFTrk", "ApcIntTrk", "BscTrk", "IscTrk", "BacTrk",
    "BrcbTrk", "UrcbTrk", "LocbTrk", "GocbTrk", "MsvcbTrk", "UsvcbTrk", "SgcbTrk",
];

/// The attributes every tracking object has, which the server sets itself
/// rather than copying from the tracked object.
const COMMON_TRACKING: &[&str] = &[
    "objRef", "serviceType", "errorCode", "originatorID", "t", "certIssuer", "d",
];

/// Where one tracking object sits in the model.
#[derive(Debug, Clone)]
struct TrkObj {
    ld: String,
    ln: String,
    object: String,
}

impl TrkObj {
    fn reference(&self) -> ObjectReference {
        ObjectReference::new(format!("{}/{}.{}", self.ld, self.ln, self.object))
    }
}

/// Finds the tracking objects of a model.
#[derive(Debug, Default)]
pub(crate) struct Tracker {
    /// By device, then kind.
    by_ld: HashMap<String, HashMap<String, TrkObj>>,
    first: HashMap<String, TrkObj>,
}

impl Tracker {
    pub(crate) fn build(m: &Model) -> Tracker {
        let mut t = Tracker::default();
        for ld in &m.devices {
            for ln in &ld.nodes {
                if ln.class != "LTRK" && !(ln.class.is_empty() && ln.name.starts_with("LTRK")) {
                    continue;
                }
                for o in &ln.objects {
                    let kind = o.name.trim_end_matches(|c: char| c.is_ascii_digit());
                    if !TRACKING_KINDS.contains(&kind) {
                        continue;
                    }
                    let obj = TrkObj {
                        ld: ld.name.clone(),
                        ln: ln.name.clone(),
                        object: o.name.clone(),
                    };
                    t.by_ld
                        .entry(ld.name.clone())
                        .or_default()
                        .entry(kind.to_string())
                        .or_insert_with(|| obj.clone());
                    t.first.entry(kind.to_string()).or_insert(obj);
                }
            }
        }
        t
    }

    fn lookup(&self, ld: &str, kind: &str) -> Option<&TrkObj> {
        self.by_ld
            .get(ld)
            .and_then(|m| m.get(kind))
            .or_else(|| self.first.get(kind))
    }

    /// Reports whether the server tracks anything.
    pub(crate) fn is_empty(&self) -> bool {
        self.first.is_empty()
    }
}

/// What a control tracking object records of a command.
#[derive(Debug, Clone)]
pub(crate) struct CtlTrack {
    pub ctl_val: Value,
    /// The Oper, SBOw or Cancel structure as written.
    pub oper: Option<Value>,
    pub or_cat: i64,
    pub or_ident: Vec<u8>,
    pub ctl_num: u8,
    pub cause: AddCause,
}

/// One tracked service.
#[derive(Debug, Clone)]
pub(crate) struct TrackRecord {
    /// The device of the addressed object.
    pub ld: String,
    /// The tracking object's kind.
    pub kind: String,
    /// The ACSI reference of the addressed object.
    pub obj_ref: String,
    pub svc: ServiceType,
    pub err: ServiceErrorCode,
    /// The control block whose state is copied, for a block service.
    pub src: Option<DataObject>,
    /// The command of a control service.
    pub ctl: Option<CtlTrack>,
    /// The attribute a Set...Values wrote, with the value asked for,
    /// recorded over the block's state.
    pub requested: Option<(String, Value)>,
}

/// Finds the attribute named `name`, ignoring case: a tracking object names
/// `rptEna` what the control block calls `RptEna`.
fn attribute_fold<'a>(attrs: &'a [DataAttribute], name: &str) -> Option<&'a DataAttribute> {
    attrs.iter().find(|a| a.name.eq_ignore_ascii_case(name))
}

/// Stores `v` in a tracking attribute when it fits its type, noting the
/// change.
fn set_tracked(cs: &mut ChangeSet, reference: ObjectReference, da: &mut DataAttribute, v: &Value) {
    if !da.children.is_empty() || !value_fits(da, v) {
        return;
    }
    let old = da.value.replace(v.clone());
    tx::record(cs, reference, da.fc, da.trg_ops, old.as_ref(), v);
}

/// Copies a control block attribute into the tracking attribute of the same
/// name, structure by structure. A data set or log reference is written in
/// ACSI notation, `LD/LN.name`, as libiec61850 does.
fn copy_tracked(cs: &mut ChangeSet, reference: ObjectReference, dst: &mut DataAttribute, src: &DataAttribute) {
    if !dst.children.is_empty() {
        for c in &mut dst.children {
            if let Some(sc) = attribute_fold(&src.children, &c.name) {
                let r = reference.child(&c.name);
                copy_tracked(cs, r, c, sc);
            }
        }
        return;
    }
    let Some(mut v) = src.value.clone() else {
        return;
    };
    if dst.name.eq_ignore_ascii_case("datSet") || dst.name.eq_ignore_ascii_case("logRef") {
        v = Value::visible_string(v.text().replace('$', "."));
    }
    set_tracked(cs, reference, dst, &v);
}

impl Tracker {
    /// Writes `rec` into its tracking object, noting the changes in `cs` so
    /// reports and logs see them. Called with the model write lock held.
    pub(crate) fn track(&self, model: &mut Model, cs: &mut ChangeSet, rec: TrackRecord, now: Value) {
        let Some(o) = self.lookup(&rec.ld, &rec.kind).cloned() else {
            return;
        };
        let base = o.reference();
        let Some(object) = model
            .device_mut(&o.ld)
            .and_then(|ld| ld.node_mut(&o.ln))
            .and_then(|ln| ln.object_mut(&o.object))
        else {
            return;
        };
        let set = |object: &mut DataObject, cs: &mut ChangeSet, name: &str, v: &Value| {
            if let Some(da) = object.attribute_mut(name) {
                set_tracked(cs, base.child(name), da, v);
            }
        };
        if let Some(src) = &rec.src {
            for da in &mut object.attributes {
                if COMMON_TRACKING.contains(&da.name.as_str()) {
                    continue;
                }
                if let Some(s) = attribute_fold(&src.attributes, &da.name) {
                    let r = base.child(&da.name);
                    copy_tracked(cs, r, da, s);
                }
            }
        }
        if let Some((name, v)) = &rec.requested {
            if let Some(da) = object
                .attributes
                .iter_mut()
                .find(|a| a.name.eq_ignore_ascii_case(name))
            {
                if !COMMON_TRACKING.contains(&da.name.as_str()) {
                    let r = base.child(&da.name);
                    let src = DataAttribute {
                        name: name.clone(),
                        value: Some(v.clone()),
                        ..Default::default()
                    };
                    copy_tracked(cs, r, da, &src);
                }
            }
        }
        if let Some(c) = &rec.ctl {
            set(object, cs, "ctlVal", &c.ctl_val);
            if let Some(origin) = object.attribute_mut("origin") {
                let r = base.child("origin");
                for (name, v) in [
                    ("orCat", Value::int8(c.or_cat as i8)),
                    ("orIdent", Value::octet_string(c.or_ident.clone())),
                ] {
                    if let Some(da) = origin
                        .children
                        .iter_mut()
                        .find(|a| a.name.eq_ignore_ascii_case(name))
                    {
                        set_tracked(cs, r.child(name), da, &v);
                    }
                }
            }
            set(object, cs, "ctlNum", &Value::uint8(c.ctl_num));
            if let Some(oper) = c.oper.as_ref().filter(|v| v.type_of() == Type::Structure) {
                // Oper and SBOw: ctlVal, origin, ctlNum, T, Test, Check.
                // Cancel: ctlVal, origin, ctlNum, T, Test.
                for (i, name) in [(3, "T"), (4, "Test"), (5, "Check")] {
                    if let Some(v) = oper.index(i) {
                        set(object, cs, name, v);
                    }
                }
            }
            // AddCause::NONE is this crate's sentinel, not a value.
            let cause = if c.cause == AddCause::NONE {
                AddCause::UNKNOWN
            } else {
                c.cause
            };
            set(object, cs, "respAddCause", &Value::int8(cause.0 as i8));
        }
        set(object, cs, "serviceType", &Value::int32(rec.svc.0));
        set(object, cs, "errorCode", &Value::int32(rec.err.0));
        set(object, cs, "t", &now);
        set(object, cs, "objRef", &Value::visible_string(&rec.obj_ref));
    }

    /// Tracks a SetDataValues on a control block attribute as the block's
    /// Set...Values service, answered with `res`. Called with the model write
    /// lock held, after the write was applied.
    ///
    /// For a report control block the attribute written is then recorded with
    /// the value the client asked for, refused or not, as libiec61850 records
    /// it: the tracking object states the service's parameter.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn track_cb_write(
        &self,
        model: &mut Model,
        cs: &mut ChangeSet,
        domain: &str,
        item: &str,
        v: &Value,
        res: Result<(), DataAccessError>,
        now: Value,
    ) {
        if self.is_empty() {
            return;
        }
        let parts: Vec<&str> = item.split('$').collect();
        if parts.len() < 3 {
            return;
        }
        let (kind, svc) = match parts[1] {
            "BR" => ("BrcbTrk", ServiceType::SET_BRCB_VALUES),
            "RP" => ("UrcbTrk", ServiceType::SET_URCB_VALUES),
            "LG" => ("LocbTrk", ServiceType::SET_LCB_VALUES),
            "GO" => ("GocbTrk", ServiceType::SET_GOCB_VALUES),
            "MS" => ("MsvcbTrk", ServiceType::SET_MSVCB_VALUES),
            "US" => ("UsvcbTrk", ServiceType::SET_USVCB_VALUES),
            "SP" => {
                if parts[0] != "LLN0" || parts[2] != "SGCB" || parts.len() != 4 {
                    return;
                }
                let svc = match parts[3] {
                    "ActSG" => ServiceType::SELECT_ACTIVE_SG,
                    "EditSG" => ServiceType::SELECT_EDIT_SG,
                    "CnfEdit" => ServiceType::CONFIRM_EDIT_SG_VALUES,
                    _ => return,
                };
                ("SgcbTrk", svc)
            }
            _ => return,
        };
        if self.lookup(domain, kind).is_none() {
            return;
        }
        let Some(src) = model
            .device(domain)
            .and_then(|ld| super::cb::cb_object(ld, parts[0], parts[1], parts[2]))
            .cloned()
        else {
            return; // not a control block this server serves
        };
        let requested = (matches!(parts[1], "BR" | "RP") && parts.len() == 4)
            .then(|| (parts[3].to_string(), v.clone()));
        let rec = TrackRecord {
            ld: domain.to_string(),
            kind: kind.to_string(),
            obj_ref: format!("{domain}/{}.{}", parts[0], parts[2]),
            svc,
            err: service_error_of(res),
            src: Some(src),
            ctl: None,
            requested,
        };
        self.track(model, cs, rec, now);
    }

    /// Tracks a control service on `reference`. `ctx` is the decoded command,
    /// `None` for a select by reading SBO. Called with the model write lock
    /// held.
    // A tracked control has this many independent facts; bundling them into a
    // struct would only move the list.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn track_control(
        &self,
        model: &mut Model,
        cs: &mut ChangeSet,
        reference: &ObjectReference,
        svc: ServiceType,
        err: ServiceErrorCode,
        ctx: Option<&ControlCtx>,
        oper: Option<&Value>,
        cause: AddCause,
        now: Value,
    ) {
        if self.is_empty() {
            return;
        }
        let Some(kind) = control_tracking_kind(model, reference, ctx.map(|c| &c.value)) else {
            return;
        };
        let rec = TrackRecord {
            ld: reference.ld().to_string(),
            kind: kind.to_string(),
            obj_ref: reference.to_string(),
            svc,
            err,
            src: None,
            ctl: ctx.map(|c| CtlTrack {
                ctl_val: c.value.clone(),
                oper: oper.cloned(),
                or_cat: i64::from(c.origin.code()),
                or_ident: c.or_ident.as_bytes().to_vec(),
                ctl_num: c.ctl_num,
                cause,
            }),
            requested: None,
        };
        self.track(model, cs, rec, now);
    }
}

/// The tracking object of a controllable object: by its CDC, and for an APC by
/// whether its value is a float or an integer.
fn control_tracking_kind(
    model: &Model,
    reference: &ObjectReference,
    ctl_val: Option<&Value>,
) -> Option<&'static str> {
    let cdc = match model.lookup(reference, Fc::Co) {
        Some(Node::Object(o)) => o.cdc.clone(),
        _ => String::new(),
    };
    Some(match cdc.as_str() {
        "SPC" => "SpcTrk",
        "DPC" => "DpcTrk",
        "INC" => "IncTrk",
        "ENC" => "EncTrk",
        "BSC" => "BscTrk",
        "ISC" => "IscTrk",
        "BAC" => "BacTrk",
        "APC" => {
            let integer = ctl_val
                .filter(|v| v.type_of() == Type::Structure)
                .and_then(|v| v.index(0))
                .is_some_and(|f| !matches!(f.type_of(), Type::Float32 | Type::Float64));
            if integer {
                "ApcIntTrk"
            } else {
                "ApcFTrk"
            }
        }
        _ => return None,
    })
}

/// Maps the data access error a write was answered with to the service error
/// a tracking object records, as libiec61850 does.
pub(crate) fn service_error_of(res: Result<(), DataAccessError>) -> ServiceErrorCode {
    match res {
        Ok(()) => ServiceErrorCode::NO_ERROR,
        Err(DataAccessError::TemporarilyUnavailable) => {
            ServiceErrorCode::INSTANCE_LOCKED_BY_OTHER_CLIENT
        }
        Err(DataAccessError::ObjectAccessDenied) => ServiceErrorCode::ACCESS_VIOLATION,
        Err(DataAccessError::ObjectValueInvalid) => ServiceErrorCode::PARAMETER_VALUE_INAPPROPRIATE,
        Err(DataAccessError::TypeInconsistent | DataAccessError::ObjectAttributeInconsistent) => {
            ServiceErrorCode::PARAMETER_VALUE_INCONSISTENT
        }
        Err(DataAccessError::ObjectNonExistent) => ServiceErrorCode::INSTANCE_NOT_AVAILABLE,
        Err(_) => ServiceErrorCode::FAILED_DUE_TO_SERVER_CONSTRAINT,
    }
}

/// The service error a CommandTermination is tracked with: none for a
/// positive one and, as libiec61850 records it, failed due to a server
/// constraint for a negative one.
pub(crate) fn termination_error(cause: AddCause) -> ServiceErrorCode {
    if cause == AddCause::NONE {
        ServiceErrorCode::NO_ERROR
    } else {
        ServiceErrorCode::FAILED_DUE_TO_SERVER_CONSTRAINT
    }
}
