//! The IEC 61850-7-3 common data classes.
//!
//! A common data class selects the attribute table a data object is built
//! from. [`new_data_object`] materialises one: its mandatory attributes, any
//! optional ones asked for, and any nested data objects the class defines,
//! each with a zero value of its type.
//!
//! The tables follow the NSD of IEC 61850-7-3 Edition 2.1 (2007B5), including
//! the classes Edition 2 and 2.1 added and the service tracking classes of
//! IEC 61850-7-2 Edition 2. The general description and namespace attributes
//! other than `d` (`dU`, `cdcName`, `dataNs`) are not in the tables.

use std::collections::BTreeSet;

use crate::mms::{Type, Value};

use super::{CtlModel, DataAttribute, DataObject, Diagnostic, Fc, TrgOps};

/// A common data class name (IEC 61850-7-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Cdc {
    // Status information.
    /// Single point status.
    Sps,
    /// Double point status.
    Dps,
    /// Integer status.
    Ins,
    /// Enumerated status.
    Ens,
    /// Visible string status.
    Vss,
    /// Protection activation information.
    Act,
    /// Directional protection activation information.
    Acd,
    /// Binary counter reading.
    Bcr,

    // Measurand information.
    /// Measured value.
    Mv,
    /// Complex measured value.
    Cmv,
    /// Sampled value.
    Sav,
    /// Phase-to-ground related measurands.
    Wye,
    /// Phase-to-phase related measurands.
    Del,

    // Controllable information.
    /// Controllable single point.
    Spc,
    /// Controllable double point.
    Dpc,
    /// Controllable integer status.
    Inc,
    /// Controllable enumerated status.
    Enc,
    /// Binary controlled step position.
    Bsc,
    /// Controllable analogue process value.
    Apc,

    // Settings.
    /// Single point setting.
    Spg,
    /// Integer status setting.
    Ing,
    /// Enumerated status setting.
    Eng,
    /// Analogue setting.
    Asg,

    // Description.
    /// Logical node name plate.
    Lpl,
    /// Device name plate.
    Dpl,

    // Classes added by Edition 2 and 2.1.
    /// Security violation counting.
    Sec,
    /// Histogram.
    Hst,
    /// Object reference status.
    Ors,
    /// Time status.
    Tcs,
    /// Sequence.
    Seq,
    /// Harmonic value.
    Hmv,
    /// Harmonic value for WYE.
    Hwye,
    /// Harmonic value for DEL.
    Hdel,
    /// Integer controlled step position.
    Isc,
    /// Binary controlled analogue process value.
    Bac,
    /// Object reference setting.
    Org,
    /// Time setting.
    Tsg,
    /// Currency setting.
    Cug,
    /// Visible string setting.
    Vsg,
    /// Setting curve.
    Curve,
    /// Curve shape setting.
    Csg,
    /// Curve shape description.
    Csd,
    /// Visible string description.
    Vsd,

    // Service tracking (IEC 61850-7-2 Edition 2), served under FC SR.
    /// Common service tracking.
    Cst,
    /// Buffered report tracking.
    Bts,
    /// Unbuffered report tracking.
    Uts,
    /// Log control tracking.
    Lts,
    /// GOOSE control tracking.
    Gts,
    /// Multicast sampled value control tracking.
    Mts,
    /// Unicast sampled value control tracking.
    Nts,
    /// Setting group control tracking.
    Sts,
    /// Control service tracking.
    Cts,
}

impl Cdc {
    /// Every class this module can build.
    pub const ALL: [Cdc; 52] = [
        Cdc::Sps,
        Cdc::Dps,
        Cdc::Ins,
        Cdc::Ens,
        Cdc::Vss,
        Cdc::Act,
        Cdc::Acd,
        Cdc::Bcr,
        Cdc::Mv,
        Cdc::Cmv,
        Cdc::Sav,
        Cdc::Wye,
        Cdc::Del,
        Cdc::Spc,
        Cdc::Dpc,
        Cdc::Inc,
        Cdc::Enc,
        Cdc::Bsc,
        Cdc::Apc,
        Cdc::Spg,
        Cdc::Ing,
        Cdc::Eng,
        Cdc::Asg,
        Cdc::Lpl,
        Cdc::Dpl,
        Cdc::Sec,
        Cdc::Hst,
        Cdc::Ors,
        Cdc::Tcs,
        Cdc::Seq,
        Cdc::Hmv,
        Cdc::Hwye,
        Cdc::Hdel,
        Cdc::Isc,
        Cdc::Bac,
        Cdc::Org,
        Cdc::Tsg,
        Cdc::Cug,
        Cdc::Vsg,
        Cdc::Curve,
        Cdc::Csg,
        Cdc::Csd,
        Cdc::Vsd,
        Cdc::Cst,
        Cdc::Bts,
        Cdc::Uts,
        Cdc::Lts,
        Cdc::Gts,
        Cdc::Mts,
        Cdc::Nts,
        Cdc::Sts,
        Cdc::Cts,
    ];

    /// Returns the standard mnemonic.
    pub fn as_str(self) -> &'static str {
        match self {
            Cdc::Sps => "SPS",
            Cdc::Dps => "DPS",
            Cdc::Ins => "INS",
            Cdc::Ens => "ENS",
            Cdc::Vss => "VSS",
            Cdc::Act => "ACT",
            Cdc::Acd => "ACD",
            Cdc::Bcr => "BCR",
            Cdc::Mv => "MV",
            Cdc::Cmv => "CMV",
            Cdc::Sav => "SAV",
            Cdc::Wye => "WYE",
            Cdc::Del => "DEL",
            Cdc::Spc => "SPC",
            Cdc::Dpc => "DPC",
            Cdc::Inc => "INC",
            Cdc::Enc => "ENC",
            Cdc::Bsc => "BSC",
            Cdc::Apc => "APC",
            Cdc::Spg => "SPG",
            Cdc::Ing => "ING",
            Cdc::Eng => "ENG",
            Cdc::Asg => "ASG",
            Cdc::Lpl => "LPL",
            Cdc::Dpl => "DPL",
            Cdc::Sec => "SEC",
            Cdc::Hst => "HST",
            Cdc::Ors => "ORS",
            Cdc::Tcs => "TCS",
            Cdc::Seq => "SEQ",
            Cdc::Hmv => "HMV",
            Cdc::Hwye => "HWYE",
            Cdc::Hdel => "HDEL",
            Cdc::Isc => "ISC",
            Cdc::Bac => "BAC",
            Cdc::Org => "ORG",
            Cdc::Tsg => "TSG",
            Cdc::Cug => "CUG",
            Cdc::Vsg => "VSG",
            Cdc::Curve => "CURVE",
            Cdc::Csg => "CSG",
            Cdc::Csd => "CSD",
            Cdc::Vsd => "VSD",
            Cdc::Cst => "CST",
            Cdc::Bts => "BTS",
            Cdc::Uts => "UTS",
            Cdc::Lts => "LTS",
            Cdc::Gts => "GTS",
            Cdc::Mts => "MTS",
            Cdc::Nts => "NTS",
            Cdc::Sts => "STS",
            Cdc::Cts => "CTS",
        }
    }

    /// Returns the class with the given mnemonic, case-insensitively, as the
    /// SCL `cdc` attribute is compared.
    pub fn from_name(s: &str) -> Option<Cdc> {
        let u = s.trim().to_ascii_uppercase();
        Cdc::ALL.into_iter().find(|c| c.as_str() == u)
    }

    /// Reports whether the class accepts control commands.
    pub fn is_controllable(self) -> bool {
        spec(self).ctl_val.is_some()
    }
}

impl std::fmt::Display for Cdc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Describes one attribute of a common data class: what it is called, the
/// functional constraint it is served under, and its type.
///
/// Structured attributes (`AnalogueValue`, `Vector`, the control structures)
/// carry their members in `children`.
#[derive(Debug, Clone, PartialEq)]
pub struct CdcAttribute {
    pub name: String,
    pub fc: Fc,
    pub kind: Type,
    /// The bit-string width; zero for other types.
    pub size: usize,
    /// Omitted unless asked for with [`CdcOptions::with_optional`].
    pub optional: bool,
    /// An array of `kind` (or, for a structure, of `children`), as long as
    /// the class's `maxPts`: see [`CdcOptions::with_max_pts`].
    pub array: bool,
    pub children: Vec<CdcAttribute>,

    /// Overrides the trigger options [`cdc_trg_ops`] derives from the name,
    /// for the attributes whose 7-3 options the rule does not produce.
    trg: Option<TrgOps>,
    /// A group of optional attributes of which at least one is present (7-3
    /// AtLeastOne): the first is built unless another member is asked for.
    one_of: &'static str,
    /// A group of optional attributes present together (7-3
    /// AllOrNonePerGroup): asking for one builds them all.
    all_or_none: &'static str,
    /// The `ctlVal` of a control tracking class, whose type is that of the
    /// control it tracks: see [`CdcOptions::with_tracked_control`].
    ctl_val_slot: bool,
}

/// Describes a data object nested inside another, as the phase measurands of
/// a `WYE` are.
#[derive(Debug, Clone, PartialEq)]
pub struct CdcSubObject {
    pub name: String,
    pub cdc: Cdc,
    pub optional: bool,
    /// A sub-object repeated `maxPts` times, as the harmonics of `HMV` are.
    /// The instances are named `name(1)`..`name(maxPts)`, as the SCL loader
    /// names the instances of an SDO with a count.
    pub array: bool,
}

/// Adjusts how a data object is built.
#[derive(Debug, Clone)]
pub struct CdcOptions {
    ctl_model: Option<CtlModel>,
    with_cancel: bool,
    integer_analogue: bool,
    optional: BTreeSet<String>,
    setting_fc: Fc,
    max_pts: usize,
    tracked: Option<Cdc>,
}

impl Default for CdcOptions {
    fn default() -> CdcOptions {
        CdcOptions {
            ctl_model: None,
            with_cancel: true,
            integer_analogue: false,
            optional: BTreeSet::new(),
            setting_fc: Fc::Sp,
            max_pts: 1,
            tracked: None,
        }
    }
}

impl CdcOptions {
    pub fn new() -> CdcOptions {
        CdcOptions::default()
    }

    /// Builds the control attributes for a controllable class: `Oper` and
    /// `Cancel` for the direct models, plus `SBO` or `SBOw` for the
    /// select-before-operate ones, and `ctlModel` carrying `m`.
    ///
    /// Without this a controllable class is built status-only, with no
    /// control attributes at all.
    #[must_use]
    pub fn with_control_model(mut self, m: CtlModel) -> CdcOptions {
        self.ctl_model = Some(m);
        self
    }

    /// Leaves the optional `Cancel` structure out of a controllable object.
    #[must_use]
    pub fn without_cancel(mut self) -> CdcOptions {
        self.with_cancel = false;
        self
    }

    /// Represents every `AnalogueValue` as an integer `i` instead of the
    /// default float `f`.
    #[must_use]
    pub fn with_integer_analogue(mut self) -> CdcOptions {
        self.integer_analogue = true;
        self
    }

    /// Includes optional attributes of the class by name, for example
    /// `instMag`, `units` or `subVal`.
    ///
    /// Names the class does not define are ignored.
    #[must_use]
    pub fn with_optional<S: AsRef<str>>(mut self, names: impl IntoIterator<Item = S>) -> CdcOptions {
        for n in names {
            self.optional.insert(n.as_ref().to_string());
        }
        self
    }

    /// Serves a setting class's values under `fc` instead of `SP`; pass
    /// [`Fc::Sg`] for values that belong to a setting group.
    #[must_use]
    pub fn with_setting_fc(mut self, fc: Fc) -> CdcOptions {
        self.setting_fc = fc;
        self
    }

    /// Sets the length of the array attributes and sub-objects of the classes
    /// that have them (`HST`, `CSG`, `CSD`, `HMV`, `HWYE`, `HDEL`), and the
    /// value of their `maxPts` attribute.
    ///
    /// Without it the arrays have one element, which is valid but rarely what
    /// a device has. Zero is ignored.
    #[must_use]
    pub fn with_max_pts(mut self, n: usize) -> CdcOptions {
        if n > 0 {
            self.max_pts = n;
        }
        self
    }

    /// Gives the `ctlVal` of a control tracking object (`CTS`) the type of the
    /// controllable class it tracks: [`Cdc::Spc`] or [`Cdc::Dpc`] for a
    /// boolean, [`Cdc::Inc`] for an integer, [`Cdc::Apc`] for an analogue
    /// value, and so on.
    ///
    /// Without it `ctlVal` is a boolean, as for the single point control
    /// tracked by `LTRK.SpcTrk`.
    #[must_use]
    pub fn with_tracked_control(mut self, cdc: Cdc) -> CdcOptions {
        self.tracked = Some(cdc);
        self
    }

    fn wants(&self, name: &str) -> bool {
        self.optional.contains(name)
    }

    /// Applies the presence groups of a class to the attributes asked for:
    /// the first member of an AtLeastOne group is built when no member is
    /// asked for, and asking for one member of an AllOrNone group asks for
    /// all of them.
    ///
    /// It returns a copy, since the option set is shared with the nested
    /// objects and with any sibling built from the same options.
    fn resolve_groups(&self, attrs: &[CdcAttribute]) -> CdcOptions {
        let mut one_of_asked: BTreeSet<&str> = BTreeSet::new();
        let mut all_asked: BTreeSet<&str> = BTreeSet::new();
        for a in attrs {
            if !a.one_of.is_empty() && self.wants(&a.name) {
                one_of_asked.insert(a.one_of);
            }
            if !a.all_or_none.is_empty() && self.wants(&a.name) {
                all_asked.insert(a.all_or_none);
            }
        }
        let mut out = self.clone();
        for a in attrs {
            if !a.one_of.is_empty() && !one_of_asked.contains(a.one_of) {
                out.optional.insert(a.name.clone());
                one_of_asked.insert(a.one_of);
            }
            if !a.all_or_none.is_empty() && all_asked.contains(a.all_or_none) {
                out.optional.insert(a.name.clone());
            }
        }
        out
    }
}

/// Returns the attribute table of a common data class.
pub fn cdc_attributes(cdc: Cdc) -> Vec<CdcAttribute> {
    spec(cdc).attrs
}

/// Returns the nested data objects of a common data class, empty for the
/// classes that have none.
pub fn cdc_sub_objects(cdc: Cdc) -> Vec<CdcSubObject> {
    spec(cdc).sub_objects
}

/// Returns the type of the class's `ctlVal`, or `None` when the class is not
/// controllable.
pub fn cdc_control_value(cdc: Cdc) -> Option<CdcAttribute> {
    spec(cdc).ctl_val.map(|b| *b)
}

/// Reports whether this crate has an attribute template for the named common
/// data class. The comparison is case-insensitive, as the SCL `cdc` attribute
/// is.
pub fn known_cdc(name: &str) -> bool {
    Cdc::from_name(name).is_some()
}

/// Returns the classes this module can build.
pub fn known_cdcs() -> Vec<Cdc> {
    Cdc::ALL.to_vec()
}

/// Builds a data object of the class named `cdc`, saying when the class is
/// one this crate does not know: it then returns a diagnostic and the named
/// data object with no attributes.
///
/// This matters for a model built from a file of a newer edition than this
/// crate, where the class is real and simply has no template here yet:
/// failing would make such a file unloadable, which is a worse outcome than
/// serving an object with no attributes.
pub fn new_data_object_or(
    name: &str,
    cdc: &str,
    opts: &CdcOptions,
) -> (DataObject, Option<Diagnostic>) {
    match Cdc::from_name(cdc) {
        Some(c) => (new_data_object(name, c, opts), None),
        None => (
            DataObject {
                name: name.to_string(),
                cdc: cdc.to_string(),
                ..Default::default()
            },
            Some(Diagnostic::new(
                name,
                format!(
                    "common data class {cdc:?} has no attribute template in this library; \
                     the object is present but has no attributes"
                ),
            )),
        ),
    }
}

/// [`new_data_object_or`] without the fallback object: an unknown class yields
/// `None` and a diagnostic.
pub fn new_data_object_or_none(
    name: &str,
    cdc: &str,
    opts: &CdcOptions,
) -> (Option<DataObject>, Option<Diagnostic>) {
    match Cdc::from_name(cdc) {
        Some(c) => (Some(new_data_object(name, c, opts)), None),
        None => (
            None,
            Some(Diagnostic::new(
                name,
                format!("common data class {cdc:?} has no attribute template in this library"),
            )),
        ),
    }
}

/// Builds a data object of the given common data class.
///
/// # Example
///
/// ```
/// use iec61850::model::{Cdc, CdcOptions, CtlModel, new_data_object};
///
/// let spc = new_data_object(
///     "SPCSO1",
///     Cdc::Spc,
///     &CdcOptions::new().with_control_model(CtlModel::SboEnhanced),
/// );
/// assert!(spc.attribute("Oper").is_some());
///
/// let mv = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new().with_optional(["units"]));
/// assert!(mv.attribute("units").is_some());
/// ```
pub fn new_data_object(name: &str, cdc: Cdc, opts: &CdcOptions) -> DataObject {
    let s = spec(cdc);
    let b = opts.resolve_groups(&s.attrs);
    let mut object = DataObject {
        name: name.to_string(),
        cdc: cdc.as_str().to_string(),
        ..Default::default()
    };
    for a in &s.attrs {
        let a = if a.ctl_val_slot {
            tracked_ctl_val(a, &b)
        } else {
            a.clone()
        };
        if let Some(mut da) = build_attribute(&a, &b) {
            inherit_trg_ops(&mut da);
            if da.name == "maxPts" && da.value.is_some() {
                da.value = Some(Value::uint32(u32::try_from(b.max_pts).unwrap_or(u32::MAX)));
            }
            object.attributes.push(da);
        }
    }
    if let (Some(ctl_val), Some(model)) = (s.ctl_val.as_deref(), b.ctl_model) {
        object
            .attributes
            .extend(control_attributes(ctl_val, model, &b));
    }
    for sub in &s.sub_objects {
        if sub.optional && !b.wants(&sub.name) {
            continue;
        }
        if !sub.array {
            object.objects.push(new_data_object(&sub.name, sub.cdc, opts));
            continue;
        }
        for ix in 1..=b.max_pts {
            object
                .objects
                .push(new_data_object(&format!("{}({ix})", sub.name), sub.cdc, opts));
        }
    }
    object
}

/// Gives the `ctlVal` slot of a tracking class the type of the tracked
/// control's `ctlVal`, or a boolean.
fn tracked_ctl_val(slot: &CdcAttribute, b: &CdcOptions) -> CdcAttribute {
    let mut v = da_bool(&slot.name, slot.fc);
    if let Some(ctl) = b.tracked.and_then(|t| spec(t).ctl_val) {
        v = *ctl;
        v.name = slot.name.clone();
        v.fc = slot.fc;
        for c in &mut v.children {
            c.fc = slot.fc;
        }
    }
    v.trg = slot.trg;
    v
}

/// Materialises one table entry, or `None` when it is an optional attribute
/// that was not asked for.
fn build_attribute(a: &CdcAttribute, b: &CdcOptions) -> Option<DataAttribute> {
    if a.optional && !b.wants(&a.name) {
        return None;
    }
    // Setting classes serve their values under SP by default, or under the
    // caller's chosen constraint when they belong to a setting group.
    let fc = if a.fc == Fc::Sp { b.setting_fc } else { a.fc };
    let mut trg = cdc_trg_ops(&a.name, fc);
    if let Some(t) = a.trg {
        if fc == a.fc {
            trg = t;
        }
    }
    let mut da = DataAttribute {
        name: a.name.clone(),
        fc,
        kind: Some(a.kind),
        trg_ops: trg,
        ..Default::default()
    };
    if a.kind == Type::Structure {
        let analogue = is_analogue(a);
        for c in &a.children {
            // An AnalogueValue carries i or f; exactly one is built.
            if analogue && (c.name == "i" || c.name == "f") {
                if (c.name == "i") != b.integer_analogue {
                    continue;
                }
                // The chosen member is never optional, whichever it is.
                let mut chosen = c.clone();
                chosen.optional = false;
                if let Some(cd) = build_member(&chosen, fc, b) {
                    da.children.push(cd);
                }
                continue;
            }
            if let Some(cd) = build_member(c, fc, b) {
                da.children.push(cd);
            }
        }
        if a.array {
            // An array of a constructed type: the members are the element
            // template, as the SCL loader builds one.
            da.kind = Some(Type::Array);
            da.count = b.max_pts;
        }
        return Some(da);
    }
    if a.array {
        da.kind = Some(Type::Array);
        da.count = b.max_pts;
        da.value = Some(Value::Array(
            (0..b.max_pts)
                .map(|_| zero_value(a.kind, a.size).unwrap_or(Value::None))
                .collect(),
        ));
        return Some(da);
    }
    da.value = zero_value(a.kind, a.size);
    Some(da)
}

/// Materialises a member of a structure, which inherits its parent's
/// functional constraint and trigger options.
fn build_member(a: &CdcAttribute, fc: Fc, b: &CdcOptions) -> Option<DataAttribute> {
    if a.optional && !b.wants(&a.name) {
        return None;
    }
    let mut child = a.clone();
    child.fc = fc;
    let mut da = build_attribute(&child, b)?;
    da.fc = fc;
    // Inherited from the enclosing attribute once it is complete.
    da.trg_ops = TrgOps(0);
    Some(da)
}

/// Gives every component of a structured attribute the attribute's own
/// trigger options, which cover all of it: a change to `mag.f` is a change
/// of `mag` (IEC 61850-7-2).
pub(crate) fn inherit_trg_ops(da: &mut DataAttribute) {
    let t = da.trg_ops;
    for c in &mut da.children {
        c.trg_ops = t;
        inherit_trg_ops(c);
    }
}

/// The trigger options of a common data class attribute, following the tables
/// of IEC 61850-7-3.
///
/// `q` is qchg; the timestamp, the deadbanded-away instantaneous values and
/// the substitution group trigger nothing; the analogue values also trigger on
/// update, and a frozen counter value only on update; every other status,
/// measurand, setting and configuration attribute is dchg. Descriptions,
/// blocking, control structures, service tracking and extensions trigger
/// nothing, and neither does a value in a setting group: the SG and SE
/// variants of the 7-3 setting classes have no trigger options, only the SP
/// form does. A table entry whose 7-3 options differ from these says so with
/// [`with_trg`].
fn cdc_trg_ops(name: &str, fc: Fc) -> TrgOps {
    if !matches!(fc, Fc::St | Fc::Mx | Fc::Sp | Fc::Sv | Fc::Cf) {
        return TrgOps(0);
    }
    match name {
        "q" => TrgOps::QUALITY_CHANGE,
        "t" | "instMag" | "instCVal" | "frTm" | "subVal" | "subMag" | "subCVal" | "subQ"
        | "subID" | "subEna" => TrgOps(0),
        "mag" | "cVal" => TrgOps(TrgOps::DATA_CHANGE.0 | TrgOps::DATA_UPDATE.0),
        "frVal" => TrgOps::DATA_UPDATE,
        _ => TrgOps::DATA_CHANGE,
    }
}

/// Reports whether a structure is an `AnalogueValue`, whose `i` and `f`
/// members are alternatives rather than both present.
fn is_analogue(a: &CdcAttribute) -> bool {
    a.kind == Type::Structure
        && a.children.len() == 2
        && a.children[0].name == "i"
        && a.children[1].name == "f"
}

/// Builds `ctlModel` and the control structures the model calls for: `Oper`
/// always, `SBO` or `SBOw` for the select-before-operate models, and `Cancel`
/// unless it was turned off.
fn control_attributes(
    ctl_val: &CdcAttribute,
    model: CtlModel,
    b: &CdcOptions,
) -> Vec<DataAttribute> {
    let mut out = vec![DataAttribute {
        name: "ctlModel".into(),
        fc: Fc::Cf,
        kind: Some(Type::Integer),
        value: Some(Value::int32(i32::from(model.code()))),
        ..Default::default()
    }];
    if model == CtlModel::StatusOnly {
        return out;
    }
    // Normal-security SBO reserves with a plain read of SBO; the enhanced
    // model reserves with a full parameter set written to SBOw.
    if model == CtlModel::SboNormal {
        out.push(DataAttribute {
            name: "SBO".into(),
            fc: Fc::Co,
            kind: Some(Type::VisibleString),
            value: Some(Value::visible_string("")),
            ..Default::default()
        });
    }
    if model == CtlModel::SboEnhanced {
        out.extend(build_attribute(&ctl_structure("SBOw", ctl_val, true), b));
    }
    out.extend(build_attribute(&ctl_structure("Oper", ctl_val, true), b));
    if b.with_cancel {
        // Cancel repeats the operate parameters without the checks.
        out.extend(build_attribute(&ctl_structure("Cancel", ctl_val, false), b));
    }
    out
}

/// The operate structure of IEC 61850-7-3:
/// `{ ctlVal, origin{orCat, orIdent}, ctlNum, T, Test [, Check] }`.
fn ctl_structure(name: &str, ctl_val: &CdcAttribute, with_check: bool) -> CdcAttribute {
    let mut value = ctl_val.clone();
    value.name = "ctlVal".into();
    value.fc = Fc::Co;
    value.optional = false;
    let mut members = vec![
        value,
        da_struct(
            "origin",
            Fc::Co,
            vec![da_int("orCat", Fc::Co), da_octet("orIdent", Fc::Co)],
        ),
        da_uint("ctlNum", Fc::Co),
        da_time("T", Fc::Co),
        da_bool("Test", Fc::Co),
    ];
    if with_check {
        members.push(da_bits("Check", Fc::Co, 2));
    }
    da_struct(name, Fc::Co, members)
}

/// The served default of a leaf: zero of its type, an all-clear quality for a
/// bit string, the epoch for timestamps.
fn zero_value(kind: Type, size: usize) -> Option<Value> {
    let v = match kind {
        Type::Boolean => Value::boolean(false),
        Type::Integer => Value::int32(0),
        Type::Unsigned => Value::uint32(0),
        Type::Float32 => Value::float32(0.0),
        Type::Float64 => Value::float64(0.0),
        Type::VisibleString => Value::visible_string(""),
        Type::MmsString => Value::mms_string(""),
        Type::OctetString => Value::octet_string(Vec::new()),
        Type::BitString => Value::bit_string(if size == 0 { 8 } else { size }),
        Type::UtcTime => Value::UtcTime([0; 8]),
        Type::BinaryTime => Value::BinaryTime(vec![0; 6]),
        _ => return None,
    };
    Some(v)
}

// Table helpers. They keep the class tables below readable: each entry is one
// attribute with its functional constraint and type.

fn da(name: &str, fc: Fc, kind: Type) -> CdcAttribute {
    CdcAttribute {
        name: name.to_string(),
        fc,
        kind,
        size: 0,
        optional: false,
        array: false,
        children: Vec::new(),
        trg: None,
        one_of: "",
        all_or_none: "",
        ctl_val_slot: false,
    }
}

fn da_bool(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::Boolean)
}
fn da_int(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::Integer)
}
fn da_uint(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::Unsigned)
}
fn da_float(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::Float32)
}
fn da_string(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::VisibleString)
}
/// A `Unicode255`, which 8-1 maps to an MMS string.
fn da_unicode(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::MmsString)
}
fn da_octet(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::OctetString)
}
fn da_time(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::UtcTime)
}
fn da_entry_time(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::BinaryTime)
}

fn da_bits(name: &str, fc: Fc, size: usize) -> CdcAttribute {
    CdcAttribute {
        size,
        ..da(name, fc, Type::BitString)
    }
}

fn da_struct(name: &str, fc: Fc, children: Vec<CdcAttribute>) -> CdcAttribute {
    CdcAttribute {
        children,
        ..da(name, fc, Type::Structure)
    }
}

/// The quality every status and measurand class carries.
fn da_quality(fc: Fc) -> CdcAttribute {
    da_bits("q", fc, 13)
}

/// The timestamp every status and measurand class carries.
fn da_t(fc: Fc) -> CdcAttribute {
    da_time("t", fc)
}

/// An `AnalogueValue`: an integer `i` or a float `f`, of which the builder
/// emits one.
fn da_analogue(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(name, fc, vec![da_int("i", fc), da_float("f", fc)])
}

/// A `Unit`: the SI unit and its multiplier.
fn da_units(fc: Fc) -> CdcAttribute {
    da_units_named("units", fc)
}

fn da_units_named(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(name, fc, vec![da_int("SIUnit", fc), da_int("multiplier", fc)])
}

/// A `Vector`: a magnitude and an optional angle.
fn da_vector(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(name, fc, vec![da_analogue("mag", fc), opt(da_analogue("ang", fc))])
}

/// A `ScaledValueConfig`, the scaling of an integer `AnalogueValue`.
fn da_svc(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(name, fc, vec![da_float("scaleFactor", fc), da_float("offset", fc)])
}

/// An `Originator`: the category and identity of whoever issued the last
/// control.
fn da_origin(fc: Fc) -> CdcAttribute {
    da_struct("origin", fc, vec![da_int("orCat", fc), da_octet("orIdent", fc)])
}

/// A `Point` of a curve.
fn da_point(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(
        name,
        fc,
        vec![da_float("xVal", fc), da_float("yVal", fc), opt(da_float("zVal", fc))],
    )
}

/// A `Cell` of a histogram: its lower bound, and optionally its upper bound
/// and a second dimension.
fn da_cell(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(
        name,
        fc,
        vec![
            da_float("xStart", fc),
            opt(da_float("xEnd", fc)),
            opt(da_float("yStart", fc)),
            opt(da_float("yEnd", fc)),
        ],
    )
}

/// A `CalendarTime`, a recurring time: the third Sunday of every month at
/// 02:00, say.
fn da_calendar(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(
        name,
        fc,
        vec![
            da_uint("occ", fc),
            da_int("occType", fc),
            da_int("occPer", fc),
            da_int("weekDay", fc),
            da_int("month", fc),
            da_uint("day", fc),
            da_uint("hr", fc),
            da_uint("mn", fc),
        ],
    )
}

/// The `PHYCOMADDR` of IEC 61850-8-1, the destination of a GOOSE or
/// sampled-value stream: MAC address, VLAN priority and identifier, and
/// APPID. It is the structure a server serves as a control block's
/// `DstAddress`.
fn da_phy_com_addr(name: &str, fc: Fc) -> CdcAttribute {
    da_struct(
        name,
        fc,
        vec![
            da_octet("Addr", fc),
            da_uint("PRIORITY", fc),
            da_uint("VID", fc),
            da_uint("APPID", fc),
        ],
    )
}

fn opt(mut a: CdcAttribute) -> CdcAttribute {
    a.optional = true;
    a
}

/// Makes `a` an array of `maxPts` elements.
fn array(mut a: CdcAttribute) -> CdcAttribute {
    a.array = true;
    a
}

/// Gives `a` the trigger options `t`, where [`cdc_trg_ops`] would derive
/// others from its name.
fn with_trg(mut a: CdcAttribute, t: TrgOps) -> CdcAttribute {
    a.trg = Some(t);
    a
}

/// An attribute that triggers nothing.
fn no_trg(a: CdcAttribute) -> CdcAttribute {
    with_trg(a, TrgOps(0))
}

fn one_of(group: &'static str, mut a: CdcAttribute) -> CdcAttribute {
    a.one_of = group;
    a
}

fn all_or_none(group: &'static str, mut a: CdcAttribute) -> CdcAttribute {
    a.all_or_none = group;
    a
}

const DCHG_DUPD: TrgOps = TrgOps(TrgOps::DATA_CHANGE.0 | TrgOps::DATA_UPDATE.0);

/// The `SV` substitution group a status, measurand or controllable class may
/// carry: the substituted value takes the type of the value it replaces, so
/// the caller passes a bare attribute of the right kind.
fn substitution(value_kind: CdcAttribute) -> Vec<CdcAttribute> {
    substitution_as("subVal", value_kind)
}

/// [`substitution`] for the classes whose substituted value has its own
/// name: `subMag` for MV, `subCVal` for CMV.
fn substitution_as(name: &str, value_kind: CdcAttribute) -> Vec<CdcAttribute> {
    let mut sub = value_kind;
    sub.name = name.into();
    sub.fc = Fc::Sv;
    let mut sub_q = da_quality(Fc::Sv);
    sub_q.name = "subQ".into();
    vec![
        opt(da_bool("subEna", Fc::Sv)),
        opt(sub),
        opt(sub_q),
        opt(da_string("subID", Fc::Sv)),
    ]
}

fn sub_object(name: &str, cdc: Cdc, optional: bool) -> CdcSubObject {
    CdcSubObject {
        name: name.to_string(),
        cdc,
        optional,
        array: false,
    }
}

fn sub_array(name: &str, cdc: Cdc, optional: bool) -> CdcSubObject {
    CdcSubObject {
        array: true,
        ..sub_object(name, cdc, optional)
    }
}

#[derive(Default)]
struct CdcSpec {
    attrs: Vec<CdcAttribute>,
    sub_objects: Vec<CdcSubObject>,
    /// The type of the control value, for the controllable classes only. The
    /// control structures are assembled around it.
    ctl_val: Option<Box<CdcAttribute>>,
}

/// The evaluation parameters of `HMV`, and with `angRef` those of `HWYE` and
/// `HDEL`.
fn harmonic_attrs(with_ang_ref: bool) -> Vec<CdcAttribute> {
    use Fc::*;
    let mut out = vec![da_uint("numHar", Cf), da_uint("numCyc", Cf), da_uint("evalTm", Cf)];
    if with_ang_ref {
        out.push(opt(da_int("angRef", Cf)));
    }
    out.extend([
        opt(da_uint("smpRate", Cf)),
        da_float("frequency", Cf),
        opt(da_int("hvRef", Cf)),
        opt(da_uint("rmsCyc", Cf)),
        da_uint("maxPts", Cf),
        opt(da_string("d", Dc)),
    ]);
    out
}

/// The common part of the service tracking classes: the object the service
/// addressed, the service and its outcome, who asked, and when. `NTS` has no
/// certificate issuer.
fn tracking(with_cert_issuer: bool) -> Vec<CdcAttribute> {
    use Fc::*;
    let mut out = vec![
        with_trg(da_string("objRef", Sr), TrgOps::DATA_UPDATE),
        da_int("serviceType", Sr),
        da_int("errorCode", Sr),
        opt(da_octet("originatorID", Sr)),
        da_t(Sr),
    ];
    if with_cert_issuer {
        out.push(opt(da_unicode("certIssuer", Sr)));
    }
    out
}

/// The `valWTr` of a step position: the position and whether it is in
/// transition.
fn val_w_tr(fc: Fc) -> CdcAttribute {
    da_struct("valWTr", fc, vec![da_int("posVal", fc), da_bool("transInd", fc)])
}

/// The per-class attribute table.
///
/// Entries are in the order IEC 61850-7-3 lists them; [`opt`] marks the ones
/// a caller has to ask for.
fn spec(cdc: Cdc) -> CdcSpec {
    use Fc::*;
    let mut s = CdcSpec::default();
    let a = &mut s.attrs;
    match cdc {
        // --- Status information ---
        Cdc::Sps => {
            a.extend([da_bool("stVal", St), da_quality(St), da_t(St)]);
            a.extend(substitution(da_bool("", St)));
            a.push(opt(da_string("d", Dc)));
        }
        Cdc::Dps => {
            a.extend([da_bits("stVal", St, 2), da_quality(St), da_t(St)]);
            a.extend(substitution(da_bits("", St, 2)));
            a.push(opt(da_string("d", Dc)));
        }
        Cdc::Ins => {
            a.extend([with_trg(da_int("stVal", St), DCHG_DUPD), da_quality(St), da_t(St)]);
            a.extend(substitution(da_int("", St)));
            a.extend([opt(da_units(Cf)), opt(da_string("d", Dc))]);
        }
        Cdc::Ens => {
            a.extend([with_trg(da_int("stVal", St), DCHG_DUPD), da_quality(St), da_t(St)]);
            a.extend(substitution(da_int("", St)));
            a.push(opt(da_string("d", Dc)));
        }
        Cdc::Vss => {
            a.extend([da_string("stVal", St), da_quality(St), da_t(St)]);
            a.push(opt(da_string("d", Dc)));
        }
        Cdc::Act => {
            a.extend([
                da_bool("general", St),
                opt(da_bool("phsA", St)),
                opt(da_bool("phsB", St)),
                opt(da_bool("phsC", St)),
                opt(da_bool("neut", St)),
                da_quality(St),
                da_t(St),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Acd => {
            a.extend([
                da_bool("general", St),
                da_int("dirGeneral", St),
                opt(da_bool("phsA", St)),
                opt(da_int("dirPhsA", St)),
                opt(da_bool("phsB", St)),
                opt(da_int("dirPhsB", St)),
                opt(da_bool("phsC", St)),
                opt(da_int("dirPhsC", St)),
                opt(da_bool("neut", St)),
                opt(da_int("dirNeut", St)),
                da_quality(St),
                da_t(St),
                opt(da_string("d", Dc)),
            ]);
        }
        // SEC counts security violations (IEC 62351-7 and the GSAL node of
        // 7-4): the count, the severity of the last one, and where it came
        // from.
        Cdc::Sec => {
            a.extend([
                da_uint("cnt", St),
                no_trg(da_int("sev", St)),
                da_t(St),
                opt(no_trg(da_octet("addr", St))),
                opt(no_trg(da_string("addInfo", St))),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Bcr => {
            a.extend([
                da_int("actVal", St),
                opt(da_int("frVal", St)),
                opt(da_time("frTm", St)),
                da_quality(St),
                da_t(St),
                opt(da_units(Cf)),
                da_float("pulsQty", Cf),
                opt(da_bool("frEna", Cf)),
                opt(da_time("strTm", Cf)),
                opt(da_int("frPd", Cf)),
                opt(da_bool("frRs", Cf)),
                opt(da_string("d", Dc)),
            ]);
        }
        // HST is a histogram: hstVal counts per cell, hstRangeC the cell
        // bounds, both maxPts long.
        Cdc::Hst => {
            a.extend([
                with_trg(array(da_int("hstVal", St)), DCHG_DUPD),
                da_quality(St),
                da_t(St),
                da_uint("numPts", Cf),
                array(da_cell("hstRangeC", Cf)),
                da_units_named("xUnits", Cf),
                opt(da_units_named("yUnits", Cf)),
                opt(da_units(Cf)),
                da_uint("maxPts", Cf),
                da_string("xD", Dc),
                opt(da_unicode("xDU", Dc)),
                opt(da_string("yD", Dc)),
                opt(da_unicode("yDU", Dc)),
                opt(da_string("d", Dc)),
            ]);
        }
        // ORS is an object reference status: the reference an object is
        // currently using, as FSCC.ActSchdRef names the active schedule.
        Cdc::Ors => {
            a.extend([da_string("stVal", St), da_quality(St), da_t(St)]);
            a.push(opt(da_string("d", Dc)));
        }
        // TCS is a time status: stVal is itself a timestamp.
        Cdc::Tcs => {
            a.extend([with_trg(da_time("stVal", St), DCHG_DUPD), da_quality(St), da_t(St)]);
            a.push(opt(da_string("d", Dc)));
        }

        // --- Measurand information ---
        Cdc::Mv => {
            a.extend([
                opt(da_analogue("instMag", Mx)),
                da_analogue("mag", Mx),
                opt(da_int("range", Mx)),
                da_quality(Mx),
                da_t(Mx),
            ]);
            a.extend(substitution_as("subMag", da_analogue("", Mx)));
            a.extend([
                opt(da_bool("blkEna", Bl)),
                opt(da_units(Cf)),
                opt(da_uint("db", Cf)),
                opt(da_uint("zeroDb", Cf)),
                opt(da_svc("sVC", Cf)),
                opt(da_uint("smpRate", Cf)),
                opt(da_float("dbRef", Cf)),
                opt(da_float("zeroDbRef", Cf)),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Cmv => {
            a.extend([
                opt(da_vector("instCVal", Mx)),
                da_vector("cVal", Mx),
                opt(da_int("range", Mx)),
                opt(da_int("rangeAng", Mx)),
                da_quality(Mx),
                da_t(Mx),
            ]);
            a.extend(substitution_as("subCVal", da_vector("", Mx)));
            a.extend([
                opt(da_bool("blkEna", Bl)),
                opt(da_units(Cf)),
                opt(da_uint("db", Cf)),
                opt(da_uint("dbAng", Cf)),
                opt(da_uint("zeroDb", Cf)),
                opt(da_svc("magSVC", Cf)),
                opt(da_svc("angSVC", Cf)),
                opt(da_int("angRef", Cf)),
                opt(da_uint("smpRate", Cf)),
                opt(da_float("dbRef", Cf)),
                opt(da_float("zeroDbRef", Cf)),
                opt(da_float("dbAngRef", Cf)),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Sav => {
            a.extend([
                da_analogue("instMag", Mx),
                da_quality(Mx),
                opt(da_t(Mx)),
                opt(da_units(Cf)),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Wye => {
            a.extend([opt(da_int("angRef", Cf)), opt(da_string("d", Dc))]);
            s.sub_objects = vec![
                sub_object("phsA", Cdc::Cmv, false),
                sub_object("phsB", Cdc::Cmv, false),
                sub_object("phsC", Cdc::Cmv, false),
                sub_object("neut", Cdc::Cmv, true),
                sub_object("net", Cdc::Cmv, true),
                sub_object("res", Cdc::Cmv, true),
            ];
        }
        Cdc::Del => {
            a.extend([opt(da_int("angRef", Cf)), opt(da_string("d", Dc))]);
            s.sub_objects = vec![
                sub_object("phsAB", Cdc::Cmv, false),
                sub_object("phsBC", Cdc::Cmv, false),
                sub_object("phsCA", Cdc::Cmv, false),
            ];
        }
        // SEQ is a set of sequence components. c2 and c3 are optional in 7-3
        // (mandatory for a synchrophasor), so they are asked for by name.
        Cdc::Seq => {
            a.extend([
                no_trg(da_int("seqT", Mx)),
                opt(da_int("phsRef", Cf)),
                opt(da_string("d", Dc)),
            ]);
            s.sub_objects = vec![
                sub_object("c1", Cdc::Cmv, false),
                sub_object("c2", Cdc::Cmv, true),
                sub_object("c3", Cdc::Cmv, true),
            ];
        }
        // HMV, HWYE and HDEL are harmonics: arrays of complex values, maxPts
        // long, with the evaluation parameters alongside.
        Cdc::Hmv => {
            a.extend(harmonic_attrs(false));
            s.sub_objects = vec![sub_array("har", Cdc::Cmv, false)];
        }
        Cdc::Hwye => {
            a.extend(harmonic_attrs(true));
            s.sub_objects = vec![
                sub_array("phsAHar", Cdc::Cmv, false),
                sub_array("phsBHar", Cdc::Cmv, true),
                sub_array("phsCHar", Cdc::Cmv, true),
                sub_array("neutHar", Cdc::Cmv, true),
                sub_array("netHar", Cdc::Cmv, true),
                sub_array("resHar", Cdc::Cmv, true),
            ];
        }
        Cdc::Hdel => {
            a.extend(harmonic_attrs(true));
            s.sub_objects = vec![
                sub_array("phsABHar", Cdc::Cmv, false),
                sub_array("phsBCHar", Cdc::Cmv, true),
                sub_array("phsCAHar", Cdc::Cmv, true),
            ];
        }

        // --- Controllable information ---
        Cdc::Spc => {
            a.extend([da_bool("stVal", St), da_quality(St), da_t(St)]);
            a.extend(substitution(da_bool("", St)));
            a.extend([
                opt(da_bool("stSeld", St)),
                opt(da_uint("sboTimeout", Cf)),
                opt(da_int("sboClass", Cf)),
                opt(da_uint("operTimeout", Cf)),
                opt(da_string("d", Dc)),
            ]);
            s.ctl_val = Some(Box::new(da_bool("ctlVal", Co)));
        }
        Cdc::Dpc => {
            a.extend([da_bits("stVal", St, 2), da_quality(St), da_t(St)]);
            a.extend(substitution(da_bits("", St, 2)));
            a.extend([
                opt(da_bool("stSeld", St)),
                opt(da_uint("sboTimeout", Cf)),
                opt(da_int("sboClass", Cf)),
                opt(da_string("d", Dc)),
            ]);
            s.ctl_val = Some(Box::new(da_bool("ctlVal", Co)));
        }
        Cdc::Inc => {
            a.extend([with_trg(da_int("stVal", St), DCHG_DUPD), da_quality(St), da_t(St)]);
            a.extend(substitution(da_int("", St)));
            a.extend([
                opt(da_bool("stSeld", St)),
                opt(da_units(Cf)),
                opt(da_int("minVal", Cf)),
                opt(da_int("maxVal", Cf)),
                opt(da_uint("stepSize", Cf)),
                opt(da_uint("sboTimeout", Cf)),
                opt(da_string("d", Dc)),
            ]);
            s.ctl_val = Some(Box::new(da_int("ctlVal", Co)));
        }
        Cdc::Enc => {
            a.extend([da_int("stVal", St), da_quality(St), da_t(St)]);
            a.extend(substitution(da_int("", St)));
            a.extend([opt(da_bool("stSeld", St)), opt(da_string("d", Dc))]);
            s.ctl_val = Some(Box::new(da_int("ctlVal", Co)));
        }
        Cdc::Bsc => {
            a.extend([val_w_tr(St), da_quality(St), da_t(St)]);
            a.extend(substitution(val_w_tr(Sv)));
            a.extend([
                opt(da_bool("stSeld", St)),
                da_bool("persistent", Cf),
                opt(da_int("minVal", Cf)),
                opt(da_int("maxVal", Cf)),
                opt(da_string("d", Dc)),
            ]);
            // Tcmd: stop, lower, higher.
            s.ctl_val = Some(Box::new(da_bits("ctlVal", Co, 2)));
        }
        // ISC is an integer-controlled step position, a tap changer that is
        // told the position rather than lower or higher.
        Cdc::Isc => {
            a.extend([
                opt(no_trg(da_origin(St))),
                opt(no_trg(da_uint("ctlNum", St))),
                val_w_tr(St),
                da_quality(St),
                da_t(St),
                opt(da_bool("stSeld", St)),
                opt(with_trg(da_bool("opRcvd", Or), TrgOps::DATA_CHANGE)),
                opt(with_trg(da_bool("opOk", Or), TrgOps::DATA_CHANGE)),
                opt(da_time("tOpOk", Or)),
            ]);
            a.extend(substitution(val_w_tr(Sv)));
            a.extend([
                opt(da_bool("blkEna", Bl)),
                opt(da_uint("sboTimeout", Cf)),
                opt(da_int("sboClass", Cf)),
                opt(da_int("minVal", Cf)),
                opt(da_int("maxVal", Cf)),
                opt(da_uint("operTimeout", Cf)),
                opt(da_string("d", Dc)),
            ]);
            s.ctl_val = Some(Box::new(da_int("ctlVal", Co)));
        }
        Cdc::Apc => {
            a.extend([da_analogue("mxVal", Mx), da_quality(Mx), da_t(Mx)]);
            a.extend(substitution(da_analogue("", Mx)));
            a.extend([
                opt(da_bool("stSeld", Mx)),
                opt(da_units(Cf)),
                opt(da_uint("db", Cf)),
                opt(da_analogue("minVal", Cf)),
                opt(da_analogue("maxVal", Cf)),
                opt(da_analogue("stepSize", Cf)),
                opt(da_uint("sboTimeout", Cf)),
                opt(da_string("d", Dc)),
            ]);
            s.ctl_val = Some(Box::new(da_analogue("ctlVal", Co)));
        }
        // BAC is an analogue value controlled by lower and higher steps, as a
        // Petersen coil's position is (ANCR.ColChg).
        Cdc::Bac => {
            a.extend([
                opt(no_trg(da_origin(Mx))),
                opt(no_trg(da_uint("ctlNum", Mx))),
                da_analogue("mxVal", Mx),
                da_quality(Mx),
                da_t(Mx),
                opt(da_bool("stSeld", Mx)),
                opt(with_trg(da_bool("opRcvd", Or), TrgOps::DATA_CHANGE)),
                opt(with_trg(da_bool("opOk", Or), TrgOps::DATA_CHANGE)),
                opt(da_time("tOpOk", Or)),
            ]);
            a.extend(substitution(da_analogue("", Mx)));
            a.extend([
                opt(da_bool("blkEna", Bl)),
                da_bool("persistent", Cf),
                opt(da_uint("sboTimeout", Cf)),
                opt(da_int("sboClass", Cf)),
                opt(da_units(Cf)),
                opt(da_uint("db", Cf)),
                opt(da_svc("sVC", Cf)),
                opt(da_analogue("minVal", Cf)),
                opt(da_analogue("maxVal", Cf)),
                opt(da_analogue("stepSize", Cf)),
                opt(da_uint("operTimeout", Cf)),
                opt(da_float("dbRef", Cf)),
                opt(da_string("d", Dc)),
            ]);
            // Tcmd: stop, lower, higher.
            s.ctl_val = Some(Box::new(da_bits("ctlVal", Co, 2)));
        }

        // --- Settings ---
        Cdc::Spg => {
            a.extend([da_bool("setVal", Sp), opt(da_string("d", Dc))]);
        }
        Cdc::Ing => {
            a.extend([
                da_int("setVal", Sp),
                opt(da_units(Cf)),
                opt(da_int("minVal", Cf)),
                opt(da_int("maxVal", Cf)),
                opt(da_uint("stepSize", Cf)),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Eng => {
            a.extend([da_int("setVal", Sp), opt(da_string("d", Dc))]);
        }
        // ORG is an object reference setting: the input an LN takes its value
        // from (LLN0.InRef, LGOS.GoCBRef), with an optional test source.
        Cdc::Org => {
            a.extend([
                da_string("setSrcRef", Sp),
                all_or_none("test", opt(da_string("setTstRef", Sp))),
                opt(da_string("setSrcCB", Sp)),
                opt(da_string("setTstCB", Sp)),
                opt(da_string("intAddr", Sp)),
                all_or_none("test", opt(da_bool("tstEna", Sp))),
                opt(da_string("purpose", Dc)),
                opt(da_string("d", Dc)),
            ]);
        }
        // TSG is a time setting, as an absolute time or a calendar rule; one
        // of them is present, setTm unless setCal is asked for.
        Cdc::Tsg => {
            a.extend([
                one_of("time", opt(da_time("setTm", Sp))),
                one_of("time", opt(da_calendar("setCal", Sp))),
                opt(da_string("d", Dc)),
            ]);
        }
        // CUG is a currency setting: an ISO 4217 code.
        Cdc::Cug => {
            a.extend([da_string("cur", Sp), opt(da_string("d", Dc))]);
        }
        Cdc::Vsg => {
            a.extend([da_string("setVal", Sp), opt(da_string("d", Dc))]);
        }
        Cdc::Asg => {
            a.extend([
                da_analogue("setMag", Sp),
                opt(da_units(Cf)),
                opt(da_analogue("minVal", Cf)),
                opt(da_analogue("maxVal", Cf)),
                opt(da_analogue("stepSize", Cf)),
                opt(da_string("d", Dc)),
            ]);
        }
        // CURVE is a curve setting by characteristic and parameters.
        Cdc::Curve => {
            a.extend([
                da_int("setCharact", Sp),
                opt(da_float("setParA", Sp)),
                opt(da_float("setParB", Sp)),
                opt(da_float("setParC", Sp)),
                opt(da_float("setParD", Sp)),
                opt(da_float("setParE", Sp)),
                opt(da_float("setParF", Sp)),
                opt(da_string("d", Dc)),
            ]);
        }
        // CSG is a curve shape setting: the points of the curve, maxPts long.
        Cdc::Csg => {
            a.extend([
                opt(da_float("pointZ", Sp)),
                da_uint("numPts", Sp),
                array(da_point("crvPts", Sp)),
                da_units_named("xUnits", Cf),
                da_units_named("yUnits", Cf),
                opt(da_units_named("zUnits", Cf)),
                da_uint("maxPts", Cf),
                da_string("xD", Dc),
                opt(da_unicode("xDU", Dc)),
                da_string("yD", Dc),
                opt(da_unicode("yDU", Dc)),
                opt(da_string("zD", Dc)),
                opt(da_unicode("zDU", Dc)),
                opt(da_string("d", Dc)),
            ]);
        }

        // --- Description ---
        Cdc::Lpl => {
            a.extend([
                da_string("vendor", Dc),
                da_string("swRev", Dc),
                opt(da_string("d", Dc)),
                opt(da_string("configRev", Dc)),
                opt(da_string("ldNs", Ex)),
            ]);
        }
        Cdc::Dpl => {
            a.extend([
                da_string("vendor", Dc),
                opt(da_string("hwRev", Dc)),
                opt(da_string("swRev", Dc)),
                opt(da_string("serNum", Dc)),
                opt(da_string("model", Dc)),
                opt(da_string("location", Dc)),
            ]);
        }
        // CSD is a curve shape description: a CSG's shape, read-only.
        Cdc::Csd => {
            a.extend([
                da_units_named("xUnits", Dc),
                da_string("xD", Dc),
                opt(da_unicode("xDU", Dc)),
                da_units_named("yUnits", Dc),
                da_string("yD", Dc),
                opt(da_unicode("yDU", Dc)),
                opt(da_units_named("zUnits", Dc)),
                opt(da_string("zD", Dc)),
                opt(da_unicode("zDU", Dc)),
                da_uint("numPts", Dc),
                array(da_point("crvPts", Dc)),
                da_uint("maxPts", Cf),
                opt(da_string("d", Dc)),
            ]);
        }
        // VSD is a visible string description.
        Cdc::Vsd => {
            a.extend([da_string("val", Dc), opt(da_string("d", Dc))]);
        }

        // --- Service tracking (IEC 61850-7-2 Edition 2, the LTRK node) ---
        // Each records the last service applied to one kind of object: who
        // asked, what for, the outcome, and the object's state afterwards.
        Cdc::Cst => {
            a.extend(tracking(true));
            a.push(opt(da_string("d", Dc)));
        }
        Cdc::Bts => {
            a.extend(tracking(true));
            a.extend([
                da_string("rptID", Sr),
                da_bool("rptEna", Sr),
                da_string("datSet", Sr),
                da_uint("confRev", Sr),
                da_bits("optFlds", Sr, 10),
                da_uint("bufTm", Sr),
                da_uint("sqNum", Sr),
                da_bits("trgOps", Sr, 6),
                da_uint("intgPd", Sr),
                da_bool("gi", Sr),
                da_bool("purgeBuf", Sr),
                da_octet("entryID", Sr),
                da_entry_time("timeOfEntry", Sr),
                opt(da_int("resvTms", Sr)),
                opt(da_octet("owner", Sr)),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Uts => {
            a.extend(tracking(true));
            a.extend([
                da_string("rptID", Sr),
                da_bool("rptEna", Sr),
                da_bool("resv", Sr),
                da_string("datSet", Sr),
                da_uint("confRev", Sr),
                da_bits("optFlds", Sr, 10),
                da_uint("bufTm", Sr),
                da_uint("sqNum", Sr),
                da_bits("trgOps", Sr, 6),
                da_uint("intgPd", Sr),
                da_bool("gi", Sr),
                opt(da_octet("owner", Sr)),
                opt(da_string("d", Dc)),
            ]);
        }
        // LTS tracks the ACSI log control block. The log's own state
        // (OldEntrTm, NewEntr...) belongs to the LOG class, not to the block.
        Cdc::Lts => {
            a.extend(tracking(true));
            a.extend([
                da_bool("logEna", Sr),
                da_string("datSet", Sr),
                da_uint("bufTm", Sr),
                da_bits("trgOps", Sr, 6),
                da_uint("intgPd", Sr),
                da_string("logRef", Sr),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Gts => {
            a.extend(tracking(true));
            a.extend([
                da_bool("goEna", Sr),
                da_string("goID", Sr),
                da_string("datSet", Sr),
                da_uint("confRev", Sr),
                da_bool("ndsCom", Sr),
                da_phy_com_addr("dstAddress", Sr),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Mts => {
            a.extend(tracking(true));
            a.extend([
                da_bool("svEna", Sr),
                da_string("msvID", Sr),
                da_string("datSet", Sr),
                da_uint("confRev", Sr),
                da_uint("smpRate", Sr),
                da_bits("optFlds", Sr, 10),
                da_int("smpMod", Sr),
                da_phy_com_addr("dstAddress", Sr),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Nts => {
            a.extend(tracking(false));
            a.extend([
                da_bool("svEna", Sr),
                da_bool("resv", Sr),
                da_string("usvID", Sr),
                da_string("datSet", Sr),
                da_uint("confRev", Sr),
                da_int("smpMod", Sr),
                da_uint("smpRate", Sr),
                da_bits("optFlds", Sr, 10),
                da_phy_com_addr("dstAddress", Sr),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Sts => {
            a.extend(tracking(true));
            a.extend([
                da_uint("numOfSG", Sr),
                da_uint("actSG", Sr),
                da_uint("editSG", Sr),
                da_bool("cnfEdit", Sr),
                da_time("lActTm", Sr),
                opt(da_uint("resvTms", Sr)),
                opt(da_string("d", Dc)),
            ]);
        }
        Cdc::Cts => {
            a.extend(tracking(true));
            let mut ctl_val = da_bool("ctlVal", Sr);
            ctl_val.ctl_val_slot = true;
            a.extend([
                ctl_val,
                opt(da_time("operTm", Sr)),
                da_origin(Sr),
                da_uint("ctlNum", Sr),
                da_time("T", Sr),
                da_bool("Test", Sr),
                da_bits("Check", Sr, 2),
                da_int("respAddCause", Sr),
                opt(da_string("d", Dc)),
            ]);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(das: &[DataAttribute]) -> Vec<&str> {
        das.iter().map(|a| a.name.as_str()).collect()
    }

    fn find<'a>(o: &'a DataObject, name: &str) -> &'a DataAttribute {
        o.attribute(name)
            .unwrap_or_else(|| panic!("{} has no {name}: {:?}", o.name, names(&o.attributes)))
    }

    const DCHG: TrgOps = TrgOps::DATA_CHANGE;

    /// Built data objects carry the trigger options of IEC 61850-7-3, down to
    /// the leaves an update writes.
    #[test]
    fn built_objects_carry_the_trigger_options_of_7_3() {
        let mv = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new());
        for (name, want) in [("mag", DCHG_DUPD), ("q", TrgOps::QUALITY_CHANGE), ("t", TrgOps(0))] {
            let a = mv.attribute(name).expect(name);
            assert_eq!(a.trg_ops, want, "{name}");
            for c in &a.children {
                assert_eq!(c.trg_ops, want, "{name}.{} inherits", c.name);
            }
        }
        let spc = new_data_object(
            "SPCSO1",
            Cdc::Spc,
            &CdcOptions::new().with_control_model(CtlModel::DirectNormal),
        );
        for a in &spc.attributes {
            if a.fc == Fc::Co {
                assert_eq!(a.trg_ops, TrgOps(0), "control structure {}", a.name);
            }
        }
        assert_eq!(spc.attribute("stVal").unwrap().trg_ops, DCHG);
    }

    #[test]
    fn class_names_round_trip() {
        for cdc in Cdc::ALL {
            assert_eq!(Cdc::from_name(cdc.as_str()), Some(cdc));
            assert_eq!(Cdc::from_name(&cdc.as_str().to_lowercase()), Some(cdc));
        }
        assert_eq!(Cdc::from_name("NOPE"), None);
        assert!(known_cdc("cmv") && known_cdc(" CMV "));
        assert!(!known_cdc("nosuchclass"));
    }

    #[test]
    fn a_measured_value_carries_only_its_mandatory_attributes_by_default() {
        let mv = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new());
        assert_eq!(names(&mv.attributes), ["mag", "q", "t"]);
        assert_eq!(mv.cdc, "MV");
        // mag is an AnalogueValue holding one member, the float by default.
        let mag = mv.attribute("mag").unwrap();
        assert_eq!(names(&mag.children), ["f"]);
        assert_eq!(mag.fc, Fc::Mx);
        assert_eq!(mag.children[0].fc, Fc::Mx, "members inherit the parent's FC");
        // The quality is the standard 13-bit string.
        assert_eq!(mv.attribute("q").unwrap().value.as_ref().unwrap().bit_len(), 13);
    }

    #[test]
    fn optional_attributes_appear_only_when_asked_for() {
        let plain = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new());
        assert!(plain.attribute("units").is_none());
        assert!(plain.attribute("db").is_none());

        let rich = new_data_object(
            "AnIn1",
            Cdc::Mv,
            &CdcOptions::new().with_optional(["units", "db", "instMag"]),
        );
        assert!(rich.attribute("units").is_some());
        assert!(rich.attribute("db").is_some());
        assert!(rich.attribute("instMag").is_some());
        // Unknown names are ignored rather than erroring.
        let ignored = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new().with_optional(["nope"]));
        assert_eq!(names(&ignored.attributes), ["mag", "q", "t"]);
    }

    /// An AnalogueValue is a choice of i or f, not a structure holding both;
    /// emitting both makes every read of a measurand the wrong shape.
    #[test]
    fn an_analogue_value_carries_exactly_one_member() {
        let f = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new());
        assert_eq!(names(&f.attribute("mag").unwrap().children), ["f"]);

        let i = new_data_object("AnIn1", Cdc::Mv, &CdcOptions::new().with_integer_analogue());
        assert_eq!(names(&i.attribute("mag").unwrap().children), ["i"]);
    }

    /// The control attributes a class gets are decided entirely by its model;
    /// building the wrong set makes control fail at the first step.
    #[test]
    fn each_control_model_builds_its_own_attribute_set() {
        let build = |m: CtlModel| {
            let o = new_data_object("SPCSO1", Cdc::Spc, &CdcOptions::new().with_control_model(m));
            names(&o.attributes)
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        let has = |v: &[String], n: &str| v.iter().any(|s| s == n);

        let direct = build(CtlModel::DirectNormal);
        assert!(has(&direct, "Oper") && has(&direct, "Cancel"));
        assert!(!has(&direct, "SBO") && !has(&direct, "SBOw"));

        let sbo_normal = build(CtlModel::SboNormal);
        assert!(has(&sbo_normal, "SBO"), "normal SBO reserves by reading SBO");
        assert!(!has(&sbo_normal, "SBOw"));

        let sbo_enhanced = build(CtlModel::SboEnhanced);
        assert!(has(&sbo_enhanced, "SBOw"), "enhanced SBO reserves by writing SBOw");
        assert!(!has(&sbo_enhanced, "SBO"));

        // status-only gets ctlModel and nothing else.
        let status = build(CtlModel::StatusOnly);
        assert!(has(&status, "ctlModel"));
        assert!(!has(&status, "Oper"));
    }

    #[test]
    fn without_a_control_model_a_controllable_class_is_status_only() {
        let o = new_data_object("SPCSO1", Cdc::Spc, &CdcOptions::new());
        assert_eq!(names(&o.attributes), ["stVal", "q", "t"]);
        assert!(o.attribute("ctlModel").is_none());
    }

    #[test]
    fn the_operate_structure_has_the_members_the_standard_defines() {
        let o = new_data_object(
            "SPCSO1",
            Cdc::Spc,
            &CdcOptions::new().with_control_model(CtlModel::DirectNormal),
        );
        let oper = o.attribute("Oper").unwrap();
        assert_eq!(
            names(&oper.children),
            ["ctlVal", "origin", "ctlNum", "T", "Test", "Check"]
        );
        assert_eq!(oper.fc, Fc::Co);
        let origin = oper.child("origin").unwrap();
        assert_eq!(names(&origin.children), ["orCat", "orIdent"]);

        // Cancel repeats the parameters without the checks.
        let cancel = o.attribute("Cancel").unwrap();
        assert_eq!(names(&cancel.children), ["ctlVal", "origin", "ctlNum", "T", "Test"]);
    }

    #[test]
    fn cancel_can_be_left_out() {
        let o = new_data_object(
            "SPCSO1",
            Cdc::Spc,
            &CdcOptions::new()
                .with_control_model(CtlModel::DirectNormal)
                .without_cancel(),
        );
        assert!(o.attribute("Oper").is_some());
        assert!(o.attribute("Cancel").is_none());
    }

    #[test]
    fn ctl_model_carries_the_configured_value() {
        for m in [
            CtlModel::DirectNormal,
            CtlModel::SboNormal,
            CtlModel::DirectEnhanced,
            CtlModel::SboEnhanced,
        ] {
            let o = new_data_object("SPCSO1", Cdc::Spc, &CdcOptions::new().with_control_model(m));
            let v = o.attribute("ctlModel").unwrap().value.as_ref().unwrap();
            assert_eq!(v.as_i32(), i32::from(m.code()));
            assert_eq!(o.attribute("ctlModel").unwrap().fc, Fc::Cf);
        }
    }

    #[test]
    fn a_wye_nests_its_mandatory_phase_measurands() {
        let wye = new_data_object("PhV", Cdc::Wye, &CdcOptions::new());
        let subs: Vec<&str> = wye.objects.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(subs, ["phsA", "phsB", "phsC"]);
        assert_eq!(wye.objects[0].cdc, "CMV");

        let full = new_data_object("PhV", Cdc::Wye, &CdcOptions::new().with_optional(["neut"]));
        let subs: Vec<&str> = full.objects.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(subs, ["phsA", "phsB", "phsC", "neut"]);
    }

    /// Setting values move between SP and SG depending on whether they belong
    /// to a setting group, and the server serves them under whichever applies.
    #[test]
    fn a_setting_class_can_be_served_under_the_setting_group_constraint() {
        let sp = new_data_object("OpDlTmms", Cdc::Ing, &CdcOptions::new());
        assert_eq!(sp.attribute("setVal").unwrap().fc, Fc::Sp);

        let sg = new_data_object("OpDlTmms", Cdc::Ing, &CdcOptions::new().with_setting_fc(Fc::Sg));
        assert_eq!(sg.attribute("setVal").unwrap().fc, Fc::Sg);
    }

    /// Every class in the table builds, and every leaf it produces has a value
    /// the server can serve.
    #[test]
    fn every_class_builds_with_a_value_on_every_leaf() {
        fn check(path: &str, das: &[DataAttribute]) {
            for da in das {
                let p = format!("{path}.{}", da.name);
                // An array of a constructed type carries its element template
                // in children and no value, as the SCL loader builds one.
                if da.kind == Some(Type::Structure)
                    || (da.kind == Some(Type::Array) && !da.children.is_empty())
                {
                    if da.kind == Some(Type::Array) {
                        assert!(da.count >= 1, "{p} is an array of no elements");
                    }
                    assert!(!da.children.is_empty(), "{p} is an empty structure");
                    check(&p, &da.children);
                    continue;
                }
                assert!(da.value.is_some(), "{p} has no value");
                assert_ne!(da.fc, Fc::None, "{p} has no functional constraint");
            }
        }
        for cdc in known_cdcs() {
            let plain = new_data_object("X", cdc, &CdcOptions::new());
            assert_eq!(plain.cdc, cdc.as_str());
            assert!(
                !plain.attributes.is_empty() || !plain.objects.is_empty(),
                "{cdc} produced an empty object"
            );
            // Build with every optional attribute asked for, which is the
            // widest tree a class can produce.
            let all_names: Vec<String> = cdc_attributes(cdc)
                .iter()
                .map(|a| a.name.clone())
                .chain(cdc_sub_objects(cdc).iter().map(|s| s.name.clone()))
                .collect();
            let rich = new_data_object(
                "X",
                cdc,
                &CdcOptions::new()
                    .with_optional(all_names)
                    .with_control_model(CtlModel::SboEnhanced),
            );
            assert!(rich.attributes.len() >= plain.attributes.len());
            check(cdc.as_str(), &rich.attributes);
            for sub in &rich.objects {
                check(&format!("{cdc}.{}", sub.name), &sub.attributes);
            }
        }
    }

    #[test]
    fn the_control_value_type_is_reported_for_controllable_classes_only() {
        assert_eq!(cdc_control_value(Cdc::Spc).unwrap().kind, Type::Boolean);
        assert_eq!(cdc_control_value(Cdc::Inc).unwrap().kind, Type::Integer);
        assert_eq!(cdc_control_value(Cdc::Apc).unwrap().kind, Type::Structure);
        assert_eq!(cdc_control_value(Cdc::Bsc).unwrap().kind, Type::BitString);
        assert!(cdc_control_value(Cdc::Mv).is_none());
        assert!(Cdc::Spc.is_controllable() && Cdc::Bac.is_controllable());
        assert!(!Cdc::Mv.is_controllable());
    }

    /// Every class whose value can be substituted carries the SV group, and
    /// the substituted value keeps the shape of the value it replaces.
    #[test]
    fn the_substitution_group_covers_the_substitutable_classes() {
        let has_sub = |cdc: Cdc| cdc_attributes(cdc).iter().any(|a| a.name == "subEna");
        for cdc in [
            Cdc::Sps,
            Cdc::Dps,
            Cdc::Ins,
            Cdc::Ens,
            Cdc::Mv,
            Cdc::Cmv,
            Cdc::Spc,
            Cdc::Dpc,
            Cdc::Inc,
            Cdc::Enc,
            Cdc::Bsc,
            Cdc::Isc,
            Cdc::Apc,
            Cdc::Bac,
        ] {
            assert!(has_sub(cdc), "{cdc} has no substitution group");
        }
        for cdc in [Cdc::Vss, Cdc::Act, Cdc::Acd, Cdc::Sav, Cdc::Org, Cdc::Hst, Cdc::Sec] {
            assert!(!has_sub(cdc), "{cdc} has a substitution group 7-3 does not give it");
        }
        let (mv, d) = new_data_object_or(
            "AnIn1",
            "MV",
            &CdcOptions::new().with_optional(["subEna", "subMag", "subQ", "subID"]),
        );
        assert!(d.is_none());
        let sub = mv.attribute("subMag").expect("subMag");
        assert_eq!(sub.kind, Some(Type::Structure));
        assert!(sub.child("f").is_some() || sub.child("i").is_some());
        let q = mv.attribute("subQ").unwrap();
        assert_eq!(q.value.as_ref().unwrap().bit_len(), 13);
    }

    /// A class this crate has no template for still yields the object, with a
    /// diagnostic, rather than failing the load of a newer file.
    #[test]
    fn an_unknown_class_yields_the_named_object_and_a_diagnostic() {
        let (o, d) = new_data_object_or("Thing", "XYZ", &CdcOptions::new());
        assert_eq!(o.name, "Thing");
        assert_eq!(o.cdc, "XYZ");
        assert!(o.attributes.is_empty() && o.objects.is_empty());
        assert!(d.is_some());
        let (o, d) = new_data_object_or_none("Thing", "XYZ", &CdcOptions::new());
        assert!(o.is_none() && d.is_some());
        for cdc in ["SEC", "HST", "BAC", "ORG", "TSG", "CUG", "VSG", "CSG"] {
            assert!(new_data_object_or("X", cdc, &CdcOptions::new()).1.is_none(), "{cdc}");
        }
    }

    #[test]
    fn a_histogram_has_arrays_max_pts_long() {
        let hst = new_data_object("Hst", Cdc::Hst, &CdcOptions::new().with_max_pts(4));
        let hv = find(&hst, "hstVal");
        assert_eq!(hv.kind, Some(Type::Array));
        assert_eq!(hv.count, 4);
        assert_eq!(hv.value.as_ref().unwrap().len(), 4);
        assert_eq!(hv.trg_ops, DCHG_DUPD);
        let rc = find(&hst, "hstRangeC");
        assert_eq!(rc.kind, Some(Type::Array));
        assert_eq!(rc.count, 4);
        assert!(rc.value.is_none() && rc.child("xStart").is_some());
        assert_eq!(find(&hst, "maxPts").value.as_ref().unwrap().as_u64(), 4);
        for name in ["numPts", "xUnits", "xD", "q", "t"] {
            find(&hst, name);
        }
        let plain = new_data_object("Hst", Cdc::Hst, &CdcOptions::new());
        assert_eq!(find(&plain, "hstVal").count, 1, "one element by default");
    }

    #[test]
    fn a_binary_controlled_analogue_value() {
        let bac = new_data_object(
            "ColChg",
            Cdc::Bac,
            &CdcOptions::new().with_control_model(CtlModel::DirectNormal),
        );
        let mx = find(&bac, "mxVal");
        assert_eq!(mx.fc, Fc::Mx);
        assert_eq!(names(&mx.children), ["f"]);
        let p = find(&bac, "persistent");
        assert_eq!((p.fc, p.kind), (Fc::Cf, Some(Type::Boolean)));
        let ctl_val = find(&bac, "Oper").child("ctlVal").unwrap();
        assert_eq!(ctl_val.kind, Some(Type::BitString));
        assert_eq!(ctl_val.value.as_ref().unwrap().bit_len(), 2);
        assert!(bac.attribute("opRcvd").is_none());
        let sub = new_data_object("ColChg", Cdc::Bac, &CdcOptions::new().with_optional(["subVal"]));
        let sv = find(&sub, "subVal");
        assert_eq!((sv.fc, sv.kind), (Fc::Sv, Some(Type::Structure)));
    }

    #[test]
    fn an_integer_controlled_step_position() {
        let isc = new_data_object(
            "TapChg",
            Cdc::Isc,
            &CdcOptions::new().with_control_model(CtlModel::SboEnhanced),
        );
        let v = find(&isc, "valWTr");
        assert!(v.child("posVal").is_some() && v.child("transInd").is_some());
        let c = find(&isc, "SBOw").child("ctlVal").unwrap();
        assert_eq!(c.kind, Some(Type::Integer));
    }

    #[test]
    fn an_object_reference_setting_builds_its_test_group_together() {
        let org = new_data_object("InRef1", Cdc::Org, &CdcOptions::new());
        let a = find(&org, "setSrcRef");
        assert_eq!((a.fc, a.kind), (Fc::Sp, Some(Type::VisibleString)));
        assert!(org.attribute("setTstRef").is_none() && org.attribute("tstEna").is_none());
        // setTstRef and tstEna come together (7-3 AllOrNonePerGroup).
        let with_test = new_data_object("InRef1", Cdc::Org, &CdcOptions::new().with_optional(["tstEna"]));
        assert!(with_test.attribute("setTstRef").is_some() && with_test.attribute("tstEna").is_some());
        // Asking for one member does not leak into a sibling built with the
        // same options.
        let o1 = CdcOptions::new().with_optional(["setTstRef"]);
        new_data_object("A", Cdc::Org, &o1);
        assert!(new_data_object("B", Cdc::Sps, &o1).attribute("tstEna").is_none());
    }

    #[test]
    fn a_time_setting_has_one_of_its_forms() {
        let tsg = new_data_object("StrTm", Cdc::Tsg, &CdcOptions::new());
        assert!(tsg.attribute("setTm").is_some() && tsg.attribute("setCal").is_none());
        let cal = new_data_object("StrTm", Cdc::Tsg, &CdcOptions::new().with_optional(["setCal"]));
        assert!(cal.attribute("setTm").is_none());
        let sc = find(&cal, "setCal");
        for m in ["occ", "occType", "occPer", "weekDay", "month", "day", "hr", "mn"] {
            assert!(sc.child(m).is_some(), "setCal has no {m}");
        }
        let both = new_data_object(
            "StrTm",
            Cdc::Tsg,
            &CdcOptions::new().with_optional(["setTm", "setCal"]),
        );
        assert!(both.attribute("setTm").is_some() && both.attribute("setCal").is_some());
    }

    #[test]
    fn string_and_currency_settings() {
        let cug = new_data_object("Cur", Cdc::Cug, &CdcOptions::new().with_setting_fc(Fc::Sg));
        let a = find(&cug, "cur");
        assert_eq!((a.fc, a.kind), (Fc::Sg, Some(Type::VisibleString)));
        let vsg = new_data_object("Txt", Cdc::Vsg, &CdcOptions::new());
        let a = find(&vsg, "setVal");
        assert_eq!((a.fc, a.kind), (Fc::Sp, Some(Type::VisibleString)));
    }

    #[test]
    fn a_curve_shape_setting() {
        let csg = new_data_object(
            "Crv",
            Cdc::Csg,
            &CdcOptions::new().with_max_pts(10).with_setting_fc(Fc::Sg),
        );
        let pts = find(&csg, "crvPts");
        assert_eq!((pts.kind, pts.count, pts.fc), (Some(Type::Array), 10, Fc::Sg));
        assert!(pts.child("xVal").is_some() && pts.child("yVal").is_some());
        assert!(pts.child("zVal").is_none());
        assert_eq!(find(&csg, "numPts").fc, Fc::Sg);
        for name in ["xUnits", "yUnits", "maxPts"] {
            assert_eq!(find(&csg, name).fc, Fc::Cf, "{name}");
        }
    }

    #[test]
    fn harmonics_are_arrays_of_sub_objects() {
        let hmv = new_data_object("Har", Cdc::Hmv, &CdcOptions::new().with_max_pts(3));
        let subs: Vec<(&str, &str)> = hmv
            .objects
            .iter()
            .map(|o| (o.name.as_str(), o.cdc.as_str()))
            .collect();
        assert_eq!(subs, [("har(1)", "CMV"), ("har(2)", "CMV"), ("har(3)", "CMV")]);
        let hwye = new_data_object(
            "HA",
            Cdc::Hwye,
            &CdcOptions::new().with_max_pts(2).with_optional(["phsBHar"]),
        );
        assert_eq!(hwye.objects.len(), 4);
    }

    #[test]
    fn service_tracking_classes() {
        let cts = new_data_object("SpcTrk", Cdc::Cts, &CdcOptions::new());
        let c = find(&cts, "ctlVal");
        assert_eq!((c.kind, c.fc), (Some(Type::Boolean), Fc::Sr));
        assert_eq!(find(&cts, "objRef").trg_ops, TrgOps::DATA_UPDATE);
        let apc = new_data_object(
            "ApcTrk",
            Cdc::Cts,
            &CdcOptions::new().with_tracked_control(Cdc::Apc),
        );
        let c = find(&apc, "ctlVal");
        assert_eq!((c.kind, c.fc), (Some(Type::Structure), Fc::Sr));
        assert_eq!(c.children.len(), 1);
        assert_eq!(c.children[0].fc, Fc::Sr);
        let gts = new_data_object("GocbTrk", Cdc::Gts, &CdcOptions::new());
        let dst = find(&gts, "dstAddress");
        for m in ["Addr", "PRIORITY", "VID", "APPID"] {
            assert!(dst.child(m).is_some(), "dstAddress has no {m}");
        }
        let nts = new_data_object("X", Cdc::Nts, &CdcOptions::new().with_optional(["certIssuer"]));
        assert!(nts.attribute("certIssuer").is_none(), "NTS has no certIssuer in 7-2");
    }

    /// A value in a setting group triggers nothing (the SG and SE variants of
    /// the 7-3 setting classes have no trigger options); the SP form and the
    /// configuration attributes keep theirs.
    #[test]
    fn setting_group_values_trigger_nothing() {
        for fc in [Fc::Sg, Fc::Se] {
            let asg = new_data_object(
                "StrVal",
                Cdc::Asg,
                &CdcOptions::new().with_setting_fc(fc).with_optional(["units"]),
            );
            let mag = find(&asg, "setMag");
            assert_eq!(mag.trg_ops, TrgOps(0), "setMag [{fc}]");
            for c in &mag.children {
                assert_eq!(c.trg_ops, TrgOps(0), "setMag.{} [{fc}]", c.name);
            }
            assert_eq!(find(&asg, "units").trg_ops, DCHG);
            let csg = new_data_object("Crv", Cdc::Csg, &CdcOptions::new().with_setting_fc(fc));
            for name in ["crvPts", "numPts"] {
                assert_eq!(find(&csg, name).trg_ops, TrgOps(0), "CSG {name} [{fc}]");
            }
        }
        let asg = new_data_object("StrVal", Cdc::Asg, &CdcOptions::new());
        assert_eq!(find(&asg, "setMag").trg_ops, DCHG);
        let ins = new_data_object("X", Cdc::Ins, &CdcOptions::new());
        assert_eq!(find(&ins, "stVal").trg_ops, DCHG_DUPD);
    }
}
