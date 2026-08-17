//! The IEC 61850-7-3 common data classes.
//!
//! A common data class selects the attribute table a data object is built
//! from. [`new_data_object`] materialises one: its mandatory attributes, any
//! optional ones asked for, and any nested data objects the class defines,
//! each with a zero value of its type.

use std::collections::BTreeSet;

use crate::mms::{Type, Value};

use super::{CtlModel, DataAttribute, DataObject, Fc};

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
}

impl Cdc {
    /// Every class this module can build.
    pub const ALL: [Cdc; 25] = [
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
        }
    }

    /// Returns the class with the given mnemonic, case-insensitively.
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
    pub children: Vec<CdcAttribute>,
}

/// Describes a data object nested inside another, as the phase measurands of
/// a `WYE` are.
#[derive(Debug, Clone, PartialEq)]
pub struct CdcSubObject {
    pub name: String,
    pub cdc: Cdc,
    pub optional: bool,
}

/// Adjusts how a data object is built.
#[derive(Debug, Clone)]
pub struct CdcOptions {
    ctl_model: Option<CtlModel>,
    with_cancel: bool,
    integer_analogue: bool,
    optional: BTreeSet<String>,
    setting_fc: Fc,
}

impl Default for CdcOptions {
    fn default() -> CdcOptions {
        CdcOptions {
            ctl_model: None,
            with_cancel: true,
            integer_analogue: false,
            optional: BTreeSet::new(),
            setting_fc: Fc::Sp,
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

    fn wants(&self, name: &str) -> bool {
        self.optional.contains(name)
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
    let mut object = DataObject {
        name: name.to_string(),
        cdc: cdc.as_str().to_string(),
        ..Default::default()
    };
    for a in &s.attrs {
        if let Some(da) = build_attribute(a, opts) {
            object.attributes.push(da);
        }
    }
    if let (Some(ctl_val), Some(model)) = (s.ctl_val.as_deref(), opts.ctl_model) {
        object
            .attributes
            .extend(control_attributes(ctl_val, model, opts));
    }
    for sub in &s.sub_objects {
        if sub.optional && !opts.wants(&sub.name) {
            continue;
        }
        object
            .objects
            .push(new_data_object(&sub.name, sub.cdc, opts));
    }
    object
}

/// Materialises one table entry, or `None` when it is an optional attribute
/// that was not asked for.
fn build_attribute(a: &CdcAttribute, opts: &CdcOptions) -> Option<DataAttribute> {
    if a.optional && !opts.wants(&a.name) {
        return None;
    }
    // Setting classes serve their values under SP by default, or under the
    // caller's chosen constraint when they belong to a setting group.
    let fc = if a.fc == Fc::Sp { opts.setting_fc } else { a.fc };
    build_attribute_with_fc(a, fc, opts)
}

fn build_attribute_with_fc(a: &CdcAttribute, fc: Fc, opts: &CdcOptions) -> Option<DataAttribute> {
    let mut da = DataAttribute {
        name: a.name.clone(),
        fc,
        kind: Some(a.kind),
        ..Default::default()
    };
    if a.kind == Type::Structure {
        let analogue = is_analogue(a);
        for c in &a.children {
            // An AnalogueValue carries i or f; exactly one is built.
            if analogue && (c.name == "i" || c.name == "f") {
                if (c.name == "i") != opts.integer_analogue {
                    continue;
                }
                // The chosen member is never optional, whichever it is.
                let mut chosen = c.clone();
                chosen.optional = false;
                if let Some(cd) = build_attribute_with_fc(&chosen, fc, opts) {
                    da.children.push(cd);
                }
                continue;
            }
            // Members of a structure inherit their parent's constraint.
            if c.optional && !opts.wants(&c.name) {
                continue;
            }
            if let Some(cd) = build_attribute_with_fc(c, fc, opts) {
                da.children.push(cd);
            }
        }
        return Some(da);
    }
    da.value = zero_value(a.kind, a.size);
    Some(da)
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
    opts: &CdcOptions,
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
        if let Some(da) = build_attribute(&ctl_structure("SBOw", ctl_val, true), opts) {
            out.push(da);
        }
    }
    if let Some(da) = build_attribute(&ctl_structure("Oper", ctl_val, true), opts) {
        out.push(da);
    }
    if opts.with_cancel {
        // Cancel repeats the operate parameters without the checks.
        if let Some(da) = build_attribute(&ctl_structure("Cancel", ctl_val, false), opts) {
            out.push(da);
        }
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
        CdcAttribute {
            name: "ctlNum".into(),
            fc: Fc::Co,
            kind: Type::Unsigned,
            size: 0,
            optional: false,
            children: Vec::new(),
        },
        CdcAttribute {
            name: "T".into(),
            fc: Fc::Co,
            kind: Type::UtcTime,
            size: 0,
            optional: false,
            children: Vec::new(),
        },
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
        children: Vec::new(),
    }
}

fn da_bool(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::Boolean)
}
fn da_int(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::Integer)
}
fn da_float(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::Float32)
}
fn da_string(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::VisibleString)
}
fn da_octet(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::OctetString)
}
fn da_time(name: &str, fc: Fc) -> CdcAttribute {
    da(name, fc, Type::UtcTime)
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
    da_struct(
        "units",
        fc,
        vec![da_int("SIUnit", fc), da_int("multiplier", fc)],
    )
}

fn opt(mut a: CdcAttribute) -> CdcAttribute {
    a.optional = true;
    a
}

/// The `SV` substitution group every status and measurand class may carry.
fn substitution(value_kind: CdcAttribute) -> Vec<CdcAttribute> {
    let mut sub = value_kind;
    sub.name = "subVal".into();
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

/// The per-class attribute table.
///
/// Entries are in the order IEC 61850-7-3 lists them, mandatory attributes
/// first; [`opt`] marks the ones a caller has to ask for.
fn spec(cdc: Cdc) -> CdcSpec {
    use Fc::*;
    let mut s = CdcSpec::default();
    match cdc {
        // --- Status information ---
        Cdc::Sps => {
            s.attrs = vec![da_bool("stVal", St), da_quality(St), da_t(St)];
            s.attrs.extend(substitution(da_bool("", St)));
            s.attrs.push(opt(da_string("d", Dc)));
        }
        Cdc::Dps => {
            s.attrs = vec![da_bits("stVal", St, 2), da_quality(St), da_t(St)];
            s.attrs.extend(substitution(da_bits("", St, 2)));
            s.attrs.push(opt(da_string("d", Dc)));
        }
        Cdc::Ins => {
            s.attrs = vec![da_int("stVal", St), da_quality(St), da_t(St)];
            s.attrs.extend(substitution(da_int("", St)));
            s.attrs.extend([opt(da_units(Cf)), opt(da_string("d", Dc))]);
        }
        Cdc::Ens => {
            s.attrs = vec![da_int("stVal", St), da_quality(St), da_t(St)];
            s.attrs.extend(substitution(da_int("", St)));
            s.attrs.push(opt(da_string("d", Dc)));
        }
        Cdc::Vss => {
            s.attrs = vec![da_string("stVal", St), da_quality(St), da_t(St)];
            s.attrs.extend(substitution(da_string("", St)));
            s.attrs.push(opt(da_string("d", Dc)));
        }
        Cdc::Act => {
            s.attrs = vec![
                da_bool("general", St),
                opt(da_bool("phsA", St)),
                opt(da_bool("phsB", St)),
                opt(da_bool("phsC", St)),
                opt(da_bool("neut", St)),
                da_quality(St),
                da_t(St),
                opt(da_string("d", Dc)),
            ];
        }
        Cdc::Acd => {
            s.attrs = vec![
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
            ];
        }
        Cdc::Bcr => {
            s.attrs = vec![
                da_int("actVal", St),
                da_quality(St),
                da_t(St),
                opt(da_int("frVal", St)),
                opt(da_time("frTm", St)),
                opt(da_float("pulsQty", Cf)),
                opt(da_units(Cf)),
                opt(da_string("d", Dc)),
            ];
        }

        // --- Measurand information ---
        Cdc::Mv => {
            s.attrs = vec![
                da_analogue("mag", Mx),
                da_quality(Mx),
                da_t(Mx),
                opt(da_analogue("instMag", Mx)),
                opt(da_int("range", Mx)),
                opt(da_units(Cf)),
                opt(da_int("db", Cf)),
                opt(da_int("zeroDb", Cf)),
                opt(da_string("d", Dc)),
            ];
        }
        Cdc::Cmv => {
            s.attrs = vec![
                da_struct(
                    "cVal",
                    Mx,
                    vec![da_analogue("mag", Mx), opt(da_analogue("ang", Mx))],
                ),
                da_quality(Mx),
                da_t(Mx),
                opt(da_int("range", Mx)),
                opt(da_units(Cf)),
                opt(da_int("db", Cf)),
                opt(da_string("d", Dc)),
            ];
        }
        Cdc::Sav => {
            s.attrs = vec![
                da_analogue("instMag", Mx),
                da_quality(Mx),
                opt(da_t(Mx)),
                opt(da_units(Cf)),
                opt(da_string("d", Dc)),
            ];
        }
        Cdc::Wye => {
            s.attrs = vec![opt(da_int("angRef", Cf)), opt(da_string("d", Dc))];
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
            s.attrs = vec![opt(da_int("angRef", Cf)), opt(da_string("d", Dc))];
            s.sub_objects = vec![
                sub_object("phsAB", Cdc::Cmv, false),
                sub_object("phsBC", Cdc::Cmv, false),
                sub_object("phsCA", Cdc::Cmv, false),
            ];
        }

        // --- Controllable information ---
        Cdc::Spc => {
            s.attrs = vec![
                da_bool("stVal", St),
                da_quality(St),
                da_t(St),
                opt(da_bool("stSeld", St)),
                opt(da_int("sboTimeout", Cf)),
                opt(da_int("sboClass", Cf)),
                opt(da_int("operTimeout", Cf)),
                opt(da_string("d", Dc)),
            ];
            s.ctl_val = Some(Box::new(da_bool("ctlVal", Co)));
        }
        Cdc::Dpc => {
            s.attrs = vec![
                da_bits("stVal", St, 2),
                da_quality(St),
                da_t(St),
                opt(da_bool("stSeld", St)),
                opt(da_int("sboTimeout", Cf)),
                opt(da_int("sboClass", Cf)),
                opt(da_string("d", Dc)),
            ];
            s.ctl_val = Some(Box::new(da_bool("ctlVal", Co)));
        }
        Cdc::Inc => {
            s.attrs = vec![
                da_int("stVal", St),
                da_quality(St),
                da_t(St),
                opt(da_bool("stSeld", St)),
                opt(da_units(Cf)),
                opt(da_int("minVal", Cf)),
                opt(da_int("maxVal", Cf)),
                opt(da_int("stepSize", Cf)),
                opt(da_int("sboTimeout", Cf)),
                opt(da_string("d", Dc)),
            ];
            s.ctl_val = Some(Box::new(da_int("ctlVal", Co)));
        }
        Cdc::Enc => {
            s.attrs = vec![
                da_int("stVal", St),
                da_quality(St),
                da_t(St),
                opt(da_bool("stSeld", St)),
                opt(da_string("d", Dc)),
            ];
            s.ctl_val = Some(Box::new(da_int("ctlVal", Co)));
        }
        Cdc::Bsc => {
            s.attrs = vec![
                da_struct(
                    "valWTr",
                    St,
                    vec![da_int("posVal", St), da_bool("transInd", St)],
                ),
                da_quality(St),
                da_t(St),
                opt(da_bool("stSeld", St)),
                opt(da_int("minVal", Cf)),
                opt(da_int("maxVal", Cf)),
                opt(da_string("d", Dc)),
            ];
            s.ctl_val = Some(Box::new(da_int("ctlVal", Co)));
        }
        Cdc::Apc => {
            s.attrs = vec![
                da_analogue("mxVal", Mx),
                da_quality(Mx),
                da_t(Mx),
                opt(da_bool("stSeld", St)),
                opt(da_units(Cf)),
                opt(da_int("db", Cf)),
                opt(da_analogue("minVal", Cf)),
                opt(da_analogue("maxVal", Cf)),
                opt(da_analogue("stepSize", Cf)),
                opt(da_int("sboTimeout", Cf)),
                opt(da_string("d", Dc)),
            ];
            s.ctl_val = Some(Box::new(da_analogue("ctlVal", Co)));
        }

        // --- Settings ---
        Cdc::Spg => {
            s.attrs = vec![da_bool("setVal", Sp), opt(da_string("d", Dc))];
        }
        Cdc::Ing => {
            s.attrs = vec![
                da_int("setVal", Sp),
                opt(da_units(Cf)),
                opt(da_int("minVal", Cf)),
                opt(da_int("maxVal", Cf)),
                opt(da_int("stepSize", Cf)),
                opt(da_string("d", Dc)),
            ];
        }
        Cdc::Eng => {
            s.attrs = vec![da_int("setVal", Sp), opt(da_string("d", Dc))];
        }
        Cdc::Asg => {
            s.attrs = vec![
                da_analogue("setMag", Sp),
                opt(da_units(Cf)),
                opt(da_analogue("minVal", Cf)),
                opt(da_analogue("maxVal", Cf)),
                opt(da_analogue("stepSize", Cf)),
                opt(da_string("d", Dc)),
            ];
        }

        // --- Description ---
        Cdc::Lpl => {
            s.attrs = vec![
                da_string("vendor", Dc),
                da_string("swRev", Dc),
                opt(da_string("d", Dc)),
                opt(da_string("configRev", Dc)),
                opt(da_string("ldNs", Ex)),
            ];
        }
        Cdc::Dpl => {
            s.attrs = vec![
                da_string("vendor", Dc),
                opt(da_string("hwRev", Dc)),
                opt(da_string("swRev", Dc)),
                opt(da_string("serNum", Dc)),
                opt(da_string("model", Dc)),
                opt(da_string("location", Dc)),
            ];
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

    #[test]
    fn class_names_round_trip() {
        for cdc in Cdc::ALL {
            assert_eq!(Cdc::from_name(cdc.as_str()), Some(cdc));
            assert_eq!(Cdc::from_name(&cdc.as_str().to_lowercase()), Some(cdc));
        }
        assert_eq!(Cdc::from_name("NOPE"), None);
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

        let i = new_data_object(
            "AnIn1",
            Cdc::Mv,
            &CdcOptions::new().with_integer_analogue(),
        );
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

        let direct = build(CtlModel::DirectNormal);
        assert!(direct.contains(&"Oper".to_string()));
        assert!(direct.contains(&"Cancel".to_string()));
        assert!(!direct.contains(&"SBO".to_string()));
        assert!(!direct.contains(&"SBOw".to_string()));

        let sbo_normal = build(CtlModel::SboNormal);
        assert!(sbo_normal.contains(&"SBO".to_string()), "normal SBO reserves by reading SBO");
        assert!(!sbo_normal.contains(&"SBOw".to_string()));

        let sbo_enhanced = build(CtlModel::SboEnhanced);
        assert!(
            sbo_enhanced.contains(&"SBOw".to_string()),
            "enhanced SBO reserves by writing SBOw"
        );
        assert!(!sbo_enhanced.contains(&"SBO".to_string()));

        // status-only gets ctlModel and nothing else.
        let status = build(CtlModel::StatusOnly);
        assert!(status.contains(&"ctlModel".to_string()));
        assert!(!status.contains(&"Oper".to_string()));
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
        assert_eq!(
            names(&cancel.children),
            ["ctlVal", "origin", "ctlNum", "T", "Test"]
        );
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

        let sg = new_data_object(
            "OpDlTmms",
            Cdc::Ing,
            &CdcOptions::new().with_setting_fc(Fc::Sg),
        );
        assert_eq!(sg.attribute("setVal").unwrap().fc, Fc::Sg);
    }

    #[test]
    fn every_known_class_builds_without_panicking() {
        for cdc in Cdc::ALL {
            let plain = new_data_object("X", cdc, &CdcOptions::new());
            assert_eq!(plain.cdc, cdc.as_str());
            assert!(
                !plain.attributes.is_empty() || !plain.objects.is_empty(),
                "{cdc} produced an empty object"
            );

            // And with every optional attribute the class defines asked for.
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
        }
    }

    #[test]
    fn the_control_value_type_is_reported_for_controllable_classes_only() {
        assert_eq!(cdc_control_value(Cdc::Spc).unwrap().kind, Type::Boolean);
        assert_eq!(cdc_control_value(Cdc::Inc).unwrap().kind, Type::Integer);
        assert_eq!(cdc_control_value(Cdc::Apc).unwrap().kind, Type::Structure);
        assert!(cdc_control_value(Cdc::Mv).is_none());
        assert!(Cdc::Spc.is_controllable());
        assert!(!Cdc::Mv.is_controllable());
    }

    #[test]
    fn every_leaf_of_a_built_object_carries_a_zero_value() {
        fn check(da: &DataAttribute) {
            if da.children.is_empty() {
                assert!(
                    da.value.is_some(),
                    "leaf {} has no value",
                    da.name
                );
            }
            for c in &da.children {
                check(c);
            }
        }
        for cdc in Cdc::ALL {
            let o = new_data_object("X", cdc, &CdcOptions::new().with_control_model(CtlModel::SboEnhanced));
            for a in &o.attributes {
                check(a);
            }
        }
    }
}
