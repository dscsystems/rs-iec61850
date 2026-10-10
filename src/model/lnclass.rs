//! The IEC 61850-7-4 logical node classes: which data objects a class has,
//! built from their common data classes, and a check of a node against them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use super::{new_data_object, Cdc, CdcOptions, Diagnostic, LogicalNode, Model};

/// Describes one data object of a logical node class (IEC 61850-7-4): its
/// name, the common data class it is built from, and whether the class
/// requires it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LnObject {
    pub name: String,
    pub cdc: Cdc,
    pub optional: bool,
    /// A data object 7-4 lets a node carry several of (Omulti, Mmulti),
    /// instantiated with a number: `Ind1`, `Ind2`, `AnIn1`... A mandatory one
    /// needs at least one instance.
    pub multi: bool,

    /// The control a tracking object of LTRK tracks.
    tracked: Option<Cdc>,
    /// The object always takes integer analogue values.
    integer_analogue: bool,
}

impl LnObject {
    /// Applies the build options the class always gives this object.
    fn class_options(&self, mut o: CdcOptions) -> CdcOptions {
        if let Some(t) = self.tracked {
            o = o.with_tracked_control(t);
        }
        if self.integer_analogue {
            o = o.with_integer_analogue();
        }
        o
    }
}

fn ln_m(name: &str, cdc: Cdc) -> LnObject {
    LnObject {
        name: name.to_string(),
        cdc,
        optional: false,
        multi: false,
        tracked: None,
        integer_analogue: false,
    }
}

fn ln_opt(name: &str, cdc: Cdc) -> LnObject {
    LnObject {
        optional: true,
        ..ln_m(name, cdc)
    }
}

fn ln_multi(name: &str, cdc: Cdc) -> LnObject {
    LnObject {
        multi: true,
        ..ln_opt(name, cdc)
    }
}

/// An optional control tracking object of LTRK, tracking a control of class
/// `tracked`.
fn ln_trk(name: &str, tracked: Cdc) -> LnObject {
    LnObject {
        tracked: Some(tracked),
        ..ln_opt(name, Cdc::Cts)
    }
}

/// The logical node classes of IEC 61850-7-4 Edition 2 and 2.1 that are
/// templated here.
///
/// The table errs one way only. A data object is marked mandatory only where
/// 7-4 makes it mandatory in every Edition 2 release; one whose presence
/// condition is conditional, or changed between releases, is optional here. A
/// data object this table does not list is not a defect: the class may define
/// it and the table not carry it, or it may be a vendor extension. So
/// [`check_logical_node`] reports what the table is sure of, a mandatory object
/// missing or an object under the wrong class, and nothing else.
fn table() -> &'static BTreeMap<&'static str, Vec<LnObject>> {
    static TABLE: OnceLock<BTreeMap<&'static str, Vec<LnObject>>> = OnceLock::new();
    TABLE.get_or_init(build_table)
}

fn build_table() -> BTreeMap<&'static str, Vec<LnObject>> {
    use Cdc::*;
    // The data every domain logical node has (7-4 "DomainLN").
    let domain = || {
        vec![
            ln_opt("Mod", Enc),
            ln_m("Beh", Ens),
            ln_opt("Health", Ens),
            ln_opt("NamPlt", Lpl),
            ln_multi("InRef", Org),
        ]
    };
    // Local and remote operation, of the nodes that can be operated from
    // either (7-4 "ControlledLN" and the switching and control classes).
    let local = || vec![ln_opt("LocKey", Sps), ln_opt("LocSta", Spc)];
    let equipment = || vec![ln_opt("EEName", Dpl), ln_opt("EEHealth", Ens)];
    // Start and operate of a protection function.
    let protection = || vec![ln_m("Str", Acd), ln_m("Op", Act)];
    let class = |parts: Vec<Vec<LnObject>>| parts.into_iter().flatten().collect::<Vec<_>>();

    let mut t = BTreeMap::new();
    // --- System logical nodes (L) ---
    t.insert(
        "LLN0",
        vec![
            ln_m("Mod", Enc),
            ln_m("Beh", Ens),
            ln_m("Health", Ens),
            ln_m("NamPlt", Lpl),
            ln_opt("Loc", Sps),
            ln_opt("LocKey", Sps),
            ln_opt("LocSta", Spc),
            ln_opt("OpTmh", Ins),
            ln_opt("Diag", Spc),
            ln_opt("LEDRs", Spc),
            ln_opt("MltLev", Spg),
            ln_opt("GrRef", Org),
            ln_multi("InRef", Org),
        ],
    );
    // LPHD is the physical device, not a function, and has no behaviour of
    // its own.
    t.insert(
        "LPHD",
        vec![
            ln_opt("NamPlt", Lpl),
            ln_m("PhyNam", Dpl),
            ln_m("PhyHealth", Ens),
            ln_opt("OutOv", Sps),
            ln_m("Proxy", Sps),
            ln_opt("InOv", Sps),
            ln_opt("NumPwrUp", Ins),
            ln_opt("WrmStr", Ins),
            ln_opt("WacTrg", Ins),
            ln_opt("PwrUp", Sps),
            ln_opt("PwrDn", Sps),
            ln_opt("PwrSupAlm", Sps),
            ln_opt("RsStat", Spc),
            ln_opt("Sim", Spc),
        ],
    );
    // LTRK records the last service of each kind (IEC 61850-7-2 Edition 2); a
    // control tracking object carries the ctlVal of the control it tracks.
    t.insert(
        "LTRK",
        class(vec![
            domain(),
            vec![
                ln_trk("SpcTrk", Spc),
                ln_trk("DpcTrk", Dpc),
                ln_trk("IncTrk", Inc),
                ln_trk("EncTrk", Enc),
                ln_trk("ApcFTrk", Apc),
                LnObject {
                    integer_analogue: true,
                    ..ln_trk("ApcIntTrk", Apc)
                },
                ln_trk("BscTrk", Bsc),
                ln_trk("IscTrk", Isc),
                ln_trk("BacTrk", Bac),
                ln_opt("GenTrk", Cst),
                ln_opt("UrcbTrk", Uts),
                ln_opt("BrcbTrk", Bts),
                ln_opt("LocbTrk", Lts),
                ln_opt("GocbTrk", Gts),
                ln_opt("MsvcbTrk", Mts),
                ln_opt("UsvcbTrk", Nts),
                ln_opt("SgcbTrk", Sts),
            ],
        ]),
    );

    // --- Control (C) and interlocking ---
    t.insert(
        "CSWI",
        class(vec![
            domain(),
            vec![ln_opt("Loc", Sps)],
            local(),
            vec![
                ln_opt("OpOpn", Act),
                ln_opt("SelOpn", Sps),
                ln_opt("OpCls", Act),
                ln_opt("SelCls", Sps),
                ln_opt("Pos", Dpc),
                ln_opt("PosA", Dpc),
                ln_opt("PosB", Dpc),
                ln_opt("PosC", Dpc),
            ],
        ]),
    );
    t.insert(
        "CILO",
        class(vec![domain(), vec![ln_m("EnaOpn", Sps), ln_m("EnaCls", Sps)]]),
    );

    // --- Generic (G) ---
    t.insert(
        "GGIO",
        class(vec![
            domain(),
            equipment(),
            vec![ln_opt("Loc", Sps)],
            local(),
            vec![
                ln_multi("AnIn", Mv),
                ln_multi("AnOut", Apc),
                ln_multi("CntVal", Bcr),
                ln_multi("Ind", Sps),
                ln_multi("IntIn", Ins),
                ln_multi("Alm", Sps),
                ln_multi("SPCSO", Spc),
                ln_multi("DPCSO", Dpc),
                ln_multi("ISCSO", Inc),
            ],
        ]),
    );
    t.insert(
        "GAPC",
        class(vec![
            domain(),
            vec![
                ln_opt("Str", Acd),
                ln_opt("Op", Act),
                ln_multi("SPCSO", Spc),
                ln_multi("DPCSO", Dpc),
                ln_multi("ISCSO", Inc),
            ],
        ]),
    );

    // --- Measurement (M) ---
    t.insert(
        "MMXU",
        class(vec![
            domain(),
            vec![
                ln_opt("TotW", Mv),
                ln_opt("TotVAr", Mv),
                ln_opt("TotVA", Mv),
                ln_opt("TotPF", Mv),
                ln_opt("Hz", Mv),
                ln_opt("PPV", Del),
                ln_opt("PhV", Wye),
                ln_opt("A", Wye),
                ln_opt("W", Wye),
                ln_opt("VAr", Wye),
                ln_opt("VA", Wye),
                ln_opt("PF", Wye),
                ln_opt("Z", Wye),
            ],
        ]),
    );
    t.insert(
        "MMXN",
        class(vec![
            domain(),
            vec![
                ln_opt("Amp", Mv),
                ln_opt("Vol", Mv),
                ln_opt("Watt", Mv),
                ln_opt("VolAmpr", Mv),
                ln_opt("VolAmp", Mv),
                ln_opt("PwrFact", Mv),
                ln_opt("Imp", Cmv),
                ln_opt("Hz", Mv),
            ],
        ]),
    );
    t.insert(
        "MSQI",
        class(vec![domain(), vec![ln_opt("SeqA", Seq), ln_opt("SeqV", Seq)]]),
    );

    // --- Protection (P) ---
    t.insert(
        "PTOC",
        class(vec![
            domain(),
            protection(),
            vec![
                ln_opt("TmACrv", Curve),
                ln_opt("StrVal", Asg),
                ln_opt("TmMult", Asg),
                ln_opt("MinOpTmms", Ing),
                ln_opt("MaxOpTmms", Ing),
                ln_opt("OpDlTmms", Ing),
                ln_opt("TypRsCrv", Eng),
                ln_opt("RsDlTmms", Ing),
                ln_opt("DirMod", Eng),
            ],
        ]),
    );
    for c in ["PTOV", "PTUV"] {
        t.insert(
            c,
            class(vec![
                domain(),
                protection(),
                vec![
                    ln_opt("StrVal", Asg),
                    ln_opt("OpDlTmms", Ing),
                    ln_opt("RsDlTmms", Ing),
                ],
            ]),
        );
    }
    t.insert(
        "PDIS",
        class(vec![
            domain(),
            protection(),
            vec![
                ln_opt("PoRch", Asg),
                ln_opt("PhStr", Asg),
                ln_opt("GndStr", Asg),
                ln_opt("OpDlTmms", Ing),
            ],
        ]),
    );
    t.insert(
        "PDIF",
        class(vec![domain(), vec![ln_opt("Str", Acd), ln_m("Op", Act)]]),
    );
    // PTRC needs a trip or an operate output; 7-4 does not say which.
    t.insert(
        "PTRC",
        class(vec![
            domain(),
            vec![ln_opt("Tr", Act), ln_opt("Op", Act), ln_opt("Str", Acd)],
        ]),
    );

    // --- Protection related (R) ---
    t.insert(
        "RREC",
        class(vec![
            domain(),
            vec![
                ln_m("Op", Act),
                ln_m("AutoRecSt", Ens),
                ln_opt("BlkRec", Spc),
                ln_opt("ChkRec", Spc),
                ln_opt("Auto", Sps),
            ],
        ]),
    );

    // --- Switchgear (X) ---
    t.insert(
        "XCBR",
        class(vec![
            domain(),
            equipment(),
            vec![ln_m("Loc", Sps)],
            local(),
            vec![
                ln_m("OpCnt", Ins),
                ln_opt("CBOpCap", Ens),
                ln_opt("POWCap", Ens),
                ln_opt("MaxOpCap", Ins),
                ln_opt("Dsc", Sps),
                ln_m("Pos", Dpc),
                ln_m("BlkOpn", Spc),
                ln_m("BlkCls", Spc),
                ln_opt("ChaMotEna", Spc),
                ln_opt("SumSwARs", Bcr),
            ],
        ]),
    );
    t.insert(
        "XSWI",
        class(vec![
            domain(),
            equipment(),
            vec![ln_m("Loc", Sps)],
            local(),
            vec![
                ln_m("OpCnt", Ins),
                ln_m("SwTyp", Ens),
                ln_opt("SwOpCap", Ens),
                ln_opt("MaxOpCap", Ins),
                ln_opt("Dsc", Sps),
                ln_m("Pos", Dpc),
                ln_m("BlkOpn", Spc),
                ln_m("BlkCls", Spc),
                ln_opt("ChaMotEna", Spc),
            ],
        ]),
    );
    t
}

fn norm_ln_class(class: &str) -> String {
    class.trim().to_ascii_uppercase()
}

/// Returns the data objects of a logical node class, in the order 7-4 lists
/// them, or an empty list when the class has no template here.
pub fn ln_class_objects(class: &str) -> Vec<LnObject> {
    table()
        .get(norm_ln_class(class).as_str())
        .cloned()
        .unwrap_or_default()
}

/// Reports whether the named logical node class has a template.
pub fn known_ln_class(class: &str) -> bool {
    table().contains_key(norm_ln_class(class).as_str())
}

/// Returns the logical node classes that have templates, sorted.
pub fn known_ln_classes() -> Vec<String> {
    table().keys().map(|k| (*k).to_string()).collect()
}

type ObjectOption = Arc<dyn Fn(CdcOptions) -> CdcOptions + Send + Sync>;

/// Adjusts how a logical node is built.
#[derive(Clone, Default)]
pub struct LnOptions {
    asked: Vec<String>,
    obj_opts: Vec<(String, ObjectOption)>,
}

impl std::fmt::Debug for LnOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LnOptions")
            .field("asked", &self.asked)
            .field(
                "obj_opts",
                &self.obj_opts.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl LnOptions {
    pub fn new() -> LnOptions {
        LnOptions::default()
    }

    /// Includes optional data objects of the class by name.
    ///
    /// A multi-instance object is asked for by instance name, `Ind1` or
    /// `AnIn3`; asking for its bare name builds the first instance. Names the
    /// class does not define are ignored.
    #[must_use]
    pub fn with_objects<S: AsRef<str>>(mut self, names: impl IntoIterator<Item = S>) -> LnOptions {
        self.asked
            .extend(names.into_iter().map(|n| n.as_ref().to_string()));
        self
    }

    /// Builds the named data object with the options `f` adds, after any
    /// options the class gives it: a control model for `Pos`, say.
    ///
    /// `name` is an instance name (`SPCSO1`) or, for every instance of a
    /// multi-instance object, its bare name (`SPCSO`).
    #[must_use]
    pub fn with_object_options(
        mut self,
        name: impl Into<String>,
        f: impl Fn(CdcOptions) -> CdcOptions + Send + Sync + 'static,
    ) -> LnOptions {
        self.obj_opts.push((name.into(), Arc::new(f)));
        self
    }

    fn apply(&self, name: &str, mut o: CdcOptions) -> CdcOptions {
        for (n, f) in &self.obj_opts {
            if n == name {
                o = f(o);
            }
        }
        o
    }

    /// The names `obj` is built under: none, its own name, or for a
    /// multi-instance object the instances asked for.
    fn instances(&self, obj: &LnObject) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for n in &self.asked {
            let n = if *n == obj.name && obj.multi {
                format!("{}1", obj.name)
            } else if *n == obj.name || (obj.multi && instance_of(n, &obj.name)) {
                n.clone()
            } else {
                continue;
            };
            if !out.contains(&n) {
                out.push(n);
            }
        }
        if out.is_empty() && !obj.optional {
            if obj.multi {
                return vec![format!("{}1", obj.name)];
            }
            return vec![obj.name.clone()];
        }
        out
    }
}

/// Builds a logical node of a 7-4 class: every data object the class makes
/// mandatory, and the optional ones asked for with
/// [`LnOptions::with_objects`], each built by [`new_data_object`] from its
/// common data class. A mandatory multi-instance object gets its first
/// instance.
///
/// ```
/// use iec61850::model::{new_logical_node, CtlModel, LnOptions};
///
/// let xcbr = new_logical_node(
///     "Q0",
///     "XCBR",
///     "1",
///     &LnOptions::new()
///         .with_objects(["SumSwARs"])
///         .with_object_options("Pos", |o| o.with_control_model(CtlModel::SboEnhanced)),
/// );
/// assert_eq!(xcbr.name, "Q0XCBR1");
/// assert!(xcbr.object("Pos").unwrap().attribute("SBOw").is_some());
/// ```
///
/// The node is named prefix+class+inst, and `LLN0` is always `LLN0`. A class
/// with no template here yields the named node with no data objects;
/// [`known_ln_class`] says which classes have one.
pub fn new_logical_node(prefix: &str, class: &str, inst: &str, opts: &LnOptions) -> LogicalNode {
    let class = norm_ln_class(class);
    let mut ln = LogicalNode {
        name: if class == "LLN0" {
            "LLN0".to_string()
        } else {
            format!("{prefix}{class}{inst}")
        },
        class: class.clone(),
        ..Default::default()
    };
    let Some(objs) = table().get(class.as_str()) else {
        return ln;
    };
    for obj in objs {
        for name in opts.instances(obj) {
            // The class's options, then those given for every instance, then
            // those given for this one, so the most specific wins.
            let mut o = obj.class_options(CdcOptions::new());
            if name != obj.name {
                o = opts.apply(&obj.name, o);
            }
            o = opts.apply(&name, o);
            ln.objects.push(new_data_object(&name, obj.cdc, &o));
        }
    }
    ln
}

/// Reports whether `name` is an instance of the multi-instance data object
/// `base`: `base` followed by a number from 1.
fn instance_of(name: &str, base: &str) -> bool {
    match name.strip_prefix(base) {
        Some(num) => {
            !num.is_empty() && !num.starts_with('0') && num.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Compares a logical node with the 7-4 template of its class, and reports
/// each mandatory data object that is missing and each data object built from
/// a common data class other than the one 7-4 gives it.
///
/// Edition 1 used `INS`, `INC` and `ING` where Edition 2 uses the enumerated
/// `ENS`, `ENC` and `ENG`; either is accepted. A node whose class has no
/// template, or that has no class (a model retrieved from a server), is not
/// checked.
pub fn check_logical_node(ln: &LogicalNode) -> Vec<Diagnostic> {
    check(ln, &ln.name)
}

impl Model {
    /// Runs [`check_logical_node`] on every logical node of the model.
    ///
    /// The diagnostics are returned, not added to `diagnostics`: conformance
    /// to 7-4 is a question about the device, not a problem interpreting the
    /// file.
    pub fn check_ln_classes(&self) -> Vec<Diagnostic> {
        let mut out = Vec::new();
        for ld in &self.devices {
            for ln in &ld.nodes {
                out.extend(check(ln, &format!("{}/{}", ld.name, ln.name)));
            }
        }
        out
    }
}

fn check(ln: &LogicalNode, path: &str) -> Vec<Diagnostic> {
    let Some(objs) = table().get(norm_ln_class(&ln.class).as_str()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut present: BTreeSet<&str> = BTreeSet::new();
    for o in &ln.objects {
        let Some(obj) = objs
            .iter()
            .find(|e| e.name == o.name || (e.multi && instance_of(&o.name, &e.name)))
        else {
            continue;
        };
        present.insert(&obj.name);
        if !o.cdc.is_empty() && !cdc_compatible(obj.cdc, &o.cdc) {
            out.push(Diagnostic::new(
                format!("{path}.{}", o.name),
                format!(
                    "data object of class {}, IEC 61850-7-4 gives {}.{} the class {}",
                    o.cdc, ln.class, obj.name, obj.cdc
                ),
            ));
        }
    }
    for obj in objs {
        if !obj.optional && !present.contains(obj.name.as_str()) {
            out.push(Diagnostic::new(
                path,
                format!(
                    "mandatory data object {} ({}) of {} is missing",
                    obj.name, obj.cdc, ln.class
                ),
            ));
        }
    }
    out
}

/// Reports whether a data object of class `got` may stand for one of class
/// `want`: the same class, or the Edition 1 integer class of an Edition 2
/// enumerated one.
fn cdc_compatible(want: Cdc, got: &str) -> bool {
    let g = got.trim().to_ascii_uppercase();
    if g == want.as_str() {
        return true;
    }
    match want {
        Cdc::Ens => g == "INS",
        Cdc::Enc => g == "INC",
        Cdc::Eng => g == "ING",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::Type;
    use crate::model::{CtlModel, DataObject, Fc, LogicalDevice};

    fn object_names(ln: &LogicalNode) -> String {
        ln.objects
            .iter()
            .map(|o| o.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn named(name: &str, cdc: &str) -> DataObject {
        DataObject {
            name: name.into(),
            cdc: cdc.into(),
            ..Default::default()
        }
    }

    /// Every class table names each data object once, and a node built from
    /// the class alone passes its own check.
    #[test]
    fn the_class_tables_are_well_formed() {
        for class in known_ln_classes() {
            let mut seen = BTreeSet::new();
            for o in ln_class_objects(&class) {
                assert!(seen.insert(o.name.clone()), "{class}.{} listed twice", o.name);
            }
            let d = check_logical_node(&new_logical_node("", &class, "1", &LnOptions::new()));
            assert!(d.is_empty(), "{class} built from its template fails the check: {d:?}");
        }
    }

    #[test]
    fn a_node_carries_its_mandatory_objects() {
        let lln0 = new_logical_node("X", "LLN0", "7", &LnOptions::new());
        assert_eq!((lln0.name.as_str(), lln0.class.as_str()), ("LLN0", "LLN0"));
        assert_eq!(object_names(&lln0), "Mod,Beh,Health,NamPlt");
        let xcbr = new_logical_node("Q0", "xcbr", "1", &LnOptions::new());
        assert_eq!(xcbr.name, "Q0XCBR1");
        assert_eq!(object_names(&xcbr), "Beh,Loc,OpCnt,Pos,BlkOpn,BlkCls");
        let pos = xcbr.object("Pos").unwrap();
        assert_eq!(pos.cdc, "DPC");
        assert!(pos.attribute("stVal").is_some());
        // A class with no template is the empty named node.
        let ln = new_logical_node("", "ZZZZ", "1", &LnOptions::new());
        assert_eq!(ln.name, "ZZZZ1");
        assert!(ln.objects.is_empty() && !known_ln_class("ZZZZ"));
    }

    #[test]
    fn optional_and_multi_instance_objects_are_built_when_asked_for() {
        let ggio = new_logical_node(
            "",
            "GGIO",
            "1",
            &LnOptions::new()
                .with_objects(["SPCSO1", "SPCSO3", "Ind", "AnIn2", "NoSuchDO", "Ind0"])
                .with_object_options("SPCSO", |o| o.with_control_model(CtlModel::DirectNormal))
                .with_object_options("SPCSO3", |o| o.with_control_model(CtlModel::SboEnhanced)),
        );
        assert_eq!(object_names(&ggio), "Beh,AnIn2,Ind1,SPCSO1,SPCSO3");
        // Options for every instance apply, and an instance's own win.
        let s1 = ggio.object("SPCSO1").unwrap();
        assert!(s1.attribute("Oper").is_some() && s1.attribute("SBOw").is_none());
        assert!(ggio.object("SPCSO3").unwrap().attribute("SBOw").is_some());
        assert_eq!(ggio.object("AnIn2").unwrap().cdc, "MV");
    }

    /// The control tracking objects of LTRK carry the ctlVal of the control
    /// they track.
    #[test]
    fn tracking_objects_carry_the_tracked_control_value() {
        let ltrk = new_logical_node(
            "",
            "LTRK",
            "1",
            &LnOptions::new().with_objects(["SpcTrk", "BscTrk", "ApcIntTrk", "GocbTrk"]),
        );
        for (name, kind) in [
            ("SpcTrk", Type::Boolean),
            ("BscTrk", Type::BitString),
            ("ApcIntTrk", Type::Structure),
        ] {
            let c = ltrk.object(name).unwrap().attribute("ctlVal").unwrap();
            assert_eq!((c.kind, c.fc), (Some(kind), Fc::Sr), "{name}");
        }
        let c = ltrk.object("ApcIntTrk").unwrap().attribute("ctlVal").unwrap();
        assert_eq!(c.children.len(), 1);
        assert_eq!(c.children[0].name, "i");
        assert_eq!(ltrk.object("GocbTrk").unwrap().cdc, "GTS");
    }

    #[test]
    fn the_check_reports_missing_and_misclassed_objects() {
        let mut xcbr = new_logical_node("Q0", "XCBR", "1", &LnOptions::new());
        xcbr.objects.retain(|o| o.name != "Pos");
        xcbr.objects.push(named("VendorX", "SPS"));
        xcbr.object_mut("BlkOpn").unwrap().cdc = "SPS".into();
        let d = check_logical_node(&xcbr);
        assert_eq!(d.len(), 2, "{d:?}");
        assert_eq!(d[0].path, "Q0XCBR1.BlkOpn");
        assert!(d[0].message.contains("SPC"));
        assert_eq!(d[1].path, "Q0XCBR1");
        assert!(d[1].message.contains("Pos"));

        // Edition 1 integer classes stand for the Edition 2 enumerated ones.
        let ed1 = LogicalNode {
            name: "LLN0".into(),
            class: "LLN0".into(),
            objects: vec![
                named("Mod", "INC"),
                named("Beh", "INS"),
                named("Health", "INS"),
                named("NamPlt", "LPL"),
            ],
            ..Default::default()
        };
        assert!(check_logical_node(&ed1).is_empty());
        // ...but not the other way round, nor for a class with no integer form.
        let wrong = LogicalNode {
            name: "LLN0".into(),
            class: "LLN0".into(),
            objects: vec![
                named("Mod", "ENC"),
                named("Beh", "ENS"),
                named("Health", "SPS"),
                named("NamPlt", "DPL"),
            ],
            ..Default::default()
        };
        assert_eq!(check_logical_node(&wrong).len(), 2);

        // Multi-instance objects are matched by instance name.
        let ggio = LogicalNode {
            name: "GGIO1".into(),
            class: "GGIO".into(),
            objects: vec![
                named("Beh", "ENS"),
                named("Ind12", "SPS"),
                named("AnIn1", "WYE"),
                named("Ind0", "WYE"),
                named("Indx", "WYE"),
            ],
            ..Default::default()
        };
        let d = check_logical_node(&ggio);
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].path, "GGIO1.AnIn1");

        // No class: nothing to check against.
        let bare = LogicalNode {
            name: "XCBR1".into(),
            ..Default::default()
        };
        assert!(check_logical_node(&bare).is_empty());
    }

    #[test]
    fn the_model_check_covers_every_node_and_leaves_the_model_alone() {
        let m = Model {
            devices: vec![LogicalDevice {
                name: "IEDLD0".into(),
                nodes: vec![
                    new_logical_node("", "LLN0", "", &LnOptions::new()),
                    LogicalNode {
                        name: "MMXU1".into(),
                        class: "MMXU".into(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let d = m.check_ln_classes();
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].path, "IEDLD0/MMXU1");
        assert!(d[0].message.contains("Beh"));
        assert!(m.diagnostics.is_empty());
    }
}
