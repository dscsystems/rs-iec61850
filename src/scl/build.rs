//! Instantiates the runtime object model from a parsed SCL document.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::mms::{Type, Value};
use crate::model::{self, Diagnostic};
use crate::time_util;

use super::types::*;
use super::{parse_file, Error, Result};

/// Receives each diagnostic as it is raised.
pub type WarnFn = Arc<dyn Fn(&Diagnostic) + Send + Sync>;

/// Adjusts model instantiation.
///
/// The default is permissive: unrecognised constructs are recorded as
/// diagnostics on the model and the model is still built.
#[derive(Clone, Default)]
pub struct BuildOptions {
    /// The IED to instantiate; the default is the first IED in the document.
    pub ied: String,
    /// The access point of the chosen IED; the default is the first access
    /// point that contains a `Server`.
    pub access_point: String,
    /// Turns diagnostics into a load error. Use it to fail a configuration
    /// check on a document that is not fully understood, for instance in a
    /// conformance test harness.
    pub strict: bool,
    /// Called for each diagnostic as it is raised, for streaming progress on a
    /// large document.
    pub on_warn: Option<WarnFn>,
}

impl std::fmt::Debug for BuildOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuildOptions")
            .field("ied", &self.ied)
            .field("access_point", &self.access_point)
            .field("strict", &self.strict)
            .field("on_warn", &self.on_warn.is_some())
            .finish()
    }
}

impl BuildOptions {
    pub fn new() -> BuildOptions {
        BuildOptions::default()
    }

    /// Selects the IED to instantiate.
    #[must_use]
    pub fn for_ied(mut self, name: impl Into<String>) -> BuildOptions {
        self.ied = name.into();
        self
    }

    /// Selects the access point of the chosen IED.
    #[must_use]
    pub fn with_access_point(mut self, name: impl Into<String>) -> BuildOptions {
        self.access_point = name.into();
        self
    }

    /// Makes a build fail when it raised any diagnostic, instead of returning
    /// a usable model.
    #[must_use]
    pub fn strict(mut self, on: bool) -> BuildOptions {
        self.strict = on;
        self
    }

    /// Installs a callback invoked for each diagnostic as it is raised.
    #[must_use]
    pub fn on_warn(mut self, f: impl Fn(&Diagnostic) + Send + Sync + 'static) -> BuildOptions {
        self.on_warn = Some(Arc::new(f));
        self
    }
}

/// Collects the diagnostics of one build.
struct Diag {
    on_warn: Option<WarnFn>,
    all: Vec<Diagnostic>,
}

impl Diag {
    fn add(&mut self, path: impl Into<String>, message: impl Into<String>) {
        let d = Diagnostic::new(path, message);
        if let Some(f) = &self.on_warn {
            f(&d);
        }
        self.all.push(d);
    }
}

/// Parses the SCL file at `path` and instantiates the runtime model of one
/// IED.
///
/// See [`build_model`] for the option semantics.
pub fn load_model(path: impl AsRef<Path>, opts: &BuildOptions) -> Result<model::Model> {
    let scl = parse_file(path)?;
    build_model(&scl, opts)
}

/// Instantiates the runtime model of one IED from a parsed SCL document.
///
/// Logical devices and nodes are expanded from the data type templates,
/// DOI/SDI/DAI initial values are applied, and datasets and control blocks
/// (including GSE and SMV addresses from the Communication section) are
/// resolved.
///
/// Initial values are applied per setting group (`Val@sGroup`) and per array
/// element (`DAI@sAddr`, `DOI`/`SDI@ix`), and the group `SettingControl`
/// declares active is the one the objects carry. What is not understood is
/// recorded as a diagnostic on the model rather than failing the build, so a
/// single unrecognised construct cannot make a whole IED unreadable; set
/// [`BuildOptions::strict`] for the opposite behaviour.
///
/// Remaining limitations, kept deliberately: `Octet64` and `EntryID` values
/// must be written as hexadecimal, a `Timestamp` must be ISO 8601, and report
/// instances beyond those the configuration declares are not created.
pub fn build_model(scl: &Scl, opts: &BuildOptions) -> Result<model::Model> {
    let mut d = Diag {
        on_warn: opts.on_warn.clone(),
        all: Vec::new(),
    };
    for m in scl.edition().validate("SCL") {
        d.add("SCL", m);
    }
    for (name, paths) in scl.dropped() {
        for p in paths {
            d.add(
                p,
                format!(
                    "element <{name}> is present in the document and is not decoded, \
                     along with anything nested inside it"
                ),
            );
        }
    }

    let ied = find_ied(scl, &opts.ied)?;
    let ap = find_ap(ied, &opts.access_point)?;
    if let Some(svc) = &ap.services {
        if !svc.name_length.is_empty() {
            d.add(
                format!("SCL/IED[{}]/AccessPoint[{}]/Services", ied.name, ap.name),
                format!(
                    "nameLength={}: the name-length limit is not enforced on object \
                     references or item IDs",
                    svc.name_length
                ),
            );
        }
        if let Some(s) = svc.sup_subscription {
            if s.max_go > 0 || s.max_sv > 0 {
                d.add(
                    format!("SCL/IED[{}]/Services/SupSubscription", ied.name),
                    "subscription supervision is declared but not implemented",
                );
            }
        }
    }
    let server = ap
        .server
        .as_ref()
        .expect("find_ap only returns access points with a Server");

    let mut b = Builder::new(scl, d);
    b.led = ied.name.clone();
    let mut m = model::Model {
        name: ied.name.clone(),
        ..Default::default()
    };
    for lde in &server.l_devices {
        b.led_inst = lde.inst.clone();
        let mut ld = model::LogicalDevice {
            name: format!("{}{}", ied.name, lde.inst),
            inst: lde.inst.clone(),
            nodes: Vec::new(),
        };
        for lne in lde.all_lns() {
            // Diagnostics name the logical node as well as the object, so a
            // shared data type template does not report the same attribute
            // three times without saying where.
            b.cur_ln = lne.instance_name();
            let ln = b
                .build_ln(&ied.name, &ap.name, &lde.inst, lne)
                .map_err(|e| {
                    Error::model(format!(
                        "{}{}/{}: {e}",
                        ied.name,
                        lde.inst,
                        lne.instance_name()
                    ))
                })?;
            b.cur_ln.clear();
            ld.nodes.push(ln);
        }
        // The active setting group is declared once per logical device, on
        // LN0, and its values are spread over every node. Applying it is
        // therefore a whole-device step, after every node is built.
        if let Some(act) = ld
            .nodes
            .iter()
            .find_map(|ln| ln.setting_control.map(|sc| sc.act_sg))
        {
            b.apply_active_group(&mut ld, usize::from(act));
        }
        m.devices.push(ld);
    }

    // Services/ConfReportControl@maxBuf is the device's report-buffer
    // capacity: apply it to the buffered blocks as their queue depth, so the
    // server buffers what the configuration says rather than its own default.
    // The access point's declaration wins over the IED's.
    let max_buf = report_max_buf(ied, ap);
    if max_buf > 0 {
        for ld in &mut m.devices {
            for ln in &mut ld.nodes {
                for rc in &mut ln.report_controls {
                    if rc.buffered && rc.max_queue_size == 0 {
                        rc.max_queue_size = max_buf;
                    }
                }
            }
        }
    }
    m.setting_groups = b.setting_groups();
    m.diagnostics = std::mem::take(&mut b.diag.all);
    if opts.strict && !m.diagnostics.is_empty() {
        let msg = m
            .diagnostics
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        return Err(Error::Strict {
            diagnostics: m.diagnostics,
            msg,
        });
    }
    Ok(m)
}

/// Returns the configured report-buffer capacity, zero if the document
/// declares none.
fn report_max_buf(ied: &Ied, ap: &AccessPoint) -> usize {
    for svc in [ap.services.as_ref(), ied.services.as_ref()].into_iter().flatten() {
        if let Some(c) = &svc.conf_report_control {
            if c.max_buf > 0 {
                return c.max_buf as usize;
            }
        }
    }
    0
}

fn find_ied<'a>(scl: &'a Scl, name: &str) -> Result<&'a Ied> {
    if scl.ieds.is_empty() {
        return Err(Error::model("document contains no IED"));
    }
    scl.ied(name)
        .ok_or_else(|| Error::model(format!("IED {name:?} not found")))
}

fn find_ap<'a>(ied: &'a Ied, name: &str) -> Result<&'a AccessPoint> {
    for ap in &ied.access_points {
        if !name.is_empty() && ap.name != name {
            continue;
        }
        if ap.server.is_some() {
            return Ok(ap);
        }
        if !name.is_empty() {
            return Err(Error::model(format!(
                "access point {name:?} of IED {:?} has no Server",
                ied.name
            )));
        }
    }
    if !name.is_empty() {
        return Err(Error::model(format!(
            "access point {name:?} not found in IED {:?}",
            ied.name
        )));
    }
    Err(Error::model(format!(
        "IED {:?} has no access point with a Server",
        ied.name
    )))
}

/// Bounds an array the document asks for, so a corrupt or hostile count
/// cannot make the loader allocate without limit. It is well above anything a
/// real device declares.
const MAX_ARRAY_COUNT: usize = 1 << 16;

/// How many instances of one indexed report control block the server names.
/// IEC 61850-6 defines the two-digit suffix `01`..`99`; a document asking for
/// more would need names the standard does not define, so the count is
/// capped.
const MAX_RCB_INSTANCES: usize = 99;

/// Resolves data type templates and enum bindings, and collects what the
/// build finds along the way.
struct Builder<'a> {
    scl: &'a Scl,
    diag: Diag,
    ln_types: HashMap<&'a str, &'a LNodeType>,
    ln_types_by_class: HashMap<(&'a str, &'a str), &'a LNodeType>,
    do_types: HashMap<&'a str, &'a DoType>,
    da_types: HashMap<&'a str, &'a DaType>,
    enums: HashMap<&'a str, &'a EnumType>,
    /// The per-setting-group initial values of FC SG and SE attributes, keyed
    /// by logical device and then by group number. The device is part of the
    /// key because an IED usually has several and they can have differently
    /// named settings: keying on the group alone would apply one device's
    /// value to another's same-named attribute.
    group_values: BTreeMap<String, BTreeMap<usize, Vec<(String, Value)>>>,
    /// The logical node and the dotted path of the data object being built,
    /// for diagnostics.
    cur_ln: String,
    cur_do: String,
    /// The IED name and logical-device instance being built, so
    /// setting-group values are recorded against a full reference.
    led: String,
    led_inst: String,
}

impl<'a> Builder<'a> {
    fn new(scl: &'a Scl, diag: Diag) -> Builder<'a> {
        let mut b = Builder {
            scl,
            diag,
            ln_types: HashMap::new(),
            ln_types_by_class: HashMap::new(),
            do_types: HashMap::new(),
            da_types: HashMap::new(),
            enums: HashMap::new(),
            group_values: BTreeMap::new(),
            cur_ln: String::new(),
            cur_do: String::new(),
            led: String::new(),
            led_inst: String::new(),
        };
        if let Some(t) = &scl.data_type_templates {
            // LNodeType identity is the pair (id, lnClass), so index both
            // ways: by id alone for the common case, and by id and class so a
            // document reusing an id across node classes still resolves.
            for x in &t.ln_node_types {
                b.ln_types.entry(x.id.as_str()).or_insert(x);
                b.ln_types_by_class
                    .insert((x.id.as_str(), x.ln_class.as_str()), x);
            }
            for x in &t.do_types {
                b.do_types.insert(x.id.as_str(), x);
            }
            for x in &t.da_types {
                b.da_types.insert(x.id.as_str(), x);
            }
            for x in &t.enum_types {
                b.enums.insert(x.id.as_str(), x);
            }
        }
        b
    }

    /// The name of the logical device being built, which is the MMS domain
    /// name: IED name plus the device instance.
    fn led_ref(&self) -> String {
        format!("{}{}", self.led, self.led_inst)
    }

    /// Builds a diagnostic path from the attribute name being built.
    fn path(&self, name: &str) -> String {
        join_path(&join_path(&self.cur_ln, &self.cur_do), name)
    }

    /// Resolves a logical node type, preferring an exact (id, lnClass) match
    /// and falling back to the id alone.
    fn ln_type(&self, id: &str, ln_class: &str) -> Option<&'a LNodeType> {
        self.ln_types_by_class
            .get(&(id, ln_class))
            .or_else(|| self.ln_types.get(id))
            .copied()
    }

    fn build_ln(
        &mut self,
        ied_name: &str,
        ap_name: &str,
        ld_inst: &str,
        lne: &Ln,
    ) -> Result<model::LogicalNode> {
        let lnt = self
            .ln_type(&lne.ln_type, &lne.ln_class)
            .ok_or_else(|| Error::model(format!("LNodeType {:?} not found", lne.ln_type)))?;

        let mut ln = model::LogicalNode {
            name: lne.instance_name(),
            class: lne.ln_class.clone(),
            ..Default::default()
        };
        for doe in &lnt.dos {
            let object = self
                .build_do(&doe.name, &doe.kind, 0)
                .map_err(|e| Error::model(format!("DO {}: {e}", doe.name)))?;
            ln.objects.push(object);
        }

        // Apply instance values.
        let ln_name = lne.instance_name();
        for doi in &lne.dois {
            let mut name = doi.name.clone();
            if ln.object(&name).is_none() {
                if let Some((base, _)) = split_array_name(&doi.name) {
                    name = base.to_string();
                }
            }
            if ln.object(&name).is_none() {
                return Err(Error::model(format!(
                    "DOI {:?} has no matching DO in type {:?}",
                    doi.name, lne.ln_type
                )));
            }
            let path = join_path(&ln_name, &doi.name);
            // A DOI with an ix addresses one element of an array-valued DO,
            // which the model holds as "Name(n)".
            let mut element: Option<String> = None;
            let ix = doi.ix.trim();
            if !ix.is_empty() {
                match array_index(ix) {
                    Some(n) => {
                        let el = format!("{}({n})", doi.name);
                        if ln.object(&name).is_some_and(|o| o.child(&el).is_some()) {
                            element = Some(el);
                        } else {
                            self.diag.add(
                                path.clone(),
                                format!(
                                    "DOI ix={ix} addresses an instance of {:?} that the type \
                                     does not declare as an array",
                                    doi.name
                                ),
                            );
                        }
                    }
                    None => self.diag.add(
                        path.clone(),
                        format!(
                            "DOI ix={ix:?} is not an array index; the value is applied to the \
                             object as a whole"
                        ),
                    ),
                }
            }
            let object = ln.object_mut(&name).expect("checked above");
            let object = match &element {
                Some(el) => object.child_mut(el).expect("checked above"),
                None => object,
            };
            self.apply_doi(object, &doi.dais, &doi.sdis, &path)
                .map_err(|e| Error::model(format!("DOI {}: {e}", doi.name)))?;
        }

        for dse in &lne.data_sets {
            ln.data_sets.push(build_data_set(ied_name, ld_inst, dse)?);
        }
        for r in &lne.report_controls {
            let rc = self.build_report_control(r);
            ln.report_controls.push(rc);
        }
        for g in &lne.gse_controls {
            let gc = self.build_gse_control(ied_name, ap_name, ld_inst, g);
            ln.gse_controls.push(gc);
        }
        for s in &lne.sampled_value_controls {
            let sc = self.build_sv_control(ied_name, ap_name, ld_inst, s);
            ln.sv_controls.push(sc);
        }
        for l in &lne.log_controls {
            ln.log_controls.push(build_log_control(l));
        }
        ln.logs = lne.logs.clone();
        if let Some(sg) = lne.setting_control {
            ln.setting_control = Some(model::SettingControl {
                num_of_sgs: sg.num_of_sgs,
                act_sg: sg.act_sg,
                resv_tms: sg.resv_tms,
            });
        }
        Ok(ln)
    }

    /// Expands a `DOType`, and its `SDO`s recursively, into a data object.
    fn build_do(&mut self, name: &str, type_id: &str, depth: usize) -> Result<model::DataObject> {
        if depth > 16 {
            return Err(Error::model(format!("SDO nesting too deep at {type_id:?}")));
        }
        let dot = *self
            .do_types
            .get(type_id)
            .ok_or_else(|| Error::model(format!("DOType {type_id:?} not found")))?;
        let prev_do = std::mem::take(&mut self.cur_do);
        self.cur_do = join_path(&prev_do, name);
        let result = self.build_do_body(name, dot, depth);
        self.cur_do = prev_do;
        result
    }

    fn build_do_body(
        &mut self,
        name: &str,
        dot: &'a DoType,
        depth: usize,
    ) -> Result<model::DataObject> {
        let mut object = model::DataObject {
            name: name.to_string(),
            cdc: dot.cdc.clone(),
            ..Default::default()
        };
        if !dot.cdc.is_empty() && !model::known_cdc(&dot.cdc) {
            let p = self.path(name);
            self.diag.add(
                p,
                format!(
                    "common data class {:?} is not one this library has attribute templates \
                     for; the SCL-provided attributes are used as they are",
                    dot.cdc
                ),
            );
        }
        for dae in &dot.das {
            let trg = trg_ops_of_flags(model::TrgOps::default(), dae.dchg, dae.qchg, dae.dupd);
            let da = self
                .build_da(&dae.name, &dae.fc, &dae.btype, &dae.kind, &dae.count, trg, &dae.vals, 0)
                .map_err(|e| Error::model(format!("DA {}: {e}", dae.name)))?;
            object.attributes.push(da);
        }
        for sdo in &dot.sdos {
            let sub = self
                .build_do(&sdo.name, &sdo.kind, depth + 1)
                .map_err(|e| Error::model(format!("SDO {}: {e}", sdo.name)))?;
            // An SDO with a count is an array: the sub-object is repeated,
            // which is how multi-instance data objects such as phsA are
            // expressed, and how a DO with a count reaches the model at all.
            match array_count(&sdo.count) {
                ArrayCount::TooBig => {
                    let p = self.path(&sdo.name);
                    self.diag.add(
                        p,
                        format!(
                            "count={:?} is beyond the {MAX_ARRAY_COUNT}-element limit this \
                             library will allocate; no instances were created",
                            sdo.count
                        ),
                    );
                }
                ArrayCount::Array(n) => {
                    for ix in 1..=n {
                        let mut el = sub.clone();
                        el.name = format!("{}({ix})", sdo.name);
                        object.objects.push(el);
                    }
                }
                ArrayCount::Scalar => object.objects.push(sub),
            }
        }
        Ok(object)
    }

    /// Expands one `DA` or `BDA`.
    ///
    /// `fc_raw` is the functional-constraint mnemonic as written, which is
    /// kept alongside the parsed constraint so an unknown one is still usable.
    /// Arrays of basic types get an array value with per-element defaults;
    /// arrays of constructed types keep the count with no value.
    // A DA and a BDA are expanded by the same code, and between them they
    // carry this many independent SCL attributes; bundling them into a struct
    // would only move the list.
    #[allow(clippy::too_many_arguments)]
    fn build_da(
        &mut self,
        name: &str,
        fc_raw: &str,
        btype: &str,
        type_id: &str,
        count: &str,
        trg: model::TrgOps,
        vals: &[Val],
        depth: usize,
    ) -> Result<model::DataAttribute> {
        if depth > 16 {
            return Err(Error::model(format!(
                "attribute nesting too deep at {name:?}"
            )));
        }
        let fc = model::parse_fc_lenient(fc_raw);
        if fc == model::Fc::Unknown {
            let p = self.path(name);
            self.diag.add(
                p,
                format!(
                    "functional constraint {fc_raw:?} on DA {name} is not one this library \
                     knows; it is carried verbatim and the attribute is readable under it"
                ),
            );
        }
        let mut da = model::DataAttribute {
            name: name.to_string(),
            fc,
            fc_name: fc_raw.to_string(),
            btype: btype.to_string(),
            // Only meaningful for Enum, where it names the EnumType whose
            // literals the value is drawn from.
            enum_type: if btype == "Enum" {
                type_id.to_string()
            } else {
                String::new()
            },
            trg_ops: trg,
            ..Default::default()
        };
        let n = match array_count(count) {
            ArrayCount::TooBig => {
                let p = self.path(name);
                self.diag.add(
                    p,
                    format!(
                        "count={count:?} is beyond the {MAX_ARRAY_COUNT}-element limit this \
                         library will allocate; the attribute is present but has no elements"
                    ),
                );
                0
            }
            ArrayCount::Array(n) => n,
            ArrayCount::Scalar => 0,
        };

        if btype == "Struct" {
            da.kind = Some(Type::Structure);
            let Some(dat) = self.da_types.get(type_id).copied() else {
                // Without the type template the structure's members are
                // unknown, but the object still exists; record it and leave
                // it valueless rather than failing the whole load.
                let p = self.path(name);
                self.diag.add(
                    p,
                    format!(
                        "DAType {type_id:?} of structured DA {name} not found; the structure \
                         is present but has no members"
                    ),
                );
                return Ok(da);
            };
            for bda in &dat.bdas {
                // A DA's trigger options cover all its components: a change to
                // mag.f is a change of mag (IEC 61850-7-2).
                let child = self
                    .build_da(
                        &bda.name,
                        fc_raw,
                        &bda.btype,
                        &bda.kind,
                        &bda.count,
                        trg_ops_of_flags(trg, bda.dchg, bda.qchg, bda.dupd),
                        &bda.vals,
                        depth + 1,
                    )
                    .map_err(|e| Error::model(format!("BDA {}: {e}", bda.name)))?;
                da.children.push(child);
            }
            if n > 0 {
                da.kind = Some(Type::Array);
                da.count = n;
            }
            return Ok(da);
        }

        if btype == "PhyComAddr" {
            // IEC 61850-8-1 maps PhyComAddr to a structure, the one a GoCB's
            // DstAddress and the tracking classes' dstAddress are served as.
            da.kind = Some(Type::Structure);
            da.children = phy_com_addr(fc, fc_raw, trg);
            if n > 0 {
                da.kind = Some(Type::Array);
                da.count = n;
            }
            return Ok(da);
        }

        let Some(kind) = kind_of(btype) else {
            let p = self.path(name);
            self.diag.add(
                p,
                format!(
                    "basic type {btype:?} of DA {name} is not in the IEC 61850-8-1 type \
                     enumeration; the attribute has no value until one is written"
                ),
            );
            return Ok(da);
        };
        if n > 0 {
            da.kind = Some(Type::Array);
            da.count = n;
            da.value = Some(Value::Array(
                (0..n).map(|_| default_value(kind, btype)).collect(),
            ));
            return Ok(da);
        }
        da.kind = Some(kind);
        da.value = Some(default_value(kind, btype));
        if let Some(v) = vals.first() {
            self.set_value(&mut da, &v.value)?;
        }
        Ok(da)
    }

    /// Parses an SCL `Val` string into the attribute's value.
    ///
    /// Enum literals are resolved through the attribute's `enum_type`, which
    /// is the `type` attribute of the declaring `DA` or `BDA`.
    fn set_value(&self, da: &mut model::DataAttribute, raw: &str) -> Result<()> {
        let s = raw.trim();
        let fail = |what: String| {
            Error::model(format!(
                "value {s:?} for {} ({}): {what}",
                da.name, da.btype
            ))
        };

        if da.btype == "Enum" {
            if let Ok(v) = s.parse::<i64>() {
                da.value = Some(Value::int64(v));
                return Ok(());
            }
            if let Some(ord) = self
                .enums
                .get(da.enum_type.as_str())
                .and_then(|et| et.ord_of(s))
            {
                da.value = Some(Value::int64(ord));
                return Ok(());
            }
            return Err(fail("unknown enum literal".into()));
        }

        let v = match da.kind {
            Some(Type::Boolean) => match s {
                "true" | "1" | "TRUE" | "True" | "t" | "T" => Value::boolean(true),
                "false" | "0" | "FALSE" | "False" | "f" | "F" => Value::boolean(false),
                _ => return Err(fail("expected a boolean".into())),
            },
            Some(Type::Integer) => Value::int64(s.parse::<i64>().map_err(|e| fail(e.to_string()))?),
            Some(Type::Unsigned) => {
                Value::uint32(s.parse::<u32>().map_err(|e| fail(e.to_string()))?)
            }
            Some(Type::Float32) => {
                Value::float32(s.parse::<f32>().map_err(|e| fail(e.to_string()))?)
            }
            Some(Type::Float64) => {
                Value::float64(s.parse::<f64>().map_err(|e| fail(e.to_string()))?)
            }
            Some(Type::VisibleString) => Value::visible_string(s),
            Some(Type::MmsString) => Value::mms_string(s),
            Some(Type::OctetString) => {
                Value::octet_string(decode_hex(s).ok_or_else(|| fail("expected hex".into()))?)
            }
            Some(Type::BitString) => {
                let width = bit_len_of(&da.btype);
                let mut v = Value::bit_string(width);
                if s.len() > width || !s.chars().all(|c| c == '0' || c == '1') {
                    return Err(fail(format!("expected a {width}-bit binary string")));
                }
                for (i, c) in s.chars().enumerate() {
                    v.set_bit(i, c == '1');
                }
                v
            }
            Some(Type::UtcTime) => {
                let (secs, nanos) = time_util::parse_iso8601(s)
                    .ok_or_else(|| fail("expected an ISO 8601 timestamp".into()))?;
                Value::utc_time_parts(secs, nanos, crate::mms::TimeQuality(0))
            }
            other => {
                return Err(fail(format!("cannot apply Val to kind {other:?}")));
            }
        };
        da.value = Some(v);
        Ok(())
    }

    /// Walks `DAI` and `SDI` elements below a data object.
    ///
    /// An `SDI` names either a sub data object or a structured data attribute,
    /// and the two are told apart by which one exists. `path` is the dotted
    /// path of the object, for diagnostics and setting-group values.
    fn apply_doi(
        &mut self,
        object: &mut model::DataObject,
        dais: &[Dai],
        sdis: &[Sdi],
        path: &str,
    ) -> Result<()> {
        for dai in dais {
            let mut name = dai.name.clone();
            if object.attribute(&name).is_none() {
                // Array members are named "AnIn(2)" in the model but the DAI
                // may address the whole array by its base name.
                match split_array_name(&dai.name) {
                    Some((base, _)) if object.attribute(base).is_some() => name = base.to_string(),
                    _ => {
                        return Err(Error::model(format!(
                            "DAI {:?} has no matching DA",
                            dai.name
                        )))
                    }
                }
            }
            let da = object.attribute_mut(&name).expect("checked above");
            self.apply_vals(da, dai, path);
        }
        for sdi in sdis {
            if let Some(target) = self.sdi_target(object, sdi, path) {
                let sub = object.child_mut(&target).expect("sdi_target checked");
                let sub_path = join_path(path, &target);
                self.apply_doi(sub, &sdi.dais, &sdi.sdis, &sub_path)
                    .map_err(|e| Error::model(format!("SDI {}: {e}", sdi.name)))?;
                continue;
            }
            if object.attribute(&sdi.name).is_some() {
                let da = object.attribute_mut(&sdi.name).expect("just checked");
                let sub_path = join_path(path, &sdi.name);
                self.apply_sdi_on_da(da, sdi, &sub_path)
                    .map_err(|e| Error::model(format!("SDI {}: {e}", sdi.name)))?;
                continue;
            }
            return Err(Error::model(format!(
                "SDI {:?} matches neither an SDO nor a DA",
                sdi.name
            )));
        }
        Ok(())
    }

    /// Resolves an `SDI` to the name of the sub-object it addresses.
    ///
    /// An `SDI` naming an array-valued sub-object without its index selects
    /// the first element, which is what `SDI@ix` overrides.
    fn sdi_target(&mut self, object: &model::DataObject, sdi: &Sdi, path: &str) -> Option<String> {
        if object.child(&sdi.name).is_some() {
            return Some(sdi.name.clone());
        }
        // "phsA" with an ix of n addresses "phsA(n)"; without one, the first.
        if split_array_name(&sdi.name).is_some() {
            return None;
        }
        let ix = sdi.ix.trim();
        let mut n = 1;
        if !ix.is_empty() {
            match array_index(ix) {
                Some(v) => n = v,
                None => self.diag.add(
                    join_path(path, &sdi.name),
                    format!("SDI ix={:?} is not an array index; the first element is used", sdi.ix),
                ),
            }
        }
        let el = format!("{}({n})", sdi.name);
        if object.child(&el).is_some() {
            return Some(el);
        }
        if !ix.is_empty() {
            self.diag.add(
                join_path(path, &sdi.name),
                format!(
                    "SDI ix={ix} addresses element {n} of {:?}, which the type does not \
                     declare as an array",
                    sdi.name
                ),
            );
        }
        None
    }

    /// Applies the `Val` elements of a `DAI`, honouring the `sAddr`
    /// sub-address and the `sGroup` setting group.
    fn apply_vals(&mut self, da: &mut model::DataAttribute, dai: &Dai, path: &str) {
        let da_path = join_path(path, &da.name);
        // An sAddr names an element of an array attribute; a DAI without one
        // applies to the whole attribute.
        let mut elem: Option<usize> = None;
        let s_addr = dai.s_addr.trim();
        if !s_addr.is_empty() {
            if da.kind != Some(Type::Array) {
                self.diag.add(
                    da_path.clone(),
                    format!(
                        "DAI sAddr={:?} is given, but {} is not an array; the value is \
                         applied to the whole attribute",
                        dai.s_addr, da.name
                    ),
                );
            } else {
                match array_index(s_addr) {
                    Some(n) if n >= 1 && n <= da.count => elem = Some(n - 1),
                    _ => self.diag.add(
                        da_path.clone(),
                        format!(
                            "DAI sAddr={:?} does not select an element of the {}-element \
                             array {}",
                            dai.s_addr, da.count, da.name
                        ),
                    ),
                }
            }
        }
        for v in &dai.vals {
            // A Val carrying an sGroup other than the active one defines a
            // setting group. It is applied, recorded, and then rolled back,
            // so the group value is kept without becoming the served one.
            let group = self.group_of(&v.s_group);

            if let Some(i) = elem {
                let Some(prev) = da.value.as_ref().and_then(|a| a.index(i)).cloned() else {
                    self.diag.add(
                        da_path.clone(),
                        format!(
                            "sAddr {:?} does not select an element of the {}-element array",
                            dai.s_addr, da.count
                        ),
                    );
                    continue;
                };
                // The value is parsed against a stand-in attribute, because
                // that is how set_value resolves an enum literal and the
                // element carries no type of its own. The stand-in carries
                // the enum binding, or an Enum array would reject every
                // literal.
                let mut tmp = model::DataAttribute {
                    name: da.name.clone(),
                    fc: da.fc,
                    fc_name: da.fc_name.clone(),
                    kind: Some(prev.type_of()),
                    btype: da.btype.clone(),
                    enum_type: da.enum_type.clone(),
                    trg_ops: da.trg_ops,
                    ..Default::default()
                };
                if let Err(e) = self.set_value(&mut tmp, &v.value) {
                    self.diag.add(da_path.clone(), e.to_string());
                    continue;
                }
                let arr = da.value.as_mut().expect("indexed above");
                arr.set_index(i, tmp.value.unwrap_or(Value::None));
                if group > 0 {
                    // The recorded value is the whole array with that one
                    // position changed, because that is what the group holds;
                    // the served array is then put back.
                    let elem_attr = model::DataAttribute {
                        name: da.name.clone(),
                        fc: da.fc,
                        value: da.value.clone(),
                        ..Default::default()
                    };
                    if self.record_group_value(group, &elem_attr, path) {
                        da.value.as_mut().expect("present").set_index(i, prev);
                    }
                }
                continue;
            }

            // The value is applied to the attribute itself, because that is
            // what resolves an enum literal against its EnumType. A Val
            // carrying an sGroup other than the active one is then rolled
            // back, leaving only the per-group record.
            let prev = da.value.clone();
            if let Err(e) = self.set_value(da, &v.value) {
                self.diag.add(da_path.clone(), e.to_string());
                continue;
            }
            if group > 0 && self.record_group_value(group, da, path) {
                // Only a setting-group value is rolled back: a Val carrying an
                // sGroup on an attribute of another constraint is just a value,
                // and discarding it would lose the document's meaning.
                da.value = prev;
            }
        }
    }

    /// Resolves an `sGroup` attribute to a group number. A `Val` without one
    /// applies to the active group, numbered 0. A group number that is not a
    /// plain integer is reported and ignored.
    fn group_of(&mut self, s_group: &str) -> usize {
        let s = s_group.trim();
        if s.is_empty() {
            return 0;
        }
        match s.parse::<usize>() {
            Ok(n) if n <= 255 => n,
            _ => {
                self.diag.add(
                    "",
                    format!(
                        "Val sGroup={s_group:?} is not a setting-group number (0..255); the \
                         value is applied to the active group only"
                    ),
                );
                0
            }
        }
    }

    /// Notes a `Val@sGroup` value of an FC SG or SE attribute for the logical
    /// device being built, so the setting-group machinery can serve it.
    ///
    /// It reports whether the value was recorded: a `Val` carrying an
    /// `sGroup` on an attribute of another constraint is not a setting-group
    /// value, and the caller must then leave it applied rather than roll it
    /// back.
    fn record_group_value(&mut self, group: usize, da: &model::DataAttribute, path: &str) -> bool {
        if da.fc != model::Fc::Sg && da.fc != model::Fc::Se {
            return false;
        }
        let led = self.led_ref();
        let reference = format!("{led}/{}", join_path(path, &da.name));
        self.group_values
            .entry(led)
            .or_default()
            .entry(group)
            .or_default()
            .push((reference, da.value.clone().unwrap_or(Value::None)));
        true
    }

    /// Writes the values of setting group `n` onto the attributes they name,
    /// so the model serves the group the device declares active. Group 0 is
    /// the active group of `Val` elements that carried no `sGroup`, which
    /// [`Builder::apply_vals`] has already applied.
    fn apply_active_group(&self, ld: &mut model::LogicalDevice, n: usize) {
        if n == 0 {
            return;
        }
        let Some(values) = self.group_values.get(&ld.name).and_then(|g| g.get(&n)) else {
            return;
        };
        for (path, value) in values {
            let Some((_, rest)) = path.split_once('/') else {
                continue;
            };
            let segs: Vec<&str> = rest.split('.').collect();
            if segs.len() < 2 {
                continue;
            }
            let Some(object) = ld.node_mut(segs[0]).and_then(|ln| ln.object_mut(segs[1])) else {
                continue;
            };
            if let Some(da) = resolve_path(object, &segs[2..]) {
                da.value = Some(value.clone());
            }
        }
    }

    /// Turns the recorded per-group values into setting groups, ordered by
    /// device and then group number so the active group comes first.
    fn setting_groups(&self) -> Vec<model::SettingGroup> {
        let mut out = Vec::new();
        for (ld, groups) in &self.group_values {
            for (number, values) in groups {
                out.push(model::SettingGroup {
                    number: *number,
                    ld: ld.clone(),
                    values: values.iter().cloned().collect(),
                });
            }
        }
        out
    }

    fn apply_sdi_on_da(&mut self, da: &mut model::DataAttribute, sdi: &Sdi, path: &str) -> Result<()> {
        for dai in &sdi.dais {
            let c = da.child_mut(&dai.name).ok_or_else(|| {
                Error::model(format!("DAI {:?} has no matching member", dai.name))
            })?;
            self.apply_vals(c, dai, path);
        }
        for sub in &sdi.sdis {
            let c = da.child_mut(&sub.name).ok_or_else(|| {
                Error::model(format!("SDI {:?} has no matching member", sub.name))
            })?;
            self.apply_sdi_on_da(c, sub, &join_path(path, &sub.name))
                .map_err(|e| Error::model(format!("SDI {}: {e}", sub.name)))?;
        }
        Ok(())
    }

    fn build_report_control(&mut self, r: &ReportControl) -> model::ReportControl {
        let mut rc = self.report_control_of(r);
        if let Some(re) = &r.rpt_enabled {
            if !re.client_lns.is_empty() {
                self.reserve_instances(&mut rc, &re.client_lns);
            }
        }
        rc
    }

    /// Resolves each `ClientLN` of a report control block to the IP address of
    /// the client IED's access point, which is how the server recognises that
    /// client when it connects. `ClientLN` i reserves instance i+1. One that
    /// names an IED with no IP address in the Communication section cannot be
    /// enforced, so its instance is left free and reported.
    fn reserve_instances(&mut self, rc: &mut model::ReportControl, clients: &[ClientLn]) {
        let n = rc.rpt_enabled;
        let mut clients = clients;
        if clients.len() > n {
            self.diag.add(
                format!("ReportControl {}", rc.name),
                format!(
                    "{} ClientLN reservations for {n} instance(s); the extra ones are ignored",
                    clients.len()
                ),
            );
            clients = &clients[..n];
        }
        rc.reservations = vec![None; clients.len()];
        for (i, cl) in clients.iter().enumerate() {
            let ap = if cl.ap_ref.is_empty() { &cl.ap_name } else { &cl.ap_ref };
            match client_ip(self.scl, &cl.ied_name, ap) {
                Some(ip) => {
                    rc.reservations[i] = Some(model::ClientReservation {
                        ied_name: cl.ied_name.clone(),
                        ip: Some(ip),
                    });
                }
                None => self.diag.add(
                    format!("ReportControl {}", rc.name),
                    format!(
                        "ClientLN {} names IED {:?}, which has no IP address in the \
                         Communication section; the instance is left unreserved",
                        i + 1,
                        cl.ied_name
                    ),
                ),
            }
        }
    }

    fn report_control_of(&mut self, r: &ReportControl) -> model::ReportControl {
        let mut rc = model::ReportControl {
            name: r.name.clone(),
            rpt_id: r.rpt_id.clone(),
            data_set: r.dat_set.clone(),
            conf_rev: r.conf_rev,
            buffered: r.buffered,
            buf_time: r.buf_time,
            intg_pd: r.intg_pd,
            trg_ops: trg_ops_of(r.trg_ops.as_ref()),
            rpt_enabled: 1,
            ..Default::default()
        };
        if let Some(re) = &r.rpt_enabled {
            if re.max > 0 {
                rc.rpt_enabled = re.max as usize;
            }
        }
        // IEC 61850-6: an unindexed block is a single instance under its own
        // name, whatever RptEnabled says.
        if !r.indexed {
            rc.not_indexed = true;
            rc.rpt_enabled = 1;
        }
        if rc.rpt_enabled > MAX_RCB_INSTANCES {
            self.diag.add(
                format!("ReportControl {}", r.name),
                format!(
                    "RptEnabled max={} exceeds the {MAX_RCB_INSTANCES} two-digit instance names \
                     IEC 61850-6 defines; capped",
                    rc.rpt_enabled
                ),
            );
            rc.rpt_enabled = MAX_RCB_INSTANCES;
        }
        if let Some(of) = &r.opt_fields {
            let mut flags = model::OptFlds::default();
            let mut set = |on: bool, f: model::OptFlds| {
                if on {
                    flags |= f;
                }
            };
            set(of.seq_num, model::OptFlds::SEQ_NUM);
            set(of.time_stamp, model::OptFlds::TIME_OF_ENTRY);
            set(of.reason_code, model::OptFlds::REASON_CODE);
            set(of.data_set, model::OptFlds::DATA_SET_NAME);
            set(of.data_ref, model::OptFlds::DATA_REF);
            set(of.buf_ovfl, model::OptFlds::BUF_OVFL);
            set(of.entry_id, model::OptFlds::ENTRY_ID);
            set(of.config_ref, model::OptFlds::CONF_REV);
            set(of.segmentation, model::OptFlds::SEGMENTATION);
            rc.opt_flds = flags;
        }
        // The Ed 1 per-block buffer depth, superseded in Ed 2 by the
        // device-wide Services/ConfReportControl@maxBuf. Honoured when present
        // so an Ed 1 file keeps its configured depth.
        if r.buf_depth > 0 && r.buffered {
            rc.max_queue_size = r.buf_depth as usize;
        }
        rc
    }

    /// Instantiates a GOOSE control block. `type` selects the legacy GSSE
    /// variant, and `Protocol` names the transmission profile: `R-GOOSE` for
    /// routable GOOSE, which [`crate::rsession`] sends to the block's IP
    /// destination.
    fn build_gse_control(
        &mut self,
        ied_name: &str,
        ap_name: &str,
        ld_inst: &str,
        g: &GseControl,
    ) -> model::GseControl {
        let mut gc = model::GseControl {
            name: g.name.clone(),
            go_id: if g.app_id.is_empty() {
                g.name.clone()
            } else {
                g.app_id.clone()
            },
            data_set: g.dat_set.clone(),
            conf_rev: g.conf_rev,
            kind: gs_type_of(&g.kind),
            protocol: protocol_of(g.protocol.as_ref()),
            fixed_offs: g.fixed_offs,
            ..Default::default()
        };
        let what = format!("GSEControl {}", g.name);
        if gc.kind != model::GsType::Goose {
            self.diag.add(
                what.clone(),
                format!(
                    "type={:?} is a legacy or vendor GOOSE variant; it is configured as a plain \
                     GOOSE control block",
                    g.kind
                ),
            );
        }
        if g.fixed_offs {
            self.diag.add(
                what.clone(),
                "fixedOffs requests the fixed-offset GOOSE encoding, which is not implemented; \
                 a publisher built from this block encodes its dataset with variable lengths",
            );
        }
        if let Some(gse) = find_gse(self.scl, ied_name, ap_name, ld_inst, &g.name) {
            let (mac, app_id, vlan_id, prio) = address_of(gse.address.as_ref());
            gc.dst_mac = mac;
            gc.app_id = app_id;
            gc.vlan_id = vlan_id;
            gc.vlan_pri = prio;
            gc.dst_ip = ip_of(gse.address.as_ref());
            gc.min_time = gse.min_time.as_ref().map_or(0, DurUnits::millis);
            gc.max_time = gse.max_time.as_ref().map_or(0, DurUnits::millis);
        }
        if gc.protocol == "R-GOOSE" && gc.dst_ip.is_none() {
            self.diag.add(
                what,
                "Protocol is R-GOOSE but the GSE address has no IP or IPv6 destination; the \
                 block cannot be sent routably",
            );
        }
        gc
    }

    /// Instantiates a sampled-value control block, including the Ed 2
    /// `SmvOpts` optional-field set and the sample mode. An R-SV block is sent
    /// by [`crate::rsession`] to its IP destination.
    fn build_sv_control(
        &mut self,
        ied_name: &str,
        ap_name: &str,
        ld_inst: &str,
        s: &SampledValueControl,
    ) -> model::SvControl {
        let mut sc = model::SvControl {
            name: s.name.clone(),
            sv_id: s.smv_id.clone(),
            data_set: s.dat_set.clone(),
            conf_rev: s.conf_rev,
            smp_rate: s.smp_rate,
            no_asdu: s.nof_asdu,
            multicast: s.multicast,
            smp_mod: smp_mod_of(&s.smp_mod),
            sv_type: s.sv_type.trim().to_string(),
            protocol: protocol_of(s.protocol.as_ref()),
            ..Default::default()
        };
        if let Some(o) = &s.smv_opts {
            sc.opts = model::SvOpts {
                refresh_time: o.refresh_time,
                sample_synchronized: o.sample_synchronized,
                sample_rate: o.sample_rate,
                data_set: o.data_set,
                security: o.security,
                timestamp: o.timestamp,
                synch_source_id: o.synch_source_id,
            };
        }
        if let Some(smv) = find_smv(self.scl, ied_name, ap_name, ld_inst, &s.name) {
            let (mac, app_id, vlan_id, prio) = address_of(smv.address.as_ref());
            sc.dst_mac = mac;
            sc.app_id = app_id;
            sc.vlan_id = vlan_id;
            sc.vlan_pri = prio;
            sc.dst_ip = ip_of(smv.address.as_ref());
        }
        if sc.protocol == "R-SV" && sc.dst_ip.is_none() {
            self.diag.add(
                format!("SampledValueControl {}", s.name),
                "Protocol is R-SV but the SMV address has no IP or IPv6 destination; the block \
                 cannot be sent routably",
            );
        }
        sc
    }
}

/// Walks the remaining segments of an attribute path from a data object,
/// descending through sub-objects and structured attributes alike, and
/// returns the attribute the path names.
fn resolve_path<'m>(
    object: &'m mut model::DataObject,
    segs: &[&str],
) -> Option<&'m mut model::DataAttribute> {
    let (first, rest) = segs.split_first()?;
    if object.child(first).is_some() {
        return resolve_path(object.child_mut(first)?, rest);
    }
    let mut da = object.attribute_mut(first)?;
    for name in rest {
        da = da.child_mut(name)?;
    }
    Some(da)
}

/// The outcome of parsing a `count` attribute.
enum ArrayCount {
    /// Not an array: absent, zero, or an enumeration literal, which the
    /// schema's union type permits.
    Scalar,
    Array(usize),
    /// A numeric count beyond [`MAX_ARRAY_COUNT`], which is a corrupt or
    /// hostile value rather than a legitimate one.
    TooBig,
}

fn array_count(count: &str) -> ArrayCount {
    match count.trim().parse::<i64>() {
        Ok(v) if v > MAX_ARRAY_COUNT as i64 => ArrayCount::TooBig,
        Ok(v) if v > 0 => ArrayCount::Array(v as usize),
        _ => ArrayCount::Scalar,
    }
}

/// Reads an SCL array index (the `ix` attribute of a `DOI`, `SDI`, `DAI` or
/// `FCDA`, or a `DAI@sAddr`) as a one-based element number.
///
/// The base of `ix` is not settled by the standard: IEC 61850-6 TISSUE 1808
/// asks the question, and both spellings occur in files from different tools.
/// Treating 0 as the first element is the only reading under which both work,
/// so `ix=0` and `ix=1` both name element one, and an `ix` of n names element
/// n above one.
fn array_index(s: &str) -> Option<usize> {
    match s.trim().parse::<i64>() {
        Ok(0) => Some(1),
        Ok(n) if n > 0 => usize::try_from(n).ok(),
        _ => None,
    }
}

/// Splits `AnIn(3)` into `AnIn` and 3.
fn split_array_name(s: &str) -> Option<(&str, usize)> {
    let i = s.rfind('(')?;
    let inner = s[i + 1..].strip_suffix(')')?;
    let n: usize = inner.parse().ok()?;
    (n > 0).then_some((&s[..i], n))
}

fn join_path(prefix: &str, name: &str) -> String {
    match (prefix.is_empty(), name.is_empty()) {
        (true, _) => name.to_string(),
        (_, true) => prefix.to_string(),
        _ => format!("{prefix}.{name}"),
    }
}

/// Adds the trigger flags of a `DA` or `BDA` to the inherited options: a
/// `BDA` inherits the options of the enclosing `DA`.
fn trg_ops_of_flags(inherited: model::TrgOps, dchg: bool, qchg: bool, dupd: bool) -> model::TrgOps {
    let mut trg = inherited;
    if dchg {
        trg |= model::TrgOps::DATA_CHANGE;
    }
    if qchg {
        trg |= model::TrgOps::QUALITY_CHANGE;
    }
    if dupd {
        trg |= model::TrgOps::DATA_UPDATE;
    }
    trg
}

/// The `PHYCOMADDR` structure of IEC 61850-8-1: the MAC address, VLAN
/// priority and identifier, and APPID of a stream.
fn phy_com_addr(fc: model::Fc, fc_raw: &str, trg: model::TrgOps) -> Vec<model::DataAttribute> {
    let leaf = |name: &str, kind: Type, v: Value| model::DataAttribute {
        name: name.to_string(),
        fc,
        fc_name: fc_raw.to_string(),
        kind: Some(kind),
        trg_ops: trg,
        value: Some(v),
        ..Default::default()
    };
    vec![
        leaf("Addr", Type::OctetString, Value::octet_string(vec![0; 6])),
        leaf("PRIORITY", Type::Unsigned, Value::uint8(0)),
        leaf("VID", Type::Unsigned, Value::uint16(0)),
        leaf("APPID", Type::Unsigned, Value::uint16(0)),
    ]
}

/// Maps an SCL basic type name to an MMS value type.
///
/// The full `tPredefinedBasicTypeEnum` of IEC 61850-8-1 is covered. A type
/// outside it yields `None`: the build records a diagnostic and keeps the
/// attribute in the tree, valueless, so that datasets, report control blocks
/// and control models which name it still resolve.
fn kind_of(btype: &str) -> Option<Type> {
    let t = match btype {
        "BOOLEAN" => Type::Boolean,
        "INT8" | "INT16" | "INT24" | "INT32" | "INT64" | "INT128" | "Enum" | "DACount" => {
            Type::Integer
        }
        "INT8U" | "INT16U" | "INT24U" | "INT32U" | "INT64U" => Type::Unsigned,
        "FLOAT32" => Type::Float32,
        "FLOAT64" => Type::Float64,
        "VisString32" | "VisString64" | "VisString65" | "VisString129" | "VisString255"
        | "ObjRef" | "Currency" => Type::VisibleString,
        "Unicode255" => Type::MmsString,
        "Octet6" | "Octet16" | "Octet64" | "EntryID" => Type::OctetString,
        "Quality" | "Dbpos" | "Tcmd" | "Check" | "TrgOps" | "OptFlds" | "SvOptFlds"
        | "LogOptFlds" => Type::BitString,
        "Timestamp" => Type::UtcTime,
        "EntryTime" => Type::BinaryTime,
        _ => return None,
    };
    Some(t)
}

/// Returns the bit-string width of a bit-string basic type. The widths are
/// fixed by IEC 61850-8-1.
fn bit_len_of(btype: &str) -> usize {
    match btype {
        "Quality" => 13,
        "Dbpos" | "Tcmd" | "Check" => 2,
        "TrgOps" => 6,
        "OptFlds" | "SvOptFlds" | "LogOptFlds" => 10,
        _ => 8,
    }
}

/// The served default of a leaf attribute: zero of the basic type, an
/// all-clear quality, or the Unix epoch for timestamps.
fn default_value(kind: Type, btype: &str) -> Value {
    match kind {
        Type::Boolean => Value::boolean(false),
        Type::Integer => Value::int32(0),
        Type::Unsigned => Value::uint32(0),
        Type::Float32 => Value::float32(0.0),
        Type::Float64 => Value::float64(0.0),
        Type::VisibleString => Value::visible_string(""),
        Type::MmsString => Value::mms_string(""),
        Type::OctetString => Value::octet_string(Vec::new()),
        Type::BitString => {
            if btype == "Quality" {
                model::Quality::GOOD.value()
            } else {
                Value::bit_string(bit_len_of(btype))
            }
        }
        Type::UtcTime => Value::UtcTime([0; 8]),
        Type::BinaryTime => Value::BinaryTime(vec![0; 6]),
        _ => Value::None,
    }
}

/// Resolves `FCDA` entries to object references.
///
/// Array index notation in `doName`/`daName` (for example `phsA(2)`) is passed
/// through verbatim, and `FCDA@ix` is the Ed 2 alternative that names the same
/// instance numerically. A member under a constraint this crate does not know
/// is carried verbatim, so it still resolves and still reports.
fn build_data_set(ied_name: &str, ld_inst: &str, dse: &DataSet) -> Result<model::DataSet> {
    let mut ds = model::DataSet {
        name: dse.name.clone(),
        ..Default::default()
    };
    for f in &dse.fcdas {
        let fc = model::parse_fc_lenient(&f.fc);
        let li = if f.ld_inst.is_empty() {
            ld_inst
        } else {
            &f.ld_inst
        };
        let ln = if f.ln_class == "LLN0" {
            "LLN0".to_string()
        } else {
            format!("{}{}{}", f.prefix, f.ln_class, f.ln_inst)
        };
        let mut do_name = f.do_name.clone();
        let mut da_name = f.da_name.clone();
        if let Some(n) = array_index(&f.ix).filter(|_| !f.ix.trim().is_empty()) {
            // ix selects an element of the innermost array the member names.
            // Where the member names an attribute, the usual case when the
            // array is an attribute array, the index goes there; otherwise it
            // goes on the data object.
            let target = if da_name.is_empty() { &mut do_name } else { &mut da_name };
            if !target.is_empty() && split_array_name(target).is_none() {
                *target = format!("{target}({n})");
            }
        }
        let mut reference = format!("{ied_name}{li}/{ln}");
        if !do_name.is_empty() {
            reference.push('.');
            reference.push_str(&do_name);
        }
        if !da_name.is_empty() {
            reference.push('.');
            reference.push_str(&da_name);
        }
        let r = model::ObjectReference::parse(reference)
            .map_err(|e| Error::model(format!("dataset {}: {e}", dse.name)))?;
        ds.entries.push(model::Fcda {
            reference: r,
            fc,
            fc_name: f.fc.clone(),
        });
    }
    Ok(ds)
}

/// Finds the IP address of an IED's access point, preferring the named access
/// point and otherwise the first one of the IED that has an address.
fn client_ip(scl: &Scl, ied_name: &str, ap_name: &str) -> Option<IpAddr> {
    let comm = scl.communication.as_ref()?;
    if ied_name.is_empty() {
        return None;
    }
    let mut fallback = None;
    for sn in &comm.sub_networks {
        for cap in &sn.connected_aps {
            if cap.ied_name != ied_name {
                continue;
            }
            let Some(ip) = cap.ip().and_then(|s| s.parse::<IpAddr>().ok()) else {
                continue;
            };
            if ap_name.is_empty() || cap.ap_name == ap_name {
                return Some(ip);
            }
            fallback.get_or_insert(ip);
        }
    }
    fallback
}

/// Converts a `TrgOps` element.
///
/// Per the schema, `gi` defaults to true, including when the element itself is
/// absent, so a control block with no `TrgOps` still answers a general
/// interrogation.
fn trg_ops_of(t: Option<&TrgOpsElem>) -> model::TrgOps {
    let Some(t) = t else {
        return model::TrgOps::GI;
    };
    let mut ops = trg_ops_of_flags(model::TrgOps::default(), t.dchg, t.qchg, t.dupd);
    if t.period {
        ops |= model::TrgOps::INTEGRITY;
    }
    if t.gi {
        ops |= model::TrgOps::GI;
    }
    ops
}

/// Maps the `type` attribute of a `GSEControl`.
fn gs_type_of(t: &str) -> model::GsType {
    if t.trim().eq_ignore_ascii_case("GSSE") {
        model::GsType::Gsse
    } else {
        model::GsType::Goose
    }
}

/// Returns the value of a `Protocol` element.
fn protocol_of(p: Option<&Protocol>) -> String {
    p.map(|p| p.value.trim().to_string()).unwrap_or_default()
}

/// Maps the `smpMod` attribute, defaulting to samples per period.
fn smp_mod_of(s: &str) -> model::SmpMod {
    match s.trim() {
        "SmpPerSec" => model::SmpMod::SmpPerSec,
        "SecPerSmp" => model::SmpMod::SecPerSmp,
        _ => model::SmpMod::SmpPerPeriod,
    }
}

fn build_log_control(l: &LogControl) -> model::LogControl {
    // lnClass is what names the node holding the log: a prefix or instance
    // without one does not.
    let class = l.ln_class.trim();
    model::LogControl {
        name: l.name.clone(),
        data_set: l.dat_set.clone(),
        log_name: l.log_name.clone(),
        trg_ops: trg_ops_of(l.trg_ops.as_ref()),
        intg_pd: l.intg_pd,
        log_ena: l.log_ena,
        buf_time: l.buf_time,
        reason_code: l.reason_code,
        log_ld_inst: l.ld_inst.trim().to_string(),
        log_ln: if class.is_empty() {
            String::new()
        } else {
            format!("{}{class}{}", l.prefix.trim(), l.ln_inst.trim())
        },
    }
}

/// Locates the Communication `GSE` entry for a control block, preferring the
/// exact access point and falling back to any access point of the IED.
fn find_gse<'a>(
    scl: &'a Scl,
    ied_name: &str,
    ap_name: &str,
    ld_inst: &str,
    cb_name: &str,
) -> Option<&'a Gse> {
    let comm = scl.communication.as_ref()?;
    let mut fallback = None;
    for sn in &comm.sub_networks {
        for cap in &sn.connected_aps {
            if cap.ied_name != ied_name {
                continue;
            }
            for g in &cap.gses {
                if g.cb_name != cb_name || (!g.ld_inst.is_empty() && g.ld_inst != ld_inst) {
                    continue;
                }
                if cap.ap_name == ap_name {
                    return Some(g);
                }
                fallback.get_or_insert(g);
            }
        }
    }
    fallback
}

fn find_smv<'a>(
    scl: &'a Scl,
    ied_name: &str,
    ap_name: &str,
    ld_inst: &str,
    cb_name: &str,
) -> Option<&'a Smv> {
    let comm = scl.communication.as_ref()?;
    let mut fallback = None;
    for sn in &comm.sub_networks {
        for cap in &sn.connected_aps {
            if cap.ied_name != ied_name {
                continue;
            }
            for v in &cap.smvs {
                if v.cb_name != cb_name || (!v.ld_inst.is_empty() && v.ld_inst != ld_inst) {
                    continue;
                }
                if cap.ap_name == ap_name {
                    return Some(v);
                }
                fallback.get_or_insert(v);
            }
        }
    }
    fallback
}

/// Extracts the MAC, APPID and VLAN parameters from an `Address`.
///
/// APPID and VLAN-ID are hexadecimal per IEC 61850-6; VLAN-PRIORITY is
/// decimal. Unparseable parameters are left zero.
fn address_of(a: Option<&Address>) -> ([u8; 6], u16, u16, u8) {
    let mut mac = [0u8; 6];
    let (mut app_id, mut vlan_id, mut prio) = (0u16, 0u16, 0u8);
    let Some(a) = a else {
        return (mac, app_id, vlan_id, prio);
    };
    if let Some(s) = a.get("MAC-Address") {
        if let Some(m) = parse_mac(s) {
            mac = m;
        }
    }
    if let Some(s) = a.get("APPID") {
        if let Ok(v) = u16::from_str_radix(s, 16) {
            app_id = v;
        }
    }
    if let Some(s) = a.get("VLAN-ID") {
        if let Ok(v) = u16::from_str_radix(s, 16) {
            vlan_id = v & 0x0fff;
        }
    }
    if let Some(s) = a.get("VLAN-PRIORITY") {
        if let Ok(v) = s.parse::<u8>() {
            prio = v & 7;
        }
    }
    (mac, app_id, vlan_id, prio)
}

/// The destination IP address of a routable (R-GOOSE, R-SV) control block:
/// the `IP` or `IPv6` parameter of its address, without a prefix length.
fn ip_of(a: Option<&Address>) -> Option<IpAddr> {
    let a = a?;
    for name in ["IP", "IPv6"] {
        let Some(s) = a.get(name) else {
            continue;
        };
        let s = s.split('/').next().unwrap_or(s);
        if let Ok(ip) = s.parse() {
            return Some(ip);
        }
    }
    None
}

/// Parses `01-0C-CD-01-00-01`, or the colon-separated form.
fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(['-', ':']).filter(|p| !p.is_empty()).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Fc;

    const DOC: &str = r#"
<SCL version="2007" revision="B">
  <Header id="demo"/>
  <Communication>
    <SubNetwork name="W01">
      <ConnectedAP iedName="ied1" apName="S1">
        <GSE ldInst="LD0" cbName="gcb01">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-01</P>
            <P type="APPID">1000</P>
            <P type="VLAN-ID">00A</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
      </ConnectedAP>
    </SubNetwork>
  </Communication>
  <IED name="ied1">
    <Services><ConfReportControl maxBuf="256"/></Services>
    <AccessPoint name="S1">
      <Server>
        <LDevice inst="LD0">
          <LN0 lnClass="LLN0" inst="" lnType="LLN0_1">
            <DataSet name="Events">
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="AnIn1" fc="MX"/>
            </DataSet>
            <ReportControl name="brcb" rptID="r1" datSet="Events" confRev="1" buffered="true">
              <TrgOps dchg="true" qchg="true"/>
              <OptFields seqNum="true" reasonCode="true"/>
            </ReportControl>
            <ReportControl name="urcb" datSet="Events" buffered="false"/>
            <ReportControl name="single" datSet="Events" buffered="false" indexed="false">
              <RptEnabled max="4"/>
            </ReportControl>
            <GSEControl name="gcb01" appID="events" datSet="Events" confRev="3"/>
          </LN0>
          <LN prefix="" lnClass="GGIO" inst="1" lnType="GGIO_1">
            <DOI name="Ind1">
              <DAI name="stVal"><Val>true</Val></DAI>
            </DOI>
            <DOI name="Mod">
              <DAI name="stVal"><Val>blocked</Val></DAI>
            </DOI>
            <DOI name="AnIn1">
              <SDI name="mag"><DAI name="f"><Val>230.4</Val></DAI></SDI>
            </DOI>
          </LN>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>
  <DataTypeTemplates>
    <LNodeType id="LLN0_1" lnClass="LLN0"><DO name="Beh" type="INS_1"/></LNodeType>
    <LNodeType id="GGIO_1" lnClass="GGIO">
      <DO name="Ind1" type="SPS_1"/>
      <DO name="Mod" type="INC_1"/>
      <DO name="AnIn1" type="MV_1"/>
    </LNodeType>
    <DOType id="SPS_1" cdc="SPS">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>
    <DOType id="INS_1" cdc="INS">
      <DA name="stVal" bType="INT32" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST"/>
    </DOType>
    <DOType id="INC_1" cdc="INC">
      <DA name="stVal" bType="Enum" type="Mod_e" fc="ST" dchg="true"/>
      <DA name="ctlModel" bType="Enum" type="CtlModel_e" fc="CF"><Val>direct-with-normal-security</Val></DA>
    </DOType>
    <DOType id="MV_1" cdc="MV">
      <DA name="mag" bType="Struct" type="AnalogueValue_1" fc="MX" dchg="true"/>
      <DA name="q" bType="Quality" fc="MX" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="MX"/>
      <DA name="units" bType="Struct" type="Unit_1" fc="CF"/>
    </DOType>
    <DAType id="AnalogueValue_1"><BDA name="f" bType="FLOAT32"/></DAType>
    <DAType id="Unit_1"><BDA name="SIUnit" bType="Enum" type="SIUnit_e"/></DAType>
    <EnumType id="Mod_e">
      <EnumVal ord="1">on</EnumVal>
      <EnumVal ord="2">blocked</EnumVal>
      <EnumVal ord="5">off</EnumVal>
    </EnumType>
    <EnumType id="CtlModel_e">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="1">direct-with-normal-security</EnumVal>
    </EnumType>
    <EnumType id="SIUnit_e"><EnumVal ord="5">A</EnumVal></EnumType>
  </DataTypeTemplates>
</SCL>"#;

    fn model_of() -> model::Model {
        let scl = crate::scl::parse(DOC).expect("document parses");
        build_model(&scl, &BuildOptions::new()).expect("model builds")
    }

    #[test]
    fn the_model_tree_is_instantiated_from_the_templates() {
        let m = model_of();
        assert_eq!(m.name, "ied1");
        assert_eq!(m.device_names(), ["ied1LD0"]);
        let ld = m.device("ied1LD0").unwrap();
        assert_eq!(ld.nodes.len(), 2);
        assert_eq!(ld.nodes[0].name, "LLN0");
        assert_eq!(ld.nodes[1].name, "GGIO1");

        // The DOs come from the LNodeType, with their DOType attributes.
        let ggio = ld.node("GGIO1").unwrap();
        let ind1 = ggio.object("Ind1").unwrap();
        assert_eq!(ind1.cdc, "SPS");
        let names: Vec<&str> = ind1.attributes.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["stVal", "q", "t"]);
    }

    #[test]
    fn functional_constraints_and_types_come_from_the_do_type() {
        let m = model_of();
        let stval = m
            .attribute(&"ied1LD0/GGIO1.Ind1.stVal".into(), Fc::St)
            .unwrap();
        assert_eq!(stval.kind, Some(Type::Boolean));
        assert_eq!(stval.btype, "BOOLEAN");
        assert!(stval.trg_ops.has(model::TrgOps::DATA_CHANGE));

        let q = m.attribute(&"ied1LD0/GGIO1.Ind1.q".into(), Fc::St).unwrap();
        assert_eq!(q.value.as_ref().unwrap().bit_len(), 13, "Quality is 13 bits");
        assert!(q.trg_ops.has(model::TrgOps::QUALITY_CHANGE));

        // A CF attribute on the same object is a different constraint.
        assert!(m
            .attribute(&"ied1LD0/GGIO1.AnIn1.units".into(), Fc::Cf)
            .is_some());
        assert!(m
            .attribute(&"ied1LD0/GGIO1.AnIn1.units".into(), Fc::Mx)
            .is_none());
    }

    #[test]
    fn structured_attributes_expand_from_their_da_type() {
        let m = model_of();
        let mag = m
            .attribute(&"ied1LD0/GGIO1.AnIn1.mag".into(), Fc::Mx)
            .unwrap();
        assert_eq!(mag.kind, Some(Type::Structure));
        assert_eq!(mag.children.len(), 1);
        assert_eq!(mag.children[0].name, "f");
        // Members inherit the enclosing attribute's constraint.
        assert_eq!(mag.children[0].fc, Fc::Mx);
    }

    #[test]
    fn initial_values_from_dai_and_sdi_are_applied() {
        let m = model_of();
        assert!(m
            .attribute(&"ied1LD0/GGIO1.Ind1.stVal".into(), Fc::St)
            .unwrap()
            .value
            .as_ref()
            .unwrap()
            .as_bool());
        assert_eq!(
            m.attribute(&"ied1LD0/GGIO1.AnIn1.mag.f".into(), Fc::Mx)
                .unwrap()
                .value
                .as_ref()
                .unwrap()
                .as_f32(),
            230.4
        );
    }

    /// Enum literals in SCL are names, not ordinals; resolving them wrong
    /// silently mis-configures things like ctlModel.
    #[test]
    fn enum_literals_resolve_to_their_ordinals() {
        let m = model_of();
        let mode = m
            .attribute(&"ied1LD0/GGIO1.Mod.stVal".into(), Fc::St)
            .unwrap();
        assert_eq!(mode.value.as_ref().unwrap().as_i64(), 2, "blocked is ord 2");

        let ctl = m
            .attribute(&"ied1LD0/GGIO1.Mod.ctlModel".into(), Fc::Cf)
            .unwrap();
        assert_eq!(ctl.value.as_ref().unwrap().as_i64(), 1);
    }

    #[test]
    fn datasets_resolve_to_fully_scoped_references() {
        let m = model_of();
        let ds = m
            .device("ied1LD0")
            .unwrap()
            .node("LLN0")
            .unwrap()
            .data_set("Events")
            .unwrap();
        assert_eq!(ds.entries.len(), 2);
        assert_eq!(
            ds.entries[0].reference.as_str(),
            "ied1LD0/GGIO1.Ind1.stVal"
        );
        assert_eq!(ds.entries[0].fc, Fc::St);
        // An FCDA with no daName names the whole data object.
        assert_eq!(ds.entries[1].reference.as_str(), "ied1LD0/GGIO1.AnIn1");
        assert_eq!(ds.entries[1].fc, Fc::Mx);
    }

    /// `indexed="false"` makes a report control block a single instance under
    /// its own name (IEC 61850-6); the default stays indexed.
    #[test]
    fn an_unindexed_report_control_is_one_instance() {
        let m = model_of();
        let ln0 = m.device("ied1LD0").unwrap().node("LLN0").unwrap();
        let single = ln0.report_control("single").unwrap();
        assert!(single.not_indexed);
        assert_eq!(single.rpt_enabled, 1, "whatever RptEnabled says");
        assert!(!ln0.report_control("urcb").unwrap().not_indexed);
    }

    /// A DA's trigger options cover its components: the leaf an update writes,
    /// mag.f, triggers as mag does (IEC 61850-7-2).
    #[test]
    fn trigger_options_reach_the_components() {
        let m = model_of();
        let f = m
            .attribute(&"ied1LD0/GGIO1.AnIn1.mag.f".into(), Fc::Mx)
            .expect("mag.f");
        assert!(f.trg_ops.has(model::TrgOps::DATA_CHANGE));
    }

    #[test]
    fn report_controls_carry_their_configuration() {
        let m = model_of();
        let ln0 = m.device("ied1LD0").unwrap().node("LLN0").unwrap();
        let brcb = ln0.report_control("brcb").unwrap();
        assert!(brcb.buffered);
        assert_eq!(brcb.conf_rev, 1);
        assert_eq!(brcb.data_set, "Events");
        assert!(brcb.trg_ops.has(model::TrgOps::DATA_CHANGE));
        assert!(brcb.trg_ops.has(model::TrgOps::QUALITY_CHANGE));
        assert!(brcb.trg_ops.has(model::TrgOps::GI), "gi defaults to true");
        assert!(brcb.opt_flds.has(model::OptFlds::SEQ_NUM));
        assert!(brcb.opt_flds.has(model::OptFlds::REASON_CODE));
        assert!(!brcb.opt_flds.has(model::OptFlds::ENTRY_ID));
        assert_eq!(brcb.rpt_enabled, 1, "the default instance count");

        // maxBuf from Services becomes the buffered block's queue depth.
        assert_eq!(brcb.max_queue_size, 256);
        let urcb = ln0.report_control("urcb").unwrap();
        assert!(!urcb.buffered);
        assert_eq!(urcb.max_queue_size, 0, "unbuffered blocks buffer nothing");
        // A control block with no TrgOps element still answers a GI.
        assert!(urcb.trg_ops.has(model::TrgOps::GI));
    }

    /// The Ethernet APPID and VLAN live in the Communication section, not on
    /// the control block; a publisher without them addresses nothing.
    #[test]
    fn goose_control_blocks_resolve_their_communication_parameters() {
        let m = model_of();
        let gcb = &m.device("ied1LD0").unwrap().node("LLN0").unwrap().gse_controls[0];
        assert_eq!(gcb.name, "gcb01");
        assert_eq!(gcb.go_id, "events", "appID is the GoID string");
        assert_eq!(gcb.conf_rev, 3);
        assert_eq!(gcb.dst_mac, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);
        assert_eq!(gcb.app_id, 0x1000, "APPID is hexadecimal");
        assert_eq!(gcb.vlan_id, 0x00a, "VLAN-ID is hexadecimal");
        assert_eq!(gcb.vlan_pri, 4, "VLAN-PRIORITY is decimal");
        assert_eq!(gcb.min_time, 4);
        assert_eq!(gcb.max_time, 1000);
    }

    #[test]
    fn selecting_an_ied_or_access_point_that_is_absent_is_an_error() {
        let scl = crate::scl::parse(DOC).unwrap();
        assert!(build_model(&scl, &BuildOptions::new().for_ied("nope")).is_err());
        assert!(build_model(&scl, &BuildOptions::new().with_access_point("S9")).is_err());
        // The named ones work.
        assert!(build_model(
            &scl,
            &BuildOptions::new().for_ied("ied1").with_access_point("S1")
        )
        .is_ok());
    }

    #[test]
    fn a_missing_template_is_reported_with_its_location() {
        let doc = DOC.replace(r#"lnType="GGIO_1""#, r#"lnType="MISSING""#);
        let scl = crate::scl::parse(&doc).unwrap();
        let err = build_model(&scl, &BuildOptions::new()).unwrap_err().to_string();
        assert!(err.contains("MISSING"), "error should name the type: {err}");
        assert!(err.contains("GGIO1"), "error should name the node: {err}");
    }

    #[test]
    fn mac_addresses_parse_in_both_separator_styles() {
        assert_eq!(
            parse_mac("01-0C-CD-01-00-01"),
            Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        );
        assert_eq!(
            parse_mac("01:0c:cd:01:00:01"),
            Some([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])
        );
        assert!(parse_mac("01-0C-CD").is_none());
        assert!(parse_mac("zz-0C-CD-01-00-01").is_none());
    }

    #[test]
    fn unknown_basic_types_have_no_kind() {
        assert_eq!(kind_of("BOOLEAN"), Some(Type::Boolean));
        assert_eq!(kind_of("SvOptFlds"), Some(Type::BitString));
        assert!(kind_of("Nonsense").is_none());
        // Every bit-string type has its standard width.
        assert_eq!(bit_len_of("Quality"), 13);
        assert_eq!(bit_len_of("Dbpos"), 2);
        assert_eq!(bit_len_of("Check"), 2);
        assert_eq!(bit_len_of("TrgOps"), 6);
        assert_eq!(bit_len_of("OptFlds"), 10);
        assert_eq!(bit_len_of("LogOptFlds"), 10);
    }

    #[test]
    fn array_indices_accept_both_bases() {
        assert_eq!(array_index("0"), Some(1));
        assert_eq!(array_index("1"), Some(1));
        assert_eq!(array_index("3"), Some(3));
        assert_eq!(array_index("-1"), None);
        assert_eq!(array_index("x"), None);
        assert_eq!(split_array_name("AnIn(3)"), Some(("AnIn", 3)));
        assert_eq!(split_array_name("AnIn(0)"), None);
        assert_eq!(split_array_name("AnIn"), None);
    }
}
