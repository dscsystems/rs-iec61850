//! Instantiates the runtime object model from a parsed SCL document.

use std::collections::HashMap;
use std::path::Path;

use crate::mms::{Type, Value};
use crate::model;
use crate::time_util;

use super::types::*;
use super::{parse_file, Error, Result};

/// Adjusts model instantiation.
#[derive(Debug, Clone, Default)]
pub struct BuildOptions {
    /// The IED to instantiate; the default is the first IED in the document.
    pub ied: String,
    /// The access point of the chosen IED; the default is the first access
    /// point that contains a `Server`.
    pub access_point: String,
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
/// Deliberate limitations: only the first `Val` of a `DAI` is applied, so
/// setting-group specific values are ignored; array elements cannot be
/// addressed by `DAI`; `Octet64` values must be hexadecimal; and report and
/// log instances beyond the configuration are not created here.
pub fn build_model(scl: &Scl, opts: &BuildOptions) -> Result<model::Model> {
    let ied = find_ied(scl, &opts.ied)?;
    let ap = find_ap(ied, &opts.access_point)?;
    let server = ap
        .server
        .as_ref()
        .expect("find_ap only returns access points with a Server");

    let builder = Builder::new(scl);
    let mut m = model::Model {
        name: ied.name.clone(),
        devices: Vec::new(),
    };

    for lde in &server.l_devices {
        let mut ld = model::LogicalDevice {
            name: format!("{}{}", ied.name, lde.inst),
            inst: lde.inst.clone(),
            nodes: Vec::new(),
        };
        for lne in lde.all_lns() {
            let ln = builder
                .build_ln(&ied.name, &ap.name, &lde.inst, lne)
                .map_err(|e| {
                    Error::model(format!(
                        "{}{}/{}: {e}",
                        ied.name,
                        lde.inst,
                        lne.instance_name()
                    ))
                })?;
            ld.nodes.push(ln);
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
    Ok(m)
}

/// Returns the configured report-buffer capacity, zero if the document
/// declares none.
fn report_max_buf(ied: &Ied, ap: &AccessPoint) -> usize {
    for svc in [ap.services.as_ref(), ied.services.as_ref()].into_iter().flatten() {
        if let Some(c) = svc.conf_report_control {
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

/// Resolves data type templates and enum bindings.
struct Builder<'a> {
    scl: &'a Scl,
    ln_types: HashMap<&'a str, &'a LNodeType>,
    do_types: HashMap<&'a str, &'a DoType>,
    da_types: HashMap<&'a str, &'a DaType>,
    enums: HashMap<&'a str, &'a EnumType>,
}

impl<'a> Builder<'a> {
    fn new(scl: &'a Scl) -> Builder<'a> {
        let mut b = Builder {
            scl,
            ln_types: HashMap::new(),
            do_types: HashMap::new(),
            da_types: HashMap::new(),
            enums: HashMap::new(),
        };
        if let Some(t) = &scl.data_type_templates {
            for x in &t.ln_node_types {
                b.ln_types.insert(x.id.as_str(), x);
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

    fn build_ln(
        &self,
        ied_name: &str,
        ap_name: &str,
        ld_inst: &str,
        lne: &Ln,
    ) -> Result<model::LogicalNode> {
        let lnt = self
            .ln_types
            .get(lne.ln_type.as_str())
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
        for doi in &lne.dois {
            let object = ln
                .object_mut(&doi.name)
                .ok_or_else(|| {
                    Error::model(format!(
                        "DOI {:?} has no matching DO in type {:?}",
                        doi.name, lne.ln_type
                    ))
                })?;
            self.apply_doi(object, &doi.dais, &doi.sdis)
                .map_err(|e| Error::model(format!("DOI {}: {e}", doi.name)))?;
        }

        for dse in &lne.data_sets {
            ln.data_sets.push(build_data_set(ied_name, ld_inst, dse)?);
        }
        for r in &lne.report_controls {
            ln.report_controls.push(build_report_control(r));
        }
        for g in &lne.gse_controls {
            ln.gse_controls
                .push(self.build_gse_control(ied_name, ap_name, ld_inst, g));
        }
        for s in &lne.sampled_value_controls {
            ln.sv_controls
                .push(self.build_sv_control(ied_name, ap_name, ld_inst, s));
        }
        for l in &lne.log_controls {
            ln.log_controls.push(build_log_control(l));
        }
        if let Some(sg) = lne.setting_control {
            ln.setting_control = Some(model::SettingControl {
                num_of_sgs: sg.num_of_sgs,
                act_sg: sg.act_sg,
            });
        }
        Ok(ln)
    }

    /// Expands a `DOType`, and its `SDO`s recursively, into a data object.
    fn build_do(&self, name: &str, type_id: &str, depth: usize) -> Result<model::DataObject> {
        if depth > 16 {
            return Err(Error::model(format!("SDO nesting too deep at {type_id:?}")));
        }
        let dot = self
            .do_types
            .get(type_id)
            .ok_or_else(|| Error::model(format!("DOType {type_id:?} not found")))?;

        let mut object = model::DataObject {
            name: name.to_string(),
            cdc: dot.cdc.clone(),
            ..Default::default()
        };
        for dae in &dot.das {
            let fc: model::Fc = dae
                .fc
                .parse()
                .map_err(|e| Error::model(format!("DA {}: {e}", dae.name)))?;
            let mut trg = model::TrgOps::default();
            if dae.dchg {
                trg |= model::TrgOps::DATA_CHANGE;
            }
            if dae.qchg {
                trg |= model::TrgOps::QUALITY_CHANGE;
            }
            if dae.dupd {
                trg |= model::TrgOps::DATA_UPDATE;
            }
            let da = self
                .build_da(&dae.name, fc, &dae.btype, &dae.kind, &dae.count, trg, &dae.vals, 0)
                .map_err(|e| Error::model(format!("DA {}: {e}", dae.name)))?;
            object.attributes.push(da);
        }
        for sdo in &dot.sdos {
            let sub = self
                .build_do(&sdo.name, &sdo.kind, depth + 1)
                .map_err(|e| Error::model(format!("SDO {}: {e}", sdo.name)))?;
            object.objects.push(sub);
        }
        Ok(object)
    }

    /// Expands one `DA` or `BDA`.
    ///
    /// `BDA` members inherit the constraint of the enclosing `DA`. Arrays of
    /// basic types get an array value with per-element defaults; arrays of
    /// constructed types keep the count with no value.
    // A DA and a BDA are expanded by the same code, and between them they
    // carry this many independent SCL attributes; bundling them into a struct
    // would only move the list.
    #[allow(clippy::too_many_arguments)]
    fn build_da(
        &self,
        name: &str,
        fc: model::Fc,
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
        let mut da = model::DataAttribute {
            name: name.to_string(),
            fc,
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
        // Non-numeric counts (rarely, an enum value name) are ignored.
        let n: usize = count.trim().parse().unwrap_or(0);

        if btype == "Struct" {
            let dat = self
                .da_types
                .get(type_id)
                .ok_or_else(|| Error::model(format!("DAType {type_id:?} not found")))?;
            da.kind = Some(Type::Structure);
            for bda in &dat.bdas {
                let child = self
                    .build_da(
                        &bda.name,
                        fc,
                        &bda.btype,
                        &bda.kind,
                        &bda.count,
                        model::TrgOps::default(),
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

        let kind = kind_of(btype)?;
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
                "true" | "1" => Value::boolean(true),
                "false" | "0" => Value::boolean(false),
                _ => return Err(fail("expected a boolean".into())),
            },
            Some(Type::Integer) => Value::int64(
                s.parse::<i64>()
                    .map_err(|e| fail(e.to_string()))?,
            ),
            Some(Type::Unsigned) => Value::uint32(
                s.parse::<u32>()
                    .map_err(|e| fail(e.to_string()))?,
            ),
            Some(Type::Float32) => Value::float32(
                s.parse::<f32>()
                    .map_err(|e| fail(e.to_string()))?,
            ),
            Some(Type::Float64) => Value::float64(
                s.parse::<f64>()
                    .map_err(|e| fail(e.to_string()))?,
            ),
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
    /// and the two are told apart by which one exists.
    fn apply_doi(
        &self,
        object: &mut model::DataObject,
        dais: &[Dai],
        sdis: &[Sdi],
    ) -> Result<()> {
        for dai in dais {
            let da = object
                .attribute_mut(&dai.name)
                .ok_or_else(|| Error::model(format!("DAI {:?} has no matching DA", dai.name)))?;
            if let Some(v) = dai.vals.first() {
                self.set_value(da, &v.value)?;
            }
        }
        for sdi in sdis {
            if object.child(&sdi.name).is_some() {
                let sub = object.child_mut(&sdi.name).expect("just checked");
                self.apply_doi(sub, &sdi.dais, &sdi.sdis)
                    .map_err(|e| Error::model(format!("SDI {}: {e}", sdi.name)))?;
                continue;
            }
            if object.attribute(&sdi.name).is_some() {
                let da = object.attribute_mut(&sdi.name).expect("just checked");
                self.apply_sdi_on_da(da, sdi)
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

    fn apply_sdi_on_da(&self, da: &mut model::DataAttribute, sdi: &Sdi) -> Result<()> {
        for dai in &sdi.dais {
            let c = da.child_mut(&dai.name).ok_or_else(|| {
                Error::model(format!("DAI {:?} has no matching member", dai.name))
            })?;
            if let Some(v) = dai.vals.first() {
                self.set_value(c, &v.value)?;
            }
        }
        for sub in &sdi.sdis {
            let c = da.child_mut(&sub.name).ok_or_else(|| {
                Error::model(format!("SDI {:?} has no matching member", sub.name))
            })?;
            self.apply_sdi_on_da(c, sub)
                .map_err(|e| Error::model(format!("SDI {}: {e}", sub.name)))?;
        }
        Ok(())
    }

    fn build_gse_control(
        &self,
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
            ..Default::default()
        };
        if let Some(gse) = find_gse(self.scl, ied_name, ap_name, ld_inst, &g.name) {
            let (mac, app_id, vlan_id, prio) = address_of(gse.address.as_ref());
            gc.dst_mac = mac;
            gc.app_id = app_id;
            gc.vlan_id = vlan_id;
            gc.vlan_pri = prio;
            gc.min_time = gse.min_time.as_ref().map_or(0, DurUnits::millis);
            gc.max_time = gse.max_time.as_ref().map_or(0, DurUnits::millis);
        }
        gc
    }

    fn build_sv_control(
        &self,
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
            ..Default::default()
        };
        if let Some(smv) = find_smv(self.scl, ied_name, ap_name, ld_inst, &s.name) {
            let (mac, app_id, vlan_id, prio) = address_of(smv.address.as_ref());
            sc.dst_mac = mac;
            sc.app_id = app_id;
            sc.vlan_id = vlan_id;
            sc.vlan_pri = prio;
        }
        sc
    }
}

/// Maps an SCL basic type name to an MMS value type.
///
/// Unknown basic types are an error rather than a silent default: a model that
/// silently loses an attribute's type serves the wrong thing forever after.
fn kind_of(btype: &str) -> Result<Type> {
    let t = match btype {
        "BOOLEAN" => Type::Boolean,
        "INT8" | "INT16" | "INT24" | "INT32" | "INT64" | "INT128" | "Enum" => Type::Integer,
        "INT8U" | "INT16U" | "INT24U" | "INT32U" | "INT64U" => Type::Unsigned,
        "FLOAT32" => Type::Float32,
        "FLOAT64" => Type::Float64,
        "VisString32" | "VisString64" | "VisString65" | "VisString129" | "VisString255"
        | "ObjRef" | "Currency" => Type::VisibleString,
        "Unicode255" => Type::MmsString,
        "Octet6" | "Octet16" | "Octet64" | "EntryID" => Type::OctetString,
        "Quality" | "Dbpos" | "Tcmd" | "Check" | "TrgOps" | "OptFlds" => Type::BitString,
        "Timestamp" => Type::UtcTime,
        "EntryTime" => Type::BinaryTime,
        other => return Err(Error::model(format!("unsupported bType {other:?}"))),
    };
    Ok(t)
}

/// Returns the bit-string width of a bit-string basic type.
fn bit_len_of(btype: &str) -> usize {
    match btype {
        "Quality" => 13,
        "Dbpos" | "Tcmd" | "Check" => 2,
        "TrgOps" => 6,
        "OptFlds" => 10,
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
/// through verbatim, as the reference form has no other way to express it.
fn build_data_set(ied_name: &str, ld_inst: &str, dse: &DataSet) -> Result<model::DataSet> {
    let mut ds = model::DataSet {
        name: dse.name.clone(),
        entries: Vec::new(),
    };
    for f in &dse.fcdas {
        let fc: model::Fc = f
            .fc
            .parse()
            .map_err(|e| Error::model(format!("dataset {}: {e}", dse.name)))?;
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
        let mut reference = format!("{ied_name}{li}/{ln}");
        if !f.do_name.is_empty() {
            reference.push('.');
            reference.push_str(&f.do_name);
        }
        if !f.da_name.is_empty() {
            reference.push('.');
            reference.push_str(&f.da_name);
        }
        let r = model::ObjectReference::parse(reference)
            .map_err(|e| Error::model(format!("dataset {}: {e}", dse.name)))?;
        ds.entries.push(model::Fcda { reference: r, fc });
    }
    Ok(ds)
}

fn build_report_control(r: &ReportControl) -> model::ReportControl {
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
    if let Some(re) = r.rpt_enabled {
        if re.max > 0 {
            rc.rpt_enabled = re.max as usize;
        }
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
    rc
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
    let mut ops = model::TrgOps::default();
    if t.dchg {
        ops |= model::TrgOps::DATA_CHANGE;
    }
    if t.qchg {
        ops |= model::TrgOps::QUALITY_CHANGE;
    }
    if t.dupd {
        ops |= model::TrgOps::DATA_UPDATE;
    }
    if t.period {
        ops |= model::TrgOps::INTEGRITY;
    }
    if t.gi {
        ops |= model::TrgOps::GI;
    }
    ops
}

fn build_log_control(l: &LogControl) -> model::LogControl {
    model::LogControl {
        name: l.name.clone(),
        data_set: l.dat_set.clone(),
        log_name: l.log_name.clone(),
        trg_ops: trg_ops_of(l.trg_ops.as_ref()),
        intg_pd: l.intg_pd,
        log_ena: l.log_ena,
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
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
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
    fn unsupported_basic_types_are_rejected() {
        assert!(kind_of("BOOLEAN").is_ok());
        assert!(kind_of("Nonsense").is_err());
        // Every bit-string type has its standard width.
        assert_eq!(bit_len_of("Quality"), 13);
        assert_eq!(bit_len_of("Dbpos"), 2);
        assert_eq!(bit_len_of("Check"), 2);
        assert_eq!(bit_len_of("TrgOps"), 6);
        assert_eq!(bit_len_of("OptFlds"), 10);
    }
}
