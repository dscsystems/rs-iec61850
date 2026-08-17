use std::fmt::Write as _;

use crate::mms::{Type, Value};

use super::{Fc, ObjectReference, OptFlds, TrgOps};

/// The root of an IED data model: the server's view when built from SCL or by
/// hand, and the client's view when retrieved online.
#[derive(Debug, Clone, Default)]
pub struct Model {
    /// The IED name.
    pub name: String,
    pub devices: Vec<LogicalDevice>,
}

/// One MMS domain.
#[derive(Debug, Clone, Default)]
pub struct LogicalDevice {
    /// The full domain name: the IED name followed by the LD instance.
    pub name: String,
    pub inst: String,
    pub nodes: Vec<LogicalNode>,
}

/// Holds data objects and the control blocks configured on them.
#[derive(Debug, Clone, Default)]
pub struct LogicalNode {
    /// For example `LLN0` or `Q0XCBR1`.
    pub name: String,
    /// The logical-node class, for example `XCBR`. Empty on retrieved models,
    /// where the server does not report it.
    pub class: String,
    pub objects: Vec<DataObject>,

    pub data_sets: Vec<DataSet>,
    pub report_controls: Vec<ReportControl>,
    pub gse_controls: Vec<GseControl>,
    pub sv_controls: Vec<SvControl>,
    pub log_controls: Vec<LogControl>,
    pub setting_control: Option<SettingControl>,
}

/// A data object or sub-data-object.
#[derive(Debug, Clone, Default)]
pub struct DataObject {
    pub name: String,
    /// The common data class, for example `MV`. Empty when unknown.
    pub cdc: String,
    pub objects: Vec<DataObject>,
    pub attributes: Vec<DataAttribute>,
}

/// A data attribute, possibly structured.
///
/// Leaf attributes carry a current value; structured attributes carry
/// children.
#[derive(Debug, Clone, Default)]
pub struct DataAttribute {
    pub name: String,
    pub fc: Fc,
    /// The leaf basic type, or [`Type::Structure`] / [`Type::Array`].
    pub kind: Option<Type>,
    /// The SCL `bType` (for example `Quality`, `Timestamp`, `INT32`), kept for
    /// diagnostics and for reconstructing the SCL.
    pub btype: String,
    /// The SCL `EnumType` id when `btype` is `Enum`.
    ///
    /// An enumerated attribute is an integer on the wire, so this is the only
    /// thing that ties a value back to the literal names it stands for. It is
    /// what lets SCL initial values given as literals be resolved, and what a
    /// browser needs to show `blocked` rather than `2`.
    pub enum_type: String,
    /// The element count when `kind` is [`Type::Array`].
    pub count: usize,
    pub children: Vec<DataAttribute>,
    /// The leaf value; `None` on structured attributes.
    pub value: Option<Value>,
    /// The dchg/qchg/dupd flags from SCL, which drive reporting.
    pub trg_ops: TrgOps,
}

/// A named set of functionally-constrained data references.
#[derive(Debug, Clone, Default)]
pub struct DataSet {
    pub name: String,
    pub entries: Vec<Fcda>,
}

/// One dataset member.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fcda {
    /// `LD/LN.DO[.DA]`.
    pub reference: ObjectReference,
    pub fc: Fc,
}

/// The SCL-side configuration of a report control block.
#[derive(Debug, Clone, Default)]
pub struct ReportControl {
    pub name: String,
    pub rpt_id: String,
    /// The dataset name within the same logical node.
    pub data_set: String,
    pub conf_rev: u32,
    pub buffered: bool,
    /// The buffer time in milliseconds.
    pub buf_time: u32,
    pub trg_ops: TrgOps,
    pub opt_flds: OptFlds,
    /// The integrity period in milliseconds.
    pub intg_pd: u32,
    /// The maximum number of enabled instances (indexed RCBs).
    pub rpt_enabled: usize,
    /// How many reports a buffered control block retains while no subscriber
    /// is enabled. Zero leaves it to the server's own default, and it has no
    /// meaning for an unbuffered control block.
    pub max_queue_size: usize,
}

/// The SCL-side configuration of a GOOSE control block.
#[derive(Debug, Clone, Default)]
pub struct GseControl {
    pub name: String,
    pub go_id: String,
    pub data_set: String,
    pub conf_rev: u32,
    /// Communication parameters resolved from the SCL Communication section,
    /// zero when absent.
    pub dst_mac: [u8; 6],
    pub app_id: u16,
    pub vlan_id: u16,
    pub vlan_pri: u8,
    /// The minimum retransmission time in milliseconds.
    pub min_time: u32,
    /// The stable retransmission time in milliseconds.
    pub max_time: u32,
}

/// The SCL-side configuration of a sampled-value control block.
#[derive(Debug, Clone, Default)]
pub struct SvControl {
    pub name: String,
    pub sv_id: String,
    pub data_set: String,
    pub conf_rev: u32,
    pub smp_rate: u32,
    pub no_asdu: u32,
    pub multicast: bool,
    pub dst_mac: [u8; 6],
    pub app_id: u16,
    pub vlan_id: u16,
    pub vlan_pri: u8,
}

/// The SCL-side configuration of a log control block.
#[derive(Debug, Clone, Default)]
pub struct LogControl {
    pub name: String,
    pub data_set: String,
    pub log_name: String,
    pub trg_ops: TrgOps,
    pub intg_pd: u32,
    pub log_ena: bool,
}

/// Describes the setting groups of a logical device.
#[derive(Debug, Clone, Copy, Default)]
pub struct SettingControl {
    pub num_of_sgs: u8,
    pub act_sg: u8,
}

/// What a reference resolves to within a [`Model`].
#[derive(Debug, Clone, Copy)]
pub enum Node<'a> {
    Device(&'a LogicalDevice),
    Node(&'a LogicalNode),
    Object(&'a DataObject),
    Attribute(&'a DataAttribute),
}

impl Model {
    /// Returns the logical device with the given (domain) name.
    pub fn device(&self, name: &str) -> Option<&LogicalDevice> {
        self.devices.iter().find(|ld| ld.name == name)
    }

    /// Returns the logical device with the given name, mutably.
    pub fn device_mut(&mut self, name: &str) -> Option<&mut LogicalDevice> {
        self.devices.iter_mut().find(|ld| ld.name == name)
    }

    /// Resolves a reference to the node it designates.
    ///
    /// When `fc` is not [`Fc::All`] or [`Fc::None`], attribute traversal is
    /// restricted to that constraint, which is what makes the same reference
    /// select a different attribute under `ST` and `MX`.
    pub fn lookup(&self, reference: &ObjectReference, fc: Fc) -> Option<Node<'_>> {
        let ld = self.device(reference.ld())?;
        let path = reference.path();
        if path.is_empty() {
            return Some(Node::Device(ld));
        }
        let ln = ld.node(path[0])?;
        if path.len() == 1 {
            return Some(Node::Node(ln));
        }
        let mut object = ln.object(path[1])?;
        let mut rest = &path[2..];
        // Descend through sub-objects while they match.
        while let Some(first) = rest.first() {
            match object.child(first) {
                Some(sub) => {
                    object = sub;
                    rest = &rest[1..];
                }
                None => break,
            }
        }
        if rest.is_empty() {
            return Some(Node::Object(object));
        }
        // Then through attributes, honouring the functional constraint at the
        // first level only: nested attributes inherit their parent's.
        let mut da = object
            .attributes
            .iter()
            .find(|a| a.name == rest[0] && fc.matches(a.fc))?;
        for name in &rest[1..] {
            da = da.child(name)?;
        }
        Some(Node::Attribute(da))
    }

    /// Resolves a reference to a data attribute under the given constraint.
    pub fn attribute(&self, reference: &ObjectReference, fc: Fc) -> Option<&DataAttribute> {
        match self.lookup(reference, fc) {
            Some(Node::Attribute(da)) => Some(da),
            _ => None,
        }
    }

    /// Resolves a reference to a data attribute, mutably.
    ///
    /// This is the write path a server takes for both client writes and
    /// process updates.
    pub fn attribute_mut(
        &mut self,
        reference: &ObjectReference,
        fc: Fc,
    ) -> Option<&mut DataAttribute> {
        let path = reference.path();
        if path.len() < 3 {
            return None;
        }
        let ld = self.device_mut(reference.ld())?;
        let ln = ld.node_mut(path[0])?;
        let mut object = ln.object_mut(path[1])?;
        let mut rest = &path[2..];
        while let Some(first) = rest.first() {
            // Look before descending: the borrow checker will not let us hold
            // a reference to the parent across the reassignment otherwise.
            if object.child(first).is_none() {
                break;
            }
            object = object.child_mut(first)?;
            rest = &rest[1..];
        }
        if rest.is_empty() {
            return None;
        }
        let mut da = object
            .attributes
            .iter_mut()
            .find(|a| a.name == rest[0] && fc.matches(a.fc))?;
        for name in &rest[1..] {
            da = da.child_mut(name)?;
        }
        Some(da)
    }

    /// Returns every logical device name, in model order.
    pub fn device_names(&self) -> Vec<String> {
        self.devices.iter().map(|ld| ld.name.clone()).collect()
    }
}

impl LogicalDevice {
    /// Returns the named logical node.
    pub fn node(&self, name: &str) -> Option<&LogicalNode> {
        self.nodes.iter().find(|ln| ln.name == name)
    }

    /// Returns the named logical node, mutably.
    pub fn node_mut(&mut self, name: &str) -> Option<&mut LogicalNode> {
        self.nodes.iter_mut().find(|ln| ln.name == name)
    }
}

impl LogicalNode {
    /// Returns the named top-level data object.
    pub fn object(&self, name: &str) -> Option<&DataObject> {
        self.objects.iter().find(|do_| do_.name == name)
    }

    /// Returns the named top-level data object, mutably.
    pub fn object_mut(&mut self, name: &str) -> Option<&mut DataObject> {
        self.objects.iter_mut().find(|do_| do_.name == name)
    }

    /// Returns the named dataset.
    pub fn data_set(&self, name: &str) -> Option<&DataSet> {
        self.data_sets.iter().find(|ds| ds.name == name)
    }

    /// Returns the named report control block.
    pub fn report_control(&self, name: &str) -> Option<&ReportControl> {
        self.report_controls.iter().find(|rc| rc.name == name)
    }
}

impl DataObject {
    /// Returns the named sub-object.
    pub fn child(&self, name: &str) -> Option<&DataObject> {
        self.objects.iter().find(|s| s.name == name)
    }

    /// Returns the named sub-object, mutably.
    pub fn child_mut(&mut self, name: &str) -> Option<&mut DataObject> {
        self.objects.iter_mut().find(|s| s.name == name)
    }

    /// Returns the named direct attribute.
    pub fn attribute(&self, name: &str) -> Option<&DataAttribute> {
        self.attributes.iter().find(|a| a.name == name)
    }

    /// Returns the named direct attribute, mutably.
    pub fn attribute_mut(&mut self, name: &str) -> Option<&mut DataAttribute> {
        self.attributes.iter_mut().find(|a| a.name == name)
    }

    /// Returns the sorted set of functional constraints present on the object,
    /// including those of nested sub-objects.
    ///
    /// A client browsing a device uses this to know which constraints are
    /// worth reading.
    pub fn fcs(&self) -> Vec<Fc> {
        let mut seen: Vec<Fc> = Vec::new();
        fn walk(o: &DataObject, seen: &mut Vec<Fc>) {
            for a in &o.attributes {
                if !seen.contains(&a.fc) {
                    seen.push(a.fc);
                }
            }
            for s in &o.objects {
                walk(s, seen);
            }
        }
        walk(self, &mut seen);
        seen.sort_unstable();
        seen
    }
}

impl DataAttribute {
    /// Returns the named child of a structured attribute.
    pub fn child(&self, name: &str) -> Option<&DataAttribute> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Returns the named child of a structured attribute, mutably.
    pub fn child_mut(&mut self, name: &str) -> Option<&mut DataAttribute> {
        self.children.iter_mut().find(|c| c.name == name)
    }

    /// Reports whether the attribute is a leaf carrying a value.
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Collects the attribute's value, assembling a structure from its
    /// children when it is not a leaf.
    ///
    /// This is what a read of a structured attribute returns.
    pub fn collect_value(&self) -> Value {
        if self.is_leaf() {
            return self.value.clone().unwrap_or(Value::None);
        }
        let children: Vec<Value> = self.children.iter().map(DataAttribute::collect_value).collect();
        if self.kind == Some(Type::Array) {
            Value::Array(children)
        } else {
            Value::Structure(children)
        }
    }

    /// Applies a value to the attribute, distributing a structure over its
    /// children.
    ///
    /// Returns false when the value's shape does not match the attribute's,
    /// which is the type-inconsistent case a server must reject.
    pub fn apply_value(&mut self, v: &Value) -> bool {
        if self.is_leaf() {
            self.value = Some(v.clone());
            return true;
        }
        let children = v.children();
        if children.len() != self.children.len() {
            return false;
        }
        self.children
            .iter_mut()
            .zip(children)
            .all(|(da, cv)| da.apply_value(cv))
    }
}

impl std::fmt::Display for Model {
    /// Renders the model tree for diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "IED {}", self.name)?;
        for ld in &self.devices {
            writeln!(f, "  LD {}", ld.name)?;
            for ln in &ld.nodes {
                writeln!(f, "    LN {}", ln.name)?;
                for object in &ln.objects {
                    dump_object(f, object, "      ")?;
                }
            }
        }
        Ok(())
    }
}

fn dump_object(
    f: &mut std::fmt::Formatter<'_>,
    object: &DataObject,
    indent: &str,
) -> std::fmt::Result {
    write!(f, "{indent}DO {}", object.name)?;
    if !object.cdc.is_empty() {
        write!(f, " ({})", object.cdc)?;
    }
    f.write_char('\n')?;
    let deeper = format!("{indent}  ");
    for a in &object.attributes {
        dump_attribute(f, a, &deeper)?;
    }
    for s in &object.objects {
        dump_object(f, s, &deeper)?;
    }
    Ok(())
}

fn dump_attribute(
    f: &mut std::fmt::Formatter<'_>,
    da: &DataAttribute,
    indent: &str,
) -> std::fmt::Result {
    write!(f, "{indent}{} [{}]", da.name, da.fc)?;
    if let Some(k) = da.kind {
        write!(f, " {k}")?;
    }
    if let Some(v) = &da.value {
        write!(f, " = {v}")?;
    }
    f.write_char('\n')?;
    let deeper = format!("{indent}  ");
    for c in &da.children {
        dump_attribute(f, c, &deeper)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a small model shaped like a real one: an MV under MX, a status
    /// point under ST, and a configuration attribute under CF.
    fn sample() -> Model {
        let leaf = |name: &str, fc: Fc, v: Value| DataAttribute {
            name: name.into(),
            fc,
            kind: Some(v.type_of()),
            value: Some(v),
            ..Default::default()
        };
        Model {
            name: "ied1".into(),
            devices: vec![LogicalDevice {
                name: "ied1LD0".into(),
                inst: "LD0".into(),
                nodes: vec![LogicalNode {
                    name: "GGIO1".into(),
                    class: "GGIO".into(),
                    objects: vec![
                        DataObject {
                            name: "AnIn1".into(),
                            cdc: "MV".into(),
                            objects: vec![],
                            attributes: vec![
                                DataAttribute {
                                    name: "mag".into(),
                                    fc: Fc::Mx,
                                    kind: Some(Type::Structure),
                                    children: vec![leaf("f", Fc::Mx, Value::float32(230.4))],
                                    ..Default::default()
                                },
                                leaf("q", Fc::Mx, Value::bit_string(13)),
                                leaf("t", Fc::Mx, Value::UtcTime([0; 8])),
                            ],
                        },
                        DataObject {
                            name: "SPCSO1".into(),
                            cdc: "SPC".into(),
                            objects: vec![],
                            attributes: vec![
                                leaf("stVal", Fc::St, Value::boolean(false)),
                                leaf("ctlModel", Fc::Cf, Value::int32(1)),
                            ],
                        },
                    ],
                    ..Default::default()
                }],
            }],
        }
    }

    #[test]
    fn a_reference_resolves_to_each_level_of_the_tree() {
        let m = sample();
        assert!(matches!(
            m.lookup(&"ied1LD0/GGIO1".into(), Fc::All),
            Some(Node::Node(_))
        ));
        assert!(matches!(
            m.lookup(&"ied1LD0/GGIO1.AnIn1".into(), Fc::All),
            Some(Node::Object(_))
        ));
        assert!(matches!(
            m.lookup(&"ied1LD0/GGIO1.AnIn1.mag".into(), Fc::Mx),
            Some(Node::Attribute(_))
        ));
        assert!(m.lookup(&"nope/GGIO1".into(), Fc::All).is_none());
        assert!(m.lookup(&"ied1LD0/NOPE".into(), Fc::All).is_none());
    }

    #[test]
    fn nested_attributes_resolve_through_their_parents() {
        let m = sample();
        let da = m
            .attribute(&"ied1LD0/GGIO1.AnIn1.mag.f".into(), Fc::Mx)
            .expect("mag.f resolves");
        assert_eq!(da.name, "f");
        assert_eq!(da.value.as_ref().unwrap().as_f32(), 230.4);
    }

    /// The same object exposes different attributes under different
    /// constraints; ignoring the constraint returns the wrong one.
    #[test]
    fn the_functional_constraint_selects_between_attributes() {
        let m = sample();
        assert!(m
            .attribute(&"ied1LD0/GGIO1.SPCSO1.stVal".into(), Fc::St)
            .is_some());
        assert!(
            m.attribute(&"ied1LD0/GGIO1.SPCSO1.stVal".into(), Fc::Cf)
                .is_none(),
            "stVal is not a configuration attribute"
        );
        assert!(m
            .attribute(&"ied1LD0/GGIO1.SPCSO1.ctlModel".into(), Fc::Cf)
            .is_some());
        // The wildcard finds either.
        assert!(m
            .attribute(&"ied1LD0/GGIO1.SPCSO1.stVal".into(), Fc::All)
            .is_some());
    }

    #[test]
    fn the_mutable_lookup_reaches_the_same_attribute() {
        let mut m = sample();
        let da = m
            .attribute_mut(&"ied1LD0/GGIO1.AnIn1.mag.f".into(), Fc::Mx)
            .expect("mag.f resolves mutably");
        da.value = Some(Value::float32(1.0));
        assert_eq!(
            m.attribute(&"ied1LD0/GGIO1.AnIn1.mag.f".into(), Fc::Mx)
                .unwrap()
                .value
                .as_ref()
                .unwrap()
                .as_f32(),
            1.0
        );
        assert!(m
            .attribute_mut(&"ied1LD0/GGIO1.AnIn1.mag.nope".into(), Fc::Mx)
            .is_none());
    }

    #[test]
    fn a_structured_attribute_collects_its_children_into_one_value() {
        let m = sample();
        let mag = m
            .attribute(&"ied1LD0/GGIO1.AnIn1.mag".into(), Fc::Mx)
            .unwrap();
        let v = mag.collect_value();
        assert_eq!(v.type_of(), Type::Structure);
        assert_eq!(v.len(), 1);
        assert_eq!(v.index(0).unwrap().as_f32(), 230.4);
    }

    #[test]
    fn applying_a_structure_distributes_it_over_the_children() {
        let mut m = sample();
        let mag = m
            .attribute_mut(&"ied1LD0/GGIO1.AnIn1.mag".into(), Fc::Mx)
            .unwrap();
        assert!(mag.apply_value(&Value::structure(vec![Value::float32(400.0)])));
        assert_eq!(mag.collect_value().index(0).unwrap().as_f32(), 400.0);

        // A shape mismatch is rejected rather than silently truncating.
        assert!(!mag.apply_value(&Value::structure(vec![
            Value::float32(1.0),
            Value::float32(2.0),
        ])));
        assert!(!mag.apply_value(&Value::float32(1.0)));
    }

    #[test]
    fn an_object_reports_every_constraint_it_carries() {
        let m = sample();
        let spcso = m.device("ied1LD0").unwrap().node("GGIO1").unwrap();
        assert_eq!(spcso.object("SPCSO1").unwrap().fcs(), [Fc::St, Fc::Cf]);
        assert_eq!(spcso.object("AnIn1").unwrap().fcs(), [Fc::Mx]);
    }

    #[test]
    fn the_model_renders_as_a_readable_tree() {
        let s = sample().to_string();
        assert!(s.contains("IED ied1"));
        assert!(s.contains("LD ied1LD0"));
        assert!(s.contains("LN GGIO1"));
        assert!(s.contains("DO AnIn1 (MV)"));
        assert!(s.contains("f [MX]"));
    }
}
