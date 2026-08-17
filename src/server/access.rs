//! Maps between MMS item IDs and the object model: the name list a client
//! browses, the values a read composes, the attribute a write lands on, and
//! the type specification `getVariableAccessAttributes` reports.
//!
//! An MMS item ID is the flat `LN$FC$DO[$SDO...][$DA...]` form. Everything
//! here is a pure function of the model, which is what makes the server's
//! wire behaviour testable without a socket.

use crate::mms::{Component, Type, TypeSpec, Value};
use crate::model::{DataAttribute, DataObject, Fc, LogicalDevice, LogicalNode};

/// Enumerates the MMS variable item IDs a client sees via `getNameList` for
/// one logical device.
///
/// For each logical node that is the bare node name, then `LN$FC` and the
/// object and attribute paths under each functional constraint, in a stable
/// order. Clients reconstruct the whole model from this list, so its shape is
/// part of the wire contract.
pub fn names_for_domain(ld: &LogicalDevice) -> Vec<String> {
    let mut names = Vec::new();
    for ln in &ld.nodes {
        names.push(ln.name.clone());

        // The constraints present on this node, in canonical order.
        let mut order: Vec<Fc> = Vec::new();
        for object in &ln.objects {
            for fc in object.fcs() {
                if !order.contains(&fc) {
                    order.push(fc);
                }
            }
        }
        order.sort_unstable();

        for fc in order {
            let prefix = format!("{}${fc}", ln.name);
            names.push(prefix.clone());
            for object in &ln.objects {
                if !has_fc(object, fc) {
                    continue;
                }
                let p = format!("{prefix}${}", object.name);
                names.push(p.clone());
                for a in &object.attributes {
                    append_attr_names(&mut names, &p, a, fc);
                }
                for sub in &object.objects {
                    append_sub_do_names(&mut names, &p, sub, fc);
                }
            }
        }
    }
    names
}

fn append_sub_do_names(names: &mut Vec<String>, prefix: &str, object: &DataObject, fc: Fc) {
    if !has_fc(object, fc) {
        return;
    }
    let p = format!("{prefix}${}", object.name);
    names.push(p.clone());
    for a in &object.attributes {
        append_attr_names(names, &p, a, fc);
    }
    for sub in &object.objects {
        append_sub_do_names(names, &p, sub, fc);
    }
}

fn append_attr_names(names: &mut Vec<String>, prefix: &str, a: &DataAttribute, fc: Fc) {
    if a.fc != fc {
        return;
    }
    let p = format!("{prefix}${}", a.name);
    names.push(p.clone());
    for c in &a.children {
        append_attr_names(names, &p, c, fc);
    }
}

/// Reports whether a data object exposes anything under `fc`.
pub fn has_fc(object: &DataObject, fc: Fc) -> bool {
    object.fcs().contains(&fc)
}

/// Splits an item ID into its logical node, functional constraint and the
/// remaining path.
///
/// Returns `None` when the item is not `LN$FC[...]`, or names a constraint
/// that does not exist.
fn split_item(item: &str) -> Option<(&str, Fc, Vec<&str>)> {
    let mut parts = item.split('$');
    let ln = parts.next()?;
    let fc: Fc = parts.next()?.parse().ok()?;
    Some((ln, fc, parts.collect()))
}

/// Returns the MMS value for an item ID within a logical node, composing
/// structures for object-level and structured-attribute reads.
///
/// A read of `LN$FC` yields every object under that constraint, a read of
/// `LN$FC$DO` yields the object, and a read down to a leaf yields its value.
pub fn resolve_read(ln: &LogicalNode, item: &str) -> Option<Value> {
    let (_, fc, rest) = split_item(item)?;
    if rest.is_empty() {
        // "LN$FC": a structure of every data object under that constraint.
        let members: Vec<Value> = ln
            .objects
            .iter()
            .filter_map(|object| do_value(object, fc))
            .collect();
        return Some(Value::Structure(members));
    }
    let (object, rest) = descend_objects(ln.object(rest[0])?, &rest[1..]);
    if rest.is_empty() {
        return do_value(object, fc);
    }
    let da = descend_attributes(object, fc, rest)?;
    Some(da_value(da))
}

/// Descends sub-objects while the path keeps matching one.
fn descend_objects<'a, 'p>(
    mut object: &'a DataObject,
    mut rest: &'p [&'p str],
) -> (&'a DataObject, &'p [&'p str]) {
    while let Some(first) = rest.first() {
        match object.child(first) {
            Some(sub) => {
                object = sub;
                rest = &rest[1..];
            }
            None => break,
        }
    }
    (object, rest)
}

/// Descends the attribute path below a data object, honouring the functional
/// constraint at the first level; nested attributes inherit their parent's.
fn descend_attributes<'a>(
    object: &'a DataObject,
    fc: Fc,
    rest: &[&str],
) -> Option<&'a DataAttribute> {
    let mut da = object
        .attributes
        .iter()
        .find(|a| a.name == rest[0] && a.fc == fc)?;
    for name in &rest[1..] {
        da = da.child(name)?;
    }
    Some(da)
}

/// Composes the value of a data object under one constraint, as a structure of
/// its matching attributes and sub-objects.
///
/// Returns `None` when the object exposes nothing under that constraint, which
/// is what keeps an empty structure off the wire.
pub fn do_value(object: &DataObject, fc: Fc) -> Option<Value> {
    let mut members: Vec<Value> = object
        .attributes
        .iter()
        .filter(|a| a.fc == fc)
        .map(da_value)
        .collect();
    for sub in &object.objects {
        if let Some(v) = do_value(sub, fc) {
            if !v.is_empty() {
                members.push(v);
            }
        }
    }
    if members.is_empty() {
        return None;
    }
    Some(Value::Structure(members))
}

/// Returns the value of a data attribute: its leaf value, or a structure of
/// its children.
pub fn da_value(da: &DataAttribute) -> Value {
    if da.children.is_empty() {
        return da.value.clone().unwrap_or(Value::boolean(false));
    }
    Value::Structure(da.children.iter().map(da_value).collect())
}

/// Finds the leaf data attribute an item ID addresses, for a write.
///
/// Only leaf attributes are writable: a structured attribute is written
/// through its members, and accepting one here would silently drop the parts
/// that did not match.
pub fn resolve_write<'a>(ln: &'a mut LogicalNode, item: &str) -> Option<&'a mut DataAttribute> {
    let parts: Vec<&str> = item.split('$').collect();
    if parts.len() < 4 {
        return None;
    }
    let fc: Fc = parts[1].parse().ok()?;
    let object = ln.object_mut(parts[2])?;
    let mut rest = &parts[3..];

    // Descend sub-objects, stopping one short so the last component names an
    // attribute rather than an object.
    let mut object = object;
    while rest.len() > 1 {
        if object.child(rest[0]).is_none() {
            break;
        }
        object = object.child_mut(rest[0])?;
        rest = &rest[1..];
    }

    let mut da = object
        .attributes
        .iter_mut()
        .find(|a| a.name == rest[0] && a.fc == fc)?;
    for name in &rest[1..] {
        da = da.child_mut(name)?;
    }
    if !da.children.is_empty() {
        return None;
    }
    Some(da)
}

/// Returns the `TypeSpec` for an item ID at logical-node, constraint,
/// data-object or data-attribute level, mirroring what conformant servers
/// report for `getVariableAccessAttributes`.
pub fn type_spec_for(ln: &LogicalNode, item: &str) -> Option<TypeSpec> {
    let parts: Vec<&str> = item.split('$').collect();
    match parts.len() {
        // "LN": a structure with one member per constraint.
        1 => return Some(ln_type_spec(ln)),
        // "LN$FC": one member per data object.
        2 => {
            let fc: Fc = parts[1].parse().ok()?;
            return Some(fc_type_spec(ln, fc));
        }
        _ => {}
    }
    let fc: Fc = parts[1].parse().ok()?;
    let (object, rest) = descend_objects(ln.object(parts[2])?, &parts[3..]);
    if rest.is_empty() {
        return Some(do_type_spec(object, fc));
    }
    Some(da_type_spec(descend_attributes(object, fc, rest)?))
}

/// The logical-node type: a structure with one member per functional
/// constraint present, named by the constraint.
fn ln_type_spec(ln: &LogicalNode) -> TypeSpec {
    let mut order: Vec<Fc> = Vec::new();
    for object in &ln.objects {
        for fc in object.fcs() {
            if !order.contains(&fc) {
                order.push(fc);
            }
        }
    }
    order.sort_unstable();
    TypeSpec::structure(
        order
            .into_iter()
            .map(|fc| Component {
                name: fc.to_string(),
                spec: fc_type_spec(ln, fc),
            })
            .collect(),
    )
}

/// The functional-constraint type: a structure with one member per data object
/// that exposes that constraint.
fn fc_type_spec(ln: &LogicalNode, fc: Fc) -> TypeSpec {
    TypeSpec::structure(
        ln.objects
            .iter()
            .filter(|o| has_fc(o, fc))
            .map(|o| Component {
                name: o.name.clone(),
                spec: do_type_spec(o, fc),
            })
            .collect(),
    )
}

fn do_type_spec(object: &DataObject, fc: Fc) -> TypeSpec {
    let mut components: Vec<Component> = object
        .attributes
        .iter()
        .filter(|a| a.fc == fc)
        .map(|a| Component {
            name: a.name.clone(),
            spec: da_type_spec(a),
        })
        .collect();
    for sub in &object.objects {
        if has_fc(sub, fc) {
            components.push(Component {
                name: sub.name.clone(),
                spec: do_type_spec(sub, fc),
            });
        }
    }
    TypeSpec::structure(components)
}

fn da_type_spec(da: &DataAttribute) -> TypeSpec {
    if !da.children.is_empty() {
        return TypeSpec::structure(
            da.children
                .iter()
                .map(|c| Component {
                    name: c.name.clone(),
                    spec: da_type_spec(c),
                })
                .collect(),
        );
    }
    value_type_spec(da.value.as_ref())
}

/// Derives the declared type of a leaf from the value it holds.
///
/// The widths are the conventional ones IEC 61850 servers report; a client
/// validating a type against its own configuration compares these.
fn value_type_spec(v: Option<&Value>) -> TypeSpec {
    let Some(v) = v else {
        return TypeSpec::scalar(Type::Boolean);
    };
    match v.type_of() {
        // A negative size declares a maximum rather than a fixed width, which
        // is how a variable-length bit string is reported.
        Type::BitString => TypeSpec::sized(Type::BitString, -(v.bit_len() as i32)),
        Type::Integer => TypeSpec::sized(Type::Integer, 32),
        Type::Unsigned => TypeSpec::sized(Type::Unsigned, 32),
        Type::VisibleString => TypeSpec::sized(Type::VisibleString, 129),
        Type::OctetString => TypeSpec::sized(Type::OctetString, 64),
        other => TypeSpec::scalar(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Model;
    use crate::scl;

    /// A small model shaped like a real one: a measurand under MX, a status
    /// point under ST and a configuration attribute under CF.
    fn sample_ln() -> LogicalNode {
        let leaf = |name: &str, fc: Fc, v: Value| DataAttribute {
            name: name.into(),
            fc,
            kind: Some(v.type_of()),
            value: Some(v),
            ..Default::default()
        };
        LogicalNode {
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
                        leaf("stVal", Fc::St, Value::boolean(true)),
                        leaf("ctlModel", Fc::Cf, Value::int32(1)),
                    ],
                },
            ],
            ..Default::default()
        }
    }

    fn sample_device() -> LogicalDevice {
        LogicalDevice {
            name: "ied1LD0".into(),
            inst: "LD0".into(),
            nodes: vec![sample_ln()],
        }
    }

    #[test]
    fn the_name_list_covers_every_level_a_client_browses() {
        let names = names_for_domain(&sample_device());
        // The bare node, then each constraint, then objects and attributes.
        for want in [
            "GGIO1",
            "GGIO1$ST",
            "GGIO1$ST$SPCSO1",
            "GGIO1$ST$SPCSO1$stVal",
            "GGIO1$MX",
            "GGIO1$MX$AnIn1",
            "GGIO1$MX$AnIn1$mag",
            "GGIO1$MX$AnIn1$mag$f",
            "GGIO1$MX$AnIn1$q",
            "GGIO1$CF",
            "GGIO1$CF$SPCSO1",
            "GGIO1$CF$SPCSO1$ctlModel",
        ] {
            assert!(names.iter().any(|n| n == want), "{want} missing from {names:?}");
        }
        // An object appears only under the constraints it actually exposes.
        assert!(!names.iter().any(|n| n == "GGIO1$MX$SPCSO1"));
        assert!(!names.iter().any(|n| n == "GGIO1$ST$AnIn1"));
    }

    #[test]
    fn the_name_list_is_ordered_stably_by_constraint() {
        let names = names_for_domain(&sample_device());
        let pos = |s: &str| names.iter().position(|n| n == s).unwrap();
        // Fc's declaration order puts ST before MX before CF.
        assert!(pos("GGIO1$ST") < pos("GGIO1$MX"));
        assert!(pos("GGIO1$MX") < pos("GGIO1$CF"));
        // An object's own name precedes its attributes.
        assert!(pos("GGIO1$MX$AnIn1") < pos("GGIO1$MX$AnIn1$mag"));
        assert!(pos("GGIO1$MX$AnIn1$mag") < pos("GGIO1$MX$AnIn1$mag$f"));
        // Two runs agree.
        assert_eq!(names, names_for_domain(&sample_device()));
    }

    #[test]
    fn a_leaf_read_returns_its_value() {
        let ln = sample_ln();
        assert_eq!(
            resolve_read(&ln, "GGIO1$MX$AnIn1$mag$f").unwrap().as_f32(),
            230.4
        );
        assert!(resolve_read(&ln, "GGIO1$ST$SPCSO1$stVal")
            .unwrap()
            .as_bool());
        assert_eq!(
            resolve_read(&ln, "GGIO1$CF$SPCSO1$ctlModel")
                .unwrap()
                .as_i32(),
            1
        );
    }

    #[test]
    fn an_object_read_composes_a_structure_of_its_attributes() {
        let ln = sample_ln();
        let v = resolve_read(&ln, "GGIO1$MX$AnIn1").unwrap();
        assert_eq!(v.type_of(), Type::Structure);
        assert_eq!(v.len(), 3, "mag, q and t");
        // mag is itself a structure holding f.
        assert_eq!(v.index(0).unwrap().index(0).unwrap().as_f32(), 230.4);
    }

    #[test]
    fn a_constraint_read_composes_every_object_under_it() {
        let ln = sample_ln();
        let v = resolve_read(&ln, "GGIO1$MX").unwrap();
        assert_eq!(v.len(), 1, "only AnIn1 has MX attributes");
        let v = resolve_read(&ln, "GGIO1$ST").unwrap();
        assert_eq!(v.len(), 1, "only SPCSO1 has ST attributes");
    }

    /// The same object under a constraint it does not expose must read as
    /// nothing, not as an empty structure a client would misinterpret.
    #[test]
    fn an_object_with_nothing_under_a_constraint_reads_as_absent() {
        let ln = sample_ln();
        assert!(resolve_read(&ln, "GGIO1$MX$SPCSO1").is_none());
        assert!(resolve_read(&ln, "GGIO1$ST$AnIn1").is_none());
    }

    #[test]
    fn malformed_or_unknown_items_resolve_to_nothing() {
        let ln = sample_ln();
        assert!(resolve_read(&ln, "GGIO1").is_none(), "no constraint");
        assert!(resolve_read(&ln, "GGIO1$XX$AnIn1").is_none(), "bad constraint");
        assert!(resolve_read(&ln, "GGIO1$MX$Nope").is_none());
        assert!(resolve_read(&ln, "GGIO1$MX$AnIn1$nope").is_none());
        assert!(resolve_read(&ln, "").is_none());
    }

    #[test]
    fn a_write_lands_on_the_addressed_leaf() {
        let mut ln = sample_ln();
        let da = resolve_write(&mut ln, "GGIO1$MX$AnIn1$mag$f").expect("resolves");
        da.value = Some(Value::float32(400.0));
        assert_eq!(
            resolve_read(&ln, "GGIO1$MX$AnIn1$mag$f").unwrap().as_f32(),
            400.0
        );
    }

    /// A structured attribute has to be written through its members; accepting
    /// the parent would silently drop whatever did not match.
    #[test]
    fn a_structured_attribute_is_not_directly_writable() {
        let mut ln = sample_ln();
        assert!(resolve_write(&mut ln, "GGIO1$MX$AnIn1$mag").is_none());
        // Nor is an object or a bare constraint.
        assert!(resolve_write(&mut ln, "GGIO1$MX$AnIn1").is_none());
        assert!(resolve_write(&mut ln, "GGIO1$MX").is_none());
    }

    #[test]
    fn a_write_under_the_wrong_constraint_does_not_resolve() {
        let mut ln = sample_ln();
        assert!(resolve_write(&mut ln, "GGIO1$ST$SPCSO1$ctlModel").is_none());
        assert!(resolve_write(&mut ln, "GGIO1$CF$SPCSO1$ctlModel").is_some());
    }

    #[test]
    fn type_specs_mirror_the_structure_at_every_level() {
        let ln = sample_ln();

        // A leaf.
        let ts = type_spec_for(&ln, "GGIO1$MX$AnIn1$mag$f").unwrap();
        assert_eq!(ts.kind, Some(Type::Float32));

        // A structured attribute.
        let ts = type_spec_for(&ln, "GGIO1$MX$AnIn1$mag").unwrap();
        assert_eq!(ts.kind, Some(Type::Structure));
        assert_eq!(ts.components.len(), 1);
        assert_eq!(ts.components[0].name, "f");

        // A data object under one constraint.
        let ts = type_spec_for(&ln, "GGIO1$MX$AnIn1").unwrap();
        let names: Vec<&str> = ts.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["mag", "q", "t"]);

        // A whole constraint, and the whole node.
        let ts = type_spec_for(&ln, "GGIO1$MX").unwrap();
        assert_eq!(ts.components.len(), 1);
        let ts = type_spec_for(&ln, "GGIO1").unwrap();
        let names: Vec<&str> = ts.components.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["ST", "MX", "CF"]);
    }

    #[test]
    fn leaf_type_specs_declare_the_conventional_widths() {
        let ln = sample_ln();
        // A bit string declares its width as a maximum, hence negative.
        let ts = type_spec_for(&ln, "GGIO1$MX$AnIn1$q").unwrap();
        assert_eq!(ts.kind, Some(Type::BitString));
        assert_eq!(ts.size, -13);

        let ts = type_spec_for(&ln, "GGIO1$CF$SPCSO1$ctlModel").unwrap();
        assert_eq!(ts.kind, Some(Type::Integer));
        assert_eq!(ts.size, 32);

        let ts = type_spec_for(&ln, "GGIO1$MX$AnIn1$t").unwrap();
        assert_eq!(ts.kind, Some(Type::UtcTime));
    }

    /// The type spec of a leaf has to encode; a client cannot browse a model
    /// whose types it cannot decode.
    #[test]
    fn every_type_spec_in_the_reference_model_encodes_and_decodes() {
        let m: Model = scl::load_model(
            concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid"),
            &scl::BuildOptions::new(),
        )
        .expect("the reference CID loads");

        let mut checked = 0;
        for ld in &m.devices {
            for name in names_for_domain(ld) {
                let Some(ln) = ld.node(name.split('$').next().unwrap()) else {
                    continue;
                };
                let Some(ts) = type_spec_for(ln, &name) else {
                    continue;
                };
                let Some(el) = ts.ber() else { continue };
                let encoded = el.encode();
                let back = crate::mms::decode_type_spec(&mut crate::asn1::Decoder::new(&encoded))
                    .unwrap_or_else(|e| panic!("{name} type spec did not decode: {e}"));
                assert_eq!(back.kind, ts.kind, "{name} changed kind on the wire");
                checked += 1;
            }
        }
        assert!(checked > 100, "expected a substantial model, checked {checked}");
    }

    /// Every name the server advertises must resolve to something readable, or
    /// a client walking the list gets an access error on its own browse.
    #[test]
    fn every_advertised_name_resolves_to_a_value() {
        let m: Model = scl::load_model(
            concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid"),
            &scl::BuildOptions::new(),
        )
        .expect("the reference CID loads");

        for ld in &m.devices {
            for name in names_for_domain(ld) {
                let ln_name = name.split('$').next().unwrap();
                let Some(ln) = ld.node(ln_name) else {
                    panic!("{name} names an unknown logical node");
                };
                if !name.contains('$') {
                    continue; // the bare node name has no value of its own
                }
                assert!(
                    resolve_read(ln, &name).is_some(),
                    "{name} is advertised but does not resolve"
                );
            }
        }
    }
}
