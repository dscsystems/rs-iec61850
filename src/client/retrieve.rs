//! Reconstructs a server's data model online, when no SCL file is available.

use crate::mms::{ObjectClass, Type, TypeSpec};
use crate::model::{DataAttribute, DataObject, Fc, LogicalDevice, LogicalNode, Model};

use super::{Client, Result};

impl Client {
    /// Reconstructs the server's data model by enumerating its domains and
    /// logical nodes and reading the type specification of each
    /// functionally-constrained top-level data object.
    ///
    /// The returned model is suitable for browsing; leaf values are not read
    /// here, so use [`read`](Client::read) for live values.
    pub async fn retrieve_model(&self) -> Result<Model> {
        let domains = self.logical_devices().await?;
        let mut m = Model::default();
        for domain in &domains {
            m.devices.push(self.retrieve_device(domain).await?);
        }
        if let Some(first) = m.devices.first() {
            // Best effort: the IED name is the common prefix up to the LD
            // instance, which the server does not report separately.
            m.name = first.name.clone();
        }
        Ok(m)
    }

    /// Reconstructs one logical device.
    pub async fn retrieve_device(&self, domain: &str) -> Result<LogicalDevice> {
        let names = self
            .mms()
            .get_name_list(ObjectClass::NamedVariable, domain)
            .await?;
        let mut ld = LogicalDevice {
            name: domain.to_string(),
            ..Default::default()
        };

        // Group variable names by (LN, FC, top-level DO). The type spec of
        // each LN$FC$DO is fetched once and expanded into the model tree.
        let mut seen: Vec<(String, String, String)> = Vec::new();
        let mut ln_order: Vec<String> = Vec::new();

        for name in &names {
            let parts: Vec<&str> = name.split('$').collect();
            if parts.len() < 3 {
                // A bare logical node entry, with no object below it yet.
                if parts.len() == 1 && !ln_order.iter().any(|l| l == parts[0]) {
                    ln_order.push(parts[0].to_string());
                }
                continue;
            }
            let (ln, fc_str, object) = (parts[0], parts[1], parts[2]);
            let Ok(fc) = fc_str.parse::<Fc>() else {
                continue;
            };
            if !ln_order.iter().any(|l| l == ln) {
                ln_order.push(ln.to_string());
            }
            let key = (ln.to_string(), fc_str.to_string(), object.to_string());
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);

            let item = format!("{ln}${fc_str}${object}");
            let Ok(ts) = self
                .mms()
                .get_variable_access_attributes(domain, &item)
                .await
            else {
                continue; // skip objects the server will not introspect
            };
            let ln_node = ensure_ln(&mut ld, ln);
            let do_node = ensure_do(ln_node, object);
            expand_type_spec(do_node, &ts, fc);
        }

        // Logical nodes with no readable objects still appear.
        for ln in &ln_order {
            ensure_ln(&mut ld, ln);
        }
        ld.nodes.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(ld)
    }
}

fn ensure_ln<'a>(ld: &'a mut LogicalDevice, name: &str) -> &'a mut LogicalNode {
    if let Some(i) = ld.nodes.iter().position(|n| n.name == name) {
        return &mut ld.nodes[i];
    }
    ld.nodes.push(LogicalNode {
        name: name.to_string(),
        class: ln_class(name),
        ..Default::default()
    });
    ld.nodes.last_mut().expect("just pushed")
}

fn ensure_do<'a>(ln: &'a mut LogicalNode, name: &str) -> &'a mut DataObject {
    if let Some(i) = ln.objects.iter().position(|o| o.name == name) {
        return &mut ln.objects[i];
    }
    ln.objects.push(DataObject {
        name: name.to_string(),
        ..Default::default()
    });
    ln.objects.last_mut().expect("just pushed")
}

/// Extracts the logical-node class from an instance name, best effort.
///
/// Without SCL the server reports only the instance name, so the class is
/// recovered by stripping the trailing instance number and taking the
/// four-letter core: `Q0XCBR1` yields `XCBR`, and `LLN0` is itself.
fn ln_class(name: &str) -> String {
    if name == "LLN0" {
        return "LLN0".to_string();
    }
    let core = name.trim_end_matches(|c: char| c.is_ascii_digit());
    if core.len() >= 4 {
        core[core.len() - 4..].to_string()
    } else {
        core.to_string()
    }
}

/// Grafts an MMS structure type spec onto a data object as data attributes
/// under the given functional constraint.
fn expand_type_spec(object: &mut DataObject, ts: &TypeSpec, fc: Fc) {
    if ts.kind != Some(Type::Structure) {
        // A data object whose view under this constraint is a single value:
        // represent it as one attribute named after the object.
        object.attributes.push(DataAttribute {
            name: object.name.clone(),
            fc,
            kind: ts.kind,
            value: Some(ts.default_value()),
            ..Default::default()
        });
        return;
    }
    for comp in &ts.components {
        object
            .attributes
            .push(attr_from_spec(&comp.name, &comp.spec, fc));
    }
}

fn attr_from_spec(name: &str, ts: &TypeSpec, fc: Fc) -> DataAttribute {
    let mut da = DataAttribute {
        name: name.to_string(),
        fc,
        kind: ts.kind,
        ..Default::default()
    };
    match ts.kind {
        Some(Type::Structure) => {
            for comp in &ts.components {
                da.children.push(attr_from_spec(&comp.name, &comp.spec, fc));
            }
        }
        Some(Type::Array) => {
            da.count = ts.elements;
            da.value = Some(ts.default_value());
        }
        _ => da.value = Some(ts.default_value()),
    }
    da
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::Component;

    #[test]
    fn logical_node_classes_are_recovered_from_instance_names() {
        assert_eq!(ln_class("LLN0"), "LLN0");
        assert_eq!(ln_class("GGIO1"), "GGIO");
        assert_eq!(ln_class("Q0XCBR1"), "XCBR");
        assert_eq!(ln_class("XCBR"), "XCBR");
        assert_eq!(ln_class("PTOC12"), "PTOC");
        // Too short to carry a four-letter class; kept as-is rather than
        // panicking on the slice.
        assert_eq!(ln_class("AB1"), "AB");
    }

    #[test]
    fn a_structure_spec_becomes_one_attribute_per_component() {
        // The shape a server reports for an MV under MX.
        let ts = TypeSpec::structure(vec![
            Component {
                name: "mag".into(),
                spec: TypeSpec::structure(vec![Component {
                    name: "f".into(),
                    spec: TypeSpec::scalar(Type::Float32),
                }]),
            },
            Component {
                name: "q".into(),
                spec: TypeSpec::sized(Type::BitString, 13),
            },
            Component {
                name: "t".into(),
                spec: TypeSpec::scalar(Type::UtcTime),
            },
        ]);
        let mut object = DataObject {
            name: "AnIn1".into(),
            ..Default::default()
        };
        expand_type_spec(&mut object, &ts, Fc::Mx);

        let names: Vec<&str> = object.attributes.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["mag", "q", "t"]);
        assert!(object.attributes.iter().all(|a| a.fc == Fc::Mx));
        let mag = object.attribute("mag").unwrap();
        assert_eq!(mag.children.len(), 1);
        assert_eq!(mag.children[0].name, "f");
        assert_eq!(mag.children[0].kind, Some(Type::Float32));
    }

    /// Some objects present a bare value under a constraint rather than a
    /// structure; dropping those loses the attribute entirely.
    #[test]
    fn a_scalar_spec_becomes_one_attribute_named_after_the_object() {
        let mut object = DataObject {
            name: "Beh".into(),
            ..Default::default()
        };
        expand_type_spec(&mut object, &TypeSpec::sized(Type::Integer, 32), Fc::St);
        assert_eq!(object.attributes.len(), 1);
        assert_eq!(object.attributes[0].name, "Beh");
        assert_eq!(object.attributes[0].kind, Some(Type::Integer));
        assert_eq!(object.attributes[0].fc, Fc::St);
    }

    #[test]
    fn an_array_spec_keeps_its_element_count() {
        let da = attr_from_spec(
            "arr",
            &TypeSpec::array(4, TypeSpec::scalar(Type::Boolean)),
            Fc::St,
        );
        assert_eq!(da.count, 4);
        assert_eq!(da.value.as_ref().unwrap().len(), 4);
    }

    #[test]
    fn expanding_two_constraints_onto_one_object_keeps_both() {
        // A controllable object is reported under CO, ST and CF separately,
        // and all three views belong on the same data object.
        let mut object = DataObject {
            name: "SPCSO1".into(),
            ..Default::default()
        };
        expand_type_spec(
            &mut object,
            &TypeSpec::structure(vec![Component {
                name: "stVal".into(),
                spec: TypeSpec::scalar(Type::Boolean),
            }]),
            Fc::St,
        );
        expand_type_spec(
            &mut object,
            &TypeSpec::structure(vec![Component {
                name: "ctlModel".into(),
                spec: TypeSpec::sized(Type::Integer, 8),
            }]),
            Fc::Cf,
        );
        assert_eq!(object.attributes.len(), 2);
        assert_eq!(object.fcs(), [Fc::St, Fc::Cf]);
    }
}
