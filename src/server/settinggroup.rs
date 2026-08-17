//! Server-side setting groups: materialises the SGCB and keeps per-group
//! copies of the `SG` and `SE` setting values, switching which copy is live as
//! the client selects groups.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::mms::Value;
use crate::model::{
    DataAttribute, DataObject, Fc, LogicalDevice, Model, ObjectReference,
};

/// The fixed MMS name of the setting group control block.
pub const SGCB_NAME: &str = "SGCB";

/// One setting, as the pair of views the standard gives it plus the stored
/// value of every group.
#[derive(Debug, Clone)]
struct Setting {
    /// The path of the `SG` (active) attribute within its logical device.
    sg: ObjectReference,
    /// The path of the `SE` (edit) attribute, when the model has one.
    se: Option<ObjectReference>,
    /// One value per setting group.
    groups: Vec<Value>,
}

/// Setting-group state for one logical device.
#[derive(Debug)]
pub struct SettingGroupManager {
    pub domain: String,
    pub num_of_sg: u8,
    state: Mutex<SgState>,
}

#[derive(Debug)]
struct SgState {
    act_sg: u8,
    edit_sg: u8,
    settings: Vec<Setting>,
}

/// Materialises an SGCB into the `LLN0` of every logical device that has
/// setting-constrained attributes.
///
/// Returns one manager per such device, keyed by domain name.
pub fn materialise_sgcbs(
    m: &mut Model,
    num_of_sg: u8,
) -> BTreeMap<String, SettingGroupManager> {
    let num_of_sg = num_of_sg.max(1);
    let mut out = BTreeMap::new();
    for ld in &mut m.devices {
        if let Some(mgr) = build_manager(ld, num_of_sg) {
            out.insert(ld.name.clone(), mgr);
        }
    }
    out
}

fn build_manager(ld: &mut LogicalDevice, num_of_sg: u8) -> Option<SettingGroupManager> {
    // Pair SG and SE attributes by their path within the device.
    let mut sg_paths: BTreeMap<String, ObjectReference> = BTreeMap::new();
    let mut se_paths: BTreeMap<String, ObjectReference> = BTreeMap::new();
    for ln in &ld.nodes {
        for object in &ln.objects {
            let base = ObjectReference::new(format!("{}/{}.{}", ld.name, ln.name, object.name));
            collect_setting_attrs(&base, object, &mut sg_paths, &mut se_paths);
        }
    }
    if sg_paths.is_empty() {
        return None;
    }

    // Snapshot each setting's configured value into every group, so a device
    // starts with its SCL values in all of them.
    let mut settings = Vec::new();
    for (key, sg) in &sg_paths {
        let current = ld
            .nodes
            .iter()
            .find_map(|_| None)
            .or_else(|| lookup_value(ld, sg, Fc::Sg))
            .unwrap_or(Value::None);
        settings.push(Setting {
            sg: sg.clone(),
            se: se_paths.get(key).cloned(),
            groups: vec![current; usize::from(num_of_sg)],
        });
    }

    let lln0 = ld.node_mut("LLN0")?;
    lln0.objects.push(build_sgcb(num_of_sg));

    Some(SettingGroupManager {
        domain: ld.name.clone(),
        num_of_sg,
        state: Mutex::new(SgState {
            act_sg: 1,
            edit_sg: 0,
            settings,
        }),
    })
}

/// Returns the current value of a setting attribute.
fn lookup_value(ld: &LogicalDevice, reference: &ObjectReference, fc: Fc) -> Option<Value> {
    let path = reference.path();
    let ln = ld.node(path.first()?)?;
    let mut object = ln.object(path.get(1)?)?;
    let mut rest = &path[2..];
    while let Some(first) = rest.first() {
        match object.child(first) {
            Some(sub) => {
                object = sub;
                rest = &rest[1..];
            }
            None => break,
        }
    }
    let first = *rest.first()?;
    let mut da = object
        .attributes
        .iter()
        .find(|a| a.name == first && a.fc == fc)?;
    for name in &rest[1..] {
        da = da.child(name)?;
    }
    da.value.clone()
}

/// Walks a data object collecting the leaf attributes served under `SG` and
/// `SE`, keyed by the path below the constraint so the two views pair up.
fn collect_setting_attrs(
    base: &ObjectReference,
    object: &DataObject,
    sg: &mut BTreeMap<String, ObjectReference>,
    se: &mut BTreeMap<String, ObjectReference>,
) {
    for a in &object.attributes {
        collect_setting_attr(&base.child(&a.name), a, sg, se);
    }
    for sub in &object.objects {
        collect_setting_attrs(&base.child(&sub.name), sub, sg, se);
    }
}

fn collect_setting_attr(
    path: &ObjectReference,
    a: &DataAttribute,
    sg: &mut BTreeMap<String, ObjectReference>,
    se: &mut BTreeMap<String, ObjectReference>,
) {
    if a.children.is_empty() {
        match a.fc {
            Fc::Sg => {
                sg.insert(path.to_string(), path.clone());
            }
            Fc::Se => {
                se.insert(path.to_string(), path.clone());
            }
            _ => {}
        }
        return;
    }
    for c in &a.children {
        collect_setting_attr(&path.child(&c.name), c, sg, se);
    }
}

fn build_sgcb(num_of_sg: u8) -> DataObject {
    let attr = |name: &str, v: Value| DataAttribute {
        name: name.to_string(),
        fc: Fc::Sp,
        kind: Some(v.type_of()),
        value: Some(v),
        ..Default::default()
    };
    DataObject {
        name: SGCB_NAME.to_string(),
        attributes: vec![
            attr("NumOfSG", Value::uint8(num_of_sg)),
            attr("ActSG", Value::uint8(1)),
            attr("EditSG", Value::uint8(0)),
            attr("CnfEdit", Value::boolean(false)),
            attr("LActTm", Value::utc_time_now()),
        ],
        ..Default::default()
    }
}

/// Reports whether an item addresses a device's SGCB, returning the attribute
/// name.
pub fn is_sgcb_write(item: &str) -> Option<&str> {
    let parts: Vec<&str> = item.split('$').collect();
    if parts.len() == 4 && parts[0] == "LLN0" && parts[1] == "SP" && parts[2] == SGCB_NAME {
        return Some(parts[3]);
    }
    None
}

impl SettingGroupManager {
    /// Handles an `ActSG`, `EditSG` or `CnfEdit` write.
    ///
    /// Called with the model write lock held, since switching groups rewrites
    /// every setting value in the device.
    pub fn on_sgcb_write(&self, model: &mut Model, attr: &str, v: &Value) {
        let mut st = self.state.lock().unwrap();
        match attr {
            "ActSG" => {
                let g = v.as_i64() as u8;
                if g < 1 || g > self.num_of_sg {
                    return;
                }
                st.act_sg = g;
                self.set_sgcb(model, "ActSG", Value::uint8(g));
                self.set_sgcb(model, "LActTm", Value::utc_time_now());
                // The chosen group's values become the ones in effect.
                let updates: Vec<(ObjectReference, Value)> = st
                    .settings
                    .iter()
                    .map(|s| (s.sg.clone(), s.groups[usize::from(g - 1)].clone()))
                    .collect();
                for (reference, value) in updates {
                    write_attr(model, &reference, Fc::Sg, value);
                }
            }
            "EditSG" => {
                let g = v.as_i64() as u8;
                st.edit_sg = g;
                self.set_sgcb(model, "EditSG", Value::uint8(g));
                if g >= 1 && g <= self.num_of_sg {
                    // The edit view shows the selected group's values.
                    let updates: Vec<(ObjectReference, Value)> = st
                        .settings
                        .iter()
                        .filter_map(|s| {
                            s.se
                                .clone()
                                .map(|se| (se, s.groups[usize::from(g - 1)].clone()))
                        })
                        .collect();
                    for (reference, value) in updates {
                        write_attr(model, &reference, Fc::Se, value);
                    }
                }
            }
            "CnfEdit" => {
                let edit = st.edit_sg;
                if !v.as_bool() || edit < 1 || edit > self.num_of_sg {
                    return;
                }
                let act = st.act_sg;
                // Commit each edited value into its group's store, and into
                // the active view when the edited group is the active one.
                let mut live: Vec<(ObjectReference, Value)> = Vec::new();
                for s in &mut st.settings {
                    let Some(se) = &s.se else { continue };
                    let Some(edited) = read_attr(model, se, Fc::Se) else {
                        continue;
                    };
                    s.groups[usize::from(edit - 1)] = edited.clone();
                    if edit == act {
                        live.push((s.sg.clone(), edited));
                    }
                }
                for (reference, value) in live {
                    write_attr(model, &reference, Fc::Sg, value);
                }
                st.edit_sg = 0;
                self.set_sgcb(model, "EditSG", Value::uint8(0));
                self.set_sgcb(model, "CnfEdit", Value::boolean(false));
            }
            _ => {}
        }
    }

    fn set_sgcb(&self, model: &mut Model, attr: &str, v: Value) {
        if let Some(a) = model
            .device_mut(&self.domain)
            .and_then(|ld| ld.node_mut("LLN0"))
            .and_then(|ln| ln.object_mut(SGCB_NAME))
            .and_then(|o| o.attribute_mut(attr))
        {
            a.value = Some(v);
        }
    }

    /// Returns the active group.
    pub fn active(&self) -> u8 {
        self.state.lock().unwrap().act_sg
    }

    /// Returns the group being edited, or zero when none is.
    pub fn editing(&self) -> u8 {
        self.state.lock().unwrap().edit_sg
    }

    /// Returns how many settings the device exposes.
    pub fn setting_count(&self) -> usize {
        self.state.lock().unwrap().settings.len()
    }
}

fn read_attr(model: &Model, reference: &ObjectReference, fc: Fc) -> Option<Value> {
    model
        .attribute(reference, fc)
        .and_then(|da| da.value.clone())
}

fn write_attr(model: &mut Model, reference: &ObjectReference, fc: Fc, v: Value) {
    if let Some(da) = model.attribute_mut(reference, fc) {
        da.value = Some(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LogicalNode, Model};

    /// A device with one protection setting exposed under both SG and SE.
    fn device_with_settings() -> Model {
        let leaf = |name: &str, fc: Fc, v: Value| DataAttribute {
            name: name.into(),
            fc,
            kind: Some(v.type_of()),
            value: Some(v),
            ..Default::default()
        };
        Model {
            name: "DEMO".into(),
            devices: vec![LogicalDevice {
                name: "DEMOPROT".into(),
                inst: "PROT".into(),
                nodes: vec![
                    LogicalNode {
                        name: "LLN0".into(),
                        ..Default::default()
                    },
                    LogicalNode {
                        name: "PTOC1".into(),
                        objects: vec![DataObject {
                            name: "OpDlTmms".into(),
                            cdc: "ING".into(),
                            attributes: vec![
                                leaf("setVal", Fc::Sg, Value::int32(1000)),
                                leaf("setVal", Fc::Se, Value::int32(1000)),
                            ],
                            ..Default::default()
                        }],
                        ..Default::default()
                    },
                ],
            }],
        }
    }

    fn setting(model: &Model, fc: Fc) -> i32 {
        model
            .attribute(&"DEMOPROT/PTOC1.OpDlTmms.setVal".into(), fc)
            .and_then(|da| da.value.as_ref())
            .map(Value::as_i32)
            .unwrap_or(-1)
    }

    #[test]
    fn a_device_with_settings_gets_an_sgcb_in_its_lln0() {
        let mut m = device_with_settings();
        let mgrs = materialise_sgcbs(&mut m, 4);
        assert_eq!(mgrs.len(), 1);
        let mgr = &mgrs["DEMOPROT"];
        assert_eq!(mgr.num_of_sg, 4);
        assert_eq!(mgr.setting_count(), 1);

        let sgcb = m
            .device("DEMOPROT")
            .unwrap()
            .node("LLN0")
            .unwrap()
            .object("SGCB")
            .expect("the SGCB is materialised");
        assert_eq!(
            sgcb.attribute("NumOfSG").unwrap().value.as_ref().unwrap().as_i64(),
            4
        );
        assert_eq!(
            sgcb.attribute("ActSG").unwrap().value.as_ref().unwrap().as_i64(),
            1
        );
        // The SGCB is served under SP, alongside ordinary set points.
        assert!(sgcb.attributes.iter().all(|a| a.fc == Fc::Sp));
    }

    #[test]
    fn a_device_with_no_settings_gets_no_sgcb() {
        let mut m = Model {
            name: "ied1".into(),
            devices: vec![LogicalDevice {
                name: "ied1LD0".into(),
                nodes: vec![LogicalNode {
                    name: "LLN0".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };
        assert!(materialise_sgcbs(&mut m, 4).is_empty());
        assert!(m
            .device("ied1LD0")
            .unwrap()
            .node("LLN0")
            .unwrap()
            .object("SGCB")
            .is_none());
    }

    /// Editing a group must not disturb the group in effect until it is
    /// confirmed, which is the whole point of the edit view.
    #[test]
    fn editing_a_group_does_not_change_the_active_values_until_confirmed() {
        let mut m = device_with_settings();
        let mgrs = materialise_sgcbs(&mut m, 4);
        let mgr = &mgrs["DEMOPROT"];

        mgr.on_sgcb_write(&mut m, "EditSG", &Value::uint8(2));
        assert_eq!(mgr.editing(), 2);

        // The client writes the edit view directly, as an SE write would.
        write_attr(
            &mut m,
            &"DEMOPROT/PTOC1.OpDlTmms.setVal".into(),
            Fc::Se,
            Value::int32(4200),
        );
        assert_eq!(setting(&m, Fc::Sg), 1000, "the active group is untouched");

        mgr.on_sgcb_write(&mut m, "CnfEdit", &Value::boolean(true));
        assert_eq!(mgr.editing(), 0, "the edit selection is released");
        assert_eq!(
            setting(&m, Fc::Sg),
            1000,
            "group 2 was edited, group 1 is still active"
        );

        // Activating the edited group brings its values into effect.
        mgr.on_sgcb_write(&mut m, "ActSG", &Value::uint8(2));
        assert_eq!(mgr.active(), 2);
        assert_eq!(setting(&m, Fc::Sg), 4200);
    }

    #[test]
    fn confirming_an_edit_of_the_active_group_takes_effect_at_once() {
        let mut m = device_with_settings();
        let mgrs = materialise_sgcbs(&mut m, 4);
        let mgr = &mgrs["DEMOPROT"];

        mgr.on_sgcb_write(&mut m, "EditSG", &Value::uint8(1));
        write_attr(
            &mut m,
            &"DEMOPROT/PTOC1.OpDlTmms.setVal".into(),
            Fc::Se,
            Value::int32(500),
        );
        mgr.on_sgcb_write(&mut m, "CnfEdit", &Value::boolean(true));
        assert_eq!(setting(&m, Fc::Sg), 500, "group 1 is the active group");
    }

    #[test]
    fn selecting_a_group_shows_its_values_in_the_edit_view() {
        let mut m = device_with_settings();
        let mgrs = materialise_sgcbs(&mut m, 4);
        let mgr = &mgrs["DEMOPROT"];

        // Put a distinct value in group 3.
        mgr.on_sgcb_write(&mut m, "EditSG", &Value::uint8(3));
        write_attr(
            &mut m,
            &"DEMOPROT/PTOC1.OpDlTmms.setVal".into(),
            Fc::Se,
            Value::int32(9999),
        );
        mgr.on_sgcb_write(&mut m, "CnfEdit", &Value::boolean(true));

        // Selecting another group shows that group's values instead.
        mgr.on_sgcb_write(&mut m, "EditSG", &Value::uint8(2));
        assert_eq!(setting(&m, Fc::Se), 1000);

        mgr.on_sgcb_write(&mut m, "EditSG", &Value::uint8(3));
        assert_eq!(setting(&m, Fc::Se), 9999);
    }

    #[test]
    fn a_group_outside_the_declared_count_is_ignored() {
        let mut m = device_with_settings();
        let mgrs = materialise_sgcbs(&mut m, 2);
        let mgr = &mgrs["DEMOPROT"];

        mgr.on_sgcb_write(&mut m, "ActSG", &Value::uint8(9));
        assert_eq!(mgr.active(), 1, "the active group is unchanged");
        mgr.on_sgcb_write(&mut m, "ActSG", &Value::uint8(0));
        assert_eq!(mgr.active(), 1);
        mgr.on_sgcb_write(&mut m, "ActSG", &Value::uint8(2));
        assert_eq!(mgr.active(), 2, "a valid group is accepted");
    }

    #[test]
    fn confirming_without_an_edit_selection_does_nothing() {
        let mut m = device_with_settings();
        let mgrs = materialise_sgcbs(&mut m, 4);
        let mgr = &mgrs["DEMOPROT"];
        mgr.on_sgcb_write(&mut m, "CnfEdit", &Value::boolean(true));
        assert_eq!(setting(&m, Fc::Sg), 1000);
        assert_eq!(mgr.editing(), 0);
    }

    #[test]
    fn sgcb_writes_are_recognised_by_their_item_id() {
        assert_eq!(is_sgcb_write("LLN0$SP$SGCB$ActSG"), Some("ActSG"));
        assert_eq!(is_sgcb_write("LLN0$SP$SGCB$CnfEdit"), Some("CnfEdit"));
        // An ordinary set point under SP is not the SGCB.
        assert!(is_sgcb_write("LLN0$SP$SomeSetpoint$setVal").is_none());
        assert!(is_sgcb_write("PTOC1$SP$SGCB$ActSG").is_none());
        assert!(is_sgcb_write("LLN0$SP$SGCB").is_none());
    }
}
