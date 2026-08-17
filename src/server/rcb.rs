//! Materialises report control blocks into the model, so they read and write
//! through the ordinary variable path, and holds their runtime state.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::asn1::Element;
use crate::mms::Value;
use crate::model::{
    DataAttribute, DataObject, Fc, LogicalNode, Model, OptFlds, ReportControl, TrgOps,
};

use super::ConnId;

/// The buffer depth of a control block that configures none, and of a server
/// that sets no default.
pub const DEFAULT_BUFFERED_REPORTS: usize = 256;

/// One buffered report retained for delivery and resync.
#[derive(Debug, Clone)]
pub struct BufEntry {
    /// The 8-octet EntryID.
    pub id: Vec<u8>,
    /// The pre-built informationReport element.
    pub element: Element,
}

/// The mutable runtime state of one report control block.
#[derive(Debug, Default)]
pub struct RcbRuntime {
    pub enabled: bool,
    pub conn: Option<ConnId>,
    pub seq_num: u32,
    /// Cancels the integrity-period task, when one is running.
    pub integrity: Option<tokio::task::AbortHandle>,

    // Buffered-report state, for a BRCB only.
    /// Pending buffered reports, oldest first.
    pub buffer: Vec<BufEntry>,
    /// A monotonic EntryID source.
    pub entry_counter: u64,
    /// A client-requested resync point, from an EntryID write.
    pub resync_id: Option<Vec<u8>>,
    /// Set when the buffer discarded unsent entries.
    pub buf_overflow: bool,
}

/// A report control block: its identity in the model plus its runtime state.
#[derive(Debug)]
pub struct RcbState {
    pub domain: String,
    /// `LN$RP$name` or `LN$BR$name`.
    pub item: String,
    pub ln_name: String,
    /// The name of the materialised data object holding the block's
    /// attributes.
    pub object_name: String,
    pub buffered: bool,
    pub data_set: String,
    /// How many reports the buffer retains, for a BRCB.
    pub max_buffer: usize,
    pub state: Mutex<RcbRuntime>,
}

impl RcbState {
    /// The registry key: the domain and item together, which are unique across
    /// the model.
    pub fn key(domain: &str, item: &str) -> String {
        format!("{domain}\u{0}{item}")
    }
}

/// Resolves how many reports one control block retains: its own configured
/// size, else the server's default, else the crate's.
pub fn buffer_depth(rc: &ReportControl, server_default: usize) -> usize {
    if rc.max_queue_size > 0 {
        rc.max_queue_size
    } else if server_default > 0 {
        server_default
    } else {
        DEFAULT_BUFFERED_REPORTS
    }
}

/// Expands each logical node's report control blocks into browsable and
/// writable data objects (under `RP` for unbuffered, `BR` for buffered)
/// carrying the standard control-block attributes, and returns the runtime
/// registry.
///
/// `buf_default` is the buffer depth for buffered blocks that do not set their
/// own.
pub fn materialise_rcbs(m: &mut Model, buf_default: usize) -> HashMap<String, RcbState> {
    let mut registry = HashMap::new();
    for ld in &mut m.devices {
        let ld_name = ld.name.clone();
        for ln in &mut ld.nodes {
            let ln_name = ln.name.clone();
            let controls = ln.report_controls.clone();
            for rc in &controls {
                let fc = if rc.buffered { Fc::Br } else { Fc::Rp };
                // Report controls are indexed by default (IEC 61850-6):
                // RptEnabled max="N" yields instances Name01..NameNN.
                let n = rc.rpt_enabled.max(1);
                for i in 1..=n {
                    let inst_name = format!("{}{:02}", rc.name, i);
                    let object = build_rcb_object(&ld_name, &ln_name, rc, fc, &inst_name);
                    ln.objects.push(object);
                    let item = format!("{ln_name}${fc}${inst_name}");
                    registry.insert(
                        RcbState::key(&ld_name, &item),
                        RcbState {
                            domain: ld_name.clone(),
                            item,
                            ln_name: ln_name.clone(),
                            object_name: inst_name,
                            buffered: rc.buffered,
                            data_set: rc.data_set.clone(),
                            max_buffer: buffer_depth(rc, buf_default),
                            state: Mutex::new(RcbRuntime::default()),
                        },
                    );
                }
            }
        }
    }
    registry
}

/// Materialises the standard URCB or BRCB attributes as a data object named
/// after the control block instance.
fn build_rcb_object(
    ld_name: &str,
    ln_name: &str,
    rc: &ReportControl,
    fc: Fc,
    inst_name: &str,
) -> DataObject {
    let ds_ref = if rc.data_set.is_empty() {
        String::new()
    } else {
        format!("{ld_name}/{ln_name}${}", rc.data_set)
    };
    let mut opt_flds = rc.opt_flds;
    if opt_flds == OptFlds::default() {
        opt_flds = OptFlds::DEFAULT;
    }
    let mut trg_ops = rc.trg_ops;
    if trg_ops == TrgOps::default() {
        trg_ops = TrgOps::DATA_CHANGE | TrgOps::QUALITY_CHANGE | TrgOps::GI;
    }

    let attr = |name: &str, v: Value| DataAttribute {
        name: name.to_string(),
        fc,
        kind: Some(v.type_of()),
        value: Some(v),
        ..Default::default()
    };
    let rpt_id = rcb_rpt_id(rc, ld_name, ln_name);

    let attributes = if rc.buffered {
        // Buffered reports carry an EntryID and a TimeofEntry, so those option
        // bits are always set whatever the configuration says.
        opt_flds |= OptFlds::ENTRY_ID | OptFlds::TIME_OF_ENTRY | OptFlds::BUF_OVFL;
        vec![
            attr("RptID", Value::visible_string(&rpt_id)),
            attr("RptEna", Value::boolean(false)),
            attr("DatSet", Value::visible_string(&ds_ref)),
            attr("ConfRev", Value::uint32(rc.conf_rev)),
            attr("OptFlds", opt_flds.value()),
            attr("BufTm", Value::uint32(rc.buf_time)),
            attr("SqNum", Value::uint16(0)),
            attr("TrgOps", trg_ops.value()),
            attr("IntgPd", Value::uint32(rc.intg_pd)),
            attr("GI", Value::boolean(false)),
            attr("PurgeBuf", Value::boolean(false)),
            attr("EntryID", Value::octet_string(vec![0u8; 8])),
            attr("TimeofEntry", Value::binary_time(SystemTime::UNIX_EPOCH)),
            attr("ResvTms", Value::int16(0)),
        ]
    } else {
        vec![
            attr("RptID", Value::visible_string(&rpt_id)),
            attr("RptEna", Value::boolean(false)),
            attr("Resv", Value::boolean(false)),
            attr("DatSet", Value::visible_string(&ds_ref)),
            attr("ConfRev", Value::uint32(rc.conf_rev)),
            attr("OptFlds", opt_flds.value()),
            attr("BufTm", Value::uint32(rc.buf_time)),
            attr("SqNum", Value::uint8(0)),
            attr("TrgOps", trg_ops.value()),
            attr("IntgPd", Value::uint32(rc.intg_pd)),
            attr("GI", Value::boolean(false)),
        ]
    };

    DataObject {
        name: inst_name.to_string(),
        attributes,
        ..Default::default()
    }
}

fn rcb_rpt_id(rc: &ReportControl, ld_name: &str, ln_name: &str) -> String {
    if !rc.rpt_id.is_empty() {
        return rc.rpt_id.clone();
    }
    let tag = if rc.buffered { "BR" } else { "RP" };
    format!("{ld_name}/{ln_name}${tag}${}", rc.name)
}

/// Reports whether an item ID addresses a report control block, returning the
/// registry key and the attribute name.
///
/// The item is `LN$FC$name[$attr]`, and only `RP` and `BR` carry control
/// blocks.
pub fn rcb_key(domain: &str, item: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = item.split('$').collect();
    if parts.len() < 3 || (parts[1] != "RP" && parts[1] != "BR") {
        return None;
    }
    let base = format!("{}${}${}", parts[0], parts[1], parts[2]);
    let attr = parts.get(3).copied().unwrap_or("").to_string();
    Some((RcbState::key(domain, &base), attr))
}

/// Encodes a monotonic counter as an 8-octet EntryID.
pub fn make_entry_id(n: u64) -> Vec<u8> {
    n.to_be_bytes().to_vec()
}

/// Looks up a materialised control-block attribute's current value.
pub fn rcb_attr_value(ln: &LogicalNode, object_name: &str, attr: &str) -> Value {
    ln.object(object_name)
        .and_then(|o| o.attribute(attr))
        .and_then(|a| a.value.clone())
        .unwrap_or(Value::boolean(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::LogicalDevice;
    use crate::scl;

    fn model_with_rcbs() -> (Model, HashMap<String, RcbState>) {
        let mut m = scl::load_model(
            concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/simpleIO_direct_control.cid"),
            &scl::BuildOptions::new(),
        )
        .expect("the reference CID loads");
        let registry = materialise_rcbs(&mut m, 0);
        (m, registry)
    }

    #[test]
    fn the_reference_model_materialises_its_control_blocks() {
        let (m, registry) = model_with_rcbs();
        assert!(
            !registry.is_empty(),
            "the reference CID configures report control blocks"
        );
        // Every registered block exists in the model as a data object under
        // its own constraint, or a client could not read it.
        for rs in registry.values() {
            let ld = m.device(&rs.domain).expect("device exists");
            let ln = ld.node(&rs.ln_name).expect("node exists");
            let object = ln
                .object(&rs.object_name)
                .unwrap_or_else(|| panic!("{} was not materialised", rs.item));
            let fc = if rs.buffered { Fc::Br } else { Fc::Rp };
            assert!(object.attributes.iter().all(|a| a.fc == fc));
            assert!(object.attribute("RptID").is_some());
            assert!(object.attribute("RptEna").is_some());
            assert!(object.attribute("DatSet").is_some());
        }
    }

    /// Indexed instances are what IEC 61850-6 specifies for RptEnabled max;
    /// a client configured for urcb02 finds nothing without them.
    #[test]
    fn rpt_enabled_max_yields_indexed_instances() {
        let mut m = Model {
            name: "ied1".into(),
            devices: vec![LogicalDevice {
                name: "ied1LD0".into(),
                inst: "LD0".into(),
                nodes: vec![LogicalNode {
                    name: "LLN0".into(),
                    report_controls: vec![ReportControl {
                        name: "urcb".into(),
                        data_set: "Events".into(),
                        rpt_enabled: 3,
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            }],
        };
        let registry = materialise_rcbs(&mut m, 0);
        assert_eq!(registry.len(), 3);
        let ln = m.device("ied1LD0").unwrap().node("LLN0").unwrap();
        for name in ["urcb01", "urcb02", "urcb03"] {
            assert!(ln.object(name).is_some(), "{name} missing");
        }
        assert!(registry.contains_key(&RcbState::key("ied1LD0", "LLN0$RP$urcb01")));
        assert!(registry.contains_key(&RcbState::key("ied1LD0", "LLN0$RP$urcb03")));
    }

    /// A buffered block carries EntryID, TimeofEntry and PurgeBuf, which an
    /// unbuffered one has no use for.
    #[test]
    fn buffered_and_unbuffered_blocks_carry_different_attributes() {
        let mut m = Model {
            name: "ied1".into(),
            devices: vec![LogicalDevice {
                name: "ied1LD0".into(),
                inst: "LD0".into(),
                nodes: vec![LogicalNode {
                    name: "LLN0".into(),
                    report_controls: vec![
                        ReportControl {
                            name: "urcb".into(),
                            buffered: false,
                            ..Default::default()
                        },
                        ReportControl {
                            name: "brcb".into(),
                            buffered: true,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }],
            }],
        };
        materialise_rcbs(&mut m, 0);
        let ln = m.device("ied1LD0").unwrap().node("LLN0").unwrap();

        let urcb = ln.object("urcb01").unwrap();
        assert!(urcb.attribute("Resv").is_some(), "URCBs reserve with Resv");
        assert!(urcb.attribute("EntryID").is_none());
        assert!(urcb.attribute("PurgeBuf").is_none());
        assert_eq!(urcb.attributes[0].fc, Fc::Rp);

        let brcb = ln.object("brcb01").unwrap();
        assert!(brcb.attribute("EntryID").is_some());
        assert!(brcb.attribute("TimeofEntry").is_some());
        assert!(brcb.attribute("PurgeBuf").is_some());
        assert!(brcb.attribute("ResvTms").is_some());
        assert_eq!(brcb.attributes[0].fc, Fc::Br);

        // A buffered report always carries its EntryID, whatever was
        // configured, so the option bits must say so.
        let opt = OptFlds::from_value(brcb.attribute("OptFlds").unwrap().value.as_ref().unwrap());
        assert!(opt.has(OptFlds::ENTRY_ID));
        assert!(opt.has(OptFlds::TIME_OF_ENTRY));
        assert!(opt.has(OptFlds::BUF_OVFL));
    }

    #[test]
    fn a_block_without_a_report_id_gets_the_standard_one() {
        let rc = ReportControl {
            name: "urcb".into(),
            ..Default::default()
        };
        assert_eq!(rcb_rpt_id(&rc, "ied1LD0", "LLN0"), "ied1LD0/LLN0$RP$urcb");

        let rc = ReportControl {
            name: "brcb".into(),
            buffered: true,
            ..Default::default()
        };
        assert_eq!(rcb_rpt_id(&rc, "ied1LD0", "LLN0"), "ied1LD0/LLN0$BR$brcb");

        // A configured one wins.
        let rc = ReportControl {
            name: "urcb".into(),
            rpt_id: "custom".into(),
            ..Default::default()
        };
        assert_eq!(rcb_rpt_id(&rc, "ied1LD0", "LLN0"), "custom");
    }

    #[test]
    fn control_block_items_are_recognised_by_their_constraint() {
        let (key, attr) = rcb_key("LD", "LLN0$RP$urcb01$RptEna").unwrap();
        assert_eq!(key, RcbState::key("LD", "LLN0$RP$urcb01"));
        assert_eq!(attr, "RptEna");

        // The block itself, with no attribute.
        let (key, attr) = rcb_key("LD", "LLN0$BR$brcb01").unwrap();
        assert_eq!(key, RcbState::key("LD", "LLN0$BR$brcb01"));
        assert_eq!(attr, "");

        // Ordinary data is not a control block.
        assert!(rcb_key("LD", "GGIO1$ST$Ind1$stVal").is_none());
        assert!(rcb_key("LD", "LLN0$GO$gcb01").is_none());
        assert!(rcb_key("LD", "LLN0").is_none());
    }

    #[test]
    fn the_buffer_depth_prefers_the_block_then_the_server_then_the_default() {
        let own = ReportControl {
            max_queue_size: 64,
            ..Default::default()
        };
        assert_eq!(buffer_depth(&own, 512), 64, "the block's own size wins");

        let none = ReportControl::default();
        assert_eq!(buffer_depth(&none, 512), 512, "then the server's default");
        assert_eq!(
            buffer_depth(&none, 0),
            DEFAULT_BUFFERED_REPORTS,
            "then the crate's"
        );
    }

    #[test]
    fn entry_ids_are_eight_octets_and_order_monotonically() {
        assert_eq!(make_entry_id(1).len(), 8);
        assert_eq!(make_entry_id(1), [0, 0, 0, 0, 0, 0, 0, 1]);
        // Big-endian, so byte order is value order: a client comparing them
        // as octet strings sees the same sequence the server counted.
        assert!(make_entry_id(1) < make_entry_id(2));
        assert!(make_entry_id(255) < make_entry_id(256));
        assert_eq!(make_entry_id(u64::MAX), [0xff; 8]);
    }
}
