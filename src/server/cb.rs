//! The GOOSE, sampled-value and log control blocks of IEC 61850-8-1, as MMS
//! objects.
//!
//! They are objects like the report and setting-group ones: a client browsing
//! the server expects to find them, and the SCL loader already carries their
//! configuration. Each block has the components IEC 61850-8-1 gives its MMS
//! structure, in the standard's order and under the standard's names, since a
//! client addresses them by name (`gcb01$GoEna`). Nothing is added that the
//! structure does not define.
//!
//! The GOOSE blocks are read-only: this crate has no server-side GOOSE
//! publisher, so their enable flags read false and writing them is refused.
//! The SV blocks take `SvEna` and, for a USVCB, `Resv` (see [`super::svcb`]);
//! the application publishes. An LCB is live: it writes the server's logs
//! ([`super::journal`]), and a client sets `LogEna`, `DatSet`, `TrgOps` and
//! `IntgPd`.

use std::time::SystemTime;

use crate::mms::Value;
use crate::model::{
    DataAttribute, DataObject, Fc, GsType, GseControl, LogControl, LogicalDevice, Model, SvControl,
    TrgOps,
};

/// Adds the GOOSE, sampled-value and log control blocks of each logical node
/// to it as browsable data objects, under the functional constraints
/// IEC 61850-8-1 assigns them: GO and GS for the GOOSE variants, MS and US for
/// multicast and unicast sampled values, and LG for logs.
pub(crate) fn materialise_control_blocks(m: &mut Model) {
    for ld in &mut m.devices {
        let (ld_name, ld_inst) = (ld.name.clone(), ld.inst.clone());
        for ln in &mut ld.nodes {
            let ln_name = ln.name.clone();
            let mut objects = Vec::new();
            for gc in &ln.gse_controls {
                objects.push(build_gocb_object(&ld_name, &ln_name, gc));
            }
            for sc in &ln.sv_controls {
                objects.push(build_svcb_object(&ld_name, &ln_name, sc));
            }
            for lc in &ln.log_controls {
                objects.push(build_lcb_object(&ld_name, &ld_inst, &ln_name, lc));
            }
            ln.objects.extend(objects);
        }
    }
}

/// Builds a read-only control-block attribute.
fn cb_attr(fc: Fc, name: &str, v: Value) -> DataAttribute {
    DataAttribute {
        name: name.to_string(),
        fc,
        kind: Some(v.type_of()),
        value: Some(v),
        ..Default::default()
    }
}

/// The DatSet a control block serves: the object reference of a dataset in
/// the block's own logical node, as the report control blocks carry it, or
/// empty when the block names none.
fn cb_data_set_ref(ld: &str, ln: &str, name: &str) -> String {
    if name.is_empty() {
        String::new()
    } else {
        format!("{ld}/{ln}${name}")
    }
}

/// The `DstAddress` structure of IEC 61850-8-1, the PHYCOMADDR of a GOOSE or
/// sampled-value block.
fn dst_address(fc: Fc, mac: [u8; 6], pri: u8, vid: u16, app_id: u16) -> DataAttribute {
    DataAttribute {
        name: "DstAddress".into(),
        fc,
        kind: Some(crate::mms::Type::Structure),
        children: vec![
            cb_attr(fc, "Addr", Value::octet_string(mac.to_vec())),
            cb_attr(fc, "PRIORITY", Value::uint8(pri)),
            cb_attr(fc, "VID", Value::uint16(vid)),
            cb_attr(fc, "APPID", Value::uint16(app_id)),
        ],
        ..Default::default()
    }
}

/// Materialises a GoCB (FC GO) or a GsCB (FC GS).
fn build_gocb_object(ld: &str, ln: &str, gc: &GseControl) -> DataObject {
    if gc.kind == GsType::Gsse {
        // GSSE was withdrawn in Edition 2 and this crate does not implement
        // it, so only the enable flag and the identity are served.
        let fc = Fc::Gs;
        return DataObject {
            name: gc.name.clone(),
            cdc: "GSCB".into(),
            attributes: vec![
                cb_attr(fc, "GsEna", Value::boolean(false)),
                cb_attr(fc, "GsID", Value::visible_string(&gc.go_id)),
            ],
            ..Default::default()
        };
    }
    let fc = Fc::Go;
    DataObject {
        name: gc.name.clone(),
        cdc: "GOCB".into(),
        attributes: vec![
            cb_attr(fc, "GoEna", Value::boolean(false)),
            cb_attr(fc, "GoID", Value::visible_string(&gc.go_id)),
            cb_attr(fc, "DatSet", Value::visible_string(cb_data_set_ref(ld, ln, &gc.data_set))),
            cb_attr(fc, "ConfRev", Value::uint32(gc.conf_rev)),
            cb_attr(fc, "NdsCom", Value::boolean(false)),
            dst_address(fc, gc.dst_mac, gc.vlan_pri, gc.vlan_id, gc.app_id),
            cb_attr(fc, "MinTime", Value::uint32(gc.min_time)),
            cb_attr(fc, "MaxTime", Value::uint32(gc.max_time)),
            cb_attr(fc, "FixedOffs", Value::boolean(gc.fixed_offs)),
        ],
        ..Default::default()
    }
}

/// Reports whether a sampled-value block is unicast: not multicast, or sent
/// over the routable R-SV profile.
pub(crate) fn is_unicast(sc: &SvControl) -> bool {
    !sc.multicast || sc.protocol == "R-SV"
}

/// Materialises an MSVCB (FC MS) or a USVCB (FC US). `OptFlds` selects which
/// optional ASDU fields the block carries, so their presence follows the
/// configuration.
fn build_svcb_object(ld: &str, ln: &str, sc: &SvControl) -> DataObject {
    let unicast = is_unicast(sc);
    let (fc, cdc, id_name) = if unicast {
        (Fc::Us, "USVCB", "UsvID")
    } else {
        (Fc::Ms, "MSVCB", "MsvID")
    };
    let mut attributes = vec![cb_attr(fc, "SvEna", Value::boolean(false))];
    if unicast {
        // A unicast block is reserved by the client it sends to.
        attributes.push(cb_attr(fc, "Resv", Value::boolean(false)));
    }
    // OptFlds is the SmvOpts bit string: one bit per optional ASDU field, in
    // the order the standard lists them.
    let o = sc.opts;
    let mut opt_flds = Value::bit_string(10);
    for (i, on) in [
        o.refresh_time,
        o.sample_synchronized,
        o.sample_rate,
        o.data_set,
        o.security,
        o.timestamp,
        o.synch_source_id,
    ]
    .into_iter()
    .enumerate()
    {
        opt_flds.set_bit(i, on);
    }
    attributes.extend([
        cb_attr(fc, id_name, Value::visible_string(&sc.sv_id)),
        cb_attr(fc, "DatSet", Value::visible_string(cb_data_set_ref(ld, ln, &sc.data_set))),
        cb_attr(fc, "ConfRev", Value::uint32(sc.conf_rev)),
        cb_attr(fc, "SmpRate", Value::uint16(sc.smp_rate as u16)),
        cb_attr(fc, "OptFlds", opt_flds),
        // SmpMod is an ENUMERATED, which MMS carries as an integer.
        cb_attr(fc, "SmpMod", Value::int8(sc.smp_mod.code() as i8)),
        dst_address(fc, sc.dst_mac, sc.vlan_pri, sc.vlan_id, sc.app_id),
        cb_attr(fc, "noASDU", Value::uint16(sc.no_asdu as u16)),
    ]);
    DataObject {
        name: sc.name.clone(),
        cdc: cdc.into(),
        attributes,
        ..Default::default()
    }
}

/// Materialises an LCB (FC LG).
///
/// While the log holds nothing the entry range reads as empty: the epoch for
/// the times and the all-zero EntryID, which is what an empty buffered report
/// control block reports too. The log manager keeps the range current as
/// entries arrive.
fn build_lcb_object(ld: &str, ld_inst: &str, ln: &str, lc: &LogControl) -> DataObject {
    let fc = Fc::Lg;
    let mut trg_ops = lc.trg_ops;
    if trg_ops == TrgOps::default() {
        trg_ops = TrgOps::DATA_CHANGE | TrgOps::GI;
    }
    let log_ref = log_target(ld, ld_inst, lc)
        .map(|(domain, name)| format!("{domain}/{name}"))
        .unwrap_or_default();
    DataObject {
        name: lc.name.clone(),
        cdc: "LCB".into(),
        attributes: vec![
            cb_attr(fc, "LogEna", Value::boolean(lc.log_ena)),
            cb_attr(fc, "LogRef", Value::visible_string(log_ref)),
            cb_attr(fc, "DatSet", Value::visible_string(cb_data_set_ref(ld, ln, &lc.data_set))),
            cb_attr(fc, "OldEntrTm", Value::binary_time(binary_time_epoch())),
            cb_attr(fc, "NewEntrTm", Value::binary_time(binary_time_epoch())),
            cb_attr(fc, "OldEnt", Value::octet_string(vec![0; 8])),
            cb_attr(fc, "NewEnt", Value::octet_string(vec![0; 8])),
            cb_attr(fc, "TrgOps", trg_ops.value()),
            cb_attr(fc, "IntgPd", Value::uint32(lc.intg_pd)),
        ],
        ..Default::default()
    }
}

/// The domain and journal name of the log an LCB writes to: its log name in
/// the logical node the SCL places it in, `LLN0` of the block's own device by
/// default (IEC 61850-6). `None` when the block names no log.
pub(crate) fn log_target(ld_name: &str, ld_inst: &str, lc: &LogControl) -> Option<(String, String)> {
    if lc.log_name.is_empty() {
        return None;
    }
    let mut domain = ld_name.to_string();
    if !lc.log_ld_inst.is_empty() {
        // The logical device name is the IED name followed by the instance,
        // so another instance of the same IED swaps the suffix.
        domain = format!(
            "{}{}",
            ld_name.strip_suffix(ld_inst).unwrap_or(ld_name),
            lc.log_ld_inst
        );
    }
    let ln = if lc.log_ln.is_empty() { "LLN0" } else { &lc.log_ln };
    Some((domain, format!("{ln}${}", lc.log_name)))
}

/// 1984-01-01, the zero of `BinaryTime`.
pub(crate) fn binary_time_epoch() -> SystemTime {
    crate::time_util::from_unix(crate::time_util::BINARY_TIME_EPOCH_DAYS * 86_400, 0)
}

/// Finds the materialised control block `name` of `ln` under the functional
/// constraint `fc`.
pub(crate) fn cb_object<'a>(
    ld: &'a LogicalDevice,
    ln: &str,
    fc: &str,
    name: &str,
) -> Option<&'a DataObject> {
    ld.node(ln)?.objects.iter().find(|o| {
        o.name == name && o.attributes.first().is_some_and(|a| a.fc.as_str() == fc)
    })
}
