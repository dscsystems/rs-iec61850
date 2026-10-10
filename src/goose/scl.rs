//! GOOSE publishing configured from a model's control blocks.

use std::sync::Arc;
use std::time::Duration;

use crate::ethernet::{Interface, VlanTag};
use crate::model::{GseControl, GsType, LogicalDevice, LogicalNode};

use super::{Error, Publisher, PublisherConfig, Result, DEFAULT_RETRANS};

/// Bounds the schedule so a MaxTime far above MinTime cannot produce an
/// unbounded number of entries.
const MAX_RETRANS_STEPS: usize = 16;

/// Builds the retransmission schedule a GOOSE control block's MinTime and
/// MaxTime (milliseconds) ask for (IEC 61850-8-1, clause 11).
///
/// The first transmission is followed by a retransmission after MinTime, and
/// the interval then doubles until it reaches MaxTime, which it holds. A
/// device that changes state often is heard from quickly after each change and
/// then rarely, and a MaxTime of 100 ms gives a publisher that is never silent
/// for longer than 100 ms.
///
/// A block that configures neither gets [`DEFAULT_RETRANS`]. A zero MinTime or
/// MaxTime is ignored, since a zero interval would mean retransmitting as fast
/// as the link allows.
pub fn retrans_from_scl(min_time: u32, max_time: u32) -> Vec<Duration> {
    let (mut min_ms, mut max_ms) = (u64::from(min_time), u64::from(max_time));
    if min_ms == 0 && max_ms == 0 {
        return DEFAULT_RETRANS.to_vec();
    }
    if min_ms == 0 {
        // Without a minimum, the doubling starts at a value that reaches the
        // maximum in a sensible number of steps.
        min_ms = (max_ms / 64).max(1);
    }
    max_ms = max_ms.max(min_ms);
    let mut out = Vec::new();
    let mut d = min_ms;
    while d < max_ms && out.len() < MAX_RETRANS_STEPS {
        out.push(Duration::from_millis(d));
        d *= 2;
    }
    out.push(Duration::from_millis(max_ms));
    out
}

impl Publisher {
    /// Returns a publisher for one GOOSE control block of a model, taking the
    /// multicast address, APPID, VLAN, identity, configuration revision and
    /// retransmission timing from its configuration.
    ///
    /// `ld` and `ln` are the logical device and node the block belongs to
    /// (LLN0 in practice): gocbRef and datSet go on the wire as full
    /// references, `LD/LLN0$GO$gcb01` and `LD/LLN0$DataSet`, which is what a
    /// subscriber configured from the same SCL matches on. A block without a
    /// data set starts with ndsCom set, as it needs commissioning.
    pub fn from_model(
        iface: Arc<dyn Interface>,
        ld: &LogicalDevice,
        ln: &LogicalNode,
        gc: &GseControl,
        src_mac: [u8; 6],
    ) -> Result<Publisher> {
        if gc.kind == GsType::Gsse {
            return Err(Error::Config(format!(
                "control block {} is GSSE, which this crate does not publish",
                gc.name
            )));
        }
        let prefix = format!("{}/{}$", ld.name, ln.name);
        let dat_set = if gc.data_set.is_empty() {
            String::new()
        } else {
            format!("{prefix}{}", gc.data_set)
        };
        let vlan = (gc.vlan_id != 0 || gc.vlan_pri != 0).then_some(VlanTag {
            priority: gc.vlan_pri,
            dei: false,
            vid: gc.vlan_id,
        });
        Publisher::new(
            iface,
            PublisherConfig {
                dst_mac: gc.dst_mac,
                src_mac,
                app_id: gc.app_id,
                vlan,
                go_cb_ref: format!("{prefix}GO${}", gc.name),
                dat_set,
                go_id: gc.go_id.clone(),
                conf_rev: gc.conf_rev,
                retrans: retrans_from_scl(gc.min_time, gc.max_time),
                nds_com: gc.data_set.is_empty(),
                ..Default::default()
            },
        )
    }
}
