//! Sampled-value publishing configured from a model's control blocks.

use std::sync::Arc;

use crate::ethernet::{Interface, VlanTag};
use crate::model::{LogicalDevice, LogicalNode, SmpMod, SvControl};

use super::{AsduOpts, Error, LeConfig, LePublisher, Result};

impl LePublisher {
    /// Returns a 9-2LE publisher for one sampled-value control block of a
    /// model, taking the multicast address, APPID, VLAN, svID, configuration
    /// revision, sample rate and ASDUs per frame from its configuration.
    ///
    /// The optional ASDU fields follow the block's SmvOpts: sampleRate emits
    /// smpRate `[6]`, and with it smpMod `[8]`, since a rate is only readable
    /// together with its unit; refreshTime emits refrTm `[4]`, dataSet the
    /// datSet `[1]` reference, and synchSourceId gmIdentity `[9]`, whose value
    /// the caller supplies with [`set_gm_identity`](LePublisher::set_gm_identity).
    ///
    /// `ld` and `ln` are the logical device and node the block belongs to;
    /// datSet goes on the wire as a full reference, `LD/LLN0$PhsMeas1`.
    /// `nominal_hz` is the power system frequency, needed to turn a per-second
    /// rate into samples per cycle; zero means 50.
    ///
    /// A unicast block (a USVCB) is published to its DstAddress like a
    /// multicast one, so that address must be an individual MAC, unless the
    /// block is R-SV. Publish it while the server reports it enabled
    /// ([`Server::on_sv_control`](crate::server::Server::on_sv_control)).
    ///
    /// A block this publisher cannot honour is refused rather than published
    /// differently from its configuration: SmvOpts security (the frames would
    /// go out unsigned), the SecPerSmp mode, and a per-second rate that is not
    /// a whole number of samples per cycle. SmvOpts timestamp is not
    /// implemented and is ignored.
    pub fn from_model(
        iface: Arc<dyn Interface>,
        ld: &LogicalDevice,
        ln: &LogicalNode,
        sc: &SvControl,
        src_mac: [u8; 6],
        nominal_hz: u32,
    ) -> Result<LePublisher> {
        if !sc.multicast && sc.protocol != "R-SV" && sc.dst_mac[0] & 1 != 0 {
            return Err(Error::Config(format!(
                "control block {} is unicast, but its destination {:02x?} is a group address",
                sc.name, sc.dst_mac
            )));
        }
        if sc.opts.security {
            return Err(Error::Config(format!(
                "control block {} asks for SmvOpts security, and IEC 62351-6 signing is not implemented",
                sc.name
            )));
        }
        let nominal_hz = if nominal_hz == 0 { 50 } else { nominal_hz };
        let (smp_mod, samples_per_cycle) = match sc.smp_mod {
            SmpMod::SmpPerPeriod => (SmpMod::SmpPerPeriod, sc.smp_rate),
            SmpMod::SmpPerSec => {
                if sc.smp_rate == 0 || sc.smp_rate % nominal_hz != 0 {
                    return Err(Error::Config(format!(
                        "control block {}: {} samples per second is not a whole number of samples per {nominal_hz} Hz cycle",
                        sc.name, sc.smp_rate
                    )));
                }
                (SmpMod::SmpPerSec, sc.smp_rate / nominal_hz)
            }
            SmpMod::SecPerSmp => {
                return Err(Error::Config(format!(
                    "control block {}: sample mode {} is not supported",
                    sc.name, sc.smp_mod
                )))
            }
        };
        let vlan = (sc.vlan_id != 0 || sc.vlan_pri != 0).then_some(VlanTag {
            priority: sc.vlan_pri,
            dei: false,
            vid: sc.vlan_id,
        });
        let dat_set = if sc.data_set.is_empty() {
            String::new()
        } else {
            format!("{}/{}${}", ld.name, ln.name, sc.data_set)
        };
        LePublisher::new(
            iface,
            LeConfig {
                app_id: sc.app_id,
                sv_id: sc.sv_id.clone(),
                conf_rev: sc.conf_rev,
                dst_mac: sc.dst_mac,
                src_mac,
                vlan,
                samples_per_cycle,
                nominal_hz,
                no_asdu: sc.no_asdu,
                smp_mod,
                dat_set,
                opts: AsduOpts {
                    sample_rate: sc.opts.sample_rate,
                    smp_mod: sc.opts.sample_rate,
                    refresh_time: sc.opts.refresh_time,
                    data_set: sc.opts.data_set,
                    synch_source_id: sc.opts.synch_source_id,
                },
                ..Default::default()
            },
        )
    }
}
