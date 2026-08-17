use std::sync::Arc;
use std::time::Duration;

use crate::ethernet::{Frame, Interface, VlanTag, ETHER_TYPE_SV};

use super::{encode_le_sample, Asdu, Error, LeSample, Pdu, Result, SMP_SYNCH_GLOBAL};

/// Configures a 9-2LE publisher.
#[derive(Debug, Clone)]
pub struct LeConfig {
    pub app_id: u16,
    pub sv_id: String,
    pub conf_rev: u32,
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub vlan: Option<VlanTag>,
    /// Samples per power cycle: 80 for protection, 256 for metering in the
    /// 9-2LE profile.
    pub samples_per_cycle: u32,
    /// The power system frequency, 50 or 60.
    pub nominal_hz: u32,
}

impl Default for LeConfig {
    fn default() -> LeConfig {
        LeConfig {
            app_id: 0x4000,
            sv_id: String::new(),
            conf_rev: 1,
            dst_mac: default_mac(0),
            src_mac: [0; 6],
            vlan: None,
            samples_per_cycle: 80,
            nominal_hz: 50,
        }
    }
}

/// Returns the 9-2LE multicast destination address for a selector within the
/// reserved range `01-0C-CD-04-00-00`..`01-0C-CD-04-01-FF`.
///
/// It is a different range from GOOSE, so a switch can prioritise and prune
/// the two independently.
pub fn default_mac(sel: u16) -> [u8; 6] {
    let [hi, lo] = sel.to_be_bytes();
    [0x01, 0x0c, 0xcd, 0x04, hi & 0x01, lo]
}

/// Emits one ASDU per frame at the configured sample rate.
#[derive(Debug)]
pub struct LePublisher {
    iface: Arc<dyn Interface>,
    cfg: LeConfig,
    rate: u32,
}

impl LePublisher {
    /// Returns a 9-2LE publisher over `iface`.
    pub fn new(iface: Arc<dyn Interface>, cfg: LeConfig) -> Result<LePublisher> {
        if cfg.sv_id.is_empty() {
            return Err(Error::Config("sv_id is required".into()));
        }
        let mut cfg = cfg;
        if cfg.samples_per_cycle == 0 {
            cfg.samples_per_cycle = 80;
        }
        if cfg.nominal_hz == 0 {
            cfg.nominal_hz = 50;
        }
        let rate = cfg.samples_per_cycle * cfg.nominal_hz;
        Ok(LePublisher { iface, cfg, rate })
    }

    /// Returns the number of samples emitted per second.
    pub fn sample_rate(&self) -> u32 {
        self.rate
    }

    /// Returns the interval between samples.
    pub fn sample_interval(&self) -> Duration {
        Duration::from_nanos(1_000_000_000 / u64::from(self.rate))
    }

    /// Drives the sample clock until `cancel` resolves, calling `fill` to
    /// populate each sample.
    ///
    /// The sample count wraps once per second, which is the 9-2LE convention:
    /// a subscriber uses it to align streams within the second and takes the
    /// second itself from the refresh time.
    ///
    /// `fill` must not block: it runs on the sample clock, and a late sample
    /// is a lost sample.
    pub async fn run<F>(
        &self,
        mut fill: F,
        cancel: impl std::future::Future<Output = ()>,
    ) -> Result<()>
    where
        F: FnMut(u16, &mut LeSample),
    {
        let mut ticker = tokio::time::interval(self.sample_interval());
        // Falling behind must not produce a burst of catch-up frames: a
        // subscriber would see them arrive faster than the sample clock.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let mut smp_cnt: u16 = 0;
        let mut cancel = std::pin::pin!(cancel);
        loop {
            tokio::select! {
                _ = &mut cancel => return Ok(()),
                _ = ticker.tick() => {
                    let mut sample = LeSample {
                        smp_cnt,
                        smp_synch: SMP_SYNCH_GLOBAL,
                        ..Default::default()
                    };
                    fill(smp_cnt, &mut sample);
                    self.emit(&sample)?;

                    smp_cnt = smp_cnt.wrapping_add(1);
                    if u32::from(smp_cnt) >= self.rate {
                        smp_cnt = 0;
                    }
                }
            }
        }
    }

    /// Sends one sample immediately, outside the clock.
    pub fn emit(&self, s: &LeSample) -> Result<()> {
        let pdu = Pdu {
            app_id: self.cfg.app_id,
            asdus: vec![Asdu {
                sv_id: self.cfg.sv_id.clone(),
                smp_cnt: s.smp_cnt,
                conf_rev: self.cfg.conf_rev,
                smp_synch: s.smp_synch,
                smp_rate: self.cfg.samples_per_cycle.min(u32::from(u16::MAX)) as u16,
                sample: encode_le_sample(s),
                ..Default::default()
            }],
        };
        self.iface.write_frame(&Frame {
            dst: self.cfg.dst_mac,
            src: self.cfg.src_mac,
            ether_type: ETHER_TYPE_SV,
            vlan: self.cfg.vlan,
            payload: pdu.marshal(),
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet;

    fn config() -> LeConfig {
        LeConfig {
            app_id: 0x4000,
            sv_id: "MU01".into(),
            dst_mac: default_mac(1),
            samples_per_cycle: 80,
            nominal_hz: 50,
            ..Default::default()
        }
    }

    #[test]
    fn a_publisher_needs_a_stream_identifier() {
        let (a, _b) = ethernet::pipe();
        let cfg = LeConfig {
            sv_id: String::new(),
            ..config()
        };
        assert!(LePublisher::new(Arc::new(a), cfg).is_err());
    }

    /// 80 samples per cycle at 50 Hz is 4000 a second, the protection profile.
    #[test]
    fn the_sample_rate_is_the_product_of_the_cycle_count_and_the_frequency() {
        let (a, _b) = ethernet::pipe();
        let p = LePublisher::new(Arc::new(a), config()).unwrap();
        assert_eq!(p.sample_rate(), 4000);
        assert_eq!(p.sample_interval(), Duration::from_micros(250));

        let (a, _b) = ethernet::pipe();
        let p = LePublisher::new(
            Arc::new(a),
            LeConfig {
                samples_per_cycle: 256,
                nominal_hz: 60,
                ..config()
            },
        )
        .unwrap();
        assert_eq!(p.sample_rate(), 15360, "the metering profile at 60 Hz");
    }

    #[test]
    fn zero_rate_parameters_fall_back_to_the_protection_profile() {
        let (a, _b) = ethernet::pipe();
        let p = LePublisher::new(
            Arc::new(a),
            LeConfig {
                samples_per_cycle: 0,
                nominal_hz: 0,
                ..config()
            },
        )
        .unwrap();
        assert_eq!(p.sample_rate(), 4000);
    }

    #[test]
    fn an_emitted_sample_lands_on_the_wire_as_a_9_2le_frame() {
        let (a, b) = ethernet::pipe();
        let p = LePublisher::new(Arc::new(a), config()).unwrap();

        let s = LeSample {
            smp_cnt: 42,
            smp_synch: SMP_SYNCH_GLOBAL,
            i: [1000, -1000, 0, 0],
            v: [230_000, 0, 0, 0],
            ..Default::default()
        };
        p.emit(&s).unwrap();

        let f = b.read_frame().unwrap();
        assert_eq!(f.ether_type, ETHER_TYPE_SV);
        assert_eq!(f.dst, default_mac(1));

        let pdu = super::super::parse(&f.payload).unwrap();
        assert_eq!(pdu.app_id, 0x4000);
        assert_eq!(pdu.asdus.len(), 1);
        let a = &pdu.asdus[0];
        assert_eq!(a.sv_id, "MU01");
        assert_eq!(a.smp_cnt, 42);
        assert_eq!(a.smp_synch, SMP_SYNCH_GLOBAL);

        let back = super::super::decode_le_sample(&a.sample).unwrap();
        assert_eq!(back.i, s.i);
        assert_eq!(back.v, s.v);
    }

    /// The sample count identifies the position within the second; if it did
    /// not wrap there, a subscriber could not align streams.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_sample_count_advances_and_wraps_once_per_second() {
        let (a, b) = ethernet::pipe();
        // A slow rate keeps the test quick while still exercising the wrap.
        let p = LePublisher::new(
            Arc::new(a),
            LeConfig {
                samples_per_cycle: 4,
                nominal_hz: 1, // a rate of 4, so it wraps after four samples
                ..config()
            },
        )
        .unwrap();
        assert_eq!(p.sample_rate(), 4);

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let publisher = tokio::spawn(async move {
            p.run(
                |cnt, s| {
                    s.i[0] = i32::from(cnt);
                },
                async {
                    let _ = stop_rx.await;
                },
            )
            .await
        });

        tokio::time::sleep(Duration::from_millis(1600)).await;
        let _ = stop_tx.send(());
        let _ = publisher.await;

        let mut counts = Vec::new();
        while let Some(f) = b.try_read_frame() {
            let pdu = super::super::parse(&f.payload).unwrap();
            counts.push(pdu.asdus[0].smp_cnt);
        }
        assert!(counts.len() >= 5, "expected several samples, got {counts:?}");
        assert_eq!(&counts[..4], &[0, 1, 2, 3], "the count advances");
        assert_eq!(counts[4], 0, "and wraps after a full second: {counts:?}");
    }

    #[test]
    fn multicast_addresses_stay_inside_the_reserved_sampled_value_range() {
        assert_eq!(default_mac(0), [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x00]);
        assert_eq!(default_mac(1), [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01]);
        assert_eq!(default_mac(0x1ff), [0x01, 0x0c, 0xcd, 0x04, 0x01, 0xff]);
        // A different range from GOOSE, so the two never collide.
        assert_ne!(default_mac(1)[3], crate::goose::default_mac(1)[3]);
    }
}
