use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::ethernet::{Interface, ETHER_TYPE_SV};

use super::{decode_le_into, parse, Asdu, LeSample};

/// Selects sampled-value streams. Zero fields match everything.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub app_id: u16,
    pub sv_id: String,
}

impl Filter {
    /// Matches every sampled-value stream on the segment.
    pub fn any() -> Filter {
        Filter::default()
    }

    /// Matches one APPID.
    pub fn app_id(app_id: u16) -> Filter {
        Filter {
            app_id,
            sv_id: String::new(),
        }
    }

    fn matches(&self, app_id: u16, a: &Asdu) -> bool {
        if self.app_id != 0 && app_id != self.app_id {
            return false;
        }
        if !self.sv_id.is_empty() && a.sv_id != self.sv_id {
            return false;
        }
        true
    }
}

/// Ends a subscription. Dropping it stops delivery.
#[derive(Debug)]
pub struct Subscription {
    stopped: Arc<AtomicBool>,
    task: Option<std::thread::JoinHandle<()>>,
}

impl Subscription {
    /// Stops delivery. The reader thread exits on the next frame or when the
    /// interface closes.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    /// Stops delivery and waits for the reader thread to finish.
    pub fn join(mut self) {
        self.stop();
        if let Some(t) = self.task.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Receives sampled-value APDUs from a shared interface.
#[derive(Debug)]
pub struct Subscriber {
    iface: Arc<dyn Interface>,
}

impl Subscriber {
    pub fn new(iface: Arc<dyn Interface>) -> Subscriber {
        Subscriber { iface }
    }

    /// Delivers each matching ASDU to `callback`, with its raw dataset
    /// payload, for streams that are not 9-2LE.
    ///
    /// The callback must not block: a sampled-value stream delivers thousands
    /// of frames a second and does not wait.
    pub fn subscribe(
        &self,
        filter: Filter,
        callback: impl Fn(&Asdu) + Send + 'static,
    ) -> Subscription {
        self.run(filter, move |_, a, _| callback(a))
    }

    /// Delivers matching ASDUs decoded as 9-2LE samples.
    ///
    /// The sample passed to the callback is reused between calls, which is
    /// what makes the steady state allocation-free; copy it to retain it
    /// beyond the callback.
    pub fn subscribe_le(
        &self,
        filter: Filter,
        callback: impl Fn(&LeSample) + Send + 'static,
    ) -> Subscription {
        self.run(filter, move |_, a, sample| {
            if decode_le_into(a, sample).is_ok() {
                callback(sample);
            }
        })
    }

    fn run(
        &self,
        filter: Filter,
        mut handle: impl FnMut(u16, &Asdu, &mut LeSample) + Send + 'static,
    ) -> Subscription {
        let stopped = Arc::new(AtomicBool::new(false));
        let iface = Arc::clone(&self.iface);
        let flag = Arc::clone(&stopped);

        // A blocking thread rather than an async task: the raw socket read is
        // a blocking syscall, and parking a runtime worker on it would stall
        // every other task sharing that worker.
        let task = std::thread::spawn(move || {
            // One reused sample backs the zero-allocation decode path.
            let mut sample = LeSample::default();
            loop {
                let Ok(frame) = iface.read_frame() else {
                    return;
                };
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                if frame.ether_type != ETHER_TYPE_SV {
                    continue;
                }
                let Ok(pdu) = parse(&frame.payload) else {
                    continue;
                };
                for a in &pdu.asdus {
                    if filter.matches(pdu.app_id, a) {
                        handle(pdu.app_id, a, &mut sample);
                    }
                }
            }
        });

        Subscription {
            stopped,
            task: Some(task),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet;
    use crate::sv::{encode_le_sample, LeConfig, LePublisher, Pdu, SMP_SYNCH_GLOBAL};
    use std::sync::Mutex;
    use std::time::Duration;

    fn asdu(sv_id: &str, smp_cnt: u16) -> Asdu {
        Asdu {
            sv_id: sv_id.into(),
            smp_cnt,
            smp_synch: SMP_SYNCH_GLOBAL,
            sample: encode_le_sample(&LeSample {
                i: [i32::from(smp_cnt), 0, 0, 0],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_filter_selects_by_appid_and_stream_identifier() {
        let a = asdu("MU01", 1);
        assert!(Filter::any().matches(0x4000, &a));
        assert!(Filter::app_id(0x4000).matches(0x4000, &a));
        assert!(!Filter::app_id(0x4001).matches(0x4000, &a));

        let f = Filter {
            app_id: 0,
            sv_id: "MU01".into(),
        };
        assert!(f.matches(0x4000, &a));
        let f = Filter {
            app_id: 0,
            sv_id: "MU02".into(),
        };
        assert!(!f.matches(0x4000, &a));
    }

    #[test]
    fn a_subscriber_receives_every_asdu_in_a_multi_asdu_frame() {
        let (a, b) = ethernet::pipe();
        let seen: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let sub = Subscriber::new(Arc::new(b)).subscribe(Filter::any(), move |x| {
            sink.lock().unwrap().push(x.smp_cnt);
        });

        // Eight samples batched into one frame, as a real publisher does.
        let pdu = Pdu {
            app_id: 0x4000,
            asdus: (0..8).map(|i| asdu("MU01", i)).collect(),
        };
        a.write_frame(&ethernet::Frame {
            ether_type: ETHER_TYPE_SV,
            payload: pdu.marshal(),
            ..Default::default()
        })
        .unwrap();

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            *seen.lock().unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7],
            "every ASDU in the frame must be delivered"
        );
        sub.stop();
        let _ = a.close();
    }

    #[test]
    fn the_typed_path_decodes_the_9_2le_channels() {
        let (a, b) = ethernet::pipe();
        let seen: Arc<Mutex<Vec<(u16, i32)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let sub = Subscriber::new(Arc::new(b)).subscribe_le(Filter::app_id(0x4000), move |s| {
            sink.lock().unwrap().push((s.smp_cnt, s.i[0]));
        });

        let pdu = Pdu {
            app_id: 0x4000,
            asdus: (1..=3).map(|i| asdu("MU01", i)).collect(),
        };
        a.write_frame(&ethernet::Frame {
            ether_type: ETHER_TYPE_SV,
            payload: pdu.marshal(),
            ..Default::default()
        })
        .unwrap();

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            *seen.lock().unwrap(),
            [(1, 1), (2, 2), (3, 3)],
            "the sample count comes from the ASDU and the channel from the payload"
        );
        sub.stop();
        let _ = a.close();
    }

    #[test]
    fn a_frame_that_is_not_sampled_values_is_ignored() {
        let (a, b) = ethernet::pipe();
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&count);
        let sub = Subscriber::new(Arc::new(b)).subscribe(Filter::any(), move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        a.write_frame(&ethernet::Frame {
            ether_type: crate::ethernet::ETHER_TYPE_GOOSE,
            payload: vec![0; 32],
            ..Default::default()
        })
        .unwrap();
        // And a malformed sampled-value frame is dropped rather than fatal.
        a.write_frame(&ethernet::Frame {
            ether_type: ETHER_TYPE_SV,
            payload: vec![0xff; 32],
            ..Default::default()
        })
        .unwrap();

        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(count.load(Ordering::SeqCst), 0);
        sub.stop();
        let _ = a.close();
    }

    #[test]
    fn a_publisher_and_subscriber_agree_end_to_end() {
        let (a, b) = ethernet::pipe();
        let p = LePublisher::new(
            Arc::new(a),
            LeConfig {
                app_id: 0x4000,
                sv_id: "MU01".into(),
                ..Default::default()
            },
        )
        .unwrap();

        let seen: Arc<Mutex<Vec<[i32; 4]>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let sub = Subscriber::new(Arc::new(b)).subscribe_le(
            Filter {
                app_id: 0x4000,
                sv_id: "MU01".into(),
            },
            move |s| {
                sink.lock().unwrap().push(s.i);
            },
        );

        for n in 0..4i32 {
            p.emit(&LeSample {
                smp_cnt: n as u16,
                i: [n * 100, -n * 100, n, 0],
                v: [230_000, 0, 0, 0],
                ..Default::default()
            })
            .unwrap();
        }

        std::thread::sleep(Duration::from_millis(150));
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 4, "got {got:?}");
        assert_eq!(got[2], [200, -200, 2, 0]);
        sub.stop();
    }
}
