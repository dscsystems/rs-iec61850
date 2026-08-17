use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::ethernet::{Frame, Interface, VlanTag, ETHER_TYPE_GOOSE};
use crate::mms::Value;

use super::{Error, Message, Result};

/// The default retransmission schedule: exponential back-off from 4 ms,
/// stable at 1 s.
///
/// A state change is repeated quickly so a lost frame is covered within a
/// protection cycle, then settles into a heartbeat that tells subscribers the
/// publisher is still alive.
pub const DEFAULT_RETRANS: &[Duration] = &[
    Duration::from_millis(4),
    Duration::from_millis(8),
    Duration::from_millis(16),
    Duration::from_millis(32),
    Duration::from_millis(64),
    Duration::from_millis(128),
    Duration::from_millis(256),
    Duration::from_millis(512),
    Duration::from_millis(1000),
];

/// Identifies one GOOSE control block on the wire.
#[derive(Debug, Clone)]
pub struct PublisherConfig {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub app_id: u16,
    pub vlan: Option<VlanTag>,
    pub go_cb_ref: String,
    pub dat_set: String,
    pub go_id: String,
    pub conf_rev: u32,
    /// The interval schedule after a state change; the last entry repeats
    /// indefinitely. Empty means [`DEFAULT_RETRANS`].
    pub retrans: Vec<Duration>,
}

impl Default for PublisherConfig {
    fn default() -> PublisherConfig {
        PublisherConfig {
            // The standard GOOSE multicast range starts here.
            dst_mac: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00],
            src_mac: [0; 6],
            app_id: 0,
            vlan: None,
            go_cb_ref: String::new(),
            dat_set: String::new(),
            go_id: String::new(),
            conf_rev: 0,
            retrans: Vec::new(),
        }
    }
}

/// The state one publisher shares with its retransmission task.
#[derive(Debug)]
struct Shared {
    iface: Arc<dyn Interface>,
    cfg: PublisherConfig,
    retrans: Vec<Duration>,
    state: Mutex<PubState>,
    closed: AtomicBool,
}

#[derive(Debug, Default)]
struct PubState {
    st_num: u32,
    /// Bumped on every publish, so a retransmission task can tell it has been
    /// superseded without a channel per publish.
    generation: u64,
}

/// Sends GOOSE messages with the standard retransmission state machine.
///
/// Each [`publish`](Publisher::publish) increments `stNum` and restarts the
/// schedule; a background task retransmits with increasing `sqNum` until the
/// next publish or close. Safe for concurrent use.
#[derive(Debug)]
pub struct Publisher {
    shared: Arc<Shared>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Publisher {
    /// Returns a publisher over `iface`.
    ///
    /// The interface is shared, not owned: closing the publisher stops
    /// retransmission but leaves the interface open.
    pub fn new(iface: Arc<dyn Interface>, cfg: PublisherConfig) -> Result<Publisher> {
        if cfg.go_cb_ref.is_empty() {
            return Err(Error::Config("go_cb_ref is required".into()));
        }
        let retrans = if cfg.retrans.is_empty() {
            DEFAULT_RETRANS.to_vec()
        } else {
            cfg.retrans.clone()
        };
        if let Some(bad) = retrans.iter().find(|d| d.is_zero()) {
            return Err(Error::Config(format!(
                "retransmission interval {bad:?} is not positive"
            )));
        }
        Ok(Publisher {
            shared: Arc::new(Shared {
                iface,
                cfg,
                retrans,
                state: Mutex::new(PubState::default()),
                closed: AtomicBool::new(false),
            }),
            task: Mutex::new(None),
        })
    }

    /// Announces a state change: `stNum` increments, `sqNum` resets to zero,
    /// the message is sent immediately and retransmission restarts.
    pub fn publish(&self, values: Vec<Value>) -> Result<()> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let (st_num, generation) = {
            let mut st = self.shared.state.lock().unwrap();
            st.st_num = st.st_num.wrapping_add(1);
            st.generation += 1;
            (st.st_num, st.generation)
        };

        let msg = Message {
            go_cb_ref: self.shared.cfg.go_cb_ref.clone(),
            dat_set: self.shared.cfg.dat_set.clone(),
            go_id: self.shared.cfg.go_id.clone(),
            time_allowed_to_live: self.shared.tatl(0),
            t: Some(SystemTime::now()),
            st_num,
            sq_num: 0,
            conf_rev: self.shared.cfg.conf_rev,
            num_dat_set_entries: values.len() as u32,
            values,
            app_id: self.shared.cfg.app_id,
            ..Default::default()
        };
        self.shared.send(&msg)?;

        // Replace the retransmission task. The old one notices the newer
        // generation and stops, so a stale frame can never follow the new
        // state onto the wire.
        let handle = tokio::spawn(retransmit(Arc::clone(&self.shared), msg, generation));
        let old = self.task.lock().unwrap().replace(handle);
        if let Some(h) = old {
            h.abort();
        }
        Ok(())
    }

    /// Returns the current state number, which counts state changes.
    pub fn st_num(&self) -> u32 {
        self.shared.state.lock().unwrap().st_num
    }

    /// Stops retransmission. It does not close the underlying interface.
    pub fn close(&self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        if let Some(h) = self.task.lock().unwrap().take() {
            h.abort();
        }
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.close();
    }
}

impl Shared {
    /// Returns `timeAllowedToLive` in milliseconds for transmission `n` of the
    /// current state: twice the interval until the next retransmission, so a
    /// subscriber that misses one frame does not yet call the value stale.
    fn tatl(&self, n: usize) -> u32 {
        let d = self.retrans[n.min(self.retrans.len() - 1)];
        (2 * d.as_millis()).max(1).min(u128::from(u32::MAX)) as u32
    }

    fn send(&self, msg: &Message) -> Result<()> {
        self.iface.write_frame(&Frame {
            dst: self.cfg.dst_mac,
            src: self.cfg.src_mac,
            ether_type: ETHER_TYPE_GOOSE,
            vlan: self.cfg.vlan,
            payload: msg.marshal(),
        })?;
        Ok(())
    }
}

/// Re-sends `msg` with an incrementing `sqNum` on the configured schedule,
/// until a newer publish supersedes it or the publisher closes.
///
/// The timestamp stays at the state-change time throughout: it says when the
/// value changed, not when this copy of it was sent.
async fn retransmit(shared: Arc<Shared>, mut msg: Message, generation: u64) {
    for i in 0usize.. {
        let idx = i.min(shared.retrans.len() - 1);
        tokio::time::sleep(shared.retrans[idx]).await;

        if shared.closed.load(Ordering::SeqCst) {
            return;
        }
        // A newer publish has taken over; stop rather than interleave.
        if shared.state.lock().unwrap().generation != generation {
            return;
        }

        msg.sq_num = msg.sq_num.wrapping_add(1);
        msg.time_allowed_to_live = shared.tatl(i + 1);
        if shared.send(&msg).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ethernet;

    fn config() -> PublisherConfig {
        PublisherConfig {
            dst_mac: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
            app_id: 0x1000,
            go_cb_ref: "IED1LD0/LLN0$GO$gcb01".into(),
            dat_set: "IED1LD0/LLN0$Events".into(),
            go_id: "events".into(),
            conf_rev: 1,
            // A fast, fixed schedule keeps the tests quick.
            retrans: vec![Duration::from_millis(10)],
            ..Default::default()
        }
    }

    #[test]
    fn a_publisher_needs_a_control_block_reference() {
        let (a, _b) = ethernet::pipe();
        let iface: Arc<dyn Interface> = Arc::new(a);
        let cfg = PublisherConfig {
            go_cb_ref: String::new(),
            ..config()
        };
        assert!(Publisher::new(Arc::clone(&iface), cfg).is_err());
    }

    #[test]
    fn a_zero_retransmission_interval_is_refused() {
        let (a, _b) = ethernet::pipe();
        let cfg = PublisherConfig {
            retrans: vec![Duration::ZERO],
            ..config()
        };
        assert!(Publisher::new(Arc::new(a), cfg).is_err());
    }

    #[tokio::test]
    async fn publishing_sends_immediately_with_a_fresh_state_number() {
        let (a, b) = ethernet::pipe();
        let pub_ = Publisher::new(Arc::new(a), config()).unwrap();

        pub_.publish(vec![Value::boolean(true)]).unwrap();
        let frame = b.read_frame().unwrap();
        assert_eq!(frame.ether_type, ETHER_TYPE_GOOSE);
        assert_eq!(frame.dst, [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);

        let m = super::super::parse(&frame.payload).unwrap();
        assert_eq!(m.st_num, 1, "the first state change is stNum 1");
        assert_eq!(m.sq_num, 0, "a state change restarts sqNum");
        assert_eq!(m.go_cb_ref, "IED1LD0/LLN0$GO$gcb01");
        assert_eq!(m.app_id, 0x1000);
        assert!(m.values[0].as_bool());
        pub_.close();
    }

    /// The retransmission heartbeat is what tells a subscriber the publisher
    /// is alive; without it a silent publisher is indistinguishable from a
    /// failed link.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_published_state_is_retransmitted_with_increasing_sequence_numbers() {
        let (a, b) = ethernet::pipe();
        let pub_ = Publisher::new(Arc::new(a), config()).unwrap();
        pub_.publish(vec![Value::boolean(true)]).unwrap();

        // Give the schedule time to produce several retransmissions, then
        // take what accumulated rather than blocking the runtime on a read.
        tokio::time::sleep(Duration::from_millis(55)).await;
        let mut sq_nums = Vec::new();
        while let Some(f) = b.try_read_frame() {
            sq_nums.push(super::super::parse(&f.payload).unwrap().sq_num);
        }
        assert!(
            sq_nums.len() >= 4,
            "expected several retransmissions, got {sq_nums:?}"
        );
        assert_eq!(
            &sq_nums[..4],
            &[0, 1, 2, 3],
            "sqNum counts the retransmissions"
        );
        pub_.close();
    }

    /// A stale retransmission arriving after a new state change would make a
    /// subscriber act on a superseded value.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_publish_supersedes_the_previous_retransmissions() {
        let (a, b) = ethernet::pipe();
        let pub_ = Publisher::new(Arc::new(a), config()).unwrap();

        pub_.publish(vec![Value::boolean(false)]).unwrap();
        tokio::time::sleep(Duration::from_millis(35)).await;
        pub_.publish(vec![Value::boolean(true)]).unwrap();
        tokio::time::sleep(Duration::from_millis(35)).await;
        pub_.close();

        // Drain everything and check that no stNum 1 frame follows a stNum 2.
        let mut seen: Vec<(u32, u32)> = Vec::new();
        while let Some(f) = b.try_read_frame() {
            let m = super::super::parse(&f.payload).unwrap();
            seen.push((m.st_num, m.sq_num));
        }
        let first_second_state = seen
            .iter()
            .position(|(st, _)| *st == 2)
            .expect("the second state was published");
        assert!(
            seen[first_second_state..].iter().all(|(st, _)| *st == 2),
            "a stale retransmission followed the new state: {seen:?}"
        );
        // And the new state started its own sequence.
        assert_eq!(seen[first_second_state], (2, 0));
    }

    #[tokio::test]
    async fn publishing_after_close_is_refused() {
        let (a, _b) = ethernet::pipe();
        let pub_ = Publisher::new(Arc::new(a), config()).unwrap();
        pub_.publish(vec![Value::boolean(true)]).unwrap();
        pub_.close();
        assert!(matches!(
            pub_.publish(vec![Value::boolean(false)]),
            Err(Error::Closed)
        ));
    }

    /// The time allowed to live has to outlast the interval until the next
    /// frame, or every subscriber marks the value stale between heartbeats.
    #[test]
    fn the_time_allowed_to_live_covers_the_next_retransmission() {
        let (a, _b) = ethernet::pipe();
        let cfg = PublisherConfig {
            retrans: DEFAULT_RETRANS.to_vec(),
            ..config()
        };
        let pub_ = Publisher::new(Arc::new(a), cfg).unwrap();
        let shared = &pub_.shared;

        for (i, d) in DEFAULT_RETRANS.iter().enumerate() {
            let tatl = u128::from(shared.tatl(i));
            assert!(
                tatl >= d.as_millis(),
                "transmission {i}: tatl {tatl}ms does not cover a {d:?} interval"
            );
        }
        // Past the end of the schedule the last interval repeats.
        assert_eq!(shared.tatl(99), shared.tatl(DEFAULT_RETRANS.len() - 1));
        // And it is never zero, which would mean "already stale".
        assert!(shared.tatl(0) >= 1);
    }

    #[tokio::test]
    async fn a_vlan_tag_is_applied_to_every_frame() {
        let (a, b) = ethernet::pipe();
        let cfg = PublisherConfig {
            vlan: Some(VlanTag {
                priority: 4,
                dei: false,
                vid: 10,
            }),
            ..config()
        };
        let pub_ = Publisher::new(Arc::new(a), cfg).unwrap();
        pub_.publish(vec![Value::boolean(true)]).unwrap();

        let f = b.read_frame().unwrap();
        let tag = f.vlan.expect("the frame carries its tag");
        assert_eq!(tag.priority, 4);
        assert_eq!(tag.vid, 10);
        pub_.close();
    }
}
