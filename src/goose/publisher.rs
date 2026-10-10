use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::ethernet::{Frame, Interface, VlanTag, ETHER_TYPE_GOOSE, MAX_PAYLOAD};
use crate::mms::{TimeQuality, Value};

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
    /// The goID the message carries. Empty defaults to `go_cb_ref`, so the
    /// field on the wire always identifies the stream.
    pub go_id: String,
    pub conf_rev: u32,
    /// The interval schedule after a state change; the last entry repeats
    /// indefinitely. Empty means [`DEFAULT_RETRANS`]. A control block's
    /// MinTime and MaxTime build it: see [`retrans_from_scl`](super::retrans_from_scl).
    pub retrans: Vec<Duration>,
    /// The initial `test` and `ndsCom` fields, which tell a receiver that the
    /// publisher is in test or needs commissioning. A receiver is expected to
    /// act on them, so they are only set deliberately;
    /// [`Publisher::set_test`] and [`Publisher::set_nds_com`] change them.
    pub test: bool,
    pub nds_com: bool,
    /// The quality of the message timestamp. `None` carries the crate
    /// default: leap seconds known and accuracy 10.
    pub time_quality: Option<TimeQuality>,
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
            test: false,
            nds_com: false,
            time_quality: None,
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
    sq_num: u32,
    test: bool,
    nds_com: bool,
    /// The time of the state being advertised, which a refresh repeats.
    t: Option<SystemTime>,
    /// Bumped on every publish, so a retransmission task can tell it has been
    /// superseded without a channel per publish.
    generation: u64,
}

/// Sends GOOSE messages with the standard retransmission state machine.
///
/// [`publish`](Publisher::publish) announces a state change: it increments
/// `stNum`, resets `sqNum` and restarts the schedule.
/// [`refresh`](Publisher::refresh) repeats the current state: it leaves
/// `stNum` alone and only restarts the schedule, which is what
/// IEC 61850-8-1 requires a publisher to do when nothing has changed. A
/// background task retransmits with increasing `sqNum` until the next
/// publish, refresh or close. Safe for concurrent use.
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
    pub fn new(iface: Arc<dyn Interface>, mut cfg: PublisherConfig) -> Result<Publisher> {
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
        if cfg.go_id.is_empty() {
            cfg.go_id = cfg.go_cb_ref.clone();
        }
        let state = PubState {
            test: cfg.test,
            nds_com: cfg.nds_com,
            ..Default::default()
        };
        Ok(Publisher {
            shared: Arc::new(Shared {
                iface,
                cfg,
                retrans,
                state: Mutex::new(state),
                closed: AtomicBool::new(false),
            }),
            task: Mutex::new(None),
        })
    }

    /// Sets the `test` field. It takes effect with the next publish or
    /// refresh: the retransmissions of a state repeat the message that
    /// announced it, so a receiver never sees the field change under an
    /// unchanged `stNum` and `sqNum` sequence. Call
    /// [`refresh`](Publisher::refresh) to put it on the wire without a state
    /// change.
    pub fn set_test(&self, test: bool) {
        self.shared.state.lock().unwrap().test = test;
    }

    /// Sets the `ndsCom` field, which tells a receiver the control block needs
    /// commissioning (IEC 61850-7-2: for instance, its data set is missing or
    /// does not fit a frame). Like [`set_test`](Publisher::set_test), it takes
    /// effect with the next publish or refresh.
    pub fn set_nds_com(&self, nds_com: bool) {
        self.shared.state.lock().unwrap().nds_com = nds_com;
    }

    /// Announces a state change: `stNum` increments, `sqNum` resets to zero,
    /// the message is sent immediately and retransmission restarts.
    ///
    /// `stNum` starts at 1 and never returns to 0. IEC 61850-8-1 reserves 0
    /// for "no state change yet", so on wrap the counter goes to 1.
    ///
    /// A message that does not fit one Ethernet frame is refused with
    /// [`Error::FrameTooLarge`] before anything changes: the state being
    /// advertised and its retransmission carry on.
    pub fn publish(&self, values: Vec<Value>) -> Result<()> {
        self.publish_state(values, true)
    }

    /// Repeats the current state without announcing a change: `stNum` stays
    /// where it is, `sqNum` resets and the retransmission schedule restarts.
    /// It keeps the timestamp of the change it repeats, so a receiver can tell
    /// how old the state is. Use it to re-advertise a value that has not
    /// changed, or to put a new `test` or `ndsCom` on the wire.
    ///
    /// A refresh before any publish has nothing to repeat, so it behaves as
    /// one.
    pub fn refresh(&self, values: Vec<Value>) -> Result<()> {
        self.publish_state(values, false)
    }

    fn publish_state(&self, values: Vec<Value>, state_change: bool) -> Result<()> {
        if self.shared.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        // The task slot is held throughout, so two publishes cannot interleave
        // their sends and task replacements.
        let mut task = self.task.lock().unwrap();
        let mut st = self.shared.state.lock().unwrap();
        let st_num = match (state_change, st.st_num) {
            (true, n) => n.wrapping_add(1).max(1),
            (false, 0) => 1,
            (false, n) => n,
        };
        let t = match (state_change, st.t) {
            (false, Some(t)) => t,
            _ => SystemTime::now(),
        };
        let cfg = &self.shared.cfg;
        let msg = Message {
            go_cb_ref: cfg.go_cb_ref.clone(),
            dat_set: cfg.dat_set.clone(),
            go_id: cfg.go_id.clone(),
            time_allowed_to_live: self.shared.tatl(0),
            t: Some(t),
            st_num,
            sq_num: 0,
            conf_rev: cfg.conf_rev,
            test: st.test,
            nds_com: st.nds_com,
            num_dat_set_entries: values.len() as u32,
            values,
            app_id: cfg.app_id,
            time_quality: cfg.time_quality,
            ..Default::default()
        };
        // The retransmissions of this state differ only in sqNum and
        // timeAllowedToLive, and grow as those gain octets. Sizing the message
        // with both at their widest means no retransmission can outgrow the
        // frame the first one fit in.
        let widest = Message {
            sq_num: u32::MAX,
            time_allowed_to_live: u32::MAX,
            ..msg.clone()
        };
        let n = widest.marshal().len();
        if n > MAX_PAYLOAD {
            return Err(Error::FrameTooLarge(format!(
                "{n} octets for {} data set members, limit {MAX_PAYLOAD}",
                msg.values.len()
            )));
        }
        st.st_num = st_num;
        st.sq_num = 0;
        st.t = Some(t);
        st.generation += 1;
        let generation = st.generation;
        drop(st);
        self.shared.send(&msg)?;

        // Replace the retransmission task. The old one notices the newer
        // generation and stops, so a stale frame can never follow the new
        // state onto the wire.
        let handle = tokio::spawn(retransmit(Arc::clone(&self.shared), msg, generation));
        if let Some(h) = task.replace(handle) {
            h.abort();
        }
        Ok(())
    }

    /// Returns the current state number, which counts state changes.
    pub fn st_num(&self) -> u32 {
        self.shared.state.lock().unwrap().st_num
    }

    /// Returns the `stNum` and `sqNum` the publisher is advertising.
    pub fn state(&self) -> (u32, u32) {
        let st = self.shared.state.lock().unwrap();
        (st.st_num, st.sq_num)
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
        // sqNum rolls over to 1, not 0: 0 marks the first transmission of a
        // state (IEC 61850-8-1), so a receiver would read a wrapped 0 as a
        // state change that did not happen.
        msg.sq_num = msg.sq_num.wrapping_add(1).max(1);
        msg.time_allowed_to_live = shared.tatl(i + 1);
        // Send under the state lock and re-check the generation, so a stale
        // retransmission can never follow the next publish on the wire, and a
        // superseded task cannot overwrite the counters of its successor.
        let mut st = shared.state.lock().unwrap();
        if st.generation != generation {
            return;
        }
        st.sq_num = msg.sq_num;
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

#[cfg(test)]
#[path = "ed21_tests.rs"]
mod ed21_tests;
