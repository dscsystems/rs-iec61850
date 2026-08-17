use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::ethernet::{Interface, ETHER_TYPE_GOOSE};

use super::{parse, Message};

/// Selects GOOSE messages for a subscription.
///
/// Zero fields match everything: an APPID of zero accepts any, and an empty
/// control block reference accepts any.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    pub app_id: u16,
    pub go_cb_ref: String,
}

impl Filter {
    /// Matches every GOOSE message on the segment.
    pub fn any() -> Filter {
        Filter::default()
    }

    /// Matches one APPID.
    pub fn app_id(app_id: u16) -> Filter {
        Filter {
            app_id,
            go_cb_ref: String::new(),
        }
    }

    fn matches(&self, m: &Message) -> bool {
        if self.app_id != 0 && m.app_id != self.app_id {
            return false;
        }
        if !self.go_cb_ref.is_empty() && m.go_cb_ref != self.go_cb_ref {
            return false;
        }
        true
    }
}

/// Protocol irregularities a subscriber detects from the per-control-block
/// sequence state.
///
/// They are diagnostics, not part of the wire format, and are what turns a
/// silent failure (a publisher that restarted, a switch dropping frames) into
/// something an operator can see.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Anomalies {
    /// The state number went backwards, which means the publisher restarted.
    pub st_num_regressed: bool,
    /// The sequence number skipped, or did not restart at zero on a new state.
    pub sq_num_gap: bool,
    /// The inter-arrival time exceeded the previous `timeAllowedToLive`.
    pub stale: bool,
}

impl Anomalies {
    /// Reports whether anything at all was flagged.
    pub fn any(self) -> bool {
        self.st_num_regressed || self.sq_num_gap || self.stale
    }
}

/// The last observed sequence state for one control block.
#[derive(Debug, Clone)]
struct SeqState {
    st_num: u32,
    sq_num: u32,
    tatl: Duration,
    arrival: Instant,
}

/// Tracks sequence continuity across messages.
///
/// It is separated from the receive loop so the anomaly rules are testable
/// without a socket or a clock.
#[derive(Debug, Default)]
pub struct SequenceTracker {
    states: HashMap<String, SeqState>,
}

impl SequenceTracker {
    pub fn new() -> SequenceTracker {
        SequenceTracker::default()
    }

    /// Records a message and returns what was irregular about it.
    ///
    /// The first message from a control block establishes the baseline and is
    /// never anomalous: there is nothing yet to compare it against.
    pub fn observe(&mut self, m: &Message, now: Instant) -> Anomalies {
        let tatl = Duration::from_millis(u64::from(m.time_allowed_to_live));
        let mut out = Anomalies::default();

        match self.states.get_mut(&m.go_cb_ref) {
            Some(st) => {
                if m.st_num < st.st_num {
                    out.st_num_regressed = true;
                }
                out.sq_num_gap = if m.st_num == st.st_num {
                    // Within one state, the sequence must advance by one.
                    m.sq_num != st.sq_num.wrapping_add(1)
                } else {
                    // A new state restarts the sequence at zero.
                    m.sq_num != 0
                };
                out.stale = !st.tatl.is_zero() && now.duration_since(st.arrival) > st.tatl;

                st.st_num = m.st_num;
                st.sq_num = m.sq_num;
                st.arrival = now;
                st.tatl = tatl;
            }
            None => {
                self.states.insert(
                    m.go_cb_ref.clone(),
                    SeqState {
                        st_num: m.st_num,
                        sq_num: m.sq_num,
                        tatl,
                        arrival: now,
                    },
                );
            }
        }
        out
    }

    /// Returns how many control blocks are being tracked.
    pub fn tracked(&self) -> usize {
        self.states.len()
    }
}

/// Ends a subscription.
///
/// Dropping it stops delivery just as calling [`stop`](Subscription::stop)
/// does, so a subscription cannot outlive the scope that owns it by accident.
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
    ///
    /// Close the interface first, or this blocks until the next frame arrives.
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

/// Receives GOOSE messages from a shared interface.
///
/// Each subscription runs its own reader thread. Several concurrent
/// subscriptions on one interface would compete for frames, so use one
/// subscription per interface and fan out in the callback.
#[derive(Debug)]
pub struct Subscriber {
    iface: Arc<dyn Interface>,
}

impl Subscriber {
    pub fn new(iface: Arc<dyn Interface>) -> Subscriber {
        Subscriber { iface }
    }

    /// Delivers matching messages to `callback` from a background thread, with
    /// anomalies filled in from per-control-block sequence tracking.
    ///
    /// The callback must not block: it runs on the receive path, and a GOOSE
    /// segment does not wait.
    ///
    /// A blocking thread rather than an async task is deliberate: the raw
    /// socket read is a blocking syscall, and parking a runtime worker on it
    /// would stall every other task sharing that worker.
    pub fn subscribe(
        &self,
        filter: Filter,
        callback: impl Fn(&Message) + Send + 'static,
    ) -> Subscription {
        let stopped = Arc::new(AtomicBool::new(false));
        let iface = Arc::clone(&self.iface);
        let flag = Arc::clone(&stopped);

        let task = std::thread::spawn(move || {
            let mut tracker = SequenceTracker::new();
            loop {
                let Ok(frame) = iface.read_frame() else {
                    return; // the interface closed or failed
                };
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                if frame.ether_type != ETHER_TYPE_GOOSE {
                    continue;
                }
                let Ok(mut m) = parse(&frame.payload) else {
                    continue; // a malformed frame is not this subscriber's problem
                };
                if !filter.matches(&m) {
                    continue;
                }
                m.anomalies = tracker.observe(&m, Instant::now());
                callback(&m);
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
    use crate::goose::{Publisher, PublisherConfig};
    use crate::mms::Value;
    use std::sync::Mutex;

    fn message(go_cb_ref: &str, st_num: u32, sq_num: u32, tatl: u32) -> Message {
        Message {
            go_cb_ref: go_cb_ref.into(),
            st_num,
            sq_num,
            time_allowed_to_live: tatl,
            ..Default::default()
        }
    }

    #[test]
    fn the_first_message_from_a_publisher_is_never_anomalous() {
        let mut t = SequenceTracker::new();
        // Even an odd-looking first message: there is nothing to compare it to.
        let a = t.observe(&message("gcb01", 42, 7, 2000), Instant::now());
        assert_eq!(a, Anomalies::default());
        assert!(!a.any());
        assert_eq!(t.tracked(), 1);
    }

    #[test]
    fn an_orderly_sequence_flags_nothing() {
        let mut t = SequenceTracker::new();
        let now = Instant::now();
        t.observe(&message("gcb01", 1, 0, 2000), now);
        for sq in 1..=5 {
            let a = t.observe(&message("gcb01", 1, sq, 2000), now);
            assert!(!a.any(), "sqNum {sq} was flagged: {a:?}");
        }
        // A state change restarts the sequence at zero.
        let a = t.observe(&message("gcb01", 2, 0, 2000), now);
        assert!(!a.any(), "a clean state change was flagged: {a:?}");
    }

    /// A publisher that restarts begins counting again, which a subscriber has
    /// to notice: its cached values are no longer trustworthy.
    #[test]
    fn a_state_number_going_backwards_is_flagged() {
        let mut t = SequenceTracker::new();
        let now = Instant::now();
        t.observe(&message("gcb01", 9, 0, 2000), now);
        let a = t.observe(&message("gcb01", 1, 0, 2000), now);
        assert!(a.st_num_regressed);
    }

    #[test]
    fn a_skipped_sequence_number_is_flagged() {
        let mut t = SequenceTracker::new();
        let now = Instant::now();
        t.observe(&message("gcb01", 1, 0, 2000), now);
        let a = t.observe(&message("gcb01", 1, 3, 2000), now);
        assert!(a.sq_num_gap, "a lost frame must be visible");
        assert!(!a.st_num_regressed);
    }

    /// A new state that does not restart at zero means the state-change frame
    /// itself was lost, which is the one frame that matters most.
    #[test]
    fn a_state_change_that_does_not_restart_the_sequence_is_flagged() {
        let mut t = SequenceTracker::new();
        let now = Instant::now();
        t.observe(&message("gcb01", 1, 4, 2000), now);
        let a = t.observe(&message("gcb01", 2, 2, 2000), now);
        assert!(a.sq_num_gap);
    }

    /// Silence beyond the advertised lifetime is how a subscriber learns the
    /// link or the publisher has failed.
    #[test]
    fn a_message_arriving_after_its_predecessors_lifetime_is_stale() {
        let mut t = SequenceTracker::new();
        let now = Instant::now();
        t.observe(&message("gcb01", 1, 0, 100), now);

        let late = now + Duration::from_millis(250);
        let a = t.observe(&message("gcb01", 1, 1, 100), late);
        assert!(a.stale, "250ms of silence exceeded a 100ms lifetime");

        // And an on-time one is not.
        let on_time = late + Duration::from_millis(50);
        let a = t.observe(&message("gcb01", 1, 2, 100), on_time);
        assert!(!a.stale);
    }

    #[test]
    fn each_control_block_is_tracked_separately() {
        let mut t = SequenceTracker::new();
        let now = Instant::now();
        t.observe(&message("gcb01", 1, 0, 2000), now);
        t.observe(&message("gcb02", 5, 9, 2000), now);
        assert_eq!(t.tracked(), 2);

        // One publisher's sequence must not disturb the other's.
        let a = t.observe(&message("gcb01", 1, 1, 2000), now);
        assert!(!a.any(), "{a:?}");
        let a = t.observe(&message("gcb02", 5, 10, 2000), now);
        assert!(!a.any(), "{a:?}");
    }

    #[test]
    fn a_filter_selects_by_appid_and_control_block() {
        let mut m = message("gcb01", 1, 0, 2000);
        m.app_id = 0x1000;

        assert!(Filter::any().matches(&m), "an empty filter matches all");
        assert!(Filter::app_id(0x1000).matches(&m));
        assert!(!Filter::app_id(0x2000).matches(&m));

        let f = Filter {
            app_id: 0,
            go_cb_ref: "gcb01".into(),
        };
        assert!(f.matches(&m));
        let f = Filter {
            app_id: 0,
            go_cb_ref: "gcb99".into(),
        };
        assert!(!f.matches(&m));

        // Both fields have to match when both are set.
        let f = Filter {
            app_id: 0x2000,
            go_cb_ref: "gcb01".into(),
        };
        assert!(!f.matches(&m));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_subscriber_receives_what_a_publisher_sends() {
        let (a, b) = ethernet::pipe();
        let pub_ = Publisher::new(
            Arc::new(a),
            PublisherConfig {
                app_id: 0x1000,
                go_cb_ref: "IED1LD0/LLN0$GO$gcb01".into(),
                go_id: "events".into(),
                retrans: vec![Duration::from_secs(3600)], // no retransmission noise
                ..Default::default()
            },
        )
        .unwrap();

        let seen: Arc<Mutex<Vec<(u32, bool)>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let sub = Subscriber::new(Arc::new(b)).subscribe(Filter::app_id(0x1000), move |m| {
            sink.lock()
                .unwrap()
                .push((m.st_num, m.values.first().is_some_and(crate::mms::Value::as_bool)));
        });

        pub_.publish(vec![Value::boolean(true)]).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        pub_.publish(vec![Value::boolean(false)]).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let got = seen.lock().unwrap().clone();
        assert_eq!(got, [(1, true), (2, false)], "got {got:?}");
        sub.stop();
        pub_.close();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_filter_rejects_another_publishers_stream() {
        let (a, b) = ethernet::pipe();
        let pub_ = Publisher::new(
            Arc::new(a),
            PublisherConfig {
                app_id: 0x1000,
                go_cb_ref: "gcb01".into(),
                retrans: vec![Duration::from_secs(3600)],
                ..Default::default()
            },
        )
        .unwrap();

        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&count);
        let sub = Subscriber::new(Arc::new(b)).subscribe(Filter::app_id(0x4000), move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        pub_.publish(vec![Value::boolean(true)]).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(count.load(Ordering::SeqCst), 0, "the filter let one through");
        sub.stop();
        pub_.close();
    }
}
