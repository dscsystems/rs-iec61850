//! IEC 61850-8-1 Edition 2 and Amendment 1 behaviour of the publisher.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::ethernet::{self, Frame, MAX_PAYLOAD};
use crate::goose::{parse, retrans_from_scl, Filter, SequenceTracker};
use crate::model::{GseControl, LogicalDevice, LogicalNode};

/// Records what a publisher sends.
#[derive(Debug, Default)]
struct Capture {
    frames: Mutex<Vec<Frame>>,
}

impl Interface for Capture {
    fn write_frame(&self, f: &Frame) -> ethernet::Result<()> {
        self.frames.lock().unwrap().push(f.clone());
        Ok(())
    }
    fn read_frame(&self) -> ethernet::Result<Frame> {
        unreachable!("a publisher never reads")
    }
    fn close(&self) -> ethernet::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn messages(&self) -> Vec<Message> {
        self.frames
            .lock()
            .unwrap()
            .iter()
            .filter_map(|f| parse(&f.payload).ok())
            .collect()
    }
}

fn test_publisher(mut cfg: PublisherConfig) -> (Publisher, Arc<Capture>) {
    if cfg.go_cb_ref.is_empty() {
        cfg.go_cb_ref = "LD/LLN0.gcb01".into();
    }
    if cfg.retrans.is_empty() {
        cfg.retrans = vec![Duration::from_secs(3600)]; // one send, no retransmission
    }
    let cap = Arc::new(Capture::default());
    let p = Publisher::new(cap.clone(), cfg).unwrap();
    (p, cap)
}

/// A state change increments stNum; a refresh does not, and keeps the
/// timestamp of the change it repeats.
#[tokio::test]
async fn publish_versus_refresh() {
    let (p, cap) = test_publisher(PublisherConfig::default());
    let values = || vec![Value::boolean(true)];
    p.publish(values()).unwrap();
    p.refresh(values()).unwrap();
    p.publish(values()).unwrap();
    let m = cap.messages();
    assert_eq!(m.len(), 3);
    assert_ne!(m[0].st_num, 0, "0 is reserved");
    assert_eq!(m[0].st_num, m[1].st_num, "a refresh changed stNum");
    assert_ne!(m[1].st_num, m[2].st_num, "a publish after a refresh kept stNum");
    assert_eq!(m[1].t, m[0].t, "a refresh moved the timestamp");
    assert!(m[2].t >= m[1].t);
}

/// stNum starts at 1 and skips 0 on wrap.
#[tokio::test]
async fn st_num_is_never_zero() {
    let (p, _cap) = test_publisher(PublisherConfig::default());
    p.shared.state.lock().unwrap().st_num = u32::MAX;
    p.publish(Vec::new()).unwrap();
    assert_eq!(p.state().0, 1);
}

/// A refresh before any publish has nothing to repeat, so it behaves as one.
#[tokio::test]
async fn a_refresh_before_any_publish_is_state_one() {
    let (p, cap) = test_publisher(PublisherConfig::default());
    p.refresh(Vec::new()).unwrap();
    let m = cap.messages();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].st_num, 1);
}

#[tokio::test]
async fn test_and_nds_com_are_transmitted() {
    for (test, nds_com) in [(false, false), (true, false), (false, true), (true, true)] {
        let (p, cap) = test_publisher(PublisherConfig {
            test,
            nds_com,
            ..Default::default()
        });
        p.publish(Vec::new()).unwrap();
        let m = cap.messages();
        assert_eq!((m[0].test, m[0].nds_com), (test, nds_com));
    }
}

/// The time quality is configurable, its default is unchanged, and 0 is a
/// real quality that round-trips.
#[tokio::test]
async fn the_time_quality_is_transmitted() {
    let tq = TimeQuality(TimeQuality::CLOCK_FAILURE.0 | TimeQuality::CLOCK_NOT_SYNCHRONIZED.0 | 3);
    let (p, cap) = test_publisher(PublisherConfig {
        time_quality: Some(tq),
        ..Default::default()
    });
    p.publish(Vec::new()).unwrap();
    assert_eq!(cap.messages()[0].time_quality, Some(tq));

    let (p, cap) = test_publisher(PublisherConfig::default());
    p.publish(Vec::new()).unwrap();
    assert_eq!(cap.messages()[0].time_quality, Some(TimeQuality::DEFAULT));

    let (p, cap) = test_publisher(PublisherConfig {
        time_quality: Some(TimeQuality(0)),
        ..Default::default()
    });
    p.publish(Vec::new()).unwrap();
    let got = cap.messages().remove(0);
    assert_eq!(got.time_quality, Some(TimeQuality(0)));
    assert_eq!(parse(&got.marshal()).unwrap().time_quality, Some(TimeQuality(0)));
}

/// The retransmission schedule comes from MinTime and MaxTime.
#[test]
fn the_schedule_comes_from_min_and_max_time() {
    let got = retrans_from_scl(20, 100);
    assert_eq!(got[0], Duration::from_millis(20));
    assert_eq!(*got.last().unwrap(), Duration::from_millis(100));
    assert!(got.windows(2).all(|w| w[1] > w[0]), "{got:?}");
    assert_eq!(retrans_from_scl(0, 0), DEFAULT_RETRANS);
    assert_eq!(*retrans_from_scl(500, 100).last().unwrap(), Duration::from_millis(500));
    assert!(retrans_from_scl(1, 1 << 30).len() <= 17);
}

fn lln0() -> (LogicalDevice, LogicalNode) {
    (
        LogicalDevice {
            name: "IEDLD0".into(),
            inst: "LD0".into(),
            ..Default::default()
        },
        LogicalNode {
            name: "LLN0".into(),
            class: "LLN0".into(),
            ..Default::default()
        },
    )
}

/// A publisher built from a model takes the addressing, identity and timing
/// the configuration states, and full references on the wire.
#[tokio::test]
async fn a_publisher_from_the_model() {
    let gc = GseControl {
        name: "gcb01".into(),
        go_id: "LD/LLN0.gcb01".into(),
        data_set: "Measurements".into(),
        conf_rev: 3,
        dst_mac: [1, 0x0c, 0xcd, 3, 0, 1],
        app_id: 0x2000,
        vlan_id: 0x123,
        vlan_pri: 4,
        min_time: 20,
        max_time: 100,
        ..Default::default()
    };
    let (ld, ln) = lln0();
    let cap = Arc::new(Capture::default());
    let p = Publisher::from_model(cap.clone(), &ld, &ln, &gc, [2, 0, 0, 0, 0, 1]).unwrap();
    assert_eq!(p.shared.retrans[0], Duration::from_millis(20));
    p.publish(Vec::new()).unwrap();
    let frames = cap.frames.lock().unwrap().clone();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].dst, gc.dst_mac);
    assert_eq!(frames[0].ether_type, ethernet::ETHER_TYPE_GOOSE);
    let vlan = frames[0].vlan.expect("a VLAN tag");
    assert_eq!((vlan.vid, vlan.priority), (0x123, 4));
    let m = cap.messages().remove(0);
    assert_eq!((m.go_id.as_str(), m.conf_rev), ("LD/LLN0.gcb01", 3));
    assert_eq!(m.go_cb_ref, "IEDLD0/LLN0$GO$gcb01");
    assert_eq!(m.dat_set, "IEDLD0/LLN0$Measurements");
    assert!(!m.nds_com);
    let f = Filter {
        go_cb_ref: "IEDLD0/LLN0$GO$gcb01".into(),
        ..Default::default()
    };
    assert!(f.matches(&m));

    // A block without a data set needs commissioning, and says so.
    let p = Publisher::from_model(cap.clone(), &ld, &ln, &GseControl { name: "g".into(), ..Default::default() }, [0; 6]).unwrap();
    assert!(p.shared.state.lock().unwrap().nds_com);
}

/// sqNum rolls over to 1, not 0.
#[tokio::test]
async fn sq_num_rolls_over_to_one() {
    let (p, cap) = test_publisher(PublisherConfig {
        retrans: vec![Duration::from_millis(1)],
        ..Default::default()
    });
    let generation = p.shared.state.lock().unwrap().generation;
    let msg = Message {
        go_cb_ref: p.shared.cfg.go_cb_ref.clone(),
        st_num: 1,
        sq_num: u32::MAX - 1,
        ..Default::default()
    };
    let task = tokio::spawn(retransmit(p.shared.clone(), msg, generation));
    for _ in 0..500 {
        if cap.messages().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    let m = cap.messages();
    assert_eq!((m[0].sq_num, m[1].sq_num), (u32::MAX, 1));
}

/// set_test and set_nds_com take effect from the next publish or refresh.
#[tokio::test]
async fn set_test_and_nds_com() {
    let (p, cap) = test_publisher(PublisherConfig::default());
    p.publish(Vec::new()).unwrap();
    p.set_test(true);
    p.set_nds_com(true);
    p.refresh(Vec::new()).unwrap();
    p.set_test(false);
    p.publish(Vec::new()).unwrap();
    let m = cap.messages();
    let flags: Vec<(bool, bool)> = m.iter().map(|m| (m.test, m.nds_com)).collect();
    assert_eq!(flags, [(false, false), (true, true), (false, true)]);
    assert_eq!(m[1].st_num, m[0].st_num);
}

/// Without a goID the control block reference goes in its place.
#[tokio::test]
async fn go_id_defaults_to_the_control_block_reference() {
    let (p, cap) = test_publisher(PublisherConfig {
        go_cb_ref: "LD/LLN0$GO$gcb01".into(),
        ..Default::default()
    });
    p.publish(Vec::new()).unwrap();
    assert_eq!(cap.messages()[0].go_id, "LD/LLN0$GO$gcb01");
}

/// A data set too large for one frame is refused, and the refusal leaves the
/// state being advertised as it was.
#[tokio::test]
async fn an_oversized_frame_is_refused() {
    let (p, cap) = test_publisher(PublisherConfig {
        retrans: vec![Duration::from_millis(5)],
        ..Default::default()
    });
    p.publish(vec![Value::boolean(true)]).unwrap();
    p.publish(vec![Value::boolean(false); 400]).expect("400 members fit");
    let before = p.state().0;
    let huge = vec![Value::boolean(false); 600];
    assert!(matches!(p.publish(huge.clone()), Err(Error::FrameTooLarge(_))));
    assert!(matches!(p.refresh(huge), Err(Error::FrameTooLarge(_))));
    assert_eq!(p.state().0, before);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(cap.frames.lock().unwrap().iter().all(|f| f.payload.len() <= MAX_PAYLOAD));
    let last = cap.messages().pop().unwrap();
    assert_eq!(last.st_num, before);
    assert_ne!(last.sq_num, 0, "the advertised state's retransmission stopped");
}

/// Both counters roll over to 1, which is neither a gap nor a regression.
#[test]
fn a_subscriber_accepts_the_rollover() {
    let mut tr = SequenceTracker::new();
    let now = std::time::Instant::now();
    let msg = |st_num, sq_num| Message {
        go_cb_ref: "LD/LLN0$GO$gcb01".into(),
        st_num,
        sq_num,
        time_allowed_to_live: 60_000,
        ..Default::default()
    };
    tr.observe(&msg(3, u32::MAX), now);
    assert!(!tr.observe(&msg(3, 1), now).sq_num_gap);
    tr.observe(&msg(u32::MAX, 0), now);
    assert!(!tr.observe(&msg(1, 0), now).st_num_regressed);
}
