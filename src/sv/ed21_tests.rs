//! IEC 61850-9-2 Edition 2 and Amendment 1 behaviour: smpMod, gmIdentity, the
//! optional ASDU fields, several ASDUs per frame, the 9-2LE quality word, and
//! publishers built from a model.

use std::sync::Mutex;

use super::*;
use crate::asn1::{cons, context_constructed, context_primitive, prim, uint_elem};
use crate::ethernet::{self, Frame};
use crate::model::{LogicalDevice, LogicalNode, Quality, SvControl, SvOpts, Validity};
use crate::sv::pdu::{sav_pdu_tag, HEADER_LEN};
use crate::sv::{decode_le_sample, parse};

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

fn publisher(cfg: LeConfig) -> LePublisher {
    LePublisher::new(Arc::new(Capture::default()), cfg).unwrap()
}

fn mu1() -> LeConfig {
    LeConfig {
        sv_id: "MU1".into(),
        ..Default::default()
    }
}

/// The quality word orientation is pinned by the masks Wireshark decodes and
/// libiec61850 writes under 9-2:2011.
#[test]
fn the_le_quality_word_orientation() {
    let invalid = Quality::GOOD.with_validity(Validity::Invalid);
    for (name, word, want) in [
        ("invalid", 0x0002, invalid),
        ("invalid, first 9-2LE guideline", 0x0001, invalid),
        ("questionable", 0x0003, Quality::GOOD.with_validity(Validity::Questionable)),
        ("overflow", 0x0004, Quality::OVERFLOW),
        ("substituted", 0x0400, Quality::SUBSTITUTED),
        ("test", 0x0800, Quality::TEST),
        ("operator blocked", 0x1000, Quality::OPERATOR_BLOCKED),
        ("derived is outside the 13 bits", 0x2000, Quality::GOOD),
        ("all clear", 0x0000, Quality::GOOD),
    ] {
        let mut s = LeSample::default();
        s.q[0] = word;
        assert_eq!(s.quality(0), want, "{name}: word {word:04x}");
    }
    let mut s = LeSample::default();
    s.set_quality(0, invalid | Quality::TEST);
    assert_eq!(s.q[0], 0x0802);
}

/// The quality round-trips, and the reserved bits survive a quality write.
#[test]
fn the_le_quality_round_trips() {
    let mut s = LeSample::default();
    s.i[0] = 1234;
    s.set_quality(0, Quality(1 << 11 | 1 << 2));
    s.q[0] |= 0x2000;
    let got = decode_le_sample(&encode_le_sample(&s)).unwrap();
    assert_ne!(got.q[0] & 0x2000, 0, "the derived bit was lost");
    assert_eq!(got.quality(0), Quality(1 << 11 | 1 << 2));
    assert_eq!(got.i[0], 1234);
    // A quality write leaves the derived bit alone.
    let mut s = got;
    s.set_quality(0, Quality::GOOD);
    assert_eq!(s.q[0], 0x2000);
}

fn asdu_with(smp_mod: Option<SmpMod>) -> Asdu {
    Asdu {
        sv_id: "MU1".into(),
        conf_rev: 1,
        smp_cnt: 7,
        smp_synch: SMP_SYNCH_GLOBAL,
        smp_rate: 4000,
        smp_mod,
        sample: vec![0; 4],
        ..Default::default()
    }
}

/// smpMod round-trips, including mode 0, which is a mode and not absence, and
/// an Edition 1 stream without it still parses.
#[test]
fn smp_mod_round_trips() {
    for m in [None, Some(SmpMod::SmpPerPeriod), Some(SmpMod::SmpPerSec), Some(SmpMod::SecPerSmp)] {
        let raw = Pdu {
            app_id: 0x4000,
            asdus: vec![asdu_with(m)],
        }
        .marshal();
        let got = parse(&raw).unwrap().asdus.remove(0);
        assert_eq!(got.smp_mod, m);
        assert_eq!((got.smp_rate, got.smp_cnt, got.sv_id.as_str()), (4000, 7, "MU1"));
    }
}

/// The wire values are the standard's, as a two-octet field after the sample.
#[test]
fn smp_mod_wire_values() {
    for (m, wire) in [
        (SmpMod::SmpPerPeriod, [0x88, 0x02, 0x00, 0x00]),
        (SmpMod::SmpPerSec, [0x88, 0x02, 0x00, 0x01]),
        (SmpMod::SecPerSmp, [0x88, 0x02, 0x00, 0x02]),
    ] {
        let a = Asdu {
            sv_id: "MU1".into(),
            conf_rev: 1,
            sample: vec![0xde, 0xad],
            smp_mod: Some(m),
            ..Default::default()
        };
        let raw = Pdu {
            app_id: 0x4000,
            asdus: vec![a],
        }
        .marshal();
        let mut tail = vec![0x87, 0x02, 0xde, 0xad];
        tail.extend_from_slice(&wire);
        assert!(raw.ends_with(&tail), "{m}: {raw:02x?}");
    }
}

/// The publisher emits only the optional fields its configuration asks for.
#[test]
fn the_publisher_emits_only_the_fields_asked_for() {
    for (opts, want) in [
        (AsduOpts::default(), false),
        (
            AsduOpts {
                sample_rate: true,
                refresh_time: true,
                data_set: true,
                smp_mod: true,
                synch_source_id: false,
            },
            true,
        ),
    ] {
        let p = publisher(LeConfig {
            dat_set: "PhsMeas1".into(),
            smp_mod: SmpMod::SmpPerSec,
            opts,
            ..mu1()
        });
        let a = p.asdu(&LeSample {
            smp_cnt: 1,
            smp_synch: SMP_SYNCH_GLOBAL,
            ..Default::default()
        });
        assert_eq!(a.smp_rate != 0, want);
        assert_eq!(a.refr_tm.is_some(), want);
        assert_eq!(!a.dat_set.is_empty(), want);
        assert_eq!(a.smp_mod, want.then_some(SmpMod::SmpPerSec));
        if let Some(t) = a.refr_tm {
            assert!(SystemTime::now().duration_since(t).unwrap_or_default() < Duration::from_secs(60));
        }
    }
}

/// refrTm carries the publisher's clock quality, 0 included.
#[test]
fn refr_tm_carries_the_clock_quality() {
    let lost = TimeQuality(TimeQuality::CLOCK_NOT_SYNCHRONIZED.0 | TimeQuality::ACCURACY_UNSPECIFIED.0);
    for q in [None, Some(lost), Some(TimeQuality(0))] {
        let p = publisher(LeConfig {
            time_quality: q,
            opts: AsduOpts {
                refresh_time: true,
                ..Default::default()
            },
            ..mu1()
        });
        let raw = Pdu {
            app_id: 0x4000,
            asdus: vec![p.asdu(&LeSample::default())],
        }
        .marshal();
        let got = parse(&raw).unwrap().asdus.remove(0);
        assert_eq!(got.refr_tm_quality, Some(q.unwrap_or(TimeQuality::DEFAULT)));
    }
}

/// smpRate is in the unit smpMod names.
#[test]
fn smp_rate_follows_smp_mod() {
    for (m, opts, want) in [
        (SmpMod::SmpPerPeriod, AsduOpts { sample_rate: true, ..Default::default() }, 80),
        (SmpMod::SmpPerPeriod, AsduOpts { sample_rate: true, smp_mod: true, ..Default::default() }, 80),
        (SmpMod::SmpPerSec, AsduOpts { sample_rate: true, smp_mod: true, ..Default::default() }, 4000),
    ] {
        let p = publisher(LeConfig {
            samples_per_cycle: 80,
            nominal_hz: 50,
            smp_mod: m,
            opts,
            ..mu1()
        });
        assert_eq!(p.asdu(&LeSample::default()).smp_rate, want, "{m}");
    }
    assert!(LePublisher::new(
        Arc::new(Capture::default()),
        LeConfig {
            smp_mod: SmpMod::SecPerSmp,
            ..mu1()
        }
    )
    .is_err());
}

/// gmIdentity round-trips, follows set_gm_identity, and a wrong length is an
/// error.
#[test]
fn gm_identity() {
    let id = [0x00, 0x1b, 0x19, 0xff, 0xfe, 0x01, 0x02, 0x03];
    let p = publisher(LeConfig {
        gm_identity: id,
        opts: AsduOpts {
            synch_source_id: true,
            ..Default::default()
        },
        ..mu1()
    });
    let a = p.asdu(&LeSample::default());
    let raw = Pdu {
        app_id: 0x4000,
        asdus: vec![a.clone()],
    }
    .marshal();
    assert_eq!(parse(&raw).unwrap().asdus[0].gm_identity, Some(id));
    let id2 = [8, 7, 6, 5, 4, 3, 2, 1];
    p.set_gm_identity(id2);
    assert_eq!(p.asdu(&LeSample::default()).gm_identity, Some(id2));
    let off = publisher(LeConfig {
        gm_identity: id,
        ..mu1()
    });
    assert_eq!(off.asdu(&LeSample::default()).gm_identity, None);

    let mut el = Asdu {
        gm_identity: None,
        ..a
    }
    .element();
    el.push(prim(context_primitive(9), vec![1, 2, 3]));
    let sav = cons(
        sav_pdu_tag(),
        [uint_elem(context_primitive(0), 1), cons(context_constructed(2), [el])],
    );
    let n = HEADER_LEN + sav.size();
    let mut raw = vec![0x40, 0, (n >> 8) as u8, n as u8, 0, 0, 0, 0];
    sav.append(&mut raw);
    assert!(parse(&raw).is_err(), "a 3-octet gmIdentity parsed");
}

/// With no_asdu above 1, a frame carries that many consecutive samples,
/// oldest first.
#[tokio::test]
async fn several_asdus_per_frame() {
    let cap = Arc::new(Capture::default());
    let p = LePublisher::new(
        cap.clone(),
        LeConfig {
            samples_per_cycle: 256,
            nominal_hz: 50,
            no_asdu: 8,
            ..mu1()
        },
    )
    .unwrap();
    p.run(|_, _| {}, tokio::time::sleep(Duration::from_millis(50)))
        .await
        .unwrap();
    let frames = cap.frames.lock().unwrap();
    assert!(!frames.is_empty());
    let pdu = parse(&frames[0].payload).unwrap();
    assert_eq!(pdu.asdus.len(), 8);
    for (i, a) in pdu.asdus.iter().enumerate() {
        assert_eq!(usize::from(a.smp_cnt), i);
    }
}

fn mu01() -> (LogicalDevice, LogicalNode, SvControl) {
    (
        LogicalDevice {
            name: "MU01LD0".into(),
            ..Default::default()
        },
        LogicalNode {
            name: "LLN0".into(),
            ..Default::default()
        },
        SvControl {
            name: "MSVCB01".into(),
            sv_id: "MU01".into(),
            data_set: "PhsMeas1".into(),
            conf_rev: 2,
            smp_rate: 4800,
            smp_mod: SmpMod::SmpPerSec,
            no_asdu: 2,
            multicast: true,
            opts: SvOpts {
                sample_rate: true,
                data_set: true,
                synch_source_id: true,
                ..Default::default()
            },
            dst_mac: [1, 0x0c, 0xcd, 4, 0, 1],
            app_id: 0x4001,
            vlan_id: 5,
            vlan_pri: 4,
            ..Default::default()
        },
    )
}

/// The publisher built from a model follows its SmvOpts, rate, mode and
/// addressing, and refuses what it cannot honour.
#[test]
fn a_publisher_from_the_model() {
    let (ld, ln, sc) = mu01();
    let p = LePublisher::from_model(Arc::new(Capture::default()), &ld, &ln, &sc, [0; 6], 60).unwrap();
    assert_eq!((p.sample_rate(), p.cfg.samples_per_cycle, p.cfg.no_asdu), (4800, 80, 2));
    assert_eq!(p.cfg.vlan.map(|v| v.vid), Some(5));
    assert_eq!((p.cfg.app_id, p.cfg.dst_mac), (0x4001, sc.dst_mac));
    let a = p.asdu(&LeSample::default());
    assert_eq!(a.dat_set, "MU01LD0/LLN0$PhsMeas1");
    assert_eq!(a.smp_rate, 4800);
    assert_eq!(a.smp_mod, Some(SmpMod::SmpPerSec));
    assert!(a.gm_identity.is_some());
    assert!(a.refr_tm.is_none());

    type Mutation = (&'static str, fn(&mut SvControl));
    let cases: [Mutation; 4] = [
        ("unicast to a group", |s| s.multicast = false),
        ("security", |s| s.opts.security = true),
        ("SecPerSmp", |s| s.smp_mod = SmpMod::SecPerSmp),
        ("fractional rate", |s| s.smp_rate = 4000),
    ];
    for (name, mutate) in cases {
        let mut bad = sc.clone();
        mutate(&mut bad);
        assert!(
            LePublisher::from_model(Arc::new(Capture::default()), &ld, &ln, &bad, [0; 6], 60).is_err(),
            "{name}: accepted"
        );
    }
}

/// A unicast block (a USVCB) is published to its individual DstAddress, in
/// the same frame format as a multicast one.
#[test]
fn a_unicast_publisher_from_the_model() {
    let (ld, ln, _) = mu01();
    let sc = SvControl {
        name: "USVCB01".into(),
        sv_id: "MU01U".into(),
        conf_rev: 1,
        smp_rate: 80,
        dst_mac: [0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e],
        app_id: 0x4002,
        ..Default::default()
    };
    let cap = Arc::new(Capture::default());
    let p = LePublisher::from_model(cap.clone(), &ld, &ln, &sc, [2, 0, 0, 0, 0, 1], 50).unwrap();
    p.emit(&LeSample {
        smp_cnt: 7,
        ..Default::default()
    })
    .unwrap();
    let frames = cap.frames.lock().unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].dst, sc.dst_mac);
    let pdu = parse(&frames[0].payload).unwrap();
    assert_eq!((pdu.app_id, pdu.asdus.len()), (0x4002, 1));
    assert_eq!((pdu.asdus[0].sv_id.as_str(), pdu.asdus[0].smp_cnt), ("MU01U", 7));
}
