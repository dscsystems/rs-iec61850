//! R-GOOSE and R-SV sessions over real UDP sockets: secured exchange, the
//! receive policy, replay protection, multicast, and the GOOSE and SV
//! publishers and subscribers running over a session.

use std::net::UdpSocket;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iec61850::ethernet::{Frame, Interface, ETHER_TYPE_SV};
use iec61850::mms::Value;
use iec61850::rsession::{
    self, Config, Error, Key, KeyStore, Payload, PayloadType, SecAlgorithm, Session, SessionId,
    SigAlgorithm, Spdu,
};
use iec61850::{goose, sv};

const KEY16: &[u8; 16] = b"0123456789ABCDEF";

fn hmac(id: u32) -> Key {
    Key {
        id,
        material: KEY16.to_vec(),
        sig: SigAlgorithm::HMAC_SHA256_128,
        ..Default::default()
    }
}

fn keys(ks: impl IntoIterator<Item = Key>) -> Option<Arc<KeyStore>> {
    Some(Arc::new(KeyStore::with_keys(ks).unwrap()))
}

/// Opens a receiving session on a free loopback port and a sending one aimed
/// at it.
fn pair(mut rx: Config, mut tx: Config) -> (Arc<Session>, Arc<Session>) {
    rx.listen = "127.0.0.1:0".into();
    let recv = Session::open(rx).unwrap();
    tx.remote = recv.local_addr().unwrap().to_string();
    let send = Session::open(tx).unwrap();
    (Arc::new(recv), Arc::new(send))
}

fn receive(s: &Session) -> Spdu {
    s.receive_timeout(Duration::from_secs(2))
        .unwrap()
        .expect("nothing received")
        .0
}

fn goose_payload() -> Payload {
    Payload {
        kind: PayloadType::GOOSE,
        apdu: vec![0x61, 0],
        ..Default::default()
    }
}

#[test]
fn a_secured_exchange() {
    for k in [
        hmac(7),
        Key {
            id: 7,
            material: KEY16.to_vec(),
            sec: SecAlgorithm::AES_128_GCM,
            ..Default::default()
        },
    ] {
        let (recv, send) = pair(
            Config { keys: keys([k.clone()]), ..Default::default() },
            Config { keys: keys([k.clone()]), ..Default::default() },
        );
        let apdu = vec![0x61, 0x02, 0x80, 0x00];
        send.send(
            SessionId::GOOSE,
            vec![Payload {
                kind: PayloadType::GOOSE,
                app_id: 1,
                apdu: apdu.clone(),
                ..Default::default()
            }],
        )
        .unwrap();
        let got = receive(&recv);
        assert_eq!(got.key_id, 7, "{k:?}");
        assert_eq!(got.payloads.len(), 1);
        assert_eq!(got.payloads[0].apdu, apdu);
    }
}

/// A receiver refuses unsecured SPDUs unless told otherwise, and SPDUs under
/// keys it does not hold, and says why.
#[test]
fn the_receive_policy() {
    let rejected: Arc<Mutex<Vec<String>>> = Arc::default();
    let r = rejected.clone();
    let recv = Session::open(Config {
        listen: "127.0.0.1:0".into(),
        keys: keys([hmac(1)]),
        on_reject: Some(Arc::new(move |rej: &rsession::Reject| {
            r.lock().unwrap().push(format!("{:?}", rej.err))
        })),
        ..Default::default()
    })
    .unwrap();
    let to = recv.local_addr().unwrap().to_string();
    let send = |ks: Option<Arc<KeyStore>>| {
        let s = Session::open(Config {
            remote: to.clone(),
            keys: ks,
            ..Default::default()
        })
        .unwrap();
        s.send(SessionId::GOOSE, vec![goose_payload()]).unwrap();
    };
    send(None);
    send(keys([hmac(2)]));
    send(keys([Key {
        material: vec![9; 16],
        ..hmac(1)
    }]));
    send(keys([hmac(1)]));
    assert_eq!(receive(&recv).key_id, 1);
    let st = recv.stats();
    assert_eq!(
        (st.unsecured, st.unknown_key, st.unauthentic, st.accepted),
        (1, 1, 1, 1),
        "{st:?}"
    );
    let rejected = rejected.lock().unwrap();
    assert_eq!(rejected.len(), 3, "{rejected:?}");
    assert!(rejected[0].starts_with("Unsecured"));
    assert!(rejected[1].starts_with("UnknownKey"));
    assert!(rejected[2].starts_with("Authentication"));

    // Unsecured traffic is accepted when the receiver allows it.
    let (open, send2) = pair(
        Config {
            allow_unsecured: true,
            ..Default::default()
        },
        Config::default(),
    );
    send2
        .send(
            SessionId::SV,
            vec![Payload {
                kind: PayloadType::SV,
                apdu: vec![0x60, 0],
                ..Default::default()
            }],
        )
        .unwrap();
    let got = receive(&open);
    assert_eq!((got.key_id, got.si), (0, SessionId::SV));
}

/// A captured secured SPDU sent again is refused.
#[test]
fn a_replay_is_refused() {
    let k = hmac(1);
    let recv = Session::open(Config {
        listen: "127.0.0.1:0".into(),
        keys: keys([k.clone()]),
        ..Default::default()
    })
    .unwrap();
    let b = rsession::marshal(
        &Spdu {
            si: SessionId::GOOSE,
            number: 10,
            payloads: vec![goose_payload()],
            ..Default::default()
        },
        Some(&k),
    )
    .unwrap();
    let c = UdpSocket::bind("127.0.0.1:0").unwrap();
    for _ in 0..3 {
        c.send_to(&b, recv.local_addr().unwrap()).unwrap();
    }
    assert_eq!(receive(&recv).number, 10);
    assert!(recv.receive_timeout(Duration::from_millis(300)).unwrap().is_none());
    let st = recv.stats();
    assert_eq!((st.replayed, st.accepted), (2, 1), "{st:?}");
}

/// A session with keys but no active one sends nothing.
#[test]
fn no_active_key_sends_nothing() {
    let store = Arc::new(KeyStore::new());
    let s = Session::open(Config {
        remote: "127.0.0.1:9".into(),
        keys: Some(store.clone()),
        ..Default::default()
    })
    .unwrap();
    assert!(matches!(
        s.send(SessionId::GOOSE, vec![goose_payload()]),
        Err(Error::NoActiveKey)
    ));
    store.add(hmac(4)).unwrap();
    store.set_active(4).unwrap();
    s.send(SessionId::GOOSE, vec![goose_payload()]).unwrap();
}

/// The GOOSE publisher and subscriber of this crate run over a session as
/// they do over Ethernet, retransmissions included.
#[tokio::test(flavor = "multi_thread")]
async fn goose_over_a_session() {
    let k = Key {
        id: 3,
        material: KEY16.to_vec(),
        sec: SecAlgorithm::AES_128_GCM,
        ..Default::default()
    };
    let (recv, send) = pair(
        Config { keys: keys([k.clone()]), ..Default::default() },
        Config { keys: keys([k]), ..Default::default() },
    );
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sub = goose::Subscriber::new(recv.clone()).subscribe(
        goose::Filter {
            go_cb_ref: "IED1LD0/LLN0$GO$gcb1".into(),
            ..Default::default()
        },
        move |m| {
            let _ = tx.lock().unwrap().send(m.clone());
        },
    );
    let publisher = goose::Publisher::new(
        send.clone(),
        goose::PublisherConfig {
            app_id: 0x3001,
            go_cb_ref: "IED1LD0/LLN0$GO$gcb1".into(),
            dat_set: "IED1LD0/LLN0$DS1".into(),
            conf_rev: 1,
            retrans: vec![Duration::from_millis(20)],
            ..Default::default()
        },
    )
    .unwrap();
    publisher
        .publish(vec![Value::boolean(true), Value::int32(1234)])
        .unwrap();
    for i in 0..2u32 {
        let m = rx.recv_timeout(Duration::from_secs(2)).expect("a message");
        assert_eq!((m.app_id, m.st_num, m.sq_num), (0x3001, 1, i));
        assert!(m.values[0].as_bool());
        assert_eq!(m.values[1].as_i64(), 1234);
    }
    publisher.close();
    sub.stop();
    recv.shutdown();
}

#[test]
fn sv_over_a_session() {
    let k = Key {
        id: 4,
        material: vec![3; 32],
        sig: SigAlgorithm::HMAC_SHA256_256,
        ..Default::default()
    };
    let (recv, send) = pair(
        Config { keys: keys([k.clone()]), ..Default::default() },
        Config { keys: keys([k]), ..Default::default() },
    );
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sub = sv::Subscriber::new(recv.clone()).subscribe(sv::Filter::any(), move |a| {
        let _ = tx.lock().unwrap().send(a.clone());
    });
    let pdu = sv::Pdu {
        app_id: 0x4001,
        asdus: vec![sv::Asdu {
            sv_id: "RSV1".into(),
            smp_cnt: 17,
            conf_rev: 1,
            sample: vec![1, 2, 3, 4],
            ..Default::default()
        }],
    };
    send.write_frame(&Frame {
        src: [0; 6],
        dst: [0; 6],
        ether_type: ETHER_TYPE_SV,
        vlan: None,
        payload: pdu.marshal(),
    })
    .unwrap();
    let a = rx.recv_timeout(Duration::from_secs(2)).expect("an ASDU");
    assert_eq!((a.sv_id.as_str(), a.smp_cnt), ("RSV1", 17));
    assert_eq!(a.sample, [1, 2, 3, 4]);
    sub.stop();
    recv.shutdown();
}

/// A session joined to a multicast group receives what is sent to it. Skipped
/// where the host has no multicast route.
#[test]
fn multicast() {
    let port = UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let group = format!("239.255.61.50:{port}");
    let Ok(rx) = Session::open(Config {
        groups: vec![group.clone()],
        keys: keys([hmac(1)]),
        ..Default::default()
    }) else {
        eprintln!("cannot join a multicast group here; skipped");
        return;
    };
    let tx = Session::open(Config {
        remote: group,
        keys: keys([hmac(1)]),
        ttl: 2,
        ..Default::default()
    })
    .unwrap();
    for _ in 0..5 {
        if tx.send(SessionId::GOOSE, vec![goose_payload()]).is_err() {
            eprintln!("cannot send multicast here; skipped");
            return;
        }
        if let Some((s, _)) = rx.receive_timeout(Duration::from_millis(200)).unwrap() {
            assert!(s.key_id == 1 && s.signed, "{s:?}");
            return;
        }
    }
    eprintln!("multicast is not looped back on this host; skipped");
}
