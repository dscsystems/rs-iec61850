//! Drives an R-GOOSE/R-SV peer with the command line of libiec61850's
//! interop/c/rsession_peer.c, which the Go peer shares.

use super::*;
use std::sync::{Arc, Mutex};
use iec61850::ethernet::{Frame, Interface, ETHER_TYPE_SV};
use iec61850::rsession::{Config, Key, KeyStore, SecAlgorithm, Session, SigAlgorithm};
use iec61850::{goose, sv};

pub const KEY16: &[u8] = b"0123456789ABCDEF";
pub const KEY32: [u8; 32] = [0x5a; 32];

pub fn key(sec: SecAlgorithm, sig: SigAlgorithm, material: &[u8]) -> Option<Key> {
    Some(Key {
        id: 1,
        material: material.to_vec(),
        sec,
        sig,
        ..Default::default()
    })
}

/// What libiec61850 publishes: unsecured, HMAC-SHA256-128, AES-GCM. (Its
/// HMAC-SHA256-256 has a length octet of 16 before a 32-octet MAC, which no
/// receiver can take.)
pub fn from_libiec() -> Vec<(&'static str, Option<Key>)> {
    vec![
        ("unsecured", None),
        ("HMAC-SHA256-128", key(SecAlgorithm::NONE, SigAlgorithm::HMAC_SHA256_128, KEY16)),
        ("AES-128-GCM", key(SecAlgorithm::AES_128_GCM, SigAlgorithm::NONE, KEY16)),
        ("AES-256-GCM", key(SecAlgorithm::AES_256_GCM, SigAlgorithm::NONE, &KEY32)),
    ]
}

/// What libiec61850 receives; it refuses a version 2 SPDU without a key.
pub fn to_libiec() -> Vec<(&'static str, Option<Key>)> {
    vec![
        ("HMAC-SHA256-128", key(SecAlgorithm::NONE, SigAlgorithm::HMAC_SHA256_128, KEY16)),
        ("HMAC-SHA256-256", key(SecAlgorithm::NONE, SigAlgorithm::HMAC_SHA256_256, &KEY32)),
        ("AES-128-GCM", key(SecAlgorithm::AES_128_GCM, SigAlgorithm::NONE, KEY16)),
        ("AES-256-GCM", key(SecAlgorithm::AES_256_GCM, SigAlgorithm::NONE, &KEY32)),
    ]
}

fn peer_args(k: &Option<Key>) -> Vec<String> {
    match k {
        None => vec!["0".into(), "-".into(), "0".into(), "0".into()],
        Some(k) => vec![
            "1".into(),
            k.material.iter().map(|b| format!("{b:02x}")).collect(),
            k.sec.0.to_string(),
            k.sig.0.to_string(),
        ],
    }
}

fn config(k: &Option<Key>) -> Config {
    match k {
        None => Config {
            allow_unsecured: true,
            ..Default::default()
        },
        Some(k) => Config {
            keys: Some(Arc::new(KeyStore::with_keys([k.clone()]).unwrap())),
            ..Default::default()
        },
    }
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn floats(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_be_bytes()).collect()
}

async fn run_peer(bin: &str, args: Vec<String>) -> (String, bool) {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    run(bin, &a, None, Duration::from_secs(10)).await
}

/// Starts a subscribing peer and waits until it listens.
async fn start_subscriber(bin: &str, args: Vec<String>) -> (tokio::process::Child, Arc<Mutex<String>>) {
    let mut child = Command::new(bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let out: Arc<Mutex<String>> = Arc::default();
    for stream in [
        Box::new(child.stdout.take().unwrap()) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
        Box::new(child.stderr.take().unwrap()),
    ] {
        let out = out.clone();
        tokio::spawn(async move {
            let mut stream = stream;
            let mut buf = [0u8; 4096];
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                out.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
    }
    for _ in 0..300 {
        if out.lock().unwrap().contains("listening") {
            return (child, out);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the peer never listened: {}", out.lock().unwrap());
}

async fn finish(mut child: tokio::process::Child, out: Arc<Mutex<String>>) -> (String, bool) {
    let ok = tokio::time::timeout(Duration::from_secs(8), child.wait())
        .await
        .ok()
        .and_then(|r| r.ok())
        .is_some_and(|s| s.success());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let text = out.lock().unwrap().clone();
    (text, ok)
}

/// Runs the exchange against the peer `bin` in each mode.
pub async fn goose_from(bin: &str, modes: Vec<(&'static str, Option<Key>)>) {
    for (name, k) in modes {
        let s = Arc::new(Session::open(Config { listen: "127.0.0.1:0".into(), ..config(&k) }).unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let sub = goose::Subscriber::new(s.clone()).subscribe(
            goose::Filter { go_cb_ref: "GOISIM/LLN0$GO$gcb1".into(), ..Default::default() },
            move |m| {
                let _ = tx.lock().unwrap().send(m.clone());
            },
        );
        let port = s.local_addr().unwrap().port().to_string();
        let mut args = vec!["goose-pub".into(), "127.0.0.1".into(), port];
        args.extend(peer_args(&k));
        args.push("3".into());
        let (out, ok) = run_peer(bin, args).await;
        assert!(ok, "{name}: peer: {out}");
        for i in 0..3 {
            let m = rx.recv_timeout(Duration::from_secs(3))
                .unwrap_or_else(|_| panic!("{name}: message {i} not received; {:?}", s.stats()));
            assert_eq!(m.app_id, 0x3001, "{name}");
            assert_eq!(m.values.len(), 3, "{name}");
            assert_eq!(m.values[0].as_i64(), 1234);
            assert!(m.values[1].as_bool());
            assert_eq!(m.values[2].text(), "r-goose");
        }
        sub.stop();
        s.shutdown();
    }
}

/// Runs the exchange against the peer `bin` in each mode.
pub async fn goose_to(bin: &str, modes: Vec<(&'static str, Option<Key>)>) {
    for (name, k) in modes {
        let port = free_udp_port();
        let mut args = vec!["goose-sub".into(), "127.0.0.1".into(), port.to_string()];
        args.extend(peer_args(&k));
        args.push("3".into());
        let (child, out) = start_subscriber(bin, args).await;
        let s = Arc::new(Session::open(Config { remote: format!("127.0.0.1:{port}"), ..config(&k) }).unwrap());
        let p = goose::Publisher::new(
            s.clone(),
            goose::PublisherConfig {
                app_id: 0x3001,
                go_cb_ref: "GOISIM/LLN0$GO$gcb1".into(),
                dat_set: "GOISIM/LLN0$DS1".into(),
                go_id: "GOISIM".into(),
                conf_rev: 1,
                retrans: vec![Duration::from_millis(50)],
                ..Default::default()
            },
        )
        .unwrap();
        p.publish(vec![Value::int32(1234), Value::boolean(true), Value::visible_string("r-goose")]).unwrap();
        let (text, ok) = finish(child, out).await;
        p.close();
        assert!(ok, "{name}: libiec61850 did not receive 3 messages:\n{text}");
        assert!(text.contains("GOOSE st=1 sq=0 valid=1"), "{name}:\n{text}");
        assert!(text.contains("1234,true,r-goose"), "{name}:\n{text}");
    }
}

/// Runs the exchange against the peer `bin` in each mode.
pub async fn sv_from(bin: &str, modes: Vec<(&'static str, Option<Key>)>) {
    for (name, k) in modes {
        let s = Arc::new(Session::open(Config { listen: "127.0.0.1:0".into(), ..config(&k) }).unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let sub = sv::Subscriber::new(s.clone()).subscribe(sv::Filter::any(), move |a| {
            let _ = tx.lock().unwrap().send(a.clone());
        });
        let port = s.local_addr().unwrap().port().to_string();
        let mut args = vec!["sv-pub".into(), "127.0.0.1".into(), port];
        args.extend(peer_args(&k));
        args.push("3".into());
        let (out, ok) = run_peer(bin, args).await;
        assert!(ok, "{name}: peer: {out}");
        for i in 0..3u16 {
            let a = rx.recv_timeout(Duration::from_secs(3))
                .unwrap_or_else(|_| panic!("{name}: ASDU {i} not received; {:?}", s.stats()));
            assert_eq!((a.sv_id.as_str(), a.smp_cnt), ("RSV1", i), "{name}");
            assert_eq!(a.sample, floats(&[1.5, -2.25]), "{name}");
        }
        sub.stop();
        s.shutdown();
    }
}

/// Runs the exchange against the peer `bin` in each mode.
pub async fn sv_to(bin: &str, modes: Vec<(&'static str, Option<Key>)>) {
    for (name, k) in modes {
        let port = free_udp_port();
        let mut args = vec!["sv-sub".into(), "127.0.0.1".into(), port.to_string()];
        args.extend(peer_args(&k));
        args.push("3".into());
        let (child, out) = start_subscriber(bin, args).await;
        let s = Session::open(Config { remote: format!("127.0.0.1:{port}"), ..config(&k) }).unwrap();
        for i in 0..3u16 {
            let pdu = sv::Pdu {
                app_id: 0x4001,
                asdus: vec![sv::Asdu {
                    sv_id: "RSV1".into(),
                    smp_cnt: i,
                    conf_rev: 1,
                    sample: floats(&[1.5, -2.25]),
                    ..Default::default()
                }],
            };
            s.write_frame(&Frame { src: [0; 6], dst: [0; 6], ether_type: ETHER_TYPE_SV, vlan: None, payload: pdu.marshal() })
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (text, ok) = finish(child, out).await;
        assert!(ok, "{name}: libiec61850 did not receive 3 ASDUs:\n{text}");
        for i in 0..3 {
            assert!(text.contains(&format!("SV svID=RSV1 smpCnt={i} v0=1.5 v1=-2.25")), "{name}:\n{text}");
        }
    }
}
