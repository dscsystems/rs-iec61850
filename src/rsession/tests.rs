//! SPDU codec, key and replay tests, with SPDUs captured from libiec61850.

use std::time::{Duration, Instant};

use super::replay::ReplayWindow;
use super::spdu::{COMMON_LEN, GCM_IV_LEN};
use super::*;

fn unhex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect()
}

/// The key the libiec61850 vectors were made with.
const TEST_KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

fn hmac_key(id: u32, material: &[u8], sig: SigAlgorithm) -> Key {
    Key { id, material: material.to_vec(), sig, ..Default::default() }
}

fn gcm_key(id: u32, material: &[u8], sec: SecAlgorithm) -> Key {
    Key { id, material: material.to_vec(), sec, ..Default::default() }
}

fn store(keys: impl IntoIterator<Item = Key>) -> KeyStore {
    KeyStore::with_keys(keys).unwrap()
}

// SPDUs sent by libiec61850 1.6's R-GOOSE publisher, captured from the wire.
// Each carries one goosePdu for "GOISIM/LLN0$GO$gcb1" with the data set
// {1234, true, "r-goose"}, APPID 0x3001, protocol version 2. libiec61850
// writes the element's APDU length two more than the APDU, and fixed header
// lengths whatever the security information holds.
const LIBIEC_UNSECURED: &str = "01 40 a1 18 80 12 00 00 00 7c 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 68 81 00 30 01 00 64 61 60 80 13 47 4f 49 53 49 4d 2f 4c 4c 4e 30 24 47 4f 24 67 63 62 31 81 02 07 d0 82 0f 47 4f 49 53 49 4d 2f 4c 4c 4e 30 24 44 53 31 83 06 47 4f 49 53 49 4d 84 08 6a bb ff 92 dc 6a 7e 0a 85 01 01 86 01 00 87 01 00 88 01 01 89 01 00 8a 01 03 ab 10 85 02 04 d2 83 01 01 8a 07 72 2d 67 6f 6f 73 65";
/// Key 1, HMAC-SHA256-128.
const LIBIEC_HMAC128: &str = "01 40 a1 18 80 12 00 00 00 7c 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 01 00 00 00 00 68 81 00 30 01 00 64 61 60 80 13 47 4f 49 53 49 4d 2f 4c 4c 4e 30 24 47 4f 24 67 63 62 31 81 02 07 d0 82 0f 47 4f 49 53 49 4d 2f 4c 4c 4e 30 24 44 53 31 83 06 47 4f 49 53 49 4d 84 08 6a bb ff 93 37 8d 4f 0a 85 01 01 86 01 00 87 01 00 88 01 01 89 01 00 8a 01 03 ab 10 85 02 04 d2 83 01 01 8a 07 72 2d 67 6f 6f 73 65 85 10 11 c8 cf 15 31 17 43 ca 22 99 5a 3b de 3e cd 07";
/// Key 1, AES-128-GCM.
const LIBIEC_GCM128: &str = "01 40 a1 18 80 12 00 00 00 7c 00 00 00 00 00 02 00 00 00 00 00 00 00 00 00 01 0c 09 95 6b 01 11 a4 1a a5 36 d1 17 a2 00 00 00 68 3f d8 a3 f0 80 d6 f8 3e 88 61 25 dd ac 43 67 1f b2 26 d4 5c 2e 6f c5 9a 82 42 f8 d1 e0 70 7c fd 70 be 5b ed 64 0f 5f 55 d8 bf 4c b4 8e 78 b6 f7 47 fe 58 24 9c 84 ba bd 81 f5 e2 bb 49 ba e4 15 b6 7d e1 04 d6 87 ae f7 25 73 79 eb fa 84 c1 8f 57 2c cb 18 79 12 85 6a eb 6c 84 9e a1 9a c8 0e 90 ce d6 7a 30 45 a4 01 85 10 d7 63 00 98 cf 43 88 83 52 72 d1 eb fa 0d 89 b2";

fn check_libiec_goose(s: &Spdu) {
    assert_eq!((s.si, s.version, s.payloads.len()), (SessionId::GOOSE, 2, 1), "{s:?}");
    let p = &s.payloads[0];
    assert_eq!((p.kind, p.app_id, p.simulation), (PayloadType::GOOSE, 0x3001, false));
    assert_eq!(p.apdu.len(), 98);
    assert_eq!(p.apdu[0], 0x61);
    assert!(p.apdu.windows(19).any(|w| w == b"GOISIM/LLN0$GO$gcb1"));
    assert!(p.apdu.ends_with(b"r-goose"));
}

#[test]
fn libiec61850_vectors_decode() {
    let s = unmarshal(&unhex(LIBIEC_UNSECURED), None).unwrap();
    check_libiec_goose(&s);
    assert!(s.key_id == 0 && !s.signed && !s.encrypted);

    let keys = store([hmac_key(1, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128)]);
    let s = unmarshal(&unhex(LIBIEC_HMAC128), Some(&keys)).unwrap();
    check_libiec_goose(&s);
    assert!(s.signed && s.key_id == 1);

    let keys = store([gcm_key(1, &TEST_KEY, SecAlgorithm::AES_128_GCM)]);
    let s = unmarshal(&unhex(LIBIEC_GCM128), Some(&keys)).unwrap();
    check_libiec_goose(&s);
    assert!(s.encrypted);
}

/// Any change to a secured SPDU, header included, fails verification.
#[test]
fn tampering_is_detected() {
    for (name, vec, key) in [
        ("HMAC", LIBIEC_HMAC128, hmac_key(1, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128)),
        ("GCM", LIBIEC_GCM128, gcm_key(1, &TEST_KEY, SecAlgorithm::AES_128_GCM)),
    ] {
        let keys = store([key]);
        let orig = unhex(vec);
        for i in 0..orig.len() {
            let mut b = orig.clone();
            b[i] ^= 1;
            assert!(unmarshal(&b, Some(&keys)).is_err(), "{name}: flipping octet {i} went unnoticed");
        }
    }
    let other = [0x55u8; 16];
    let err = unmarshal(&unhex(LIBIEC_HMAC128), Some(&store([hmac_key(1, &other, SigAlgorithm::HMAC_SHA256_128)])));
    assert!(matches!(err, Err(Error::Authentication(_))), "{err:?}");
    let err = unmarshal(&unhex(LIBIEC_GCM128), Some(&store([gcm_key(1, &other, SecAlgorithm::AES_128_GCM)])));
    assert!(matches!(err, Err(Error::Authentication(_))), "{err:?}");
    let err = unmarshal(&unhex(LIBIEC_HMAC128), Some(&store([hmac_key(2, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128)])));
    assert!(matches!(err, Err(Error::UnknownKey(1))), "{err:?}");
    let err = unmarshal(&unhex(LIBIEC_HMAC128), Some(&store([hmac_key(1, &TEST_KEY, SigAlgorithm::HMAC_SHA256_256)])));
    assert!(matches!(err, Err(Error::Authentication(_))), "{err:?}");
    // A secured SPDU with its trailer cut off is not taken as unsecured.
    let b = unhex(LIBIEC_HMAC128);
    let err = unmarshal(&b[..b.len() - 18], Some(&store([hmac_key(1, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128)])));
    assert!(matches!(err, Err(Error::Authentication(_))), "{err:?}");
}

#[test]
fn marshal_round_trips() {
    let payloads = vec![
        Payload { kind: PayloadType::GOOSE, app_id: 0x3001, apdu: vec![0x61, 0x03, 0x80, 0x01, 0x41], ..Default::default() },
        Payload { kind: PayloadType::GOOSE, app_id: 0x3002, simulation: true, apdu: vec![0x61, 0x00] },
    ];
    let m32 = [7u8; 32];
    let cases: Vec<(&str, u16, Option<Key>)> = vec![
        ("v2 unsecured", 2, None),
        ("v1 unsecured", 1, None),
        ("v2 HMAC-SHA256-80", 2, Some(hmac_key(9, &TEST_KEY, SigAlgorithm::HMAC_SHA256_80))),
        ("v2 HMAC-SHA256-128", 2, Some(hmac_key(9, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128))),
        ("v2 HMAC-SHA256-256", 2, Some(hmac_key(9, &m32, SigAlgorithm::HMAC_SHA256_256))),
        ("v2 HMAC-SHA3-128", 2, Some(hmac_key(9, &TEST_KEY, SigAlgorithm::HMAC_SHA3_128))),
        ("v1 HMAC-SHA256-128", 1, Some(hmac_key(9, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128))),
        ("v2 AES-128-GCM", 2, Some(gcm_key(9, &TEST_KEY, SecAlgorithm::AES_128_GCM))),
        ("v2 AES-256-GCM", 2, Some(Key { time_of_current_key: 1_700_000_000, time_to_next_key: 3600, ..gcm_key(9, &m32, SecAlgorithm::AES_256_GCM) })),
    ];
    for (name, version, key) in cases {
        let keys = key.clone().map(|k| store([k]));
        let input = Spdu { si: SessionId::GOOSE, number: 42, version, payloads: payloads.clone(), ..Default::default() };
        let b = marshal(&input, key.as_ref()).unwrap();
        let encrypted = key.as_ref().is_some_and(|k| k.sec != SecAlgorithm::NONE);
        if encrypted {
            assert!(!b.windows(5).any(|w| w == payloads[0].apdu.as_slice()), "{name}: APDU in clear");
        }
        let out = unmarshal(&b, keys.as_ref()).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((out.si, out.number, out.version), (SessionId::GOOSE, 42, version), "{name}");
        assert_eq!(out.payloads, payloads, "{name}");
        if let Some(k) = &key {
            assert_eq!((out.key_id, out.time_of_current_key, out.time_to_next_key), (9, k.time_of_current_key, k.time_to_next_key));
            assert_eq!((out.signed, out.encrypted), (k.sig != SigAlgorithm::NONE, encrypted), "{name}");
        }
        let sec_info = if version == 2 { 11 + if encrypted { GCM_IV_LEN } else { 0 } } else { 12 };
        assert_eq!(usize::from(b[3]), 2 + usize::from(COMMON_LEN) + sec_info, "{name}: session header length");
        assert_eq!(b[5], COMMON_LEN);
        assert_eq!(u32::from_be_bytes([b[6], b[7], b[8], b[9]]) as usize, b.len() - 10, "{name}: SPDU length");
    }
}

/// Version 1 declares its algorithms in the header, and they must be the
/// key's.
#[test]
fn version_1_algorithms_are_bound_to_the_key() {
    let k = hmac_key(3, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128);
    let s = Spdu {
        si: SessionId::SV,
        version: 1,
        payloads: vec![Payload { kind: PayloadType::SV, apdu: vec![0x60, 0], ..Default::default() }],
        ..Default::default()
    };
    let mut b = marshal(&s, Some(&k)).unwrap();
    b[23] = SigAlgorithm::HMAC_SHA256_80.0;
    assert!(matches!(unmarshal(&b, Some(&store([k]))), Err(Error::Algorithm(_))));
    let v1 = Spdu { version: 1, ..Default::default() };
    assert!(matches!(marshal(&v1, Some(&gcm_key(3, &TEST_KEY, SecAlgorithm::AES_128_GCM))), Err(Error::Version1Encrypt)));
}

#[test]
fn keys_are_validated() {
    type Case = (Key, fn(&Error) -> bool);
    let cases: Vec<Case> = vec![
        (hmac_key(0, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128), |e| matches!(e, Error::KeyId)),
        (Key { id: 1, material: TEST_KEY.to_vec(), ..Default::default() }, |e| matches!(e, Error::KeyAlgorithm)),
        (Key { sig: SigAlgorithm::HMAC_SHA256_128, ..gcm_key(1, &TEST_KEY, SecAlgorithm::AES_128_GCM) }, |e| matches!(e, Error::KeyCombination)),
        (gcm_key(1, &TEST_KEY, SecAlgorithm::AES_256_GCM), |e| matches!(e, Error::KeyLength(_))),
        (hmac_key(1, &TEST_KEY[..8], SigAlgorithm::HMAC_SHA256_128), |e| matches!(e, Error::KeyLength(_))),
        (hmac_key(1, &TEST_KEY, SigAlgorithm::AES_GMAC_128), |e| matches!(e, Error::KeyUnsupported(_))),
    ];
    for (k, want) in cases {
        let err = KeyStore::with_keys([k.clone()]).unwrap_err();
        assert!(want(&err), "{k:?}: {err}");
    }
    let s = store([hmac_key(1, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128)]);
    assert_eq!(s.active(), 1);
    s.remove(1);
    assert!(s.lookup(1).is_none());
    assert!(s.active_key().is_none());
    assert_eq!(s.active(), 0);
}

/// No input makes unmarshal panic; every prefix of a valid SPDU is refused.
#[test]
fn truncated_spdus_are_refused() {
    let keys = store([gcm_key(1, &TEST_KEY, SecAlgorithm::AES_128_GCM)]);
    for vec in [LIBIEC_UNSECURED, LIBIEC_GCM128] {
        let b = unhex(vec);
        for n in 0..b.len() {
            if unmarshal(&b[..n], Some(&keys)).is_ok() {
                assert!(n >= b.len() - 2, "a {n}-octet prefix decoded");
            }
        }
    }
}

/// Arbitrary input never panics, and what decodes re-encodes to something
/// that decodes.
#[test]
fn arbitrary_input_never_panics() {
    let keys = store([hmac_key(1, &TEST_KEY, SigAlgorithm::HMAC_SHA256_128)]);
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let bases = [unhex(LIBIEC_UNSECURED), unhex(LIBIEC_HMAC128), unhex(LIBIEC_GCM128)];
    for i in 0..20_000 {
        let mut b = bases[i % 3].clone();
        for _ in 0..(next() % 4 + 1) {
            let pos = (next() as usize) % b.len();
            b[pos] = next() as u8;
        }
        b.truncate((next() as usize) % (b.len() + 1));
        if let Ok(s) = unmarshal(&b, Some(&keys)) {
            let re = Spdu { si: s.si, number: s.number, version: s.version, payloads: s.payloads, ..Default::default() };
            if let Ok(out) = marshal(&re, None) {
                unmarshal(&out, None).expect("a re-encoded SPDU decodes");
            }
        }
    }
}

#[test]
fn the_replay_window() {
    let mut w = ReplayWindow::default();
    let mut now = Instant::now();
    let reset = Some(Duration::from_secs(10));
    let accept = |w: &mut ReplayWindow, n: u32, now: Instant| w.accept(n, now, 64, reset);
    for n in [5, 6, 8, 7] {
        assert!(accept(&mut w, n, now), "fresh {n} refused");
    }
    for n in [5, 6, 7, 8] {
        assert!(!accept(&mut w, n, now), "replayed {n} accepted");
    }
    assert!(accept(&mut w, 100, now) && !accept(&mut w, 30, now) && accept(&mut w, 99, now));
    // The counter wraps.
    let mut w = ReplayWindow::default();
    assert!(accept(&mut w, 0xffff_fffe, now));
    assert!(accept(&mut w, 0xffff_ffff, now));
    assert!(accept(&mut w, 0, now));
    assert!(accept(&mut w, 1, now));
    assert!(!accept(&mut w, 0xffff_ffff, now));
    // A sender silent past the reset time may start again from zero.
    let mut w = ReplayWindow::default();
    accept(&mut w, 500, now);
    now += Duration::from_secs(5);
    assert!(!accept(&mut w, 0, now), "restart accepted within the reset time");
    now += Duration::from_secs(11);
    assert!(accept(&mut w, 0, now) && accept(&mut w, 1, now) && !accept(&mut w, 0, now));
}
