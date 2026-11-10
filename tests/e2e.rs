#![cfg(feature = "e2e")]
mod e2e_common;
use e2e_common::*;
use iec61850::{
    client::{Client, Options as ClientOptions},
    iec62351::e2e::{
        Association, AuthenticatorTagging, Corrections, Edition, Group, IcvAlgorithm, Kind,
    },
    model::Fc,
    scl,
    server::{Options as ServerOptions, Server},
};

#[test]
fn native_profile_roundtrips_both_editions_algorithms_groups_and_rekeys() {
    let pki = Pki::new();
    for rsa in [false, true] {
        let client = pki.issue(1, rsa);
        let server = pki.issue(2, rsa);
        for edition in [Edition::First2018, Edition::Amendment2020] {
            for group in [Group::P256, Group::Modp2048] {
                for algorithm in [
                    IcvAlgorithm::HmacSha256,
                    IcvAlgorithm::GmacAes128,
                    IcvAlgorithm::GmacAes256,
                ] {
                    let configure = |p: &mut iec61850::iec62351::e2e::Policy| {
                        p.edition = edition;
                        p.dh_groups = vec![group];
                        p.icv_algorithms = vec![algorithm];
                        p.max_messages_per_key = 2;
                    };
                    let mut c =
                        Association::client(pki.config(&client, configure), server.ae.clone());
                    let mut s = Association::server(pki.config(&server, configure));
                    let request = c.handshake_request(&[5, 0]).unwrap();
                    assert_eq!(
                        s.process_handshake_request(&request, client.ae.clone())
                            .unwrap(),
                        [5, 0]
                    );
                    let accept = s.handshake_accept(&[2, 1, 7]).unwrap();
                    assert_eq!(
                        c.process_handshake_accept(&accept, &server.ae).unwrap(),
                        [2, 1, 7]
                    );
                    for _ in 0..10 {
                        let data = c.seal(&[2, 1, 42]).unwrap();
                        assert_eq!(s.open(&data).unwrap(), [2, 1, 42]);
                        let data = s.seal(&[2, 1, 21]).unwrap();
                        assert_eq!(c.open(&data).unwrap(), [2, 1, 21]);
                    }
                    assert!(c.epoch() >= 3);
                    assert_eq!(c.epoch(), s.epoch());
                    let request = c.signed_control(Kind::ReleaseRequest, None, &[]).unwrap();
                    s.verify_control(Kind::ReleaseRequest, &request).unwrap();
                    let response = s.signed_control(Kind::ReleaseResponse, None, &[]).unwrap();
                    c.verify_control(Kind::ReleaseResponse, &response).unwrap();
                }
            }
        }
    }
}

#[test]
fn signatures_identity_replay_and_tampering_are_refused() {
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    let cc = pki.config(&client, |_| {});
    let sc = pki.config(&server, |_| {});
    let mut c = Association::client(cc, server.ae.clone());
    let request = c.handshake_request(&[5, 0]).unwrap();
    let mut bad = request.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(Association::server(sc.clone())
        .process_handshake_request(&bad, client.ae.clone())
        .is_err());
    assert!(Association::server(sc.clone())
        .process_handshake_request(&request, server.ae.clone())
        .is_err());
    let mut s = Association::server(sc.clone());
    s.process_handshake_request(&request, client.ae.clone())
        .unwrap();
    assert!(Association::server(sc)
        .process_handshake_request(&request, client.ae.clone())
        .is_err());
    let response = s.handshake_accept(&[5, 0]).unwrap();
    c.process_handshake_accept(&response, &server.ae).unwrap();
    let data = c.seal(&[5, 0]).unwrap();
    s.open(&data).unwrap();
    assert!(s.open(&data).is_err());
    // Every truncation is rejected without panicking.
    for n in 0..request.len() {
        let mut receiver = Association::server(pki.config(&server, |_| {}));
        assert!(receiver
            .process_handshake_request(&request[..n], client.ae.clone())
            .is_err());
    }
}

#[test]
fn uncorrected_gmac_and_clause13_authenticators_interoperate() {
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    let configure = |p: &mut iec61850::iec62351::e2e::Policy| {
        p.icv_algorithms = vec![IcvAlgorithm::GmacAes128];
        p.authenticator = AuthenticatorTagging::Clause13;
    };
    let mut c = Association::client(
        pki.config(&client, |p| {
            configure(p);
            p.corrections = Corrections::None;
        }),
        server.ae.clone(),
    );
    let mut s = Association::server(pki.config(&server, configure));
    let req = c.handshake_request(&[5, 0]).unwrap();
    s.process_handshake_request(&req, client.ae).unwrap();
    let resp = s.handshake_accept(&[5, 0]).unwrap();
    c.process_handshake_accept(&resp, &server.ae).unwrap();
    let data = c.seal(&[5, 0]).unwrap();
    s.open(&data).unwrap();
}

#[tokio::test]
async fn mms_native_association_read_rekey_and_signed_release() {
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    for edition in [Edition::First2018, Edition::Amendment2020] {
        let configure = |p: &mut iec61850::iec62351::e2e::Policy| {
            p.edition = edition;
            p.max_messages_per_key = 2;
        };
        let model = scl::load_model(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/simpleIO_direct_control.cid"
            ),
            &scl::BuildOptions::new(),
        )
        .unwrap();
        let srv = Server::new(
            model,
            ServerOptions::new().with_e2e(pki.config(&server, configure), true),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let copy = srv.clone();
        let task = tokio::spawn(async move {
            copy.serve(listener).await.unwrap();
        });
        assert!(Client::dial(&addr).await.is_err());
        let options = ClientOptions::new()
            .with_timeout(std::time::Duration::from_secs(5))
            .with_e2e(pki.config(&client, configure), server.ae.clone());
        let conn = Client::dial_with(&addr, options).await.unwrap();
        for _ in 0..10 {
            conn.read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx)
                .await
                .unwrap();
        }
        conn.close().await.unwrap();
        srv.close().await.unwrap();
        task.abort();
    }
}

#[test]
fn signed_handshake_faults_have_specific_diagnostics_and_ber_spans_verify() {
    use iec61850::asn1::{self, context_constructed as cc, TAG_SEQUENCE as SEQ};
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    let mut c = Association::client(pki.config(&client, |_| {}), server.ae.clone());
    let request = c.handshake_request(&[5, 0]).unwrap();
    for (fault, diagnostic) in [
        (0, 4),
        (1, 10),
        (2, 11),
        (3, 5),
        (4, 17),
        (5, 6),
        (6, 13),
        (7, 16),
    ] {
        let changed = resigned(
            &request,
            &client,
            |token| match fault {
                0 => token.insert(2, asn1::prim(asn1::TAG_BIT_STRING, vec![6, 64]).encode()),
                1 => {
                    token[5] =
                        asn1::prim(asn1::TAG_GENERAL_TIME, b"20000101000000Z".to_vec()).encode()
                }
                2 => {
                    token[3] = asn1::cons(
                        SEQ,
                        [
                            asn1::int_elem(asn1::TAG_INTEGER, 28),
                            asn1::prim(asn1::TAG_OCTET_STRING, vec![0; 65]),
                        ],
                    )
                    .encode()
                }
                3 => {
                    token[4] = asn1::cons(
                        SEQ,
                        [asn1::oid_elem(asn1::TAG_OID, &asn1::Oid::from([1, 2, 3]))],
                    )
                    .encode()
                }
                4 => token[6] = asn1::cons(SEQ, []).encode(),
                5 => {
                    token[6] =
                        asn1::cons(cc(0), [asn1::cons(cc(0), []), asn1::cons(cc(1), [])]).encode()
                }
                6 => token[6] = asn1::cons(cc(0), [asn1::cons(cc(1), [])]).encode(),
                7 => token.push(asn1::prim(asn1::TAG_OCTET_STRING, vec![1, 2, 3]).encode()),
                _ => unreachable!(),
            },
            false,
        );
        let mut s = Association::server(pki.config(&server, |p| p.require_authorization = true));
        let error = s
            .process_handshake_request(&changed, client.ae.clone())
            .unwrap_err();
        assert_eq!(error.diagnostic, Some(diagnostic), "fault {fault}: {error}");
    }
    let indefinite = resigned(&request, &client, |_| {}, true);
    let mut s = Association::server(pki.config(&server, |_| {}));
    s.process_handshake_request(&indefinite, client.ae.clone())
        .expect("signature covers received indefinite TBS including EOC");
    // A changed ICV terminates the receiver instead of being delivered as MMS.
    let accept = s.handshake_accept(&[5, 0]).unwrap();
    // This request's signature changed for the indefinite BER, so use a separate pair for transfer corruption.
    drop(accept);
    let mut s = Association::server(pki.config(&server, |_| {}));
    s.process_handshake_request(&request, client.ae.clone())
        .unwrap();
    let accept = s.handshake_accept(&[5, 0]).unwrap();
    c.process_handshake_accept(&accept, &server.ae).unwrap();
    let mut data = c.seal(&[5, 0]).unwrap();
    *data.last_mut().unwrap() ^= 1;
    assert!(s.open(&data).unwrap_err().diagnostic.is_none());
    assert!(s.open(&c.seal(&[5, 0]).unwrap()).is_err());
}

#[tokio::test]
async fn a_missing_signed_release_response_is_reported_as_an_error() {
    use iec61850::mms;
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    let config = pki.config(&server, |_| {});
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let opts = mms::AcceptOptions {
            e2e: Some(config),
            e2e_required: true,
            ..Default::default()
        };
        let conn = mms::accept_conn_opts(Box::new(stream), Some(peer), &opts)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        conn.close().await.unwrap();
    });
    let conn = Client::dial_with(
        &addr,
        ClientOptions::new().with_e2e(pki.config(&client, |_| {}), server.ae),
    )
    .await
    .unwrap();
    assert!(
        conn.close().await.is_err(),
        "EOF cannot substitute for a signed release response"
    );
    task.await.unwrap();
}

#[tokio::test]
async fn signed_refusals_and_optional_plain_migration_are_supported() {
    use iec61850::mms;
    let pki = Pki::new();
    let other = Pki::new();
    let client = other.issue(1, false);
    let server = pki.issue(2, false);
    let model = scl::load_model(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/simpleIO_direct_control.cid"
        ),
        &scl::BuildOptions::new(),
    )
    .unwrap();
    let srv = Server::new(
        model,
        ServerOptions::new().with_e2e(pki.config(&server, |_| {}), false),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let copy = srv.clone();
    let task = tokio::spawn(async move {
        copy.serve(listener).await.unwrap();
    });
    // The client trusts the real server; its own identity was issued by an untrusted CA.
    let options = ClientOptions::new().with_e2e(pki.config(&client, |_| {}), server.ae.clone());
    let err = Client::dial_with(&addr, options).await.unwrap_err();
    assert!(
        matches!(err,iec61850::client::Error::Mms(mms::Error::E2E(ref error)) if error.diagnostic==Some(9)),
        "{err}"
    );
    let plain = Client::dial(&addr).await.unwrap();
    plain
        .read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx)
        .await
        .unwrap();
    plain.close().await.unwrap();
    srv.close().await.unwrap();
    task.abort();
}

#[tokio::test]
async fn native_security_over_tls_requires_separate_peer_certificates() {
    use iec61850::iec62351::{self, Options as TlsOptions};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    let tls_identity = || {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
        let cert = params.signed_by(&key, &pki.root, &pki.key).unwrap();
        (cert.der().to_vec(), key.serialize_der())
    };
    let client_tls = tls_identity();
    let server_tls = tls_identity();
    for same in [false, true] {
        let (srv_cert, srv_key) = if same {
            (&server.certificate, &server.key)
        } else {
            (&server_tls.0, &server_tls.1)
        };
        let opts = |cert: &Vec<u8>, key: &Vec<u8>| TlsOptions {
            certificates: vec![CertificateDer::from(cert.clone())],
            key: Some(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.clone()))),
            roots: vec![pki.root.der().clone()],
            no_server_name: true,
            ..Default::default()
        };
        let model = scl::load_model(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/simpleIO_direct_control.cid"
            ),
            &scl::BuildOptions::new(),
        )
        .unwrap();
        let srv = Server::new(
            model,
            ServerOptions::new()
                .with_tls(iec62351::server_config(opts(srv_cert, srv_key)).unwrap())
                .with_e2e(pki.config(&server, |_| {}), true),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let copy = srv.clone();
        let task = tokio::spawn(async move {
            copy.serve(listener).await.unwrap();
        });
        let tls = iec62351::client_config(opts(&client_tls.0, &client_tls.1)).unwrap();
        let options = ClientOptions::new()
            .with_tls(tls)
            .with_e2e(pki.config(&client, |_| {}), server.ae.clone());
        let result = Client::dial_with(&addr, options).await;
        if same {
            assert!(result.unwrap_err().to_string().contains("must differ"));
        } else {
            let conn = result.unwrap();
            assert_eq!(conn.mms().peer_e2e_security().unwrap().ae, server.ae);
            conn.read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx)
                .await
                .unwrap();
            conn.close().await.unwrap();
        }
        srv.close().await.unwrap();
        task.abort();
    }
}

#[test]
fn a_server_can_request_rekey_and_the_client_acknowledges_it() {
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    let mut c = Association::client(pki.config(&client, |_| {}), server.ae.clone());
    let mut s = Association::server(pki.config(&server, |_| {}));
    let request = c.handshake_request(&[5, 0]).unwrap();
    s.process_handshake_request(&request, client.ae).unwrap();
    let response = s.handshake_accept(&[5, 0]).unwrap();
    c.process_handshake_accept(&response, &server.ae).unwrap();
    s.request_rekey();
    let request = s.seal(&[5, 0]).unwrap();
    c.open(&request).unwrap();
    assert!(c.rekey_due());
    let change = c.seal(&[5, 0]).unwrap();
    s.open(&change).unwrap();
    let ack = s.seal(&[5, 0]).unwrap();
    c.open(&ack).unwrap();
    assert_eq!(c.epoch(), 1);
    assert_eq!(s.epoch(), 1);
}

#[test]
fn malformed_certificate_versions_and_empty_rsa_moduli_are_rejected() {
    let pki = Pki::new();
    let mut credential = pki.issue(1, false);
    let position = credential
        .certificate
        .windows(5)
        .position(|v| v == [0xa0, 3, 2, 1, 2])
        .unwrap();
    credential.certificate[position + 4] = 255;
    assert!(iec61850::x509::parse(&credential.certificate).is_err());
    assert_eq!(
        iec61850::x509::PublicKey::Rsa {
            n: Vec::new(),
            e: vec![3]
        }
        .rsa_bits(),
        Some(0)
    );
    let oid = iec61850::asn1::Oid::from([2, u32::MAX, 1]);
    let mut encoded = Vec::new();
    iec61850::asn1::append_oid(&mut encoded, &oid);
    assert_eq!(iec61850::asn1::decode_oid(&encoded).unwrap(), oid);
}
