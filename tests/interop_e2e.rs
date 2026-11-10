#![cfg(feature = "e2e")]
mod e2e_common;
use e2e_common::*;
use iec61850::{
    client::{Client, Options as ClientOptions},
    iec62351::e2e::{AuthenticatorTagging, Corrections, Edition, Group, IcvAlgorithm, Policy},
    model::Fc,
    scl,
    server::{Options as ServerOptions, Server},
};
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};
struct Files(PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn files(pki: &Pki, c: &Credential, s: &Credential, suffix: &str) -> Files {
    let path = std::env::temp_dir().join(format!("rs-e2e-interop-{}-{suffix}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    for (name, id) in [("client", c), ("server", s)] {
        std::fs::write(path.join(format!("{name}.pem")), pem(&id.certificate)).unwrap();
        std::fs::write(path.join(format!("{name}.key")), &id.key_pem).unwrap();
    }
    std::fs::write(path.join("root.pem"), pki.root.pem()).unwrap();
    Files(path)
}
#[derive(Clone, Copy)]
struct Case {
    edition: Edition,
    group: Group,
    algorithm: IcvAlgorithm,
    rsa: bool,
    corrections: Corrections,
    tagging: AuthenticatorTagging,
}
impl Case {
    fn policy(self, p: &mut Policy) {
        p.edition = self.edition;
        p.dh_groups = vec![self.group];
        p.icv_algorithms = vec![self.algorithm];
        p.corrections = self.corrections;
        p.authenticator = self.tagging;
        p.max_messages_per_key = 2;
    }
    fn args(self, mode: &str, address: &str, files: &Files, server: bool) -> Vec<String> {
        let role = if server { "server" } else { "client" };
        vec![
            mode.into(),
            address.into(),
            files.0.join(format!("{role}.pem")).display().to_string(),
            files.0.join(format!("{role}.key")).display().to_string(),
            files.0.join("root.pem").display().to_string(),
            format!("1.3.6.1.4.1.55555/{}", if server { 2 } else { 1 }),
            format!("1.3.6.1.4.1.55555/{}", if server { 1 } else { 2 }),
            if self.group == Group::P256 {
                "23"
            } else {
                "14"
            }
            .into(),
            match self.algorithm {
                IcvAlgorithm::HmacSha256 => "1",
                IcvAlgorithm::GmacAes128 => "2",
                IcvAlgorithm::GmacAes256 => "3",
            }
            .into(),
            if self.edition == Edition::First2018 {
                "2018"
            } else {
                "2020"
            }
            .into(),
            if self.corrections == Corrections::InForce {
                "in-force"
            } else {
                "none"
            }
            .into(),
            if self.tagging == AuthenticatorTagging::AnnexB {
                "0"
            } else {
                "1"
            }
            .into(),
        ]
    }
}
fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for edition in [Edition::First2018, Edition::Amendment2020] {
        for group in [Group::P256, Group::Modp2048] {
            for algorithm in [
                IcvAlgorithm::HmacSha256,
                IcvAlgorithm::GmacAes128,
                IcvAlgorithm::GmacAes256,
            ] {
                cases.push(Case {
                    edition,
                    group,
                    algorithm,
                    rsa: group == Group::Modp2048,
                    corrections: Corrections::InForce,
                    tagging: AuthenticatorTagging::AnnexB,
                });
            }
        }
    }
    cases.push(Case {
        edition: Edition::Amendment2020,
        group: Group::P256,
        algorithm: IcvAlgorithm::GmacAes128,
        rsa: false,
        corrections: Corrections::None,
        tagging: AuthenticatorTagging::Clause13,
    });
    cases
}
fn peer() -> Option<String> {
    let peer = std::env::var("IEC61850_GO_PEER").ok();
    if peer.is_none() {
        eprintln!("SKIP: set IEC61850_GO_PEER (interop/e2e.sh)");
    }
    peer
}
#[tokio::test]
async fn rust_client_go_server_native_e2e() {
    let Some(bin) = peer() else { return };
    let pki = Pki::new();
    let ec_c = pki.issue(1, false);
    let ec_s = pki.issue(2, false);
    let rsa_c = pki.issue(1, true);
    let rsa_s = pki.issue(2, true);
    for (index, case) in cases().into_iter().enumerate() {
        let (c, s) = if case.rsa {
            (&rsa_c, &rsa_s)
        } else {
            (&ec_c, &ec_s)
        };
        let files = files(&pki, c, s, &format!("go-server-{index}"));
        let mut child = Command::new(&bin)
            .args(case.args("e2e-server", "127.0.0.1:0", &files, true))
            .env(
                "SIMPLEIO_CID",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/testdata/simpleIO_direct_control.cid"
                ),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let line = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let addr = line.strip_prefix("listening ").expect(&line);
        let opts = ClientOptions::new()
            .with_timeout(Duration::from_secs(10))
            .with_e2e(pki.config(c, |p| case.policy(p)), s.ae.clone());
        let conn = Client::dial_with(addr, opts)
            .await
            .unwrap_or_else(|e| panic!("case {index}: {e}"));
        for _ in 0..10 {
            conn.read("simpleIOGenericIO/GGIO1.AnIn1.mag.f", Fc::Mx)
                .await
                .unwrap();
        }
        conn.close().await.unwrap();
        drop(child.stdin.take());
        assert!(tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success());
    }
}
#[tokio::test]
async fn go_client_rust_server_native_e2e() {
    let Some(bin) = peer() else { return };
    let pki = Pki::new();
    let ec_c = pki.issue(1, false);
    let ec_s = pki.issue(2, false);
    let rsa_c = pki.issue(1, true);
    let rsa_s = pki.issue(2, true);
    for (index, case) in cases().into_iter().enumerate() {
        let (c, s) = if case.rsa {
            (&rsa_c, &rsa_s)
        } else {
            (&ec_c, &ec_s)
        };
        let files = files(&pki, c, s, &format!("rust-server-{index}"));
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
            ServerOptions::new().with_e2e(pki.config(s, |p| case.policy(p)), true),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let copy = srv.clone();
        let task = tokio::spawn(async move {
            copy.serve(listener).await.unwrap();
        });
        let output = tokio::time::timeout(
            Duration::from_secs(30),
            Command::new(&bin)
                .args(case.args("e2e-client", &addr, &files, false))
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            output.status.success(),
            "case {index}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("released"));
        srv.close().await.unwrap();
        task.abort();
    }
}

#[tokio::test]
async fn bundled_tools_load_native_credentials_and_require_e2e() {
    let pki = Pki::new();
    let client = pki.issue(1, false);
    let server = pki.issue(2, false);
    let files = files(&pki, &client, &server, "cli");
    let path = |name: &str| files.0.join(name).display().to_string();
    let mut process = Command::new(env!("CARGO_BIN_EXE_ied-server"))
        .args([
            "--addr",
            "127.0.0.1:0",
            "--quiet",
            "--scl",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/testdata/simpleIO_direct_control.cid"
            ),
            "--e2e-cert",
            &path("server.pem"),
            "--e2e-key",
            &path("server.key"),
            "--e2e-ca",
            &path("root.pem"),
            "--e2e-icv",
            "aes128-gmac",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(process.stdout.take().unwrap()).lines();
    let address = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let line = lines.next_line().await.unwrap().expect("server startup");
            if let Some(addr) = line.strip_prefix("ied-server: listening on ") {
                break addr.to_string();
            }
        }
    })
    .await
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ied-client"))
        .args([
            "--addr",
            &address,
            "--e2e-cert",
            &path("client.pem"),
            "--e2e-key",
            &path("client.key"),
            "--e2e-ca",
            &path("root.pem"),
            "--e2e-peer",
            "1.3.6.1.4.1.55555/2",
            "--e2e-icv",
            "aes128-gmac",
            "read",
            "simpleIOGenericIO/GGIO1.AnIn1.mag.f",
            "MX",
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plain = Command::new(env!("CARGO_BIN_EXE_ied-client"))
        .args(["--addr", &address, "identify"])
        .output()
        .await
        .unwrap();
    assert!(!plain.status.success());
    process.kill().await.unwrap();
    process.wait().await.unwrap();
}
