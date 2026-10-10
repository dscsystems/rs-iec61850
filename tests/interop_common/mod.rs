//! What the interop test files share: environment gates, process and
//! server helpers, and the R-GOOSE/R-SV peer driver.
#![allow(dead_code, unused_imports)]

pub mod rsession;

pub use std::path::{Path, PathBuf};
pub use std::process::Stdio;
pub use std::sync::{Arc, Mutex};
pub use std::time::{Duration, SystemTime};

pub use iec61850::client::{AcsiClass, Client, ControlOptions, Options as ClientOptions, Stage};
pub use iec61850::mms::{ObjectClass, Type, Value};
pub use iec61850::model::{self, AddCause, CtlModel, Fc, TrgOps};
pub use iec61850::scl;
pub use iec61850::server::{ConnectionState, Options, Server, SvControlEvent};
pub use tokio::io::AsyncReadExt;
pub use tokio::net::TcpListener;
pub use tokio::process::Command;

pub fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

pub fn need(var: &str) -> Option<String> {
    let v = env(var);
    if v.is_none() {
        eprintln!("skipped: set {var}");
    }
    v
}

pub fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)
}

pub fn load(name: &str) -> model::Model {
    scl::load_model(testdata(name), &scl::BuildOptions::new()).expect("fixture loads")
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

pub fn temp_dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("iec61850-interop-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), to).unwrap();
        }
    }
}

pub async fn dial(addr: &str) -> Client {
    let mut last = None;
    for _ in 0..50 {
        match Client::dial_with(addr, ClientOptions::new().with_timeout(Duration::from_secs(3))).await {
            Ok(c) => return c,
            Err(e) => last = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("dial {addr}: {last:?}");
}

/// Serves `server` on a loopback port and returns the host and port.
pub async fn serve(server: &Server) -> (String, u16) {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = ln.local_addr().unwrap().port();
    let s = server.clone();
    tokio::spawn(async move {
        let _ = s.serve(ln).await;
    });
    ("127.0.0.1".into(), port)
}

/// Runs a C program to completion, or stops it after `limit`, and returns
/// its output and whether it exited successfully. Line buffering keeps the
/// output of a program that is stopped.
pub async fn run(bin: &str, args: &[&str], dir: Option<&Path>, limit: Duration) -> (String, bool) {
    let mut cmd = Command::new("timeout");
    cmd.arg(limit.as_secs().to_string()).args(["stdbuf", "-oL", bin]).args(args).kill_on_drop(true);
    if let Some(d) = dir {
        cmd.current_dir(d);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("{bin}: {e}"));
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let collect = async {
        let (mut a, mut b) = (String::new(), String::new());
        let _ = tokio::join!(so.read_to_string(&mut a), se.read_to_string(&mut b));
        a + &b
    };
    let wait = async {
        let out = collect.await;
        (out, child.wait().await.map(|s| s.success()).unwrap_or(false))
    };
    tokio::time::timeout(limit + Duration::from_secs(5), wait)
        .await
        .unwrap_or_else(|_| ("(did not stop)".into(), false))
}

/// A C server running for the duration of a test.
pub struct CServer(pub tokio::process::Child);

impl CServer {
    pub fn start(bin: &str, args: &[&str], dir: &Path) -> CServer {
        let child = Command::new(bin)
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|e| panic!("{bin}: {e}"));
        CServer(child)
    }

    /// Stops the server with SIGINT, which the examples handle by flushing
    /// and exiting, and returns what it printed.
    pub async fn stop(mut self) -> String {
        if let Some(pid) = self.0.id() {
            let _ = std::process::Command::new("kill").args(["-INT", &pid.to_string()]).status();
        }
        let mut out = String::new();
        if let Some(mut so) = self.0.stdout.take() {
            let _ = tokio::time::timeout(Duration::from_secs(3), so.read_to_string(&mut out)).await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), self.0.wait()).await;
        out
    }
}

