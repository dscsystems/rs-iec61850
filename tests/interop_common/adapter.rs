//! The adapter images of otfabric/mms-interop: one container per peer
//! program, JSON Lines on stdout, the readiness event before a server
//! accepts.
//!
//! Containers run on the host network, so a server adapter listens on a
//! loopback port of ours and a client adapter reaches this crate's server at
//! 127.0.0.1, with no port mapping or gateway alias in between.

use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value as Json;
use tokio::io::{AsyncBufReadExt, BufReader};

use super::*;

/// One of the implementations mms-interop packages.
#[derive(Clone, Copy, Debug)]
pub struct Stack {
    /// The command prefix and the `adapter` of the ready event.
    pub name: &'static str,
    /// The variable that overrides the image, as the Go suites name it.
    pub image_env: &'static str,
    /// The image the pinned mms-interop release published (v0.4.0).
    pub image: &'static str,
}

pub const LIBIEC61850: Stack = Stack {
    name: "libiec61850",
    image_env: "LIBIEC61850_IMAGE",
    image: "ghcr.io/otfabric/mms-interop-libiec61850@sha256:966e17e37e7fb5c22b825443ce79565d51067705c8f8485fd63d4001b4bd31ff",
};
pub const IEC61850BEAN: Stack = Stack {
    name: "iec61850bean",
    image_env: "IEC61850BEAN_IMAGE",
    image: "ghcr.io/otfabric/mms-interop-iec61850bean@sha256:ab2cda6a77ea054a04a736fdf1c36c5c8f50c766aa41cf5818bd11f3fadfac7d",
};
pub const DSCSYSTEMS: Stack = Stack {
    name: "dscsystems",
    image_env: "DSCSYSTEMS_IMAGE",
    image: "ghcr.io/otfabric/mms-interop-dscsystems@sha256:899e4d96605a921647e7c079db0b0a7f69c05d0582830b81607bc1a152a8d60a",
};
pub const IEC61850_RUST: Stack = Stack {
    name: "iec61850-rust",
    image_env: "IEC61850RUST_IMAGE",
    image: "ghcr.io/otfabric/mms-interop-iec61850-rust@sha256:c46c83c6d7eaa9800bbe48fb6ca9d25a4e9338d0bfc6f31fbba7813d89e4445d",
};

impl Stack {
    /// Whether `MMS_INTEROP_STACKS` (comma-separated names, or `all`)
    /// selects this stack. Unset, every test is skipped, so a checkout
    /// without Docker stays green.
    pub fn selected(&self) -> bool {
        let Some(list) = env("MMS_INTEROP_STACKS") else {
            eprintln!("skipped: set MMS_INTEROP_STACKS (e.g. all)");
            return false;
        };
        let on = list.split(',').map(str::trim).any(|s| s == "all" || s == self.name);
        if !on {
            eprintln!("skipped: {} is not in MMS_INTEROP_STACKS", self.name);
        }
        on
    }

    pub fn image(&self) -> String {
        env(self.image_env).unwrap_or_else(|| self.image.to_string())
    }

    /// The adapter command for a role, e.g. `dscsystems-ied-server`.
    pub fn command(&self, role: &str) -> String {
        format!("{}-{role}", self.name)
    }
}

/// The path of a vendored mms-interop fixture.
pub fn fixture(rel: &str) -> PathBuf {
    testdata("mms-interop").join(rel)
}

pub fn read_json(path: &Path) -> Json {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn container_name(role: &str) -> String {
    static N: AtomicUsize = AtomicUsize::new(0);
    format!("rs-iec61850-{role}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
}

fn docker(name: &str, image: &str, entrypoint: &str, args: &[String]) -> Command {
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "--name", name, "--network", "host", "--entrypoint", entrypoint, image])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    cmd
}

/// Removes a container. Killing `docker run` leaves the container running,
/// still holding its port, so every adapter is removed by name.
fn remove(name: &str) {
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// A server adapter running for the duration of a test.
pub struct AdapterServer {
    name: String,
    _child: tokio::process::Child,
    pub addr: String,
    /// The readiness event.
    pub ready: Json,
}

impl AdapterServer {
    /// Starts `<stack>-<role>` with `--port` and waits for its readiness
    /// event.
    pub async fn start(stack: Stack, role: &str, extra: &[&str]) -> AdapterServer {
        let port = free_port();
        let name = container_name(role);
        let mut args: Vec<String> = extra.iter().map(|s| s.to_string()).collect();
        args.extend(["--port".into(), port.to_string()]);
        let mut child = docker(&name, &stack.image(), &stack.command(role), &args)
            .spawn()
            .unwrap_or_else(|e| panic!("docker: {e}"));
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut stderr = child.stderr.take().unwrap();
        let wait = async {
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(ev) = serde_json::from_str::<Json>(&line) {
                    if ev["event"] == "ready" {
                        return Some(ev);
                    }
                }
            }
            None
        };
        // Pulling an image the first time is what this limit mostly covers.
        let ready = match tokio::time::timeout(Duration::from_secs(120), wait).await {
            Ok(Some(ev)) => ev,
            other => {
                remove(&name);
                let mut err = String::new();
                let _ = tokio::time::timeout(Duration::from_secs(2), stderr.read_to_string(&mut err)).await;
                panic!("{}: no readiness event ({other:?}): {err}", stack.command(role));
            }
        };
        // Keep draining both streams so a chatty server never blocks on a
        // full pipe.
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        tokio::spawn(async move { tokio::io::copy(&mut stderr, &mut tokio::io::sink()).await });
        AdapterServer { name, _child: child, addr: format!("127.0.0.1:{port}"), ready }
    }

    /// The IED name the server reports, which prefixes its logical devices.
    pub fn ied_name(&self) -> String {
        self.ready["ied_name"].as_str().unwrap_or_default().to_string()
    }
}

impl Drop for AdapterServer {
    fn drop(&mut self) {
        remove(&self.name);
    }
}

/// What a client adapter printed: one JSON object per operation.
pub struct Run {
    pub lines: Vec<Json>,
    pub code: Option<i32>,
    pub stderr: String,
}

impl Run {
    /// The first result of `operation`, and with `target` the first for that
    /// target.
    pub fn op(&self, operation: &str, target: Option<&str>) -> &Json {
        self.lines
            .iter()
            .find(|l| l["operation"] == operation && target.is_none_or(|t| l["target"] == t))
            .unwrap_or_else(|| panic!("no {operation} {target:?} result in {self}"))
    }

    /// Asserts an operation succeeded and returns its result.
    pub fn ok(&self, operation: &str, target: Option<&str>) -> &Json {
        let r = self.op(operation, target);
        assert_eq!(r["ok"], true, "{operation} {target:?} failed: {r}\n{self}");
        r
    }

    /// The adapter refused a step because its own stack lacks the service.
    pub fn unsupported(&self) -> Option<&Json> {
        self.lines.iter().find(|l| l["code"] == "unsupported" || l["error"] == "unsupported")
    }
}

impl std::fmt::Display for Run {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "exit {:?}", self.code)?;
        for l in &self.lines {
            writeln!(f, "  {l}")?;
        }
        if !self.stderr.trim().is_empty() {
            writeln!(f, "stderr:\n{}", self.stderr.trim_end())?;
        }
        Ok(())
    }
}

/// A client adapter running against this crate's server.
pub struct AdapterClient {
    name: String,
    child: tokio::process::Child,
    lines: tokio::sync::mpsc::UnboundedReceiver<Json>,
    seen: Vec<Json>,
}

impl AdapterClient {
    /// Starts `<stack>-<role>` against 127.0.0.1:`port`.
    pub fn start(stack: Stack, role: &str, port: u16, extra: &[&str]) -> AdapterClient {
        let name = container_name(role);
        let mut args: Vec<String> = vec!["--host".into(), "127.0.0.1".into(), "--port".into(), port.to_string()];
        args.extend(extra.iter().map(|s| s.to_string()));
        let mut child = docker(&name, &stack.image(), &stack.command(role), &args)
            .spawn()
            .unwrap_or_else(|e| panic!("docker: {e}"));
        let mut out = BufReader::new(child.stdout.take().unwrap()).lines();
        let (tx, lines) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok(Some(line)) = out.next_line().await {
                match serde_json::from_str::<Json>(&line) {
                    Ok(v) => {
                        let _ = tx.send(v);
                    }
                    Err(_) => eprintln!("adapter stdout is not JSON: {line}"),
                }
            }
        });
        AdapterClient { name, child, lines, seen: Vec::new() }
    }

    /// Waits for the next line whose `operation` is `operation`, so a test
    /// can act on the server between two of the adapter's steps.
    pub async fn wait_for(&mut self, operation: &str, limit: Duration) -> Option<Json> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            let line = tokio::time::timeout_at(deadline, self.lines.recv()).await.ok()??;
            self.seen.push(line.clone());
            if line["operation"] == operation {
                return Some(line);
            }
        }
    }

    /// Waits for the adapter to exit, or stops it after `limit`.
    pub async fn finish(mut self, limit: Duration) -> Run {
        let mut stderr = self.child.stderr.take().unwrap();
        let mut err = String::new();
        let code = tokio::time::timeout(limit, async {
            let _ = stderr.read_to_string(&mut err).await;
            self.child.wait().await.ok().and_then(|s| s.code())
        })
        .await
        .ok()
        .flatten();
        remove(&self.name);
        while let Ok(l) = self.lines.try_recv() {
            self.seen.push(l);
        }
        // The reader task may still hold lines written just before exit.
        while let Ok(Some(l)) = tokio::time::timeout(Duration::from_millis(200), self.lines.recv()).await {
            self.seen.push(l);
        }
        Run { lines: std::mem::take(&mut self.seen), code, stderr: err }
    }

    /// Runs a fixed-sequence adapter to completion.
    pub async fn run(stack: Stack, role: &str, port: u16, extra: &[&str]) -> Run {
        AdapterClient::start(stack, role, port, extra).finish(Duration::from_secs(90)).await
    }
}

impl Drop for AdapterClient {
    fn drop(&mut self) {
        remove(&self.name);
    }
}
