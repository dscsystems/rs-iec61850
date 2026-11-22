//! Structured security observations from the MMS server.
//!
//! The dispatcher uses a bounded queue and a separate worker. A slow or
//! panicking sink cannot block an association task.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{json, Value};

macro_rules! kinds {
    ($($variant:ident => $code:literal, $category:literal, $severity:literal;)*) => {
        /// Stable event codes, shared with the Go MMS server.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum Kind { $($variant,)* }

        impl Kind {
            const ALL: &'static [Kind] = &[$(Self::$variant,)*];
            pub fn code(self) -> &'static str {
                match self { $(Self::$variant => $code,)* }
            }
            pub fn category(self) -> &'static str {
                match self { $(Self::$variant => $category,)* }
            }
            pub fn severity(self) -> &'static str {
                match self { $(Self::$variant => $severity,)* }
            }
        }
    };
}

kinds! {
    ConnAccepted => "conn.accepted", "connection", "info";
    ConnRejectedLimit => "conn.rejected_limit", "connection", "warning";
    ConnNoData => "conn.no_data", "connection", "notice";
    ConnNeverAssociated => "conn.never_associated", "connection", "warning";
    ConnIdleTimeout => "conn.idle_timeout", "connection", "notice";
    ConnClosed => "conn.closed", "connection", "info";
    ConnAcceptError => "conn.accept_error", "resource", "critical";
    TlsHandshakeFailed => "tls.handshake_failed", "tls", "warning";
    TlsHandshakeTimeout => "tls.handshake_timeout", "tls", "warning";
    AssocEstablished => "assoc.established", "association", "info";
    AssocSetupFailed => "assoc.setup_failed", "association", "warning";
    AssocAbortedByPeer => "assoc.aborted_by_peer", "association", "notice";
    DosSlowFrame => "dos.slow_frame", "resource", "warning";
    EventsDropped => "meta.events_dropped", "meta", "warning";
    SinkPanic => "meta.sink_panic", "meta", "warning";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Observed,
    Rejected,
    Disconnected,
}

impl Action {
    pub fn code(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Rejected => "rejected",
            Self::Disconnected => "disconnected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TlsPeer {
    pub version: Option<u16>,
    pub cipher_suite: Option<u16>,
    pub server_name: Option<String>,
    pub fingerprint_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AcsePeer {
    pub calling: crate::mms::AcseIdentity,
    pub called: crate::mms::AcseIdentity,
    pub password_presented: bool,
    pub a_profile_common_name: Option<String>,
    pub a_profile_sha256: Option<String>,
    pub e2e_peer_ae: Option<String>,
    pub e2e_association_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub remote_addr: Option<SocketAddr>,
    pub local_addr: Option<SocketAddr>,
    pub connected_at: SystemTime,
    pub tls: Option<TlsPeer>,
    pub acse: Option<AcsePeer>,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub reason: &'static str,
    pub duration: Duration,
    pub requests: u64,
    pub octets_in: u64,
    pub octets_out: u64,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub time: SystemTime,
    pub kind: Kind,
    pub action: Action,
    pub protocol: &'static str,
    pub session_id: Option<u64>,
    pub peer: Option<PeerInfo>,
    pub stage: Option<&'static str>,
    pub summary: Option<SessionSummary>,
    pub detail: Option<String>,
    pub error: Option<String>,
    pub count: u64,
    pub first_seen: Option<SystemTime>,
}

impl Event {
    pub fn new(kind: Kind, action: Action) -> Self {
        Self {
            time: SystemTime::now(),
            kind,
            action,
            protocol: "mms",
            session_id: None,
            peer: None,
            stage: None,
            summary: None,
            detail: None,
            error: None,
            count: 1,
            first_seen: None,
        }
    }

    /// Encodes the event for structured logging, using the Go event field
    /// names for the fields both libraries report.
    pub fn json(&self) -> Value {
        let mut value = json!({
            "time": crate::time_util::format_system_time(self.time),
            "kind": self.kind.code(),
            "category": self.kind.category(),
            "severity": self.kind.severity(),
            "action": self.action.code(),
            "protocol": self.protocol,
            "role": "server",
            "session": self.session_id,
            "stage": self.stage,
            "detail": self.detail,
            "error": self.error,
            "count": self.count,
            "first_seen": self.first_seen.map(crate::time_util::format_system_time),
            "session_summary": self.summary.as_ref().map(|s| json!({
                "reason": s.reason,
                "duration_ms": u64::try_from(s.duration.as_millis()).unwrap_or(u64::MAX),
                "requests": s.requests,
                "octets_in": s.octets_in,
                "octets_out": s.octets_out,
            })),
            "peer": self.peer.as_ref().map(|p| json!({
                "network": "tcp",
                "remote": p.remote_addr.map(|a| a.to_string()),
                "local": p.local_addr.map(|a| a.to_string()),
                "connected_at": crate::time_util::format_system_time(p.connected_at),
                "tls": p.tls.as_ref().map(|t| json!({
                    "version": t.version,
                    "cipher_suite": t.cipher_suite,
                    "server_name": t.server_name,
                    "sha256": t.fingerprint_sha256,
                })),
                "acse": p.acse.as_ref().map(|a| json!({
                    "calling_ap_title": a.calling.ap_title.as_ref().map(ToString::to_string),
                    "calling_ae_qualifier": a.calling.ae_qualifier,
                    "called_ap_title": a.called.ap_title.as_ref().map(ToString::to_string),
                    "called_ae_qualifier": a.called.ae_qualifier,
                    "password_presented": a.password_presented,
                    "aprofile_subject": a.a_profile_common_name,
                    "aprofile_sha256": a.a_profile_sha256,
                    "e2e": a.e2e_association_id.is_some().then_some(true),
                    "e2e_peer_ae": a.e2e_peer_ae,
                    "e2e_asso_id": a.e2e_association_id,
                })),
            })),
        });
        fn omit_nulls(value: &mut Value) {
            if let Value::Object(fields) = value {
                fields.retain(|_, value| !value.is_null());
                fields.values_mut().for_each(omit_nulls);
            }
        }
        omit_nulls(&mut value);
        value
    }
}

/// A security event consumer. Callbacks run on the dispatcher's worker.
pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// Writes one JSON object per line from the dispatcher's worker.
pub fn json_lines(writer: impl Write + Send + 'static) -> Sink {
    let writer = Mutex::new(writer);
    Arc::new(move |event| {
        let mut writer = writer.lock().unwrap();
        if let Err(error) = writeln!(writer, "{}", event.json()) {
            tracing::warn!(%error, "could not write security event");
        }
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub reported: u64,
    pub delivered: u64,
    pub aggregated: u64,
    /// Events discarded because the queue was full or its worker had stopped.
    pub dropped: u64,
    pub sink_panics: u64,
    pub by_kind: HashMap<Kind, u64>,
    pub by_category: HashMap<&'static str, u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Maximum queued events. Zero is treated as one.
    pub queue_size: usize,
    /// Repeats within this window produce a summary. Zero delivers each event.
    pub aggregate_window: Duration,
    /// Maximum number of distinct events tracked for aggregation.
    pub max_aggregate_keys: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            queue_size: 1024,
            aggregate_window: Duration::from_secs(1),
            max_aggregate_keys: 4096,
        }
    }
}

#[derive(Debug, Default)]
struct Counters {
    by_kind: [AtomicU64; Kind::ALL.len()],
    delivered: AtomicU64,
    aggregated: AtomicU64,
    dropped: AtomicU64,
    sink_panics: AtomicU64,
}

/// A bounded FIFO that can be shared across servers. Dropping its last
/// handle closes the queue and the worker drains any pending events.
#[derive(Debug, Clone)]
pub struct Dispatcher {
    tx: mpsc::SyncSender<Event>,
    counters: Arc<Counters>,
}

impl Dispatcher {
    /// Starts a worker with the given capacity and default aggregation.
    pub fn new(capacity: usize, sink: Sink) -> std::io::Result<Self> {
        Self::with_options(
            Options {
                queue_size: capacity,
                ..Options::default()
            },
            sink,
        )
    }

    pub fn with_options(options: Options, sink: Sink) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(options.queue_size.max(1));
        let counters = Arc::new(Counters::default());
        let stats = counters.clone();
        std::thread::Builder::new()
            .name("iec61850-security".into())
            .spawn(move || {
                Worker {
                    stats,
                    sink,
                    options,
                    seen: HashMap::new(),
                    drops_seen: 0,
                }
                .run(rx);
            })?;
        Ok(Self { tx, counters })
    }

    /// Queues an event without waiting. Returns false if it was dropped.
    pub fn report(&self, event: Event) -> bool {
        self.counters.by_kind[event.kind as usize].fetch_add(1, Relaxed);
        if self.tx.try_send(event).is_err() {
            self.counters.dropped.fetch_add(1, Relaxed);
            return false;
        }
        true
    }

    pub fn stats(&self) -> Stats {
        let mut stats = Stats {
            delivered: self.counters.delivered.load(Relaxed),
            aggregated: self.counters.aggregated.load(Relaxed),
            dropped: self.counters.dropped.load(Relaxed),
            sink_panics: self.counters.sink_panics.load(Relaxed),
            ..Stats::default()
        };
        for &kind in Kind::ALL {
            let count = self.counters.by_kind[kind as usize].load(Relaxed);
            if count > 0 {
                stats.reported += count;
                stats.by_kind.insert(kind, count);
                *stats.by_category.entry(kind.category()).or_default() += count;
            }
        }
        stats
    }
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key {
    kind: Kind,
    session: Option<u64>,
    peer: Option<IpAddr>,
    stage: Option<&'static str>,
}

struct Aggregate {
    until: Instant,
    first: SystemTime,
    repeats: Option<Event>,
}

struct Worker {
    stats: Arc<Counters>,
    sink: Sink,
    options: Options,
    seen: HashMap<Key, Aggregate>,
    drops_seen: u64,
}

impl Worker {
    fn run(mut self, rx: mpsc::Receiver<Event>) {
        let interval = (self.options.aggregate_window / 2)
            .clamp(Duration::from_millis(10), Duration::from_secs(1));
        let mut sweep = Instant::now() + interval;
        loop {
            match rx.recv_timeout(sweep.saturating_duration_since(Instant::now())) {
                Ok(event) => self.handle(event, Instant::now()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            self.report_drops();
            let now = Instant::now();
            if now >= sweep {
                self.flush(Some(now));
                sweep = now + interval;
            }
        }
        self.report_drops();
        self.flush(None);
    }

    fn handle(&mut self, mut event: Event, now: Instant) {
        if self.options.aggregate_window.is_zero() {
            self.deliver(event);
            return;
        }
        let key = Key {
            kind: event.kind,
            session: event.session_id,
            peer: event
                .peer
                .as_ref()
                .and_then(|p| p.remote_addr)
                .map(|a| a.ip()),
            stage: event.stage,
        };
        if let Some(entry) = self.seen.get_mut(&key) {
            if now < entry.until {
                event.count += entry.repeats.as_ref().map_or(0, |e| e.count);
                event.first_seen = Some(entry.first);
                entry.repeats = Some(event);
                self.stats.aggregated.fetch_add(1, Relaxed);
                return;
            }
        }
        if let Some(repeat) = self.seen.remove(&key).and_then(|e| e.repeats) {
            self.deliver(repeat);
        }
        if self.seen.len() >= self.options.max_aggregate_keys.max(1) {
            self.flush(None);
        }
        if let Some(until) = now.checked_add(self.options.aggregate_window) {
            self.seen.insert(
                key,
                Aggregate {
                    until,
                    first: event.time,
                    repeats: None,
                },
            );
        }
        self.deliver(event);
    }

    fn flush(&mut self, now: Option<Instant>) {
        let mut due = Vec::new();
        self.seen.retain(|_, entry| {
            if now.is_some_and(|now| entry.until > now) {
                return true;
            }
            due.extend(entry.repeats.take());
            false
        });
        for event in due {
            self.deliver(event);
        }
    }

    fn report_drops(&mut self) {
        let dropped = self.stats.dropped.load(Relaxed);
        if dropped != self.drops_seen {
            let mut event = Event::new(Kind::EventsDropped, Action::Observed);
            event.count = dropped - self.drops_seen;
            self.drops_seen = dropped;
            self.deliver(event);
        }
    }

    fn deliver(&self, event: Event) {
        self.stats.delivered.fetch_add(1, Relaxed);
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.sink)(event))).is_err()
            && self.stats.sink_panics.fetch_add(1, Relaxed) == 0
        {
            let event = Event::new(Kind::SinkPanic, Action::Observed);
            self.stats.delivered.fetch_add(1, Relaxed);
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.sink)(event)))
                .is_err()
            {
                self.stats.sink_panics.fetch_add(1, Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_are_aggregated_and_pending_counts_drain() {
        let (output, results) = mpsc::channel();
        let dispatcher = Dispatcher::new(4, Arc::new(move |e| output.send(e).unwrap())).unwrap();
        for _ in 0..3 {
            let event = Event::new(Kind::ConnAcceptError, Action::Observed);
            assert!(dispatcher.report(event));
        }
        let first = results.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(first.count, 1);
        drop(dispatcher);
        let repeats = results.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(repeats.kind, first.kind);
        assert_eq!(repeats.count, 2);
        assert_eq!(repeats.first_seen, Some(first.time));
    }

    #[test]
    fn a_blocked_sink_drops_overflow_without_blocking_submitters() {
        let (output, results) = mpsc::channel();
        let (unblock, wait) = mpsc::channel();
        let wait = Mutex::new(wait);
        let dispatcher = Dispatcher::with_options(
            Options {
                queue_size: 1,
                aggregate_window: Duration::ZERO,
                ..Options::default()
            },
            Arc::new(move |e| {
                let first = e.kind == Kind::ConnAccepted;
                output.send(e).unwrap();
                if first {
                    wait.lock().unwrap().recv().unwrap();
                }
            }),
        )
        .unwrap();
        let submit = |kind| dispatcher.report(Event::new(kind, Action::Observed));
        assert!(submit(Kind::ConnAccepted));
        assert_eq!(
            results.recv_timeout(Duration::from_secs(2)).unwrap().kind,
            Kind::ConnAccepted
        );
        assert!(submit(Kind::ConnClosed));
        assert!(!submit(Kind::ConnClosed));
        assert_eq!(dispatcher.stats().dropped, 1);
        assert_eq!(dispatcher.stats().by_kind[&Kind::ConnClosed], 2);
        unblock.send(()).unwrap();
        let output: Vec<_> = (0..2)
            .map(|_| results.recv_timeout(Duration::from_secs(2)).unwrap())
            .collect();
        assert!(output
            .iter()
            .any(|e| e.kind == Kind::EventsDropped && e.count == 1));
        assert!(output.iter().any(|e| e.kind == Kind::ConnClosed));
    }
}
