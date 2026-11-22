use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::time::Instant;

use crate::mms::{self, frameguard::Traffic};
use crate::secevent::{AcsePeer, Action, Dispatcher, Event, Kind, PeerInfo, SessionSummary};

use super::server::Inner;

static NEXT_SESSION: AtomicU64 = AtomicU64::new(1);

pub(super) struct Connection {
    pub peer: Option<SocketAddr>,
    pub traffic: Option<Arc<Traffic>>,
    start: Instant,
    deadline: Option<Instant>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    events: Option<Dispatcher>,
    session: Option<(u64, PeerInfo)>,
}

pub(super) enum Setup<T> {
    Finished(T),
    Closing,
    TimedOut,
}

impl Connection {
    pub fn new(inner: &Inner, peer: Option<SocketAddr>, local_addr: Option<SocketAddr>) -> Self {
        let start = Instant::now();
        let limit = inner.handshake_timeout.unwrap_or(Duration::from_secs(10));
        let session = inner.security_events.as_ref().map(|_| {
            (
                NEXT_SESSION.fetch_add(1, Relaxed),
                PeerInfo {
                    remote_addr: peer,
                    local_addr,
                    connected_at: SystemTime::now(),
                    tls: None,
                    acse: None,
                },
            )
        });
        let cx = Self {
            peer,
            traffic: session.as_ref().map(|_| Arc::new(Traffic::default())),
            start,
            deadline: (!limit.is_zero())
                .then(|| start.checked_add(limit))
                .flatten(),
            shutdown: inner.shutdown.subscribe(),
            events: inner.security_events.clone(),
            session,
        };
        cx.emit(Kind::ConnAccepted, Action::Observed, |_| {});
        cx
    }

    pub async fn setup<T>(&mut self, work: impl Future<Output = T>) -> Setup<T> {
        let deadline = self.deadline;
        tokio::select! {
            biased;
            _ = self.shutdown.wait_for(|closed| *closed) => Setup::Closing,
            _ = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            } => Setup::TimedOut,
            result = work => Setup::Finished(result),
        }
    }

    pub fn emit(&self, kind: Kind, action: Action, fill: impl FnOnce(&mut Event)) {
        if let (Some(dispatcher), Some((id, peer))) = (&self.events, &self.session) {
            let mut event = Event::new(kind, action);
            event.session_id = Some(*id);
            event.peer = Some(peer.clone());
            fill(&mut event);
            dispatcher.report(event);
        }
    }

    #[cfg(feature = "tls")]
    pub fn tls(&mut self, tls: &rustls::ServerConnection) {
        use sha2::{Digest, Sha256};
        if let Some((_, peer)) = &mut self.session {
            peer.tls = Some(crate::secevent::TlsPeer {
                version: tls.protocol_version().map(u16::from),
                cipher_suite: tls.negotiated_cipher_suite().map(|s| u16::from(s.suite())),
                server_name: tls.server_name().map(str::to_owned),
                fingerprint_sha256: tls
                    .peer_certificates()
                    .and_then(|c| c.first())
                    .map(|c| format!("{:x}", Sha256::digest(c.as_ref()))),
            });
        }
    }

    #[cfg(feature = "tls")]
    pub fn tls_failed(&self, timeout: bool, error: Option<&std::io::Error>) {
        let kind = if timeout {
            Kind::TlsHandshakeTimeout
        } else {
            Kind::TlsHandshakeFailed
        };
        self.emit(kind, Action::Disconnected, |e| {
            e.protocol = "tls";
            e.error = error.map(ToString::to_string);
        });
    }

    pub fn established(&mut self, assoc: &mms::ServerConn) {
        if let Some((_, peer)) = &mut self.session {
            peer.acse = Some(AcsePeer {
                calling: assoc.calling.clone(),
                called: assoc.called.clone(),
                password_presented: assoc.password.is_some(),
                #[cfg(feature = "tls")]
                a_profile_common_name: assoc
                    .a_profile_peer
                    .as_ref()
                    .and_then(|cert| cert.common_name.clone()),
                #[cfg(not(feature = "tls"))]
                a_profile_common_name: None,
                #[cfg(feature = "tls")]
                a_profile_sha256: assoc.a_profile_sha256.clone(),
                #[cfg(not(feature = "tls"))]
                a_profile_sha256: None,
                #[cfg(feature = "e2e")]
                e2e_peer_ae: assoc.e2e_peer.as_ref().map(|p| p.ae.ap_title.to_string()),
                #[cfg(not(feature = "e2e"))]
                e2e_peer_ae: None,
                #[cfg(feature = "e2e")]
                e2e_association_id: assoc.e2e_peer.as_ref().map(|p| p.association_id.clone()),
                #[cfg(not(feature = "e2e"))]
                e2e_association_id: None,
            });
        }
        self.emit(Kind::AssocEstablished, Action::Observed, |e| {
            e.detail = Some(format!("max PDU {}", assoc.max_pdu));
        });
    }

    pub fn failed(&self, timed_out: bool, error: Option<&mms::Error>) {
        let Some(traffic) = &self.traffic else { return };
        let stage = *traffic.stage.lock().unwrap();
        let no_data = stage == Some("cotp")
            && traffic.octets_in.load(Relaxed) == 0
            && matches!(error, Some(mms::Error::Osi(crate::osi::Error::Io(e))) if e.kind() == std::io::ErrorKind::UnexpectedEof);
        let (kind, action) = if timed_out {
            (Kind::ConnNeverAssociated, Action::Disconnected)
        } else if no_data {
            (Kind::ConnNoData, Action::Observed)
        } else if matches!(
            error,
            Some(mms::Error::AssociationRejected(_) | mms::Error::Rejected(_))
        ) {
            (Kind::AssocSetupFailed, Action::Rejected)
        } else {
            (Kind::AssocSetupFailed, Action::Disconnected)
        };
        self.emit(kind, action, |e| {
            e.stage = stage;
            // An application authenticator can put arbitrary data in its
            // error. Publish the rejection and stage without that text.
            if !no_data && !matches!(stage, Some("auth" | "e2e" | "aprofile")) {
                e.error = error.map(ToString::to_string);
            }
        });
    }

    pub fn closed(&self, local: bool, result: &mms::Result<()>) {
        let Some(traffic) = &self.traffic else { return };
        let (reason, action, event) = match (local, result) {
            (true, _) => ("closed locally", Action::Disconnected, None),
            (_, Ok(()) | Err(mms::Error::Osi(crate::osi::Error::Closed))) => {
                ("concluded", Action::Observed, None)
            }
            (_, Err(mms::Error::FrameTimeout)) => (
                "frame timeout",
                Action::Disconnected,
                Some(Kind::DosSlowFrame),
            ),
            (_, Err(mms::Error::IdleTimeout)) => (
                "idle timeout",
                Action::Disconnected,
                Some(Kind::ConnIdleTimeout),
            ),
            (_, Err(mms::Error::Aborted(_))) => (
                "aborted by peer",
                Action::Observed,
                Some(Kind::AssocAbortedByPeer),
            ),
            (_, Err(mms::Error::Timeout)) => ("write stalled", Action::Disconnected, None),
            (_, Err(mms::Error::Osi(crate::osi::Error::Io(e))))
                if e.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                ("peer closed", Action::Observed, None)
            }
            _ => ("transport error", Action::Observed, None),
        };
        if let Some(kind) = event {
            self.emit(kind, action, |e| {
                e.error = result.as_ref().err().map(ToString::to_string)
            });
        }
        self.emit(Kind::ConnClosed, action, |e| {
            e.summary = Some(SessionSummary {
                reason,
                duration: self.start.elapsed(),
                octets_in: traffic.octets_in.load(Relaxed),
                octets_out: traffic.octets_out.load(Relaxed),
                requests: traffic.requests.load(Relaxed),
            });
        });
    }
}
