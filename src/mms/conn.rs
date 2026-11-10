#[cfg(feature = "e2e")]
use crate::mms::secure as super_e2e;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch, Mutex as AsyncMutex};

use crate::asn1::{self, cons, context_primitive, prim, Decoder, Element};
use crate::osi::{self, acse, cotp, presentation, session};

use super::client_ext::FileServer;
use super::pdu::*;
use super::report::InformationReport;
use super::transport::{self, BoxTransport, FramingReader, FramingWriter};
use super::{Error, ErrorClass, InitiateRequest, Result, ServiceError};

/// The ACSE identity of an application entity, re-exported at the MMS layer so
/// callers do not reach into the OSI modules.
pub type AcseIdentity = acse::Identity;

/// The ACSE application context an association proposes (IEC 61850-8-1).
///
/// The default, [`ApplicationContext::Mms`], is what most servers expect;
/// [`ApplicationContext::Acsi`] is for a server that accepts only the
/// IEC 61850 one.
pub type ApplicationContext = acse::ApplicationContext;

/// The lifecycle state of an association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not established: never dialled, concluded, or dropped by the peer or
    /// the transport.
    Closed,
    /// A handshake in progress. [`Conn::dial`] is awaited to completion and
    /// returns nothing until the association is up, so a `Conn` is never
    /// observed in this state; it exists for parity and for callers tracking
    /// their own connect attempt.
    Connecting,
    /// An established association that can carry requests.
    Connected,
    /// A close that has begun: the conclude has been sent and the transport is
    /// being torn down.
    Closing,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            State::Closed => "closed",
            State::Connecting => "connecting",
            State::Connected => "connected",
            State::Closing => "closing",
        })
    }
}

/// How long a confirmed request waits for its response unless
/// [`Options::request_timeout`] says otherwise.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Configures an MMS client connection.
pub struct Options {
    /// When set, the ACSE authentication value sent in the AARQ.
    pub password: Option<String>,
    /// IEC 62351-4 compatibility-mode authentication.
    #[cfg(feature = "tls")]
    pub a_profile: Option<Arc<crate::iec62351::aprofile::Config>>,
    #[cfg(feature = "e2e")]
    pub e2e: Option<super_e2e::ClientSecurity>,
    /// Overrides the proposed MMS association parameters.
    pub initiate: Option<InitiateRequest>,
    /// Bounds the TCP and association handshake.
    pub connect_timeout: Option<Duration>,
    /// Bounds the wait for each confirmed request's response (and each
    /// Cancel's), after which the request fails with [`Error::Timeout`] and
    /// a late response is discarded. A server that cannot decode a request
    /// may drop it without answering, so without a bound the caller waits
    /// for good. `None` waits indefinitely. The default is
    /// [`DEFAULT_REQUEST_TIMEOUT`].
    ///
    /// It does not bound [`Outstanding::wait`], whose caller holds the
    /// request, nor an ObtainFile, which lasts as long as the server takes
    /// to read the file from this end.
    pub request_timeout: Option<Duration>,
    /// The ACSE identity to address. Devices that check the called AP-title
    /// refuse an association that omits it.
    pub called: AcseIdentity,
    /// The ACSE identity to claim.
    pub calling: AcseIdentity,
    /// The application-context-name the AARQ proposes.
    pub application_context: ApplicationContext,
    /// When set, wraps the TCP connection per IEC 62351-3. The default
    /// MMS-over-TLS port is 3782.
    #[cfg(feature = "tls")]
    pub tls: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
    /// When set, the server name presented in the TLS handshake. Defaults to
    /// the host part of the dial address.
    #[cfg(feature = "tls")]
    pub tls_server_name: Option<String>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("initiate", &self.initiate)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("called", &self.called)
            .field("calling", &self.calling)
            .field("application_context", &self.application_context)
            .finish_non_exhaustive()
    }
}

impl Default for Options {
    fn default() -> Options {
        Options {
            password: None,
            #[cfg(feature = "tls")]
            a_profile: None,
            #[cfg(feature = "e2e")]
            e2e: None,
            initiate: None,
            connect_timeout: None,
            request_timeout: Some(DEFAULT_REQUEST_TIMEOUT),
            called: AcseIdentity::default(),
            calling: AcseIdentity::default(),
            application_context: ApplicationContext::default(),
            #[cfg(feature = "tls")]
            tls: None,
            #[cfg(feature = "tls")]
            tls_server_name: None,
        }
    }
}

/// Bounds a wait by the request timeout, when there is one.
async fn bounded<T>(limit: Option<Duration>, fut: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    match limit {
        Some(d) => tokio::time::timeout(d, fut).await.map_err(|_| Error::Timeout)?,
        None => fut.await,
    }
}

/// Identifies a registered unconfirmed-PDU handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandlerId(u64);

type ReportFn = Arc<dyn Fn(&InformationReport) + Send + Sync>;
type RawFn = Arc<dyn Fn(&[u8]) + Send + Sync>;
/// A registered handler with the id its removal takes.
type Registered<F> = Vec<(u64, F)>;

#[derive(Default)]
struct Handlers {
    reports: Registered<ReportFn>,
    raw: Registered<RawFn>,
}

/// What a pending confirmed call resolves to: the response's service element
/// content, or the error that ended it.
type CallResult = std::result::Result<Vec<u8>, Error>;

struct Lifecycle {
    state: State,
    close_err: Option<Arc<Error>>,
}

pub(crate) struct Shared {
    pending: Mutex<HashMap<u32, oneshot::Sender<CallResult>>>,
    /// Cancel requests awaiting their answer, by the invoke id they cancel.
    cancels: Mutex<HashMap<u32, oneshot::Sender<Result<()>>>>,
    /// Serves the file reads of the ObtainFile in progress, `None` when none
    /// is.
    pub(crate) files: Mutex<Option<Arc<FileServer>>>,
    handlers: Mutex<Handlers>,
    life: Mutex<Lifecycle>,
    done_tx: watch::Sender<bool>,
    next_id: AtomicU32,
    next_handler: AtomicU64,
    request_timeout: Option<Duration>,
    max_pdu: usize,
    pub(crate) writer: Arc<AsyncMutex<FramingWriter>>,
}

impl Shared {
    fn state(&self) -> State {
        self.life.lock().unwrap().state
    }

    /// Returns the error a request on a connection that is not up gets.
    fn closed_error(&self) -> Option<Error> {
        let life = self.life.lock().unwrap();
        if life.state == State::Connected {
            return None;
        }
        Some(match &life.close_err {
            Some(e) => e.duplicate(),
            None => Error::Closed,
        })
    }

    /// Records the cause that ended the association and fails every pending
    /// call with it.
    fn fail_all(&self, err: Error) {
        let err = {
            let mut life = self.life.lock().unwrap();
            // The first cause wins; a Close or Abort records its own before
            // the reader ever sees the transport end.
            if life.state == State::Connected || (life.state == State::Closing && life.close_err.is_none()) {
                life.close_err = Some(Arc::new(err));
            }
            life.state = State::Closed;
            life.close_err
                .clone()
                .unwrap_or_else(|| Arc::new(Error::Closed))
        };
        let pending: Vec<_> = self.pending.lock().unwrap().drain().collect();
        for (_, tx) in pending {
            let _ = tx.send(Err(err.duplicate()));
        }
        let cancels: Vec<_> = self.cancels.lock().unwrap().drain().collect();
        for (_, tx) in cancels {
            let _ = tx.send(Err(err.duplicate()));
        }
        let _ = self.done_tx.send(true);
    }

    fn deliver(&self, id: u32, res: CallResult) {
        let tx = self.pending.lock().unwrap().remove(&id);
        match tx {
            Some(tx) => {
                let _ = tx.send(res);
            }
            None => tracing::warn!(invoke_id = id, "mms: response for unknown invoke id"),
        }
    }

    /// Sends a confirmed request and registers its response slot.
    async fn start(self: &Arc<Self>, service: Element) -> Result<Outstanding> {
        let id = {
            if let Some(e) = self.closed_error() {
                return Err(e);
            }
            self.next_id.fetch_add(1, Ordering::Relaxed)
        };
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);

        // ConfirmedRequestPDU ::= [0] SEQUENCE { invokeID INTEGER, service }
        let req = cons(
            TAG_CONFIRMED_REQUEST,
            [asn1::uint_elem(asn1::TAG_INTEGER, u64::from(id)), service],
        )
        .encode();

        if req.len() > self.max_pdu {
            self.pending.lock().unwrap().remove(&id);
            return Err(Error::protocol("request exceeds negotiated PDU size"));
        }
        tracing::trace!(invoke_id = id, len = req.len(), "mms: tx PDU");
        let send = bounded(self.request_timeout, async {
            self.writer.lock().await.send_mms(&req).await
        }).await;
        if let Err(e) = send {
            self.pending.lock().unwrap().remove(&id);
            self.fail_all(e.duplicate());
            return Err(e);
        }
        Ok(Outstanding {
            shared: Arc::clone(self),
            id,
            rx: Some(rx),
        })
    }
}

/// A confirmed request that has been sent and whose response has not been
/// collected.
///
/// [`wait`](Outstanding::wait) collects the response;
/// [`cancel`](Outstanding::cancel) asks the server to abandon the request.
/// Dropping it without waiting discards the response when it arrives.
pub struct Outstanding {
    shared: Arc<Shared>,
    id: u32,
    rx: Option<oneshot::Receiver<CallResult>>,
}

impl std::fmt::Debug for Outstanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Outstanding").field("invoke_id", &self.id).finish()
    }
}

impl Outstanding {
    /// Returns the request's MMS invoke identifier.
    pub fn invoke_id(&self) -> u32 {
        self.id
    }

    /// Returns the response of the request: its service element content, or
    /// the error the server answered with.
    pub async fn wait(mut self) -> Result<Vec<u8>> {
        let rx = self.rx.take().expect("waited once");
        match rx.await {
            Ok(res) => res,
            // The sender was dropped without a value, which only happens if
            // the reader task died without draining; treat it as a close.
            Err(_) => Err(Error::Closed),
        }
    }

    /// Asks the server to abandon the request (MMS Cancel).
    ///
    /// It returns `Ok` when the server agreed, in which case
    /// [`wait`](Outstanding::wait) reports the request's error; a server that
    /// has already answered, or cannot cancel, refuses with a service error
    /// of class cancel (10).
    pub async fn cancel(&self) -> Result<()> {
        cancel(&self.shared, self.id).await
    }
}

impl Drop for Outstanding {
    fn drop(&mut self) {
        if self.rx.is_some() {
            self.shared.pending.lock().unwrap().remove(&self.id);
        }
    }
}

/// Sends a Cancel-RequestPDU for `invoke_id` and waits for its answer.
async fn cancel(shared: &Arc<Shared>, invoke_id: u32) -> Result<()> {
    if let Some(e) = shared.closed_error() {
        return Err(e);
    }
    let (tx, rx) = oneshot::channel();
    {
        let mut cancels = shared.cancels.lock().unwrap();
        if cancels.contains_key(&invoke_id) {
            return Err(Error::protocol(format!(
                "a cancel of request {invoke_id} is already outstanding"
            )));
        }
        cancels.insert(invoke_id, tx);
    }
    let pdu = asn1::uint_elem(TAG_CANCEL_REQUEST, u64::from(invoke_id)).encode();
    if let Err(e) = bounded(shared.request_timeout, async { shared.writer.lock().await.send_mms(&pdu).await }).await {
        shared.cancels.lock().unwrap().remove(&invoke_id);
        shared.fail_all(e.duplicate());
        return Err(e);
    }
    let res = bounded(shared.request_timeout, async {
        match rx.await {
            Ok(res) => res,
            Err(_) => Err(Error::Closed),
        }
    })
    .await;
    if matches!(res, Err(Error::Timeout)) {
        shared.cancels.lock().unwrap().remove(&invoke_id);
    }
    res
}

/// An established MMS association.
///
/// It is safe for concurrent use: several tasks may issue confirmed requests,
/// which are matched to responses by invoke ID. Unconfirmed PDUs (information
/// reports) are delivered to every handler registered with
/// [`on_information_report`](Conn::on_information_report).
pub struct Conn {
    shared: Arc<Shared>,
    done_rx: watch::Receiver<bool>,
    reader_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    negotiated: InitiateRequest,
    responding: AcseIdentity,
    #[cfg(feature = "tls")]
    a_profile_peer: Option<crate::x509::Certificate>,
    /// Runs one ObtainFile at a time.
    pub(crate) obtain_lock: AsyncMutex<()>,
    #[cfg(feature = "e2e")]
    e2e_peer: Option<crate::iec62351::e2e::PeerSecurity>,
    #[cfg(feature = "e2e")]
    rekey_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("state", &self.state())
            .field("negotiated", &self.negotiated)
            .finish_non_exhaustive()
    }
}

impl Conn {
    /// Establishes an MMS association to a `host:port` address.
    pub async fn dial(addr: &str, opts: Options) -> Result<Conn> {
        let timeout = opts.connect_timeout;
        let fut = Conn::dial_inner(addr, opts);
        match timeout {
            Some(d) => tokio::time::timeout(d, fut)
                .await
                .map_err(|_| Error::Timeout)?,
            None => fut.await,
        }
    }

    async fn dial_inner(addr: &str, opts: Options) -> Result<Conn> {
        let tcp = TcpStream::connect(addr).await?;
        // Nagle would coalesce a request with the next one and add latency to
        // every round trip; MMS is strictly request/response.
        let _ = tcp.set_nodelay(true);

        #[allow(unused_mut)]
        let mut tls_peer_certificate: Option<Vec<u8>> = None;
        #[cfg(feature = "tls")]
        let stream: BoxTransport = match &opts.tls {
            Some(cfg) => {
                let name = opts
                    .tls_server_name
                    .clone()
                    .unwrap_or_else(|| addr.rsplit_once(':').map_or(addr, |(h, _)| h).trim_start_matches('[').trim_end_matches(']').to_string());
                let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(name)
                    .map_err(|e| Error::protocol(format!("invalid TLS server name: {e}")))?;
                let connector = tokio_rustls::TlsConnector::from(cfg.clone());
                let tls = connector.connect(server_name, tcp).await?;
                tls_peer_certificate = tls.get_ref().1.peer_certificates().and_then(|chain| chain.first()).map(|cert| cert.to_vec());
                Box::new(tls)
            }
            None => Box::new(tcp),
        };
        #[cfg(not(feature = "tls"))]
        let stream: BoxTransport = Box::new(tcp);

        Conn::handshake(stream, opts, tls_peer_certificate).await
    }

    /// Establishes an association over an already-connected stream.
    ///
    /// This is what the in-memory tests and the TLS path share, and it is the
    /// entry point for callers that bring their own transport.
    pub async fn from_stream(stream: BoxTransport, opts: Options) -> Result<Conn> {
        bounded(opts.connect_timeout, Conn::handshake(stream, opts, None)).await
    }

    async fn handshake(stream: BoxTransport, opts: Options, #[allow(unused_variables)] tls_peer_certificate: Option<Vec<u8>>) -> Result<Conn> {
        let mut ct = cotp::Conn::connect(stream, cotp::Options::default()).await?;

        let init = opts.initiate.clone().unwrap_or_default();
        #[cfg(feature = "e2e")]
        if let Some(security) = &opts.e2e {
            if opts.password.as_ref().is_some_and(|p| !p.is_empty()) || opts.a_profile.is_some() {
                return Err(Error::protocol("E2E uses the ACSE kernel and cannot be combined with password or A-profile"));
            }
            let (reader, mut writer, negotiated, responding) = super::secure::client_handshake(ct, &opts, security, &init, tls_peer_certificate.as_deref()).await?;
            writer.write_timeout = opts.request_timeout;
            return Self::established(reader, writer, negotiated, responding, opts.request_timeout);
        }
        // The ACSE AARQ wraps the MMS InitiateRequest; the presentation CP
        // wraps the AARQ; the session CONNECT carries the CP.
        let aarq = acse::aarq_for(
            &encode_initiate_request(&init),
            opts.password.as_deref().unwrap_or(""),
            &opts.called,
            &opts.calling,
            opts.application_context,
        );
        #[cfg(feature = "tls")]
        let aarq = if let Some(ap) = &opts.a_profile {
            if opts.password.as_ref().is_some_and(|p| !p.is_empty()) {
                return Err(Error::protocol("A-profile cannot be combined with a password"));
            }
            if opts.tls.is_none() && !ap.allow_without_tls {
                return Err(Error::protocol("A-profile requires TLS"));
            }
            let value = ap.value()?;
            acse::with_authentication(&aarq, true, &ap.mechanism.clone().unwrap_or_else(crate::iec62351::aprofile::mechanism), &value.encode())?
        } else { aarq };
        let cp = presentation::build_cp(
            presentation::DEFAULT_CALLING_PSEL,
            presentation::DEFAULT_CALLED_PSEL,
            &aarq,
        );
        let cpa_user_data = match session::connect_client(&mut ct, &[], &[], &cp).await {
            Ok(ud) => ud,
            Err(osi::Error::Refused { reason, user_data }) => {
                // A refused association: the CPR carries the AARE saying why.
                if let Ok(aare) = presentation::parse_cpr_user_data(&user_data) {
                    if let Ok(res) = acse::parse_aare(&aare) {
                        if !res.accepted {
                            return Err(Error::Rejected(res.diagnostic));
                        }
                    }
                }
                return Err(Error::protocol(format!(
                    "association refused at the session layer (reason {reason})"
                )));
            }
            Err(e) => return Err(e.into()),
        };
        let aare = presentation::parse_cp_user_data(&cpa_user_data)?;
        let res = acse::parse_aare(&aare)?;
        if !res.accepted {
            return Err(Error::Rejected(res.diagnostic));
        }
        #[cfg(feature = "tls")]
        let a_profile_peer = if let Some(ap) = &opts.a_profile {
            let verified = (|| {
                if res.mechanism.is_none() { return Err(Error::protocol("AARE has no authentication mechanism")); }
                let value = res.authentication.as_deref().ok_or_else(|| Error::protocol("AARE has no A-profile value"))?;
                let value = crate::iec62351::aprofile::Value::parse(value)?;
                ap.verifier.verify(&value).map_err(Error::from)
            })();
            match verified {
                Ok(cert) => Some(cert),
                Err(e) => {
                    let _ = session::abort(&mut ct, &[]).await;
                    return Err(e);
                }
            }
        } else { None };
        if opts.called.ap_title.as_ref().is_some_and(|id| Some(id) != res.responding.ap_title.as_ref())
            || opts.called.ae_qualifier.is_some_and(|id| Some(id) != res.responding.ae_qualifier) {
            return Err(Error::protocol("responding ACSE identity does not match called identity"));
        }
        let negotiated = parse_initiate_response(&res.user_data)?;

        // We proposed the contexts, so their identifiers are ours.
        let (reader, mut writer) =
            transport::split(ct, presentation::CONTEXT_MMS, presentation::CONTEXT_ACSE);
        writer.write_timeout = opts.request_timeout;
        #[allow(unused_mut)]
        let mut conn = Self::established(reader, writer, negotiated, res.responding, opts.request_timeout)?;
        #[cfg(feature = "tls")]
        { conn.a_profile_peer = a_profile_peer; }
        Ok(conn)
    }

    #[allow(unused_mut)]
    fn established(mut reader: FramingReader, writer: FramingWriter, negotiated: InitiateRequest, responding: AcseIdentity, request_timeout: Option<Duration>) -> Result<Self> {
        #[cfg(feature = "e2e")]
        let security = writer.security.clone();
        #[cfg(feature = "e2e")]
        let e2e_peer = security.as_ref().and_then(|s| s.association.lock().unwrap().peer_security().cloned());
        let (done_tx, done_rx) = watch::channel(false);
        let writer = Arc::new(AsyncMutex::new(writer));
        #[cfg(feature = "e2e")]
        reader.attach_writer(writer.clone());
        let shared = Arc::new(Shared {
            pending: Mutex::new(HashMap::new()),
            cancels: Mutex::new(HashMap::new()),
            files: Mutex::new(None),
            handlers: Mutex::new(Handlers::default()),
            life: Mutex::new(Lifecycle {
                state: State::Connected,
                close_err: None,
            }),
            done_tx,
            next_id: AtomicU32::new(1),
            next_handler: AtomicU64::new(1),
            request_timeout,
            max_pdu: usize::try_from(negotiated.local_detail).unwrap_or(0).max(1),
            writer,
        });

        let reader_task = tokio::spawn(read_loop(reader, Arc::clone(&shared)));
        #[cfg(feature = "e2e")]
        let rekey_task = security.map(|security| {
            let weak = Arc::downgrade(&shared);
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(1));
                loop {
                    ticker.tick().await;
                    let Some(shared) = weak.upgrade() else { return };
                    if shared.state() != State::Connected { return; }
                    let overdue = security.association.lock().unwrap().rekey_overdue(Duration::from_secs(30));
                    if overdue {
                        shared.fail_all(Error::E2E(crate::iec62351::e2e::Error::data(0, "rekey acknowledgement overdue")));
                        let _ = shared.writer.lock().await.shutdown().await;
                        return;
                    }
                    let due = security.association.lock().unwrap().rekey_due();
                    if due {
                        let request = asn1::bool_elem(context_primitive(super::service::STATUS as u32), false);
                        match shared.start(request).await {
                            Ok(request) => { let _ = bounded(shared.request_timeout, request.wait()).await; }
                            Err(_) => return,
                        }
                    }
                }
            })
        });

        Ok(Conn {
            shared,
            done_rx,
            reader_task: Mutex::new(Some(reader_task)),
            negotiated,
            responding,
            #[cfg(feature = "tls")]
            a_profile_peer: None,
            obtain_lock: AsyncMutex::new(()),
            #[cfg(feature = "e2e")]
            e2e_peer,
            #[cfg(feature = "e2e")]
            rekey_task: Mutex::new(rekey_task),
        })
    }

    /// Returns the ACSE identity the peer answered with in its AARE.
    ///
    /// It is empty when the peer omitted it, which is legal, and which a proxy
    /// has to reproduce faithfully rather than inventing one.
    #[cfg(feature = "tls")]
    pub fn peer_a_profile_certificate(&self) -> Option<&crate::x509::Certificate> {
        self.a_profile_peer.as_ref()
    }

    #[cfg(feature = "e2e")]
    pub fn peer_e2e_security(&self) -> Option<&crate::iec62351::e2e::PeerSecurity> { self.e2e_peer.as_ref() }

    pub fn responding_identity(&self) -> &AcseIdentity {
        &self.responding
    }

    /// Returns the association parameters agreed during the initiate exchange.
    ///
    /// A proxy replays these so its own clients see the capabilities the real
    /// device advertised, in particular the `servicesSupported` bit string
    /// that clients gate feature use on.
    pub fn negotiated(&self) -> &InitiateRequest {
        &self.negotiated
    }

    /// Returns the negotiated maximum outstanding services.
    pub fn max_serv_outstanding(&self) -> i32 {
        self.negotiated.max_serv_outstanding
    }

    /// Reports the lifecycle state of the association.
    ///
    /// It becomes [`State::Closed`] as soon as the reader task sees the
    /// transport end, so a peer that drops the association is visible without
    /// issuing a request first.
    pub fn state(&self) -> State {
        self.shared.state()
    }

    /// Returns the error that ended the association, or `None` while it is
    /// still up.
    pub fn err(&self) -> Option<Arc<Error>> {
        let life = self.shared.life.lock().unwrap();
        match life.state {
            State::Connected | State::Connecting => None,
            _ => life.close_err.clone(),
        }
    }

    /// Resolves when the association ends, whether from [`close`](Conn::close),
    /// [`abort`](Conn::abort), a peer disconnect or a transport error.
    ///
    /// This is the push counterpart to polling [`state`](Conn::state). By the
    /// time it returns, `state` reports [`State::Closed`] and [`err`](Conn::err)
    /// reports the cause.
    pub async fn closed(&self) {
        let mut rx = self.done_rx.clone();
        if *rx.borrow() {
            return;
        }
        // A send error means the sender is gone, which also means it is over.
        let _ = rx.wait_for(|done| *done).await;
    }

    /// Registers a handler for unconfirmed information reports (used by ACSI
    /// reporting) and returns its id, which
    /// [`remove_handler`](Conn::remove_handler) takes.
    ///
    /// Handlers are additive and are called in registration order: an
    /// association carrying several report subscriptions delivers every report
    /// to all of them, so a later registration never silences an earlier one.
    ///
    /// Handlers must be registered before enabling any report. They run on the
    /// connection's reader task and must not block; hand heavy work to your
    /// own task.
    pub fn on_information_report(
        &self,
        f: impl Fn(&InformationReport) + Send + Sync + 'static,
    ) -> HandlerId {
        let id = self.shared.next_handler.fetch_add(1, Ordering::Relaxed);
        self.shared
            .handlers
            .lock()
            .unwrap()
            .reports
            .push((id, Arc::new(f)));
        HandlerId(id)
    }

    /// Registers a handler receiving the undecoded content of every
    /// unconfirmed PDU, before the decoded report handlers run.
    ///
    /// It exists for proxies and diagnostics that must reproduce or record
    /// exactly what arrived. Like [`on_information_report`](Conn::on_information_report),
    /// handlers are additive, run on the reader task and must not block.
    pub fn on_raw_unconfirmed(&self, f: impl Fn(&[u8]) + Send + Sync + 'static) -> HandlerId {
        let id = self.shared.next_handler.fetch_add(1, Ordering::Relaxed);
        self.shared
            .handlers
            .lock()
            .unwrap()
            .raw
            .push((id, Arc::new(f)));
        HandlerId(id)
    }

    /// Removes a previously registered handler. Idempotent.
    pub fn remove_handler(&self, id: HandlerId) {
        let mut h = self.shared.handlers.lock().unwrap();
        h.reports.retain(|(i, _)| *i != id.0);
        h.raw.retain(|(i, _)| *i != id.0);
    }

    /// Issues a confirmed request carrying the given service element and
    /// returns the response's service element content.
    ///
    /// This is the escape hatch for services this crate does not wrap: a
    /// thorough census wants to try `GetCapabilityList` and vendor services,
    /// and a proxy may need to forward whatever a client sends. A confirmed
    /// error comes back as [`Error::Service`], a per-item access failure as
    /// [`Error::Access`]. It is bounded by [`Options::request_timeout`].
    pub async fn call(&self, service: Element) -> Result<Vec<u8>> {
        self.call_inner(service).await
    }

    pub(crate) async fn call_inner(&self, service: Element) -> Result<Vec<u8>> {
        // Dropping the request on a timeout releases its response slot.
        let req = self.start(service).await?;
        bounded(self.shared.request_timeout, req.wait()).await
    }

    /// Issues a confirmed request and waits for its response without the
    /// request timeout.
    pub(crate) async fn call_unbounded(&self, service: Element) -> Result<Vec<u8>> {
        self.start(service).await?.wait().await
    }

    /// Sends a confirmed request and returns without waiting for its
    /// response.
    ///
    /// [`Outstanding::wait`] collects it; [`Outstanding::cancel`] asks the
    /// server to abandon it.
    pub async fn start(&self, service: Element) -> Result<Outstanding> {
        self.shared.start(service).await
    }

    /// Asks the server to abandon the outstanding request with the given
    /// invoke identifier (ISO 9506 Cancel).
    pub async fn cancel(&self, invoke_id: u32) -> Result<()> {
        cancel(&self.shared, invoke_id).await
    }

    /// Ends the association abruptly (ACSE A-ABORT): nothing more is sent or
    /// answered, and requests still outstanding fail with
    /// [`Error::Aborted`]. [`close`](Conn::close) releases the association in
    /// order and is what a client normally uses.
    pub async fn abort(&self) -> Result<()> {
        {
            let mut life = self.shared.life.lock().unwrap();
            if life.state != State::Connected {
                return Ok(());
            }
            life.state = State::Closing;
            life.close_err = Some(Arc::new(Error::Aborted(" by this end".into())));
        }
        let res = {
            let mut w = self.shared.writer.lock().await;
            let res = w.send_abort().await;
            let _ = w.shutdown().await;
            res
        };
        self.shared.fail_all(Error::Closed);
        self.finish_close().await;
        res
    }

    /// Releases the association (a best-effort MMS conclude) and closes the
    /// transport.
    pub async fn close(&self) -> Result<()> {
        {
            let mut life = self.shared.life.lock().unwrap();
            if life.state != State::Connected {
                return Ok(());
            }
            // Concurrent callers see Closing until the reader has drained.
            life.state = State::Closing;
            life.close_err = Some(Arc::new(Error::Closed));
        }

        #[cfg(feature = "e2e")]
        {
            let mut w = self.shared.writer.lock().await;
            if w.security.is_some() {
                self.shared.life.lock().unwrap().close_err = None;
                let sent = w.send_release(false).await;
                drop(w);
                let outcome = if sent.is_ok() {
                    bounded(self.shared.request_timeout, async {
                        self.closed().await;
                        match self.err() { Some(error) if !matches!(&*error, Error::Closed) => Err(error.duplicate()), _ => Ok(()) }
                    }).await
                } else { sent };
                self.shared.fail_all(match &outcome { Err(error) => error.duplicate(), _ => Error::Closed });
                let _ = self.shared.writer.lock().await.shutdown().await;
                self.finish_close().await;
                return outcome;
            }
        }
        {
            let mut w = self.shared.writer.lock().await;
            let conclude = prim(TAG_CONCLUDE_REQUEST, Vec::new()).encode();
            let _ = w.send_mms(&conclude).await;
            let _ = w.shutdown().await;
        }
        self.shared.fail_all(Error::Closed);
        self.finish_close().await;
        Ok(())
    }

    async fn finish_close(&self) {
        // The reader's fail_all moves the state to Closed and wakes `closed`.
        self.closed().await;
        let handle = self.reader_task.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.await;
        }
        self.shared.life.lock().unwrap().state = State::Closed;
    }

    pub(crate) fn shared(&self) -> &Arc<Shared> {
        &self.shared
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        #[cfg(feature = "e2e")]
        if let Some(task) = self.rekey_task.lock().unwrap().take() { task.abort(); }
        // Stop the reader rather than leaking a task that holds the socket.
        if let Some(h) = self.reader_task.lock().unwrap().take() {
            h.abort();
        }
    }
}

async fn read_loop(mut reader: FramingReader, shared: Arc<Shared>) {
    let mut done = shared.done_tx.subscribe();
    loop {
        if *done.borrow() { return; }
        let received = tokio::select! {
            _ = done.changed() => return,
            received = reader.recv_mms() => received,
        };
        match received {
            Ok(pdu) => dispatch(&pdu, &shared),
            Err(e) => {
                shared.fail_all(e);
                return;
            }
        }
    }
}

fn dispatch(pdu: &[u8], shared: &Arc<Shared>) {
    let mut dec = Decoder::new(pdu);
    let Ok((tag, content)) = dec.read_tlv() else {
        tracing::warn!("mms: bad PDU");
        return;
    };
    tracing::trace!(%tag, len = pdu.len(), "mms: rx PDU");

    if tag == TAG_CONFIRMED_RESPONSE || tag == TAG_CONFIRMED_ERROR {
        let Ok((id, body)) = split_invoke(content) else {
            tracing::warn!("mms: bad confirmed PDU");
            return;
        };
        let res = if tag == TAG_CONFIRMED_RESPONSE {
            Ok(body.to_vec())
        } else {
            Err(Error::Service(decode_service_error(body)))
        };
        shared.deliver(id, res);
    } else if tag == TAG_REJECT_PDU {
        deliver_reject(content, shared);
    } else if tag == TAG_UNCONFIRMED {
        handle_unconfirmed(content, shared);
    } else if tag == TAG_CONCLUDE_RESPONSE || tag == TAG_CONCLUDE_RESPONSE_LEGACY {
        // The peer accepted our conclude; the reader will see EOF next.
    } else if tag == TAG_CANCEL_RESPONSE || tag == TAG_CANCEL_ERROR {
        deliver_cancel(tag, content, shared);
    } else if tag == TAG_CONFIRMED_REQUEST {
        // A request from the server: the file reads of an ObtainFile this end
        // asked for. Served off the reader, which has to keep delivering the
        // responses the ObtainFile is waiting on.
        let shared = Arc::clone(shared);
        let content = content.to_vec();
        tokio::spawn(async move { super::client_ext::serve_request(&shared, &content).await });
    } else {
        tracing::debug!(%tag, "mms: unhandled PDU tag");
    }
}

/// Hands a Cancel-ResponsePDU or Cancel-ErrorPDU to the cancel waiting for
/// it.
fn deliver_cancel(tag: asn1::Tag, content: &[u8], shared: &Arc<Shared>) {
    let (id, res) = if tag == TAG_CANCEL_RESPONSE {
        let Ok(n) = asn1::decode_uint(content) else {
            return;
        };
        (n as u32, Ok(()))
    } else {
        // Cancel-ErrorPDU ::= SEQUENCE { originalInvokeID [0], serviceError [1] }
        let mut dec = Decoder::new(content);
        let Ok(b) = dec.expect(context_primitive(0)) else {
            return;
        };
        let id = asn1::decode_uint(b).unwrap_or(0) as u32;
        let mut se = ServiceError::new(ErrorClass(0), 0);
        if let Some((class, code)) = drill_error_class(dec.rest(), 0) {
            se.class = ErrorClass(class);
            se.code = code;
        }
        (id, Err(Error::Service(se)))
    };
    if let Some(tx) = shared.cancels.lock().unwrap().remove(&id) {
        let _ = tx.send(res);
    }
}

/// Parses a RejectPDU (`originalInvokeID [0] IMPLICIT Unsigned32 OPTIONAL`,
/// `rejectReason CHOICE`) and delivers a [`ServiceError`].
fn deliver_reject(content: &[u8], shared: &Arc<Shared>) {
    let mut dec = Decoder::new(content);
    let mut id = 0u32;
    match dec.optional(context_primitive(0)) {
        Ok(Some(b)) => id = asn1::decode_uint(b).unwrap_or(0) as u32,
        Ok(None) => {}
        Err(_) => {
            tracing::warn!("mms: bad reject PDU");
            return;
        }
    }
    let mut se = ServiceError {
        class: ErrorClass(0),
        code: 0,
        rejected: true,
        detail: String::new(),
    };
    if dec.more() {
        if let Ok((tag, rr)) = dec.read_tlv() {
            se.class = ErrorClass(tag.number as u8);
            if let Ok(n) = asn1::decode_int(rr) {
                se.code = n as u8;
            }
            se.detail = reject_reason_name(tag.number, se.code);
        }
    }
    shared.deliver(id, Err(Error::Service(se)));
}

pub(crate) fn decode_service_error(body: &[u8]) -> ServiceError {
    // ConfirmedErrorPDU carries serviceError { errorClass [n] CHOICE }. The
    // nesting varies by MMS module, so drill to the innermost primitive
    // context-specific element: its tag number is the error class and its
    // content the code.
    let mut se = ServiceError {
        class: ErrorClass(0),
        code: 0,
        rejected: false,
        detail: String::new(),
    };
    if let Some((class, code)) = drill_error_class(body, 0) {
        se.class = ErrorClass(class);
        se.code = code;
    }
    se
}

fn handle_unconfirmed(content: &[u8], shared: &Arc<Shared>) {
    // The raw handlers run first and see every unconfirmed PDU, including
    // services this crate does not decode. A proxy that must reproduce what
    // arrived needs the octets, not an interpretation of them.
    let (raw, reports) = {
        let h = shared.handlers.lock().unwrap();
        (h.raw.clone(), h.reports.clone())
    };
    for (_, f) in &raw {
        f(content);
    }

    let mut dec = Decoder::new(content);
    let Ok((tag, body)) = dec.read_tlv() else {
        return;
    };
    if tag != asn1::context_constructed(UNCONF_INFORMATION_REPORT) {
        return;
    }
    let Some(rep) = super::report::parse_information_report(body) else {
        return;
    };
    for (_, f) in &reports {
        f(&rep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_renders_each_phase() {
        assert_eq!(State::Closed.to_string(), "closed");
        assert_eq!(State::Connecting.to_string(), "connecting");
        assert_eq!(State::Connected.to_string(), "connected");
        assert_eq!(State::Closing.to_string(), "closing");
    }

    #[test]
    fn a_confirmed_error_pdu_decodes_to_its_class_and_code() {
        // serviceError { errorClass { access [7] INTEGER 3 } }
        let body = cons(
            asn1::context_constructed(0),
            [asn1::int_elem(context_primitive(7), 3)],
        )
        .encode();
        let se = decode_service_error(&body);
        assert_eq!(se.class, ErrorClass::ACCESS);
        assert_eq!(se.code, 3);
        assert!(!se.rejected);
    }

    #[test]
    fn an_undecodable_error_body_still_yields_a_service_error() {
        let se = decode_service_error(&[]);
        assert_eq!(se.class, ErrorClass(0));
        assert!(!se.rejected);
    }
}
