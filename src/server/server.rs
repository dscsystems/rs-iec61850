use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use tokio::net::{TcpListener, TcpStream};

use crate::mms::{self, BoxTransport, Value};
use crate::model::{AddCause, Fc, Model, ObjectReference};

use super::access;
use super::control::ControlCtx;
use super::file::FileStore;
use super::reporting::ReportManager;
use super::select::Selections;
use super::{ConnId, Error, Result, Tx};

/// The associations a server is holding, by id.
pub type ConnMap = HashMap<ConnId, Arc<mms::ServerConn>>;

/// A handler consulted before applying a client write.
///
/// Returning an error rejects the write with the corresponding MMS
/// `DataAccessError`.
pub type WriteHandler = Arc<
    dyn Fn(&crate::model::DataAttribute, &Value) -> std::result::Result<(), mms::DataAccessError>
        + Send
        + Sync,
>;

/// Decides whether a control is allowed and applies its effect.
///
/// Returning [`AddCause::NONE`] accepts the command; any other value rejects
/// it with that additional cause.
pub type ControlHandler = Arc<dyn Fn(&ControlCtx) -> AddCause + Send + Sync>;

/// Called when a client connection opens, closes, or is refused.
pub type ConnectionHandler = Arc<dyn Fn(&ConnectionEvent) + Send + Sync>;

/// The identity returned by the Identify service.
#[derive(Debug, Clone)]
pub struct Identity {
    pub vendor: String,
    pub model: String,
    pub revision: String,
}

impl Default for Identity {
    fn default() -> Identity {
        Identity {
            vendor: "rs-iec61850".into(),
            model: String::new(),
            revision: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// What happened to a client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// An association that completed its handshake.
    Opened,
    /// An association that has ended, by either side.
    Closed,
    /// A connection dropped without an association, because the server was
    /// already at its maximum.
    Refused,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ConnectionState::Opened => "opened",
            ConnectionState::Closed => "closed",
            ConnectionState::Refused => "refused",
        })
    }
}

/// Describes a change in the server's client connections.
#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    /// The client's transport address, when the transport has one.
    pub peer: Option<SocketAddr>,
    pub state: ConnectionState,
    /// The number of connections held just after the event, counting
    /// associations still setting up.
    pub open: usize,
    /// The association's id. `None` for a refused connection, which never
    /// became one.
    pub conn: Option<ConnId>,
}

/// Configures a [`Server`].
#[derive(Default)]
pub struct Options {
    /// The Identify response.
    pub identity: Option<Identity>,
    /// Enables MMS file services backed by this directory.
    pub file_store: Option<std::path::PathBuf>,
    /// Caps the number of client connections served at once.
    ///
    /// A client arriving at the cap is dropped at the transport, before any
    /// association is set up, and reported as [`ConnectionState::Refused`].
    /// Zero, the default, is unlimited.
    pub max_connections: usize,
    /// How many reports a buffered control block retains while no subscriber
    /// is enabled, for the blocks that set no size of their own.
    pub report_buffer_size: usize,
    /// Enables setting-group handling with this many groups.
    pub setting_groups: u8,
    /// Enables TLS per IEC 62351-3.
    #[cfg(feature = "tls")]
    pub tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("identity", &self.identity)
            .field("file_store", &self.file_store)
            .field("max_connections", &self.max_connections)
            .field("report_buffer_size", &self.report_buffer_size)
            .field("setting_groups", &self.setting_groups)
            .finish_non_exhaustive()
    }
}

impl Options {
    pub fn new() -> Options {
        Options::default()
    }

    #[must_use]
    pub fn with_identity(mut self, id: Identity) -> Options {
        self.identity = Some(id);
        self
    }

    #[must_use]
    pub fn with_file_store(mut self, root: impl Into<std::path::PathBuf>) -> Options {
        self.file_store = Some(root.into());
        self
    }

    #[must_use]
    pub fn with_max_connections(mut self, n: usize) -> Options {
        self.max_connections = n;
        self
    }

    #[must_use]
    pub fn with_report_buffer_size(mut self, n: usize) -> Options {
        self.report_buffer_size = n;
        self
    }

    #[must_use]
    pub fn with_setting_groups(mut self, n: u8) -> Options {
        self.setting_groups = n;
        self
    }

    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, cfg: Arc<tokio_rustls::rustls::ServerConfig>) -> Options {
        self.tls = Some(cfg);
        self
    }
}

/// The shared state behind a [`Server`].
pub(crate) struct Inner {
    pub model: RwLock<Model>,
    pub reports: ReportManager,
    pub conns: Mutex<ConnMap>,
    pub selections: Mutex<Selections>,
    pub controls: RwLock<HashMap<ObjectReference, ControlHandler>>,
    pub write_handler: RwLock<Option<WriteHandler>>,
    pub conn_handler: Mutex<Option<ConnectionHandler>>,
    pub identity: Identity,
    pub files: Option<FileStore>,
    pub setting_groups: std::collections::BTreeMap<String, super::SettingGroupManager>,
    pub max_conns: usize,
    pub open: Mutex<usize>,
    pub next_conn: AtomicU64,
    #[cfg(feature = "tls")]
    pub tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
}

impl std::fmt::Debug for Inner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inner")
            .field("identity", &self.identity)
            .field("open", &*self.open.lock().unwrap())
            .field("max_conns", &self.max_conns)
            .finish_non_exhaustive()
    }
}

impl Inner {
    /// Reserves one connection slot, reporting the resulting count and whether
    /// the limit allowed it.
    fn take_slot(&self) -> (usize, bool) {
        let mut open = self.open.lock().unwrap();
        if self.max_conns > 0 && *open >= self.max_conns {
            return (*open, false);
        }
        *open += 1;
        (*open, true)
    }

    fn release_slot(&self) -> usize {
        let mut open = self.open.lock().unwrap();
        *open = open.saturating_sub(1);
        *open
    }

    fn notify(&self, ev: ConnectionEvent) {
        let h = self.conn_handler.lock().unwrap().clone();
        if let Some(h) = h {
            h(&ev);
        }
    }
}

/// Serves one IED data model over MMS.
#[derive(Debug, Clone)]
pub struct Server {
    pub(crate) inner: Arc<Inner>,
}

impl Server {
    /// Returns a server serving `model`.
    ///
    /// Report control blocks are materialised into the model here, so they
    /// read and write through the ordinary variable path.
    pub fn new(model: Model, opts: Options) -> Server {
        let mut model = model;
        let mut identity = opts.identity.unwrap_or_default();
        if identity.model.is_empty() {
            identity.model = model.name.clone();
        }
        // Setting groups are materialised before the report engine, so an
        // SGCB appears in the model the blocks are built from.
        let setting_groups = if opts.setting_groups > 0 {
            super::settinggroup::materialise_sgcbs(&mut model, opts.setting_groups)
        } else {
            std::collections::BTreeMap::new()
        };
        // A control refusal reports its cause through LastApplError, so the
        // model must carry one whether or not the SCL declared it.
        super::control::materialise_last_appl_error(&mut model);
        let reports = ReportManager::new(&mut model, opts.report_buffer_size);

        Server {
            inner: Arc::new(Inner {
                model: RwLock::new(model),
                reports,
                conns: Mutex::new(HashMap::new()),
                selections: Mutex::new(Selections::default()),
                controls: RwLock::new(HashMap::new()),
                write_handler: RwLock::new(None),
                conn_handler: Mutex::new(None),
                identity,
                files: opts.file_store.map(FileStore::new),
                setting_groups,
                max_conns: opts.max_connections,
                open: Mutex::new(0),
                next_conn: AtomicU64::new(1),
                #[cfg(feature = "tls")]
                tls: opts.tls,
            }),
        }
    }

    /// Registers a handler consulted before applying a client write.
    ///
    /// Returning an error rejects the write with the corresponding MMS
    /// `DataAccessError`; returning `Ok` allows it, and the value is then
    /// applied.
    pub fn on_write(
        &self,
        h: impl Fn(&crate::model::DataAttribute, &Value) -> std::result::Result<(), mms::DataAccessError>
            + Send
            + Sync
            + 'static,
    ) {
        *self.inner.write_handler.write().unwrap() = Some(Arc::new(h));
    }

    /// Registers a handler for the controllable object at `reference`.
    ///
    /// Both the select and operate phases are delivered; inspect
    /// [`ControlCtx::select`]. With no handler registered, operates are
    /// accepted and the object's sibling `stVal` is set to the control value.
    pub fn on_control(
        &self,
        reference: impl Into<ObjectReference>,
        h: impl Fn(&ControlCtx) -> AddCause + Send + Sync + 'static,
    ) {
        self.inner
            .controls
            .write()
            .unwrap()
            .insert(reference.into(), Arc::new(h));
    }

    /// Registers a handler called when a client connection opens, closes, or
    /// is refused for exceeding the maximum.
    ///
    /// It runs on the connection's own task, so it must not block and must not
    /// call back into [`update`](Server::update). Registering a second handler
    /// replaces the first; register before serving, or the first clients may
    /// connect unobserved.
    pub fn on_connection(&self, h: impl Fn(&ConnectionEvent) + Send + Sync + 'static) {
        *self.inner.conn_handler.lock().unwrap() = Some(Arc::new(h));
    }

    /// Binds to `addr` and serves associations until the future is dropped.
    pub async fn listen_and_serve(&self, addr: &str) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        self.serve(listener).await
    }

    /// Binds to `addr` and returns the listener, so a caller can learn the
    /// bound port before serving.
    pub async fn bind(&self, addr: &str) -> Result<TcpListener> {
        Ok(TcpListener::bind(addr).await?)
    }

    /// Accepts associations on `listener` until the future is dropped.
    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, peer) = listener.accept().await?;
            let server = self.clone();
            tokio::spawn(async move {
                server.serve_conn(stream, peer).await;
            });
        }
    }

    /// Serves one already-accepted connection.
    ///
    /// This is what the in-memory tests use, and the entry point for callers
    /// that bring their own transport.
    pub async fn serve_stream(&self, stream: BoxTransport, peer: Option<SocketAddr>) {
        self.serve_transport(stream, peer).await;
    }

    async fn serve_conn(&self, stream: TcpStream, peer: SocketAddr) {
        // Nagle would add latency to every response; MMS is request/response.
        let _ = stream.set_nodelay(true);

        #[cfg(feature = "tls")]
        let transport: BoxTransport = match &self.inner.tls {
            Some(cfg) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(cfg));
                match acceptor.accept(stream).await {
                    Ok(s) => Box::new(s),
                    Err(e) => {
                        tracing::warn!(%peer, error = %e, "server: TLS handshake failed");
                        return;
                    }
                }
            }
            None => Box::new(stream),
        };
        #[cfg(not(feature = "tls"))]
        let transport: BoxTransport = Box::new(stream);

        self.serve_transport(transport, Some(peer)).await;
    }

    async fn serve_transport(&self, stream: BoxTransport, peer: Option<SocketAddr>) {
        let inner = &self.inner;

        // The slot is taken before the handshake, so a flood of half-open
        // connections cannot outrun the limit.
        let (open, allowed) = inner.take_slot();
        if !allowed {
            tracing::warn!(?peer, max = inner.max_conns, "server: connection refused");
            inner.notify(ConnectionEvent {
                peer,
                state: ConnectionState::Refused,
                open,
                conn: None,
            });
            return;
        }

        let sc = match mms::accept_conn(stream, peer).await {
            Ok(sc) => Arc::new(sc),
            Err(e) => {
                tracing::warn!(?peer, error = %e, "server: association setup failed");
                inner.release_slot();
                return;
            }
        };

        let id = ConnId(inner.next_conn.fetch_add(1, Ordering::Relaxed));
        let open = {
            let mut conns = inner.conns.lock().unwrap();
            conns.insert(id, Arc::clone(&sc));
            conns.len()
        };
        tracing::info!(?peer, %id, "server: association established");
        inner.notify(ConnectionEvent {
            peer,
            state: ConnectionState::Opened,
            open,
            conn: Some(id),
        });

        let handler = super::handler::Handler {
            inner: Arc::clone(inner),
            conn: id,
        };
        if let Err(e) = sc.serve(&handler).await {
            tracing::debug!(?peer, %id, error = %e, "server: association ended");
        }

        // Everything the association held goes with it: its reservations, its
        // report subscriptions and its slot.
        inner.conns.lock().unwrap().remove(&id);
        let open = inner.release_slot();
        inner.reports.disable_conn(id);
        inner.selections.lock().unwrap().release_conn(id);
        let _ = sc.close().await;
        inner.notify(ConnectionEvent {
            peer,
            state: ConnectionState::Closed,
            open,
            conn: Some(id),
        });
    }

    /// Returns how many client connections the server is holding, counting
    /// associations still setting up.
    pub fn open_connections(&self) -> usize {
        *self.inner.open.lock().unwrap()
    }

    /// Returns the configured connection limit, or zero when unlimited.
    pub fn max_connections(&self) -> usize {
        self.inner.max_conns
    }

    /// Closes every open association and stops the report engine.
    pub async fn close(&self) -> Result<()> {
        self.inner.reports.shutdown();
        let conns: Vec<Arc<mms::ServerConn>> =
            self.inner.conns.lock().unwrap().values().cloned().collect();
        for sc in conns {
            let _ = sc.close().await;
        }
        Ok(())
    }

    /// Applies a batch of value changes atomically with respect to client
    /// reads.
    ///
    /// The transaction is the process side's entry point for pushing new
    /// measurement and status values. Reports whose dataset includes any
    /// changed attribute are emitted before the lock is released, so a client
    /// never sees a half-applied batch.
    pub fn update<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Tx<'_>) -> R,
    {
        let inner = &self.inner;
        let mut model = inner.model.write().unwrap();
        let (out, changed) = {
            let mut tx = Tx::new(&mut model);
            let out = f(&mut tx);
            (out, std::mem::take(&mut tx.changed))
        };
        let conns = inner.conns.lock().unwrap();
        inner.reports.on_update(&mut model, &conns, &changed);
        out
    }

    /// Returns a server-local snapshot value for a reference and constraint,
    /// with no network involved.
    ///
    /// It takes the model lock, so it must not be called from inside an
    /// [`update`](Server::update) callback; use [`Tx::get`] there.
    pub fn read(&self, reference: impl Into<ObjectReference>, fc: Fc) -> Option<Value> {
        let model = self.inner.model.read().unwrap();
        model.attribute(&reference.into(), fc).map(access::da_value)
    }

    /// Reads an MMS item ID directly, as a client would.
    ///
    /// This composes structures for object-level reads, which is what makes it
    /// useful for checking what a client would actually receive.
    pub fn read_item(&self, domain: &str, item: &str) -> Option<Value> {
        let model = self.inner.model.read().unwrap();
        let ln_name = item.split('$').next()?;
        let ln = model.device(domain)?.node(ln_name)?;
        access::resolve_read(ln, item)
    }

    /// Runs `f` with a read-only view of the model.
    pub fn with_model<R>(&self, f: impl FnOnce(&Model) -> R) -> R {
        f(&self.inner.model.read().unwrap())
    }

    /// Returns the server's identity, as the Identify service reports it.
    pub fn identity(&self) -> &Identity {
        &self.inner.identity
    }
}

/// Sentinel errors for write and control handlers, mapped to MMS
/// `DataAccessError` codes.
pub const ERR_ACCESS_DENIED: mms::DataAccessError = mms::DataAccessError::ObjectAccessDenied;
pub const ERR_OBJECT_VALUE_INVALID: mms::DataAccessError =
    mms::DataAccessError::ObjectValueInvalid;
pub const ERR_OBJECT_NON_EXISTENT: mms::DataAccessError = mms::DataAccessError::ObjectNonExistent;

impl From<String> for Error {
    fn from(s: String) -> Error {
        Error::Server(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_states_render_their_names() {
        assert_eq!(ConnectionState::Opened.to_string(), "opened");
        assert_eq!(ConnectionState::Closed.to_string(), "closed");
        assert_eq!(ConnectionState::Refused.to_string(), "refused");
    }

    #[test]
    fn the_identity_defaults_to_the_crate_and_model_names() {
        let id = Identity::default();
        assert_eq!(id.vendor, "rs-iec61850");
        assert_eq!(id.revision, env!("CARGO_PKG_VERSION"));

        let m = Model {
            name: "ied1".into(),
            devices: vec![],
        };
        let s = Server::new(m, Options::new());
        assert_eq!(s.identity().model, "ied1", "the model name fills in");
    }

    #[test]
    fn a_configured_identity_wins() {
        let s = Server::new(
            Model::default(),
            Options::new().with_identity(Identity {
                vendor: "ACME".into(),
                model: "GW".into(),
                revision: "1.0".into(),
            }),
        );
        assert_eq!(s.identity().vendor, "ACME");
        assert_eq!(s.identity().model, "GW");
        assert_eq!(s.identity().revision, "1.0");
    }

    #[test]
    fn the_connection_limit_refuses_beyond_its_cap() {
        let s = Server::new(Model::default(), Options::new().with_max_connections(2));
        assert_eq!(s.max_connections(), 2);
        assert_eq!(s.inner.take_slot(), (1, true));
        assert_eq!(s.inner.take_slot(), (2, true));
        assert_eq!(s.inner.take_slot(), (2, false), "the third is refused");
        assert_eq!(s.inner.release_slot(), 1);
        assert_eq!(s.inner.take_slot(), (2, true), "a freed slot is reusable");
    }

    #[test]
    fn an_unlimited_server_never_refuses() {
        let s = Server::new(Model::default(), Options::new());
        assert_eq!(s.max_connections(), 0);
        for i in 1..=100 {
            assert_eq!(s.inner.take_slot(), (i, true));
        }
    }

    #[test]
    fn releasing_more_slots_than_were_taken_does_not_underflow() {
        let s = Server::new(Model::default(), Options::new());
        assert_eq!(s.inner.release_slot(), 0);
        assert_eq!(s.inner.release_slot(), 0);
        assert_eq!(s.open_connections(), 0);
    }
}
