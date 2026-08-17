use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::mms::{self, BoxTransport, ObjectClass, State, Value};
use crate::model::{Fc, ObjectReference};

use super::{Error, Result};

/// Configures a [`Client`].
#[derive(Debug, Default)]
pub struct Options {
    /// An ACSE authentication password.
    pub password: Option<String>,
    /// Bounds the connection handshake.
    pub timeout: Option<Duration>,
    /// The ACSE identity to address; devices that check the called AP-title
    /// refuse an association that omits it.
    pub called: mms::AcseIdentity,
    /// The ACSE identity to claim.
    pub calling: mms::AcseIdentity,
    /// Overrides the proposed MMS association parameters.
    pub initiate: Option<mms::InitiateRequest>,
    /// Enables TLS per IEC 62351-3. The default MMS-over-TLS port is 3782.
    #[cfg(feature = "tls")]
    pub tls: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
    /// The server name presented in the TLS handshake; defaults to the host
    /// part of the dial address.
    #[cfg(feature = "tls")]
    pub tls_server_name: Option<String>,
}

impl Options {
    pub fn new() -> Options {
        Options::default()
    }

    /// Sets an ACSE authentication password.
    #[must_use]
    pub fn with_password(mut self, pw: impl Into<String>) -> Options {
        self.password = Some(pw.into());
        self
    }

    /// Bounds the connection handshake.
    #[must_use]
    pub fn with_timeout(mut self, d: Duration) -> Options {
        self.timeout = Some(d);
        self
    }

    /// Sets the ACSE identity to address.
    #[must_use]
    pub fn with_called(mut self, id: mms::AcseIdentity) -> Options {
        self.called = id;
        self
    }

    /// Sets the ACSE identity to claim.
    #[must_use]
    pub fn with_calling(mut self, id: mms::AcseIdentity) -> Options {
        self.calling = id;
        self
    }

    /// Enables TLS per IEC 62351-3.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls(mut self, cfg: Arc<tokio_rustls::rustls::ClientConfig>) -> Options {
        self.tls = Some(cfg);
        self
    }

    fn into_mms(self) -> mms::Options {
        mms::Options {
            password: self.password,
            initiate: self.initiate,
            connect_timeout: self.timeout,
            called: self.called,
            calling: self.calling,
            #[cfg(feature = "tls")]
            tls: self.tls,
            #[cfg(feature = "tls")]
            tls_server_name: self.tls_server_name,
        }
    }
}

/// A connection to an IEC 61850 server (IED).
///
/// It is safe for concurrent use: several tasks may issue requests, which the
/// MMS association matches to responses by invoke ID.
#[derive(Debug)]
pub struct Client {
    conn: Arc<mms::Conn>,
    /// One permit per request the association allows outstanding. A server
    /// enforces its own limit by rejecting the excess, so honouring it here
    /// turns a protocol error into a short wait.
    outstanding: Semaphore,
}

impl Client {
    /// Connects to an IED at `host:port` with default options.
    pub async fn dial(addr: &str) -> Result<Client> {
        Client::dial_with(addr, Options::default()).await
    }

    /// Connects to an IED at `host:port`.
    pub async fn dial_with(addr: &str, opts: Options) -> Result<Client> {
        let conn = mms::Conn::dial(addr, opts.into_mms()).await?;
        Ok(Client::from_conn(conn))
    }

    /// Wraps an already-established association.
    ///
    /// This is the entry point for callers that bring their own transport, and
    /// what the in-memory tests use.
    pub async fn from_stream(stream: BoxTransport, opts: Options) -> Result<Client> {
        let conn = mms::Conn::from_stream(stream, opts.into_mms()).await?;
        Ok(Client::from_conn(conn))
    }

    fn from_conn(conn: mms::Conn) -> Client {
        let permits = conn.max_serv_outstanding().max(1) as usize;
        Client {
            conn: Arc::new(conn),
            outstanding: Semaphore::new(permits),
        }
    }

    /// Returns the underlying MMS connection, for services the ACSI layer does
    /// not wrap.
    pub fn mms(&self) -> &Arc<mms::Conn> {
        &self.conn
    }

    /// Releases the association.
    pub async fn close(&self) -> Result<()> {
        self.conn.close().await?;
        Ok(())
    }

    /// Reports the connection state.
    ///
    /// [`dial`](Client::dial) returns a client only once the association is up,
    /// so a fresh client is [`State::Connected`]. It turns [`State::Closed`]
    /// when the peer or the transport drops the association, without a request
    /// having to fail first.
    ///
    /// Polling the state is a way to observe a connection loss, not to guard a
    /// request: the association may still drop between the check and the call,
    /// so handle the request error as well.
    pub fn state(&self) -> State {
        self.conn.state()
    }

    /// Resolves when the connection ends, whether from [`close`](Client::close),
    /// a peer disconnect or a transport error.
    ///
    /// It replaces polling [`state`](Client::state) with a wait, so a
    /// supervisor can reconnect the moment the IED drops the association:
    ///
    /// ```no_run
    /// # async fn run(c: &iec61850::client::Client) {
    /// c.closed().await;
    /// eprintln!("connection lost: {:?}", c.err());
    /// # }
    /// ```
    pub async fn closed(&self) {
        self.conn.closed().await;
    }

    /// Returns the error that ended the association, or `None` while it is
    /// still up.
    ///
    /// It tells a closed connection that was closed locally apart from one the
    /// peer or the network dropped.
    pub fn err(&self) -> Option<Arc<mms::Error>> {
        self.conn.err()
    }

    /// Returns the logical device (MMS domain) names.
    pub async fn logical_devices(&self) -> Result<Vec<String>> {
        Ok(self.conn.get_name_list(ObjectClass::Domain, "").await?)
    }

    /// Returns the logical node names within a logical device.
    pub async fn logical_nodes(&self, ld: &str) -> Result<Vec<String>> {
        let names = self
            .conn
            .get_name_list(ObjectClass::NamedVariable, ld)
            .await?;
        // The server reports flat MMS item IDs; the logical node is the part
        // before the first separator, and a bare entry is the node itself.
        let mut out: Vec<String> = Vec::new();
        for n in names {
            let ln = n.split_once('$').map_or(n.as_str(), |(ln, _)| ln);
            if !ln.is_empty() && !out.iter().any(|e| e == ln) {
                out.push(ln.to_string());
            }
        }
        Ok(out)
    }

    /// Reads the data attribute (or object) at `reference` under the given
    /// functional constraint.
    pub async fn read(
        &self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
    ) -> Result<Value> {
        let reference = reference.into();
        let (domain, item) = reference.to_mms(fc);
        let vals = self.conn.read(&domain, &[&item]).await?;
        let Some(v) = vals.into_iter().next() else {
            return Err(mms::DataAccessError::ObjectNonExistent.into());
        };
        if let Some(code) = v.as_access_error() {
            return Err(code.into());
        }
        Ok(v)
    }

    /// Writes a value to the data attribute at `reference` under the given
    /// functional constraint.
    pub async fn write(
        &self,
        reference: impl Into<ObjectReference>,
        fc: Fc,
        value: Value,
    ) -> Result<()> {
        let reference = reference.into();
        let (domain, item) = reference.to_mms(fc);
        let results = self.conn.write(&domain, &[&item], &[value]).await?;
        match results.into_iter().next() {
            Some(Err(code)) => Err(code.into()),
            _ => Ok(()),
        }
    }

    /// Reads several references in one MMS request, returning values in order.
    ///
    /// All references must share a logical device, since one request names one
    /// domain; use [`read_many`](Client::read_many) for references that span
    /// devices.
    pub async fn read_values(
        &self,
        fc: Fc,
        references: &[ObjectReference],
    ) -> Result<Vec<Value>> {
        if references.is_empty() {
            return Ok(Vec::new());
        }
        let domain = references[0].ld().to_string();
        if let Some(odd) = references.iter().find(|r| r.ld() != domain) {
            return Err(Error::client(format!(
                "read_values needs one logical device, got {domain:?} and {:?}",
                odd.ld()
            )));
        }
        let items: Vec<String> = references.iter().map(|r| r.to_mms(fc).1).collect();
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        Ok(self.conn.read(&domain, &refs).await?)
    }

    /// Reads each reference with its own request, running them concurrently
    /// within the association's outstanding-request limit.
    ///
    /// Results come back in the order given, each with its own outcome, so one
    /// failing leaves the others unaffected and references may span logical
    /// devices. When they share a device and a single outcome is enough,
    /// [`read_values`](Client::read_values) asks for them in one round trip
    /// instead of many.
    pub async fn read_many(
        &self,
        fc: Fc,
        references: &[ObjectReference],
    ) -> Vec<Result<Value>> {
        let mut futures = Vec::with_capacity(references.len());
        for r in references {
            futures.push(async move {
                // A closed semaphore only happens at shutdown, where the read
                // below would fail anyway.
                let _permit = self.outstanding.acquire().await;
                self.read(r.clone(), fc).await
            });
        }
        join_all(futures).await
    }
}

/// Awaits every future concurrently and collects the results in the order
/// given.
///
/// This is `join_all` in miniature: the crate carries no futures-util
/// dependency for one combinator. Polling them as a single future is what
/// keeps every read in flight at once, which is the whole point here since the
/// association demultiplexes the responses by invoke ID.
async fn join_all<F: std::future::Future>(futures: Vec<F>) -> Vec<F::Output> {
    let mut pending: Vec<Option<std::pin::Pin<Box<F>>>> =
        futures.into_iter().map(|f| Some(Box::pin(f))).collect();
    let mut results: Vec<Option<F::Output>> = (0..pending.len()).map(|_| None).collect();

    std::future::poll_fn(|cx| {
        let mut all_done = true;
        for (i, slot) in pending.iter_mut().enumerate() {
            let Some(fut) = slot else { continue };
            match fut.as_mut().poll(cx) {
                std::task::Poll::Ready(v) => {
                    results[i] = Some(v);
                    // Dropping the future here releases its semaphore permit
                    // as soon as it finishes, rather than at the end.
                    *slot = None;
                }
                std::task::Poll::Pending => all_done = false,
            }
        }
        if all_done {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;

    results
        .into_iter()
        .map(|v| v.expect("every future completed"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn join_all_preserves_order_regardless_of_completion_order() {
        // Later entries finish first, so a naive collect would reorder them.
        let futures: Vec<_> = (0..8u32)
            .map(|i| async move {
                tokio::time::sleep(Duration::from_millis(u64::from(8 - i))).await;
                i
            })
            .collect();
        assert_eq!(join_all(futures).await, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[tokio::test]
    async fn join_all_runs_its_futures_concurrently() {
        // Eight 50ms sleeps run together take about 50ms, not 400ms.
        let start = std::time::Instant::now();
        let futures: Vec<_> = (0..8)
            .map(|_| async { tokio::time::sleep(Duration::from_millis(50)).await })
            .collect();
        join_all(futures).await;
        assert!(
            start.elapsed() < Duration::from_millis(400),
            "futures ran sequentially: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn join_all_of_nothing_is_nothing() {
        let empty: Vec<std::future::Ready<u8>> = Vec::new();
        assert!(join_all(empty).await.is_empty());
    }
}
