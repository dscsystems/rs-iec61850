use std::net::SocketAddr;
use std::sync::Arc;

use std::sync::Mutex;

use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::asn1::{self, cons, context_constructed, context_primitive, prim, Decoder, Element};
use crate::osi::{acse, cotp, presentation, session};

use super::pdu::*;
use super::transport::{self, BoxTransport, FramingReader, FramingWriter};
use super::{AcseIdentity, DataAccessError, Error, ErrorClass, InitiateRequest, Result};

/// Depth of the per-association outbound queue for unconfirmed PDUs.
const UNCONFIRMED_QUEUE_DEPTH: usize = 512;

/// A decoded confirmed-request service.
#[derive(Debug, Clone)]
pub struct Request {
    pub invoke_id: u32,
    /// The confirmed service CHOICE tag number.
    pub service: u32,
    /// The service-specific content octets.
    pub content: Vec<u8>,
}

/// Processes a decoded confirmed request.
///
/// Returning `Ok` sends the encoded confirmed-response service element (the
/// CHOICE element, for example an `A4` read response); returning `Err` sends a
/// confirmed-error or a reject.
pub trait Handler: Send + Sync {
    fn handle(
        &self,
        req: Request,
        conn: &ServerConn,
    ) -> impl std::future::Future<Output = Result<Element>> + Send;
}

/// Receives each handshake APDU as it is read or written.
pub type TraceFn = Arc<dyn Fn(&str, &[u8]) + Send + Sync>;

/// Configures the server-side association handshake.
#[derive(Default)]
pub struct AcceptOptions {
    /// When set, the parameters to answer with instead of echoing the client's
    /// proposal.
    ///
    /// A proxy sets this to the parameters the real device advertised, so its
    /// clients see the device's capabilities rather than their own request
    /// reflected back. The values are still bounded by the client's proposal
    /// where the protocol requires it: neither side may be asked to accept a
    /// larger PDU or more outstanding services than it offered.
    pub initiate: Option<InitiateRequest>,

    /// When set, the identity to answer with in the AARE.
    ///
    /// A proxy sets it to the device's identity: a client configured with the
    /// device's AP-title checks it and refuses an association that omits it or
    /// answers with the wrong one. `None` keeps the bare acceptance, which is
    /// legal and is what a server with no identity of its own sends.
    pub responding: Option<AcseIdentity>,

    /// When set, called with each handshake APDU as it is read or written,
    /// before any interpretation.
    ///
    /// A peer that aborts the association gives no reason, so these bytes are
    /// the only way to see what it objected to.
    pub trace: Option<TraceFn>,
}

impl std::fmt::Debug for AcceptOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptOptions")
            .field("initiate", &self.initiate)
            .field("responding", &self.responding)
            .field("trace", &self.trace.is_some())
            .finish()
    }
}

impl AcceptOptions {
    fn trace(&self, event: &str, data: &[u8]) {
        if let Some(t) = &self.trace {
            t(event, data);
        }
    }
}

/// One accepted MMS association on the server side.
///
/// It reads confirmed requests and dispatches them to a [`Handler`], sending
/// the responses the handler returns. The [`crate::server`] module builds on
/// it; most applications use that higher-level API instead.
#[derive(Debug)]
pub struct ServerConn {
    writer: Arc<AsyncMutex<FramingWriter>>,
    reader: AsyncMutex<Option<FramingReader>>,
    unconf_tx: mpsc::Sender<Vec<u8>>,
    pump: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// The ACSE authentication value presented by the client.
    pub password: Option<String>,
    pub peer: Option<SocketAddr>,
    /// The identity the client addressed. A client that fills this in is
    /// checking which application entity it reached and will compare the
    /// responding identity in the AARE against it.
    pub called: AcseIdentity,
    /// The identity the client claims to be.
    pub calling: AcseIdentity,
    /// The association parameters the client proposed.
    pub negotiated: InitiateRequest,
}

/// Performs the server-side association handshake over an already-accepted
/// transport (TCP or TLS) and returns the association.
pub async fn accept_conn(stream: BoxTransport, peer: Option<SocketAddr>) -> Result<ServerConn> {
    accept_conn_opts(stream, peer, &AcceptOptions::default()).await
}

/// [`accept_conn`] with explicit control over the response parameters.
pub async fn accept_conn_opts(
    stream: BoxTransport,
    peer: Option<SocketAddr>,
    opts: &AcceptOptions,
) -> Result<ServerConn> {
    let mut ct = cotp::Conn::accept(stream).await?;

    // The session CONNECT carries the presentation CP with the ACSE AARQ.
    let res = session::accept_server(&mut ct).await?;
    opts.trace("rx CP", &res.user_data);
    let cp = presentation::parse_cp(&res.user_data)?;
    opts.trace("rx AARQ", &cp.user_data);
    let areq = acse::parse_aarq(&cp.user_data)?;
    opts.trace("rx InitiateRequest", &areq.user_data);
    let proposed = parse_initiate_request(&areq.user_data)?;

    // Build the InitiateResponse -> AARE -> CPA -> session ACCEPT.
    let answer = match &opts.initiate {
        Some(want) => clamp_initiate(want, &proposed),
        None => proposed.clone(),
    };
    let init_resp = encode_initiate_response(&answer);
    opts.trace("tx InitiateResponse", &init_resp);
    let responding = opts.responding.clone().unwrap_or_default();
    let aare = acse::aare_with_identity(&init_resp, &responding);
    opts.trace("tx AARE", &aare);
    // The responder's selector is the one the peer addressed, so it sees the
    // entity it dialled answer rather than a stack default.
    let responding_psel = if cp.called_psel.is_empty() {
        presentation::DEFAULT_CALLED_PSEL.to_vec()
    } else {
        cp.called_psel.clone()
    };
    let cpa = presentation::build_cpa(&responding_psel, cp.contexts, &aare);
    opts.trace("tx CPA", &cpa);
    session::reply(
        &mut ct,
        res.called_ssel.as_deref().unwrap_or(&[]),
        &cpa,
    )
    .await?;

    let (reader, writer) = transport::split(ct);
    let writer = Arc::new(AsyncMutex::new(writer));
    let (unconf_tx, unconf_rx) = mpsc::channel(UNCONFIRMED_QUEUE_DEPTH);

    // A dedicated writer task drains unconfirmed PDUs (reports) so callers
    // never block on the socket while holding the model lock.
    let pump = tokio::spawn(pump_unconfirmed(Arc::clone(&writer), unconf_rx));

    Ok(ServerConn {
        writer,
        reader: AsyncMutex::new(Some(reader)),
        unconf_tx,
        pump: Mutex::new(Some(pump)),
        password: areq.password,
        peer,
        called: areq.called,
        calling: areq.calling,
        negotiated: proposed,
    })
}

async fn pump_unconfirmed(
    writer: Arc<AsyncMutex<FramingWriter>>,
    mut rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(pdu) = rx.recv().await {
        if writer.lock().await.send_mms(&pdu).await.is_err() {
            return;
        }
    }
}

impl ServerConn {
    /// Reads confirmed requests until the association ends, dispatching each
    /// to `handler`.
    ///
    /// It returns when the peer concludes, the connection closes, or a fatal
    /// transport error occurs.
    pub async fn serve<H: Handler>(&self, handler: &H) -> Result<()> {
        let mut reader = match self.reader.lock().await.take() {
            Some(r) => r,
            None => return Err(Error::protocol("association is already being served")),
        };
        loop {
            let pdu = reader.recv_mms().await?;
            if !self.handle_pdu(&pdu, handler).await? {
                return Ok(());
            }
        }
    }

    /// Handles one PDU. Returns false when the association should end.
    async fn handle_pdu<H: Handler>(&self, pdu: &[u8], handler: &H) -> Result<bool> {
        let mut dec = Decoder::new(pdu);
        let Ok((tag, content)) = dec.read_tlv() else {
            return Ok(true); // ignore malformed PDUs
        };
        if tag == TAG_CONFIRMED_REQUEST {
            self.handle_confirmed(content, handler).await?;
            Ok(true)
        } else if tag == TAG_CONCLUDE_REQUEST {
            // Accept the conclude and end the association.
            let _ = self.send(&cons(TAG_CONCLUDE_RESPONSE, []).encode()).await;
            Ok(false)
        } else {
            Ok(true)
        }
    }

    async fn handle_confirmed<H: Handler>(&self, content: &[u8], handler: &H) -> Result<()> {
        let Some(req) = parse_confirmed_request(content) else {
            return Ok(());
        };
        let invoke_id = req.invoke_id;
        match handler.handle(req, self).await {
            Ok(resp) => {
                // ConfirmedResponsePDU ::= [1] SEQUENCE { invokeID, service }
                let out = cons(
                    TAG_CONFIRMED_RESPONSE,
                    [asn1::uint_elem(asn1::TAG_INTEGER, u64::from(invoke_id)), resp],
                )
                .encode();
                self.send(&out).await
            }
            Err(e) => self.send(&encode_error_pdu(invoke_id, &e)).await,
        }
    }

    /// Queues an unconfirmed PDU (an information report) for asynchronous
    /// transmission.
    ///
    /// It never blocks the caller: if the outbound queue is full (a slow or
    /// stalled client) the report is dropped rather than stalling the server,
    /// which is the buffer-overflow condition the protocol already models for
    /// reporting. Reporting it lets a buffered RCB set `BufOvfl` so the client
    /// learns it missed entries.
    pub fn send_unconfirmed(&self, service: Element) -> Result<()> {
        let pdu = cons(TAG_UNCONFIRMED, [service]).encode();
        self.unconf_tx
            .try_send(pdu)
            .map_err(|_| Error::ReportQueueFull)
    }

    async fn send(&self, pdu: &[u8]) -> Result<()> {
        self.writer.lock().await.send_mms(pdu).await
    }

    /// Closes the transport and stops the unconfirmed writer.
    pub async fn close(&self) -> Result<()> {
        if let Some(h) = self.pump.lock().unwrap().take() {
            h.abort();
        }
        self.writer.lock().await.shutdown().await
    }
}

impl Drop for ServerConn {
    fn drop(&mut self) {
        if let Some(h) = self.pump.lock().unwrap().take() {
            h.abort();
        }
    }
}

/// Limits the parameters answered with to what the client proposed, where the
/// protocol requires the responder not to exceed the initiator's offer.
///
/// The service and parameter bitmaps are ours to state and pass through
/// untouched: they describe what this end supports, not a negotiated minimum.
pub(crate) fn clamp_initiate(want: &InitiateRequest, proposed: &InitiateRequest) -> InitiateRequest {
    fn clamp(ours: i32, theirs: i32) -> i32 {
        if theirs > 0 && (ours == 0 || ours > theirs) {
            theirs
        } else {
            ours
        }
    }
    let mut out = want.clone();
    out.local_detail = clamp(out.local_detail, proposed.local_detail);
    out.max_serv_outstanding = clamp(out.max_serv_outstanding, proposed.max_serv_outstanding);
    out.max_serv_outstanding_calling = clamp(
        out.max_serv_outstanding_calling,
        proposed.max_serv_outstanding_calling,
    );
    out.max_serv_outstanding_called = clamp(
        out.max_serv_outstanding_called,
        proposed.max_serv_outstanding_called,
    );
    out.nesting_level = clamp(out.nesting_level, proposed.nesting_level);
    out
}

/// Maps a handler error to the `errorClass` CHOICE tag number and value used
/// in a ServiceError (the IEC 61850 MMS profile).
///
/// The access-class enum (0..3) differs from the `DataAccessError` enum used
/// inline in read results, so the two must not be conflated.
pub(crate) fn error_class_choice(err: &Error) -> (u32, i64) {
    match err {
        Error::Access(dae) => match dae {
            DataAccessError::ObjectAccessUnsupported => (7, 1),
            DataAccessError::ObjectNonExistent => (7, 2),
            DataAccessError::ObjectAccessDenied => (7, 3),
            _ => (7, 2),
        },
        Error::Service(se) if se.class != ErrorClass(0) => {
            (u32::from(se.class.0), i64::from(se.code))
        }
        _ => (4, 0), // service: other
    }
}

/// Builds the RejectPDU or ConfirmedErrorPDU answering a failed request.
pub(crate) fn encode_error_pdu(invoke_id: u32, err: &Error) -> Vec<u8> {
    // A rejected request is answered with a RejectPDU, not a service error.
    if let Error::Service(se) = err {
        if se.rejected {
            return cons(
                TAG_REJECT_PDU,
                [
                    // originalInvokeID [0]
                    asn1::uint_elem(context_primitive(0), u64::from(invoke_id)),
                    // rejectReason [category]
                    asn1::int_elem(context_primitive(u32::from(se.class.0)), i64::from(se.code)),
                ],
            )
            .encode();
        }
    }
    // ConfirmedErrorPDU ::= [2] SEQUENCE {
    //   invokeID     [0] IMPLICIT Unsigned32,
    //   serviceError [2] SEQUENCE { errorClass [0] CHOICE { [class] value } } }
    let (class_tag, value) = error_class_choice(err);
    let mut id_bytes = Vec::new();
    asn1::append_uint(&mut id_bytes, u64::from(invoke_id));
    cons(
        TAG_CONFIRMED_ERROR,
        [
            prim(context_primitive(0), id_bytes),
            cons(
                context_constructed(2),
                [cons(
                    context_constructed(0),
                    [asn1::int_elem(context_primitive(class_tag), value)],
                )],
            ),
        ],
    )
    .encode()
}

/// Splits a ConfirmedRequestPDU's content into its invoke id and service.
pub(crate) fn parse_confirmed_request(content: &[u8]) -> Option<Request> {
    let mut dec = Decoder::new(content);
    let id_bytes = dec.expect(asn1::TAG_INTEGER).ok()?;
    let invoke_id = asn1::decode_uint(id_bytes).ok()? as u32;
    // The service is the next element; its tag number is the service id.
    let (service_tag, service_content) = dec.read_tlv().ok()?;
    Some(Request {
        invoke_id,
        service: service_tag.number,
        content: service_content.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::ServiceError;

    #[test]
    fn a_responder_never_exceeds_what_the_client_proposed() {
        let want = InitiateRequest {
            local_detail: 65000,
            max_serv_outstanding: 10,
            nesting_level: 10,
            ..Default::default()
        };
        let proposed = InitiateRequest {
            local_detail: 32000,
            max_serv_outstanding: 3,
            nesting_level: 5,
            ..Default::default()
        };
        let out = clamp_initiate(&want, &proposed);
        assert_eq!(out.local_detail, 32000);
        assert_eq!(out.max_serv_outstanding, 3);
        assert_eq!(out.nesting_level, 5);
    }

    #[test]
    fn a_responder_may_state_less_than_the_client_offered() {
        let want = InitiateRequest {
            local_detail: 1024,
            max_serv_outstanding: 1,
            nesting_level: 2,
            ..Default::default()
        };
        let proposed = InitiateRequest {
            local_detail: 65000,
            max_serv_outstanding: 10,
            nesting_level: 5,
            ..Default::default()
        };
        let out = clamp_initiate(&want, &proposed);
        assert_eq!(out.local_detail, 1024, "our smaller offer stands");
        assert_eq!(out.max_serv_outstanding, 1);
        assert_eq!(out.nesting_level, 2);
    }

    /// The access error class in a ServiceError is a different enum from the
    /// DataAccessError used inline in read results; conflating them tells the
    /// client the wrong thing.
    #[test]
    fn access_errors_map_to_the_service_error_access_class() {
        assert_eq!(
            error_class_choice(&Error::Access(DataAccessError::ObjectNonExistent)),
            (7, 2)
        );
        assert_eq!(
            error_class_choice(&Error::Access(DataAccessError::ObjectAccessDenied)),
            (7, 3)
        );
        assert_eq!(
            error_class_choice(&Error::Access(DataAccessError::ObjectAccessUnsupported)),
            (7, 1)
        );
        assert_eq!(
            error_class_choice(&Error::protocol("boom")),
            (4, 0),
            "an unclassified failure is service: other"
        );
    }

    #[test]
    fn a_rejected_request_is_answered_with_a_reject_pdu() {
        let err = Error::Service(ServiceError {
            class: ErrorClass(1),
            code: 1,
            rejected: true,
            detail: String::new(),
        });
        let pdu = encode_error_pdu(7, &err);
        assert_eq!(pdu[0], 0xa4, "RejectPDU is [4]");

        let err = Error::Access(DataAccessError::ObjectNonExistent);
        let pdu = encode_error_pdu(7, &err);
        assert_eq!(pdu[0], 0xa2, "ConfirmedErrorPDU is [2]");
    }

    #[test]
    fn a_confirmed_request_splits_into_its_invoke_id_and_service() {
        let pdu = cons(
            TAG_CONFIRMED_REQUEST,
            [
                asn1::uint_elem(asn1::TAG_INTEGER, 9),
                cons(context_constructed(SVC_READ), []),
            ],
        )
        .encode();
        let mut dec = Decoder::new(&pdu);
        let content = dec.expect(TAG_CONFIRMED_REQUEST).unwrap();
        let req = parse_confirmed_request(content).unwrap();
        assert_eq!(req.invoke_id, 9);
        assert_eq!(req.service, SVC_READ);

        assert!(parse_confirmed_request(&[]).is_none());
    }
}
