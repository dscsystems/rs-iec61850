use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use crate::osi::{self, acse, cotp, presentation, session};

use super::{Error, Result};

/// Any byte stream an MMS association can run over.
///
/// Erasing the stream type here keeps [`Conn`](super::Conn) and the whole
/// ACSI layer above it free of type parameters, so a TLS association and a
/// plain TCP one have the same type.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for T {}

/// A type-erased transport.
pub type BoxTransport = Box<dyn Transport>;

/// Carries MMS PDUs over the session and presentation data phase on top of an
/// established COTP connection.
///
/// The two halves exist separately so a reader task can demultiplex responses
/// while other tasks issue requests.
pub(crate) struct FramingWriter {
    w: cotp::Writer<WriteHalf<BoxTransport>>,
    /// The presentation-context-identifier the peer assigned to the MMS
    /// context. It is the proposer's choice, not a constant, so it comes from
    /// the association setup: tagging data with the wrong one produces PDUs
    /// the peer cannot decode, which looks like silence.
    mms_context: i64,
    /// The identifier of the ACSE context, which carries an abort.
    acse_context: i64,
    pub(crate) write_timeout: Option<std::time::Duration>,
    closed: tokio::sync::watch::Sender<bool>,
    #[cfg(feature = "e2e")]
    pub(crate) security: Option<super::secure::Security>,
}

pub(crate) struct FramingReader {
    r: cotp::Reader<ReadHalf<BoxTransport>>,
    #[cfg(feature = "e2e")]
    pub(crate) security: Option<super::secure::Security>,
    #[cfg(feature = "e2e")]
    reply: Option<std::sync::Arc<tokio::sync::Mutex<FramingWriter>>>,
}

/// Splits an established COTP connection into MMS framing halves, tagging
/// data with the negotiated presentation contexts.
pub(crate) fn split(
    conn: cotp::Conn<BoxTransport>,
    mms_context: i64,
    acse_context: i64,
) -> (FramingReader, FramingWriter) {
    let (r, w) = conn.into_split();
    (
        FramingReader { r,
            #[cfg(feature = "e2e")] security: None,
            #[cfg(feature = "e2e")] reply: None,
        },
        FramingWriter {
            w,
            mms_context,
            acse_context,
            write_timeout: None,
            closed: tokio::sync::watch::channel(false).0,
            #[cfg(feature = "e2e")] security: None,
        },
    )
}

impl std::fmt::Debug for FramingWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FramingWriter")
    }
}

impl std::fmt::Debug for FramingReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FramingReader")
    }
}

impl FramingWriter {
    /// Wraps an MMS PDU in the presentation and session data-phase framing and
    /// writes it.
    pub(crate) async fn send_mms(&mut self, pdu: &[u8]) -> Result<()> {
        if *self.closed.borrow() {
            return Err(Error::Closed);
        }
        #[cfg(feature = "e2e")]
        let data = match &self.security {
            Some(security) => presentation::wrap_data(security.e2e, &security.seal(pdu)?),
            None => presentation::wrap_data(self.mms_context, pdu),
        };
        #[cfg(not(feature = "e2e"))]
        let data = presentation::wrap_data(self.mms_context, pdu);
        let send = session::send_data(&mut self.w, &data);
        let result = match self.write_timeout {
            Some(limit) if !limit.is_zero() => match tokio::time::timeout(limit, send).await {
                Ok(r) => r.map_err(Error::from),
                Err(_) => Err(Error::Timeout),
            },
            _ => send.await.map_err(Error::from),
        };
        if result.is_err() {
            #[cfg(feature = "e2e")]
            if let Some(security) = &self.security { security.association.lock().unwrap().close(); }
            self.closed.send_replace(true);
        }
        result
    }

    /// Aborts the association as its user: an ACSE ABRT in an ARU
    /// presentation PDU in a session ABORT, as libiec61850 frames it.
    pub(crate) async fn send_abort(&mut self) -> Result<()> {
        #[cfg(feature = "e2e")]
        let apdu = match &self.security { Some(sec) => sec.control(crate::iec62351::e2e::Kind::ApplicationAbort, None)?, None => acse::abrt(acse::ABORT_SOURCE_USER) };
        #[cfg(not(feature = "e2e"))]
        let apdu = acse::abrt(acse::ABORT_SOURCE_USER);
        let aru = presentation::wrap_abort(self.acse_context, &apdu);
        let send = session::abort(&mut self.w, &aru);
        match self.write_timeout {
            Some(limit) if !limit.is_zero() => tokio::time::timeout(limit, send).await.map_err(|_| Error::Timeout)??,
            _ => send.await?,
        }
        Ok(())
    }

    #[cfg(feature = "e2e")]
    pub(crate) async fn send_release(&mut self, response: bool) -> Result<()> {
        let sec = self.security.as_ref().ok_or_else(|| Error::protocol("release outside E2E"))?;
        let apdu = sec.control(if response { crate::iec62351::e2e::Kind::ReleaseResponse } else { crate::iec62351::e2e::Kind::ReleaseRequest }, None)?;
        let data = presentation::wrap_data(sec.acse, &apdu);
        let send = session::release(&mut self.w, response, &data);
        match self.write_timeout {
            Some(limit) if !limit.is_zero() => tokio::time::timeout(limit, send).await.map_err(|_| Error::Timeout)??,
            _ => send.await?,
        }
        Ok(())
    }

    #[cfg(feature = "e2e")]
    pub(crate) async fn security_abort(&mut self, error: &crate::iec62351::e2e::Error) -> Result<()> {
        let sec = self.security.as_ref().ok_or_else(|| Error::protocol("abort outside E2E"))?;
        let apdu = sec.control(crate::iec62351::e2e::Kind::DataAbort, Some(error))?;
        let data = presentation::wrap_abort(sec.acse, &apdu);
        let send = session::abort(&mut self.w, &data);
        match self.write_timeout {
            Some(limit) if !limit.is_zero() => tokio::time::timeout(limit, send).await.map_err(|_| Error::Timeout)??,
            _ => send.await?,
        }
        Ok(())
    }

    /// Observes closure and fatal write failures.
    pub(crate) fn closed(&self) -> tokio::sync::watch::Receiver<bool> {
        self.closed.subscribe()
    }

    /// Shuts the transport down.
    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        self.closed.send_replace(true);
        #[cfg(feature = "e2e")]
        if let Some(security) = &self.security { security.association.lock().unwrap().close(); }
        match self.write_timeout {
            Some(limit) if !limit.is_zero() => tokio::time::timeout(limit, self.w.shutdown()).await.map_err(|_| Error::Timeout)??,
            _ => self.w.shutdown().await?,
        }
        Ok(())
    }
}

impl FramingReader {
    #[cfg(feature = "e2e")]
    pub(crate) fn attach_writer(&mut self, writer: std::sync::Arc<tokio::sync::Mutex<FramingWriter>>) {
        if self.security.is_some() { self.reply = Some(writer); }
    }
    /// Reads one MMS PDU, stripping the session and presentation framing.
    ///
    /// An abort by the peer is [`Error::Aborted`], naming whether the peer's
    /// user or its provider aborted.
    pub(crate) async fn recv_mms(&mut self) -> Result<Vec<u8>> {
        let ud = match session::receive_data(&mut self.r).await {
            Ok(ud) => ud,
            #[cfg(feature = "e2e")]
            Err(osi::Error::Release { response, user_data }) if self.security.is_some() => {
                let sec = self.security.as_ref().unwrap();
                let apdu = presentation::unwrap_data_strict(&user_data, sec.acse)?;
                sec.verify_release(&apdu, response)?;
                if !response { if let Some(writer) = &self.reply { writer.lock().await.send_release(true).await?; } }
                return Err(Error::Closed);
            }
            Err(osi::Error::Aborted { user_data }) => {
                #[cfg(feature = "e2e")]
                if let Some(sec) = &self.security {
                    let apdu = presentation::unwrap_abort(&user_data)?;
                    sec.verify_abort(&apdu)?;
                }
                let by_provider = presentation::unwrap_abort(&user_data)
                    .ok()
                    .and_then(|abrt| acse::parse_abrt(&abrt).ok())
                    == Some(acse::ABORT_SOURCE_PROVIDER);
                return Err(Error::Aborted(if by_provider {
                    " by the peer's provider".into()
                } else {
                    " by the peer".into()
                }));
            }
            Err(e) => return Err(e.into()),
        };
        #[cfg(feature = "e2e")]
        if let Some(sec) = &self.security {
            let result = presentation::unwrap_data_strict(&ud, sec.e2e).map_err(Error::from).and_then(|pdu| sec.open(&pdu));
            if let Err(error) = &result {
                let failure = match error { Error::E2E(error) => error.clone(), _ => crate::iec62351::e2e::Error::data(1, error.to_string()) };
                if let Some(writer) = &self.reply { let _ = writer.lock().await.security_abort(&failure).await; }
            }
            return result;
        }
        Ok(presentation::unwrap_data(&ud)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_stalled_write_times_out_and_ends_the_association() {
        let (client, server) = tokio::io::duplex(256);
        let accepting = tokio::spawn(cotp::Conn::accept(Box::new(server) as BoxTransport));
        let client = cotp::Conn::connect(Box::new(client) as BoxTransport, cotp::Options::default()).await.unwrap();
        let _peer = accepting.await.unwrap().unwrap(); // never drains data
        let (_reader, mut writer) = split(client, 3, 1);
        writer.write_timeout = Some(std::time::Duration::from_millis(20));
        let closed = writer.closed();
        assert!(matches!(writer.send_mms(&vec![0; 4096]).await, Err(Error::Timeout)));
        assert!(*closed.borrow());
        assert!(matches!(writer.send_mms(&[0]).await, Err(Error::Closed)));
    }
}
