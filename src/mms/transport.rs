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
}

pub(crate) struct FramingReader {
    r: cotp::Reader<ReadHalf<BoxTransport>>,
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
        FramingReader { r },
        FramingWriter {
            w,
            mms_context,
            acse_context,
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
        session::send_data(&mut self.w, &presentation::wrap_data(self.mms_context, pdu)).await?;
        Ok(())
    }

    /// Aborts the association as its user: an ACSE ABRT in an ARU
    /// presentation PDU in a session ABORT, as libiec61850 frames it.
    pub(crate) async fn send_abort(&mut self) -> Result<()> {
        let aru = presentation::wrap_abort(self.acse_context, &acse::abrt(acse::ABORT_SOURCE_USER));
        session::abort(&mut self.w, &aru).await?;
        Ok(())
    }

    /// Shuts the transport down.
    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        self.w.shutdown().await?;
        Ok(())
    }
}

impl FramingReader {
    /// Reads one MMS PDU, stripping the session and presentation framing.
    ///
    /// An abort by the peer is [`Error::Aborted`], naming whether the peer's
    /// user or its provider aborted.
    pub(crate) async fn recv_mms(&mut self) -> Result<Vec<u8>> {
        let ud = match session::receive_data(&mut self.r).await {
            Ok(ud) => ud,
            Err(osi::Error::Aborted { user_data }) => {
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
        Ok(presentation::unwrap_data(&ud)?)
    }
}
