use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};

use crate::osi::{cotp, presentation, session};

use super::Result;

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
}

pub(crate) struct FramingReader {
    r: cotp::Reader<ReadHalf<BoxTransport>>,
}

/// Splits an established COTP connection into MMS framing halves.
pub(crate) fn split(conn: cotp::Conn<BoxTransport>) -> (FramingReader, FramingWriter) {
    let (r, w) = conn.into_split();
    (FramingReader { r }, FramingWriter { w })
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
        session::send_data(&mut self.w, &presentation::wrap_data(pdu)).await?;
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
    pub(crate) async fn recv_mms(&mut self) -> Result<Vec<u8>> {
        let ud = session::receive_data(&mut self.r).await?;
        Ok(presentation::unwrap_data(&ud)?)
    }
}
