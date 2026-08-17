//! ISO 8073 / X.224 Connection-Oriented Transport Protocol class 0, as
//! profiled by RFC 1006 for MMS.
//!
//! It provides connection establishment (CR/CC) and data transfer (DT) with
//! reassembly of the TPDU segments produced by the class-0 EOT mechanism.

use tokio::io::{AsyncRead, AsyncWrite};

use super::{tpkt, Error, Result};

/// TPDU type codes (high nibble of the type octet).
const TPDU_CR: u8 = 0xe0; // connection request
const TPDU_CC: u8 = 0xd0; // connection confirm
const TPDU_DR: u8 = 0x80; // disconnect request
const TPDU_DT: u8 = 0xf0; // data
const TPDU_ER: u8 = 0x70; // error

/// Parameter codes.
const PARAM_TPDU_SIZE: u8 = 0xc0;
const PARAM_SRC_TSAP: u8 = 0xc1;
const PARAM_DST_TSAP: u8 = 0xc2;

/// End-of-transmission flag in a DT TPDU's number octet.
const EOT: u8 = 0x80;

/// The transport selector used by common IEC 61850 stacks.
pub const DEFAULT_TSAP: &[u8] = &[0x00, 0x01];

/// Configures a COTP connection.
#[derive(Debug, Clone)]
pub struct Options {
    /// The calling transport selector. For MMS this is conventionally the
    /// two octets `{0, 1}`.
    pub src_tsap: Vec<u8>,
    /// The called transport selector.
    pub dst_tsap: Vec<u8>,
    /// The proposed maximum TPDU size as a power-of-two code (10 = 1024).
    pub tpdu_size_code: u8,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            src_tsap: DEFAULT_TSAP.to_vec(),
            dst_tsap: DEFAULT_TSAP.to_vec(),
            tpdu_size_code: 10, // 1024 octets
        }
    }
}

/// A COTP class-0 connection over a byte stream (typically TCP or TLS).
///
/// It is not safe for concurrent use by multiple senders; callers serialise
/// sends, and a single reader drains it.
#[derive(Debug)]
pub struct Conn<S> {
    stream: S,
    max_tpdu: usize,
    src_ref: u16,
    dst_ref: u16,
    src_tsap: Vec<u8>,
    dst_tsap: Vec<u8>,
}

impl<S> Conn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Performs the CR/CC handshake as the calling (client) side.
    pub async fn connect(stream: S, opts: Options) -> Result<Conn<S>> {
        let size_code = if opts.tpdu_size_code == 0 {
            10
        } else {
            opts.tpdu_size_code
        };
        let mut c = Conn {
            stream,
            max_tpdu: 1usize << size_code,
            src_ref: 1,
            dst_ref: 0,
            src_tsap: opts.src_tsap,
            dst_tsap: opts.dst_tsap,
        };
        c.send_cr(size_code).await?;
        c.recv_cc().await?;
        Ok(c)
    }

    /// Performs the CR/CC handshake as the called (server) side: reads the
    /// peer's CR, echoes the negotiated TPDU size and TSAPs, and returns an
    /// established connection.
    pub async fn accept(stream: S) -> Result<Conn<S>> {
        let mut c = Conn {
            stream,
            max_tpdu: 1024,
            src_ref: 1,
            dst_ref: 0,
            src_tsap: Vec::new(),
            dst_tsap: Vec::new(),
        };
        let tpdu = tpkt::read_packet(&mut c.stream).await?;
        let (_, typ, body) = parse_header(&tpdu)?;
        if typ != TPDU_CR {
            return Err(Error::Cotp(format!("expected CR, got type 0x{typ:02x}")));
        }
        // body = destRef(2) srcRef(2) class(1) params...
        if body.len() >= 4 {
            c.dst_ref = u16::from_be_bytes([body[2], body[3]]);
        }
        let mut size_code = 10u8;
        if body.len() > 5 {
            let mut params = &body[5..];
            while params.len() >= 2 {
                let code = params[0];
                let plen = usize::from(params[1]);
                if 2 + plen > params.len() {
                    break;
                }
                let val = &params[2..2 + plen];
                match code {
                    PARAM_TPDU_SIZE if plen == 1 => {
                        size_code = val[0];
                        c.max_tpdu = 1usize << size_code.min(24);
                    }
                    // The peer's source selector is our destination, and
                    // vice versa.
                    PARAM_SRC_TSAP => c.dst_tsap = val.to_vec(),
                    PARAM_DST_TSAP => c.src_tsap = val.to_vec(),
                    _ => {}
                }
                params = &params[2 + plen..];
            }
        }
        c.send_cc(size_code).await?;
        Ok(c)
    }

    async fn send_cr(&mut self, size_code: u8) -> Result<()> {
        let mut b = vec![0u8, TPDU_CR];
        b.extend_from_slice(&0u16.to_be_bytes()); // destRef
        b.extend_from_slice(&self.src_ref.to_be_bytes());
        b.push(0); // class 0, no options
        write_param(&mut b, PARAM_TPDU_SIZE, &[size_code]);
        write_param(&mut b, PARAM_SRC_TSAP, &self.src_tsap.clone());
        write_param(&mut b, PARAM_DST_TSAP, &self.dst_tsap.clone());
        b[0] = (b.len() - 1) as u8; // LI covers everything after the LI octet
        tpkt::write_packet(&mut self.stream, &b).await
    }

    async fn send_cc(&mut self, size_code: u8) -> Result<()> {
        let mut b = vec![0u8, TPDU_CC];
        // Echo the peer's srcRef as our destRef.
        b.extend_from_slice(&self.dst_ref.to_be_bytes());
        b.extend_from_slice(&self.src_ref.to_be_bytes());
        b.push(0); // class 0
        write_param(&mut b, PARAM_TPDU_SIZE, &[size_code]);
        if !self.src_tsap.is_empty() {
            write_param(&mut b, PARAM_SRC_TSAP, &self.src_tsap.clone());
        }
        if !self.dst_tsap.is_empty() {
            write_param(&mut b, PARAM_DST_TSAP, &self.dst_tsap.clone());
        }
        b[0] = (b.len() - 1) as u8;
        tpkt::write_packet(&mut self.stream, &b).await
    }

    async fn recv_cc(&mut self) -> Result<()> {
        let tpdu = tpkt::read_packet(&mut self.stream).await?;
        let (_, typ, body) = parse_header(&tpdu)?;
        if typ != TPDU_CC {
            if typ == TPDU_DR {
                return Err(Error::Cotp("connection refused (DR)".into()));
            }
            return Err(Error::Cotp(format!("expected CC, got type 0x{typ:02x}")));
        }
        if body.len() < 5 {
            return Err(Error::Cotp("short CC".into()));
        }
        // body = destRef(2) srcRef(2) class(1) params...; the peer's srcRef
        // is our destination reference.
        self.dst_ref = u16::from_be_bytes([body[2], body[3]]);
        if body.len() > 5 {
            self.parse_params(&body[5..]);
        }
        Ok(())
    }

    fn parse_params(&mut self, mut params: &[u8]) {
        while params.len() >= 2 {
            let code = params[0];
            let plen = usize::from(params[1]);
            if 2 + plen > params.len() {
                return;
            }
            let val = &params[2..2 + plen];
            if code == PARAM_TPDU_SIZE && plen == 1 {
                // Only ever negotiate downwards.
                let sz = 1usize << val[0].min(24);
                if sz > 0 && sz < self.max_tpdu {
                    self.max_tpdu = sz;
                }
            }
            params = &params[2 + plen..];
        }
    }

    /// Transmits a complete transport service data unit, segmenting it into
    /// class-0 DT TPDUs no larger than the negotiated size.
    pub async fn send(&mut self, tsdu: &[u8]) -> Result<()> {
        // The class-0 DT header is 3 octets (LI, type, number), so the
        // payload per TPDU is the negotiated size minus that.
        let max_data = self.max_tpdu.saturating_sub(3).max(1);
        let mut off = 0usize;
        loop {
            let end = (off + max_data).min(tsdu.len());
            let last = end >= tsdu.len();
            let mut b = Vec::with_capacity(3 + (end - off));
            b.push(2); // LI: length of the header after LI (type + number)
            b.push(TPDU_DT);
            b.push(if last { EOT } else { 0 });
            b.extend_from_slice(&tsdu[off..end]);
            tpkt::write_packet(&mut self.stream, &b).await?;
            off = end;
            if last {
                return Ok(());
            }
        }
    }

    /// Reads DT TPDUs until EOT and returns the reassembled TSDU.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let tpdu = tpkt::read_packet(&mut self.stream).await?;
            let (li, typ, body) = parse_header(&tpdu)?;
            match typ {
                TPDU_DT => {
                    if body.is_empty() {
                        return Err(Error::Cotp("short DT".into()));
                    }
                    let num = body[0];
                    buf.extend_from_slice(&tpdu[1 + li..]);
                    if num & EOT != 0 {
                        return Ok(buf);
                    }
                }
                TPDU_DR => return Err(Error::Closed),
                TPDU_ER => return Err(Error::Cotp("received ER TPDU".into())),
                other => {
                    return Err(Error::Cotp(format!("unexpected TPDU type 0x{other:02x}")));
                }
            }
        }
    }

    /// Returns the negotiated maximum TPDU size in octets.
    pub fn max_tpdu(&self) -> usize {
        self.max_tpdu
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes the connection and returns the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Splits the established connection into independent reading and writing
    /// halves.
    ///
    /// The class-0 protocol state that matters after the handshake is the
    /// negotiated TPDU size, which only the writer needs, so the two halves
    /// share nothing and can be driven from different tasks. That is what
    /// lets a client demultiplex responses on a reader task while other tasks
    /// issue requests.
    pub fn into_split(self) -> (Reader<tokio::io::ReadHalf<S>>, Writer<tokio::io::WriteHalf<S>>) {
        let max_tpdu = self.max_tpdu;
        let (r, w) = tokio::io::split(self.stream);
        (Reader { stream: r }, Writer { stream: w, max_tpdu })
    }
}

/// The reading half of a split COTP connection.
#[derive(Debug)]
pub struct Reader<R> {
    stream: R,
}

impl<R: AsyncRead + Unpin> Reader<R> {
    /// Reads DT TPDUs until EOT and returns the reassembled TSDU.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let tpdu = tpkt::read_packet(&mut self.stream).await?;
            let (li, typ, body) = parse_header(&tpdu)?;
            match typ {
                TPDU_DT => {
                    if body.is_empty() {
                        return Err(Error::Cotp("short DT".into()));
                    }
                    let num = body[0];
                    buf.extend_from_slice(&tpdu[1 + li..]);
                    if num & EOT != 0 {
                        return Ok(buf);
                    }
                }
                TPDU_DR => return Err(Error::Closed),
                TPDU_ER => return Err(Error::Cotp("received ER TPDU".into())),
                other => {
                    return Err(Error::Cotp(format!("unexpected TPDU type 0x{other:02x}")));
                }
            }
        }
    }
}

/// The writing half of a split COTP connection.
#[derive(Debug)]
pub struct Writer<W> {
    stream: W,
    max_tpdu: usize,
}

impl<W: AsyncWrite + Unpin> Writer<W> {
    /// Transmits a complete TSDU, segmenting it into class-0 DT TPDUs no
    /// larger than the negotiated size.
    pub async fn send(&mut self, tsdu: &[u8]) -> Result<()> {
        let max_data = self.max_tpdu.saturating_sub(3).max(1);
        let mut off = 0usize;
        loop {
            let end = (off + max_data).min(tsdu.len());
            let last = end >= tsdu.len();
            let mut b = Vec::with_capacity(3 + (end - off));
            b.push(2);
            b.push(TPDU_DT);
            b.push(if last { EOT } else { 0 });
            b.extend_from_slice(&tsdu[off..end]);
            tpkt::write_packet(&mut self.stream, &b).await?;
            off = end;
            if last {
                return Ok(());
            }
        }
    }

    /// Shuts down the underlying stream.
    pub async fn shutdown(&mut self) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        self.stream.shutdown().await?;
        Ok(())
    }
}

/// Sends a complete TSDU. Implemented by both a whole [`Conn`] and a
/// [`Writer`] half, so the session layer works against either.
pub trait SendTsdu {
    fn send_tsdu(
        &mut self,
        tsdu: &[u8],
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Receives a complete TSDU. Implemented by both a whole [`Conn`] and a
/// [`Reader`] half.
pub trait RecvTsdu {
    fn recv_tsdu(&mut self) -> impl std::future::Future<Output = Result<Vec<u8>>> + Send;
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SendTsdu for Conn<S> {
    async fn send_tsdu(&mut self, tsdu: &[u8]) -> Result<()> {
        self.send(tsdu).await
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> RecvTsdu for Conn<S> {
    async fn recv_tsdu(&mut self) -> Result<Vec<u8>> {
        self.receive().await
    }
}

impl<W: AsyncWrite + Unpin + Send> SendTsdu for Writer<W> {
    async fn send_tsdu(&mut self, tsdu: &[u8]) -> Result<()> {
        self.send(tsdu).await
    }
}

impl<R: AsyncRead + Unpin + Send> RecvTsdu for Reader<R> {
    async fn recv_tsdu(&mut self) -> Result<Vec<u8>> {
        self.receive().await
    }
}

fn write_param(b: &mut Vec<u8>, code: u8, val: &[u8]) {
    b.push(code);
    b.push(val.len() as u8);
    b.extend_from_slice(val);
}

/// Splits a COTP TPDU into its length indicator, type and header body (the
/// octets after the type, within the header).
fn parse_header(tpdu: &[u8]) -> Result<(usize, u8, &[u8])> {
    if tpdu.len() < 2 {
        return Err(Error::Cotp("truncated TPDU".into()));
    }
    let li = usize::from(tpdu[0]);
    if li == 0 || 1 + li > tpdu.len() {
        return Err(Error::Cotp(format!(
            "bad LI {li} (len {})",
            tpdu.len()
        )));
    }
    let typ = tpdu[1] & 0xf0;
    Ok((li, typ, &tpdu[2..1 + li]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drives a client and a server over a duplex pipe and returns both
    /// established connections.
    async fn pair() -> (
        Conn<tokio::io::DuplexStream>,
        Conn<tokio::io::DuplexStream>,
    ) {
        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move { Conn::accept(srv).await });
        let client = Conn::connect(cli, Options::default()).await.unwrap();
        let server = server.await.unwrap().unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn handshake_agrees_on_references_and_selectors() {
        let (client, server) = pair().await;
        assert_eq!(
            server.dst_ref, client.src_ref,
            "server must adopt the client's srcRef as its destination"
        );
        assert_eq!(client.dst_ref, server.src_ref);
        assert_eq!(server.dst_tsap, DEFAULT_TSAP);
    }

    #[tokio::test]
    async fn a_tsdu_larger_than_one_tpdu_is_segmented_and_reassembled() {
        let (mut client, mut server) = pair().await;
        // 4000 bytes against a 1024-octet TPDU forces four segments.
        let payload: Vec<u8> = b"ABCDEFGH".repeat(500);
        assert!(payload.len() > client.max_tpdu());

        let expected = payload.clone();
        let reader = tokio::spawn(async move { server.receive().await });
        client.send(&payload).await.unwrap();
        assert_eq!(reader.await.unwrap().unwrap(), expected);
    }

    #[tokio::test]
    async fn data_flows_in_both_directions() {
        let (mut client, mut server) = pair().await;
        let reader = tokio::spawn(async move {
            let got = server.receive().await.unwrap();
            server.send(b"pong").await.unwrap();
            got
        });
        client.send(b"ping").await.unwrap();
        assert_eq!(reader.await.unwrap(), b"ping");
        assert_eq!(client.receive().await.unwrap(), b"pong");
    }

    #[tokio::test]
    async fn an_empty_tsdu_still_produces_one_eot_segment() {
        let (mut client, mut server) = pair().await;
        let reader = tokio::spawn(async move { server.receive().await });
        client.send(b"").await.unwrap();
        assert_eq!(reader.await.unwrap().unwrap(), b"");
    }

    #[test]
    fn a_malformed_length_indicator_is_rejected() {
        assert!(parse_header(&[]).is_err());
        assert!(parse_header(&[0x00, 0xf0]).is_err(), "LI of zero");
        assert!(parse_header(&[0xff, 0xf0]).is_err(), "LI past the buffer");
    }
}
