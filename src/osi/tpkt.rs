//! RFC 1006 (ISO transport service on top of TCP), the framing layer beneath
//! COTP for MMS over TCP port 102.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{Error, Result};

/// Length of the TPKT header: version(1), reserved(1), length(2).
const HEADER_LEN: usize = 4;
const VERSION: u8 = 3;

/// Bounds a single TPKT to guard against hostile length fields; IEC 61850
/// payloads are far smaller.
pub const MAX_PACKET: usize = 1 << 20;

/// Frames `payload` as a TPKT and writes it to `w`.
pub async fn write_packet<W>(w: &mut W, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let total = HEADER_LEN + payload.len();
    if total > MAX_PACKET {
        return Err(Error::Tpkt(format!(
            "packet of {total} bytes exceeds max {MAX_PACKET}"
        )));
    }
    // One write, so a packet never interleaves with another sender's.
    let mut frame = Vec::with_capacity(total);
    frame.push(VERSION);
    frame.push(0);
    frame.extend_from_slice(&(total as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    w.write_all(&frame).await?;
    w.flush().await?;
    Ok(())
}

/// Reads exactly one TPKT from `r` and returns its payload (the COTP TPDU).
pub async fn read_packet<R>(r: &mut R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut hdr = [0u8; HEADER_LEN];
    r.read_exact(&mut hdr).await?;
    if hdr[0] != VERSION {
        return Err(Error::Tpkt(format!("bad version {}", hdr[0])));
    }
    let total = usize::from(u16::from_be_bytes([hdr[2], hdr[3]]));
    if !(HEADER_LEN..=MAX_PACKET).contains(&total) {
        return Err(Error::Tpkt(format!("bad length {total}")));
    }
    let mut payload = vec![0u8; total - HEADER_LEN];
    r.read_exact(&mut payload).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packets_round_trip_through_a_stream() {
        let mut buf: Vec<u8> = Vec::new();
        write_packet(&mut buf, b"hello").await.unwrap();
        write_packet(&mut buf, b"").await.unwrap();
        assert_eq!(&buf[..4], &[3, 0, 0, 9]);

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_packet(&mut cursor).await.unwrap(), b"hello");
        assert_eq!(read_packet(&mut cursor).await.unwrap(), b"");
    }

    #[tokio::test]
    async fn a_bad_version_octet_is_rejected() {
        let mut cursor = std::io::Cursor::new(vec![4u8, 0, 0, 4]);
        assert!(matches!(
            read_packet(&mut cursor).await,
            Err(Error::Tpkt(_))
        ));
    }

    #[tokio::test]
    async fn a_length_below_the_header_size_is_rejected() {
        // A length of 2 would imply a negative payload length.
        let mut cursor = std::io::Cursor::new(vec![3u8, 0, 0, 2]);
        assert!(matches!(
            read_packet(&mut cursor).await,
            Err(Error::Tpkt(_))
        ));
    }
}
