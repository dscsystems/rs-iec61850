//! The minimal subset of the ISO 8327-1 connection-oriented session protocol
//! used by the MMS profile.
//!
//! That is the CONNECT/ACCEPT SPDUs for association setup and the
//! GIVE-TOKENS + DATA-TRANSFER prefix used for every data message. The full
//! session service (tokens, activities, resynchronisation) is not used by MMS
//! and is not implemented.

use super::cotp::{RecvTsdu, SendTsdu};
use super::{Error, Result};

/// SPDU type identifiers (the SI octet).
///
/// GIVE-TOKENS and DATA-TRANSFER share SI `0x01` and cannot be told apart by
/// value, which is why [`strip_data_prefix`] strips by count rather than by
/// type.
const SI_GIVE_TOKENS: u8 = 0x01;
const SI_DATA_TRANSFER: u8 = 0x01;
const SI_CONNECT: u8 = 0x0d;
const SI_ACCEPT: u8 = 0x0e;

/// Parameter and parameter-group identifiers.
const PGI_CONNECT_ACCEPT: u8 = 0x05;
const PI_PROTOCOL_OPTS: u8 = 0x13;
const PI_VERSION_NUMBER: u8 = 0x16;
const PI_SESSION_USER_REQ: u8 = 0x14;
const PI_CALLING_SSEL: u8 = 0x33;
const PI_CALLED_SSEL: u8 = 0x34;
const PGI_USER_DATA: u8 = 0xc1;

/// Sends a CONNECT SPDU carrying `user_data` (the presentation CP PDU) and
/// returns the user data from the peer's ACCEPT SPDU.
pub async fn connect_client<T>(
    t: &mut T,
    calling_ssel: &[u8],
    called_ssel: &[u8],
    user_data: &[u8],
) -> Result<Vec<u8>>
where
    T: SendTsdu + RecvTsdu,
{
    let spdu = build_connect(SI_CONNECT, calling_ssel, called_ssel, user_data);
    t.send_tsdu(&spdu).await?;
    let resp = t.recv_tsdu().await?;
    let parsed = parse_connect_like(&resp)?;
    if parsed.si != SI_ACCEPT {
        return Err(Error::Session(format!(
            "expected ACCEPT, got SI 0x{:02x}",
            parsed.si
        )));
    }
    Ok(parsed.user_data)
}

/// What a responder learns from a peer's CONNECT SPDU.
#[derive(Debug, Clone, Default)]
pub struct AcceptResult {
    pub user_data: Vec<u8>,
    pub calling_ssel: Option<Vec<u8>>,
    pub called_ssel: Option<Vec<u8>>,
}

/// Reads a CONNECT SPDU and returns its user data. The caller then invokes
/// [`reply`] to send the ACCEPT.
pub async fn accept_server<T>(t: &mut T) -> Result<AcceptResult>
where
    T: RecvTsdu,
{
    let spdu = t.recv_tsdu().await?;
    let parsed = parse_connect_like(&spdu)?;
    if parsed.si != SI_CONNECT {
        return Err(Error::Session(format!(
            "expected CONNECT, got SI 0x{:02x}",
            parsed.si
        )));
    }
    Ok(AcceptResult {
        user_data: parsed.user_data,
        calling_ssel: find_param(&parsed.params, PI_CALLING_SSEL),
        called_ssel: find_param(&parsed.params, PI_CALLED_SSEL),
    })
}

/// Sends the ACCEPT SPDU carrying `user_data` (the presentation CPA PDU).
///
/// `called_ssel` is echoed back when the peer addressed one: a responder that
/// answers a CONNECT without naming the session selector it was reached at
/// leaves a peer that checks it unable to confirm it reached the right end.
pub async fn reply<T>(t: &mut T, called_ssel: &[u8], user_data: &[u8]) -> Result<()>
where
    T: SendTsdu,
{
    t.send_tsdu(&build_connect(SI_ACCEPT, &[], called_ssel, user_data))
        .await
}

/// Sends a data-phase message: the GIVE-TOKENS and DATA-TRANSFER SPDUs
/// followed by `user_data` (the presentation user-data PDU).
pub async fn send_data<T>(t: &mut T, user_data: &[u8]) -> Result<()>
where
    T: SendTsdu,
{
    let mut buf = Vec::with_capacity(4 + user_data.len());
    buf.extend_from_slice(&[SI_GIVE_TOKENS, 0x00]); // GIVE TOKENS, LI 0
    buf.extend_from_slice(&[SI_DATA_TRANSFER, 0x00]); // DATA TRANSFER, LI 0
    buf.extend_from_slice(user_data);
    t.send_tsdu(&buf).await
}

/// Reads a data-phase message and returns the presentation user data,
/// stripping the session SPDU prefix.
pub async fn receive_data<T>(t: &mut T) -> Result<Vec<u8>>
where
    T: RecvTsdu,
{
    let tsdu = t.recv_tsdu().await?;
    Ok(strip_data_prefix(&tsdu)?.to_vec())
}

/// Strips the session prefix from a data-phase TSDU.
///
/// The data phase is prefixed by GIVE-TOKENS then DATA-TRANSFER. Both SPDUs
/// share SI `0x01`, so they cannot be told apart by value; strip up to two
/// such SPDUs and return the presentation user data that follows. Some stacks
/// omit GIVE-TOKENS, leaving a single DATA-TRANSFER.
pub fn strip_data_prefix(tsdu: &[u8]) -> Result<&[u8]> {
    let mut rest = tsdu;
    for _ in 0..2 {
        if rest.len() < 2 || rest[0] != SI_DATA_TRANSFER {
            break;
        }
        let li = usize::from(rest[1]);
        if 2 + li > rest.len() {
            return Err(Error::Session(format!("bad SPDU LI {li}")));
        }
        rest = &rest[2 + li..];
    }
    Ok(rest)
}

fn build_connect(si: u8, calling_ssel: &[u8], called_ssel: &[u8], user_data: &[u8]) -> Vec<u8> {
    let mut params: Vec<u8> = Vec::new();

    // Connect/Accept Item parameter group.
    let mut cai: Vec<u8> = Vec::new();
    write_pi(&mut cai, PI_PROTOCOL_OPTS, &[0x00]); // no extended concatenation
    write_pi(&mut cai, PI_VERSION_NUMBER, &[0x02]);
    write_pi(&mut params, PGI_CONNECT_ACCEPT, &cai);

    // Session user requirements: duplex functional unit (bit 1) = 0x0002.
    write_pi(&mut params, PI_SESSION_USER_REQ, &[0x00, 0x02]);

    if !calling_ssel.is_empty() {
        write_pi(&mut params, PI_CALLING_SSEL, calling_ssel);
    }
    if !called_ssel.is_empty() {
        write_pi(&mut params, PI_CALLED_SSEL, called_ssel);
    }

    // The user data parameter group carries the presentation PDU.
    write_pi(&mut params, PGI_USER_DATA, user_data);

    let mut out = Vec::with_capacity(4 + params.len());
    out.push(si);
    // MMS CONNECTs stay well under 255 octets, but guard the long form anyway.
    if params.len() < 255 {
        out.push(params.len() as u8);
    } else {
        out.push(0xff);
        out.push((params.len() >> 8) as u8);
        out.push(params.len() as u8);
    }
    out.extend_from_slice(&params);
    out
}

struct ConnectLike {
    si: u8,
    params: Vec<u8>,
    user_data: Vec<u8>,
}

/// Parses a CONNECT/ACCEPT SPDU and returns its SI and the user-data
/// parameter contents.
fn parse_connect_like(spdu: &[u8]) -> Result<ConnectLike> {
    if spdu.len() < 2 {
        return Err(Error::Session("short SPDU".into()));
    }
    let si = spdu[0];
    let (li, off) = if spdu[1] == 0xff {
        if spdu.len() < 4 {
            return Err(Error::Session("short long-form LI".into()));
        }
        ((usize::from(spdu[2]) << 8) | usize::from(spdu[3]), 4)
    } else {
        (usize::from(spdu[1]), 2)
    };
    if off + li > spdu.len() {
        return Err(Error::Session(format!("SPDU LI {li} exceeds buffer")));
    }
    let params = &spdu[off..off + li];
    let user_data = find_user_data(params)?.unwrap_or_default();
    Ok(ConnectLike {
        si,
        params: params.to_vec(),
        user_data,
    })
}

/// Returns the value of a session parameter, or `None` when absent.
fn find_param(mut params: &[u8], code: u8) -> Option<Vec<u8>> {
    while params.len() >= 2 {
        let plen = usize::from(params[1]);
        if 2 + plen > params.len() {
            return None;
        }
        if params[0] == code {
            return Some(params[2..2 + plen].to_vec());
        }
        params = &params[2 + plen..];
    }
    None
}

/// Walks the parameter fields looking for the user-data PGI.
fn find_user_data(mut params: &[u8]) -> Result<Option<Vec<u8>>> {
    while params.len() >= 2 {
        let code = params[0];
        let plen = usize::from(params[1]);
        if 2 + plen > params.len() {
            return Err(Error::Session(format!(
                "parameter length {plen} overflows"
            )));
        }
        if code == PGI_USER_DATA {
            return Ok(Some(params[2..2 + plen].to_vec()));
        }
        params = &params[2 + plen..];
    }
    Ok(None)
}

fn write_pi(b: &mut Vec<u8>, code: u8, val: &[u8]) {
    b.push(code);
    b.push(val.len() as u8);
    b.extend_from_slice(val);
}

#[cfg(test)]
mod tests {
    use super::super::cotp;
    use super::*;

    #[test]
    fn a_connect_spdu_round_trips_its_selectors_and_user_data() {
        let spdu = build_connect(SI_CONNECT, &[0x00, 0x01], &[0x00, 0x02], b"presentation-cp");
        let parsed = parse_connect_like(&spdu).unwrap();
        assert_eq!(parsed.si, SI_CONNECT);
        assert_eq!(parsed.user_data, b"presentation-cp");
        assert_eq!(find_param(&parsed.params, PI_CALLING_SSEL).unwrap(), [0, 1]);
        assert_eq!(find_param(&parsed.params, PI_CALLED_SSEL).unwrap(), [0, 2]);
    }

    #[test]
    fn absent_selectors_are_omitted_rather_than_sent_empty() {
        let spdu = build_connect(SI_ACCEPT, &[], &[], b"x");
        let parsed = parse_connect_like(&spdu).unwrap();
        assert!(find_param(&parsed.params, PI_CALLING_SSEL).is_none());
        assert!(find_param(&parsed.params, PI_CALLED_SSEL).is_none());
    }

    #[test]
    fn both_session_prefix_spdus_are_stripped() {
        // GIVE-TOKENS then DATA-TRANSFER, the usual pair.
        let tsdu = [0x01, 0x00, 0x01, 0x00, 0xa0, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(
            strip_data_prefix(&tsdu).unwrap(),
            &[0xa0, 0x03, 0x02, 0x01, 0x01]
        );
    }

    #[test]
    fn a_lone_data_transfer_spdu_is_also_accepted() {
        // Some stacks omit GIVE-TOKENS; the payload here starts with 0xa0,
        // which is not 0x01, so stripping stops after one SPDU.
        let tsdu = [0x01, 0x00, 0xa0, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(
            strip_data_prefix(&tsdu).unwrap(),
            &[0xa0, 0x03, 0x02, 0x01, 0x01]
        );
    }

    #[test]
    fn an_spdu_length_past_the_buffer_is_rejected() {
        assert!(strip_data_prefix(&[0x01, 0x40, 0x00]).is_err());
        assert!(parse_connect_like(&[0x0d, 0x7f]).is_err());
        assert!(parse_connect_like(&[0x0d]).is_err());
    }

    #[tokio::test]
    async fn a_full_session_association_and_data_exchange() {
        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut t = cotp::Conn::accept(srv).await.unwrap();
            let acc = accept_server(&mut t).await.unwrap();
            reply(&mut t, b"\x00\x01", b"cpa-pdu").await.unwrap();
            let data = receive_data(&mut t).await.unwrap();
            send_data(&mut t, b"response").await.unwrap();
            (acc, data)
        });

        let mut t = cotp::Conn::connect(cli, cotp::Options::default())
            .await
            .unwrap();
        let cpa = connect_client(&mut t, b"\x00\x01", b"\x00\x01", b"cp-pdu")
            .await
            .unwrap();
        assert_eq!(cpa, b"cpa-pdu");
        send_data(&mut t, b"request").await.unwrap();
        assert_eq!(receive_data(&mut t).await.unwrap(), b"response");

        let (acc, data) = server.await.unwrap();
        assert_eq!(acc.user_data, b"cp-pdu");
        assert_eq!(acc.calling_ssel.unwrap(), [0, 1]);
        assert_eq!(data, b"request");
    }
}
