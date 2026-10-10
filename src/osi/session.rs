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
const SI_REFUSE: u8 = 0x0c;
const SI_ABORT: u8 = 0x19;

/// Parameter and parameter-group identifiers.
const PGI_CONNECT_ACCEPT: u8 = 0x05;
const PI_PROTOCOL_OPTS: u8 = 0x13;
const PI_VERSION_NUMBER: u8 = 0x16;
const PI_SESSION_USER_REQ: u8 = 0x14;
const PI_CALLING_SSEL: u8 = 0x33;
const PI_CALLED_SSEL: u8 = 0x34;
const PGI_USER_DATA: u8 = 0xc1;
const PI_TRANSPORT_DISC: u8 = 0x11;
const PI_REASON_CODE: u8 = 0x32;

/// The REFUSE reason code of a rejection by the called session user, whose
/// following octets carry its user data (the presentation CPR).
pub const REASON_USER_DATA: u8 = 2;

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
    if resp.first() == Some(&SI_REFUSE) {
        let params = spdu_params(&resp)?;
        return Err(match find_param(params, PI_REASON_CODE) {
            Some(rc) if !rc.is_empty() => Error::Refused {
                reason: rc[0],
                user_data: rc[1..].to_vec(),
            },
            _ => Error::Refused {
                reason: 0,
                user_data: Vec::new(),
            },
        });
    }
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
/// Sends a REFUSE SPDU, the session user's rejection of a CONNECT, carrying
/// `user_data` (the presentation CPR) after reason code 2. The transport
/// connection is to be released after it.
pub async fn refuse<T>(t: &mut T, user_data: &[u8]) -> Result<()>
where
    T: SendTsdu,
{
    let mut params = Vec::new();
    write_pi(&mut params, PI_TRANSPORT_DISC, &[0x01]); // release the transport
    let mut rc = vec![REASON_USER_DATA];
    rc.extend_from_slice(user_data);
    write_pi(&mut params, PI_REASON_CODE, &rc);
    t.send_tsdu(&spdu(SI_REFUSE, &params)).await
}

/// Sends an ABORT SPDU carrying `user_data` (the presentation ARU). The
/// transport disconnect parameter says the transport is released, by the
/// user, for no stated reason, as libiec61850 sends it.
pub async fn abort<T>(t: &mut T, user_data: &[u8]) -> Result<()>
where
    T: SendTsdu,
{
    let mut params = Vec::new();
    write_pi(&mut params, PI_TRANSPORT_DISC, &[0x0b]);
    write_pi(&mut params, PGI_USER_DATA, user_data);
    t.send_tsdu(&spdu(SI_ABORT, &params)).await
}

fn spdu(si: u8, params: &[u8]) -> Vec<u8> {
    let mut out = vec![si];
    append_len(&mut out, params.len());
    out.extend_from_slice(params);
    out
}

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
    if tsdu.first() == Some(&SI_ABORT) {
        let user_data = spdu_params(&tsdu)
            .ok()
            .and_then(|p| find_user_data(p).ok().flatten())
            .unwrap_or_default();
        return Err(Error::Aborted { user_data });
    }
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
    spdu(si, &params)
}

/// Appends a session length indicator: one octet up to 254, else 0xff and two
/// octets (ISO 8327-1 8.2.5).
fn append_len(b: &mut Vec<u8>, n: usize) {
    if n < 255 {
        b.push(n as u8);
    } else {
        b.extend_from_slice(&[0xff, (n >> 8) as u8, n as u8]);
    }
}

/// Reads a length indicator at `b[0]`, returning the length and the octets
/// the indicator took.
fn read_len(b: &[u8]) -> Option<(usize, usize)> {
    match b {
        [0xff, hi, lo, ..] => Some(((usize::from(*hi) << 8) | usize::from(*lo), 3)),
        [0xff, ..] | [] => None,
        [n, ..] => Some((usize::from(*n), 1)),
    }
}

/// Returns the parameter field of an SPDU.
fn spdu_params(spdu: &[u8]) -> Result<&[u8]> {
    if spdu.len() < 2 {
        return Err(Error::Session("short SPDU".into()));
    }
    let (li, n) = read_len(&spdu[1..]).ok_or_else(|| Error::Session("short long-form LI".into()))?;
    if 1 + n + li > spdu.len() {
        return Err(Error::Session(format!("SPDU LI {li} exceeds buffer")));
    }
    Ok(&spdu[1 + n..1 + n + li])
}

struct ConnectLike {
    si: u8,
    params: Vec<u8>,
    user_data: Vec<u8>,
}

/// Parses a CONNECT/ACCEPT SPDU and returns its SI and the user-data
/// parameter contents.
fn parse_connect_like(spdu: &[u8]) -> Result<ConnectLike> {
    let params = spdu_params(spdu)?;
    let user_data = find_user_data(params)?.unwrap_or_default();
    Ok(ConnectLike {
        si: spdu[0],
        params: params.to_vec(),
        user_data,
    })
}

/// Returns the value of a session parameter, or `None` when absent.
fn find_param(mut params: &[u8], code: u8) -> Option<Vec<u8>> {
    while params.len() >= 2 {
        let (plen, n) = read_len(&params[1..])?;
        if 1 + n + plen > params.len() {
            return None;
        }
        if params[0] == code {
            return Some(params[1 + n..1 + n + plen].to_vec());
        }
        params = &params[1 + n + plen..];
    }
    None
}

/// Walks the parameter fields looking for the user-data PGI.
fn find_user_data(mut params: &[u8]) -> Result<Option<Vec<u8>>> {
    while params.len() >= 2 {
        let code = params[0];
        let (plen, n) = read_len(&params[1..])
            .ok_or_else(|| Error::Session("short parameter length".into()))?;
        if 1 + n + plen > params.len() {
            return Err(Error::Session(format!(
                "parameter length {plen} overflows"
            )));
        }
        if code == PGI_USER_DATA {
            return Ok(Some(params[1 + n..1 + n + plen].to_vec()));
        }
        params = &params[1 + n + plen..];
    }
    Ok(None)
}

fn write_pi(b: &mut Vec<u8>, code: u8, val: &[u8]) {
    b.push(code);
    append_len(b, val.len());
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

    /// User data longer than 254 octets takes the long length form, in the
    /// parameter as in the SPDU, and parses back.
    #[test]
    fn long_user_data_uses_the_long_length_form() {
        let ud = vec![0x5a; 600];
        let spdu = build_connect(SI_CONNECT, &[0, 1], &[], &ud);
        let parsed = parse_connect_like(&spdu).unwrap();
        assert_eq!(parsed.user_data, ud);
    }

    /// A refused CONNECT surfaces the CPR the peer sent, and an ABORT in the
    /// data phase surfaces the ARU.
    #[tokio::test]
    async fn refuse_and_abort_carry_their_user_data() {
        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut t = cotp::Conn::accept(srv).await.unwrap();
            accept_server(&mut t).await.unwrap();
            refuse(&mut t, b"cpr-pdu").await.unwrap();
        });
        let mut t = cotp::Conn::connect(cli, cotp::Options::default()).await.unwrap();
        match connect_client(&mut t, &[], &[], b"cp").await {
            Err(Error::Refused { reason, user_data }) => {
                assert_eq!(reason, REASON_USER_DATA);
                assert_eq!(user_data, b"cpr-pdu");
            }
            other => panic!("{other:?}"),
        }
        server.await.unwrap();

        let (cli, srv) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut t = cotp::Conn::accept(srv).await.unwrap();
            accept_server(&mut t).await.unwrap();
            reply(&mut t, &[], b"cpa").await.unwrap();
            abort(&mut t, b"aru-pdu").await.unwrap();
        });
        let mut t = cotp::Conn::connect(cli, cotp::Options::default()).await.unwrap();
        connect_client(&mut t, &[], &[], b"cp").await.unwrap();
        match receive_data(&mut t).await {
            Err(Error::Aborted { user_data }) => assert_eq!(user_data, b"aru-pdu"),
            other => panic!("{other:?}"),
        }
        server.await.unwrap();
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
