//! The ISAKMP message and payload codec (RFC 2408), with the GDOI payload
//! types of RFC 6407.

use super::{Error, Result};

// Payload types (RFC 2408 3.1, RFC 6407 5).
pub(crate) const P_NONE: u8 = 0;
pub(crate) const P_SA: u8 = 1;
pub(crate) const P_PROPOSAL: u8 = 2;
pub(crate) const P_TRANS: u8 = 3;
pub(crate) const P_KE: u8 = 4;
pub(crate) const P_ID: u8 = 5;
pub(crate) const P_CERT: u8 = 6;
pub(crate) const P_HASH: u8 = 8;
pub(crate) const P_SIG: u8 = 9;
pub(crate) const P_NONCE: u8 = 10;
pub(crate) const P_NOTIFY: u8 = 11;
pub(crate) const P_SAT: u8 = 16;
pub(crate) const P_KD: u8 = 17;

// Exchange types.
pub(crate) const XCHG_MAIN: u8 = 2; // ISAKMP Identity Protection (IKE main mode)
pub(crate) const XCHG_INFO: u8 = 5; // Informational
pub(crate) const XCHG_PULL: u8 = 32; // GDOI GROUPKEY-PULL

pub(crate) const ISAKMP_VERSION: u8 = 0x10; // major 1, minor 0
pub(crate) const FLAG_ENCRYPTED: u8 = 0x01;
pub(crate) const HEADER_LEN: usize = 28;
pub(crate) const DOI_GDOI: u32 = 2; // RFC 6407 2.1
pub(crate) const SIT_IDENTITY: u32 = 1; // SIT_IDENTITY_ONLY
pub(crate) const PROTO_ISAKMP: u8 = 1;
pub(crate) const TRANS_KEY_IKE: u8 = 1;
pub(crate) const PROTO_IEC61850: u8 = 3; // GDOI_PROTO_IEC_61850, RFC 8052
pub(crate) const KD_TYPE_TEK: u8 = 1;

/// Bounds a message the codec accepts: an ISAKMP message fits a UDP datagram.
pub(crate) const MAX_MESSAGE: usize = 65535;

pub(crate) fn malformed(msg: impl Into<String>) -> Error {
    Error::Malformed(msg.into())
}

/// The fixed ISAKMP header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Header {
    pub ic: [u8; 8],
    pub rc: [u8; 8],
    pub next: u8,
    pub exchange: u8,
    pub flags: u8,
    pub msg_id: u32,
    pub length: u32,
}

impl Header {
    pub(crate) fn marshal(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(&self.ic);
        b.extend_from_slice(&self.rc);
        b.extend_from_slice(&[self.next, ISAKMP_VERSION, self.exchange, self.flags]);
        b.extend_from_slice(&self.msg_id.to_be_bytes());
        b.extend_from_slice(&self.length.to_be_bytes());
    }

    pub(crate) fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }
}

pub(crate) fn parse_header(b: &[u8]) -> Result<Header> {
    if b.len() < HEADER_LEN {
        return Err(malformed(format!("{} octets, shorter than the header", b.len())));
    }
    if b[17] >> 4 != 1 {
        return Err(malformed(format!("ISAKMP major version {}", b[17] >> 4)));
    }
    let mut h = Header {
        next: b[16],
        exchange: b[18],
        flags: b[19],
        msg_id: u32::from_be_bytes([b[20], b[21], b[22], b[23]]),
        length: u32::from_be_bytes([b[24], b[25], b[26], b[27]]),
        ..Default::default()
    };
    h.ic.copy_from_slice(&b[0..8]);
    h.rc.copy_from_slice(&b[8..16]);
    if (h.length as usize) < HEADER_LEN || h.length as usize > b.len() || h.length as usize > MAX_MESSAGE {
        return Err(malformed(format!("length {} for {} octets", h.length, b.len())));
    }
    Ok(h)
}

/// One generic payload: its type and body (after the 4-octet generic
/// header). `raw_len` is the whole payload's length on the wire, header
/// included, which HASH computations account for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Payload {
    pub kind: u8,
    pub body: Vec<u8>,
    pub raw_len: usize,
}

impl Payload {
    pub(crate) fn new(kind: u8, body: Vec<u8>) -> Payload {
        Payload {
            kind,
            raw_len: 4 + body.len(),
            body,
        }
    }
}

/// Encodes payloads as a chain: each generic header names the type of the
/// payload after it. `next` is the type of the payload that follows the chain
/// (0 at the end of a message).
pub(crate) fn encode_chain(ps: &[Payload], next: u8) -> Vec<u8> {
    let mut b = Vec::new();
    for (i, p) in ps.iter().enumerate() {
        let n = ps.get(i + 1).map_or(next, |q| q.kind);
        b.extend_from_slice(&[n, 0]);
        b.extend_from_slice(&((4 + p.body.len()) as u16).to_be_bytes());
        b.extend_from_slice(&p.body);
    }
    b
}

/// Walks a payload chain starting with type `first`, until a payload names no
/// successor. It returns the payloads and the octets the chain occupies; what
/// follows (padding) is not part of it.
pub(crate) fn parse_chain(b: &[u8], first: u8) -> Result<(Vec<Payload>, usize)> {
    let mut ps = Vec::new();
    let (mut off, mut t) = (0usize, first);
    while t != P_NONE {
        if b.len() - off < 4 {
            return Err(malformed("truncated payload header"));
        }
        let next = b[off];
        let n = usize::from(u16::from_be_bytes([b[off + 2], b[off + 3]]));
        if n < 4 || n > b.len() - off {
            return Err(malformed(format!(
                "payload of type {t} claims {n} octets, {} remain",
                b.len() - off
            )));
        }
        ps.push(Payload {
            kind: t,
            body: b[off + 4..off + n].to_vec(),
            raw_len: n,
        });
        off += n;
        t = next;
        if ps.len() > 64 {
            return Err(malformed("more than 64 payloads"));
        }
    }
    Ok((ps, off))
}

/// Returns the first payload of type `t`.
pub(crate) fn find(ps: &[Payload], t: u8) -> Option<&Payload> {
    ps.iter().find(|p| p.kind == t)
}

/// An ISAKMP data attribute (RFC 2408 3.3): basic (TV) when the value fits 16
/// bits and the attribute type allows it, variable (TLV) otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attribute {
    pub kind: u16,
    /// Big-endian.
    pub value: Vec<u8>,
    pub basic: bool,
}

impl Attribute {
    pub(crate) fn basic(kind: u16, v: u16) -> Attribute {
        Attribute {
            kind,
            value: v.to_be_bytes().to_vec(),
            basic: true,
        }
    }

    pub(crate) fn variable(kind: u16, v: Vec<u8>) -> Attribute {
        Attribute {
            kind,
            value: v,
            basic: false,
        }
    }

    /// A variable attribute holding a 32-bit number.
    pub(crate) fn uint32(kind: u16, v: u32) -> Attribute {
        Attribute::variable(kind, v.to_be_bytes().to_vec())
    }

    pub(crate) fn uint(&self) -> u64 {
        self.value.iter().fold(0u64, |v, &c| v << 8 | u64::from(c))
    }
}

pub(crate) fn encode_attrs(attrs: &[Attribute]) -> Vec<u8> {
    let mut b = Vec::new();
    for a in attrs {
        if a.basic {
            b.extend_from_slice(&(0x8000 | a.kind).to_be_bytes());
            b.extend_from_slice(&a.value[a.value.len() - 2..]);
        } else {
            b.extend_from_slice(&(a.kind & 0x7fff).to_be_bytes());
            b.extend_from_slice(&(a.value.len() as u16).to_be_bytes());
            b.extend_from_slice(&a.value);
        }
    }
    b
}

pub(crate) fn parse_attrs(b: &[u8]) -> Result<Vec<Attribute>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off < b.len() {
        if b.len() - off < 4 {
            return Err(malformed("truncated attribute"));
        }
        let t = u16::from_be_bytes([b[off], b[off + 1]]);
        if t & 0x8000 != 0 {
            out.push(Attribute {
                kind: t & 0x7fff,
                value: b[off + 2..off + 4].to_vec(),
                basic: true,
            });
            off += 4;
            continue;
        }
        let n = usize::from(u16::from_be_bytes([b[off + 2], b[off + 3]]));
        if n > b.len() - off - 4 {
            return Err(malformed(format!(
                "attribute {t} of {n} octets, {} remain",
                b.len() - off - 4
            )));
        }
        out.push(Attribute::variable(t, b[off + 4..off + 4 + n].to_vec()));
        off += 4 + n;
    }
    Ok(out)
}

pub(crate) fn attr_by_type(attrs: &[Attribute], t: u16) -> Option<&Attribute> {
    attrs.iter().find(|a| a.kind == t)
}

/// Identification types (RFC 2407 4.6.2.1, RFC 8052 4).
pub const ID_IPV4_ADDR: u8 = 1;
pub const ID_FQDN: u8 = 2;
pub const ID_USER_FQDN: u8 = 3;
pub const ID_IPV6_ADDR: u8 = 5;
pub const ID_DER_ASN1_DN: u8 = 9;
pub const ID_KEY_ID: u8 = 11;
pub const ID_OID: u8 = 13;

/// An identification payload body: type, three octets of DOI-specific data
/// (protocol and port in phase 1, zero in GDOI), data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IdPayload {
    pub kind: u8,
    pub data: Vec<u8>,
}

impl IdPayload {
    pub(crate) fn body(&self) -> Vec<u8> {
        let mut b = vec![self.kind, 0, 0, 0];
        b.extend_from_slice(&self.data);
        b
    }
}

pub(crate) fn parse_id(b: &[u8]) -> Result<IdPayload> {
    if b.len() < 4 {
        return Err(malformed(format!("identification of {} octets", b.len())));
    }
    Ok(IdPayload {
        kind: b[0],
        data: b[4..].to_vec(),
    })
}

/// A Notification payload body (RFC 2408 3.14) with no SPI.
pub(crate) fn notify(doi: u32, kind: u16, data: &[u8]) -> Vec<u8> {
    let mut b = doi.to_be_bytes().to_vec();
    b.extend_from_slice(&[PROTO_ISAKMP, 0]);
    b.extend_from_slice(&kind.to_be_bytes());
    b.extend_from_slice(data);
    b
}

// Notify message types used (RFC 2408 3.14.1).
pub const NOTIFY_INVALID_PAYLOAD: u16 = 1;
pub const NOTIFY_NO_PROPOSAL_CHOSEN: u16 = 14;
pub const NOTIFY_INVALID_ID_INFO: u16 = 18;
pub const NOTIFY_INVALID_CERT: u16 = 19;
pub const NOTIFY_INVALID_HASH_INFO: u16 = 23;
pub const NOTIFY_AUTH_FAILED: u16 = 24;
pub const NOTIFY_INVALID_SIGNATURE: u16 = 25;

/// The name of a notify message type.
pub fn notify_name(t: u16) -> String {
    match t {
        NOTIFY_INVALID_PAYLOAD => "INVALID-PAYLOAD-TYPE".into(),
        NOTIFY_NO_PROPOSAL_CHOSEN => "NO-PROPOSAL-CHOSEN".into(),
        NOTIFY_INVALID_ID_INFO => "INVALID-ID-INFORMATION".into(),
        NOTIFY_INVALID_CERT => "INVALID-CERTIFICATE".into(),
        NOTIFY_INVALID_HASH_INFO => "INVALID-HASH-INFORMATION".into(),
        NOTIFY_AUTH_FAILED => "AUTHENTICATION-FAILED".into(),
        NOTIFY_INVALID_SIGNATURE => "INVALID-SIGNATURE".into(),
        n => format!("notify {n}"),
    }
}

/// Reads the notify message type of a Notification payload body.
pub(crate) fn parse_notify(b: &[u8]) -> Result<u16> {
    if b.len() < 8 {
        return Err(malformed(format!("notification of {} octets", b.len())));
    }
    Ok(u16::from_be_bytes([b[6], b[7]]))
}
