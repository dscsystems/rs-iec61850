use crate::asn1::{
    self, bit_string_elem, cons, context_constructed, context_primitive, int_elem, prim,
    BitString, Decoder, Tag,
};

use super::{Error, Result};

/// MMSpdu CHOICE tags (ISO 9506-2), context class.
pub(crate) const TAG_CONFIRMED_REQUEST: Tag = context_constructed(0);
pub(crate) const TAG_CONFIRMED_RESPONSE: Tag = context_constructed(1);
pub(crate) const TAG_CONFIRMED_ERROR: Tag = context_constructed(2);
pub(crate) const TAG_UNCONFIRMED: Tag = context_constructed(3);
pub(crate) const TAG_REJECT_PDU: Tag = context_constructed(4);
pub(crate) const TAG_INITIATE_REQUEST: Tag = context_constructed(8);
pub(crate) const TAG_INITIATE_RESPONSE: Tag = context_constructed(9);
pub(crate) const TAG_INITIATE_ERROR: Tag = context_constructed(10);
pub(crate) const TAG_CONCLUDE_REQUEST: Tag = context_constructed(11);
pub(crate) const TAG_CONCLUDE_RESPONSE: Tag = context_constructed(12);

/// Confirmed service CHOICE tags used within ConfirmedRequest/Response
/// (ISO 9506-2 `ConfirmedServiceRequest`).
/// The MMS `status` service, which this crate does not issue but names for
/// completeness of the service table.
#[allow(dead_code)]
pub(crate) const SVC_STATUS: u32 = 0;
pub(crate) const SVC_GET_NAME_LIST: u32 = 1;
pub(crate) const SVC_IDENTIFY: u32 = 2;
pub(crate) const SVC_READ: u32 = 4;
pub(crate) const SVC_WRITE: u32 = 5;
pub(crate) const SVC_GET_VARIABLE_ACCESS: u32 = 6;
pub(crate) const SVC_DEFINE_NAMED_VAR_LIST: u32 = 11;
pub(crate) const SVC_GET_NAMED_VAR_LIST_ATTR: u32 = 12;
pub(crate) const SVC_DELETE_NAMED_VAR_LIST: u32 = 13;
pub(crate) const SVC_READ_JOURNAL: u32 = 65;
pub(crate) const SVC_FILE_OPEN: u32 = 72;
pub(crate) const SVC_FILE_READ: u32 = 73;
pub(crate) const SVC_FILE_CLOSE: u32 = 74;
pub(crate) const SVC_FILE_DELETE: u32 = 76;
pub(crate) const SVC_FILE_DIRECTORY: u32 = 77;

/// Unconfirmed service CHOICE tags.
pub(crate) const UNCONF_INFORMATION_REPORT: u32 = 0;

/// The negotiated service bitmap.
///
/// Only presence matters to most peers, so it is kept as raw bits.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceSupport {
    pub bits: BitString,
    /// When set, emitted verbatim as the `servicesSupported` bit string
    /// content (including its leading unused-bits octet) instead of
    /// re-encoding `bits`.
    ///
    /// Clients gate feature use on this bitmap, so a proxy standing in for a
    /// device has to reproduce the device's octets exactly rather than a
    /// reconstruction that happens to set the same flags.
    pub raw: Option<Vec<u8>>,
}

/// The negotiable parameters of an MMS association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateRequest {
    pub local_detail: i32,
    /// Both calling and called, unless the two fields below are set.
    pub max_serv_outstanding: i32,
    pub nesting_level: i32,
    pub services: ServiceSupport,

    /// Preserves the calling and called values separately.
    ///
    /// `max_serv_outstanding` collapses them to the smaller, which is right
    /// for a client deciding how many requests to have in flight, but loses
    /// information a proxy needs to reproduce the peer's advertisement. When
    /// either is non-zero it is encoded in place of the collapsed value.
    pub max_serv_outstanding_calling: i32,
    pub max_serv_outstanding_called: i32,

    /// When set, emitted verbatim as the `proposedParameterCBB` bit string,
    /// including its leading unused-bits octet.
    pub parameter_cbb_raw: Option<Vec<u8>>,
}

impl Default for InitiateRequest {
    /// Typical client initiate parameters.
    fn default() -> InitiateRequest {
        InitiateRequest {
            local_detail: 65000,
            max_serv_outstanding: 10,
            nesting_level: 5,
            services: default_service_support(),
            max_serv_outstanding_calling: 0,
            max_serv_outstanding_called: 0,
            parameter_cbb_raw: None,
        }
    }
}

/// The 85-bit CBB bit string, enabling the services a client uses.
///
/// The set is the one substation clients advertise in practice: status,
/// getNameList, identify, read, write, getVariableAccessAttributes, the
/// named-variable-list services, the file services and informationReport.
fn default_service_support() -> ServiceSupport {
    let mut bits = BitString::new(85);
    for bit in [
        0, 1, 2, 4, 5, 6, 11, 12, 13, 14, 15, 16, 18, 19, 72, 73, 74, 76, 77, 79,
    ] {
        bits.set_bit(bit, true);
    }
    ServiceSupport { bits, raw: None }
}

/// The parameter-support bit string (proposed): indexed bits str1(0), str2(1),
/// vnam(2), valt(3), vadr(4), vsca(7), tpy(8), vlis(9)...
fn parameter_cbb() -> BitString {
    let mut bs = BitString::new(11);
    bs.set_bit(2, true); // vnam
    bs.set_bit(3, true); // valt
    bs.set_bit(4, true); // vadr
    bs.set_bit(5, true);
    bs.set_bit(6, true);
    bs
}

/// Builds an MMS InitiateRequestPDU.
pub fn encode_initiate_request(req: &InitiateRequest) -> Vec<u8> {
    encode_initiate(TAG_INITIATE_REQUEST, req)
}

/// Builds an MMS InitiateResponsePDU mirroring `req`.
pub fn encode_initiate_response(req: &InitiateRequest) -> Vec<u8> {
    encode_initiate(TAG_INITIATE_RESPONSE, req)
}

fn encode_initiate(tag: Tag, req: &InitiateRequest) -> Vec<u8> {
    let cbb = match &req.parameter_cbb_raw {
        Some(raw) => prim(context_primitive(1), raw.clone()),
        None => bit_string_elem(context_primitive(1), &parameter_cbb()),
    };
    let svc = match &req.services.raw {
        Some(raw) => prim(context_primitive(2), raw.clone()),
        None => bit_string_elem(context_primitive(2), &req.services.bits),
    };
    let detail = cons(
        context_constructed(4),
        [
            int_elem(context_primitive(0), 1), // proposedVersionNumber
            cbb,
            svc,
        ],
    );

    let calling = if req.max_serv_outstanding_calling == 0 {
        req.max_serv_outstanding
    } else {
        req.max_serv_outstanding_calling
    };
    let called = if req.max_serv_outstanding_called == 0 {
        req.max_serv_outstanding
    } else {
        req.max_serv_outstanding_called
    };

    cons(
        tag,
        [
            int_elem(context_primitive(0), i64::from(req.local_detail)),
            int_elem(context_primitive(1), i64::from(calling)),
            int_elem(context_primitive(2), i64::from(called)),
            int_elem(context_primitive(3), i64::from(req.nesting_level)),
            detail,
        ],
    )
    .encode()
}

/// Decodes an InitiateResponsePDU, returning the negotiated parameters.
pub fn parse_initiate_response(pdu: &[u8]) -> Result<InitiateRequest> {
    let mut dec = Decoder::new(pdu);
    match dec.expect(TAG_INITIATE_RESPONSE) {
        Ok(content) => parse_initiate_body(content),
        Err(e) => {
            // Some servers answer an unacceptable proposal with InitiateError.
            if Decoder::new(pdu).peek_is(TAG_INITIATE_ERROR) {
                return Err(Error::Rejected("InitiateError".into()));
            }
            Err(e.into())
        }
    }
}

/// Decodes an InitiateRequestPDU (server side).
pub fn parse_initiate_request(pdu: &[u8]) -> Result<InitiateRequest> {
    let mut dec = Decoder::new(pdu);
    let content = dec.expect(TAG_INITIATE_REQUEST)?;
    parse_initiate_body(content)
}

fn parse_initiate_body(content: &[u8]) -> Result<InitiateRequest> {
    let mut req = InitiateRequest {
        local_detail: 0,
        max_serv_outstanding: 0,
        nesting_level: 0,
        services: ServiceSupport::default(),
        max_serv_outstanding_calling: 0,
        max_serv_outstanding_called: 0,
        parameter_cbb_raw: None,
    };
    let mut dec = Decoder::new(content);
    if let Some(c) = dec.optional(context_primitive(0))? {
        req.local_detail = asn1::decode_int(c).unwrap_or(0) as i32;
    }
    if let Some(c) = dec.optional(context_primitive(1))? {
        let n = asn1::decode_int(c).unwrap_or(0) as i32;
        req.max_serv_outstanding = n;
        req.max_serv_outstanding_calling = n;
    }
    if let Some(c) = dec.optional(context_primitive(2))? {
        let n = asn1::decode_int(c).unwrap_or(0) as i32;
        req.max_serv_outstanding_called = n;
        // Keep the smaller of the two: it is the one that actually bounds
        // how many requests may be in flight.
        if n < req.max_serv_outstanding || req.max_serv_outstanding == 0 {
            req.max_serv_outstanding = n;
        }
    }
    if let Some(c) = dec.optional(context_primitive(3))? {
        req.nesting_level = asn1::decode_int(c).unwrap_or(0) as i32;
    }
    if let Some(c) = dec.optional(context_constructed(4))? {
        let mut detail = Decoder::new(c);
        while detail.more() {
            let Ok((tag, dc)) = detail.read_tlv() else {
                break;
            };
            if tag == context_primitive(1) {
                req.parameter_cbb_raw = Some(dc.to_vec());
            } else if tag == context_primitive(2) {
                let raw = Some(dc.to_vec());
                req.services = match asn1::decode_bit_string(dc) {
                    Ok(bits) => ServiceSupport { bits, raw },
                    Err(_) => ServiceSupport {
                        bits: BitString::default(),
                        raw,
                    },
                };
            }
        }
    }
    if req.local_detail == 0 {
        req.local_detail = 65000;
    }
    if req.max_serv_outstanding == 0 {
        req.max_serv_outstanding = 1;
    }
    Ok(req)
}

/// Reads the leading invokeID of a confirmed PDU and returns it plus the
/// remaining service-specific content.
///
/// The invokeID is a universal INTEGER in ConfirmedResponsePDU but is
/// context-tagged `[0]` in ConfirmedErrorPDU and RejectPDU in the MMS module
/// IEC 61850 uses, so both are accepted.
pub(crate) fn split_invoke(content: &[u8]) -> Result<(u32, &[u8])> {
    let mut dec = Decoder::new(content);
    let (tag, id_bytes) = dec.read_tlv()?;
    if tag != asn1::TAG_INTEGER && tag != context_primitive(0) {
        return Err(Error::protocol(format!("unexpected invokeID tag {tag}")));
    }
    let id = asn1::decode_uint(id_bytes)? as u32;
    Ok((id, dec.rest()))
}

/// Returns the human-readable name of a reject reason.
pub(crate) fn reject_reason_name(category: u32, code: u8) -> String {
    if category == 1 {
        // confirmed-requestPDU
        let name = match code {
            0 => Some("other"),
            1 => Some("unrecognized-service"),
            2 => Some("unrecognized-modifier"),
            3 => Some("invalid-invokeID"),
            4 => Some("invalid-argument"),
            5 => Some("invalid-modifier"),
            6 => Some("max-serv-outstanding-exceeded"),
            8 => Some("max-recursion-exceeded"),
            9 => Some("value-out-of-range"),
            _ => None,
        };
        if let Some(n) = name {
            return n.to_string();
        }
    }
    format!("reject category {category} code {code}")
}

/// Descends constructed context-specific elements to the first primitive
/// context-specific element, returning its tag number (the error class) and
/// integer value (the code).
///
/// The nesting of `serviceError` varies by MMS module, so drilling is more
/// robust than assuming one shape.
pub(crate) fn drill_error_class(body: &[u8], depth: usize) -> Option<(u8, u8)> {
    if depth > 8 {
        return None;
    }
    let mut dec = Decoder::new(body);
    while dec.more() {
        let Ok((tag, content)) = dec.read_tlv() else {
            return None;
        };
        if tag.class != asn1::Class::ContextSpecific {
            continue;
        }
        if tag.constructed {
            if let Some(found) = drill_error_class(content, depth + 1) {
                return Some(found);
            }
            continue;
        }
        let n = asn1::decode_int(content).unwrap_or(0);
        return Some((tag.number as u8, n as u8));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initiate_parameters_round_trip() {
        let req = InitiateRequest::default();
        let back = parse_initiate_request(&encode_initiate_request(&req)).unwrap();
        assert_eq!(back.local_detail, 65000);
        assert_eq!(back.max_serv_outstanding, 10);
        assert_eq!(back.nesting_level, 5);
        // The service bitmap must survive: clients gate feature use on it.
        assert!(back.services.bits.bit(4), "read must stay advertised");
        assert!(back.services.bits.bit(5), "write must stay advertised");
        assert!(back.services.bits.bit(72), "fileOpen must stay advertised");
    }

    #[test]
    fn a_response_pdu_is_tagged_differently_from_a_request() {
        let req = InitiateRequest::default();
        assert_eq!(encode_initiate_request(&req)[0], 0xa8);
        assert_eq!(encode_initiate_response(&req)[0], 0xa9);
        assert!(parse_initiate_response(&encode_initiate_response(&req)).is_ok());
        // A request must not parse as a response.
        assert!(parse_initiate_response(&encode_initiate_request(&req)).is_err());
    }

    #[test]
    fn max_serv_outstanding_collapses_to_the_smaller_of_the_two_directions() {
        let req = InitiateRequest {
            max_serv_outstanding_calling: 5,
            max_serv_outstanding_called: 2,
            ..Default::default()
        };
        let back = parse_initiate_request(&encode_initiate_request(&req)).unwrap();
        assert_eq!(back.max_serv_outstanding_calling, 5);
        assert_eq!(back.max_serv_outstanding_called, 2);
        assert_eq!(
            back.max_serv_outstanding, 2,
            "the bound on requests in flight is the smaller direction"
        );
    }

    /// A proxy has to reproduce a device's advertisement octet for octet: a
    /// re-encoding that happens to set the same flags can still differ, and
    /// clients validate the bitmap.
    #[test]
    fn raw_service_support_is_emitted_verbatim() {
        let raw = vec![0x03, 0xf1, 0x00, 0xff];
        let req = InitiateRequest {
            services: ServiceSupport {
                bits: BitString::new(85),
                raw: Some(raw.clone()),
            },
            ..Default::default()
        };
        let back = parse_initiate_request(&encode_initiate_request(&req)).unwrap();
        assert_eq!(back.services.raw.as_ref(), Some(&raw));
    }

    #[test]
    fn an_initiate_error_is_reported_as_a_rejection() {
        let pdu = cons(TAG_INITIATE_ERROR, []).encode();
        assert!(matches!(
            parse_initiate_response(&pdu),
            Err(Error::Rejected(_))
        ));
    }

    /// ConfirmedResponsePDU carries the invokeID as a universal INTEGER, but
    /// ConfirmedErrorPDU and RejectPDU carry it context-tagged [0]. Accepting
    /// only one form loses every error reply.
    #[test]
    fn split_invoke_accepts_both_invoke_id_taggings() {
        let universal = cons(
            context_constructed(0),
            [asn1::uint_elem(asn1::TAG_INTEGER, 42), prim(context_primitive(4), vec![])],
        );
        let content = match &universal {
            asn1::Element::Constructed { children, .. } => {
                let mut b = Vec::new();
                for c in children {
                    c.append(&mut b);
                }
                b
            }
            _ => unreachable!(),
        };
        assert_eq!(split_invoke(&content).unwrap().0, 42);

        let mut ctx = Vec::new();
        asn1::uint_elem(context_primitive(0), 43).append(&mut ctx);
        assert_eq!(split_invoke(&ctx).unwrap().0, 43);

        // Anything else is a malformed PDU rather than invoke id zero.
        let mut bad = Vec::new();
        asn1::append_tlv(&mut bad, asn1::TAG_OCTET_STRING, &[1]);
        assert!(split_invoke(&bad).is_err());
    }

    #[test]
    fn reject_reasons_are_named_where_the_standard_names_them() {
        assert_eq!(reject_reason_name(1, 1), "unrecognized-service");
        assert_eq!(reject_reason_name(1, 6), "max-serv-outstanding-exceeded");
        assert_eq!(reject_reason_name(9, 3), "reject category 9 code 3");
    }

    #[test]
    fn error_class_drilling_finds_the_innermost_primitive() {
        // serviceError [2] { errorClass [0] { access [7] INTEGER 3 } }
        let pdu = cons(
            context_constructed(2),
            [cons(
                context_constructed(0),
                [int_elem(context_primitive(7), 3)],
            )],
        )
        .encode();
        assert_eq!(drill_error_class(&pdu, 0), Some((7, 3)));
        assert_eq!(drill_error_class(&[], 0), None);
    }
}
