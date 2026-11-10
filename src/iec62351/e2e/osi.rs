//! OSI environment mapping and Virtual API wrappers for native E2E MMS.
use super::{Edition, Error, Result};
use crate::asn1::{
    self, cons, context_constructed as cc, raw_content, Class, Decoder, Tag, TAG_INTEGER as INT,
    TAG_SEQUENCE as SEQ,
};
pub const CONTEXT_E2E: i64 = 5;
fn external_tag() -> Tag {
    Tag::new(Class::Universal, true, 8)
}
pub fn external(context: i64, pdu: &[u8]) -> Vec<u8> {
    cons(
        external_tag(),
        [
            asn1::int_elem(INT, context),
            raw_content(cc(0), pdu.to_vec()),
        ],
    )
    .encode()
}
pub fn parse_external(bytes: &[u8], expected: i64) -> Result<Vec<u8>> {
    let mut outer = Decoder::new(bytes);
    let mut d = Decoder::new(outer.expect(external_tag())?);
    let context = asn1::decode_int(d.expect(INT)?)?;
    let inner = d.expect(cc(0))?;
    if outer.more() || d.more() || context != expected {
        return Err(Error::hs(1, "invalid EXTERNAL context or trailing data"));
    }
    let mut pdu = Decoder::new(inner);
    pdu.skip()?;
    if pdu.more() {
        return Err(Error::hs(1, "EXTERNAL contains multiple PDUs"));
    }
    Ok(inner.to_vec())
}
pub fn application(edition: Edition, context: i64, pdu: &[u8]) -> Vec<u8> {
    if edition == Edition::First2018 {
        pdu.to_vec()
    } else {
        external(context, pdu)
    }
}
pub fn parse_application(edition: Edition, context: i64, pdu: &[u8]) -> Result<Vec<u8>> {
    if edition == Edition::First2018 {
        let mut d = Decoder::new(pdu);
        d.skip()?;
        if d.more() {
            return Err(Error::hs(1, "application contains multiple PDUs"));
        }
        Ok(pdu.to_vec())
    } else {
        parse_external(pdu, context)
    }
}
pub fn alternative(pdu: &[u8], tag: u32) -> Result<Vec<u8>> {
    let mut d = Decoder::new(pdu);
    let c = d.expect(SEQ)?;
    if d.more() {
        return Err(Error::hs(1, "trailing SecPDU data"));
    }
    Ok(raw_content(cc(tag), c.to_vec()).encode())
}
pub fn parse_alternative(pdu: &[u8]) -> Result<(u32, Vec<u8>)> {
    let mut d = Decoder::new(pdu);
    let (tag, c) = d.read_tlv()?;
    if d.more() || tag.class != Class::ContextSpecific || !tag.constructed {
        return Err(Error::hs(1, "invalid SecPDU alternative"));
    }
    Ok((tag.number, raw_content(SEQ, c.to_vec()).encode()))
}
