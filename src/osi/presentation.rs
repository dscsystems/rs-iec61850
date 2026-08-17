//! The subset of the ISO 8823 / X.226 connection-oriented presentation
//! protocol used by MMS.
//!
//! That is the CP/CPA connection PDUs that negotiate the ACSE and MMS
//! presentation contexts, and the fully-encoded-data wrapping applied to
//! every data-phase PDU.

use crate::asn1::{
    self, application_constructed, context_constructed, context_primitive, cons, int_elem,
    oid_elem, prim, raw_content, Decoder, Element, Oid, TAG_INTEGER, TAG_OID, TAG_SEQUENCE,
    TAG_SET,
};

use super::{Error, Result};

/// Presentation context identifiers used by the MMS profile.
pub const CONTEXT_ACSE: i64 = 1;
pub const CONTEXT_MMS: i64 = 3;

fn oid_acse() -> Oid {
    Oid::new(vec![2, 2, 1, 0, 1]) // acse-as (association control)
}

fn oid_mms() -> Oid {
    Oid::new(vec![1, 0, 9506, 2, 1]) // MMS abstract syntax
}

fn oid_ber() -> Oid {
    Oid::new(vec![2, 1, 1]) // basic encoding transfer syntax
}

/// Default presentation selectors used by common IEC 61850 stacks.
pub const DEFAULT_CALLING_PSEL: &[u8] = &[0x00, 0x00, 0x00, 0x01];
pub const DEFAULT_CALLED_PSEL: &[u8] = &[0x00, 0x00, 0x00, 0x01];

/// Builds a CP (Connect Presentation) PDU wrapping `acse_data` (the ACSE
/// AARQ) in the ACSE presentation context.
pub fn build_cp(calling_psel: &[u8], called_psel: &[u8], acse_data: &[u8]) -> Vec<u8> {
    let mut normal = Element::seq(context_constructed(2)); // normal-mode-parameters [2]
    if !calling_psel.is_empty() {
        normal.push(prim(context_primitive(1), calling_psel.to_vec()));
    }
    if !called_psel.is_empty() {
        normal.push(prim(context_primitive(2), called_psel.to_vec()));
    }
    normal.push(cons(
        context_constructed(4), // context-definition-list [4]
        [
            context_entry(CONTEXT_ACSE, &oid_acse()),
            context_entry(CONTEXT_MMS, &oid_mms()),
        ],
    ));
    normal.push(user_data(CONTEXT_ACSE, acse_data));

    cons(TAG_SET, [mode_selector(), normal]).encode() // CP-type ::= SET
}

/// Builds a CPA (Connect Presentation Accept) PDU accepting the contexts the
/// peer proposed and wrapping `acse_data` (the ACSE AARE).
///
/// The CPA is not a CP with a different name: ISO 8823 gives its normal-mode
/// parameters their own tags, where the responder states one
/// responding-presentation-selector [3] and there is no place for the calling
/// [1] or called [2] selectors a CP carries. A CPA built from the CP's tags
/// decodes as a malformed CPA, and a peer that validates it drops the
/// connection before any user data is exchanged.
///
/// `contexts` is the number of presentation contexts the peer proposed: the
/// result list has one entry per proposal, matched by position, so a fixed
/// pair would misreport any peer that proposes a different number.
pub fn build_cpa(responding_psel: &[u8], contexts: usize, acse_data: &[u8]) -> Vec<u8> {
    let mut normal = Element::seq(context_constructed(2));
    if !responding_psel.is_empty() {
        // responding-presentation-selector [3] IMPLICIT OCTET STRING
        normal.push(prim(context_primitive(3), responding_psel.to_vec()));
    }
    // Default to the ACSE and MMS pair every MMS peer proposes.
    let contexts = if contexts == 0 { 2 } else { contexts };
    let mut results = Element::seq(context_constructed(5));
    for _ in 0..contexts {
        results.push(context_result(0)); // acceptance
    }
    normal.push(results);
    normal.push(user_data(CONTEXT_ACSE, acse_data));

    cons(TAG_SET, [mode_selector(), normal]).encode()
}

/// What a responder needs from a peer's CP: the selector it addressed and how
/// many presentation contexts it proposed.
#[derive(Debug, Clone, Default)]
pub struct Cp {
    pub calling_psel: Vec<u8>,
    pub called_psel: Vec<u8>,
    pub contexts: usize,
    /// The ACSE AARQ.
    pub user_data: Vec<u8>,
}

/// Decodes a CP PDU.
pub fn parse_cp(pdu: &[u8]) -> Result<Cp> {
    let mut cp = Cp::default();
    let mut dec = Decoder::new(pdu);
    let set_content = dec
        .expect(TAG_SET)
        .map_err(|e| Error::Presentation(format!("CP not a SET: {e}")))?;
    let mut inner = Decoder::new(set_content);
    let mut have_user_data = false;
    while inner.more() {
        let (tag, content) = inner.read_tlv()?;
        if tag != context_constructed(2) {
            continue; // not normal-mode-parameters
        }
        let mut nm = Decoder::new(content);
        while nm.more() {
            let (t, c) = nm.read_tlv()?;
            match t {
                x if x == context_primitive(1) => cp.calling_psel = c.to_vec(),
                x if x == context_primitive(2) => cp.called_psel = c.to_vec(),
                // context-definition-list
                x if x == context_constructed(4) => cp.contexts = count_sequences(c),
                // fully-encoded-data
                x if x == application_constructed(1) => {
                    cp.user_data = parse_pdv_list(c)?.1;
                    have_user_data = true;
                }
                _ => {}
            }
        }
    }
    if !have_user_data {
        return Err(Error::Presentation("no user data in CP".into()));
    }
    Ok(cp)
}

/// Counts the SEQUENCE entries in a list.
fn count_sequences(content: &[u8]) -> usize {
    let mut dec = Decoder::new(content);
    let mut n = 0;
    while dec.more() {
        match dec.read_tlv() {
            Ok((tag, _)) if tag == TAG_SEQUENCE => n += 1,
            Ok(_) => {}
            Err(_) => return n,
        }
    }
    n
}

/// Wraps an MMS PDU in fully-encoded-data for the MMS context.
pub fn wrap_data(mms_pdu: &[u8]) -> Vec<u8> {
    user_data(CONTEXT_MMS, mms_pdu).encode()
}

/// Extracts the user data (an MMS PDU) from a data-phase presentation PDU,
/// ignoring the presentation-context-identifier.
pub fn unwrap_data(pdu: &[u8]) -> Result<Vec<u8>> {
    Ok(parse_user_data(pdu)?.1)
}

/// Extracts the ACSE user data from a CP or CPA PDU.
pub fn parse_cp_user_data(pdu: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decoder::new(pdu);
    let set_content = dec
        .expect(TAG_SET)
        .map_err(|e| Error::Presentation(format!("CP not a SET: {e}")))?;
    let mut inner = Decoder::new(set_content);
    while inner.more() {
        let (tag, content) = inner.read_tlv()?;
        if tag != context_constructed(2) {
            continue; // not normal-mode-parameters
        }
        let mut nm = Decoder::new(content);
        while nm.more() {
            let (t, c) = nm.read_tlv()?;
            if t == application_constructed(1) {
                // fully-encoded-data
                return Ok(parse_pdv_list(c)?.1);
            }
        }
    }
    Err(Error::Presentation("no user data in CP".into()))
}

fn mode_selector() -> Element {
    // mode-selector [0] IMPLICIT SET { mode-value [0] INTEGER normal(1) }
    cons(
        context_constructed(0),
        [int_elem(context_primitive(0), 1)],
    )
}

fn context_entry(id: i64, abstract_syntax: &Oid) -> Element {
    cons(
        TAG_SEQUENCE,
        [
            int_elem(TAG_INTEGER, id),
            oid_elem(TAG_OID, abstract_syntax),
            cons(TAG_SEQUENCE, [oid_elem(TAG_OID, &oid_ber())]),
        ],
    )
}

fn context_result(result: i64) -> Element {
    // Result ::= SEQUENCE { result [0] INTEGER, transfer-syntax-name [1] }
    cons(
        TAG_SEQUENCE,
        [
            int_elem(context_primitive(0), result),
            oid_elem(context_primitive(1), &oid_ber()),
        ],
    )
}

/// Builds a fully-encoded-data [APPLICATION 1] wrapping `payload` in the
/// given presentation context via single-ASN1-type.
fn user_data(context_id: i64, payload: &[u8]) -> Element {
    let pdv = cons(
        TAG_SEQUENCE,
        [
            int_elem(TAG_INTEGER, context_id),
            raw_content(context_constructed(0), payload.to_vec()), // single-ASN1-type [0]
        ],
    );
    cons(application_constructed(1), [pdv])
}

fn parse_user_data(pdu: &[u8]) -> Result<(i64, Vec<u8>)> {
    let mut dec = Decoder::new(pdu);
    let (tag, content) = dec.read_tlv()?;
    if tag != application_constructed(1) {
        return Err(Error::Presentation(format!(
            "expected fully-encoded-data, got {tag}"
        )));
    }
    parse_pdv_list(content)
}

fn parse_pdv_list(content: &[u8]) -> Result<(i64, Vec<u8>)> {
    let mut dec = Decoder::new(content);
    let seq = dec.expect(TAG_SEQUENCE)?;
    let mut inner = Decoder::new(seq);
    let mut context_id = 0i64;
    // An optional transfer-syntax-name OID, then the context-identifier
    // INTEGER, then the presentation-data-values.
    while inner.more() {
        let (tag, c) = inner.read_tlv()?;
        if tag == TAG_INTEGER {
            context_id = asn1::decode_int(c)?;
        } else if tag == context_constructed(0) {
            // single-ASN1-type
            return Ok((context_id, c.to_vec()));
        } else if tag == context_primitive(1) {
            // octet-aligned
            return Ok((context_id, c.to_vec()));
        }
    }
    Err(Error::Presentation("no data values in PDV-list".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::Tag;

    fn normal_mode_params(pdu: &[u8]) -> Vec<u8> {
        let mut dec = Decoder::new(pdu);
        let set = dec.expect(TAG_SET).expect("CP is a SET");
        let mut inner = Decoder::new(set);
        while inner.more() {
            let (tag, c) = inner.read_tlv().unwrap();
            if tag == context_constructed(2) {
                return c.to_vec();
            }
        }
        panic!("no normal-mode-parameters");
    }

    fn tags_of(content: &[u8]) -> Vec<Tag> {
        let mut dec = Decoder::new(content);
        let mut tags = Vec::new();
        while dec.more() {
            let (tag, _) = dec.read_tlv().unwrap();
            tags.push(tag);
        }
        tags
    }

    /// The CPA has its own parameter tags. A responder that answers with the
    /// CP's calling [1] and called [2] selectors emits a CPA that no
    /// conforming decoder accepts, and peers that validate it drop the
    /// connection before any user data is exchanged. Real devices answer with
    /// responding [3] alone.
    #[test]
    fn cpa_uses_the_responding_selector_only() {
        let cpa = build_cpa(&[0x00, 0x00, 0x00, 0x01], 2, &[0x61, 0x00]);
        let tags = tags_of(&normal_mode_params(&cpa));

        assert!(
            !tags.contains(&context_primitive(1)),
            "CPA carries a calling-presentation-selector, which exists only in a CP"
        );
        assert!(
            !tags.contains(&context_primitive(2)),
            "CPA carries a called-presentation-selector, which exists only in a CP"
        );
        assert!(
            tags.contains(&context_primitive(3)),
            "CPA has no responding-presentation-selector [3]"
        );
        assert!(
            tags.contains(&context_constructed(5)),
            "CPA has no presentation-context-definition-result-list [5]"
        );
    }

    /// The result list is matched to the proposal by position, so its length
    /// has to follow what the peer actually proposed.
    #[test]
    fn cpa_results_match_the_number_of_proposed_contexts() {
        for contexts in [1usize, 2, 3] {
            let cpa = build_cpa(&[], contexts, &[0x61, 0x00]);
            let params = normal_mode_params(&cpa);
            let mut dec = Decoder::new(&params);
            let mut found = None;
            while dec.more() {
                let (tag, c) = dec.read_tlv().unwrap();
                if tag == context_constructed(5) {
                    found = Some(count_sequences(c));
                }
            }
            assert_eq!(
                found,
                Some(contexts),
                "{contexts} proposed contexts produced {found:?} results"
            );
        }
    }

    /// The CP a real client sends must yield the selector it addressed and
    /// the number of contexts it proposed. This is a CP captured from a live
    /// IEC 61850 client.
    #[test]
    fn parses_a_cp_from_a_real_client() {
        let hex = concat!(
            "31819da003800101a28195810400000001820400000001a423300f020101060452",
            "0100013004060251013010020103060528ca2202013004060251016162306002",
            "0101a05b6059a107060528ca220203a20706052987670101a30302010ca6060604",
            "29018767a70302010cbe33283106025101020103a028a826800300fde881010a82",
            "010a830105a416800101810305f100820c03ee1c00000408000079ef18",
        );
        let raw = decode_hex(hex);
        let cp = parse_cp(&raw).expect("a live client's CP must parse");
        assert_eq!(
            cp.called_psel,
            [0x00, 0x00, 0x00, 0x01],
            "called PSel mismatch"
        );
        assert_eq!(cp.contexts, 2, "contexts should be the ACSE and MMS pair");
        assert_eq!(
            cp.user_data.first(),
            Some(&0x60),
            "user data is not an AARQ: {:02x?}",
            cp.user_data
        );
    }

    #[test]
    fn cp_round_trips_through_its_own_parser() {
        let cp = build_cp(DEFAULT_CALLING_PSEL, DEFAULT_CALLED_PSEL, &[0x60, 0x02, 0x01, 0x00]);
        let parsed = parse_cp(&cp).unwrap();
        assert_eq!(parsed.calling_psel, DEFAULT_CALLING_PSEL);
        assert_eq!(parsed.called_psel, DEFAULT_CALLED_PSEL);
        assert_eq!(parsed.contexts, 2);
        assert_eq!(parsed.user_data, [0x60, 0x02, 0x01, 0x00]);
        assert_eq!(parse_cp_user_data(&cp).unwrap(), parsed.user_data);
    }

    #[test]
    fn data_phase_wrapping_round_trips() {
        let mms = [0xa0u8, 0x03, 0x02, 0x01, 0x2a];
        let wrapped = wrap_data(&mms);
        assert_eq!(unwrap_data(&wrapped).unwrap(), mms);
        // The MMS context identifier must be the one the CP defined.
        assert_eq!(parse_user_data(&wrapped).unwrap().0, CONTEXT_MMS);
    }

    #[test]
    fn a_cp_without_user_data_is_rejected() {
        let bare = cons(TAG_SET, [mode_selector()]).encode();
        assert!(parse_cp(&bare).is_err());
        assert!(parse_cp(&[]).is_err());
        assert!(unwrap_data(&[0x30, 0x00]).is_err());
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
