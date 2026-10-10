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
/// One presentation context a peer proposed: the identifier it chose for it,
/// the abstract syntax it means, and the transfer syntax it proposes for that
/// syntax.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    pub id: i64,
    pub abstract_syntax: Option<Oid>,
    pub transfer_syntax: Option<Oid>,
}

impl Context {
    /// Reports whether the context carries ACSE. The identifier does not say
    /// so: a peer is free to number its contexts as it likes, and only the
    /// abstract syntax decides what each one is for.
    pub fn is_acse(&self) -> bool {
        self.abstract_syntax.as_ref() == Some(&oid_acse())
    }

    /// Reports whether the context carries MMS.
    pub fn is_mms(&self) -> bool {
        self.abstract_syntax.as_ref() == Some(&oid_mms())
    }

    /// Reports whether the context proposes the basic encoding rules, the
    /// only transfer syntax this crate implements.
    pub fn ber(&self) -> bool {
        self.transfer_syntax.as_ref() == Some(&oid_ber())
    }

    /// Reports whether this crate can serve the context.
    pub fn acceptable(&self) -> bool {
        (self.is_acse() || self.is_mms()) && self.ber()
    }
}

/// Which of the contexts a peer proposed this crate accepted, under the
/// identifiers the peer gave them.
///
/// A presentation context identifier is chosen by the proposer, not agreed
/// as a constant: the ACSE and MMS contexts are conventionally numbered 1 and
/// 3, but that is a convention of the stacks that use it. A responder that
/// assumes 3 and a proposer that chose 2 agree on nothing, and every
/// subsequent PDU is mis-tagged, which a client sees as silence rather than as
/// an error.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Negotiated {
    /// The identifier the peer assigned to the ACSE context, zero when it
    /// proposed none.
    pub acse: i64,
    /// The identifier the peer assigned to the MMS context, zero when it
    /// proposed none.
    pub mms: i64,
}

impl Negotiated {
    pub fn has_acse(&self) -> bool {
        self.acse != 0
    }

    pub fn has_mms(&self) -> bool {
        self.mms != 0
    }
}

/// Decides which of the proposed contexts this crate accepts, without
/// building anything. A responder needs the outcome before the CPA: the AARE
/// inside it names the MMS context by the identifier the peer chose.
pub fn negotiate(proposed: &[Context]) -> Negotiated {
    let mut neg = Negotiated::default();
    for c in proposed {
        if !c.acceptable() {
            continue;
        }
        if c.is_acse() {
            neg.acse = c.id;
        } else if c.is_mms() {
            neg.mms = c.id;
        }
    }
    neg
}

/// The per-context outcome in a CPA's result list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextResult {
    Acceptance = 0,
    /// The responder cannot serve the context.
    ProviderRejection = 1,
    /// The abstract syntax is unknown.
    AbstractSyntaxNotSupported = 2,
}

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

/// Builds a CPA (Connect Presentation Accept) PDU wrapping `acse_data` (the
/// ACSE AARE), accepting the contexts this crate can serve and rejecting the
/// rest.
///
/// The result list has one entry per proposal, in proposal order, which is
/// how the peer maps it back to its own contexts.
///
/// The CPA is not a CP with a different name: ISO 8823 gives its normal-mode
/// parameters their own tags, where the responder states one
/// responding-presentation-selector [3] rather than echoing the calling and
/// called ones [1] and [2]. A CPA built with the CP's tags decodes as a
/// malformed CPA, and a peer that validates it drops the connection before
/// any user data is exchanged.
pub fn build_cpa(responding_psel: &[u8], proposed: &[Context], acse_data: &[u8]) -> (Negotiated, Vec<u8>) {
    let neg = negotiate(proposed);
    let mut normal = Element::seq(context_constructed(2));
    if !responding_psel.is_empty() {
        // responding-presentation-selector [3] IMPLICIT OCTET STRING
        normal.push(prim(context_primitive(3), responding_psel.to_vec()));
    }
    normal.push(result_list(proposed));
    normal.push(user_data(acse_context_or_default(neg), acse_data));
    (neg, cons(TAG_SET, [mode_selector(), normal]).encode())
}

/// The context that carries the AARE. A peer that proposed no ACSE context
/// cannot receive it; the CPA is then built with the conventional identifier
/// and the peer will reject it.
fn acse_context_or_default(neg: Negotiated) -> i64 {
    if neg.acse == 0 {
        CONTEXT_ACSE
    } else {
        neg.acse
    }
}

/// The presentation-context-definition-result-list [5]: one result per
/// proposed context, in order.
fn result_list(proposed: &[Context]) -> Element {
    let mut results = Element::seq(context_constructed(5));
    for c in proposed {
        results.push(context_result(if c.acceptable() {
            ContextResult::Acceptance
        } else {
            ContextResult::ProviderRejection
        }));
    }
    results
}

/// Builds a CPR (Connect Presentation Reject) PDU for a connection the
/// presentation user refuses, an association the ACSE rejects, carrying
/// `acse_data` (the rejecting AARE) in the ACSE context.
///
/// Its normal-mode parameters are a SEQUENCE (ISO 8823), with the responding
/// selector and the per-context results as in a CPA.
pub fn build_cpr(responding_psel: &[u8], proposed: &[Context], acse_data: &[u8]) -> Vec<u8> {
    let neg = negotiate(proposed);
    let mut seq = Element::seq(TAG_SEQUENCE);
    if !responding_psel.is_empty() {
        seq.push(prim(context_primitive(3), responding_psel.to_vec()));
    }
    seq.push(result_list(proposed));
    seq.push(user_data(acse_context_or_default(neg), acse_data));
    seq.encode()
}

/// Extracts the ACSE user data (the AARE) from a CPR PDU.
pub fn parse_cpr_user_data(pdu: &[u8]) -> Result<Vec<u8>> {
    let seq = Decoder::new(pdu)
        .expect(TAG_SEQUENCE)
        .map_err(|e| Error::Presentation(format!("CPR not a SEQUENCE: {e}")))?;
    find_fully_encoded(seq)
}

/// Builds an ARU (abnormal release by the user) PDU carrying `abrt` (the ACSE
/// ABRT) in the ACSE presentation context: its normal-mode parameters,
/// `[0] IMPLICIT SEQUENCE`, hold only the user data.
pub fn wrap_abort(acse_context_id: i64, abrt: &[u8]) -> Vec<u8> {
    let id = if acse_context_id == 0 {
        CONTEXT_ACSE
    } else {
        acse_context_id
    };
    cons(context_constructed(0), [user_data(id, abrt)]).encode()
}

/// Extracts the user data (the ACSE ABRT) from an ARU PDU. A SEQUENCE in
/// place of the `[0]` tag is accepted too.
pub fn unwrap_abort(pdu: &[u8]) -> Result<Vec<u8>> {
    let (tag, content) = Decoder::new(pdu).read_tlv()?;
    if tag != context_constructed(0) && tag != TAG_SEQUENCE {
        return Err(Error::Presentation(format!("ARU of tag {tag}")));
    }
    find_fully_encoded(content)
}

/// Returns the data of the first fully-encoded-data element among a PDU's
/// parameters.
fn find_fully_encoded(content: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decoder::new(content);
    while dec.more() {
        let (t, c) = dec.read_tlv()?;
        if t == application_constructed(1) {
            return Ok(parse_pdv_list(c)?.1);
        }
    }
    Err(Error::Presentation("no user data".into()))
}

/// What a responder needs from a peer's CP: the selector it addressed and how
/// many presentation contexts it proposed.
#[derive(Debug, Clone, Default)]
pub struct Cp {
    pub calling_psel: Vec<u8>,
    pub called_psel: Vec<u8>,
    /// The presentation contexts the peer proposed.
    pub contexts: Vec<Context>,
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
                x if x == context_constructed(4) => cp.contexts = parse_context_list(c),
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

/// Decodes a context-definition-list.
///
/// Each entry is `PresentationContextDefinition ::= SEQUENCE {
/// presentation-context-identifier INTEGER, abstract-syntax,
/// transfer-syntax-name }`, and the last may instead be the abbreviated form
/// without a transfer syntax.
fn parse_context_list(content: &[u8]) -> Vec<Context> {
    let mut dec = Decoder::new(content);
    let mut out = Vec::new();
    while dec.more() {
        let Ok((tag, body)) = dec.read_tlv() else {
            return out;
        };
        if tag != TAG_SEQUENCE {
            // An entry that does not decode ends the list; the caller's
            // acceptance check reports the shortfall.
            return out;
        }
        let mut entry = Decoder::new(body);
        let mut c = Context::default();
        while entry.more() {
            let Ok((t, v)) = entry.read_tlv() else {
                return out;
            };
            if t == TAG_INTEGER {
                if let Ok(n) = asn1::decode_int(v) {
                    c.id = n;
                }
            } else if t == TAG_OID {
                // The abbreviated form names the transfer syntax directly.
                let Ok(oid) = asn1::decode_oid(v) else {
                    return out;
                };
                if c.abstract_syntax.is_none() {
                    c.abstract_syntax = Some(oid);
                } else {
                    c.transfer_syntax = Some(oid);
                }
            } else if t == TAG_SEQUENCE {
                // transfer-syntax-name, a CHOICE of OIDs.
                let mut ts = Decoder::new(v);
                while ts.more() {
                    let Ok((ot, ov)) = ts.read_tlv() else {
                        break;
                    };
                    if ot == TAG_OID {
                        if let Ok(oid) = asn1::decode_oid(ov) {
                            c.transfer_syntax = Some(oid);
                        }
                    }
                }
            }
        }
        out.push(c);
    }
    out
}

/// Wraps an MMS PDU in fully-encoded-data for the MMS presentation context.
///
/// `context_id` is the identifier the peer assigned to it, which is not
/// necessarily [`CONTEXT_MMS`]: the identifier is the proposer's choice. Zero
/// uses the conventional one.
pub fn wrap_data(context_id: i64, mms_pdu: &[u8]) -> Vec<u8> {
    let id = if context_id == 0 { CONTEXT_MMS } else { context_id };
    user_data(id, mms_pdu).encode()
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

/// Builds one entry of a CPA result list: `Result ::= SEQUENCE { result [0]
/// INTEGER, transfer-syntax-name [1] }`. An accepted context names the
/// transfer syntax it is accepted with; a rejected one carries only the
/// reason.
fn context_result(result: ContextResult) -> Element {
    let mut e = cons(TAG_SEQUENCE, [int_elem(context_primitive(0), result as i64)]);
    if result == ContextResult::Acceptance {
        e.push(oid_elem(context_primitive(1), &oid_ber()));
    }
    e
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
    fn default_contexts() -> Vec<Context> {
        vec![ctx(CONTEXT_ACSE, oid_acse(), oid_ber()), ctx(CONTEXT_MMS, oid_mms(), oid_ber())]
    }

    fn ctx(id: i64, abstract_syntax: Oid, transfer_syntax: Oid) -> Context {
        Context {
            id,
            abstract_syntax: Some(abstract_syntax),
            transfer_syntax: Some(transfer_syntax),
        }
    }

    fn count_entries(content: &[u8]) -> usize {
        tags_of(content).iter().filter(|t| **t == TAG_SEQUENCE).count()
    }

    /// Decodes a CPA's result list into (result, names a transfer syntax).
    fn result_list(cpa: &[u8]) -> Vec<(i64, bool)> {
        let params = normal_mode_params(cpa);
        let mut dec = Decoder::new(&params);
        while dec.more() {
            let (tag, content) = dec.read_tlv().unwrap();
            if tag != context_constructed(5) {
                continue;
            }
            let mut out = Vec::new();
            let mut entries = Decoder::new(content);
            while entries.more() {
                let (_, body) = entries.read_tlv().unwrap();
                let mut inner = Decoder::new(body);
                let mut e = (-1, false);
                while inner.more() {
                    let (rt, rc) = inner.read_tlv().unwrap();
                    if rt == context_primitive(0) {
                        e.0 = asn1::decode_int(rc).unwrap();
                    } else if rt == context_primitive(1) {
                        e.1 = true;
                    }
                }
                out.push(e);
            }
            return out;
        }
        panic!("no result list in the CPA");
    }

    fn set_user_data(cpa: &[u8]) -> Vec<u8> {
        let params = normal_mode_params(cpa);
        let mut dec = Decoder::new(&params);
        while dec.more() {
            let (tag, content) = dec.read_tlv().unwrap();
            if tag == application_constructed(1) {
                return content.to_vec();
            }
        }
        panic!("no user data in the CPA");
    }

    #[test]
    fn cpa_uses_the_responding_selector_only() {
        let (_, cpa) = build_cpa(&[0x00, 0x00, 0x00, 0x01], &default_contexts(), &[0x61, 0x00]);
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
    /// The result list is matched to the proposal by position, so its length
    /// has to follow what the peer actually proposed.
    #[test]
    fn cpa_results_match_the_proposed_contexts() {
        for n in [1usize, 2, 3] {
            let mut contexts = default_contexts();
            contexts.push(ctx(7, Oid::new(vec![1, 2, 3, 4]), oid_ber()));
            contexts.truncate(n);
            let (_, cpa) = build_cpa(&[], &contexts, &[0x61, 0x00]);
            let params = normal_mode_params(&cpa);
            let mut dec = Decoder::new(&params);
            let mut found = None;
            while dec.more() {
                let (tag, c) = dec.read_tlv().unwrap();
                if tag == context_constructed(5) {
                    found = Some(count_entries(c));
                }
            }
            assert_eq!(found, Some(n), "{n} proposed contexts produced {found:?} results");
        }
    }

    /// The presentation-context-identifier is the proposer's choice, so a
    /// responder that assumes the conventional 3 and a peer that chose
    /// something else agree on nothing.
    #[test]
    fn the_negotiated_context_is_the_proposers_choice() {
        let cases = [
            (default_contexts(), CONTEXT_ACSE, CONTEXT_MMS),
            (vec![ctx(1, oid_acse(), oid_ber()), ctx(2, oid_mms(), oid_ber())], 1, 2),
            (vec![ctx(2, oid_mms(), oid_ber()), ctx(1, oid_acse(), oid_ber())], 1, 2),
            (vec![ctx(9, oid_mms(), oid_ber()), ctx(4, oid_acse(), oid_ber())], 4, 9),
        ];
        for (contexts, acse, mms) in cases {
            let (neg, _) = build_cpa(&[], &contexts, &[0x61, 0x00]);
            assert_eq!((neg.acse, neg.mms), (acse, mms), "{contexts:?}");
            assert!(neg.has_acse() && neg.has_mms());
        }
    }

    /// A context this crate cannot serve is rejected rather than accepted.
    #[test]
    fn an_unacceptable_context_is_rejected() {
        let contexts = vec![
            ctx(1, oid_acse(), oid_ber()),
            ctx(2, Oid::new(vec![1, 2, 3]), oid_ber()),
            ctx(3, oid_mms(), Oid::new(vec![2, 1, 2])),
            ctx(4, oid_mms(), oid_ber()),
        ];
        let (neg, cpa) = build_cpa(&[], &contexts, &[0x61, 0x00]);
        assert_eq!(neg.mms, 4);
        let results = result_list(&cpa);
        assert_eq!(results, [(0, true), (1, false), (1, false), (0, true)]);
    }

    /// A peer that proposes no MMS context gets an answer that says so.
    #[test]
    fn no_mms_context() {
        let (neg, _) = build_cpa(&[], &[ctx(1, oid_acse(), oid_ber())], &[0x61, 0x00]);
        assert!(!neg.has_mms() && neg.has_acse());
    }

    /// The CPA carries the AARE in the ACSE context the peer proposed.
    #[test]
    fn the_cpa_user_data_uses_the_negotiated_acse_context() {
        for id in [1, 2, 5, 17] {
            let contexts = vec![ctx(id, oid_acse(), oid_ber()), ctx(id + 1, oid_mms(), oid_ber())];
            let (_, cpa) = build_cpa(&[], &contexts, &[0x61, 0x2a]);
            let (got, data) = parse_pdv_list(&set_user_data(&cpa)).unwrap();
            assert_eq!(got, id);
            assert_eq!(data.first(), Some(&0x61));
        }
    }

    /// Data PDUs go into the negotiated MMS context.
    #[test]
    fn wrap_data_uses_the_negotiated_context() {
        for id in [0, CONTEXT_MMS, 2, 9] {
            let pdu = wrap_data(id, &[0xa0, 0x01, 0x02]);
            let (got, data) = parse_user_data(&pdu).unwrap();
            assert_eq!(got, if id == 0 { CONTEXT_MMS } else { id });
            assert_eq!(data, [0xa0, 0x01, 0x02]);
        }
    }

    /// A CPR and an ARU carry their ACSE APDU in the ACSE context, and parse
    /// back.
    #[test]
    fn cpr_and_aru_round_trip() {
        let cpr = build_cpr(&[0, 0, 0, 1], &default_contexts(), &[0x61, 0x00]);
        assert_eq!(parse_cpr_user_data(&cpr).unwrap(), [0x61, 0x00]);
        let aru = wrap_abort(0, &[0x64, 0x03, 0x80, 0x01, 0x00]);
        assert_eq!(unwrap_abort(&aru).unwrap(), [0x64, 0x03, 0x80, 0x01, 0x00]);
        assert!(unwrap_abort(&[0x31, 0x00]).is_err());
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
        assert_eq!(cp.contexts.len(), 2, "contexts should be the ACSE and MMS pair");
        let neg = negotiate(&cp.contexts);
        assert_eq!((neg.acse, neg.mms), (1, 3));
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
        assert_eq!(parsed.contexts, default_contexts());
        let (neg, cpa) = build_cpa(&parsed.called_psel, &parsed.contexts, &[0x61, 0x00]);
        assert_eq!((neg.acse, neg.mms), (CONTEXT_ACSE, CONTEXT_MMS));
        assert!(normal_mode_params(&cpa).windows(4).any(|w| w == DEFAULT_CALLED_PSEL));
        assert_eq!(parsed.user_data, [0x60, 0x02, 0x01, 0x00]);
        assert_eq!(parse_cp_user_data(&cp).unwrap(), parsed.user_data);
    }

    #[test]
    fn data_phase_wrapping_round_trips() {
        let mms = [0xa0u8, 0x03, 0x02, 0x01, 0x2a];
        let wrapped = wrap_data(CONTEXT_MMS, &mms);
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
