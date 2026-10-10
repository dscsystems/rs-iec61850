//! The subset of ISO 8650 / X.227 ACSE used by MMS.
//!
//! That is the AARQ/AARE association-control APDUs that carry the MMS
//! Initiate request/response as user information, plus the RLRQ/RLRE release
//! APDUs. Optional ACSE password authentication is supported.

use crate::asn1::{
    application_constructed, cons, context_constructed, context_primitive, decode_int, decode_oid,
    int_elem, oid_elem, prim, raw_content, bit_string_elem, BitString, Class, Decoder, Element,
    Oid, Tag, TAG_INTEGER, TAG_OID,
};

use super::{Error, Result};

/// APDU tags (application class).
fn tag_aarq() -> Tag {
    application_constructed(0) // 0x60
}
fn tag_aare() -> Tag {
    application_constructed(1) // 0x61
}
fn tag_rlrq() -> Tag {
    application_constructed(2) // 0x62
}
fn tag_rlre() -> Tag {
    application_constructed(3) // 0x63
}
fn tag_abrt() -> Tag {
    application_constructed(4) // 0x64
}

/// `[UNIVERSAL 8] EXTERNAL`, which carries the MMS PDU as user information.
fn tag_external() -> Tag {
    Tag::new(Class::Universal, true, 8)
}

/// The MMS application context name OID.
fn oid_mms_context() -> Oid {
    Oid::new(vec![1, 0, 9506, 2, 3])
}

/// The ACSI application context name, the alternative IEC 61850-7-2 defines
/// for the association. Some servers accept only this one; most, including
/// the reference C stack, accept the plain MMS context.
fn oid_acsi_context() -> Oid {
    Oid::new(vec![1, 0, 61850, 4, 0, 2])
}

/// Names the application-context-name an AARQ proposes.
///
/// The default is the plain MMS context, which interoperates with the widest
/// set of peers. A responder does not choose one: an AARE echoes the context
/// the peer proposed ([`aare_for`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ApplicationContext {
    /// The plain ISO 9506-2 MMS context, 1.0.9506.2.3.
    #[default]
    Mms,
    /// The IEC 61850 ACSI context, 1.0.61850.4.0.2.
    Acsi,
}

impl ApplicationContext {
    /// Returns the object identifier the context is named by.
    pub fn oid(self) -> Oid {
        match self {
            ApplicationContext::Mms => oid_mms_context(),
            ApplicationContext::Acsi => oid_acsi_context(),
        }
    }
}

/// Reports whether `oid` is one of the two contexts this crate serves.
fn known_application_context(oid: Option<&Oid>) -> bool {
    oid.is_some_and(|o| *o == oid_mms_context() || *o == oid_acsi_context())
}

/// The ACSE password authentication mechanism, 2.2.3.1 (ISO/IEC 8650-1,
/// IEC 61850-8-1 clause 21). libiec61850 drops an association naming any
/// other mechanism.
pub fn password_mechanism() -> Oid {
    Oid::new(vec![2, 2, 3, 1])
}

/// Associate-source-diagnostic values of the acse-service-user (ISO 8650).
pub const DIAG_NO_REASON: i64 = 1;
pub const DIAG_AUTH_MECHANISM_NOT_RECOGNISED: i64 = 11;
pub const DIAG_AUTHENTICATION_FAILURE: i64 = 13;
pub const DIAG_AUTHENTICATION_REQUIRED: i64 = 14;

/// ABRT source values (ISO 8650).
pub const ABORT_SOURCE_USER: i64 = 0;
pub const ABORT_SOURCE_PROVIDER: i64 = 1;

/// The presentation-context-identifier used for MMS in the EXTERNAL indirect
/// reference.
pub const PRESENTATION_CONTEXT_MMS: i64 = 3;

/// The application-entity identity carried in an AARQ or AARE: the AP-title
/// and AE-qualifier, plus the invocation identifiers when the peer supplies
/// them.
///
/// Clients configured with a device's AP-title check the responding identity
/// in the AARE before they will use the association, so a server standing in
/// for a device has to answer with the device's identity rather than omit it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// ap-title-form2 (OBJECT IDENTIFIER).
    pub ap_title: Option<Oid>,
    pub ae_qualifier: Option<i32>,
    pub ap_invocation_id: Option<i32>,
    pub ae_invocation_id: Option<i32>,
}

impl Identity {
    /// Reports whether the identity carries nothing to encode.
    pub fn is_empty(&self) -> bool {
        self.ap_title.is_none()
            && self.ae_qualifier.is_none()
            && self.ap_invocation_id.is_none()
            && self.ae_invocation_id.is_none()
    }
}

/// Builds an A-ASSOCIATE request APDU carrying `mms_initiate` (an MMS
/// InitiateRequestPDU) as user information.
///
/// If `password` is non-empty an ACSE authentication-value (mechanism-name
/// password) is included.
pub fn aarq(mms_initiate: &[u8], password: &str) -> Vec<u8> {
    aarq_with_identity(
        mms_initiate,
        password,
        &Identity::default(),
        &Identity::default(),
    )
}

/// [`aarq`] addressing a called AE and claiming a calling one.
///
/// Empty identities produce byte-for-byte the same APDU [`aarq`] builds.
pub fn aarq_with_identity(
    mms_initiate: &[u8],
    password: &str,
    called: &Identity,
    calling: &Identity,
) -> Vec<u8> {
    aarq_for(mms_initiate, password, called, calling, ApplicationContext::Mms)
}

/// [`aarq_with_identity`] proposing the given application context.
pub fn aarq_for(
    mms_initiate: &[u8],
    password: &str,
    called: &Identity,
    calling: &Identity,
    app_ctx: ApplicationContext,
) -> Vec<u8> {
    let mut seq = cons(
        tag_aarq(),
        [
            // application-context-name [1] EXPLICIT OID
            cons(context_constructed(1), [oid_elem(TAG_OID, &app_ctx.oid())]),
        ],
    );
    // called-AP-title [2]..[5], then calling-AP-title [6]..[9].
    add_identity(&mut seq, 2, called);
    add_identity(&mut seq, 6, calling);
    if !password.is_empty() {
        // sender-acse-requirements [10] BIT STRING { authentication(0) }
        let mut bs = BitString::new(1);
        bs.set_bit(0, true);
        seq.push(bit_string_elem(context_primitive(10), &bs));
        // mechanism-name [11] OID: password-1, {joint-iso-itu-t(2)
        // association-control(2) authentication-mechanism(3) password-1(1)}.
        seq.push(oid_elem(context_primitive(11), &password_mechanism()));
        // calling-authentication-value [12] EXPLICIT AuthenticationValue
        //   charstring [0] IMPLICIT GraphicString
        seq.push(cons(
            context_constructed(12),
            [prim(context_primitive(0), password.as_bytes().to_vec())],
        ));
    }
    // user-information [30] IMPLICIT SEQUENCE OF EXTERNAL
    seq.push(cons(
        context_constructed(30),
        [external(mms_initiate, PRESENTATION_CONTEXT_MMS)],
    ));
    seq.encode()
}

/// Appends the identity fields to an AARQ or AARE, starting at the given
/// context tag number.
///
/// The four fields are consecutive in both APDUs (called-AP-title is [2] and
/// responding-AP-title is [4]), so one encoder serves both by being told
/// where its block begins.
fn add_identity(seq: &mut Element, base: u32, id: &Identity) {
    if let Some(oid) = &id.ap_title {
        // AP-title ::= CHOICE { ap-title-form1, ap-title-form2 OBJECT IDENTIFIER }
        seq.push(cons(context_constructed(base), [oid_elem(TAG_OID, oid)]));
    }
    if let Some(q) = id.ae_qualifier {
        // AE-qualifier ::= CHOICE { ..., ae-qualifier-form2 INTEGER }
        seq.push(cons(
            context_constructed(base + 1),
            [int_elem(TAG_INTEGER, i64::from(q))],
        ));
    }
    if let Some(v) = id.ap_invocation_id {
        seq.push(cons(
            context_constructed(base + 2),
            [int_elem(TAG_INTEGER, i64::from(v))],
        ));
    }
    if let Some(v) = id.ae_invocation_id {
        seq.push(cons(
            context_constructed(base + 3),
            [int_elem(TAG_INTEGER, i64::from(v))],
        ));
    }
}

/// Reads the identity block beginning at the given context tag number,
/// ignoring tags outside it. Returns whether the tag belonged to the block.
fn parse_identity(tag: Tag, content: &[u8], base: u32, id: &mut Identity) -> bool {
    if tag == context_constructed(base) {
        if let Some(oid) = first_oid(content) {
            id.ap_title = Some(oid);
        }
    } else if tag == context_constructed(base + 1) {
        if let Ok(n) = decode_int(first_int(content)) {
            id.ae_qualifier = Some(n as i32);
        }
    } else if tag == context_constructed(base + 2) {
        if let Ok(n) = decode_int(first_int(content)) {
            id.ap_invocation_id = Some(n as i32);
        }
    } else if tag == context_constructed(base + 3) {
        if let Ok(n) = decode_int(first_int(content)) {
            id.ae_invocation_id = Some(n as i32);
        }
    } else {
        return false;
    }
    true
}

/// Builds an A-ASSOCIATE response APDU accepting the association and carrying
/// `mms_initiate_resp` as user information.
pub fn aare(mms_initiate_resp: &[u8]) -> Vec<u8> {
    aare_with_identity(mms_initiate_resp, &Identity::default())
}

/// [`aare`] carrying a responding AP-title and AE-qualifier.
///
/// An empty identity produces byte-for-byte the bare acceptance [`aare`]
/// builds, so a server with nothing to claim is unchanged.
pub fn aare_with_identity(mms_initiate_resp: &[u8], responding: &Identity) -> Vec<u8> {
    aare_for(mms_initiate_resp, responding, None, 0)
}

/// [`aare_with_identity`] answering a specific AARQ.
///
/// `proposed` is the application-context-name the peer proposed, which the
/// AARE echoes when it is one this crate serves: answering an ACSI proposal
/// with the MMS context, or the reverse, is a mismatch a strict peer refuses.
/// `None` or an unknown context answers with the plain MMS one.
///
/// `mms_context_id` is the presentation-context-identifier the peer gave the
/// MMS abstract syntax, which the user information's EXTERNAL must carry as
/// its indirect-reference: the identifier is the proposer's choice, not a
/// constant. Zero uses the conventional [`PRESENTATION_CONTEXT_MMS`].
pub fn aare_for(
    mms_initiate_resp: &[u8],
    responding: &Identity,
    proposed: Option<&Oid>,
    mms_context_id: i64,
) -> Vec<u8> {
    let ctx = match proposed {
        Some(o) if known_application_context(Some(o)) => o.clone(),
        _ => oid_mms_context(),
    };
    let mms_context_id = if mms_context_id == 0 {
        PRESENTATION_CONTEXT_MMS
    } else {
        mms_context_id
    };
    let mut seq = cons(
        tag_aare(),
        [
            cons(context_constructed(1), [oid_elem(TAG_OID, &ctx)]),
            // result [2] EXPLICIT INTEGER accepted(0)
            cons(context_constructed(2), [int_elem(TAG_INTEGER, 0)]),
            // result-source-diagnostic [3] EXPLICIT CHOICE
            //   acse-service-user [1] INTEGER 0
            cons(
                context_constructed(3),
                [cons(context_constructed(1), [int_elem(TAG_INTEGER, 0)])],
            ),
        ],
    );
    // responding-AP-title [4] .. responding-AE-invocation-identifier [7],
    // which the ASN.1 places between the diagnostic and the user information.
    add_identity(&mut seq, 4, responding);
    seq.push(cons(
        context_constructed(30),
        [external(mms_initiate_resp, mms_context_id)],
    ));
    seq.encode()
}

/// Builds a rejecting AARE with the given service-user diagnostic.
pub fn aare_reject(diagnostic: i64) -> Vec<u8> {
    aare_reject_for(None, diagnostic)
}

/// [`aare_reject`] answering with the application context the peer proposed
/// (the MMS context when `None` or unknown), as a responder must echo it.
pub fn aare_reject_for(proposed: Option<&Oid>, diagnostic: i64) -> Vec<u8> {
    let ctx = match proposed {
        Some(o) if known_application_context(Some(o)) => o.clone(),
        _ => oid_mms_context(),
    };
    cons(
        tag_aare(),
        [
            cons(context_constructed(1), [oid_elem(TAG_OID, &ctx)]),
            // rejected-permanent(1)
            cons(context_constructed(2), [int_elem(TAG_INTEGER, 1)]),
            cons(
                context_constructed(3),
                [cons(
                    context_constructed(1),
                    [int_elem(TAG_INTEGER, diagnostic)],
                )],
            ),
        ],
    )
    .encode()
}

/// Builds an A-RELEASE request APDU.
pub fn rlrq() -> Vec<u8> {
    cons(tag_rlrq(), []).encode()
}

/// Builds an A-RELEASE response APDU.
pub fn rlre() -> Vec<u8> {
    cons(tag_rlre(), []).encode()
}

/// Wraps a pre-encoded MMS PDU as an ACSE EXTERNAL using the MMS presentation
/// context indirect reference and single-ASN1-type encoding.
/// Builds an A-ABORT APDU: `ABRT-apdu ::= [APPLICATION 4] IMPLICIT SEQUENCE {
/// abort-source [0] IMPLICIT INTEGER }`.
pub fn abrt(source: i64) -> Vec<u8> {
    cons(tag_abrt(), [int_elem(context_primitive(0), source)]).encode()
}

/// Returns the abort source of an A-ABORT APDU.
pub fn parse_abrt(apdu: &[u8]) -> Result<i64> {
    let content = Decoder::new(apdu)
        .expect(tag_abrt())
        .map_err(|e| Error::Acse(format!("not an ABRT: {e}")))?;
    match Decoder::new(content).optional(context_primitive(0))? {
        Some(src) => Ok(decode_int(src)?),
        None => Ok(ABORT_SOURCE_USER),
    }
}

fn external(mms_pdu: &[u8], context_id: i64) -> Element {
    cons(
        tag_external(),
        [
            int_elem(TAG_INTEGER, context_id), // indirect-reference
            raw_content(context_constructed(0), mms_pdu.to_vec()), // single-ASN1-type [0]
        ],
    )
}

/// The outcome of parsing an AARE.
#[derive(Debug, Clone, Default)]
pub struct AareResult {
    pub accepted: bool,
    pub diagnostic: i64,
    /// The MMS InitiateResponsePDU.
    pub user_data: Vec<u8>,
    /// The identity the peer answered with. A proxy replays it so its own
    /// clients see the device's identity; it is empty when the peer omitted
    /// the fields, which is legal.
    pub responding: Identity,
}

/// Parses an A-ASSOCIATE response and extracts the MMS user data.
pub fn parse_aare(apdu: &[u8]) -> Result<AareResult> {
    let mut dec = Decoder::new(apdu);
    let content = dec
        .expect(tag_aare())
        .map_err(|e| Error::Acse(format!("not an AARE: {e}")))?;
    let mut res = AareResult {
        accepted: true,
        ..Default::default()
    };
    let mut inner = Decoder::new(content);
    while inner.more() {
        let (tag, c) = inner.read_tlv()?;
        // responding-AP-title [4] .. responding-AE-invocation-identifier [7].
        if parse_identity(tag, c, 4, &mut res.responding) {
            continue;
        }
        if tag == context_constructed(2) {
            // result
            if let Ok(n) = decode_int(first_int(c)) {
                if n != 0 {
                    res.accepted = false;
                }
            }
        } else if tag == context_constructed(3) {
            // result-source-diagnostic
            res.diagnostic = parse_diagnostic(c);
        } else if tag == context_constructed(30) {
            // user-information
            res.user_data = parse_user_info(c)?;
        }
    }
    Ok(res)
}

/// The outcome of parsing an AARQ.
#[derive(Debug, Clone, Default)]
pub struct AarqRequest {
    /// The application-context-name the peer proposed, `None` when it could
    /// not be decoded.
    pub application_context: Option<Oid>,
    /// The MMS InitiateRequestPDU.
    pub user_data: Vec<u8>,
    pub password: Option<String>,
    /// The identity the peer addressed. A client that fills this in is
    /// checking who it reached, and expects the responding identity in the
    /// AARE to match.
    pub called: Identity,
    /// The identity the peer claims.
    pub calling: Identity,
}

/// Parses an A-ASSOCIATE request and extracts the MMS user data and any
/// calling authentication password.
pub fn parse_aarq(apdu: &[u8]) -> Result<AarqRequest> {
    let mut req = AarqRequest::default();
    let mut dec = Decoder::new(apdu);
    let content = dec
        .expect(tag_aarq())
        .map_err(|e| Error::Acse(format!("not an AARQ: {e}")))?;
    let mut inner = Decoder::new(content);
    while inner.more() {
        let (tag, c) = inner.read_tlv()?;
        // called-AP-title [2]..[5], then calling-AP-title [6]..[9].
        if parse_identity(tag, c, 2, &mut req.called)
            || parse_identity(tag, c, 6, &mut req.calling)
        {
            continue;
        }
        if tag == context_constructed(1) {
            // application-context-name
            req.application_context = first_oid(c);
        } else if tag == context_constructed(12) {
            // calling-authentication-value
            let mut av = Decoder::new(c);
            if let Some(pw) = av.optional(context_primitive(0))? {
                req.password = Some(String::from_utf8_lossy(pw).into_owned());
            }
        } else if tag == context_constructed(30) {
            req.user_data = parse_user_info(c)?;
        }
    }
    Ok(req)
}

/// Reports whether `apdu` is an RLRQ (release request).
pub fn is_release(apdu: &[u8]) -> bool {
    Decoder::new(apdu).peek_is(tag_rlrq())
}

/// Reports whether `apdu` is an RLRE (release response).
pub fn is_release_response(apdu: &[u8]) -> bool {
    Decoder::new(apdu).peek_is(tag_rlre())
}

fn parse_user_info(content: &[u8]) -> Result<Vec<u8>> {
    let mut dec = Decoder::new(content);
    let ext = dec
        .expect(tag_external())
        .map_err(|e| Error::Acse(format!("user-info not EXTERNAL: {e}")))?;
    let mut ed = Decoder::new(ext);
    while ed.more() {
        let (tag, c) = ed.read_tlv()?;
        if tag == context_constructed(0) || tag == context_primitive(1) {
            // single-ASN1-type or octet-aligned
            return Ok(c.to_vec());
        }
    }
    Err(Error::Acse("EXTERNAL has no encoding".into()))
}

fn parse_diagnostic(content: &[u8]) -> i64 {
    let mut dec = Decoder::new(content);
    while dec.more() {
        let Ok((_, c)) = dec.read_tlv() else {
            return 0;
        };
        if let Ok(n) = decode_int(first_int(c)) {
            return n;
        }
    }
    0
}

/// Returns the OBJECT IDENTIFIER inside an EXPLICIT wrapper, which is how
/// AP-title form2 is carried.
fn first_oid(content: &[u8]) -> Option<Oid> {
    let mut dec = Decoder::new(content);
    let c = dec.expect(TAG_OID).ok()?;
    decode_oid(c).ok()
}

/// Returns the content of the first INTEGER within an EXPLICIT wrapper, or
/// the bytes themselves if they are already primitive content.
fn first_int(content: &[u8]) -> &[u8] {
    let mut dec = Decoder::new(content);
    if dec.peek_is(TAG_INTEGER) {
        if let Ok(c) = dec.expect(TAG_INTEGER) {
            return c;
        }
    }
    content
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A proxy standing in for a device has to reproduce its identity
    /// exactly, so what goes into the AARE must come back out unchanged.
    #[test]
    fn aare_responding_identity_round_trips() {
        let want = Identity {
            ap_title: Some(Oid::new(vec![1, 1, 999, 1])),
            ae_qualifier: Some(12),
            ..Default::default()
        };
        let res = parse_aare(&aare_with_identity(&[0xa9, 0x00], &want)).unwrap();
        assert!(
            res.accepted,
            "identity fields made the AARE unparseable as an acceptance"
        );
        assert_eq!(res.responding.ap_title, want.ap_title);
        assert_eq!(res.responding.ae_qualifier, Some(12));
    }

    /// An empty identity must leave the APDU byte-identical to the bare
    /// acceptance: servers with no identity of their own must not start
    /// emitting half-filled ACSE fields.
    #[test]
    fn an_empty_identity_leaves_the_apdus_unchanged() {
        let user = [0xa9u8, 0x00];
        assert_eq!(
            aare_with_identity(&user, &Identity::default()),
            aare(&user),
            "an empty identity changed the AARE encoding"
        );
        assert_eq!(
            aarq_with_identity(&user, "", &Identity::default(), &Identity::default()),
            aarq(&user, ""),
            "an empty identity changed the AARQ encoding"
        );
    }

    /// The client's AARQ says who it addressed; a replica needs that to know
    /// the client is checking identity at all.
    #[test]
    fn aarq_identities_and_password_round_trip() {
        let called = Identity {
            ap_title: Some(Oid::new(vec![1, 1, 999, 1])),
            ae_qualifier: Some(12),
            ..Default::default()
        };
        let calling = Identity {
            ap_title: Some(Oid::new(vec![1, 1, 999, 2])),
            ae_qualifier: Some(7),
            ..Default::default()
        };
        let req =
            parse_aarq(&aarq_with_identity(&[0xa8, 0x00], "secret", &called, &calling)).unwrap();
        assert_eq!(req.called.ap_title, called.ap_title);
        assert_eq!(req.calling.ap_title, calling.ap_title);
        assert_eq!(req.called.ae_qualifier, Some(12));
        assert_eq!(req.calling.ae_qualifier, Some(7));
        assert_eq!(req.password.as_deref(), Some("secret"));
        assert_eq!(req.user_data, [0xa8, 0x00]);
    }

    #[test]
    fn an_aarq_without_a_password_carries_no_authentication_fields() {
        let req = parse_aarq(&aarq(&[0xa8, 0x00], "")).unwrap();
        assert!(req.password.is_none());
        assert!(req.called.is_empty() && req.calling.is_empty());
    }

    #[test]
    fn a_rejecting_aare_is_reported_as_rejected_with_its_diagnostic() {
        let res = parse_aare(&aare_reject(2)).unwrap();
        assert!(!res.accepted);
        assert_eq!(res.diagnostic, 2);
        assert!(res.user_data.is_empty());
    }

    /// The password mechanism is encoded as libiec61850 and other IEC 61850
    /// servers expect it: mechanism-name [11] 2.2.3.1 = 8b 03 52 03 01.
    #[test]
    fn the_password_mechanism_is_2_2_3_1() {
        let apdu = aarq(&[0xa8, 0x00], "user1@testpw");
        assert!(apdu.windows(5).any(|w| w == [0x8b, 0x03, 0x52, 0x03, 0x01]), "{apdu:02x?}");
        assert!(!apdu.windows(4).any(|w| w == [0x52, 0x03, 0x00, 0x01]));
    }

    /// Decodes the application-context-name of an AARE and the
    /// indirect-reference of its user information's EXTERNAL.
    fn aare_fields(apdu: &[u8]) -> (Oid, i64) {
        let content = Decoder::new(apdu).expect(tag_aare()).unwrap();
        let mut d = Decoder::new(content);
        let (mut ctx, mut reference) = (Oid::new(vec![]), -1);
        while d.more() {
            let (tag, c) = d.read_tlv().unwrap();
            if tag == context_constructed(1) {
                ctx = first_oid(c).unwrap();
            } else if tag == context_constructed(30) {
                let ext = Decoder::new(c).expect(tag_external()).unwrap();
                reference = decode_int(Decoder::new(ext).expect(TAG_INTEGER).unwrap()).unwrap();
            }
        }
        (ctx, reference)
    }

    /// The EXTERNAL carrying the InitiateResponse names the MMS presentation
    /// context by the identifier the peer chose.
    #[test]
    fn the_aare_uses_the_negotiated_mms_context() {
        assert_eq!(aare_fields(&aare_for(&[0xa9, 0x00], &Identity::default(), None, 5)).1, 5);
        assert_eq!(
            aare_fields(&aare_for(&[0xa9, 0x00], &Identity::default(), None, 0)).1,
            PRESENTATION_CONTEXT_MMS
        );
    }

    /// The AARE answers with the application context the peer proposed, when
    /// it is one this crate serves.
    #[test]
    fn the_aare_echoes_the_proposed_application_context() {
        let other = Oid::new(vec![1, 2, 3]);
        for (proposed, want) in [
            (Some(oid_acsi_context()), oid_acsi_context()),
            (Some(oid_mms_context()), oid_mms_context()),
            (None, oid_mms_context()),
            (Some(other), oid_mms_context()),
        ] {
            let apdu = aare_for(&[0xa9, 0x00], &Identity::default(), proposed.as_ref(), 3);
            assert_eq!(aare_fields(&apdu).0, want);
        }
    }

    /// The context an AARQ proposes is what the responder reads back.
    #[test]
    fn the_aarq_application_context_round_trips() {
        for c in [ApplicationContext::Acsi, ApplicationContext::Mms] {
            let req = parse_aarq(&aarq_for(
                &[0xa8, 0x00],
                "",
                &Identity::default(),
                &Identity::default(),
                c,
            ))
            .unwrap();
            assert_eq!(req.application_context, Some(c.oid()));
        }
        let req = parse_aarq(&aarq(&[0xa8, 0x00], "")).unwrap();
        assert_eq!(req.application_context, Some(oid_mms_context()));
    }

    #[test]
    fn an_abrt_round_trips_its_source() {
        assert_eq!(parse_abrt(&abrt(ABORT_SOURCE_PROVIDER)).unwrap(), ABORT_SOURCE_PROVIDER);
        assert_eq!(parse_abrt(&abrt(ABORT_SOURCE_USER)).unwrap(), ABORT_SOURCE_USER);
        assert!(parse_abrt(&rlrq()).is_err());
    }

    #[test]
    fn release_apdus_are_recognised_by_tag() {
        assert!(is_release(&rlrq()));
        assert!(!is_release(&rlre()));
        assert!(is_release_response(&rlre()));
        assert!(!is_release(&aarq(&[0xa8, 0x00], "")));
    }

    #[test]
    fn malformed_apdus_are_rejected_rather_than_panicking() {
        assert!(parse_aare(&[]).is_err());
        assert!(parse_aarq(&[0x60]).is_err());
        assert!(parse_aare(&aarq(&[0xa8, 0x00], "")).is_err(), "AARQ is not an AARE");
    }
}
