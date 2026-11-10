use super::{AuthenticatorTagging, Edition, Error, Result};
use crate::asn1::{
    self, cons, context_constructed as cc, context_primitive as cp, prim, raw_content, raw_tlv,
    Class, Decoder, Element, Oid, Tag, TAG_BIT_STRING as BITS, TAG_GENERAL_TIME as TIME,
    TAG_INTEGER as INT, TAG_OCTET_STRING as OCT, TAG_OID as OID, TAG_SEQUENCE as SEQ,
    TAG_SET as SET,
};
use std::time::{Duration, SystemTime};
const UTF: Tag = Tag::new(Class::Universal, false, 12);
const ENUM: Tag = Tag::new(Class::Universal, false, 10);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    pub oid: Oid,
    pub parameters: Option<Vec<u8>>,
}
impl AlgorithmIdentifier {
    pub fn new(oid: &[u32], parameters: Option<Vec<u8>>) -> Self {
        Self {
            oid: Oid(oid.to_vec()),
            parameters,
        }
    }
    pub(crate) fn null_or_absent(&self) -> bool {
        self.parameters.as_deref().is_none_or(|p| p == [5, 0])
    }
    fn element(&self) -> Element {
        let mut e = cons(SEQ, [asn1::oid_elem(OID, &self.oid)]);
        if let Some(p) = &self.parameters {
            e.push(raw_tlv(p.clone()));
        }
        e
    }
    fn parse(d: &mut Decoder<'_>) -> Result<Self> {
        let mut a = Decoder::new(d.expect(SEQ)?);
        let oid = asn1::decode_oid(a.expect(OID)?)?;
        let parameters = if a.more() {
            Some(take(&mut a)?.full.to_vec())
        } else {
            None
        };
        end(&a)?;
        Ok(Self { oid, parameters })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    HandshakeRequest,
    HandshakeAccept,
    ApplicationReject,
    HandshakeReject,
    HandshakeAbort,
    DataAbort,
    ApplicationAbort,
    ReleaseRequest,
    ReleaseResponse,
}
impl Kind {
    pub(crate) fn handshake(self) -> bool {
        matches!(self, Self::HandshakeRequest | Self::HandshakeAccept)
    }
    fn application(self) -> bool {
        matches!(
            self,
            Self::HandshakeRequest
                | Self::HandshakeAccept
                | Self::ApplicationReject
                | Self::ApplicationAbort
        )
    }
}

pub(crate) struct Span<'a> {
    pub tag: Tag,
    pub content: &'a [u8],
    pub full: &'a [u8],
    pub signed: &'a [u8],
}
pub(crate) fn take<'a>(d: &mut Decoder<'a>) -> Result<Span<'a>> {
    let before = d.rest();
    let (tag, content) = d.read_tlv()?;
    let full = &before[..before.len() - d.rest().len()];
    let offset = content.as_ptr() as usize - before.as_ptr() as usize;
    Ok(Span {
        tag,
        content,
        full,
        signed: &full[offset..],
    })
}
fn end(d: &Decoder<'_>) -> Result<()> {
    if d.more() {
        Err(Error::hs(1, "trailing fields"))
    } else {
        Ok(())
    }
}
fn extensions(d: &mut Decoder<'_>) -> Result<()> {
    for _ in 0..8 {
        if !d.more() {
            return Ok(());
        }
        d.skip()?;
    }
    end(d)
}
fn full_element(bytes: &[u8]) -> Result<()> {
    let mut d = Decoder::new(bytes);
    d.skip()?;
    end(&d)
}
fn name(d: &mut Decoder<'_>) -> Result<String> {
    let b = d.expect(UTF)?;
    if b.is_empty()
        || b.len() > 128
        || !b
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(b))
    {
        return Err(Error::hs(1, "invalid association identifier"));
    }
    String::from_utf8(b.to_vec()).map_err(|_| Error::hs(1, "association identifier"))
}
fn version(d: &mut Decoder<'_>) -> Result<Option<asn1::BitString>> {
    d.optional(BITS)?
        .map(asn1::decode_bit_string)
        .transpose()
        .map_err(Error::from)
}
pub(crate) fn version_valid(v: &Option<asn1::BitString>, offering: bool) -> bool {
    v.as_ref()
        .is_none_or(|v| v.bit(0) && (offering || (1..v.length).all(|i| !v.bit(i))))
}
fn version_element() -> Element {
    prim(BITS, vec![7, 128])
}
fn path(d: &mut Decoder<'_>) -> Result<Vec<Vec<u8>>> {
    let Some(content) = d.optional(SEQ)? else {
        return Ok(Vec::new());
    };
    let mut d = Decoder::new(content);
    let mut out = Vec::new();
    while d.more() {
        if out.len() >= 4 {
            return Err(Error::hs(9, "certificate path too long"));
        }
        let cert = d.expect(OCT)?;
        if cert.len() > 8192 {
            return Err(Error::hs(9, "path certificate too large"));
        }
        out.push(cert.to_vec());
    }
    Ok(out)
}
fn path_element(path: &[Vec<u8>]) -> Option<Element> {
    (!path.is_empty()).then(|| cons(SEQ, path.iter().map(|p| prim(OCT, p.clone()))))
}
fn algorithms(tag: Tag, list: &[AlgorithmIdentifier], first: bool) -> Element {
    cons(
        tag,
        list.iter().map(|a| {
            if first {
                asn1::oid_elem(OID, &a.oid)
            } else {
                a.element()
            }
        }),
    )
}
fn parse_algorithms(content: &[u8], first: bool) -> Result<Vec<AlgorithmIdentifier>> {
    let mut d = Decoder::new(content);
    let mut out = Vec::new();
    while d.more() {
        if out.len() >= 16 {
            return Err(Error::hs(1, "too many algorithms"));
        }
        out.push(if first {
            AlgorithmIdentifier {
                oid: asn1::decode_oid(d.expect(OID)?)?,
                parameters: None,
            }
        } else {
            AlgorithmIdentifier::parse(&mut d)?
        });
    }
    Ok(out)
}

#[derive(Debug, Clone)]
pub(crate) struct Token1 {
    pub sig: AlgorithmIdentifier,
    pub certificate: Vec<u8>,
    pub path: Vec<Vec<u8>>,
    pub version: Option<asn1::BitString>,
    pub id: String,
    pub group: i64,
    pub public: Vec<u8>,
    pub hmac: AlgorithmIdentifier,
    pub time: Vec<u8>,
    pub icv: Vec<AlgorithmIdentifier>,
    pub aea: bool,
    pub encryption: bool,
    pub confidentiality: asn1::BitString,
    pub attribute: Option<Vec<u8>>,
}
impl Token1 {
    pub(crate) fn element(&self, ed: Edition) -> Element {
        let first = ed == Edition::First2018;
        let mut e = cons(
            SEQ,
            [self.sig.element(), prim(OCT, self.certificate.clone())],
        );
        if let Some(path) = path_element(&self.path) {
            e.push(path);
        }
        if let Some(version) = &self.version {
            e.push(asn1::bit_string_elem(BITS, version));
        }
        e.push(prim(UTF, self.id.as_bytes().to_vec()));
        if first {
            e.push(prim(TIME, self.time.clone()));
        }
        e.push(cons(
            SEQ,
            [
                asn1::int_elem(INT, self.group),
                prim(OCT, self.public.clone()),
            ],
        ));
        e.push(if first {
            asn1::oid_elem(OID, &self.hmac.oid)
        } else {
            self.hmac.element()
        });
        if !first {
            e.push(prim(TIME, self.time.clone()));
        }
        if self.aea {
            e.push(algorithms(if first { SET } else { SEQ }, &self.icv, first));
        } else {
            let mut mode = cons(if first { SEQ } else { cc(0) }, []);
            if self.encryption {
                mode.push(algorithms(cc(0), &[], first));
            }
            mode.push(algorithms(cc(1), &self.icv, first));
            e.push(mode);
        }
        e.push(asn1::bit_string_elem(BITS, &self.confidentiality));
        if let Some(cert) = &self.attribute {
            e.push(prim(OCT, cert.clone()));
        }
        e
    }
    fn parse(content: &[u8], ed: Edition) -> Result<Self> {
        let first = ed == Edition::First2018;
        let mut d = Decoder::new(content);
        let sig = AlgorithmIdentifier::parse(&mut d)?;
        let certificate = d.expect(OCT)?.to_vec();
        let path = path(&mut d)?;
        let version = version(&mut d)?;
        let id = name(&mut d)?;
        let mut time = Vec::new();
        if first {
            time = d.expect(TIME)?.to_vec();
        }
        let mut dh = Decoder::new(d.expect(SEQ)?);
        let group = asn1::decode_int(dh.expect(INT)?)?;
        let public = dh.expect(OCT)?.to_vec();
        end(&dh)?;
        let hmac = if first {
            AlgorithmIdentifier {
                oid: asn1::decode_oid(d.expect(OID)?)?,
                parameters: None,
            }
        } else {
            AlgorithmIdentifier::parse(&mut d)?
        };
        if !first {
            time = d.expect(TIME)?.to_vec();
        }
        let (tag, mode) = d.read_tlv()?;
        let aea = tag == if first { SET } else { SEQ };
        let mut encryption = false;
        let icv = if aea {
            parse_algorithms(mode, first)?
        } else {
            if tag != if first { SEQ } else { cc(0) } {
                return Err(Error::hs(1, "encryption mode"));
            }
            let mut mode = Decoder::new(mode);
            if mode.optional(cc(0))?.is_some() {
                encryption = true;
            }
            let algorithms = parse_algorithms(mode.expect(cc(1))?, first)?;
            end(&mode)?;
            algorithms
        };
        let confidentiality = asn1::decode_bit_string(d.expect(BITS)?)?;
        let attribute = d.optional(OCT)?.map(Vec::from);
        extensions(&mut d)?;
        Ok(Self {
            sig,
            certificate,
            path,
            version,
            id,
            group,
            public,
            hmac,
            time,
            icv,
            aea,
            encryption,
            confidentiality,
            attribute,
        })
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Token3 {
    pub sig: AlgorithmIdentifier,
    pub certificate: Vec<u8>,
    pub path: Vec<Vec<u8>>,
    pub version: Option<asn1::BitString>,
    pub id: Option<String>,
    pub time: Vec<u8>,
}
impl Token3 {
    pub(crate) fn element(&self) -> Element {
        let mut e = cons(SEQ, [self.sig.element(), version_element()]);
        if let Some(id) = &self.id {
            e.push(prim(UTF, id.as_bytes().to_vec()));
        }
        e.push(prim(TIME, self.time.clone()));
        e.push(prim(OCT, self.certificate.clone()));
        if let Some(path) = path_element(&self.path) {
            e.push(path);
        }
        e
    }
    fn parse(content: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(content);
        let sig = AlgorithmIdentifier::parse(&mut d)?;
        let version = version(&mut d)?;
        let id = if d.peek_is(UTF) {
            Some(name(&mut d)?)
        } else {
            None
        };
        let time = d.expect(TIME)?.to_vec();
        let certificate = d.expect(OCT)?.to_vec();
        let path = path(&mut d)?;
        extensions(&mut d)?;
        Ok(Self {
            sig,
            version,
            id,
            time,
            certificate,
            path,
        })
    }
}
#[derive(Debug)]
pub(crate) struct Signed {
    pub protocol: Option<String>,
    pub token1: Option<Token1>,
    pub token3: Option<Token3>,
    pub application: Vec<u8>,
    pub diagnostic: Option<u8>,
    pub algorithm: AlgorithmIdentifier,
    pub signature: Vec<u8>,
    pub tbs: Vec<u8>,
}
impl Signed {
    pub(crate) fn encode(
        kind: Kind,
        protocol: Option<&str>,
        token: Element,
        application: &[u8],
        diagnostic: Option<u8>,
        identity: &super::Identity,
    ) -> Result<Vec<u8>> {
        let mut tbs = token.encode();
        if !application.is_empty() {
            full_element(application)?;
            tbs.extend_from_slice(application);
        }
        if let Some(diag) = diagnostic {
            tbs.extend_from_slice(&asn1::int_elem(ENUM, i64::from(diag)).encode());
        }
        let sig = identity.sign(&tbs)?;
        let mut e = cons(SEQ, []);
        if kind == Kind::HandshakeRequest {
            e.push(prim(UTF, protocol.unwrap_or("").as_bytes().to_vec()));
        }
        e.push(raw_content(SEQ, tbs));
        e.push(cons(SEQ, [identity.signature.element(), prim(OCT, sig)]));
        Ok(e.encode())
    }
    /// Input is a complete universal SEQUENCE; every authenticated span is
    /// retained exactly, including EOC octets from indefinite BER.
    pub(crate) fn parse(bytes: &[u8], kind: Kind, ed: Edition) -> Result<Self> {
        let mut outer = Decoder::new(bytes);
        let mut d = Decoder::new(outer.expect(SEQ)?);
        end(&outer)?;
        let protocol = if kind == Kind::HandshakeRequest {
            Some(
                String::from_utf8(d.expect(UTF)?.to_vec())
                    .map_err(|_| Error::hs(1, "protocol string"))?,
            )
        } else {
            None
        };
        let tbs = take(&mut d)?;
        if tbs.tag != SEQ {
            return Err(Error::hs(1, "TBS is not a sequence"));
        }
        let mut signature = Decoder::new(d.expect(SEQ)?);
        let algorithm = AlgorithmIdentifier::parse(&mut signature)?;
        let sig = signature.expect(OCT)?.to_vec();
        end(&signature)?;
        extensions(&mut d)?;
        let mut body = Decoder::new(tbs.content);
        let content = body.expect(SEQ)?;
        let (token1, token3) = if kind.handshake() {
            (Some(Token1::parse(content, ed)?), None)
        } else {
            (None, Some(Token3::parse(content)?))
        };
        let mut application = Vec::new();
        let mut diagnostic = None;
        if kind.application() && body.more() {
            application = take(&mut body)?.full.to_vec();
        } else if matches!(
            kind,
            Kind::HandshakeReject | Kind::HandshakeAbort | Kind::DataAbort
        ) {
            diagnostic = body
                .optional(ENUM)?
                .map(asn1::decode_int)
                .transpose()?
                .map(|n| u8::try_from(n).map_err(|_| Error::hs(1, "diagnostic range")))
                .transpose()?;
        }
        extensions(&mut body)?;
        Ok(Self {
            protocol,
            token1,
            token3,
            application,
            diagnostic,
            algorithm,
            signature: sig,
            tbs: tbs.signed.to_vec(),
        })
    }
}
#[derive(Debug, Clone)]
pub(crate) struct Token2 {
    pub version: Option<asn1::BitString>,
    pub id: String,
    pub time: Vec<u8>,
    pub sequence: i64,
    pub iv: Option<Vec<u8>>,
    pub rekey: Option<Vec<u8>>,
    pub request_rekey: bool,
    pub changed_key: bool,
}
impl Token2 {
    pub(crate) fn element(&self) -> Element {
        let mut e = cons(
            SEQ,
            [
                version_element(),
                prim(UTF, self.id.as_bytes().to_vec()),
                prim(TIME, self.time.clone()),
                asn1::int_elem(INT, self.sequence),
            ],
        );
        if let Some(v) = &self.iv {
            e.push(prim(cp(0), v.clone()));
        }
        if let Some(v) = &self.rekey {
            e.push(prim(cp(1), v.clone()));
        }
        if self.request_rekey {
            e.push(asn1::bool_elem(cp(2), true));
        }
        if self.changed_key {
            e.push(asn1::bool_elem(cp(3), true));
        }
        e
    }
    fn parse(content: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(content);
        let version = version(&mut d)?;
        let id = name(&mut d)?;
        let time = d.expect(TIME)?.to_vec();
        let sequence = asn1::decode_int(d.expect(INT)?)?;
        let iv = d.optional(cp(0))?.map(Vec::from);
        let rekey = d.optional(cp(1))?.map(Vec::from);
        let request_rekey = d
            .optional(cp(2))?
            .map(asn1::decode_bool)
            .transpose()?
            .unwrap_or(false);
        let changed_key = d
            .optional(cp(3))?
            .map(asn1::decode_bool)
            .transpose()?
            .unwrap_or(false);
        extensions(&mut d)?;
        Ok(Self {
            version,
            id,
            time,
            sequence,
            iv,
            rekey,
            request_rekey,
            changed_key,
        })
    }
}
#[derive(Debug)]
pub(crate) struct Transfer {
    pub token: Token2,
    pub application: Vec<u8>,
    pub algorithm: AlgorithmIdentifier,
    pub nonce: Vec<u8>,
    pub icv: Vec<u8>,
    pub tbp: Vec<u8>,
}
impl Transfer {
    pub(crate) fn body(token: &Token2, application: &[u8]) -> Result<Vec<u8>> {
        full_element(application)?;
        Ok([token.element().encode(), application.to_vec()].concat())
    }
    pub(crate) fn encode(
        tbp: Vec<u8>,
        algorithm: &AlgorithmIdentifier,
        nonce: &[u8],
        icv: Vec<u8>,
        tagging: AuthenticatorTagging,
    ) -> Vec<u8> {
        let mut auth = cons(SEQ, []);
        if !nonce.is_empty() {
            auth.push(prim(
                if tagging == AuthenticatorTagging::AnnexB {
                    OCT
                } else {
                    cp(0)
                },
                nonce.to_vec(),
            ));
        }
        auth.push(algorithm.element());
        auth.push(prim(
            if tagging == AuthenticatorTagging::AnnexB {
                OCT
            } else {
                cp(1)
            },
            icv,
        ));
        cons(SEQ, [raw_content(SEQ, tbp), auth]).encode()
    }
    pub(crate) fn parse(bytes: &[u8], tagging: AuthenticatorTagging) -> Result<Self> {
        let mut outer = Decoder::new(bytes);
        let mut d = Decoder::new(outer.expect(SEQ)?);
        end(&outer)?;
        let body = take(&mut d)?;
        if body.tag != SEQ {
            return Err(Error::data(1, "TBP is not a sequence"));
        }
        let mut b = Decoder::new(body.content);
        let token = Token2::parse(b.expect(SEQ)?)?;
        let application = take(&mut b)?;
        if application.tag == OCT {
            return Err(Error::data(3, "encryption not selected"));
        }
        extensions(&mut b)?;
        let mut auth = Decoder::new(d.expect(SEQ)?);
        let nonce = auth
            .optional(if tagging == AuthenticatorTagging::AnnexB {
                OCT
            } else {
                cp(0)
            })?
            .unwrap_or_default()
            .to_vec();
        let algorithm = AlgorithmIdentifier::parse(&mut auth)?;
        let icv = auth
            .expect(if tagging == AuthenticatorTagging::AnnexB {
                OCT
            } else {
                cp(1)
            })?
            .to_vec();
        extensions(&mut auth)?;
        extensions(&mut d)?;
        Ok(Self {
            token,
            application: application.full.to_vec(),
            algorithm,
            nonce,
            icv,
            tbp: body.signed.to_vec(),
        })
    }
}

pub(crate) fn format_time(time: SystemTime) -> Vec<u8> {
    let (secs, nanos) = crate::time_util::unix_parts(time);
    let (y, m, d, h, mi, s) = crate::time_util::civil_from_unix(secs);
    let ms = nanos / 1_000_000;
    let mut text = format!("{y:04}{m:02}{d:02}{h:02}{mi:02}{s:02}");
    if ms != 0 {
        text.push('.');
        text.push_str(format!("{ms:03}").trim_end_matches('0'));
    }
    text.push('Z');
    text.into_bytes()
}
pub(crate) fn parse_time(bytes: &[u8]) -> Result<SystemTime> {
    let text = std::str::from_utf8(bytes).map_err(|_| Error::hs(10, "time encoding"))?;
    let digits = text
        .strip_suffix('Z')
        .ok_or_else(|| Error::hs(10, "UTC time required"))?;
    let (whole, fraction) = digits
        .split_once(['.', ','])
        .map_or((digits, None), |(a, b)| (a, Some(b)));
    if !matches!(whole.len(), 10 | 12 | 14)
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.is_some_and(|f| {
            whole.len() != 14 || f.is_empty() || !f.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(Error::hs(10, "invalid GeneralizedTime"));
    }
    let n = |a, b| {
        whole[a..b]
            .parse::<u32>()
            .map_err(|_| Error::hs(10, "invalid time"))
    };
    let (y, m, d, h) = (n(0, 4)?, n(4, 6)?, n(6, 8)?, n(8, 10)?);
    let mi = if whole.len() >= 12 { n(10, 12)? } else { 0 };
    let sec = if whole.len() == 14 { n(12, 14)? } else { 0 };
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 59 {
        return Err(Error::hs(10, "time out of range"));
    }
    let days = crate::time_util::days_from_civil(i64::from(y), m, d);
    if crate::time_util::civil_from_days(days) != (i64::from(y), m, d) {
        return Err(Error::hs(10, "invalid calendar date"));
    }
    let nanos = if let Some(f) = fraction {
        let f = &f[..f.len().min(9)];
        f.parse::<u32>().map_err(|_| Error::hs(10, "fraction"))? * 10u32.pow(9 - f.len() as u32)
    } else {
        0
    };
    Ok(crate::time_util::from_unix(
        days * 86400 + i64::from(h * 3600 + mi * 60 + sec),
        nanos,
    ))
}
pub(crate) fn millis(time: SystemTime) -> SystemTime {
    let (s, n) = crate::time_util::unix_parts(time);
    crate::time_util::from_unix(s, n / 1_000_000 * 1_000_000)
}
pub(crate) fn fresh(time: SystemTime, now: SystemTime, window: Duration) -> bool {
    now.duration_since(time)
        .or_else(|_| time.duration_since(now))
        .is_ok_and(|d| d <= window)
}
