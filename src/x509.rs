//! The few parts of an X.509 certificate this crate reads itself: the
//! subject's common name and whether it has alternative names (IED
//! certificates are often named by their common name alone), and the subject
//! public key, to judge its strength and to verify signatures with it.
//!
//! Chain validation is not done here; webpki does it.

use crate::asn1::{self, decode_oid, Decoder, Tag, TAG_BIT_STRING, TAG_INTEGER, TAG_OID, TAG_SEQUENCE, TAG_SET};

/// A decoding failure.
#[derive(Debug, thiserror::Error)]
#[error("x509: {0}")]
pub struct Error(String);

impl From<asn1::Error> for Error {
    fn from(e: asn1::Error) -> Error {
        Error(e.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

/// The curve of an elliptic-curve key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
    P521,
    Other,
}

impl Curve {
    /// The field size in bits, 0 when unknown.
    pub fn bits(self) -> usize {
        match self {
            Curve::P256 => 256,
            Curve::P384 => 384,
            Curve::P521 => 521,
            Curve::Other => 0,
        }
    }
}

/// A subject public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// The modulus and exponent, big-endian without leading zeros.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// The curve and the uncompressed point.
    Ec { curve: Curve, point: Vec<u8> },
    Ed25519(Vec<u8>),
    /// An algorithm this module does not know, by its OID arcs.
    Other(Vec<u32>),
}

impl PublicKey {
    /// The size of an RSA modulus in bits.
    pub fn rsa_bits(&self) -> Option<usize> {
        match self {
            PublicKey::Rsa { n, .. } => {
                let first = n.first().copied().unwrap_or(0);
                Some(n.len() * 8 - first.leading_zeros() as usize)
            }
            _ => None,
        }
    }
}

/// What this crate reads of a certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// The subject's common name, when it has one.
    pub common_name: Option<String>,
    /// Whether the certificate carries a subject alternative name extension.
    pub has_alt_names: bool,
    pub public_key: PublicKey,
    /// The DER of the subject Name.
    pub subject: Vec<u8>,
    /// The DER of the issuer Name.
    pub issuer: Vec<u8>,
    /// The X.509 version: 1, 2 or 3.
    pub version: u8,
    /// The serial number's INTEGER content octets.
    pub serial: Vec<u8>,
    /// The validity period, in seconds since the Unix epoch.
    pub not_before: i64,
    pub not_after: i64,
    /// The subject public key's AlgorithmIdentifier content and the key bits,
    /// as a signature verification algorithm takes them.
    pub spki_alg: Vec<u8>,
    pub spki_key: Vec<u8>,
    /// What the issuer signed (the whole tbsCertificate), how, and the
    /// signature.
    pub signed: Signed,
}

/// A signed structure: the octets signed, the AlgorithmIdentifier content of
/// the signature, and the signature.
#[derive(Debug, Clone, Default)]
pub struct Signed {
    pub tbs: Vec<u8>,
    pub algorithm: Vec<u8>,
    pub signature: Vec<u8>,
}

/// What this crate reads of a certificate revocation list.
#[derive(Debug, Clone)]
pub struct Crl {
    /// The DER of the issuer Name.
    pub issuer: Vec<u8>,
    /// When the next CRL is due, in seconds since the Unix epoch.
    pub next_update: Option<i64>,
    /// The serial numbers revoked, as INTEGER content octets.
    pub revoked: Vec<Vec<u8>>,
    pub signed: Signed,
}

const OID_RSA: &[u32] = &[1, 2, 840, 113549, 1, 1, 1];
const OID_EC: &[u32] = &[1, 2, 840, 10045, 2, 1];
const OID_P256: &[u32] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_P384: &[u32] = &[1, 3, 132, 0, 34];
const OID_P521: &[u32] = &[1, 3, 132, 0, 35];
const OID_ED25519: &[u32] = &[1, 3, 101, 112];
const OID_CN: &[u32] = &[2, 5, 4, 3];
const OID_SAN: &[u32] = &[2, 5, 29, 17];

fn context(n: u32, constructed: bool) -> Tag {
    Tag::new(asn1::Class::ContextSpecific, constructed, n)
}

/// Reads the next element of `d`, returning its whole TLV and its content.
fn tlv<'a>(d: &mut Decoder<'a>, tag: Tag) -> Result<(&'a [u8], &'a [u8])> {
    let before = d.rest();
    let content = d.expect(tag)?;
    Ok((&before[..before.len() - d.rest().len()], content))
}

/// Splits a signed structure: SEQUENCE { tbs, AlgorithmIdentifier, BIT STRING }.
fn parse_signed(der: &[u8]) -> Result<(Signed, &[u8])> {
    let outer = Decoder::new(der).expect(TAG_SEQUENCE)?;
    let mut d = Decoder::new(outer);
    let (tbs_tlv, tbs) = tlv(&mut d, TAG_SEQUENCE)?;
    let algorithm = d.expect(TAG_SEQUENCE)?;
    let bits = d.expect(TAG_BIT_STRING)?;
    let signature = bits.get(1..).ok_or_else(|| Error("empty signature".into()))?;
    Ok((
        Signed {
            tbs: tbs_tlv.to_vec(),
            algorithm: algorithm.to_vec(),
            signature: signature.to_vec(),
        },
        tbs,
    ))
}

const TAG_UTC_TIME: Tag = Tag::new(asn1::Class::Universal, false, 23);

/// Reads a UTCTime or GeneralizedTime, `YYMMDDHHMMSSZ` or
/// `YYYYMMDDHHMMSSZ`, as seconds since the Unix epoch.
fn parse_time(d: &mut Decoder<'_>) -> Result<i64> {
    let (t, v) = d.read_tlv()?;
    let s = std::str::from_utf8(v).map_err(|_| Error("time is not ASCII".into()))?;
    let digits = s.strip_suffix('Z').ok_or_else(|| Error(format!("time {s:?} is not UTC")))?;
    let (year, rest) = if t == TAG_UTC_TIME {
        let yy: i64 = digits.get(..2).and_then(|x| x.parse().ok()).ok_or_else(|| Error(format!("time {s:?}")))?;
        (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &digits[2..])
    } else if t == asn1::TAG_GENERAL_TIME {
        let yyyy: i64 = digits.get(..4).and_then(|x| x.parse().ok()).ok_or_else(|| Error(format!("time {s:?}")))?;
        (yyyy, &digits[4..])
    } else {
        return Err(Error(format!("time of tag {t:?}")));
    };
    let field = |i: usize| -> Result<u32> {
        rest.get(i..i + 2).and_then(|x| x.parse().ok()).ok_or_else(|| Error(format!("time {s:?}")))
    };
    let days = crate::time_util::days_from_civil(year, field(0)?, field(2)?);
    Ok(days * 86400 + i64::from(field(4)?) * 3600 + i64::from(field(6)?) * 60 + i64::from(field(8)?))
}

/// Decodes the parts of a DER certificate this crate uses.
pub fn parse(der: &[u8]) -> Result<Certificate> {
    let (signed, tbs) = parse_signed(der)?;
    let mut d = Decoder::new(tbs);
    let version = match d.optional(context(0, true))? {
        Some(v) => asn1::decode_int(Decoder::new(v).expect(TAG_INTEGER)?)? as u8 + 1,
        None => 1,
    };
    let serial = d.expect(TAG_INTEGER)?.to_vec();
    d.expect(TAG_SEQUENCE)?; // signature algorithm
    let (issuer, _) = tlv(&mut d, TAG_SEQUENCE)?;
    let validity = d.expect(TAG_SEQUENCE)?;
    let mut vd = Decoder::new(validity);
    let not_before = parse_time(&mut vd)?;
    let not_after = parse_time(&mut vd)?;
    let (subject_tlv, subject) = tlv(&mut d, TAG_SEQUENCE)?;
    let spki = d.expect(TAG_SEQUENCE)?;
    let mut sd = Decoder::new(spki);
    let spki_alg = sd.expect(TAG_SEQUENCE)?.to_vec();
    let spki_key = sd.expect(TAG_BIT_STRING)?.get(1..).unwrap_or_default().to_vec();
    d.optional(context(1, false))?; // issuerUniqueID
    d.optional(context(2, false))?; // subjectUniqueID
    let mut has_alt_names = false;
    if let Some(exts) = d.optional(context(3, true))? {
        let list = Decoder::new(exts).expect(TAG_SEQUENCE)?;
        let mut ed = Decoder::new(list);
        while ed.more() {
            let ext = ed.expect(TAG_SEQUENCE)?;
            let oid = decode_oid(Decoder::new(ext).expect(TAG_OID)?)?;
            has_alt_names |= oid.arcs() == OID_SAN;
        }
    }
    Ok(Certificate {
        common_name: common_name(subject)?,
        has_alt_names,
        public_key: parse_spki_contents(spki)?,
        subject: subject_tlv.to_vec(),
        issuer: issuer.to_vec(),
        version,
        serial,
        not_before,
        not_after,
        spki_alg,
        spki_key,
        signed,
    })
}

/// Decodes the parts of a DER certificate revocation list this crate uses.
pub fn parse_crl(der: &[u8]) -> Result<Crl> {
    let (signed, tbs) = parse_signed(der)?;
    let mut d = Decoder::new(tbs);
    d.optional(TAG_INTEGER)?; // version
    d.expect(TAG_SEQUENCE)?; // signature algorithm
    let (issuer, _) = tlv(&mut d, TAG_SEQUENCE)?;
    parse_time(&mut d)?; // thisUpdate
    let next_update = match d.peek() {
        Ok(t) if t == TAG_UTC_TIME || t == asn1::TAG_GENERAL_TIME => Some(parse_time(&mut d)?),
        _ => None,
    };
    let mut revoked = Vec::new();
    if let Some(list) = d.optional(TAG_SEQUENCE)? {
        let mut ld = Decoder::new(list);
        while ld.more() {
            let entry = ld.expect(TAG_SEQUENCE)?;
            revoked.push(Decoder::new(entry).expect(TAG_INTEGER)?.to_vec());
        }
    }
    Ok(Crl {
        issuer: issuer.to_vec(),
        next_update,
        revoked,
        signed,
    })
}

/// The first common name of a Name (the content of its SEQUENCE).
fn common_name(name: &[u8]) -> Result<Option<String>> {
    let mut d = Decoder::new(name);
    while d.more() {
        let rdn = d.expect(TAG_SET)?;
        let mut rd = Decoder::new(rdn);
        while rd.more() {
            let atv = rd.expect(TAG_SEQUENCE)?;
            let mut ad = Decoder::new(atv);
            let oid = decode_oid(ad.expect(TAG_OID)?)?;
            let (_, value) = ad.read_tlv()?;
            if oid.arcs() == OID_CN {
                return Ok(Some(String::from_utf8_lossy(value).into_owned()));
            }
        }
    }
    Ok(None)
}

/// Decodes a SubjectPublicKeyInfo, given either with its outer SEQUENCE or as
/// the content of it (as a webpki trust anchor holds it).
pub fn parse_spki(b: &[u8]) -> Result<PublicKey> {
    let mut d = Decoder::new(b);
    let first = d.expect(TAG_SEQUENCE)?;
    if d.more() {
        // The algorithm identifier, then the key: the content form.
        parse_spki_contents(b)
    } else {
        parse_spki_contents(first)
    }
}

fn parse_spki_contents(spki: &[u8]) -> Result<PublicKey> {
    let mut d = Decoder::new(spki);
    let alg = d.expect(TAG_SEQUENCE)?;
    let bits = d.expect(TAG_BIT_STRING)?;
    let key = bits.get(1..).ok_or_else(|| Error("empty public key".into()))?;
    let mut ad = Decoder::new(alg);
    let oid = decode_oid(ad.expect(TAG_OID)?)?;
    match oid.arcs() {
        OID_RSA => {
            let rsa = Decoder::new(key).expect(TAG_SEQUENCE)?;
            let mut rd = Decoder::new(rsa);
            let n = strip(rd.expect(TAG_INTEGER)?);
            let e = strip(rd.expect(TAG_INTEGER)?);
            Ok(PublicKey::Rsa { n, e })
        }
        OID_EC => {
            let curve = match ad.optional(TAG_OID)? {
                Some(c) => match decode_oid(c)?.arcs() {
                    OID_P256 => Curve::P256,
                    OID_P384 => Curve::P384,
                    OID_P521 => Curve::P521,
                    _ => Curve::Other,
                },
                None => Curve::Other,
            };
            Ok(PublicKey::Ec {
                curve,
                point: key.to_vec(),
            })
        }
        OID_ED25519 => Ok(PublicKey::Ed25519(key.to_vec())),
        other => Ok(PublicKey::Other(other.to_vec())),
    }
}

/// An unsigned big-endian integer without its sign octet.
fn strip(b: &[u8]) -> Vec<u8> {
    let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b[start..].to_vec()
}
