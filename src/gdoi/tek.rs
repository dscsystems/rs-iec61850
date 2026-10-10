//! Group identities and traffic encryption keys: the GDOI SA, SA TEK and Key
//! Download payloads with the IEC 61850 payloads of RFC 8052.

use std::collections::HashMap;
use std::time::Duration;

use crate::asn1::{decode_oid, oid_elem, Decoder, Oid, TAG_OID};
use crate::rsession::{self, SecAlgorithm, SigAlgorithm};

use super::crypto::random_bytes;
use super::isakmp::{
    encode_attrs, encode_chain, malformed, parse_attrs, parse_chain, Attribute, IdPayload, Payload,
    DOI_GDOI, ID_KEY_ID, ID_OID, KD_TYPE_TEK, PROTO_IEC61850, P_NONE, P_SAT,
};
use super::{Error, Result};

/// Names a group: a 4-octet group identifier (ID_KEY_ID, which every GDOI
/// implementation supports), or an OID with an optional OID-specific selector
/// (ID_OID, RFC 8052), which IEC 62351-9 uses to name the GOOSE or sampled
/// value stream a key protects. The OIDs are defined in IEC 62351-9, not
/// here: the application passes the one its key server is configured with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct GroupId {
    pub key_id: u32,
    pub oid: Option<Oid>,
    /// The OID-specific payload, DER encoded (a multicast address, say);
    /// empty when the OID needs none.
    pub selector: Vec<u8>,
}

impl GroupId {
    /// A group named by an ID_KEY_ID.
    pub fn key_id(id: u32) -> GroupId {
        GroupId {
            key_id: id,
            ..Default::default()
        }
    }

    /// A group named by an OID, without a selector.
    pub fn oid(oid: impl Into<Oid>) -> GroupId {
        GroupId {
            oid: Some(oid.into()),
            ..Default::default()
        }
    }

    /// Encodes the group as a GDOI identification payload.
    pub(crate) fn id(&self) -> Result<IdPayload> {
        match &self.oid {
            None => Ok(IdPayload {
                kind: ID_KEY_ID,
                data: self.key_id.to_be_bytes().to_vec(),
            }),
            Some(oid) => Ok(IdPayload {
                kind: ID_OID,
                data: oid_and_selector(oid, &self.selector)?,
            }),
        }
    }

    pub(crate) fn from_id(id: &IdPayload) -> Result<GroupId> {
        match id.kind {
            ID_KEY_ID => {
                let d: [u8; 4] = id
                    .data
                    .as_slice()
                    .try_into()
                    .map_err(|_| malformed(format!("ID_KEY_ID of {} octets", id.data.len())))?;
                Ok(GroupId::key_id(u32::from_be_bytes(d)))
            }
            ID_OID => {
                let (oid, selector, rest) = parse_oid_and_selector(&id.data)?;
                if !rest.is_empty() {
                    return Err(malformed(format!("{} octets after the ID_OID selector", rest.len())));
                }
                Ok(GroupId {
                    key_id: 0,
                    oid: Some(oid),
                    selector,
                })
            }
            t => Err(malformed(format!("group identification of type {t}"))),
        }
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.oid {
            None => write!(f, "group {}", self.key_id),
            Some(oid) if !self.selector.is_empty() => write!(f, "group {oid} [{:02x?}]", self.selector),
            Some(oid) => write!(f, "group {oid}"),
        }
    }
}

/// Encodes the OID Length, OID, OID-Specific Payload Length and OID-Specific
/// Payload fields shared by the ID_OID identification data and the IEC 61850
/// SA TEK (RFC 8052 figures 2 and 4). The OID is its DER encoding, tag and
/// length included.
pub(crate) fn oid_and_selector(oid: &Oid, sel: &[u8]) -> Result<Vec<u8>> {
    let der = oid_elem(TAG_OID, oid).encode();
    if der.len() > 255 || sel.len() > 0xffff {
        return Err(Error::Config("OID or selector too long".into()));
    }
    let mut b = vec![der.len() as u8];
    b.extend_from_slice(&der);
    b.extend_from_slice(&(sel.len() as u16).to_be_bytes());
    b.extend_from_slice(sel);
    Ok(b)
}

/// Reads the fields [`oid_and_selector`] writes and returns what follows
/// them.
pub(crate) fn parse_oid_and_selector(b: &[u8]) -> Result<(Oid, Vec<u8>, &[u8])> {
    if b.is_empty() || usize::from(b[0]) + 3 > b.len() {
        return Err(malformed("truncated OID"));
    }
    let n = usize::from(b[0]);
    let mut d = Decoder::new(&b[1..1 + n]);
    let oid = d
        .expect(TAG_OID)
        .ok()
        .and_then(|c| decode_oid(c).ok())
        .filter(|_| !d.more())
        .ok_or_else(|| malformed("OID is not one DER object identifier"))?;
    let b = &b[1 + n..];
    let sl = usize::from(u16::from_be_bytes([b[0], b[1]]));
    if sl > b.len() - 2 {
        return Err(malformed(format!("selector of {sl} octets, {} remain", b.len() - 2)));
    }
    Ok((oid, b[2..2 + sl].to_vec(), &b[2 + sl..]))
}

/// An IEC 62351-9 authentication algorithm (RFC 8052 2.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AuthAlg(pub u16);

/// An IEC 62351-9 confidentiality algorithm (RFC 8052 2.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EncAlg(pub u16);

impl AuthAlg {
    pub const NONE: AuthAlg = AuthAlg(1);
    pub const HMAC_SHA256_128: AuthAlg = AuthAlg(2);
    pub const HMAC_SHA256: AuthAlg = AuthAlg(3);
    pub const AES_GMAC_128: AuthAlg = AuthAlg(4);
    pub const AES_GMAC_256: AuthAlg = AuthAlg(5);

    /// The length of the keying material RFC 8052 2.3 gives the algorithm:
    /// the key, plus a 4-octet salt for GMAC. `None` for an unknown one.
    fn key_len(self) -> Option<usize> {
        match self {
            AuthAlg::NONE => Some(0),
            AuthAlg::HMAC_SHA256_128 | AuthAlg::HMAC_SHA256 => Some(32),
            AuthAlg::AES_GMAC_128 => Some(20),
            AuthAlg::AES_GMAC_256 => Some(36),
            _ => None,
        }
    }
}

impl EncAlg {
    pub const NONE: EncAlg = EncAlg(1);
    pub const AES_CBC_128: EncAlg = EncAlg(2);
    pub const AES_CBC_256: EncAlg = EncAlg(3);
    pub const AES_GCM_128: EncAlg = EncAlg(4);
    pub const AES_GCM_256: EncAlg = EncAlg(5);

    /// The keying material length, with a 4-octet salt for GCM.
    fn key_len(self) -> Option<usize> {
        match self {
            EncAlg::NONE => Some(0),
            EncAlg::AES_CBC_128 => Some(16),
            EncAlg::AES_CBC_256 => Some(32),
            EncAlg::AES_GCM_128 => Some(20),
            EncAlg::AES_GCM_256 => Some(36),
            _ => None,
        }
    }

    fn authenticated(self) -> bool {
        self == EncAlg::AES_GCM_128 || self == EncAlg::AES_GCM_256
    }
}

impl std::fmt::Display for AuthAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            AuthAlg::NONE => f.write_str("NONE"),
            AuthAlg::HMAC_SHA256_128 => f.write_str("HMAC-SHA256-128"),
            AuthAlg::HMAC_SHA256 => f.write_str("HMAC-SHA256"),
            AuthAlg::AES_GMAC_128 => f.write_str("AES-GMAC-128"),
            AuthAlg::AES_GMAC_256 => f.write_str("AES-GMAC-256"),
            AuthAlg(n) => write!(f, "AuthAlg({n})"),
        }
    }
}

impl std::fmt::Display for EncAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            EncAlg::NONE => f.write_str("NONE"),
            EncAlg::AES_CBC_128 => f.write_str("AES-CBC-128"),
            EncAlg::AES_CBC_256 => f.write_str("AES-CBC-256"),
            EncAlg::AES_GCM_128 => f.write_str("AES-GCM-128"),
            EncAlg::AES_GCM_256 => f.write_str("AES-GCM-256"),
            EncAlg(n) => write!(f, "EncAlg({n})"),
        }
    }
}

// SA TEK attributes (RFC 8052 2.2.4).
const ATTR_SA_ATD: u16 = 1; // SA Time Activation Delay, variable, seconds
const ATTR_SA_KDA: u16 = 2; // Key Delivery Assurance, basic, percent

// KD key packet attributes (RFC 6407 5.6.1).
const ATTR_TEK_ALGORITHM_KEY: u16 = 1;
const ATTR_TEK_INTEGRITY_KEY: u16 = 2;

/// One traffic encryption key of a group with its policy: the traffic it
/// protects (OID and selector), the SPI a receiver finds it by (the IEC 61850
/// key identifier), the algorithms, and the keying material.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Tek {
    pub spi: u32,
    pub oid: Oid,
    pub selector: Vec<u8>,
    pub auth: AuthAlg,
    pub enc: EncAlg,
    /// How long the key has left when it is sent; zero means it does not
    /// expire.
    pub lifetime: Duration,
    /// How long a member waits before using it (SA_ATD), so a key can be
    /// distributed ahead of its use.
    pub activation_delay: Duration,
    /// The Key Delivery Assurance percentage (SA_KDA), `None` when the policy
    /// has none.
    pub kda: Option<u16>,
    /// The confidentiality key (TEK_ALGORITHM_KEY) and the authentication key
    /// (TEK_INTEGRITY_KEY), in the layout RFC 8052 2.3 gives: for GCM and
    /// GMAC, the AES key followed by a 4-octet salt.
    pub algorithm_key: Vec<u8>,
    pub integrity_key: Vec<u8>,
}

impl std::fmt::Debug for Tek {
    // The keys stay out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tek")
            .field("spi", &self.spi)
            .field("oid", &self.oid)
            .field("selector", &self.selector)
            .field("auth", &self.auth)
            .field("enc", &self.enc)
            .field("lifetime", &self.lifetime)
            .field("activation_delay", &self.activation_delay)
            .field("kda", &self.kda)
            .finish_non_exhaustive()
    }
}

impl Tek {
    /// Makes a TEK with a random SPI and fresh keying material for the
    /// algorithms. A key server rotating keys makes a new one per rotation.
    pub fn new(oid: impl Into<Oid>, selector: Vec<u8>, auth: AuthAlg, enc: EncAlg, lifetime: Duration) -> Result<Tek> {
        let (Some(al), Some(el)) = (auth.key_len(), enc.key_len()) else {
            return Err(Error::Policy(format!("unknown algorithm {auth}/{enc}")));
        };
        let mut spi = 0;
        while spi == 0 {
            spi = u32::from_be_bytes(random_bytes(4).try_into().expect("4 octets"));
        }
        let t = Tek {
            spi,
            oid: oid.into(),
            selector,
            auth,
            enc,
            lifetime,
            activation_delay: Duration::ZERO,
            kda: None,
            algorithm_key: random_bytes(el),
            integrity_key: random_bytes(al),
        };
        t.check_policy()?;
        Ok(t)
    }

    /// Validates the algorithm combination and key lengths RFC 8052 requires.
    pub fn check_policy(&self) -> Result<()> {
        let (Some(al), Some(el)) = (self.auth.key_len(), self.enc.key_len()) else {
            return Err(Error::Policy(format!("unknown algorithm {}/{}", self.auth, self.enc)));
        };
        if self.spi == 0 {
            return Err(Error::Policy("SPI 0".into()));
        }
        if self.enc.authenticated() && self.auth != AuthAlg::NONE {
            return Err(Error::Policy(format!("{} is used with authentication NONE", self.enc)));
        }
        if (self.enc == EncAlg::AES_CBC_128 || self.enc == EncAlg::AES_CBC_256) && self.auth == AuthAlg::NONE {
            return Err(Error::Policy(format!(
                "{} provides no authentication and needs an authentication algorithm",
                self.enc
            )));
        }
        if self.enc == EncAlg::NONE && self.auth == AuthAlg::NONE {
            return Err(Error::Policy("neither authentication nor confidentiality".into()));
        }
        if self.integrity_key.len() != al || self.algorithm_key.len() != el {
            return Err(Error::Policy(format!(
                "keying material {}/{} octets, {}/{} take {al}/{el}",
                self.integrity_key.len(),
                self.algorithm_key.len(),
                self.auth,
                self.enc
            )));
        }
        Ok(())
    }

    /// The key the IEC 61850-90-5 session layer ([`crate::rsession`]) uses for
    /// this TEK: the SPI is the key identifier, HMAC-SHA256-128 and
    /// HMAC-SHA256 sign, AES-GCM-128 and AES-GCM-256 encrypt. The GCM salt is
    /// not used: the session protocol carries a whole random IV in every SPDU.
    /// AES-CBC and AES-GMAC TEKs have no session-layer counterpart and are
    /// refused with [`Error::Unsupported`].
    pub fn rsession_key(&self) -> Result<rsession::Key> {
        let mut k = rsession::Key {
            id: self.spi,
            ..Default::default()
        };
        match (self.enc, self.auth) {
            (EncAlg::AES_GCM_128, AuthAlg::NONE) => {
                k.sec = SecAlgorithm::AES_128_GCM;
                k.material = self.algorithm_key[..16].to_vec();
            }
            (EncAlg::AES_GCM_256, AuthAlg::NONE) => {
                k.sec = SecAlgorithm::AES_256_GCM;
                k.material = self.algorithm_key[..32].to_vec();
            }
            (EncAlg::NONE, AuthAlg::HMAC_SHA256_128) => {
                k.sig = SigAlgorithm::HMAC_SHA256_128;
                k.material = self.integrity_key.clone();
            }
            (EncAlg::NONE, AuthAlg::HMAC_SHA256) => {
                k.sig = SigAlgorithm::HMAC_SHA256_256;
                k.material = self.integrity_key.clone();
            }
            (enc, auth) => return Err(Error::Unsupported(format!("{auth}/{enc}"))),
        }
        Ok(k)
    }

    /// Encodes the TEK's policy as an IEC 61850 SA TEK payload body (RFC 8052
    /// figure 4).
    fn sat_body(&self) -> Result<Vec<u8>> {
        let mut b = vec![PROTO_IEC61850];
        b.extend_from_slice(&oid_and_selector(&self.oid, &self.selector)?);
        b.extend_from_slice(&self.spi.to_be_bytes());
        b.extend_from_slice(&self.auth.0.to_be_bytes());
        b.extend_from_slice(&self.enc.0.to_be_bytes());
        b.extend_from_slice(&seconds(self.lifetime).to_be_bytes());
        let mut attrs = Vec::new();
        if !self.activation_delay.is_zero() {
            attrs.push(Attribute::uint32(ATTR_SA_ATD, seconds(self.activation_delay)));
        }
        if let Some(kda) = self.kda {
            attrs.push(Attribute::basic(ATTR_SA_KDA, kda));
        }
        b.extend_from_slice(&encode_attrs(&attrs));
        Ok(b)
    }
}

/// Rounds a duration up to whole seconds, so a remaining lifetime is never
/// reported as zero ("does not expire") while time remains.
fn seconds(d: Duration) -> u32 {
    if d.is_zero() {
        return 0;
    }
    let s = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    u32::try_from(s).unwrap_or(u32::MAX)
}

/// Decodes an SA TEK payload body. A TEK of another protocol than IEC 61850
/// is `None`, to be skipped.
pub(crate) fn parse_sat(b: &[u8]) -> Result<Option<Tek>> {
    let Some((&proto, rest)) = b.split_first() else {
        return Err(malformed("empty SA TEK"));
    };
    if proto != PROTO_IEC61850 {
        return Ok(None);
    }
    let (oid, selector, rest) = parse_oid_and_selector(rest)?;
    if rest.len() < 12 {
        return Err(malformed(format!("SA TEK policy of {} octets", rest.len())));
    }
    let mut t = Tek {
        spi: u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
        oid,
        selector,
        auth: AuthAlg(u16::from_be_bytes([rest[4], rest[5]])),
        enc: EncAlg(u16::from_be_bytes([rest[6], rest[7]])),
        lifetime: Duration::from_secs(u64::from(u32::from_be_bytes([rest[8], rest[9], rest[10], rest[11]]))),
        ..Default::default()
    };
    for a in parse_attrs(&rest[12..])? {
        match a.kind {
            ATTR_SA_ATD => {
                if a.value.len() > 8 {
                    return Err(malformed(format!("SA_ATD of {} octets", a.value.len())));
                }
                t.activation_delay = Duration::from_secs(a.uint());
            }
            ATTR_SA_KDA => t.kda = Some(a.uint() as u16),
            _ => {}
        }
    }
    Ok(Some(t))
}

/// Encodes the GDOI SA payload body with its SA TEK payloads (RFC 6407 5.2):
/// DOI, situation 0, the type of the first SA attribute payload, and the
/// chain of SA TEKs.
pub(crate) fn sa_body(teks: &[Tek]) -> Result<Vec<u8>> {
    if teks.is_empty() {
        return Err(Error::Config("a group policy needs at least one TEK".into()));
    }
    let sats = teks
        .iter()
        .map(|t| Ok(Payload::new(P_SAT, t.sat_body()?)))
        .collect::<Result<Vec<_>>>()?;
    let mut b = DOI_GDOI.to_be_bytes().to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&u16::from(P_SAT).to_be_bytes());
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&encode_chain(&sats, P_NONE));
    Ok(b)
}

/// Decodes a GDOI SA payload body into its IEC 61850 TEKs. SA KEK and GAP
/// payloads are skipped: this member does not take GROUPKEY-PUSH rekeys, and
/// re-registers instead.
pub(crate) fn parse_sa(b: &[u8]) -> Result<Vec<Tek>> {
    if b.len() < 12 {
        return Err(malformed(format!("SA of {} octets", b.len())));
    }
    let doi = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    if doi != DOI_GDOI {
        return Err(malformed(format!("SA DOI {doi}, not GDOI")));
    }
    let first = u16::from_be_bytes([b[8], b[9]]);
    let first = u8::try_from(first).map_err(|_| malformed(format!("SA attribute payload type {first}")))?;
    let (ps, _) = parse_chain(&b[12..], first)?;
    let mut teks = Vec::new();
    for p in ps.iter().filter(|p| p.kind == P_SAT) {
        if let Some(t) = parse_sat(&p.body)? {
            teks.push(t);
        }
    }
    Ok(teks)
}

/// Encodes a Key Download payload body carrying the keys of `teks` (RFC 6407
/// 5.6, RFC 8052 2.3).
pub(crate) fn kd_body(teks: &[Tek]) -> Vec<u8> {
    let mut b = (teks.len() as u16).to_be_bytes().to_vec();
    b.extend_from_slice(&[0, 0]);
    for t in teks {
        let mut attrs = Vec::new();
        if !t.algorithm_key.is_empty() {
            attrs.push(Attribute::variable(ATTR_TEK_ALGORITHM_KEY, t.algorithm_key.clone()));
        }
        if !t.integrity_key.is_empty() {
            attrs.push(Attribute::variable(ATTR_TEK_INTEGRITY_KEY, t.integrity_key.clone()));
        }
        let attrs = encode_attrs(&attrs);
        b.extend_from_slice(&[KD_TYPE_TEK, 0]);
        b.extend_from_slice(&((4 + 1 + 4 + attrs.len()) as u16).to_be_bytes());
        b.push(4);
        b.extend_from_slice(&t.spi.to_be_bytes());
        b.extend_from_slice(&attrs);
    }
    b
}

/// The keying material of one SPI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeyPacket {
    pub algorithm: Vec<u8>,
    pub integrity: Vec<u8>,
}

/// Decodes a Key Download payload body into the TEK keys by SPI.
pub(crate) fn parse_kd(b: &[u8]) -> Result<HashMap<u32, KeyPacket>> {
    if b.len() < 4 {
        return Err(malformed(format!("KD of {} octets", b.len())));
    }
    let n = usize::from(u16::from_be_bytes([b[0], b[1]]));
    let mut out = HashMap::new();
    let mut off = 4;
    for _ in 0..n {
        if b.len() - off < 5 {
            return Err(malformed("truncated key packet"));
        }
        let kind = b[off];
        let kl = usize::from(u16::from_be_bytes([b[off + 2], b[off + 3]]));
        if kl < 5 || kl > b.len() - off {
            return Err(malformed(format!("key packet of {kl} octets, {} remain", b.len() - off)));
        }
        let kp = &b[off..off + kl];
        off += kl;
        if kind != KD_TYPE_TEK {
            continue;
        }
        let spi_size = usize::from(kp[4]);
        if spi_size != 4 || 5 + spi_size > kp.len() {
            return Err(malformed(format!("TEK key packet with a {spi_size}-octet SPI")));
        }
        let spi = u32::from_be_bytes([kp[5], kp[6], kp[7], kp[8]]);
        let mut p = KeyPacket::default();
        for a in parse_attrs(&kp[9..])? {
            match a.kind {
                ATTR_TEK_ALGORITHM_KEY => p.algorithm = a.value,
                ATTR_TEK_INTEGRITY_KEY => p.integrity = a.value,
                _ => {}
            }
        }
        out.insert(spi, p);
    }
    Ok(out)
}
