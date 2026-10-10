use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::Sha3_256;

use super::{Error, Key, KeyStore, Result, SecAlgorithm, SigAlgorithm};

/// The session identifier (SI) of an SPDU: what kind of application data it
/// carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SessionId(pub u8);

impl SessionId {
    pub const TUNNELLED: SessionId = SessionId(0xa0);
    pub const GOOSE: SessionId = SessionId(0xa1);
    pub const SV: SessionId = SessionId(0xa2);
    pub const MANAGEMENT: SessionId = SessionId(0xa3);
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            SessionId::TUNNELLED => f.write_str("tunnelled"),
            SessionId::GOOSE => f.write_str("GOOSE"),
            SessionId::SV => f.write_str("SV"),
            SessionId::MANAGEMENT => f.write_str("management"),
            SessionId(n) => write!(f, "SessionId({n:#04x})"),
        }
    }
}

/// Tags one application PDU inside the session user data: the session
/// identifier's low nibble with the high bit set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PayloadType(pub u8);

impl PayloadType {
    pub const TUNNELLED: PayloadType = PayloadType(0x80);
    pub const GOOSE: PayloadType = PayloadType(0x81);
    pub const SV: PayloadType = PayloadType(0x82);
    pub const MANAGEMENT: PayloadType = PayloadType(0x83);
}

/// One application PDU: a goosePdu or savPdu without the layer-2 header,
/// whose APPID and simulation flag the session carries instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Payload {
    pub kind: PayloadType,
    pub simulation: bool,
    pub app_id: u16,
    pub apdu: Vec<u8>,
}

/// A decoded session protocol data unit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Spdu {
    pub si: SessionId,
    /// Increments with every SPDU a sender sends.
    pub number: u32,
    /// The protocol version, 1 or 2; 0 marshals as 2.
    pub version: u16,
    /// The key the SPDU is secured with; 0 when it is not secured.
    pub key_id: u32,
    pub time_of_current_key: u32,
    pub time_to_next_key: i16,
    pub payloads: Vec<Payload>,
    /// How the SPDU was protected. Set by [`unmarshal`] and ignored by
    /// [`marshal`], which protects an SPDU as its key says.
    pub signed: bool,
    pub encrypted: bool,
}

// Wire constants.
const CLTP_LI: u8 = 0x01; // connectionless transport: length indicator
const CLTP_UD: u8 = 0x40; // connectionless transport: unit data TPDU
const TAG_COMMON: u8 = 0x80; // common session header parameter
pub(crate) const COMMON_LEN: u8 = 10; // SPDU length, SPDU number, version
const TAG_SIGNATURE: u8 = 0x85; // MAC or GCM tag after the user data
const TAG_PADDING: u8 = 0xaf; // padding before the signature
const ELEMENT_HEADER: usize = 6; // payload type, simulation, APPID, APDU length
pub(crate) const GCM_IV_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;

/// Encodes an SPDU secured with `key`: signed when the key has an
/// authentication algorithm, encrypted when it has an encryption one, and
/// neither when `key` is `None`. The version is `s.version` (2 when 0); the
/// key ID, the key times and the signed and encrypted flags are taken from
/// `key`, not from `s`. The GCM initialisation vector is random.
///
/// The layout, in network byte order:
///
/// ```text
/// 01 40                          connectionless transport header
/// SI LI                          session identifier, session header length
/// 80 0A len(4) number(4) ver(2)  common session header
/// security information:
///   v1: timeOfCurrentKey(4) timeToNextKey(2) sec(1) sig(1) keyID(4)
///   v2: timeOfCurrentKey(4) timeToNextKey(2) keyID(4) ivLen(1) iv
/// payload length(4)
/// { type(1) simulation(1) APPID(2) APDU length(2) APDU }...
/// 85 len MAC                     when signed or encrypted
/// ```
///
/// A MAC covers everything before its tag. Encryption covers the payload
/// elements, with everything before them as additional authenticated data,
/// and puts the GCM tag in the trailer.
pub fn marshal(s: &Spdu, key: Option<&Key>) -> Result<Vec<u8>> {
    let mut iv = [0u8; GCM_IV_LEN];
    if key.is_some_and(|k| k.sec != SecAlgorithm::NONE) {
        getrandom::getrandom(&mut iv).map_err(|e| Error::Random(e.to_string()))?;
    }
    marshal_with_iv(s, key, iv)
}

pub(crate) fn marshal_with_iv(s: &Spdu, key: Option<&Key>, iv: [u8; GCM_IV_LEN]) -> Result<Vec<u8>> {
    let version = if s.version == 0 { 2 } else { s.version };
    if version != 1 && version != 2 {
        return Err(Error::Version(version));
    }
    if let Some(k) = key {
        k.validate()?;
        if version == 1 && k.sec != SecAlgorithm::NONE {
            return Err(Error::Version1Encrypt);
        }
    }
    let encrypt = key.is_some_and(|k| k.sec != SecAlgorithm::NONE);
    let iv: &[u8] = if encrypt { &iv } else { &[] };

    let mut user_len = 0usize;
    for p in &s.payloads {
        if p.apdu.len() > 0xffff {
            return Err(Error::Malformed(format!(
                "APDU of {} octets exceeds the 16-bit length",
                p.apdu.len()
            )));
        }
        user_len += ELEMENT_HEADER + p.apdu.len();
    }
    let sec_info_len = if version == 2 { 11 + iv.len() } else { 12 };
    let trailer = match key {
        None => 0,
        Some(k) if encrypt => {
            let _ = k;
            2 + GCM_TAG_LEN
        }
        Some(k) => 2 + k.sig.mac_len(),
    };
    let session_hdr_len = 2 + usize::from(COMMON_LEN) + sec_info_len;
    let total = 2 + 2 + session_hdr_len + 4 + user_len + trailer;
    let mut b = Vec::with_capacity(total);

    b.extend_from_slice(&[CLTP_LI, CLTP_UD, s.si.0, session_hdr_len as u8, TAG_COMMON, COMMON_LEN]);
    // The SPDU length counts the octets that follow it.
    let spdu_len = (total - b.len() - 4) as u32;
    b.extend_from_slice(&spdu_len.to_be_bytes());
    b.extend_from_slice(&s.number.to_be_bytes());
    b.extend_from_slice(&version.to_be_bytes());
    let (key_id, tock, ttnk) = key.map_or((0, 0, 0), |k| (k.id, k.time_of_current_key, k.time_to_next_key));
    b.extend_from_slice(&tock.to_be_bytes());
    b.extend_from_slice(&ttnk.to_be_bytes());
    if version == 1 {
        let (sec, sig) = key.map_or((0, 0), |k| (k.sec.0, k.sig.0));
        b.extend_from_slice(&[sec, sig]);
        b.extend_from_slice(&key_id.to_be_bytes());
    } else {
        b.extend_from_slice(&key_id.to_be_bytes());
        b.push(iv.len() as u8);
        b.extend_from_slice(iv);
    }
    b.extend_from_slice(&(user_len as u32).to_be_bytes());
    let user_start = b.len();
    for p in &s.payloads {
        b.extend_from_slice(&[p.kind.0, u8::from(p.simulation)]);
        b.extend_from_slice(&p.app_id.to_be_bytes());
        b.extend_from_slice(&(p.apdu.len() as u16).to_be_bytes());
        b.extend_from_slice(&p.apdu);
    }

    match key {
        None => {}
        Some(k) if encrypt => {
            let sealed = gcm_seal(k, iv, &b[user_start..], &b[..user_start])?;
            let (ct, tag) = sealed.split_at(sealed.len() - GCM_TAG_LEN);
            b.truncate(user_start);
            b.extend_from_slice(ct);
            b.extend_from_slice(&[TAG_SIGNATURE, GCM_TAG_LEN as u8]);
            b.extend_from_slice(tag);
        }
        Some(k) => {
            let mac = compute_mac(k, &b);
            b.extend_from_slice(&[TAG_SIGNATURE, mac.len() as u8]);
            b.extend_from_slice(&mac);
        }
    }
    Ok(b)
}

/// Decodes and verifies an SPDU.
///
/// A secured SPDU is checked with the key it names, which `keys` must hold:
/// its MAC or GCM tag must verify, and in version 1 the algorithms it declares
/// must be the key's. An unsecured SPDU (key ID 0) is decoded and returned as
/// it is: whether to accept one is the caller's policy
/// ([`Session`](super::Session) refuses them unless told otherwise).
///
/// The session and common header lengths and the SPDU length are not relied
/// on, since implementations disagree on what they count; the fields are read
/// in order and every length that delimits data is bounds checked. An element
/// whose APDU length exceeds what remains by exactly two octets is accepted,
/// as libiec61850 writes one (it counts the length field itself).
pub fn unmarshal(b: &[u8], keys: Option<&KeyStore>) -> Result<Spdu> {
    let mut r = Reader { b, off: 0, short: false };
    if r.u8() != CLTP_LI || r.u8() != CLTP_UD {
        return Err(Error::Malformed("not a connectionless transport unit".into()));
    }
    let mut s = Spdu {
        si: SessionId(r.u8()),
        ..Default::default()
    };
    r.u8(); // session header length
    if r.u8() != TAG_COMMON {
        return Err(Error::Malformed("no common session header".into()));
    }
    r.u8(); // common header length
    r.u32(); // SPDU length
    s.number = r.u32();
    s.version = r.u16();
    s.time_of_current_key = r.u32();
    s.time_to_next_key = r.u16() as i16;
    if r.short {
        return Err(Error::Malformed("truncated session header".into()));
    }

    let lookup = |id: u32| keys.and_then(|k| k.lookup(id)).ok_or(Error::UnknownKey(id));
    let mut key = None;
    let mut iv: &[u8] = &[];
    match s.version {
        1 => {
            let (sec, sig) = (SecAlgorithm(r.u8()), SigAlgorithm(r.u8()));
            s.key_id = r.u32();
            if r.short {
                return Err(Error::Malformed("truncated security information".into()));
            }
            if s.key_id == 0 {
                if sec != SecAlgorithm::NONE || sig != SigAlgorithm::NONE {
                    return Err(Error::Malformed("algorithms without a key".into()));
                }
            } else {
                let k = lookup(s.key_id)?;
                // The declared algorithms must be the key's, or a forged
                // header could ask for a weaker check than the key is used
                // with.
                if sec != k.sec || sig != k.sig {
                    return Err(Error::Algorithm(format!(
                        "SPDU declares {sec}/{sig}, key {} is {}/{}",
                        s.key_id, k.sec, k.sig
                    )));
                }
                key = Some(k);
            }
        }
        2 => {
            s.key_id = r.u32();
            let iv_len = usize::from(r.u8());
            iv = r.bytes(iv_len);
            if r.short {
                return Err(Error::Malformed("truncated security information".into()));
            }
            if s.key_id != 0 {
                let k = lookup(s.key_id)?;
                if k.sec != SecAlgorithm::NONE && iv_len != GCM_IV_LEN {
                    return Err(Error::Malformed(format!(
                        "{iv_len}-octet initialisation vector, GCM uses {GCM_IV_LEN}"
                    )));
                }
                key = Some(k);
            }
        }
        v => return Err(Error::Version(v)),
    }

    let ul = r.u32() as usize;
    if r.short || ul > b.len() - r.off {
        return Err(Error::Malformed(format!("payload length {ul} exceeds the SPDU")));
    }
    let user_start = r.off;
    let user_end = user_start + ul;
    let mut user: std::borrow::Cow<[u8]> = std::borrow::Cow::Borrowed(&b[user_start..user_end]);

    match &key {
        None if user_end != b.len() => {
            // Nothing follows the user data of an unsecured SPDU. A trailer
            // here is a secured SPDU whose key identifier was cleared, and is
            // refused as such rather than read as unsecured.
            return Err(Error::Malformed(format!(
                "{} octets after the user data of an unsecured SPDU",
                b.len() - user_end
            )));
        }
        None => {}
        Some(k) => {
            let mut trailer = &b[user_end..];
            // Padding may precede the trailer.
            if trailer.len() >= 2 && trailer[0] == TAG_PADDING {
                let n = 2 + usize::from(trailer[1]);
                if n > trailer.len() {
                    return Err(Error::Malformed("truncated padding".into()));
                }
                trailer = &trailer[n..];
            }
            let sig_pos = b.len() - trailer.len();
            if trailer.len() < 2 || trailer[0] != TAG_SIGNATURE {
                return Err(Error::Authentication("no signature trailer".into()));
            }
            let n = usize::from(trailer[1]);
            if 2 + n > trailer.len() {
                return Err(Error::Malformed("truncated signature".into()));
            }
            let tag = &trailer[2..2 + n];
            if k.sec != SecAlgorithm::NONE {
                if n != GCM_TAG_LEN {
                    return Err(Error::Authentication(format!("{n}-octet GCM tag")));
                }
                let mut sealed = Vec::with_capacity(user.len() + GCM_TAG_LEN);
                sealed.extend_from_slice(&user);
                sealed.extend_from_slice(tag);
                let plain = gcm_open(k, iv, &sealed, &b[..user_start])
                    .map_err(|_| Error::Authentication("GCM tag does not verify".into()))?;
                user = std::borrow::Cow::Owned(plain);
                s.encrypted = true;
            } else {
                if n != k.sig.mac_len() {
                    return Err(Error::Authentication(format!(
                        "{n}-octet MAC, {} is {}",
                        k.sig,
                        k.sig.mac_len()
                    )));
                }
                if !verify_mac(k, &b[..sig_pos], tag) {
                    return Err(Error::Authentication("MAC does not verify".into()));
                }
                s.signed = true;
            }
        }
    }

    let mut off = 0;
    while off < user.len() {
        if user.len() - off < ELEMENT_HEADER {
            return Err(Error::Malformed("truncated payload element".into()));
        }
        let h = &user[off..off + ELEMENT_HEADER];
        let mut n = usize::from(u16::from_be_bytes([h[4], h[5]]));
        let mut p = Payload {
            kind: PayloadType(h[0]),
            simulation: h[1] != 0,
            app_id: u16::from_be_bytes([h[2], h[3]]),
            apdu: Vec::new(),
        };
        off += ELEMENT_HEADER;
        let rest = user.len() - off;
        if n > rest {
            if n != rest + 2 {
                return Err(Error::Malformed(format!("APDU of {n} octets, {rest} remain")));
            }
            n = rest;
        }
        p.apdu = user[off..off + n].to_vec();
        off += n;
        s.payloads.push(p);
    }
    Ok(s)
}

fn gcm_seal(k: &Key, iv: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(iv);
    let msg = AeadPayload { msg: plain, aad };
    let out = match k.sec {
        SecAlgorithm::AES_128_GCM => Aes128Gcm::new_from_slice(&k.material)
            .map_err(|e| Error::KeyLength(e.to_string()))?
            .encrypt(nonce, msg),
        _ => Aes256Gcm::new_from_slice(&k.material)
            .map_err(|e| Error::KeyLength(e.to_string()))?
            .encrypt(nonce, msg),
    };
    out.map_err(|_| Error::Authentication("GCM encryption failed".into()))
}

fn gcm_open(k: &Key, iv: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(iv);
    let msg = AeadPayload { msg: sealed, aad };
    let out = match k.sec {
        SecAlgorithm::AES_128_GCM => Aes128Gcm::new_from_slice(&k.material)
            .map_err(|e| Error::KeyLength(e.to_string()))?
            .decrypt(nonce, msg),
        _ => Aes256Gcm::new_from_slice(&k.material)
            .map_err(|e| Error::KeyLength(e.to_string()))?
            .decrypt(nonce, msg),
    };
    out.map_err(|_| Error::Authentication("GCM tag does not verify".into()))
}

/// The full HMAC of `data` under `key`, before truncation.
fn full_mac(key: &Key, data: &[u8]) -> Vec<u8> {
    if key.sig.is_sha3() {
        let mut m = <Hmac<Sha3_256> as Mac>::new_from_slice(&key.material).expect("HMAC takes any key");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    } else {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&key.material).expect("HMAC takes any key");
        m.update(data);
        m.finalize().into_bytes().to_vec()
    }
}

/// The truncated HMAC of `data` under `key`.
pub(crate) fn compute_mac(key: &Key, data: &[u8]) -> Vec<u8> {
    let mut m = full_mac(key, data);
    m.truncate(key.sig.mac_len());
    m
}

/// Compares the MAC in constant time.
fn verify_mac(key: &Key, data: &[u8], tag: &[u8]) -> bool {
    let want = compute_mac(key, data);
    want.len() == tag.len() && want.iter().zip(tag).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Reads big-endian fields, recording a read past the end instead of
/// panicking.
struct Reader<'a> {
    b: &'a [u8],
    off: usize,
    short: bool,
}

impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> &'a [u8] {
        if self.short || n > self.b.len() - self.off {
            self.short = true;
            return &[];
        }
        let v = &self.b[self.off..self.off + n];
        self.off += n;
        v
    }

    fn u8(&mut self) -> u8 {
        self.bytes(1).first().copied().unwrap_or(0)
    }

    fn u16(&mut self) -> u16 {
        match self.bytes(2) {
            [a, b] => u16::from_be_bytes([*a, *b]),
            _ => 0,
        }
    }

    fn u32(&mut self) -> u32 {
        match self.bytes(4) {
            [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
            _ => 0,
        }
    }
}
