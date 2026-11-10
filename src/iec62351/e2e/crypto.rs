use super::codec::AlgorithmIdentifier as Alg;
use super::{AeTitle, Error, Phase, Result};
use crate::{
    asn1::{self, Decoder, TAG_BIT_STRING, TAG_INTEGER, TAG_OID, TAG_SEQUENCE as SEQ, TAG_SET},
    x509,
};
use aes_gcm::{
    aead::{
        consts::{U12, U16},
        AeadInPlace, KeyInit,
    },
    aes::{Aes128, Aes256},
    AesGcm,
};
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Encoding, U2048, U512,
};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::zeroize::Zeroizing;
use rustls::{pki_types::PrivateKeyDer, SignatureScheme};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) fn random(n: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; n];
    getrandom::getrandom(&mut bytes).map_err(|e| Error::hs(0, e.to_string()))?;
    Ok(bytes)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    Modp2048,
    P256,
}
impl Group {
    pub(crate) fn code(self) -> i64 {
        match self {
            Self::Modp2048 => 14,
            Self::P256 => 23,
        }
    }
    pub(crate) fn from_code(c: i64) -> Result<Self> {
        match c {
            14 => Ok(Self::Modp2048),
            23 => Ok(Self::P256),
            _ => Err(Error::hs(11, "DH group not supported")),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcvAlgorithm {
    HmacSha256,
    GmacAes128,
    GmacAes256,
}
impl IcvAlgorithm {
    pub(crate) fn key_len(self) -> usize {
        if self == Self::GmacAes128 {
            16
        } else {
            32
        }
    }
    pub(crate) fn id(self, corrected: bool) -> Alg {
        match self {
            Self::HmacSha256 => hmac_id(),
            Self::GmacAes128 => Alg::new(
                &[2, 16, 840, 1, 101, 3, 4, 1, if corrected { 9 } else { 6 }],
                None,
            ),
            Self::GmacAes256 => Alg::new(
                &[2, 16, 840, 1, 101, 3, 4, 1, if corrected { 49 } else { 46 }],
                None,
            ),
        }
    }
    pub(crate) fn from_id(a: &Alg) -> Option<Self> {
        if a.oid == hmac_id().oid && a.null_or_absent() {
            return Some(Self::HmacSha256);
        }
        let alg = match a.oid.arcs() {
            [2, 16, 840, 1, 101, 3, 4, 1, 6 | 9] => Self::GmacAes128,
            [2, 16, 840, 1, 101, 3, 4, 1, 46 | 49] => Self::GmacAes256,
            _ => return None,
        };
        if let Some(params) = &a.parameters {
            let valid = (|| -> asn1::Result<bool> {
                let mut outer = Decoder::new(params);
                let mut d = Decoder::new(outer.expect(SEQ)?);
                d.expect(asn1::TAG_OCTET_STRING)?;
                let n = d
                    .optional(TAG_INTEGER)?
                    .map(asn1::decode_int)
                    .transpose()?
                    .unwrap_or(12);
                Ok(!outer.more() && !d.more() && n == 12)
            })();
            if !matches!(valid, Ok(true)) {
                return None;
            }
        }
        Some(alg)
    }
    pub(crate) fn mac(self, key: &[u8], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        if self == Self::HmacSha256 {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                .map_err(|_| Error::data(1, "HMAC key"))?;
            mac.update(data);
            return Ok(mac.finalize().into_bytes().to_vec());
        }
        if nonce.len() != 12 && nonce.len() != 16 {
            return Err(Error::data(6, "GMAC nonce must be 12 or 16 octets"));
        }
        macro_rules! gmac {
            ($aes:ty,$n:ty) => {{
                let c = AesGcm::<$aes, $n, U12>::new_from_slice(key)
                    .map_err(|_| Error::data(1, "GMAC key"))?;
                c.encrypt_in_place_detached(nonce.into(), data, &mut [])
                    .map(|t| t.to_vec())
                    .map_err(|_| Error::data(1, "GMAC"))
            }};
        }
        match (self, nonce.len()) {
            (Self::GmacAes128, 12) => gmac!(Aes128, U12),
            (Self::GmacAes128, 16) => gmac!(Aes128, U16),
            (Self::GmacAes256, 12) => gmac!(Aes256, U12),
            (Self::GmacAes256, 16) => gmac!(Aes256, U16),
            _ => Err(Error::data(1, "GMAC parameters")),
        }
    }
}
pub(crate) fn hmac_id() -> Alg {
    Alg::new(&[1, 2, 840, 113549, 2, 9], Some(vec![5, 0]))
}
pub(crate) fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().to_vec()
}
pub(crate) fn derive(alg: IcvAlgorithm, salt: &[u8], secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let hmac = |key: &[u8], data: &[u8]| {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
        m.update(data);
        m.finalize().into_bytes().to_vec()
    };
    let prk = Zeroizing::new(hmac(salt, secret));
    let first = Zeroizing::new(hmac(&prk, &[1]));
    let second = Zeroizing::new(hmac(&prk, &[first.as_slice(), &[2]].concat()));
    let bytes = Zeroizing::new([first.as_slice(), second.as_slice()].concat());
    let n = alg.key_len();
    (bytes[..n].to_vec(), bytes[n..2 * n].to_vec())
}
pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
    use p256::elliptic_curve::subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// Signing credential. AE identity is read from the Annex G certificate subject.
pub struct Identity {
    pub ae: AeTitle,
    pub certificate: Vec<u8>,
    pub path: Vec<Vec<u8>>,
    key: Arc<dyn rustls::sign::SigningKey>,
    pub(crate) signature: Alg,
}
impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("ae", &self.ae)
            .finish_non_exhaustive()
    }
}
impl Identity {
    pub fn new(
        certificate: Vec<u8>,
        key: PrivateKeyDer<'static>,
        path: Vec<Vec<u8>>,
    ) -> Result<Self> {
        let ae = profile(&certificate, false)?;
        let cert = x509::parse(&certificate).map_err(|e| Error::hs(8, e.to_string()))?;
        let signature = match cert.public_key {
            x509::PublicKey::Rsa { .. } => {
                Alg::new(&[1, 2, 840, 113549, 1, 1, 11], Some(vec![5, 0]))
            }
            _ => Alg::new(&[1, 2, 840, 10045, 4, 3, 2], None),
        };
        let key = super::super::provider()
            .key_provider
            .load_private_key(key)
            .map_err(|e| Error::hs(8, e.to_string()))?;
        let id = Self {
            ae,
            certificate,
            path,
            key,
            signature,
        };
        verify(&cert, &id.signature, b"key check", &id.sign(b"key check")?)?;
        Ok(id)
    }
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.key
            .choose_scheme(&[scheme(&self.signature)?])
            .ok_or_else(|| Error::hs(3, "unsupported signing key"))?
            .sign(data)
            .map_err(|e| Error::hs(3, e.to_string()))
    }
}
fn scheme(a: &Alg) -> Result<SignatureScheme> {
    match a.oid.arcs() {
        [1, 2, 840, 113549, 1, 1, 11] if a.null_or_absent() => {
            Ok(SignatureScheme::RSA_PKCS1_SHA256)
        }
        [1, 2, 840, 10045, 4, 3, 2] if a.parameters.is_none() => {
            Ok(SignatureScheme::ECDSA_NISTP256_SHA256)
        }
        _ => Err(Error::hs(3, "invalid signature algorithm")),
    }
}
pub(crate) fn verify(cert: &x509::Certificate, alg: &Alg, data: &[u8], sig: &[u8]) -> Result<()> {
    let scheme = scheme(alg)?;
    let provider = super::super::provider();
    let valid = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .filter(|(s, _)| *s == scheme)
        .flat_map(|(_, a)| a.iter())
        .any(|a| {
            a.public_key_alg_id().as_ref() == cert.spki_alg.as_slice()
                && a.verify_signature(&cert.spki_key, data, sig).is_ok()
        });
    if valid {
        Ok(())
    } else {
        Err(Error::alarm(Phase::Handshake, "invalid signature"))
    }
}

/// Validate Annex G constraints and return the subject's form-2 AE title.
pub fn profile(der: &[u8], any_attribute: bool) -> Result<AeTitle> {
    profile_inner(der, any_attribute).map_err(|mut e| {
        e.diagnostic = Some(8);
        e
    })
}
fn profile_inner(der: &[u8], any_attribute: bool) -> Result<AeTitle> {
    if der.len() > 8192 {
        return Err(Error::hs(8, "certificate exceeds 8192 octets"));
    }
    let c = x509::parse(der).map_err(|e| Error::hs(8, e.to_string()))?;
    if c.version != 3
        || c.serial.is_empty()
        || c.serial[0] & 0x80 != 0
        || c.serial.iter().all(|b| *b == 0)
    {
        return Err(Error::hs(8, "certificate version or serial"));
    }
    match &c.public_key {
        x509::PublicKey::Rsa { .. } if c.public_key.rsa_bits().unwrap_or(0) >= 2048 => {}
        x509::PublicKey::Ec {
            curve: x509::Curve::P256,
            ..
        } => {}
        _ => return Err(Error::hs(8, "certificate key must be RSA >=2048 or P-256")),
    }
    let sig_oid = asn1::decode_oid(Decoder::new(&c.signed.algorithm).expect(TAG_OID)?)?;
    if !matches!(
        sig_oid.arcs(),
        [1, 2, 840, 113549, 1, 1, 10..=13] | [1, 2, 840, 10045, 4, 3, 2..=4]
    ) {
        return Err(Error::hs(
            8,
            "certificate requires SHA-256 or stronger signature",
        ));
    }
    if sig_oid.arcs() == [1, 2, 840, 113549, 1, 1, 10] {
        let mut algorithm = Decoder::new(&c.signed.algorithm);
        algorithm.expect(TAG_OID)?;
        let mut parameters = Decoder::new(algorithm.expect(SEQ)?);
        let hash = parameters
            .optional(asn1::context_constructed(0))?
            .ok_or_else(|| Error::hs(8, "RSA-PSS defaults to SHA-1"))?;
        let mut hash = Decoder::new(Decoder::new(hash).expect(SEQ)?);
        let hash = asn1::decode_oid(hash.expect(TAG_OID)?)?;
        if !matches!(hash.arcs(), [2, 16, 840, 1, 101, 3, 4, 2, 1..=3]) {
            return Err(Error::hs(8, "RSA-PSS requires SHA-256 or stronger"));
        }
    }
    let mut subject = Decoder::new(&c.subject);
    let mut rd = Decoder::new(subject.expect(SEQ)?);
    let mut set = Decoder::new(rd.expect(TAG_SET)?);
    let mut attr = Decoder::new(set.expect(SEQ)?);
    let attribute = asn1::decode_oid(attr.expect(TAG_OID)?)?;
    let mut oid = asn1::decode_oid(attr.expect(TAG_OID)?)?;
    if subject.more()
        || rd.more()
        || set.more()
        || attr.more()
        || (!any_attribute && attribute.arcs() != [2, 5, 4, 106])
        || oid.0.len() < 3
    {
        return Err(Error::hs(
            8,
            "certificate must have one OID-valued AE subject attribute",
        ));
    }
    let qualifier = oid.0.pop().unwrap();
    if qualifier > i32::MAX as u32 {
        return Err(Error::hs(8, "AE qualifier out of range"));
    }
    let mut tbs = Decoder::new(&c.signed.tbs);
    let mut d = Decoder::new(tbs.expect(SEQ)?);
    d.optional(asn1::context_constructed(0))?;
    for _ in 0..6 {
        d.skip()?;
    }
    if d.peek_is(asn1::context_primitive(1)) || d.peek_is(asn1::context_primitive(2)) {
        return Err(Error::hs(8, "unique identifiers not allowed"));
    }
    let mut usage = None;
    let ext = d.expect(asn1::context_constructed(3))?;
    let mut ed = Decoder::new(Decoder::new(ext).expect(SEQ)?);
    while ed.more() {
        let mut e = Decoder::new(ed.expect(SEQ)?);
        let id = asn1::decode_oid(e.expect(TAG_OID)?)?;
        e.optional(asn1::TAG_BOOLEAN)?;
        let value = e.expect(asn1::TAG_OCTET_STRING)?;
        if id.arcs() == [2, 5, 29, 15] {
            if usage.is_some() {
                return Err(Error::hs(8, "duplicate key usage"));
            }
            usage = Some(asn1::decode_bit_string(
                Decoder::new(value).expect(TAG_BIT_STRING)?,
            )?);
        }
        if id.arcs() == [2, 5, 29, 19] {
            let mut bc = Decoder::new(Decoder::new(value).expect(SEQ)?);
            if bc
                .optional(asn1::TAG_BOOLEAN)?
                .map(asn1::decode_bool)
                .transpose()?
                .unwrap_or(false)
            {
                return Err(Error::hs(8, "CA certificate is not an end entity"));
            }
        }
    }
    let usage = usage.ok_or_else(|| Error::hs(8, "key usage missing"))?;
    if !usage.bit(0) || !usage.bit(4) || usage.bit(5) {
        return Err(Error::hs(
            8,
            "digitalSignature and keyAgreement required; keyCertSign forbidden",
        ));
    }
    Ok(AeTitle {
        ap_title: oid,
        ae_qualifier: qualifier,
    })
}

const MODP_2048_P: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
);

pub(crate) enum Dh {
    Ec(p256::SecretKey),
    Modp(U512),
}
impl std::fmt::Debug for Dh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dh(<redacted>)")
    }
}
impl Dh {
    pub(crate) fn generate(group: Group) -> Result<Self> {
        match group {
            Group::P256 => loop {
                let bytes = Zeroizing::new(random(32)?);
                if let Ok(key) = p256::SecretKey::from_slice(&bytes) {
                    return Ok(Self::Ec(key));
                }
            },
            Group::Modp2048 => {
                let mut bytes = Zeroizing::new(random(64)?);
                bytes[0] |= 0x80;
                Ok(Self::Modp(U512::from_be_slice(&bytes)))
            }
        }
    }
    pub(crate) fn public(&self) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        match self {
            Self::Ec(key) => key.public_key().to_encoded_point(false).as_bytes().to_vec(),
            Self::Modp(x) => modp_pow(&U2048::from_u8(2), x),
        }
    }
    pub(crate) fn shared(&self, peer: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ec(key) => {
                if peer.len() != 65 || peer[0] != 4 {
                    return Err(Error::hs(1, "uncompressed P-256 point required"));
                }
                let pk = p256::PublicKey::from_sec1_bytes(peer)
                    .map_err(|e| Error::hs(1, e.to_string()))?;
                Ok(
                    p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), pk.as_affine())
                        .raw_secret_bytes()
                        .to_vec(),
                )
            }
            Self::Modp(x) => {
                if peer.len() != 256 {
                    return Err(Error::hs(1, "MODP public value width"));
                }
                let y = U2048::from_be_slice(peer);
                let p = U2048::from_be_hex(MODP_2048_P);
                if y <= U2048::ONE || y >= p.wrapping_sub(&U2048::ONE) {
                    return Err(Error::hs(1, "MODP public value out of range"));
                }
                let q = p.shr_vartime(1);
                let params = DynResidueParams::new(&p);
                if DynResidue::new(&y, params).pow(&q).retrieve() != U2048::ONE {
                    return Err(Error::hs(1, "MODP public value not in subgroup"));
                }
                Ok(modp_pow(&y, x))
            }
        }
    }
}
fn modp_pow(y: &U2048, x: &U512) -> Vec<u8> {
    let params = DynResidueParams::new(&U2048::from_be_hex(MODP_2048_P));
    DynResidue::new(y, params)
        .pow(x)
        .retrieve()
        .to_be_bytes()
        .to_vec()
}

impl Drop for Dh {
    fn drop(&mut self) {
        use p256::elliptic_curve::zeroize::Zeroize;
        if let Self::Modp(secret) = self {
            secret.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn hmac_and_gmac_known_answers() {
        assert_eq!(
            IcvAlgorithm::HmacSha256
                .mac(&[0x0b; 20], &[], b"Hi There")
                .unwrap(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(
            IcvAlgorithm::GmacAes128
                .mac(&[0; 16], &[0; 12], &[])
                .unwrap(),
            hex("58e2fccefa7e3061367f1d57")
        );
        assert_eq!(
            IcvAlgorithm::GmacAes256
                .mac(&[0; 32], &[0; 12], &[])
                .unwrap(),
            hex("530f8afbc74536b9a963b4f1")
        );
    }
    #[test]
    fn invalid_public_values_are_refused() {
        assert!(Dh::generate(Group::P256).unwrap().shared(&[0; 65]).is_err());
        assert!(Dh::generate(Group::Modp2048)
            .unwrap()
            .shared(&[0; 256])
            .is_err());
    }
}
