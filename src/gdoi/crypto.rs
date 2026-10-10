//! The phase 1 cryptography: suites, the PRF, Diffie-Hellman, the key
//! derivation of RFC 2409, AES-CBC and the signature authentication methods.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use sha2::{Digest, Sha256, Sha384};

use super::isakmp::{malformed, Attribute};
use super::{Error, Result};
use crate::x509;

// Phase 1 attribute classes (RFC 2409 appendix A).
pub(crate) const ATTR_ENC_ALG: u16 = 1;
pub(crate) const ATTR_HASH_ALG: u16 = 2;
pub(crate) const ATTR_AUTH_METH: u16 = 3;
pub(crate) const ATTR_GROUP_DESC: u16 = 4;
pub(crate) const ATTR_LIFE_TYPE: u16 = 11;
pub(crate) const ATTR_LIFE_DUR: u16 = 12;
pub(crate) const ATTR_KEY_LENGTH: u16 = 14;

// Phase 1 attribute values.
pub(crate) const ENC_AES_CBC: u16 = 7;
pub(crate) const LIFE_SECONDS: u16 = 1;
pub(crate) const AUTH_PSK: u16 = 1;
pub(crate) const AUTH_RSA_SIG: u16 = 3;
pub(crate) const AUTH_ECDSA_256: u16 = 9; // RFC 4754
pub(crate) const AUTH_ECDSA_384: u16 = 10; // RFC 4754

/// One phase 1 proposal: the algorithms protecting the exchange with the key
/// server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Suite {
    /// The AES-CBC key length, 128 or 256.
    pub key_bits: u16,
    /// [`Suite::SHA2_256`] or [`Suite::SHA2_384`]; it is the PRF, as HMAC.
    pub hash: u16,
    /// The Diffie-Hellman group: [`Suite::MODP_2048`], [`Suite::ECP_256`] or
    /// [`Suite::ECP_384`].
    pub group: u16,
}

impl Suite {
    pub const SHA2_256: u16 = 4;
    pub const SHA2_384: u16 = 5;
    pub const MODP_2048: u16 = 14;
    pub const ECP_256: u16 = 19; // RFC 5903
    pub const ECP_384: u16 = 20;

    pub(crate) fn valid(&self) -> bool {
        (self.key_bits == 128 || self.key_bits == 256)
            && (self.hash == Suite::SHA2_256 || self.hash == Suite::SHA2_384)
            && matches!(self.group, Suite::MODP_2048 | Suite::ECP_256 | Suite::ECP_384)
    }

    pub(crate) fn hash_alg(&self) -> HashAlg {
        if self.hash == Suite::SHA2_384 {
            HashAlg::Sha384
        } else {
            HashAlg::Sha256
        }
    }

    /// The transform's attributes, with the authentication method and the
    /// lifetime.
    pub(crate) fn attrs(&self, auth: u16, life_secs: u32) -> Vec<Attribute> {
        vec![
            Attribute::basic(ATTR_ENC_ALG, ENC_AES_CBC),
            Attribute::basic(ATTR_KEY_LENGTH, self.key_bits),
            Attribute::basic(ATTR_HASH_ALG, self.hash),
            Attribute::basic(ATTR_GROUP_DESC, self.group),
            Attribute::basic(ATTR_AUTH_METH, auth),
            Attribute::basic(ATTR_LIFE_TYPE, LIFE_SECONDS),
            Attribute::uint32(ATTR_LIFE_DUR, life_secs),
        ]
    }
}

impl std::fmt::Display for Suite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = if self.hash == Suite::SHA2_384 { "SHA2-384" } else { "SHA2-256" };
        let g = match self.group {
            Suite::MODP_2048 => "MODP-2048",
            Suite::ECP_256 => "ECP-256",
            Suite::ECP_384 => "ECP-384",
            _ => "?",
        };
        write!(f, "AES-CBC-{}/{h}/{g}", self.key_bits)
    }
}

/// The suites offered when a configuration names none, strongest first.
pub const DEFAULT_SUITES: &[Suite] = &[
    Suite { key_bits: 256, hash: Suite::SHA2_256, group: Suite::ECP_256 },
    Suite { key_bits: 128, hash: Suite::SHA2_256, group: Suite::ECP_256 },
    Suite { key_bits: 256, hash: Suite::SHA2_384, group: Suite::ECP_384 },
    Suite { key_bits: 128, hash: Suite::SHA2_256, group: Suite::MODP_2048 },
];

/// Reads a transform's attributes; `None` for one outside what this
/// implementation supports.
pub(crate) fn suite_from_attrs(attrs: &[Attribute]) -> Option<(Suite, u16)> {
    let get = |t: u16| {
        super::isakmp::attr_by_type(attrs, t)
            .filter(|a| a.value.len() <= 8)
            .map(Attribute::uint)
    };
    let (enc, kl, h, g, am) = (
        get(ATTR_ENC_ALG)?,
        get(ATTR_KEY_LENGTH)?,
        get(ATTR_HASH_ALG)?,
        get(ATTR_GROUP_DESC)?,
        get(ATTR_AUTH_METH)?,
    );
    if enc != u64::from(ENC_AES_CBC) {
        return None;
    }
    let s = Suite {
        key_bits: u16::try_from(kl).ok()?,
        hash: u16::try_from(h).ok()?,
        group: u16::try_from(g).ok()?,
    };
    s.valid().then_some((s, u16::try_from(am).ok()?))
}

/// The negotiated hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
}

impl HashAlg {
    pub(crate) fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        match self {
            HashAlg::Sha256 => {
                let mut h = Sha256::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
            HashAlg::Sha384 => {
                let mut h = Sha384::new();
                parts.iter().for_each(|p| h.update(p));
                h.finalize().to_vec()
            }
        }
    }
}

/// HMAC with the negotiated hash.
pub(crate) fn prf(h: HashAlg, key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    match h {
        HashAlg::Sha256 => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key");
            parts.iter().for_each(|p| m.update(p));
            m.finalize().into_bytes().to_vec()
        }
        HashAlg::Sha384 => {
            let mut m = <Hmac<Sha384> as Mac>::new_from_slice(key).expect("HMAC takes any key");
            parts.iter().for_each(|p| m.update(p));
            m.finalize().into_bytes().to_vec()
        }
    }
}

pub(crate) fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("the system random source");
    b
}

/// The 2048-bit MODP group of RFC 3526.
const MODP_2048_P: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B",
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510",
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
);
pub(crate) const MODP_LEN: usize = 256;

fn modp_p() -> BigUint {
    BigUint::parse_bytes(MODP_2048_P.as_bytes(), 16).expect("the RFC 3526 prime")
}

fn pad(b: Vec<u8>, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n.saturating_sub(b.len())];
    out.extend_from_slice(&b);
    out
}

/// One side's ephemeral Diffie-Hellman key.
pub(crate) enum Dh {
    Modp { x: BigUint, public: Vec<u8> },
    P256 { key: p256::SecretKey, public: Vec<u8> },
    P384 { key: p384::SecretKey, public: Vec<u8> },
}

impl Dh {
    pub(crate) fn new(group: u16) -> Result<Dh> {
        match group {
            Suite::ECP_256 => loop {
                if let Ok(k) = p256::SecretKey::from_slice(&random_bytes(32)) {
                    return Ok(Dh::from_p256(k));
                }
            },
            Suite::ECP_384 => loop {
                if let Ok(k) = p384::SecretKey::from_slice(&random_bytes(48)) {
                    return Ok(Dh::from_p384(k));
                }
            },
            Suite::MODP_2048 => {
                let x = BigUint::from_bytes_be(&random_bytes(64));
                let y = BigUint::from(2u32).modpow(&x, &modp_p());
                Ok(Dh::Modp {
                    public: pad(y.to_bytes_be(), MODP_LEN),
                    x,
                })
            }
            g => Err(Error::Config(format!("Diffie-Hellman group {g}"))),
        }
    }

    /// RFC 5903: the KE value is x followed by y, without the uncompressed
    /// point prefix.
    pub(crate) fn from_p256(key: p256::SecretKey) -> Dh {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let public = key.public_key().to_encoded_point(false).as_bytes()[1..].to_vec();
        Dh::P256 { key, public }
    }

    fn from_p384(key: p384::SecretKey) -> Dh {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let public = key.public_key().to_encoded_point(false).as_bytes()[1..].to_vec();
        Dh::P384 { key, public }
    }

    /// The KE payload value.
    pub(crate) fn public(&self) -> &[u8] {
        match self {
            Dh::Modp { public, .. } | Dh::P256 { public, .. } | Dh::P384 { public, .. } => public,
        }
    }

    /// Computes g^xy from the peer's KE value: for an ECP group its x
    /// coordinate (RFC 5903), for MODP the value padded to the modulus
    /// length.
    pub(crate) fn shared(&self, peer: &[u8]) -> Result<Vec<u8>> {
        let mut point = vec![4u8];
        point.extend_from_slice(peer);
        let bad = |e: &dyn std::fmt::Display| Error::Malformed(format!("peer key exchange value: {e}"));
        match self {
            Dh::P256 { key, .. } => {
                let pk = p256::PublicKey::from_sec1_bytes(&point).map_err(|e| bad(&e))?;
                let s = p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), pk.as_affine());
                Ok(s.raw_secret_bytes().to_vec())
            }
            Dh::P384 { key, .. } => {
                let pk = p384::PublicKey::from_sec1_bytes(&point).map_err(|e| bad(&e))?;
                let s = p384::ecdh::diffie_hellman(key.to_nonzero_scalar(), pk.as_affine());
                Ok(s.raw_secret_bytes().to_vec())
            }
            Dh::Modp { x, .. } => {
                if peer.len() != MODP_LEN {
                    return Err(malformed(format!("MODP key exchange value of {} octets", peer.len())));
                }
                let p = modp_p();
                let y = BigUint::from_bytes_be(peer);
                let one = BigUint::from(1u32);
                if y <= one || y >= &p - &one {
                    return Err(malformed("peer key exchange value out of range"));
                }
                Ok(pad(y.modpow(x, &p).to_bytes_be(), MODP_LEN))
            }
        }
    }
}

/// AES with the phase 1 key.
enum Cipher {
    A128(Box<aes::Aes128>),
    A256(Box<aes::Aes256>),
}

const BLOCK: usize = 16;

impl Cipher {
    fn new(key: &[u8]) -> Result<Cipher> {
        match key.len() {
            16 => Ok(Cipher::A128(Box::new(aes::Aes128::new(GenericArray::from_slice(key))))),
            32 => Ok(Cipher::A256(Box::new(aes::Aes256::new(GenericArray::from_slice(key))))),
            n => Err(Error::Config(format!("AES key of {n} octets"))),
        }
    }

    fn encrypt(&self, b: &mut [u8]) {
        let block = GenericArray::from_mut_slice(b);
        match self {
            Cipher::A128(c) => c.encrypt_block(block),
            Cipher::A256(c) => c.encrypt_block(block),
        }
    }

    fn decrypt(&self, b: &mut [u8]) {
        let block = GenericArray::from_mut_slice(b);
        match self {
            Cipher::A128(c) => c.decrypt_block(block),
            Cipher::A256(c) => c.decrypt_block(block),
        }
    }
}

/// The keying material of a phase 1 SA (RFC 2409 5).
pub(crate) struct Keys {
    pub hash: HashAlg,
    pub a: Vec<u8>,
    cipher: Cipher,
    /// The last CBC output block of phase 1.
    pub phase1_last: Option<Vec<u8>>,
}

impl Keys {
    pub(crate) fn derive(s: Suite, skeyid: &[u8], gxy: &[u8], ci: &[u8], cr: &[u8]) -> Result<Keys> {
        let h = s.hash_alg();
        let d = prf(h, skeyid, &[gxy, ci, cr, &[0]]);
        let a = prf(h, skeyid, &[&d, gxy, ci, cr, &[1]]);
        let e = prf(h, skeyid, &[&a, gxy, ci, cr, &[2]]);
        // Appendix B: take the key from SKEYID_e, expanding it by feeding the
        // PRF into itself when it is too short.
        let need = usize::from(s.key_bits / 8);
        let mut material = e.clone();
        if material.len() < need {
            let (mut ka, mut prev) = (Vec::new(), vec![0u8]);
            while ka.len() < need {
                prev = prf(h, &e, &[&prev]);
                ka.extend_from_slice(&prev);
            }
            material = ka;
        }
        Ok(Keys {
            hash: h,
            cipher: Cipher::new(&material[..need])?,
            a,
            phase1_last: None,
        })
    }

    /// The IV of the first message of a phase 2 or informational exchange:
    /// hash(last phase 1 CBC block | M-ID).
    pub(crate) fn phase2_iv(&self, msg_id: u32) -> Vec<u8> {
        let last = self.phase1_last.as_deref().unwrap_or(&[]);
        self.hash.digest(&[last, &msg_id.to_be_bytes()])[..BLOCK].to_vec()
    }

    /// Pads `plain` with zeros to the block size and encrypts it with `iv`,
    /// returning the ciphertext and the IV of the next message (its last
    /// block).
    pub(crate) fn encrypt(&self, plain: &[u8], iv: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut n = plain.len();
        let r = n % BLOCK;
        if r != 0 || n == 0 {
            n += BLOCK - r;
        }
        let mut buf = vec![0u8; n];
        buf[..plain.len()].copy_from_slice(plain);
        let mut prev = iv.to_vec();
        for chunk in buf.chunks_mut(BLOCK) {
            chunk.iter_mut().zip(&prev).for_each(|(c, p)| *c ^= p);
            self.cipher.encrypt(chunk);
            prev.copy_from_slice(chunk);
        }
        (buf, prev)
    }

    /// Decrypts `ct` with `iv`, returning the plaintext (padding included) and
    /// the IV of the next message.
    pub(crate) fn decrypt(&self, ct: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if ct.is_empty() || ct.len() % BLOCK != 0 || iv.len() != BLOCK {
            return Err(malformed(format!("ciphertext of {} octets", ct.len())));
        }
        let next = ct[ct.len() - BLOCK..].to_vec();
        let mut buf = ct.to_vec();
        let mut prev = iv.to_vec();
        for (i, chunk) in buf.chunks_mut(BLOCK).enumerate() {
            self.cipher.decrypt(chunk);
            chunk.iter_mut().zip(&prev).for_each(|(c, p)| *c ^= p);
            prev.copy_from_slice(&ct[i * BLOCK..(i + 1) * BLOCK]);
        }
        Ok((buf, next))
    }
}

/// The IV of the first encrypted phase 1 message: hash(g^xi | g^xr),
/// truncated to the block size.
pub(crate) fn phase1_iv(h: HashAlg, gxi: &[u8], gxr: &[u8]) -> Vec<u8> {
    h.digest(&[gxi, gxr])[..BLOCK].to_vec()
}

/// A private key that authenticates phase 1: RSA (2048 bits or more), or
/// ECDSA on P-256 or P-384.
#[derive(Clone)]
pub enum PrivateKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PrivateKey::Rsa(_) => "PrivateKey::Rsa",
            PrivateKey::P256(_) => "PrivateKey::P256",
            PrivateKey::P384(_) => "PrivateKey::P384",
        })
    }
}

impl PrivateKey {
    /// Reads a PKCS #8 DER private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey> {
        use p256::pkcs8::DecodePrivateKey;
        if let Ok(k) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::P256(k));
        }
        if let Ok(k) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(PrivateKey::P384(k));
        }
        if let Ok(k) = <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_der(der) {
            return Ok(PrivateKey::Rsa(Box::new(k)));
        }
        Err(Error::Config("the private key is not PKCS #8 RSA, P-256 or P-384".into()))
    }

    /// The signature authentication method the key calls for.
    pub(crate) fn auth_method(&self) -> Result<u16> {
        match self {
            PrivateKey::Rsa(k) => {
                use rsa::traits::PublicKeyParts;
                let bits = k.n().bits();
                if bits < 2048 {
                    return Err(Error::Config(format!("{bits}-bit RSA key, at least 2048 required")));
                }
                Ok(AUTH_RSA_SIG)
            }
            PrivateKey::P256(_) => Ok(AUTH_ECDSA_256),
            PrivateKey::P384(_) => Ok(AUTH_ECDSA_384),
        }
    }
}

fn ecdsa_digest(auth: u16, h: &[u8]) -> Vec<u8> {
    if auth == AUTH_ECDSA_384 {
        Sha384::digest(h).to_vec()
    } else {
        Sha256::digest(h).to_vec()
    }
}

/// Signs HASH_I or HASH_R for the authentication method: RSA as a PKCS #1
/// private-key encryption of the hash with no algorithm identifier (RFC 2409
/// 5.1), ECDSA over the hash of it as r followed by s (RFC 4754).
pub(crate) fn sign(auth: u16, key: &PrivateKey, h: &[u8]) -> Result<Vec<u8>> {
    let fail = |e: &dyn std::fmt::Display| Error::Auth(format!("signing: {e}"));
    match (auth, key) {
        (AUTH_RSA_SIG, PrivateKey::Rsa(k)) => k
            .sign(rsa::Pkcs1v15Sign::new_unprefixed(), h)
            .map_err(|e| fail(&e)),
        (AUTH_ECDSA_256, PrivateKey::P256(k)) => {
            let sig: p256::ecdsa::Signature = k.sign_prehash(&ecdsa_digest(auth, h)).map_err(|e| fail(&e))?;
            Ok(sig.to_bytes().to_vec())
        }
        (AUTH_ECDSA_384, PrivateKey::P384(k)) => {
            let sig: p384::ecdsa::Signature = k.sign_prehash(&ecdsa_digest(auth, h)).map_err(|e| fail(&e))?;
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(Error::Config(format!("authentication method {auth} does not suit the key"))),
    }
}

/// Checks a signature over HASH_I or HASH_R with a certificate's key, which
/// must suit the authentication method.
pub(crate) fn verify(auth: u16, key: &x509::PublicKey, h: &[u8], sig: &[u8]) -> Result<()> {
    let bad = |what: String| Error::Auth(what);
    match (auth, key) {
        (AUTH_RSA_SIG, x509::PublicKey::Rsa { n, e }) => {
            let pk = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(n), rsa::BigUint::from_bytes_be(e))
                .map_err(|e| bad(format!("RSA key: {e}")))?;
            pk.verify(rsa::Pkcs1v15Sign::new_unprefixed(), h, sig)
                .map_err(|_| bad("signature does not verify".into()))
        }
        (AUTH_ECDSA_256, x509::PublicKey::Ec { curve: x509::Curve::P256, point }) => {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| bad(format!("ECDSA key: {e}")))?;
            if sig.len() != 64 {
                return Err(bad(format!("ECDSA signature of {} octets", sig.len())));
            }
            let s = p256::ecdsa::Signature::from_slice(sig).map_err(|e| bad(e.to_string()))?;
            vk.verify_prehash(&ecdsa_digest(auth, h), &s)
                .map_err(|_| bad("signature does not verify".into()))
        }
        (AUTH_ECDSA_384, x509::PublicKey::Ec { curve: x509::Curve::P384, point }) => {
            let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| bad(format!("ECDSA key: {e}")))?;
            if sig.len() != 96 {
                return Err(bad(format!("ECDSA signature of {} octets", sig.len())));
            }
            let s = p384::ecdsa::Signature::from_slice(sig).map_err(|e| bad(e.to_string()))?;
            vk.verify_prehash(&ecdsa_digest(auth, h), &s)
                .map_err(|_| bad("signature does not verify".into()))
        }
        _ => Err(bad(format!("a certificate key that does not suit authentication method {auth}"))),
    }
}

/// Compares MACs in constant time.
pub(crate) fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
