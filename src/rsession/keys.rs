use std::collections::HashMap;
use std::sync::RwLock;

use super::{Error, Result};

/// The encryption algorithm of a key. The values are the ones libiec61850
/// uses; in protocol version 1 they are carried on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SecAlgorithm(pub u8);

impl SecAlgorithm {
    pub const NONE: SecAlgorithm = SecAlgorithm(0);
    pub const AES_128_GCM: SecAlgorithm = SecAlgorithm(1);
    pub const AES_256_GCM: SecAlgorithm = SecAlgorithm(2);

    /// The key length the algorithm requires, 0 for none or an unknown one.
    pub(crate) fn key_len(self) -> usize {
        match self {
            SecAlgorithm::AES_128_GCM => 16,
            SecAlgorithm::AES_256_GCM => 32,
            _ => 0,
        }
    }
}

impl std::fmt::Display for SecAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            SecAlgorithm::NONE => f.write_str("none"),
            SecAlgorithm::AES_128_GCM => f.write_str("AES-128-GCM"),
            SecAlgorithm::AES_256_GCM => f.write_str("AES-256-GCM"),
            SecAlgorithm(n) => write!(f, "SecAlgorithm({n})"),
        }
    }
}

/// The message authentication algorithm of a key, numbered as libiec61850
/// numbers them; in protocol version 1 they are carried on the wire.
///
/// The HMACs are truncated to their leftmost octets. The AES-GMAC variants
/// (4 and 5) are not implemented: a key naming one is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SigAlgorithm(pub u8);

impl SigAlgorithm {
    pub const NONE: SigAlgorithm = SigAlgorithm(0);
    pub const HMAC_SHA256_80: SigAlgorithm = SigAlgorithm(1);
    pub const HMAC_SHA256_128: SigAlgorithm = SigAlgorithm(2);
    pub const HMAC_SHA256_256: SigAlgorithm = SigAlgorithm(3);
    pub const AES_GMAC_64: SigAlgorithm = SigAlgorithm(4);
    pub const AES_GMAC_128: SigAlgorithm = SigAlgorithm(5);
    pub const HMAC_SHA3_80: SigAlgorithm = SigAlgorithm(6);
    pub const HMAC_SHA3_128: SigAlgorithm = SigAlgorithm(7);
    pub const HMAC_SHA3_256: SigAlgorithm = SigAlgorithm(8);

    /// The length of the truncated MAC, 0 for none or an unsupported
    /// algorithm.
    pub(crate) fn mac_len(self) -> usize {
        match self {
            SigAlgorithm::HMAC_SHA256_80 | SigAlgorithm::HMAC_SHA3_80 => 10,
            SigAlgorithm::HMAC_SHA256_128 | SigAlgorithm::HMAC_SHA3_128 => 16,
            SigAlgorithm::HMAC_SHA256_256 | SigAlgorithm::HMAC_SHA3_256 => 32,
            _ => 0,
        }
    }

    pub(crate) fn is_sha3(self) -> bool {
        matches!(
            self,
            SigAlgorithm::HMAC_SHA3_80 | SigAlgorithm::HMAC_SHA3_128 | SigAlgorithm::HMAC_SHA3_256
        )
    }
}

impl std::fmt::Display for SigAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match *self {
            SigAlgorithm::NONE => "none",
            SigAlgorithm::HMAC_SHA256_80 => "HMAC-SHA256-80",
            SigAlgorithm::HMAC_SHA256_128 => "HMAC-SHA256-128",
            SigAlgorithm::HMAC_SHA256_256 => "HMAC-SHA256-256",
            SigAlgorithm::AES_GMAC_64 => "AES-GMAC-64",
            SigAlgorithm::AES_GMAC_128 => "AES-GMAC-128",
            SigAlgorithm::HMAC_SHA3_80 => "HMAC-SHA3-80",
            SigAlgorithm::HMAC_SHA3_128 => "HMAC-SHA3-128",
            SigAlgorithm::HMAC_SHA3_256 => "HMAC-SHA3-256",
            SigAlgorithm(n) => return write!(f, "SigAlgorithm({n})"),
        };
        f.write_str(s)
    }
}

/// The shortest HMAC key accepted: 128 bits, the security level of the
/// shortest tag worth having.
const MIN_HMAC_KEY: usize = 16;

/// The key material of one security association: its identifier, the
/// secret, the algorithms it is used with, and the key timing the header
/// carries.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Key {
    /// 0 is reserved for "no key".
    pub id: u32,
    /// The secret. An AES key is 16 or 32 octets as the algorithm requires;
    /// an HMAC key at least 16.
    pub material: Vec<u8>,
    pub sec: SecAlgorithm,
    pub sig: SigAlgorithm,
    /// Carried in every SPDU sent under the key, as the key distribution
    /// center issued them (IEC 62351-9). The session layer does not
    /// interpret them.
    pub time_of_current_key: u32,
    pub time_to_next_key: i16,
}

impl std::fmt::Debug for Key {
    // The material stays out of logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("material", &format_args!("[{} octets]", self.material.len()))
            .field("sec", &self.sec)
            .field("sig", &self.sig)
            .field("time_of_current_key", &self.time_of_current_key)
            .field("time_to_next_key", &self.time_to_next_key)
            .finish()
    }
}

impl Key {
    /// Checks that the key is usable as configured.
    pub fn validate(&self) -> Result<()> {
        if self.id == 0 {
            return Err(Error::KeyId);
        }
        if self.sec == SecAlgorithm::NONE && self.sig == SigAlgorithm::NONE {
            return Err(Error::KeyAlgorithm);
        }
        // AES-GCM authenticates what it encrypts, and the only other
        // implementation of the protocol lays out an HMAC over an encrypted
        // payload in a way no receiver can verify; a key does one or the
        // other.
        if self.sec != SecAlgorithm::NONE && self.sig != SigAlgorithm::NONE {
            return Err(Error::KeyCombination);
        }
        if self.sec != SecAlgorithm::NONE {
            let n = self.sec.key_len();
            if n == 0 {
                return Err(Error::KeyUnsupported(self.sec.to_string()));
            }
            if self.material.len() != n {
                return Err(Error::KeyLength(format!(
                    "{} needs {n} octets, have {}",
                    self.sec,
                    self.material.len()
                )));
            }
        } else {
            if self.sig.mac_len() == 0 {
                return Err(Error::KeyUnsupported(self.sig.to_string()));
            }
            if self.material.len() < MIN_HMAC_KEY {
                return Err(Error::KeyLength(format!(
                    "{} needs at least {MIN_HMAC_KEY} octets, have {}",
                    self.sig,
                    self.material.len()
                )));
            }
        }
        Ok(())
    }
}

/// The keys of a session: every key a receiver accepts, and the one a sender
/// uses.
///
/// Keys are looked up by the identifier each SPDU carries, so a receiver
/// holding the current and the next key keeps accepting a publisher across a
/// key change. Share one between sessions, or with a key distribution client,
/// through an `Arc`. Safe for concurrent use.
#[derive(Debug, Default)]
pub struct KeyStore {
    inner: RwLock<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    keys: HashMap<u32, Key>,
    active: u32,
}

impl KeyStore {
    /// Returns an empty store.
    pub fn new() -> KeyStore {
        KeyStore::default()
    }

    /// Returns a store holding `keys`; the first becomes the active one.
    pub fn with_keys(keys: impl IntoIterator<Item = Key>) -> Result<KeyStore> {
        let s = KeyStore::default();
        for (i, k) in keys.into_iter().enumerate() {
            let id = k.id;
            s.add(k)?;
            if i == 0 {
                s.inner.write().unwrap().active = id;
            }
        }
        Ok(s)
    }

    /// Adds a key, or replaces the key of the same identifier.
    pub fn add(&self, k: Key) -> Result<()> {
        k.validate()?;
        self.inner.write().unwrap().keys.insert(k.id, k);
        Ok(())
    }

    /// Removes a key. Removing the active key leaves the sender without one:
    /// it sends nothing until another is made active.
    pub fn remove(&self, id: u32) {
        let mut inner = self.inner.write().unwrap();
        inner.keys.remove(&id);
        if inner.active == id {
            inner.active = 0;
        }
    }

    /// Makes the key with identifier `id` the one a sender uses.
    pub fn set_active(&self, id: u32) -> Result<()> {
        let mut inner = self.inner.write().unwrap();
        if !inner.keys.contains_key(&id) {
            return Err(Error::NoSuchKey(id));
        }
        inner.active = id;
        Ok(())
    }

    /// Returns the identifier of the active key, 0 when there is none.
    pub fn active(&self) -> u32 {
        let inner = self.inner.read().unwrap();
        if inner.keys.contains_key(&inner.active) {
            inner.active
        } else {
            0
        }
    }

    /// Returns the sender's key, `None` when there is none.
    pub(crate) fn active_key(&self) -> Option<Key> {
        let inner = self.inner.read().unwrap();
        inner.keys.get(&inner.active).cloned()
    }

    /// Returns a copy of the key with identifier `id`.
    pub fn lookup(&self, id: u32) -> Option<Key> {
        self.inner.read().unwrap().keys.get(&id).cloned()
    }

    /// Returns the identifiers of the keys held.
    pub fn ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.inner.read().unwrap().keys.keys().copied().collect();
        ids.sort_unstable();
        ids
    }
}
