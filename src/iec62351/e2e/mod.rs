//! IEC 62351-4 native end-to-end security for MMS. Integrity-protected
//! transfer, signed key agreement, rekey, release and abort; encryption is
//! deliberately refused, matching the Go reference's implemented profile.
mod association;
mod codec;
mod crypto;
mod files;
pub use files::Files;
pub mod osi;
use super::pki::{RevocationChecker, TrustStore};
use crate::{asn1::Oid, osi::acse};
pub use association::{Association, PeerSecurity, Role};
pub use codec::{AlgorithmIdentifier, Kind};
pub use crypto::{Group, IcvAlgorithm, Identity};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Edition {
    First2018,
    #[default]
    Amendment2020,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Corrections {
    #[default]
    InForce,
    None,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthenticatorTagging {
    #[default]
    AnnexB,
    Clause13,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChainInit {
    #[default]
    ZeroOctet,
    Empty,
    ZeroHash,
}

/// Form-2 AE title, bound to the OID-valued certificate subject.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AeTitle {
    pub ap_title: Oid,
    pub ae_qualifier: u32,
}
impl AeTitle {
    pub fn oid(&self) -> Oid {
        let mut arcs = self.ap_title.0.clone();
        arcs.push(self.ae_qualifier);
        Oid(arcs)
    }
    pub fn acse(&self) -> acse::Identity {
        acse::Identity {
            ap_title: Some(self.ap_title.clone()),
            ae_qualifier: Some(self.ae_qualifier as i32),
            ..Default::default()
        }
    }
    pub fn from_acse(id: &acse::Identity) -> Option<Self> {
        Some(Self {
            ap_title: id.ap_title.clone()?,
            ae_qualifier: u32::try_from(id.ae_qualifier?).ok()?,
        })
    }
}
pub fn security_syntax() -> Oid {
    Oid::from([1, 0, 62351, 4, 1, 2, 1])
}
pub fn application_context() -> Oid {
    Oid::from([1, 0, 62351, 4, 2, 1])
}
pub const IEC61850_PROTOCOL: &str = "IEC 61850-8-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Handshake,
    Data,
    Release,
}
#[derive(Debug, Clone, thiserror::Error)]
#[error("E2E {phase:?}: diagnostic {diagnostic:?}, {detail}")]
pub struct Error {
    pub phase: Phase,
    pub diagnostic: Option<u8>,
    pub detail: String,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub(crate) fn hs(diagnostic: u8, detail: impl Into<String>) -> Self {
        Self {
            phase: Phase::Handshake,
            diagnostic: Some(diagnostic),
            detail: detail.into(),
        }
    }
    pub(crate) fn data(diagnostic: u8, detail: impl Into<String>) -> Self {
        Self {
            phase: Phase::Data,
            diagnostic: Some(diagnostic),
            detail: detail.into(),
        }
    }
    pub(crate) fn alarm(phase: Phase, detail: impl Into<String>) -> Self {
        Self {
            phase,
            diagnostic: None,
            detail: detail.into(),
        }
    }
}
impl From<crate::asn1::Error> for Error {
    fn from(e: crate::asn1::Error) -> Self {
        Self::hs(1, e.to_string())
    }
}

pub type EventHandler = Arc<dyn Fn(&Event) + Send + Sync>;
#[derive(Debug, Clone)]
pub struct Event {
    pub code: &'static str,
    pub association_id: String,
    pub error: Option<Error>,
}

/// Security policy shared by all the endpoint's associations.
pub struct Policy {
    pub trust: Arc<TrustStore>,
    pub revocation: Option<Arc<RevocationChecker>>,
    pub edition: Edition,
    pub corrections: Corrections,
    pub authenticator: AuthenticatorTagging,
    pub chain_init: ChainInit,
    pub dh_groups: Vec<Group>,
    pub icv_algorithms: Vec<IcvAlgorithm>,
    pub freshness: Duration,
    pub rekey_interval: Duration,
    pub rekey_request: Option<Duration>,
    pub max_messages_per_key: u64,
    pub require_authorization: bool,
    pub accept_any_ae_attribute: bool,
    pub accept_sha256_hmac_id: bool,
    pub now: fn() -> SystemTime,
    pub on_event: Option<EventHandler>,
}
impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("edition", &self.edition)
            .field("groups", &self.dh_groups)
            .finish_non_exhaustive()
    }
}
impl Policy {
    pub fn new(trust: Arc<TrustStore>) -> Self {
        Self {
            trust,
            revocation: None,
            edition: Edition::default(),
            corrections: Corrections::default(),
            authenticator: AuthenticatorTagging::default(),
            chain_init: ChainInit::default(),
            dh_groups: vec![Group::P256, Group::Modp2048],
            icv_algorithms: vec![
                IcvAlgorithm::HmacSha256,
                IcvAlgorithm::GmacAes128,
                IcvAlgorithm::GmacAes256,
            ],
            freshness: Duration::from_secs(600),
            rekey_interval: Duration::from_secs(3600),
            rekey_request: None,
            max_messages_per_key: 1 << 30,
            require_authorization: false,
            accept_any_ae_attribute: false,
            accept_sha256_hmac_id: false,
            now: SystemTime::now,
            on_event: None,
        }
    }
    pub(crate) fn read_diag(&self, d: u8) -> u8 {
        if self.edition == Edition::Amendment2020
            && self.corrections == Corrections::InForce
            && d >= 19
        {
            d.saturating_add(1)
        } else {
            d
        }
    }
    pub(crate) fn wire_diag(&self, d: u8) -> u8 {
        if self.edition == Edition::First2018 && d > 16 {
            1
        } else if self.edition == Edition::Amendment2020
            && self.corrections == Corrections::InForce
            && d > 19
        {
            d - 1
        } else {
            d
        }
    }
}

/// One endpoint's credential and policy. Reuse it across connections so replay
/// protection and live association identifier allocation cover the endpoint.
#[derive(Debug)]
pub struct Config {
    pub identity: Identity,
    pub policy: Policy,
    pub protected_protocols: Vec<String>,
    pub tls_protected: bool,
    pub accept_t100_context: bool,
    cache: Mutex<HashMap<Vec<u8>, SystemTime>>,
    ids: Mutex<HashSet<(Oid, u16)>>,
}
impl Config {
    pub fn new(identity: Identity, policy: Policy) -> Result<Self> {
        if policy.trust.is_empty()
            || policy.dh_groups.is_empty()
            || policy.icv_algorithms.is_empty()
            || policy.freshness.is_zero()
            || policy.freshness > Duration::from_secs(600)
            || !(Duration::from_secs(900)..=Duration::from_secs(86400))
                .contains(&policy.rekey_interval)
            || policy.max_messages_per_key == 0
        {
            return Err(Error::hs(1, "invalid E2E policy"));
        }
        Ok(Self {
            identity,
            policy,
            protected_protocols: vec![IEC61850_PROTOCOL.into()],
            tls_protected: false,
            accept_t100_context: false,
            cache: Mutex::default(),
            ids: Mutex::default(),
        })
    }
    pub(crate) fn allocate(&self, peer: &AeTitle) -> Result<String> {
        let mut ids = self.ids.lock().unwrap();
        let start = u16::from_be_bytes(crypto::random(2)?.try_into().unwrap()) % 999;
        for off in 0..999 {
            let id = (start + off) % 999 + 1;
            if ids.insert((peer.oid(), id)) {
                return Ok(id.to_string());
            }
        }
        Err(Error::hs(0, "association identifiers exhausted"))
    }
    pub(crate) fn release(&self, peer: &AeTitle, id: &str) {
        if let Ok(id) = id.parse() {
            self.ids.lock().unwrap().remove(&(peer.oid(), id));
        }
    }
    pub(crate) fn remember(
        &self,
        peer: &AeTitle,
        time: &[u8],
        id: &str,
        expires: SystemTime,
    ) -> Result<()> {
        let now = (self.policy.now)();
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|_, e| *e >= now);
        let key = [
            peer.oid().to_string().as_bytes(),
            b"|",
            time,
            b"|",
            id.as_bytes(),
        ]
        .concat();
        if cache.contains_key(&key) || cache.len() >= 65536 {
            return Err(Error::alarm(
                Phase::Handshake,
                "replayed handshake or full replay cache",
            ));
        }
        cache.insert(key, expires);
        Ok(())
    }
}
