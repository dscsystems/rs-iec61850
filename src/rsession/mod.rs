//! The session protocol of IEC 61850-90-5, which carries GOOSE and sampled
//! values over UDP (R-GOOSE and R-SV, adopted by IEC 61850-8-1 and 9-2
//! Amendment 1), with the message security that goes with it: an HMAC over
//! each SPDU, or AES-GCM encryption of its user data, under keys identified in
//! the header.
//!
//! # Using it
//!
//! A [`Session`] is an [`ethernet::Interface`](crate::ethernet::Interface), so
//! the GOOSE and SV publishers and subscribers of this crate run over it as
//! they run over a network interface:
//!
//! ```no_run
//! use std::sync::Arc;
//! use iec61850::{goose, rsession};
//!
//! # fn run(ld: &iec61850::model::LogicalDevice, ln: &iec61850::model::LogicalNode,
//! #        gc: &iec61850::model::GseControl, k: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
//! let keys = Arc::new(rsession::KeyStore::with_keys([rsession::Key {
//!     id: 1,
//!     material: k,
//!     sec: rsession::SecAlgorithm::AES_128_GCM,
//!     ..Default::default()
//! }])?);
//! let s = Arc::new(rsession::Session::open(rsession::Config {
//!     remote: gc.dst_ip.unwrap().to_string(),
//!     keys: Some(keys),
//!     ..Default::default()
//! })?);
//! let publisher = goose::Publisher::from_model(s, ld, ln, gc, [0; 6])?;
//! # Ok(())
//! # }
//! ```
//!
//! A receiver refuses what it cannot verify: an SPDU under a key it does not
//! hold, one whose MAC or tag does not verify, an unsecured one (unless
//! [`Config::allow_unsecured`]), and a secured one it has already accepted
//! (the replay window). Refusals are counted ([`Session::stats`]) and reported
//! to [`Config::on_reject`] for the security event log.
//!
//! # Keys
//!
//! Keys come from the [`KeyStore`]: the active key secures what a session
//! sends, and every key in the store is accepted on receipt, so a key change
//! is: add the new key everywhere, make it active at the publisher, then
//! remove the old one.
//!
//! # The wire format
//!
//! [`marshal`] documents the layout. Where the references disagree it follows
//! the one that makes the fields consistent, and reads the other:
//!
//! - Header lengths. The session header length counts the common header and
//!   the security information; the common header length is 10. libiec61850
//!   writes fixed values (24 and 18) whatever the header holds. Neither it nor
//!   Wireshark reads them, and neither does [`unmarshal`].
//! - SPDU length counts the octets after the field. No receiver checks it.
//! - APDU length is the length of the APDU, as Wireshark reads it. libiec61850
//!   writes two more; [`unmarshal`] accepts that on the last element.
//! - A MAC covers the SPDU from its first octet (the transport header) to the
//!   signature tag, as libiec61850 computes it. HMAC-SHA256-80, -128 and -256
//!   and the HMAC-SHA3 variants are implemented; the AES-GMAC ones are not.
//! - Encryption (version 2 only) is AES-GCM with a random 12-octet IV in the
//!   header, everything before the user data as additional authenticated
//!   data, and the 16-octet tag in the trailer. A key either signs or
//!   encrypts.
//!
//! The encoding is checked against libiec61850 1.6's R-GOOSE output (the test
//! vectors in this module) and against the Go implementation in both
//! directions (`interop/`).

mod keys;
mod replay;
mod session;
mod spdu;

pub use keys::{Key, KeyStore, SecAlgorithm, SigAlgorithm};
pub use session::{Config, Reject, RejectHandler, Session, Stats, DEFAULT_PORT};
pub use spdu::{marshal, unmarshal, Payload, PayloadType, SessionId, Spdu};

/// Errors of the session layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rsession: malformed SPDU: {0}")]
    Malformed(String),
    #[error("rsession: unsupported protocol version {0}")]
    Version(u16),
    #[error("rsession: unknown key {0}")]
    UnknownKey(u32),
    #[error("rsession: security algorithms do not match the key: {0}")]
    Algorithm(String),
    #[error("rsession: authentication failed: {0}")]
    Authentication(String),
    #[error("rsession: unsecured SPDU")]
    Unsecured,
    #[error("rsession: replayed SPDU: {0}")]
    Replay(String),
    #[error("rsession: no active key")]
    NoActiveKey,
    #[error("rsession: protocol version 1 carries no encryption")]
    Version1Encrypt,
    #[error("rsession: key ID 0 is reserved")]
    KeyId,
    #[error("rsession: key has no algorithm")]
    KeyAlgorithm,
    #[error("rsession: algorithm not supported: {0}")]
    KeyUnsupported(String),
    #[error("rsession: key length does not suit the algorithm: {0}")]
    KeyLength(String),
    #[error("rsession: a key either encrypts or signs")]
    KeyCombination,
    #[error("rsession: no key {0}")]
    NoSuchKey(u32),
    #[error("rsession: session does not receive")]
    NotListening,
    #[error("rsession: session has no remote address")]
    NoRemote,
    #[error("rsession: session closed")]
    Closed,
    #[error("rsession: {0}")]
    Address(String),
    #[error("rsession: random source: {0}")]
    Random(String),
    #[error("rsession: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for the session layer.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
