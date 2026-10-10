//! Group key distribution for IEC 61850 (IEC 62351-9): the Group Domain of
//! Interpretation (GDOI, RFC 6407) with the IEC 61850 payloads of RFC 8052,
//! over an IKEv1 phase 1 (RFC 2409).
//!
//! A key server hands the traffic encryption keys (TEKs) of a group to the
//! members it authorises; a member installs them in the
//! [`rsession::KeyStore`](crate::rsession::KeyStore) its R-GOOSE and R-SV
//! sessions use.
//!
//! # Key server
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use iec61850::gdoi::*;
//! # async fn run(creds: Credentials, oid: iec61850::asn1::Oid) -> std::result::Result<(), Box<dyn std::error::Error>> {
//! let group = Arc::new(Group::new());
//! group.add(Tek::new(oid.clone(), Vec::new(), AuthAlg::NONE, EncAlg::AES_GCM_128,
//!     std::time::Duration::from_secs(86400))?)?;
//! let ks = Server::new(ServerConfig {
//!     credentials: creds,
//!     authorize: Some(Arc::new(|member: &Peer, _group: &GroupId| member.common_name.is_some())),
//!     ..Default::default()
//! })?;
//! ks.add_group(GroupId::oid(oid), group);
//! ks.listen_and_serve("0.0.0.0:848").await?;
//! # Ok(())
//! # }
//! ```
//!
//! A rotation adds the next TEK with an activation delay, so members pick it
//! up before it is used, and removes the old one after it expires.
//!
//! # Group member
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use iec61850::{gdoi::*, rsession};
//! # async fn run(creds: Credentials, oid: iec61850::asn1::Oid) {
//! let keys = Arc::new(rsession::KeyStore::new());
//! let member = Member::new(MemberConfig {
//!     server: "ks.substation:848".into(),
//!     credentials: creds,
//!     authorize_server: Some(Arc::new(|ks: &Peer| {
//!         (ks.common_name.as_deref() == Some("ks1")).then_some(()).ok_or("not our key server".into())
//!     })),
//!     ..Default::default()
//! }, GroupId::oid(oid), keys.clone());
//! member.run(std::future::pending()).await;
//! # }
//! ```
//!
//! [`Member::run`] registers, installs each TEK when its activation delay
//! passes, makes the newest one active for sending, drops keys when they
//! expire or the key server stops listing them, and registers again before
//! they run out.
//!
//! # What is implemented
//!
//! - Phase 1: IKEv1 main mode, as initiator (member) and responder (key
//!   server), authenticated with certificates (RSA of 2048 bits or more, ECDSA
//!   P-256 and P-384, RFC 4754) or a pre-shared key; AES-CBC-128 or -256,
//!   SHA2-256 or SHA2-384, and Diffie-Hellman groups 14 (2048-bit MODP), 19 and
//!   20 (256- and 384-bit ECP, RFC 5903). Certificates are verified to the
//!   configured roots and bound to the identification payload.
//! - GROUPKEY-PULL (RFC 6407 3): the member names its group by ID_KEY_ID or by
//!   the ID_OID of RFC 8052, and receives the group's SA TEKs
//!   (GDOI_PROTO_IEC_61850) and their keys, with the SA_ATD activation delay
//!   and the SA_KDA attribute. The key server authorises each member for each
//!   group, and records nothing until the member has proven it holds the
//!   server's nonce.
//! - Both sides retransmit or answer retransmissions, refuse what does not
//!   verify, and tell the peer with an ISAKMP notification.
//! - A TEK maps to an rsession key: HMAC-SHA256-128 and HMAC-SHA256 sign,
//!   AES-GCM-128 and -256 encrypt, the SPI is the key ID.
//!
//! # Not implemented
//!
//! - GROUPKEY-PUSH and the rekey SA (KEK, LKH, SEQ): a member re-registers
//!   instead, so a key server has to distribute a new key ahead of its use.
//! - Aggressive mode, NAT traversal, and the GAP payload.
//! - AES-CBC and AES-GMAC TEKs are distributed and returned, but the session
//!   layer has no counterpart: [`Member`] skips them with an event.
//!
//! The wire format is the Go implementation's, against which this one is
//! checked in both directions (`interop/`).

mod crypto;
mod exchange;
mod isakmp;
mod keeper;
mod member;
mod server;
mod tek;

pub use crypto::{PrivateKey, Suite, DEFAULT_SUITES};
pub use exchange::{AuthorizeFn, AuthorizeServerFn, Credentials, Peer, DEFAULT_PORT};
pub use isakmp::{
    notify_name, ID_DER_ASN1_DN, ID_FQDN, ID_IPV4_ADDR, ID_IPV6_ADDR, ID_KEY_ID, ID_OID, ID_USER_FQDN,
    NOTIFY_AUTH_FAILED, NOTIFY_INVALID_CERT, NOTIFY_INVALID_HASH_INFO, NOTIFY_INVALID_ID_INFO,
    NOTIFY_INVALID_PAYLOAD, NOTIFY_INVALID_SIGNATURE, NOTIFY_NO_PROPOSAL_CHOSEN,
};
pub use keeper::{Event, EventFn, EventKind, Member};
pub use member::{register, MemberConfig, Registration};
pub use server::{Group, PskFn, RegisterFn, RejectFn, Server, ServerConfig};
pub use tek::{AuthAlg, EncAlg, GroupId, Tek};

/// Errors of GDOI.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("gdoi: malformed ISAKMP message: {0}")]
    Malformed(String),
    #[error("gdoi: {0}")]
    Config(String),
    #[error("gdoi: {0}")]
    Auth(String),
    #[error("gdoi: TEK policy not allowed: {0}")]
    Policy(String),
    #[error("gdoi: TEK algorithm the session layer does not implement: {0}")]
    Unsupported(String),
    /// A notification the peer sent refusing the exchange.
    #[error("gdoi: peer refused the exchange: {}", notify_name(*.0))]
    Notify(u16),
    /// A refusal the key server tells the member of with a notification.
    #[error("gdoi: {1}")]
    Refused(u16, String),
    #[error("gdoi: key server did not answer")]
    Timeout,
    #[error("gdoi: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Session(#[from] crate::rsession::Error),
}

/// Result alias for GDOI.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
