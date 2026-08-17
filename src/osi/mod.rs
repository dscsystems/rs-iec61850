//! The OSI upper stack beneath MMS: TPKT, COTP, session, presentation and
//! ACSE.
//!
//! MMS needs a full OSI upper stack; that complexity is quarantined here so
//! [`crate::mms`] reads as a clean ISO 9506 implementation. These modules are
//! an implementation detail of the MMS layer and are exported only for
//! tooling.
//!
//! The layering, innermost last:
//!
//! ```text
//! acse -> presentation -> session -> cotp -> tpkt -> TCP
//! ```
//!
//! [`tpkt`] and [`cotp`] do I/O; [`session`] drives a COTP connection;
//! [`presentation`] and [`acse`] are pure byte-level codecs with no I/O of
//! their own.

pub mod acse;
pub mod cotp;
pub mod presentation;
pub mod session;
pub mod tpkt;

/// Errors raised by the OSI stack.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("asn1: {0}")]
    Asn1(#[from] crate::asn1::Error),
    #[error("tpkt: {0}")]
    Tpkt(String),
    #[error("cotp: {0}")]
    Cotp(String),
    #[error("session: {0}")]
    Session(String),
    #[error("presentation: {0}")]
    Presentation(String),
    #[error("acse: {0}")]
    Acse(String),
    /// The peer closed the association (COTP DR, or a clean EOF).
    #[error("association closed by peer")]
    Closed,
}

/// Result alias for the OSI stack.
pub type Result<T> = std::result::Result<T, Error>;
