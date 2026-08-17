//! The high-level IEC 61850 ACSI server.
//!
//! It serves a data model (built from SCL or programmatically) over MMS to
//! clients, with hooks for write access and control, and an atomic update API
//! for the process side to drive value changes.

pub mod access;
mod control;
mod file;
mod handler;
mod rcb;
mod reporting;
#[allow(clippy::module_inception)]
mod server;
mod select;
mod settinggroup;
mod tx;

pub use control::{ControlCtx, Phase};
pub use file::{FileInfo, FileStore};
pub use server::{
    ConnectionEvent, ConnectionHandler, ConnectionState, ControlHandler, Identity, Options, Server,
    WriteHandler, ERR_ACCESS_DENIED, ERR_OBJECT_NON_EXISTENT, ERR_OBJECT_VALUE_INVALID,
};
pub use server::ConnMap;
pub(crate) use server::Inner;
pub use settinggroup::SettingGroupManager;
pub use tx::Tx;

/// Identifies one accepted client association.
///
/// Reservations and report subscriptions are keyed by it rather than by a
/// pointer, so a connection that goes away releases exactly what it held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId(pub u64);

impl std::fmt::Display for ConnId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "conn{}", self.0)
    }
}

/// Errors raised by the ACSI server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Mms(#[from] crate::mms::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("server: {0}")]
    Server(String),
}

/// Result alias for the ACSI server.
pub type Result<T> = std::result::Result<T, Error>;
