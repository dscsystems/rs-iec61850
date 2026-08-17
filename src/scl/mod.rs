//! Parses IEC 61850-6 SCL files (ICD, CID, SCD, IID) and instantiates the
//! runtime object model of the [`crate::model`] module.
//!
//! The parser covers the subset needed to configure a server or a GOOSE
//! subscriber: IEDs with access points, servers, logical devices and nodes,
//! data type templates, datasets, report/GOOSE/SV/log/setting-group control
//! blocks, initial values (DOI/SDI/DAI) and the Communication section.
//! Substation topology, Services capabilities beyond the report-buffer
//! capacity, KDC and certificate elements and private extensions are decoded
//! loosely or ignored.
//!
//! Elements are matched by local name, so any SCL namespace revision is
//! accepted.

mod build;
mod dom;
mod parse;
mod types;

pub use build::{build_model, load_model, BuildOptions};
pub use dom::Node;
pub use parse::{parse, parse_file};
pub use types::*;

/// Errors raised while reading or instantiating an SCL document.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("scl: {0}")]
    Xml(String),
    #[error("scl: {0}")]
    Io(#[from] std::io::Error),
    /// The document is well-formed but does not describe what was asked for.
    #[error("scl: {0}")]
    Model(String),
}

impl Error {
    pub(crate) fn model(msg: impl Into<String>) -> Error {
        Error::Model(msg.into())
    }
}

/// Result alias for the SCL module.
pub type Result<T> = std::result::Result<T, Error>;
