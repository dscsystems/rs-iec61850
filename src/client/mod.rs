//! The high-level IEC 61850 ACSI client.
//!
//! It presents an IED as a data model addressed by object reference and
//! functional constraint, layered on the MMS services in [`crate::mms`].
//!
//! ```no_run
//! use iec61850::{client::Client, model::Fc};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let c = Client::dial("192.168.10.5:102").await?;
//! let v = c.read("ied1LD0/GGIO1.AnIn1.mag.f", Fc::Mx).await?;
//! println!("{v}");
//! c.close().await?;
//! # Ok(())
//! # }
//! ```

mod control;
mod dataset;
mod directory;
mod file;
mod log;
mod report;
mod retrieve;
mod settinggroup;

#[allow(clippy::module_inception)]
mod client;

pub use client::{Client, Options};
pub use control::{ControlError, ControlObject, ControlOptions, Stage};
pub use dataset::{DataSet, DataSetEntry};
pub use directory::{AcsiClass, DirectoryEntry};
pub use file::FileReader;
pub use report::{Rcb, Report, ReportEntry, ReportSubscription};
pub use settinggroup::SettingGroups;

/// A log entry, as returned by a journal query.
pub type LogEntry = crate::mms::JournalEntry;

/// A file entry, as returned by a filestore directory listing.
pub type FileEntry = crate::mms::FileEntry;

/// Errors raised by the ACSI client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Mms(#[from] crate::mms::Error),
    #[error(transparent)]
    Access(#[from] crate::mms::DataAccessError),
    #[error(transparent)]
    Reference(#[from] crate::model::RefError),
    #[error(transparent)]
    Control(#[from] ControlError),
    #[error("client: {0}")]
    Client(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub(crate) fn client(msg: impl Into<String>) -> Error {
        Error::Client(msg.into())
    }
}

/// Result alias for the ACSI client.
pub type Result<T> = std::result::Result<T, Error>;
