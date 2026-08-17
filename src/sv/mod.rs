//! The IEC 61850-9-2 Sampled Values mapping over raw Ethernet.
//!
//! A merging unit publishes digitised current and voltage continuously at
//! thousands of samples a second, with no acknowledgement and no
//! retransmission: a lost sample is simply lost, and the receive path has to
//! keep up. This module has the `savPdu`/ASDU codec, a generic and a typed
//! 9-2LE subscriber, and a 9-2LE publisher with a sample clock.
//!
//! ```no_run
//! use std::sync::Arc;
//! use iec61850::{ethernet, sv};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let eth: Arc<dyn ethernet::Interface> =
//!     ethernet::open("eth0", &[ethernet::ETHER_TYPE_SV])?.into();
//!
//! // 80 samples per cycle at 50 Hz is 4000 samples a second.
//! let publisher = sv::LePublisher::new(
//!     Arc::clone(&eth),
//!     sv::LeConfig {
//!         app_id: 0x4000,
//!         sv_id: "MU01".into(),
//!         dst_mac: sv::default_mac(1),
//!         samples_per_cycle: 80,
//!         nominal_hz: 50,
//!         ..Default::default()
//!     },
//! )?;
//!
//! publisher
//!     .run(
//!         |smp_cnt, out| {
//!             out.i[0] = i32::from(smp_cnt) * 10;
//!             out.v[0] = 230_000;
//!         },
//!         std::future::pending(),
//!     )
//!     .await?;
//! # Ok(())
//! # }
//! ```

mod le;
mod pdu;
mod publisher;
mod subscriber;

pub use le::{
    decode_le_into, decode_le_sample, encode_le_sample, write_le_sample, LeSample, LE_SAMPLE_LEN,
};
pub use pdu::{parse, Asdu, Pdu, SMP_SYNCH_GLOBAL, SMP_SYNCH_LOCAL, SMP_SYNCH_NONE};
pub use publisher::{default_mac, LeConfig, LePublisher};
pub use subscriber::{Filter, Subscriber, Subscription};

/// Errors raised by the sampled-value layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("sv: {0}")]
    Codec(String),
    #[error("sv: {0}")]
    Config(String),
    #[error(transparent)]
    Ethernet(#[from] crate::ethernet::Error),
}

impl From<crate::asn1::Error> for Error {
    fn from(e: crate::asn1::Error) -> Error {
        Error::Codec(e.to_string())
    }
}

/// Result alias for the sampled-value layer.
pub type Result<T> = std::result::Result<T, Error>;
