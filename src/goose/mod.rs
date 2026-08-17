//! The IEC 61850-8-1 GOOSE mapping over raw Ethernet.
//!
//! GOOSE carries protection-critical status between IEDs on a switched
//! segment, with no acknowledgement: reliability comes from repeating each
//! state change on a fast, decaying schedule and from a subscriber that
//! notices gaps. This module has the `goosePdu` codec, a publisher running
//! that retransmission state machine, and a subscriber with anomaly detection.
//!
//! ```no_run
//! use std::sync::Arc;
//! use iec61850::{ethernet, goose, mms::Value, model::Quality};
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let eth: Arc<dyn ethernet::Interface> =
//!     ethernet::open("eth0", &[ethernet::ETHER_TYPE_GOOSE])?.into();
//!
//! let publisher = goose::Publisher::new(
//!     Arc::clone(&eth),
//!     goose::PublisherConfig {
//!         dst_mac: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
//!         app_id: 0x1000,
//!         go_cb_ref: "IED1LD0/LLN0$GO$gcb01".into(),
//!         dat_set: "IED1LD0/LLN0$Events".into(),
//!         go_id: "events".into(),
//!         conf_rev: 1,
//!         ..Default::default()
//!     },
//! )?;
//! publisher.publish(vec![Value::boolean(true), Quality::GOOD.value()])?;
//! # Ok(())
//! # }
//! ```

mod message;
mod publisher;
mod subscriber;

pub use message::{parse, Message};
pub use publisher::{Publisher, PublisherConfig, DEFAULT_RETRANS};
pub use subscriber::{Anomalies, Filter, SequenceTracker, Subscriber, Subscription};

/// Errors raised by the GOOSE layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("goose: {0}")]
    Codec(String),
    #[error("goose: {0}")]
    Config(String),
    #[error(transparent)]
    Ethernet(#[from] crate::ethernet::Error),
    #[error("goose: the publisher is closed")]
    Closed,
}

impl From<crate::asn1::Error> for Error {
    fn from(e: crate::asn1::Error) -> Error {
        Error::Codec(e.to_string())
    }
}

/// Result alias for the GOOSE layer.
pub type Result<T> = std::result::Result<T, Error>;

/// Returns the standard GOOSE multicast destination address for an offset
/// within the reserved range `01-0C-CD-01-00-00`..`01-0C-CD-01-01-FF`.
pub fn default_mac(offset: u16) -> [u8; 6] {
    let [hi, lo] = offset.to_be_bytes();
    [0x01, 0x0c, 0xcd, 0x01, hi & 0x01, lo]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multicast_addresses_stay_inside_the_reserved_goose_range() {
        assert_eq!(default_mac(0), [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00]);
        assert_eq!(default_mac(1), [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01]);
        assert_eq!(default_mac(0x1ff), [0x01, 0x0c, 0xcd, 0x01, 0x01, 0xff]);
        // The range is 512 addresses wide, so an offset past it wraps rather
        // than colliding with the sampled-value range that follows.
        assert_eq!(default_mac(0x200), [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x00]);
        for offset in [0u16, 1, 255, 256, 511] {
            let mac = default_mac(offset);
            assert_eq!(&mac[..4], &[0x01, 0x0c, 0xcd, 0x01]);
        }
    }
}
