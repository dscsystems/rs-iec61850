//! A pure-Rust implementation of the IEC 61850 protocol family: MMS
//! client/server (IEC 61850-8-1), GOOSE and Sampled Values publish/subscribe,
//! and SCL configuration handling.
//!
//! Most applications use the high-level modules:
//!
//! * [`client`] - ACSI client for talking to IEDs (browse, read, write,
//!   datasets, reporting, controls, file transfer)
//! * [`server`] - ACSI server for building IEDs, simulators and gateways
//! * [`goose`], [`sv`] - layer-2 publish/subscribe
//! * [`scl`] - SCL (ICD/CID/SCD) parsing and model instantiation
//! * [`model`] - the IEC 61850 object model and common data types
//!
//! The lower layers ([`mms`], [`asn1`]) are exported where useful for tooling
//! but are not needed for typical use.
//!
//! # Example
//!
//! Load an IED model from its SCL file and read a configured value out of it:
//!
//! ```no_run
//! use iec61850::{model::Fc, scl};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let model = scl::load_model("substation.cid", &scl::BuildOptions::new())?;
//! let da = model
//!     .attribute(&"ied1LD0/GGIO1.AnIn1.mag.f".into(), Fc::Mx)
//!     .expect("the model defines AnIn1");
//! println!("{:?}", da.value);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

pub mod asn1;
pub mod mms;
pub mod client;
pub mod ethernet;
pub mod goose;
pub mod model;
pub mod osi;
pub mod scl;
pub mod server;
pub mod sv;

/// Crate version, from `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) mod time_util;
