//! Raw layer-2 access for the GOOSE and Sampled Values transports.
//!
//! An [`Interface`] is a network device that can send and receive frames;
//! [`Frame`] marshalling is a pure function, so the codecs above are testable
//! without a socket, and [`pipe`] gives an in-memory segment for tests and
//! simulation.
//!
//! The AF_PACKET backend is Linux-only and needs `CAP_NET_RAW` (or root). On
//! other platforms [`open`] returns an error; use [`pipe`] there.

mod frame;
#[cfg(target_os = "linux")]
mod afpacket;

pub use frame::{parse_frame, Frame, VlanTag};

/// EtherType values used by the IEC 61850 layer-2 protocols.
pub const ETHER_TYPE_GOOSE: u16 = 0x88b8;
pub const ETHER_TYPE_SV: u16 = 0x88ba;
/// The 802.1Q tag protocol identifier.
pub(crate) const ETHER_TYPE_VLAN: u16 = 0x8100;

/// Errors raised by the layer-2 transport.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ethernet: {0}")]
    Frame(String),
    #[error("ethernet: {0}")]
    Io(#[from] std::io::Error),
    #[error("ethernet: the interface is closed")]
    Closed,
    #[error("ethernet: raw layer-2 access is not supported on this platform; use pipe() for tests")]
    Unsupported,
}

/// Result alias for the layer-2 transport.
pub type Result<T> = std::result::Result<T, Error>;

/// A raw layer-2 endpoint able to send and receive frames.
///
/// [`read_frame`](Interface::read_frame) blocks until a frame arrives, an
/// error occurs or the interface is closed; implementations must make
/// [`close`](Interface::close) unblock a concurrent reader, or a subscriber
/// task can never be stopped.
pub trait Interface: Send + Sync + std::fmt::Debug {
    fn write_frame(&self, f: &Frame) -> Result<()>;
    fn read_frame(&self) -> Result<Frame>;
    fn close(&self) -> Result<()>;
}

/// Binds a raw socket to the named interface.
///
/// With no EtherTypes every protocol is delivered; with one or more, reception
/// is restricted to those, compared after VLAN decapsulation so tagged frames
/// are matched on their inner protocol.
#[cfg(target_os = "linux")]
pub fn open(ifname: &str, ether_types: &[u16]) -> Result<Box<dyn Interface>> {
    Ok(Box::new(afpacket::AfPacket::open(ifname, ether_types)?))
}

/// Binds a raw socket to the named interface.
///
/// Only Linux has a backend; elsewhere this always fails and [`pipe`] is the
/// way to exercise the protocols.
#[cfg(not(target_os = "linux"))]
pub fn open(_ifname: &str, _ether_types: &[u16]) -> Result<Box<dyn Interface>> {
    Err(Error::Unsupported)
}

mod pipe;
pub use pipe::pipe;
