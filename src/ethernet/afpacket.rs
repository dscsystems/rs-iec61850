//! The Linux AF_PACKET `SOCK_RAW` backend.
//!
//! It needs `CAP_NET_RAW` (or root), which is the price of speaking layer 2 at
//! all: GOOSE and SV have no IP layer to borrow a socket from.

use std::sync::atomic::{AtomicBool, Ordering};

use super::{parse_frame, Error, Frame, Interface, Result};

/// The largest frame the socket will read, sized for jumbo frames since a
/// sampled-value stream may use them.
const READ_BUFFER: usize = 9216;

/// How long a read blocks before checking the closed flag.
///
/// Without a timeout, `close` could not unblock a reader, and a subscriber
/// task would outlive its interface.
const READ_TIMEOUT_MS: i64 = 200;

#[derive(Debug)]
pub struct AfPacket {
    fd: std::os::fd::RawFd,
    name: String,
    /// The EtherTypes to deliver, empty for all of them.
    filter: Vec<u16>,
    closed: AtomicBool,
}

// The file descriptor is owned by this type and only used through it.
unsafe impl Send for AfPacket {}
unsafe impl Sync for AfPacket {}

/// Converts a 16-bit value to network byte order, as the AF_PACKET protocol
/// fields require.
fn htons(v: u16) -> u16 {
    v.to_be()
}

impl AfPacket {
    pub fn open(ifname: &str, ether_types: &[u16]) -> Result<AfPacket> {
        let index = interface_index(ifname)?;

        // One requested EtherType is also filtered in the kernel via the bind
        // protocol; otherwise everything is received and filtered here.
        let proto: u16 = if ether_types.len() == 1 {
            ether_types[0]
        } else {
            libc::ETH_P_ALL as u16
        };

        // SAFETY: a plain socket(2) call with constant arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                i32::from(htons(proto)),
            )
        };
        if fd < 0 {
            return Err(Error::Io(std::io::Error::last_os_error()));
        }

        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = htons(proto);
        addr.sll_ifindex = index;

        // SAFETY: addr is a correctly initialised sockaddr_ll of the length
        // given, and fd is the socket just created.
        let rc = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: fd is open and not used again.
            unsafe { libc::close(fd) };
            return Err(Error::Frame(format!("bind {ifname}: {e}")));
        }

        let tv = libc::timeval {
            tv_sec: READ_TIMEOUT_MS / 1000,
            tv_usec: (READ_TIMEOUT_MS % 1000) * 1000,
        };
        // SAFETY: tv is a valid timeval of the length given.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::Frame(format!("SO_RCVTIMEO: {e}")));
        }

        Ok(AfPacket {
            fd,
            name: ifname.to_string(),
            filter: ether_types.to_vec(),
            closed: AtomicBool::new(false),
        })
    }

    fn wants(&self, et: u16) -> bool {
        self.filter.is_empty() || self.filter.contains(&et)
    }
}

impl Interface for AfPacket {
    fn write_frame(&self, f: &Frame) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        let buf = f.marshal();
        // SAFETY: buf is a valid slice of the length given, fd is open.
        let n = unsafe {
            libc::write(
                self.fd,
                buf.as_ptr().cast::<libc::c_void>(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(Error::Frame(format!(
                "write {}: {}",
                self.name,
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn read_frame(&self) -> Result<Frame> {
        let mut buf = vec![0u8; READ_BUFFER];
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(Error::Closed);
            }
            // SAFETY: buf is a valid mutable slice of the length given.
            let n = unsafe {
                libc::recv(
                    self.fd,
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                    0,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.raw_os_error() {
                    // The receive timeout expired, which is how the closed
                    // flag gets polled; and a signal is not a failure.
                    Some(libc::EAGAIN) | Some(libc::EINTR) => continue,
                    _ => {
                        if self.closed.load(Ordering::SeqCst) {
                            return Err(Error::Closed);
                        }
                        return Err(Error::Frame(format!("read {}: {e}", self.name)));
                    }
                }
            }
            let Ok(f) = parse_frame(&buf[..n as usize]) else {
                continue; // a runt frame is not this layer's problem
            };
            if !self.wants(f.ether_type) {
                continue;
            }
            return Ok(f);
        }
    }

    fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        // SAFETY: fd is open, and the swap above guarantees one close only.
        unsafe { libc::close(self.fd) };
        Ok(())
    }
}

impl Drop for AfPacket {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Looks up a network interface's index by name.
fn interface_index(ifname: &str) -> Result<i32> {
    let c_name = std::ffi::CString::new(ifname)
        .map_err(|_| Error::Frame(format!("interface name {ifname:?} contains a NUL")))?;
    // SAFETY: c_name is a valid NUL-terminated string for the call's duration.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(Error::Frame(format!(
            "interface {ifname}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(index as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonexistent_interface_is_reported_rather_than_bound() {
        let err = AfPacket::open("definitely-not-an-interface", &[]).unwrap_err();
        assert!(
            err.to_string().contains("definitely-not-an-interface"),
            "the error should name the interface: {err}"
        );
    }

    #[test]
    fn the_loopback_interface_has_an_index() {
        // Every Linux system has "lo"; looking it up needs no privileges.
        assert!(interface_index("lo").unwrap() > 0);
        assert!(interface_index("nope0").is_err());
    }

    #[test]
    fn htons_puts_the_protocol_in_network_order() {
        // The value the kernel expects is big-endian whatever the host is.
        assert_eq!(htons(0x88b8).to_ne_bytes(), 0x88b8u16.to_be_bytes());
    }
}
