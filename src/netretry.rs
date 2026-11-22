//! Pace retries when a socket operation can recover without being reopened.

use std::io::{Error, ErrorKind};
use std::time::Duration;

pub(crate) fn temporary(error: &Error) -> bool {
    if matches!(
        error.kind(),
        ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
    ) {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
        )
    }
    #[cfg(windows)]
    {
        // WSAEMFILE, WSAENOBUFS.
        matches!(error.raw_os_error(), Some(10024 | 10055))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}

#[derive(Default)]
pub(crate) struct Backoff(Duration);

impl Backoff {
    pub(crate) fn next(&mut self) -> Duration {
        self.0 = (self.0 * 2).clamp(Duration::from_millis(5), Duration::from_secs(1));
        self.0
    }

    pub(crate) fn reset(&mut self) {
        self.0 = Duration::ZERO;
    }
}
