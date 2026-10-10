use std::time::{Duration, Instant};

/// Tracks the SPDU numbers accepted from one sender under one key, in the
/// manner of the IPsec anti-replay window (RFC 4303): the highest number
/// seen, and a bitmap of the ones below it.
///
/// Numbers are compared in serial number arithmetic (RFC 1982), so the
/// counter may wrap.
#[derive(Debug, Default, Clone)]
pub(crate) struct ReplayWindow {
    top: u32,
    /// Bit i: top-i has been accepted.
    seen: u64,
    last: Option<Instant>,
}

impl ReplayWindow {
    /// Reports whether SPDU number `n` is fresh, and records it if so.
    ///
    /// `size` is the window width (at most 64). A number too old for the
    /// window, or one already seen, is a replay, except after `reset` has
    /// passed with nothing accepted: a sender that restarts numbers from zero,
    /// as a restarted publisher does, is taken back rather than shut out until
    /// its counter overtakes the old one. A `reset` of `None` never resets.
    pub(crate) fn accept(&mut self, n: u32, now: Instant, size: u32, reset: Option<Duration>) -> bool {
        let expired = match (self.last, reset) {
            (None, _) => true,
            (Some(last), Some(reset)) => now.saturating_duration_since(last) > reset,
            (Some(_), None) => false,
        };
        if expired {
            self.top = n;
            self.seen = 1;
            self.last = Some(now);
            return true;
        }
        let diff = n.wrapping_sub(self.top) as i32;
        if diff > 0 {
            self.seen = if diff >= 64 { 1 } else { (self.seen << diff) | 1 };
            self.top = n;
        } else {
            let off = -i64::from(diff);
            if off >= i64::from(size) || self.seen & (1 << off) != 0 {
                return false;
            }
            self.seen |= 1 << off;
        }
        self.last = Some(now);
        true
    }

    pub(crate) fn last(&self) -> Option<Instant> {
        self.last
    }
}
