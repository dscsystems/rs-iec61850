use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{Error, Frame, Interface, Result};

/// How deep each direction of the pipe buffers.
///
/// A publisher retransmitting a burst must not block on a subscriber that has
/// not caught up yet, so the buffer covers a whole GOOSE burst.
const PIPE_DEPTH: usize = 64;

/// Returns two connected in-memory interfaces: a frame written to one end is
/// delivered to the other end's reader.
///
/// It is the layer-2 analogue of a socket pair, used for tests and for
/// simulating a shared segment without a real NIC. Frames are copied on write,
/// so callers may reuse their buffers.
pub fn pipe() -> (PipeEnd, PipeEnd) {
    let (ab_tx, ab_rx) = std::sync::mpsc::sync_channel(PIPE_DEPTH);
    let (ba_tx, ba_rx) = std::sync::mpsc::sync_channel(PIPE_DEPTH);
    let closed = Arc::new(AtomicBool::new(false));
    (
        PipeEnd {
            out: ab_tx,
            input: Mutex::new(ba_rx),
            closed: Arc::clone(&closed),
        },
        PipeEnd {
            out: ba_tx,
            input: Mutex::new(ab_rx),
            closed,
        },
    )
}

/// One end of an in-memory layer-2 segment.
#[derive(Debug)]
pub struct PipeEnd {
    out: SyncSender<Frame>,
    input: Mutex<Receiver<Frame>>,
    closed: Arc<AtomicBool>,
}

/// How long a blocked read waits before checking whether the pipe was closed.
///
/// A reader has to notice a close even when no frame ever arrives, or a
/// subscriber task outlives the interface it was reading.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

impl PipeEnd {
    /// Takes a frame if one is already waiting, without blocking.
    ///
    /// [`Interface::read_frame`] blocks until a frame arrives or the pipe
    /// closes, which is right for a subscriber but leaves a test with no way
    /// to drain what has accumulated. This is that way.
    pub fn try_read_frame(&self) -> Option<Frame> {
        self.input
            .lock()
            .expect("the pipe reader is not poisoned")
            .try_recv()
            .ok()
    }
}

impl Interface for PipeEnd {
    fn write_frame(&self, f: &Frame) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::Closed);
        }
        // A full pipe means the peer is not reading; dropping the frame is
        // what a real segment does, and is better than stalling a publisher's
        // retransmission clock.
        match self.out.try_send(f.clone()) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(_)) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Err(Error::Closed),
        }
    }

    fn read_frame(&self) -> Result<Frame> {
        let input = self.input.lock().expect("the pipe reader is not poisoned");
        loop {
            if self.closed.load(Ordering::SeqCst) {
                return Err(Error::Closed);
            }
            match input.recv_timeout(POLL_INTERVAL) {
                Ok(f) => return Ok(f),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(Error::Closed)
                }
            }
        }
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::ETHER_TYPE_GOOSE;
    use super::*;

    fn frame(payload: &[u8]) -> Frame {
        Frame {
            dst: [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01],
            ether_type: ETHER_TYPE_GOOSE,
            payload: payload.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn a_frame_written_at_one_end_arrives_at_the_other() {
        let (a, b) = pipe();
        a.write_frame(&frame(b"hello")).unwrap();
        let got = b.read_frame().unwrap();
        assert_eq!(got.payload, b"hello");
        assert_eq!(got.ether_type, ETHER_TYPE_GOOSE);

        // And the reverse direction is independent.
        b.write_frame(&frame(b"world")).unwrap();
        assert_eq!(a.read_frame().unwrap().payload, b"world");
    }

    #[test]
    fn frames_arrive_in_the_order_they_were_written() {
        let (a, b) = pipe();
        for i in 0u8..8 {
            a.write_frame(&frame(&[i])).unwrap();
        }
        for i in 0u8..8 {
            assert_eq!(b.read_frame().unwrap().payload, [i]);
        }
    }

    /// A publisher must be able to reuse its buffer, so the pipe copies.
    #[test]
    fn a_written_frame_is_copied() {
        let (a, b) = pipe();
        let mut f = frame(b"first");
        a.write_frame(&f).unwrap();
        f.payload = b"second".to_vec();
        a.write_frame(&f).unwrap();

        assert_eq!(b.read_frame().unwrap().payload, b"first");
        assert_eq!(b.read_frame().unwrap().payload, b"second");
    }

    /// A subscriber blocked on a read has to notice the close, or its task
    /// outlives the interface.
    #[test]
    fn closing_unblocks_a_waiting_reader() {
        let (a, b) = pipe();
        let b = Arc::new(b);
        let reader = Arc::clone(&b);
        let handle = std::thread::spawn(move || reader.read_frame());

        std::thread::sleep(Duration::from_millis(20));
        b.close().unwrap();

        let result = handle.join().expect("the reader thread finished");
        assert!(matches!(result, Err(Error::Closed)));
        // And writing to a closed end fails rather than silently succeeding.
        assert!(matches!(a.read_frame(), Err(Error::Closed)));
    }

    #[test]
    fn closing_is_idempotent_and_both_ends_see_it() {
        let (a, b) = pipe();
        a.close().unwrap();
        a.close().unwrap();
        assert!(matches!(a.write_frame(&frame(b"x")), Err(Error::Closed)));
        assert!(matches!(b.write_frame(&frame(b"x")), Err(Error::Closed)));
    }

    #[test]
    fn a_non_blocking_read_returns_what_is_waiting_and_then_nothing() {
        let (a, b) = pipe();
        assert!(b.try_read_frame().is_none(), "nothing has been sent yet");

        a.write_frame(&frame(b"one")).unwrap();
        a.write_frame(&frame(b"two")).unwrap();
        assert_eq!(b.try_read_frame().unwrap().payload, b"one");
        assert_eq!(b.try_read_frame().unwrap().payload, b"two");
        assert!(
            b.try_read_frame().is_none(),
            "a drained pipe must not block or repeat"
        );
    }

    /// A saturated segment drops frames rather than stalling the publisher,
    /// which is what a real one does and what keeps a retransmission clock
    /// honest.
    #[test]
    fn a_full_pipe_drops_rather_than_blocking() {
        let (a, _b) = pipe();
        for i in 0..PIPE_DEPTH * 2 {
            a.write_frame(&frame(&[i as u8]))
                .expect("writing never blocks or fails on a full pipe");
        }
    }
}
