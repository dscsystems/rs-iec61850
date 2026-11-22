use std::future::Future;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};

use super::{BoxTransport, Error};

#[derive(Default)]
pub(crate) struct Traffic {
    enabled: AtomicBool,
    pub(crate) stage: std::sync::Mutex<Option<&'static str>>,
    pub(crate) octets_in: AtomicU64,
    pub(crate) octets_out: AtomicU64,
    pub(crate) requests: AtomicU64,
}

#[derive(Debug, thiserror::Error)]
enum Deadline {
    #[error("TPKT frame completion timed out")]
    Frame,
    #[error("MMS association idle")]
    Idle,
}

pub(super) fn read_error(error: crate::osi::Error) -> Error {
    if let crate::osi::Error::Io(io) = &error {
        match io.get_ref().and_then(|err| err.downcast_ref::<Deadline>()) {
            Some(Deadline::Frame) => return Error::FrameTimeout,
            Some(Deadline::Idle) => return Error::IdleTimeout,
            None => {}
        }
    }
    error.into()
}

/// Enforces timeouts on TPKT octets, below COTP reassembly. Tokio's split
/// serializes the read and write polls of this transport, so writes can update
/// activity even while a reader is waiting on an idle deadline.
pub(super) struct Guard {
    stream: BoxTransport,
    traffic: Arc<Traffic>,
    count: bool,
    frame_limit: Duration,
    idle_limit: Duration,
    header: [u8; 4],
    header_len: usize,
    remaining: usize,
    frame_start: Instant,
    last_activity: Instant,
    timer: Option<Pin<Box<Sleep>>>,
}

impl Guard {
    pub(super) fn wrap(
        stream: BoxTransport,
        frame_limit: Duration,
        idle_limit: Duration,
        stats: Option<Arc<Traffic>>,
    ) -> (BoxTransport, Option<Arc<Traffic>>) {
        if frame_limit.is_zero() && idle_limit.is_zero() && stats.is_none() {
            return (stream, None);
        }
        let count = stats.is_some();
        let traffic = stats.unwrap_or_default();
        let now = Instant::now();
        (
            Box::new(Self {
                stream,
                traffic: traffic.clone(),
                count,
                frame_limit,
                idle_limit,
                header: [0; 4],
                header_len: 0,
                remaining: 0,
                frame_start: now,
                last_activity: now,
                timer: None,
            }),
            Some(traffic),
        )
    }

    fn track(&mut self, mut bytes: &[u8], now: Instant) {
        while !bytes.is_empty() {
            if self.remaining != 0 {
                let take = self.remaining.min(bytes.len());
                self.remaining -= take;
                bytes = &bytes[take..];
                continue;
            }
            if self.header_len == 0 {
                self.frame_start = now;
            }
            let take = (4 - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + take].copy_from_slice(&bytes[..take]);
            self.header_len += take;
            bytes = &bytes[take..];
            if self.header_len == 4 {
                self.remaining = usize::from(u16::from_be_bytes([self.header[2], self.header[3]]))
                    .saturating_sub(4);
                self.header_len = 0;
            }
        }
    }
}

impl Traffic {
    pub(super) fn enable(&self) {
        self.enabled
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

impl AsyncRead for Guard {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let active = self
            .traffic
            .enabled
            .load(std::sync::atomic::Ordering::Acquire);
        let mid_frame = self.header_len != 0 || self.remaining != 0;
        let (start, limit, failure) = if mid_frame {
            (self.frame_start, self.frame_limit, Deadline::Frame)
        } else {
            (self.last_activity, self.idle_limit, Deadline::Idle)
        };
        if active && !limit.is_zero() {
            if let Some(at) = start.checked_add(limit) {
                let timer = self
                    .timer
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
                if timer.deadline() != at {
                    timer.as_mut().reset(at);
                }
                if timer.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::Error::new(ErrorKind::TimedOut, failure)));
                }
            }
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        let bytes = &buf.filled()[before..];
        if !bytes.is_empty() {
            if self.count {
                self.traffic
                    .octets_in
                    .fetch_add(bytes.len() as u64, Relaxed);
            }
            if active {
                let now = Instant::now();
                self.last_activity = now;
                self.track(bytes, now);
            }
        }
        result
    }
}

impl AsyncWrite for Guard {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = result {
            if n != 0 {
                if self.count {
                    self.traffic.octets_out.fetch_add(n as u64, Relaxed);
                }
                self.last_activity = Instant::now();
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test(start_paused = true)]
    async fn frame_deadline_starts_at_first_octet_and_is_not_renewed() {
        let (mut peer, stream) = tokio::io::duplex(128);
        let limit = Duration::from_secs(10);
        let (mut stream, guard) = Guard::wrap(Box::new(stream), limit, Duration::ZERO, None);
        guard.unwrap().enable();
        let read = tokio::spawn(async move { crate::osi::tpkt::read_packet(&mut stream).await });
        tokio::time::advance(limit * 2).await;
        assert!(!read.is_finished(), "no frame has started");

        peer.write_all(&[3]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(limit - Duration::from_secs(1)).await;
        peer.write_all(&[0]).await.unwrap();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(matches!(
            read_error(read.await.unwrap().unwrap_err()),
            Error::FrameTimeout
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn writes_extend_the_idle_deadline_of_a_pending_reader() {
        let (mut peer, stream) = tokio::io::duplex(128);
        let limit = Duration::from_secs(10);
        let (stream, guard) = Guard::wrap(Box::new(stream), limit, limit, None);
        guard.unwrap().enable();
        let (mut reader, mut writer) = tokio::io::split(stream);
        let read = tokio::spawn(async move { crate::osi::tpkt::read_packet(&mut reader).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(8)).await;
        writer.write_all(b"report").await.unwrap();
        let mut data = [0; 6];
        peer.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"report");

        tokio::time::advance(Duration::from_secs(3)).await;
        assert!(!read.is_finished(), "the write renewed the idle deadline");
        tokio::time::advance(Duration::from_secs(7)).await;
        assert!(matches!(
            read_error(read.await.unwrap().unwrap_err()),
            Error::IdleTimeout
        ));
    }
}
