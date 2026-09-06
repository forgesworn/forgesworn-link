use super::{LanError, admission::Lease};
use link_core::id::NodeId;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub const MAX_PAIRING_STREAM_BYTES: u64 = 1 << 20;
pub const MAX_PAIRING_SESSION: Duration = Duration::from_secs(60);

pub(super) struct SessionGuard {
    pub endpoint_active: Arc<AtomicBool>,
    pub lease: Arc<Lease>,
    pub deadline: Option<Instant>,
    pub connection: quinn::Connection,
}
impl SessionGuard {
    pub fn check(&self) -> Result<(), LanError> {
        if !self.endpoint_active.load(Ordering::Acquire)
            || !self.lease.valid()
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(LanError::Admission);
        }
        if self.connection.close_reason().is_some() {
            return Err(LanError::Closed);
        }
        Ok(())
    }
    fn io_check(&self) -> io::Result<()> {
        // A remote clean close may follow an already authenticated, buffered
        // response. Quinn decides stream completion; revoked local consent
        // still prevents consuming even those buffered bytes.
        if !self.endpoint_active.load(Ordering::Acquire)
            || !self.lease.valid()
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "LAN session consent ended",
            ));
        }
        Ok(())
    }
}

/// Streams check their admission on every read/write, including buffered bytes.
/// Raw Quinn streams are deliberately not exposed through this candidate API.
pub struct LanStream {
    inner: crate::Stream,
    guard: Arc<SessionGuard>,
    read_left: u64,
    write_left: u64,
}
impl LanStream {
    fn new(
        pair: (quinn::SendStream, quinn::RecvStream),
        guard: Arc<SessionGuard>,
        pairing: bool,
    ) -> Self {
        let budget = if pairing {
            MAX_PAIRING_STREAM_BYTES
        } else {
            u64::MAX
        };
        Self {
            inner: crate::Stream {
                send: pair.0,
                recv: pair.1,
            },
            guard,
            read_left: budget,
            write_left: budget,
        }
    }
    /// Finish and wait for QUIC acknowledgement before closing the session.
    pub async fn finish(&mut self) -> Result<(), LanError> {
        self.guard.io_check().map_err(|_| LanError::Admission)?;
        self.inner.send.finish().map_err(|_| LanError::Closed)?;
        if self
            .inner
            .send
            .stopped()
            .await
            .map_err(|_| LanError::Closed)?
            .is_some()
        {
            return Err(LanError::Closed);
        }
        self.guard.io_check().map_err(|_| LanError::Admission)?;
        Ok(())
    }
}
impl AsyncRead for LanStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.guard.io_check()?;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_left == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pairing stream byte limit",
            )));
        }
        let limit = buf
            .remaining()
            .min(self.read_left.min(usize::MAX as u64) as usize);
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(limit));
        match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let read = limited.filled().len();
                self.read_left -= read as u64;
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl AsyncWrite for LanStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.guard.io_check()?;
        if self.write_left == 0 && !buf.is_empty() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "pairing stream byte limit",
            )));
        }
        let limit = buf
            .len()
            .min(self.write_left.min(usize::MAX as u64) as usize);
        match Pin::new(&mut self.inner).poll_write(cx, &buf[..limit]) {
            Poll::Ready(Ok(written)) => {
                self.write_left -= written as u64;
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.guard.io_check()?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.guard.io_check()?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Authenticated local QUIC. There is no relay, migration or reconnect API.
pub struct LanSession {
    pub(super) peer: NodeId,
    pub(super) guard: Arc<SessionGuard>,
}
impl LanSession {
    pub fn peer(&self) -> NodeId {
        self.peer
    }
    pub fn is_live(&self) -> bool {
        self.guard.check().is_ok()
    }
    pub async fn open_stream(&self) -> Result<LanStream, LanError> {
        self.guard.check()?;
        let pair = tokio::time::timeout(Duration::from_secs(5), self.guard.connection.open_bi())
            .await
            .map_err(|_| LanError::Timeout)?
            .map_err(|_| LanError::Closed)?;
        self.guard.check()?;
        Ok(LanStream::new(pair, self.guard.clone(), false))
    }
    pub async fn accept_stream(&self) -> Result<LanStream, LanError> {
        self.guard.check()?;
        let pair = self
            .guard
            .connection
            .accept_bi()
            .await
            .map_err(|_| LanError::Closed)?;
        self.guard.check()?;
        Ok(LanStream::new(pair, self.guard.clone(), false))
    }
    pub fn close(&self) {
        self.guard
            .connection
            .close(0_u32.into(), b"local session closed");
    }
    pub async fn closed(&self) {
        self.guard.connection.closed().await;
    }
}
impl Drop for LanSession {
    fn drop(&mut self) {
        self.close();
    }
}

/// One unclaimed transport key and one dialler-initiated application stream.
/// The product must prove its raw pairing secret before accepting a claim/body.
pub struct LanPairingSession {
    pub(super) peer: NodeId,
    pub(super) guard: Arc<SessionGuard>,
    pub(super) dialler: bool,
    pub(super) stream_used: AtomicBool,
}
impl LanPairingSession {
    pub fn provisional_peer(&self) -> NodeId {
        self.peer
    }
    pub fn is_live(&self) -> bool {
        self.guard.check().is_ok()
    }
    pub async fn stream(&self) -> Result<LanStream, LanError> {
        self.guard.check()?;
        if self.stream_used.swap(true, Ordering::AcqRel) {
            return Err(LanError::StreamLimit);
        }
        let pair = tokio::time::timeout(Duration::from_secs(5), async {
            if self.dialler {
                self.guard.connection.open_bi().await
            } else {
                self.guard.connection.accept_bi().await
            }
        })
        .await
        .map_err(|_| LanError::Timeout)?
        .map_err(|_| LanError::Closed)?;
        self.guard.check()?;
        Ok(LanStream::new(pair, self.guard.clone(), true))
    }
    pub fn close(&self) {
        self.guard
            .connection
            .close(0_u32.into(), b"pairing session closed");
    }
    pub async fn closed(&self) {
        self.guard.connection.closed().await;
    }
}
impl Drop for LanPairingSession {
    fn drop(&mut self) {
        self.close();
    }
}
