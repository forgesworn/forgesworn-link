use super::address::AddressPolicy;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::{self, IoSliceMut},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

#[derive(Default)]
pub(super) struct Counters {
    pub sent: AtomicU64,
    pub refused: AtomicU64,
}
pub(super) struct LocalSocket {
    pub inner: Arc<dyn AsyncUdpSocket>,
    pub policy: AddressPolicy,
    pub active: Arc<AtomicBool>,
    pub counters: Arc<Counters>,
}
impl std::fmt::Debug for LocalSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalOnlyUdpSocket")
    }
}
impl AsyncUdpSocket for LocalSocket {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) || !self.policy.permits(transmit.destination) {
            self.counters.refused.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "outside the selected LAN consent",
            ));
        }
        self.inner.try_send(transmit)?;
        self.counters.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(count)) => {
                for entry in &mut meta[..count] {
                    if !self.active.load(Ordering::Acquire) || !self.policy.permits(entry.addr) {
                        entry.len = 0;
                        entry.stride = 1;
                    }
                }
                Poll::Ready(Ok(count))
            }
            result => result,
        }
    }
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
