//! Shared loopback traffic shaper for the native recovery probes.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

pub(super) const IPV4: &str = "127.0.0.1:0";
pub(super) const IPV6: &str = "[::1]:0";

async fn forward(
    receive: Arc<UdpSocket>,
    from: SocketAddr,
    send: Arc<UdpSocket>,
    target: SocketAddr,
    active: Arc<AtomicBool>,
) -> Result<()> {
    let mut queue = VecDeque::<(tokio::time::Instant, Vec<u8>)>::new();
    let mut buf = [0; 2048];
    let mut seen = 0u64;
    loop {
        let deadline = queue.front().map(|p| p.0);
        tokio::select! {
            biased;
            _ = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let (_, packet) = queue.pop_front().context("queued packet")?;
                if active.load(Ordering::Relaxed) {
                    send.send_to(&packet, target).await?;
                }
            }
            packet = receive.recv_from(&mut buf) => {
                let (size, source) = packet?;
                ensure!(source == from, "unexpected UDP peer {source}, want {from}");
                seen += 1;
                if active.load(Ordering::Relaxed) && !seen.is_multiple_of(200) {
                    ensure!(queue.len() < 8192, "UDP shaper queue filled");
                    queue.push_back((
                        tokio::time::Instant::now() + Duration::from_millis(20),
                        buf[..size].to_vec(),
                    ));
                }
            }
        }
    }
}

pub(super) struct Gateway {
    pub(super) addrs: (SocketAddr, SocketAddr),
    active: Arc<AtomicBool>,
    tasks: [JoinHandle<Result<()>>; 2],
}

impl Gateway {
    pub(super) async fn start(a: SocketAddr, b: SocketAddr) -> Result<Self> {
        let front_a = Arc::new(UdpSocket::bind(IPV4).await?);
        let front_b = Arc::new(UdpSocket::bind(IPV6).await?);
        let addrs = (front_a.local_addr()?, front_b.local_addr()?);
        let active = Arc::new(AtomicBool::new(true));
        let a_to_b = tokio::spawn(forward(
            front_a.clone(),
            a,
            front_b.clone(),
            b,
            active.clone(),
        ));
        let b_to_a = tokio::spawn(forward(front_b, b, front_a, a, active.clone()));
        Ok(Self {
            addrs,
            active,
            tasks: [a_to_b, b_to_a],
        })
    }

    pub(super) fn blackhole(&self) {
        self.active.store(false, Ordering::Relaxed);
    }

    pub(super) fn check(&self) -> Result<()> {
        ensure!(
            self.tasks.iter().all(|task| !task.is_finished()),
            "shaper stopped"
        );
        Ok(())
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
