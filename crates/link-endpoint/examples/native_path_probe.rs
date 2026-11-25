//! Native loopback, shaped UDP and path recovery measurements.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use link_endpoint::{
    Endpoint, EndpointConfig, NodeId, PathStatus, RelaySpec, Session, TransportKey,
};
use link_relay::{RelayConfig, RelayHandle, TlsMaterial};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;

const MIB: usize = 1024 * 1024;
const BULK: usize = 64 * MIB;
const SMALL_BULK: usize = 8 * MIB;
const SHAPED_BULK: usize = 4 * MIB;
const SMALL: usize = 1024;
static CHUNK: [u8; 64 * 1024] = [0xa5; 64 * 1024];
const IPV4: &str = "127.0.0.1:0";
const IPV6: &str = "[::1]:0";

async fn serve(session: &Session, count: usize) -> Result<()> {
    for _ in 0..count {
        let mut stream = session.accept_stream().await?;
        let mut size = [0u8; 8];
        stream.recv.read_exact(&mut size).await?;
        let total = u64::from_be_bytes(size) as usize;
        for offset in (0..total).step_by(CHUNK.len()) {
            stream
                .send
                .write_all(&CHUNK[..CHUNK.len().min(total - offset)])
                .await?;
        }
        stream.send.finish()?;
    }
    Ok(())
}

async fn transfer(
    session: &Session,
    size: usize,
    expected: [u8; 32],
) -> Result<(Duration, Duration)> {
    let start = Instant::now();
    let mut stream = session.open_stream().await?;
    stream.send.write_all(&(size as u64).to_be_bytes()).await?;
    stream.send.finish()?;
    let mut buf = vec![0; 64 * 1024];
    let first = stream.recv.read(&mut buf).await?.context("no first byte")?;
    ensure!(first > 0, "empty packet");
    let latency = start.elapsed();
    let mut hasher = Sha256::new();
    hasher.update(&buf[..first]);
    let mut read = first;
    while let Some(n) = stream.recv.read(&mut buf).await? {
        hasher.update(&buf[..n]);
        read += n;
    }
    let elapsed = start.elapsed();
    let actual: [u8; 32] = hasher.finalize().into();
    ensure!(read == size && actual == expected, "wrong payload");
    Ok((latency, elapsed))
}

fn expected(size: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for offset in (0..size).step_by(CHUNK.len()) {
        hasher.update(&CHUNK[..CHUNK.len().min(size - offset)]);
    }
    hasher.finalize().into()
}

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

struct Gateway {
    addrs: (SocketAddr, SocketAddr),
    active: Arc<AtomicBool>,
    tasks: [JoinHandle<Result<()>>; 2],
}

impl Gateway {
    async fn start(pair: &Pair) -> Result<Self> {
        let front_a = Arc::new(UdpSocket::bind(IPV4).await?);
        let front_b = Arc::new(UdpSocket::bind(IPV6).await?);
        let addrs = (front_a.local_addr()?, front_b.local_addr()?);
        let active = Arc::new(AtomicBool::new(true));
        let a_to_b = tokio::spawn(forward(
            front_a.clone(),
            pair.a.paths().udp_local(),
            front_b.clone(),
            pair.b.paths().udp_local(),
            active.clone(),
        ));
        let b_to_a = tokio::spawn(forward(
            front_b,
            pair.b.paths().udp_local(),
            front_a,
            pair.a.paths().udp_local(),
            active.clone(),
        ));
        Ok(Self {
            addrs,
            active,
            tasks: [a_to_b, b_to_a],
        })
    }

    fn advertise(&self, pair: &Pair) {
        pair.a
            .paths()
            .set_peer_candidates(pair.b.node_id(), vec![self.addrs.0]);
        pair.b
            .paths()
            .set_peer_candidates(pair.a.node_id(), vec![self.addrs.1]);
        pair.sending.request_direct();
        pair.receiving.request_direct();
    }

    fn check(&self) -> Result<()> {
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

struct Pair {
    a: Endpoint,
    b: Endpoint,
    sending: Session,
    receiving: Arc<Session>,
    relay: RelayHandle,
}

impl Pair {
    async fn start(direct: bool, shaped: bool, idle_routes: u8) -> Result<Self> {
        let tls = TlsMaterial::self_signed(&["127.0.0.1".into()])?;
        let pin = tls.fingerprint();
        let relay = link_relay::start(RelayConfig {
            tls: Some(tls),
            ..RelayConfig::default()
        })
        .await?;
        let spec = RelaySpec::pinned(relay.url("127.0.0.1"), pin);
        let a_key = TransportKey::generate();
        let b_key = TransportKey::generate();
        let a_id = a_key.node_id();
        let b_id = b_key.node_id();
        let config = |key, peer, bind: &str| {
            let mut config = EndpointConfig::new(key);
            config.relays = vec![spec.clone()];
            config.allow_direct = direct;
            config.bind = bind.parse().expect("loopback socket");
            config.net_poll = Duration::ZERO;
            if shaped {
                config.probe_delay = Duration::from_secs(3600);
            }
            let mut routes = HashMap::from([(peer, Zeroizing::new([0x51; 32]))]);
            for index in 1..=idle_routes {
                routes.insert(NodeId([index; 32]), Zeroizing::new([index; 32]));
            }
            config.paired_routes = Some(routes);
            config
        };
        // Different address families force the direct path through the gateway.
        let b_bind = if shaped { IPV6 } else { IPV4 };
        let (a, b) = tokio::try_join!(
            Endpoint::open(config(a_key, b_id, IPV4)),
            Endpoint::open(config(b_key, a_id, b_bind))
        )?;
        let card = b.card(Duration::from_secs(300), Vec::new());
        let (sending, receiving) = timeout(Duration::from_secs(15), async {
            tokio::try_join!(a.connect(&card), b.accept())
        })
        .await??;
        if shaped {
            timeout(Duration::from_secs(5), async {
                while a.paths().candidate_updates(b_id) == 0
                    || b.paths().candidate_updates(a_id) == 0
                {
                    sleep(Duration::from_millis(2)).await;
                }
            })
            .await?;
        }
        Ok(Self {
            a,
            b,
            sending,
            receiving: Arc::new(receiving),
            relay,
        })
    }

    async fn wait_path(
        &self,
        status: PathStatus,
        addrs: Option<(SocketAddr, SocketAddr)>,
    ) -> Result<()> {
        timeout(Duration::from_secs(18), async {
            loop {
                let a = self.sending.path();
                let b = self.receiving.path();
                if a.status == status
                    && b.status == status
                    && addrs.is_none_or(|(a_addr, b_addr)| {
                        self.a
                            .paths()
                            .proven_direct(self.b.node_id())
                            .is_some_and(|proof| proof.addr == a_addr)
                            && self
                                .b
                                .paths()
                                .proven_direct(self.a.node_id())
                                .is_some_and(|proof| proof.addr == b_addr)
                    })
                {
                    return;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .with_context(|| format!("did not reach {status} at {addrs:?}"))
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        self.relay.shutdown();
    }
}

async fn throughput(mode: &str, samples: usize) -> Result<()> {
    let shaped = mode == "shaped";
    let roster = mode == "relay-roster";
    let direct = matches!(mode, "direct" | "shaped");
    let status = if direct {
        PathStatus::Direct
    } else {
        PathStatus::Relayed
    };
    let pair = Pair::start(direct, shaped, if roster { 32 } else { 0 }).await?;
    let gateway = if shaped {
        let gateway = Gateway::start(&pair).await?;
        gateway.advertise(&pair);
        Some(gateway)
    } else {
        None
    };
    let addrs = gateway.as_ref().map(|gateway| gateway.addrs);
    pair.wait_path(status, addrs).await?;
    let history = (pair.sending.history().len(), pair.receiving.history().len());
    let bulk_size = match mode {
        "shaped" => SHAPED_BULK,
        "relay-roster" => SMALL_BULK,
        _ => BULK,
    };
    let send = async {
        let bulk_digest = expected(bulk_size);
        let small_digest = expected(SMALL);
        for round in 0..samples + 2 {
            let (_, elapsed) = timeout(
                Duration::from_secs(30),
                transfer(&pair.sending, bulk_size, bulk_digest),
            )
            .await??;
            ensure!(pair.sending.path().status == status, "path changed");
            if round >= 2 {
                let mib = bulk_size as f64 / MIB as f64;
                println!("bulk,{mode},{:.4}", mib / elapsed.as_secs_f64());
            }
        }
        for round in 0..64 {
            let (ttfb, _) = timeout(
                Duration::from_secs(15),
                transfer(&pair.sending, SMALL, small_digest),
            )
            .await??;
            if round >= 2 {
                println!("ttfb,{mode},{:.4}", ttfb.as_secs_f64() * 1e6);
            }
        }
        Ok(())
    };
    let receiving = pair.receiving.clone();
    let server = tokio::spawn(async move { serve(&receiving, samples + 2 + 64).await });
    tokio::try_join!(async { server.await? }, send)?;
    ensure!(
        history == (pair.sending.history().len(), pair.receiving.history().len()),
        "path changed during a transfer"
    );
    pair.wait_path(status, addrs).await?;
    if let Some(gateway) = gateway {
        gateway.check()?;
    }
    tokio::join!(pair.a.close(), pair.b.close());
    Ok(())
}

async fn recover(handover: bool) -> Result<Duration> {
    let pair = Pair::start(true, true, 0).await?;
    let original = Gateway::start(&pair).await?;
    original.advertise(&pair);
    pair.wait_path(PathStatus::Direct, Some(original.addrs))
        .await?;
    let digest = expected(SMALL);
    let exercise = async {
        timeout(
            Duration::from_secs(5),
            transfer(&pair.sending, SMALL, digest),
        )
        .await??;
        let new_gateway = if handover {
            Some(Gateway::start(&pair).await?)
        } else {
            None
        };
        let start = Instant::now();
        original.active.store(false, Ordering::Relaxed);
        let (status, addrs) = if let Some(gateway) = &new_gateway {
            gateway.advertise(&pair);
            (PathStatus::Direct, Some(gateway.addrs))
        } else {
            (PathStatus::Relayed, None)
        };
        tokio::try_join!(
            async {
                timeout(
                    Duration::from_secs(45),
                    transfer(&pair.sending, SMALL, digest),
                )
                .await??;
                Ok::<_, anyhow::Error>(())
            },
            pair.wait_path(status, addrs)
        )?;
        let elapsed = start.elapsed();
        original.check()?;
        if let Some(gateway) = &new_gateway {
            gateway.check()?;
        }
        Ok(elapsed)
    };
    let ((), elapsed) = tokio::try_join!(serve(&pair.receiving, 2), exercise)?;
    tokio::join!(pair.a.close(), pair.b.close());
    Ok(elapsed)
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().unwrap_or_else(|| "direct".into());
    let samples = args
        .next()
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(10usize);
    ensure!(
        samples > 0 && args.next().is_none(),
        "provide a mode and positive sample count"
    );
    match mode.as_str() {
        "direct" | "shaped" | "relay" | "relay-roster" => throughput(&mode, samples).await?,
        "blackhole" | "handover" => {
            let handover = mode == "handover";
            for offset in (0..samples).step_by(4) {
                let mut batch = JoinSet::new();
                for _ in offset..samples.min(offset + 4) {
                    batch.spawn(recover(handover));
                }
                while let Some(sample) = batch.join_next().await {
                    println!("recovery,{mode},{:.4}", sample??.as_secs_f64() * 1000.0);
                }
            }
        }
        _ => anyhow::bail!("use direct, shaped, relay, relay-roster, blackhole or handover"),
    }
    Ok(())
}
