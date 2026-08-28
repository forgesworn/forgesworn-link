//! Shared loopback harness.  Everything here runs on 127.0.0.1 with plain
//! `ws://`, which is what the relay allows on loopback.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use link_core::card::{Card, VerifyContext};
use link_endpoint::{
    Endpoint, EndpointConfig, PathReport, PathStatus, RelaySpec, Session, TransportKey,
};
use link_relay::{RelayConfig, RelayHandle};
use sha2::{Digest, Sha256};

pub const MIB: usize = 1024 * 1024;

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "link_endpoint=info,link_relay=info".into()),
        )
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub async fn start_relay() -> RelayHandle {
    link_relay::start(RelayConfig {
        ws_bind: "127.0.0.1:0".parse().unwrap(),
        udp_bind: "127.0.0.1:0".parse().unwrap(),
        hosts: vec!["127.0.0.1".into()],
        tls: None,
        bytes_per_second: 0,
        max_sessions: 64,
        reflector_per_second: 100.0,
    })
    .await
    .expect("relay starts")
}

pub struct EndpointOptions {
    pub relays: Vec<RelaySpec>,
    pub allow_direct: bool,
    pub probe_delay: Duration,
    pub reflector: Option<std::net::SocketAddr>,
}

pub async fn start_endpoint(options: EndpointOptions) -> Endpoint {
    let mut config = EndpointConfig::new(TransportKey::generate());
    config.relays = options.relays;
    config.allow_direct = options.allow_direct;
    config.probe_delay = options.probe_delay;
    config.reflector = options.reflector;
    // Bind loopback so the announced candidate is unambiguous on a test machine.
    config.bind = "127.0.0.1:0".parse().unwrap();
    Endpoint::open(config).await.expect("endpoint opens")
}

/// Card delivery is out of scope for the transport, so the test does it by hand
/// and verifies the exact bytes, which is what a pairing flow would do.
pub fn exchange_card(from: &Endpoint) -> Card {
    let card = from.card(Duration::from_secs(300), Vec::new());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    Card::verify(
        card.as_bytes(),
        &VerifyContext::new(now).expecting(from.node_id()),
    )
    .expect("a freshly signed card verifies")
}

/// Deterministic payload so both ends can be checked without shipping a fixture.
pub fn fill(state: &mut u64, buf: &mut [u8]) {
    for chunk in buf.chunks_mut(8) {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        let bytes = x.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// Open a stream, send `total` deterministic bytes, read the peer's digest back.
/// Nothing on either side holds more than one 64 KiB buffer.
pub async fn send_and_verify(session: &Session, seed: u64, total: usize) -> anyhow::Result<()> {
    let mut stream = session.open_stream().await?;
    stream.send.write_all(&(total as u64).to_be_bytes()).await?;

    let mut hasher = Sha256::new();
    let mut state = seed;
    let mut buf = vec![0u8; 64 * 1024];
    let mut written = 0usize;
    while written < total {
        let len = buf.len().min(total - written);
        fill(&mut state, &mut buf[..len]);
        hasher.update(&buf[..len]);
        stream.send.write_all(&buf[..len]).await?;
        written += len;
    }
    stream.send.finish()?;
    let sent = hasher.finalize();

    let mut echoed = [0u8; 32];
    stream.recv.read_exact(&mut echoed).await?;
    anyhow::ensure!(
        echoed == sent.as_slice(),
        "digest mismatch: peer {} local {}",
        hex_of(&echoed),
        hex_of(&sent)
    );
    Ok(())
}

/// Accept one stream, sink it while hashing, and return the digest to the peer.
/// `received` is bumped as bytes actually arrive, so a test can act on progress
/// rather than on a wall clock.
pub async fn sink_one_stream(
    session: &Session,
    received: Option<&Arc<AtomicUsize>>,
) -> anyhow::Result<usize> {
    let mut stream = session.accept_stream().await?;
    let mut header = [0u8; 8];
    stream.recv.read_exact(&mut header).await?;
    let total = u64::from_be_bytes(header) as usize;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut read = 0usize;
    while read < total {
        let len = buf.len().min(total - read);
        stream.recv.read_exact(&mut buf[..len]).await?;
        hasher.update(&buf[..len]);
        read += len;
        if let Some(counter) = received {
            counter.store(read, Ordering::SeqCst);
        }
    }
    stream.send.write_all(&hasher.finalize()).await?;
    stream.send.finish()?;
    Ok(read)
}

/// Serve `count` streams in the background so a test can drive the other side.
pub fn spawn_sink(session: Arc<Session>, count: usize) -> tokio::task::JoinHandle<usize> {
    spawn_sink_counting(session, count, None)
}

pub fn spawn_sink_counting(
    session: Arc<Session>,
    count: usize,
    received: Option<Arc<AtomicUsize>>,
) -> tokio::task::JoinHandle<usize> {
    tokio::spawn(async move {
        let mut served = 0;
        for _ in 0..count {
            match sink_one_stream(&session, received.as_ref()).await {
                Ok(_) => served += 1,
                Err(_) => break,
            }
        }
        served
    })
}

pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Wait until the session's recorded transition history satisfies `predicate`,
/// then return that history.  Assertions read the history rather than the live
/// status, because a state such as `Reconnecting` can last under 100 ms and
/// polling for it is a race the test will eventually lose.
pub async fn wait_for_history(
    session: &Session,
    within: Duration,
    predicate: impl Fn(&[PathReport]) -> bool,
) -> Vec<PathReport> {
    let deadline = Instant::now() + within;
    loop {
        let history = session.history();
        if predicate(&history) || Instant::now() >= deadline {
            return history;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Wait for an arbitrary condition, such as a byte counter reaching a mark.
pub async fn wait_until(within: Duration, predicate: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

pub fn statuses(history: &[PathReport]) -> Vec<PathStatus> {
    history.iter().map(|report| report.status).collect()
}

pub fn saw_failed(history: &[PathReport]) -> bool {
    history
        .iter()
        .any(|report| matches!(report.status, PathStatus::Failed(_)))
}

pub fn saw(history: &[PathReport], status: PathStatus) -> bool {
    history.iter().any(|report| report.status == status)
}

/// True when `status` appears after the last occurrence of `after`.
pub fn saw_after(history: &[PathReport], after: PathStatus, status: PathStatus) -> bool {
    match history.iter().rposition(|report| report.status == after) {
        Some(index) => history[index + 1..].iter().any(|r| r.status == status),
        None => false,
    }
}

pub fn describe(history: &[PathReport]) -> String {
    history
        .iter()
        .map(|report| format!("{} ({})", report.status, report.cause))
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// Peak resident set size in bytes.  A high-water mark, so it never decreases.
/// Uses `getrusage`, so it is available on Unix only; the memory test that
/// consumes it is gated to Unix as well.
#[cfg(unix)]
pub fn peak_rss_bytes() -> u64 {
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: getrusage fills a caller-owned struct and touches nothing else.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
        return 0;
    }
    let raw = usage.ru_maxrss as u64;
    // Linux reports kibibytes, the BSDs and macOS report bytes.
    if cfg!(target_os = "linux") {
        raw * 1024
    } else {
        raw
    }
}
