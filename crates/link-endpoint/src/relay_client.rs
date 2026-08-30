//! The outbound WebSocket relay session of spec 3.1, with the failover of 4.3.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Waker;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use link_core::id::{NodeId, TransportKey};
use link_core::wire::{Frame, MAX_QUEUED_FRAMES};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

use crate::rendezvous_book::TagBook;

/// Backoff bounds of spec 4.3.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Reconnecting for longer than this is `Failed(Relay)`, spec 4.3.
const RECONNECT_DEADLINE: Duration = Duration::from_secs(60);
/// Well inside the relay's 90 second idle close.
const PING_INTERVAL: Duration = Duration::from_secs(20);

/// One configured relay.
#[derive(Clone, Debug)]
pub struct RelaySpec {
    pub url: String,
    /// SHA-256 of the relay's DER leaf.  The spike pins rather than ship a root store.
    pub cert_sha256: Option<String>,
    /// Accept any relay leaf.  Development only, and it says so in the logs.
    pub insecure_tls: bool,
}

impl RelaySpec {
    pub fn plain(url: impl Into<String>) -> Self {
        RelaySpec {
            url: url.into(),
            cert_sha256: None,
            insecure_tls: false,
        }
    }

    pub fn pinned(url: impl Into<String>, cert_sha256: impl Into<String>) -> Self {
        RelaySpec {
            url: url.into(),
            cert_sha256: Some(cert_sha256.into()),
            insecure_tls: false,
        }
    }

    fn parts(&self) -> anyhow::Result<(bool, String, u16, String)> {
        let (tls, rest) = if let Some(rest) = self.url.strip_prefix("wss://") {
            (true, rest)
        } else if let Some(rest) = self.url.strip_prefix("ws://") {
            (false, rest)
        } else {
            anyhow::bail!("relay URL must start with ws:// or wss://");
        };
        let (authority, path) = match rest.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (rest, "/".to_string()),
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                (h.to_string(), p.parse::<u16>()?)
            }
            _ => (authority.to_string(), if tls { 443 } else { 80 }),
        };
        Ok((tls, host.to_lowercase(), port, path))
    }

    /// The lowercase host a node signs against, spec 3.1.  The port is not part
    /// of it, which the spec does not say explicitly.
    pub fn host(&self) -> anyhow::Result<String> {
        Ok(self.parts()?.1)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayStatus {
    Connecting,
    Up(String),
    Reconnecting,
    Failed,
}

/// Write-readiness for quinn's `UdpPoller`.  A hand-rolled waker set, because
/// the poller must be `Sync` and one shared waker would starve a second driver.
#[derive(Default, Debug)]
pub struct WriteReadiness {
    wakers: std::sync::Mutex<Vec<(u64, Waker)>>,
    next_id: AtomicU64,
}

impl WriteReadiness {
    pub fn new_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn register(&self, id: u64, waker: &Waker) {
        let mut wakers = self.wakers.lock().expect("wakers");
        match wakers.iter_mut().find(|(existing, _)| *existing == id) {
            Some(slot) => slot.1 = waker.clone(),
            None => wakers.push((id, waker.clone())),
        }
    }

    pub fn unregister(&self, id: u64) {
        self.wakers
            .lock()
            .expect("wakers")
            .retain(|(existing, _)| *existing != id);
    }

    fn wake_all(&self) {
        let woken: Vec<Waker> = self
            .wakers
            .lock()
            .expect("wakers")
            .drain(..)
            .map(|(_, w)| w)
            .collect();
        for waker in woken {
            waker.wake();
        }
    }
}

/// Ordered relay status events.  A watch channel only ever holds the latest
/// value, so a relay outage shorter than an observer's poll interval would
/// vanish from it; a broadcast queue keeps every distinct state in order.
const EVENT_CAPACITY: usize = 64;

/// A handle onto the single live relay session.
#[derive(Clone)]
pub struct RelayClient {
    outbound: mpsc::Sender<Frame>,
    status: watch::Receiver<RelayStatus>,
    events: broadcast::Sender<RelayStatus>,
    readiness: Arc<WriteReadiness>,
    /// `Some` switches the session to tag mode, spec 9: registration instead
    /// of identity auth, and sends translated to the pair's current tag.
    book: Option<Arc<TagBook>>,
}

/// What the path socket should do with a datagram it could not queue.
pub enum QueueOutcome {
    Queued,
    /// The relay is up but the queue is full: apply backpressure to quinn.
    WouldBlock,
    /// No relay session at all: the datagram is loss, which QUIC handles.
    Dropped,
}

impl RelayClient {
    /// Queue a datagram for the relay.  Never blocks, so it is safe to call
    /// from quinn's driver.
    pub fn try_send(&self, destination: NodeId, datagram: &[u8]) -> QueueOutcome {
        let (up, host) = match &*self.status.borrow() {
            RelayStatus::Up(url) => (true, RelaySpec::plain(url.clone()).host().ok()),
            _ => (false, None),
        };
        let frame = match &self.book {
            None => Frame::Send {
                destination,
                datagram: datagram.to_vec(),
            },
            Some(book) => {
                // Tag mode: the peer's identity never goes to the relay.  The
                // tag depends on which relay this session is on, so nothing is
                // sendable before the welcome names it.
                let Some(host) = host else {
                    return QueueOutcome::Dropped;
                };
                let Some(tag) = book.tag_for_send(destination, &host, now_unix()) else {
                    return QueueOutcome::Dropped;
                };
                Frame::SendTag {
                    tag,
                    datagram: datagram.to_vec(),
                }
            }
        };
        match self.outbound.try_send(frame) {
            Ok(()) => QueueOutcome::Queued,
            Err(mpsc::error::TrySendError::Full(_)) if up => QueueOutcome::WouldBlock,
            Err(_) => QueueOutcome::Dropped,
        }
    }

    pub fn has_capacity(&self) -> bool {
        self.outbound.capacity() > 0
    }

    pub fn readiness(&self) -> &Arc<WriteReadiness> {
        &self.readiness
    }

    pub fn status(&self) -> RelayStatus {
        self.status.borrow().clone()
    }

    pub fn watch(&self) -> watch::Receiver<RelayStatus> {
        self.status.clone()
    }

    /// Every distinct status this client enters from now on, in order.  A
    /// session watches this rather than sampling `status()`, so a reconnect
    /// that completes in tens of milliseconds is still recorded.
    pub fn subscribe(&self) -> broadcast::Receiver<RelayStatus> {
        self.events.subscribe()
    }

    /// Wait until a relay welcome has arrived, or the reconnect deadline passes.
    pub async fn wait_up(&self) -> Option<String> {
        let mut rx = self.status.clone();
        loop {
            match &*rx.borrow_and_update() {
                RelayStatus::Up(url) => return Some(url.clone()),
                RelayStatus::Failed => return None,
                _ => {}
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    }
}

/// Start the relay driver.  Inbound datagrams are pushed to `inbound`.
pub fn spawn(
    key: TransportKey,
    relays: Vec<RelaySpec>,
    inbound: mpsc::Sender<(NodeId, Vec<u8>)>,
    book: Option<Arc<TagBook>>,
) -> RelayClient {
    let (outbound_tx, outbound_rx) = mpsc::channel::<Frame>(MAX_QUEUED_FRAMES);
    let (status_tx, status_rx) = watch::channel(RelayStatus::Connecting);
    let readiness = Arc::new(WriteReadiness::default());
    let (events_tx, _) = broadcast::channel(EVENT_CAPACITY);
    tokio::spawn(driver(
        key,
        relays,
        inbound,
        outbound_rx,
        status_tx,
        events_tx.clone(),
        readiness.clone(),
        book.clone(),
    ));
    RelayClient {
        outbound: outbound_tx,
        status: status_rx,
        events: events_tx,
        readiness,
        book,
    }
}

/// Publish a status, on the watch for anyone asking "what now" and on the
/// broadcast for anyone that must not miss a step.
fn set_status(
    status: &watch::Sender<RelayStatus>,
    events: &broadcast::Sender<RelayStatus>,
    next: RelayStatus,
) {
    if *status.borrow() == next {
        return;
    }
    let _ = status.send(next.clone());
    let _ = events.send(next);
}

#[allow(clippy::too_many_arguments)]
async fn driver(
    key: TransportKey,
    relays: Vec<RelaySpec>,
    inbound: mpsc::Sender<(NodeId, Vec<u8>)>,
    mut outbound: mpsc::Receiver<Frame>,
    status: watch::Sender<RelayStatus>,
    events: broadcast::Sender<RelayStatus>,
    readiness: Arc<WriteReadiness>,
    book: Option<Arc<TagBook>>,
) {
    if relays.is_empty() {
        set_status(&status, &events, RelayStatus::Failed);
        return;
    }
    let mut index = 0usize;
    let mut backoff = BACKOFF_MIN;
    let mut down_since: Option<std::time::Instant> = None;

    loop {
        let spec = relays[index % relays.len()].clone();
        match connect(&key, &spec, book.as_deref()).await {
            Ok(ws) => {
                backoff = BACKOFF_MIN;
                // Drop anything queued while the previous relay was down.  Those
                // datagrams are stale and QUIC has already retransmitted; in tag
                // mode they also carry the previous relay's tags.
                while outbound.try_recv().is_ok() {}
                set_status(&status, &events, RelayStatus::Up(spec.url.clone()));
                readiness.wake_all();
                info!(relay = %spec.url, "relay session up");
                let host = spec.host().unwrap_or_default();
                pump(
                    ws,
                    &mut outbound,
                    &inbound,
                    &readiness,
                    book.as_deref(),
                    &host,
                )
                .await;
                warn!(relay = %spec.url, "relay session lost");
                set_status(&status, &events, RelayStatus::Reconnecting);
                down_since = Some(std::time::Instant::now());
                readiness.wake_all();
                // Spec 4.3: next configured relay, then the same one.
                index += 1;
                continue;
            }
            Err(e) => {
                debug!(relay = %spec.url, error = %e, "relay connect failed");
                set_status(&status, &events, RelayStatus::Reconnecting);
                let since = *down_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() > RECONNECT_DEADLINE {
                    warn!("no relay within 60 s");
                    set_status(&status, &events, RelayStatus::Failed);
                    return;
                }
                index += 1;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

type Socket = tokio_tungstenite::WebSocketStream<Box<dyn Duplex>>;

pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

async fn connect(
    key: &TransportKey,
    spec: &RelaySpec,
    book: Option<&TagBook>,
) -> anyhow::Result<Socket> {
    let (tls, host, port, path) = spec.parts()?;
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await??;
    stream.set_nodelay(true).ok();

    let transport: Box<dyn Duplex> = if tls {
        let connector = crate::relay_tls::connector(spec)?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())?;
        Box::new(connector.connect(server_name, stream).await?)
    } else {
        Box::new(stream)
    };

    let request = format!("{}://{host}:{port}{path}", if tls { "wss" } else { "ws" });
    let (mut ws, _) = tokio_tungstenite::client_async(request, transport).await?;

    // First contact: identity auth (spec 3.1) or tag registration (spec 9).
    let challenge = match next_frame(&mut ws).await? {
        Some(Frame::Challenge(challenge)) => challenge,
        other => anyhow::bail!("expected a challenge, got {other:?}"),
    };
    match book {
        None => {
            let signature = link_core::wire::sign_relay_auth(key, &host, &challenge);
            ws.send(Message::Binary(
                Frame::Auth {
                    node_id: key.node_id(),
                    signature,
                }
                .encode(),
            ))
            .await?;
        }
        Some(book) => {
            // No identity and no signature ever go to the relay on this path;
            // the challenge is acknowledged by ignoring it.
            let tags = book.registration(&host, now_unix());
            if tags.is_empty() {
                anyhow::bail!("tag mode with no rendezvous pairs to register");
            }
            ws.send(Message::Binary(Frame::Register { tags }.encode()))
                .await?;
        }
    }
    match next_frame(&mut ws).await? {
        Some(Frame::Welcome(_token)) => Ok(ws),
        other => anyhow::bail!("expected a welcome, got {other:?}"),
    }
}

async fn next_frame(ws: &mut Socket) -> anyhow::Result<Option<Frame>> {
    let message = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await?
        .transpose()?;
    Ok(match message {
        Some(Message::Binary(bytes)) => Frame::decode(&bytes),
        Some(_) => None,
        None => None,
    })
}

async fn pump(
    mut ws: Socket,
    outbound: &mut mpsc::Receiver<Frame>,
    inbound: &mpsc::Sender<(NodeId, Vec<u8>)>,
    readiness: &WriteReadiness,
    book: Option<&TagBook>,
    host: &str,
) {
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Tag mode re-registers when the epoch turns, so the relay always holds the
    // previous, current and next epoch's tags for every pair.
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_epoch = link_core::rendezvous::epoch_index(now_unix());
    let mut nonce = [0u8; 8];
    loop {
        tokio::select! {
            _ = ping.tick() => {
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                if ws.send(Message::Binary(Frame::Ping(nonce).encode())).await.is_err() {
                    return;
                }
            }
            _ = refresh.tick(), if book.is_some() => {
                let current = link_core::rendezvous::epoch_index(now_unix());
                if current != last_epoch {
                    last_epoch = current;
                    if let Some(book) = book {
                        let tags = book.registration(host, now_unix());
                        if !tags.is_empty()
                            && ws.send(Message::Binary(Frame::Register { tags }.encode())).await.is_err()
                        {
                            return;
                        }
                    }
                }
            }
            frame = outbound.recv() => {
                let Some(frame) = frame else { return };
                if ws.send(Message::Binary(frame.encode())).await.is_err() {
                    return;
                }
                // Hysteresis: wake a stalled sender once the queue is half empty.
                if outbound.capacity() >= MAX_QUEUED_FRAMES / 2 {
                    readiness.wake_all();
                }
            }
            message = ws.next() => {
                let Some(Ok(message)) = message else { return };
                match message {
                    Message::Binary(bytes) => match Frame::decode(&bytes) {
                        Some(Frame::Recv { source, datagram }) => {
                            // Identity deliveries belong to identity sessions.
                            if book.is_some() {
                                return;
                            }
                            // A full inbound queue is loss, not backpressure.
                            let _ = inbound.try_send((source, datagram));
                        }
                        Some(Frame::RecvTag { tag, datagram }) => {
                            let Some(book) = book else { return };
                            // Attribute by this endpoint's own book; a tag it
                            // cannot resolve (a stale epoch, a removed pair) is
                            // dropped, which QUIC treats as loss.
                            if let Some(peer) = book.resolve(&tag, host, now_unix()) {
                                let _ = inbound.try_send((peer, datagram));
                            }
                        }
                        Some(Frame::Pong(_)) => {}
                        Some(Frame::Close(reason)) => {
                            debug!(reason, "relay closed the session");
                            return;
                        }
                        _ => return,
                    },
                    Message::Ping(payload) => {
                        if ws.send(Message::Pong(payload)).await.is_err() {
                            return;
                        }
                    }
                    Message::Pong(_) => {}
                    _ => return,
                }
            }
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
