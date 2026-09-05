//! The outbound WebSocket relay session of spec 3.1, with the failover of 4.3.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Waker;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use link_core::id::{NodeId, TransportKey};
use link_core::wire::{CLOSE_REASON_SUPERSEDED, Frame, MAX_QUEUED_FRAMES};
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
/// Bounds the whole TCP/TLS/WebSocket/registration exchange, including a
/// peer which accepts TCP but never completes its TLS or HTTP handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
    /// This identity-mode driver lost its node-ID slot to a newer process and
    /// has stopped permanently. Tag mode cannot attribute an eviction and
    /// therefore reports `Reconnecting` instead.
    Superseded,
    /// The current outage exceeded the session retry budget. The endpoint
    /// keeps trying its configured relays so a later operation can connect;
    /// sessions which have already failed are never resumed.
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

/// A datagram a relay session delivered, with which driver it arrived on so
/// the path socket can answer the peer on the same relay.
pub struct RelayInbound {
    pub source: NodeId,
    pub datagram: Vec<u8>,
    pub driver: u64,
}

/// A handle onto one relay driver: a single live session that walks its own
/// relay list with failover, spec 4.3.
#[derive(Clone)]
pub struct RelayDriver {
    id: u64,
    urls: Arc<Vec<String>>,
    outbound: mpsc::Sender<Frame>,
    status: watch::Receiver<RelayStatus>,
    events: broadcast::Sender<RelayStatus>,
    readiness: Arc<WriteReadiness>,
    /// `Some` switches the session to tag mode, spec 9: registration instead
    /// of identity auth, and sends translated to the pair's current tag.
    book: Option<Arc<TagBook>>,
    /// The lowercase host of the relay the session is on, memoised against
    /// its URL, so a tag-mode datagram costs no URL parse.
    host_memo: Arc<Mutex<Option<(String, String)>>>,
    stop: watch::Sender<bool>,
}

/// At most this many drivers beyond the home driver; past it a peer's hints
/// are ignored and the home relay is used, so fan-out is bounded.
const MAX_EXTRA_DRIVERS: usize = 16;

/// The relay pool, spec 3.1: the **home** driver over this endpoint's own
/// configured list, plus one driver per distinct relay list a peer's card
/// names, started on demand.  The dialer sends to a peer on the relay the
/// peer's card names and the acceptor answers on whichever driver the
/// dialer's datagrams arrived on, so two nodes need no shared configuration
/// to meet.
#[derive(Clone)]
pub struct RelayClient {
    key: TransportKey,
    book: Option<Arc<TagBook>>,
    inbound: mpsc::Sender<RelayInbound>,
    /// One write-readiness set for the whole pool: a drain on any driver
    /// wakes quinn, which retries and is told again if its driver is full.
    readiness: Arc<WriteReadiness>,
    home: RelayDriver,
    next_id: Arc<AtomicU64>,
    extra: Arc<Mutex<HashMap<Vec<String>, RelayDriver>>>,
    by_id: Arc<Mutex<HashMap<u64, RelayDriver>>>,
}

impl RelayClient {
    /// End every driver, including idle or failed drivers retrying in the
    /// background. A closed endpoint must not reconnect to its relays.
    pub fn close(&self) {
        let _extra = self.extra.lock().expect("drivers");
        for driver in self.by_id.lock().expect("drivers").values() {
            driver.stop.send_replace(true);
        }
    }

    /// The driver over this endpoint's own configured relays.
    pub fn home(&self) -> RelayDriver {
        self.home.clone()
    }

    /// The pool's write-readiness set.
    pub fn readiness(&self) -> &Arc<WriteReadiness> {
        &self.readiness
    }

    /// The driver with this id, if it is still in the pool.
    pub fn driver(&self, id: u64) -> Option<RelayDriver> {
        self.by_id.lock().expect("drivers").get(&id).cloned()
    }

    /// A driver over `relays`, started now if none exists yet.  A list equal
    /// to the home list is the home driver; an empty list is the home driver;
    /// past the fan-out bound it is the home driver too.
    pub fn driver_for(&self, relays: &[RelaySpec]) -> RelayDriver {
        let urls: Vec<String> = relays.iter().map(|spec| spec.url.clone()).collect();
        if urls.is_empty() || urls == *self.home.urls {
            return self.home.clone();
        }
        let mut extra = self.extra.lock().expect("drivers");
        if *self.home.stop.borrow() {
            return self.home.clone();
        }
        if let Some(driver) = extra.get(&urls) {
            return driver.clone();
        }
        if extra.len() >= MAX_EXTRA_DRIVERS {
            warn!(
                bound = MAX_EXTRA_DRIVERS,
                "relay fan-out bound reached; using the home relay for this peer"
            );
            return self.home.clone();
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let driver = spawn_driver(
            id,
            self.key.clone(),
            relays.to_vec(),
            self.inbound.clone(),
            self.book.clone(),
            self.readiness.clone(),
        );
        extra.insert(urls, driver.clone());
        self.by_id
            .lock()
            .expect("drivers")
            .insert(id, driver.clone());
        driver
    }
}

/// What the path socket should do with a datagram it could not queue.
pub enum QueueOutcome {
    Queued,
    /// The relay is up but the queue is full: apply backpressure to quinn.
    WouldBlock,
    /// No relay session at all: the datagram is loss, which QUIC handles.
    Dropped,
}

impl RelayDriver {
    /// This driver's id, which inbound datagrams carry.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The relay URLs this driver walks, in order.
    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// Queue a datagram for the relay.  Never blocks, so it is safe to call
    /// from quinn's driver.
    pub fn try_send(&self, destination: NodeId, datagram: &[u8]) -> QueueOutcome {
        let up = matches!(&*self.status.borrow(), RelayStatus::Up(_));
        let frame = match &self.book {
            None => Frame::Send {
                destination,
                datagram: datagram.to_vec(),
            },
            Some(book) => {
                // Tag mode: the peer's identity never goes to the relay.  The
                // tag depends on which relay this session is on, so nothing is
                // sendable before the welcome names it.
                let Some(tag) =
                    self.with_current_host(|host| book.tag_for_send(destination, host, now_unix()))
                else {
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

    /// Run `f` with the lowercase host of the relay the session is on, or
    /// return `None` when no session is up.  The host is parsed once per
    /// relay URL and memoised, so this is a string compare per call.
    fn with_current_host<T>(&self, f: impl FnOnce(&str) -> Option<T>) -> Option<T> {
        let status = self.status.borrow();
        let RelayStatus::Up(url) = &*status else {
            return None;
        };
        let mut memo = self.host_memo.lock().expect("host memo");
        if memo.as_ref().is_none_or(|(memo_url, _)| memo_url != url) {
            let host = RelaySpec::plain(url.clone()).host().ok()?;
            *memo = Some((url.clone(), host));
        }
        let (_, host) = memo.as_ref().expect("memoised above");
        f(host)
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
                RelayStatus::Superseded | RelayStatus::Failed => return None,
                _ => {}
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    }
}

/// Start the pool with its home driver over `relays`.  Inbound datagrams
/// from every driver are pushed to `inbound`.
pub fn spawn(
    key: TransportKey,
    relays: Vec<RelaySpec>,
    inbound: mpsc::Sender<RelayInbound>,
    book: Option<Arc<TagBook>>,
) -> RelayClient {
    let readiness = Arc::new(WriteReadiness::default());
    let home = spawn_driver(
        0,
        key.clone(),
        relays,
        inbound.clone(),
        book.clone(),
        readiness.clone(),
    );
    let by_id = HashMap::from([(0, home.clone())]);
    RelayClient {
        key,
        book,
        inbound,
        readiness,
        home,
        next_id: Arc::new(AtomicU64::new(1)),
        extra: Arc::new(Mutex::new(HashMap::new())),
        by_id: Arc::new(Mutex::new(by_id)),
    }
}

/// Start one driver over `relays` with the given id.
fn spawn_driver(
    id: u64,
    key: TransportKey,
    relays: Vec<RelaySpec>,
    inbound: mpsc::Sender<RelayInbound>,
    book: Option<Arc<TagBook>>,
    readiness: Arc<WriteReadiness>,
) -> RelayDriver {
    let (outbound_tx, outbound_rx) = mpsc::channel::<Frame>(MAX_QUEUED_FRAMES);
    let (status_tx, status_rx) = watch::channel(RelayStatus::Connecting);
    let (events_tx, _) = broadcast::channel(EVENT_CAPACITY);
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let urls: Vec<String> = relays.iter().map(|spec| spec.url.clone()).collect();
    let work = driver(
        id,
        key,
        relays,
        inbound,
        outbound_rx,
        status_tx.clone(),
        events_tx.clone(),
        readiness.clone(),
        book.clone(),
    );
    let stopped_events = events_tx.clone();
    let stopped_readiness = readiness.clone();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = stop_rx.changed() => {
                set_status(&status_tx, &stopped_events, RelayStatus::Failed);
                stopped_readiness.wake_all();
            }
            _ = work => {}
        }
    });
    RelayDriver {
        id,
        urls: Arc::new(urls),
        outbound: outbound_tx,
        status: status_rx,
        events: events_tx,
        readiness,
        book,
        host_memo: Arc::new(Mutex::new(None)),
        stop: stop_tx,
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
    driver_id: u64,
    key: TransportKey,
    relays: Vec<RelaySpec>,
    inbound: mpsc::Sender<RelayInbound>,
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
        if let Some(book) = &book
            && book.is_empty()
        {
            // A peerless tag node is idle, not failing: there is nothing to
            // register yet, so the reconnect deadline must not run and the
            // client must not die.  A fresh node learns its first pair from
            // the shell (a Nostr claim) after opening; the first upsert lets
            // the next pass connect and register within a second.
            set_status(&status, &events, RelayStatus::Connecting);
            down_since = None;
            tokio::time::sleep(BACKOFF_MIN).await;
            continue;
        }
        let spec = relays[index % relays.len()].clone();
        let attempt = tokio::time::timeout(CONNECT_TIMEOUT, connect(&key, &spec, book.as_deref()))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|result| result);
        match attempt {
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
                let end = pump(
                    driver_id,
                    ws,
                    &mut outbound,
                    &inbound,
                    &readiness,
                    book.as_deref(),
                    &host,
                )
                .await;
                match end {
                    PumpEnd::Lost => warn!(relay = %spec.url, "relay session lost"),
                    PumpEnd::Superseded => warn!(
                        relay = %spec.url,
                        "a newer session registered this node ID or tag"
                    ),
                }
                if end == PumpEnd::Superseded && book.is_none() {
                    // Identity mode can attribute the replacement exactly: a
                    // newer process with this node ID won.  Retrying made two
                    // live processes steal the slot from each other every 30
                    // seconds, contradicting newest-wins and stalling long
                    // transfers.  The superseded instance stops; a deliberate
                    // restart creates a new endpoint and may take the slot.
                    set_status(&status, &events, RelayStatus::Superseded);
                    readiness.wake_all();
                    return;
                }
                set_status(&status, &events, RelayStatus::Reconnecting);
                down_since = Some(std::time::Instant::now());
                readiness.wake_all();
                // Spec 4.3: next configured relay, then the same one.
                index += 1;
                if end == PumpEnd::Superseded {
                    // Tag mode cannot tell which endpoint a third holder of
                    // one pair tag replaced.  Back off before retrying so the
                    // legitimate two ends can converge without a hot loop.
                    tokio::time::sleep(BACKOFF_MAX).await;
                }
                continue;
            }
            Err(e) => {
                debug!(relay = %spec.url, error = %e, "relay connect failed");
                let since = *down_since.get_or_insert_with(std::time::Instant::now);
                if since.elapsed() > RECONNECT_DEADLINE {
                    if *status.borrow() != RelayStatus::Failed {
                        warn!("no relay within 60 s; sessions fail, endpoint keeps reconnecting");
                    }
                    set_status(&status, &events, RelayStatus::Failed);
                    readiness.wake_all();
                } else {
                    set_status(&status, &events, RelayStatus::Reconnecting);
                }
                index += 1;
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

type Socket = tokio_tungstenite::WebSocketStream<Box<dyn Duplex>>;

/// Why a relay session ended, as far as the pump can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PumpEnd {
    /// The socket failed, the relay closed for any other reason, or a frame
    /// was malformed: reconnect on the usual backoff.
    Lost,
    /// The relay said a newer session registered this node ID or tag (spec
    /// 3.1, close reason 2). Identity mode stops; anonymous tag mode backs off
    /// because it cannot attribute a third registration to either endpoint.
    Superseded,
}

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
    driver_id: u64,
    mut ws: Socket,
    outbound: &mut mpsc::Receiver<Frame>,
    inbound: &mpsc::Sender<RelayInbound>,
    readiness: &WriteReadiness,
    book: Option<&TagBook>,
    host: &str,
) -> PumpEnd {
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Tag mode re-registers when the epoch turns or the book changes (a card
    // rotation upsert), so the relay always holds the previous, current and
    // next epoch's tags for the current pair set.
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_epoch = link_core::rendezvous::epoch_index(now_unix());
    let mut last_version = book.map(TagBook::version).unwrap_or(0);
    // A dummy sender keeps identity mode's receiver pending forever.  Tag
    // mode replaces it with the book's broadcast state, so removals reach
    // every relay driver immediately, including an empty replacement set.
    let (_idle_changes, idle_rx) = watch::channel(0u64);
    let mut book_changes = book.map(TagBook::subscribe).unwrap_or(idle_rx);
    let mut nonce = [0u8; 8];
    loop {
        tokio::select! {
            _ = ping.tick() => {
                rand::rngs::OsRng.fill_bytes(&mut nonce);
                if ws.send(Message::Binary(Frame::Ping(nonce).encode())).await.is_err() {
                    return PumpEnd::Lost;
                }
            }
            _ = refresh.tick(), if book.is_some() => {
                let Some(book) = book else { continue };
                let current = link_core::rendezvous::epoch_index(now_unix());
                let version = book.version();
                if current != last_epoch || version != last_version {
                    last_epoch = current;
                    last_version = version;
                    let tags = book.registration(host, now_unix());
                    if ws.send(Message::Binary(Frame::Register { tags }.encode())).await.is_err() {
                        return PumpEnd::Lost;
                    }
                }
            }
            changed = book_changes.changed(), if book.is_some() => {
                if changed.is_err() {
                    return PumpEnd::Lost;
                }
                let Some(book) = book else { continue };
                last_epoch = link_core::rendezvous::epoch_index(now_unix());
                last_version = book.version();
                let tags = book.registration(host, now_unix());
                if ws.send(Message::Binary(Frame::Register { tags }.encode())).await.is_err() {
                    return PumpEnd::Lost;
                }
            }
            frame = outbound.recv() => {
                let Some(frame) = frame else { return PumpEnd::Lost };
                if ws.send(Message::Binary(frame.encode())).await.is_err() {
                    return PumpEnd::Lost;
                }
                // Hysteresis: wake a stalled sender once the queue is half empty.
                if outbound.capacity() >= MAX_QUEUED_FRAMES / 2 {
                    readiness.wake_all();
                }
            }
            message = ws.next() => {
                let Some(Ok(message)) = message else { return PumpEnd::Lost };
                match message {
                    Message::Binary(bytes) => match Frame::decode(&bytes) {
                        Some(Frame::Recv { source, datagram }) => {
                            // Identity deliveries belong to identity sessions.
                            if book.is_some() {
                                return PumpEnd::Lost;
                            }
                            // A full inbound queue is loss, not backpressure.
                            let _ = inbound.try_send(RelayInbound {
                                source,
                                datagram,
                                driver: driver_id,
                            });
                        }
                        Some(Frame::RecvTag { tag, datagram }) => {
                            let Some(book) = book else { return PumpEnd::Lost };
                            // Attribute by this endpoint's own book; a tag it
                            // cannot resolve (a stale epoch, a removed pair) is
                            // dropped, which QUIC treats as loss.
                            if let Some(peer) = book.resolve(&tag, host, now_unix()) {
                                let _ = inbound.try_send(RelayInbound {
                                    source: peer,
                                    datagram,
                                    driver: driver_id,
                                });
                            }
                        }
                        Some(Frame::Pong(_)) => {}
                        Some(Frame::Close(reason)) => {
                            debug!(reason, "relay closed the session");
                            return if reason == CLOSE_REASON_SUPERSEDED {
                                PumpEnd::Superseded
                            } else {
                                PumpEnd::Lost
                            };
                        }
                        _ => return PumpEnd::Lost,
                    },
                    Message::Ping(payload) => {
                        if ws.send(Message::Pong(payload)).await.is_err() {
                            return PumpEnd::Lost;
                        }
                    }
                    Message::Pong(_) => {}
                    _ => return PumpEnd::Lost,
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
