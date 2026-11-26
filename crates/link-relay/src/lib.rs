//! `link-relay`: the WebSocket datagram relay and the UDP reflector of spec
//! section 3, plus the tag-mode sessions of spec section 9.  One self-hostable
//! binary, two services, no persistence.
//!
//! A session speaks one of two modes, chosen by its first frame.  An identity
//! session authenticates a node ID and routes by it (spec 3.1, the deployed
//! behaviour).  A tag session registers pair-scoped rendezvous tags and routes
//! by them (spec 9). Private relays can also require proof of an operator
//! grant. The relay routes by tags and keeps identity frames off that path.

use std::collections::HashMap;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use link_core::admission::ADMISSION_PROOF_BYTES;
use link_core::id::NodeId;
use link_core::rendezvous::{TAG_BYTES, Tag};
use link_core::wire::{
    CLOSE_REASON_ADMISSION, CLOSE_REASON_MALFORMED, CLOSE_REASON_SUPERSEDED, Frame,
    IDLE_CLOSE_SECONDS, MAX_QUEUED_FRAMES, MAX_TAGS_PER_REGISTER, REFLECT_REQUEST_BYTES,
    parse_reflect_request, reflect_reply, verify_relay_auth,
};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message, protocol::WebSocketConfig};
use tracing::{info, warn};

mod admission;
pub use admission::{MAX_ADMISSION_KEYS, RelayAdmission};

/// The relay's process-level diagnostics. Embedding applications can enable
/// this target without enabling the WebSocket dependency's frame logging.
pub const LOG_TARGET: &str = "link_relay::summary";
const ACTIVITY_INTERVAL: Duration = Duration::from_secs(5 * 60);
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);
// Full Register: one frame type byte, a 16-bit count and the largest roster.
const MAX_MESSAGE_BYTES: usize = 1 + 2 + MAX_TAGS_PER_REGISTER * TAG_BYTES;

/// Anything the relay can speak WebSocket over: plain TCP or TLS.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

type RelayWebSocket = WebSocketStream<Box<dyn Duplex>>;

#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Address for the WebSocket listener.
    pub ws_bind: SocketAddr,
    /// Address for the UDP reflector.
    pub udp_bind: SocketAddr,
    /// Hosts a node may legitimately have signed against, lowercase, no port.
    pub hosts: Vec<String>,
    /// `None` means plain `ws://`, which is only acceptable on loopback.
    pub tls: Option<TlsMaterial>,
    /// Per-session outbound byte budget.  Zero means the operator set no budget.
    pub bytes_per_second: u64,
    /// Cap on concurrent sessions, counted from accept so unauthenticated
    /// handshakes cannot slip under it.
    pub max_sessions: usize,
    /// Cap on concurrent sessions from one source address, counted the same
    /// way.  Zero means no per-source cap.  A tag session presents no identity
    /// (spec 9), so without this one address could hold every slot; the
    /// rendezvous section makes the cap a MUST.
    pub max_sessions_per_source: usize,
    /// Reflector replies per source address per second.
    pub reflector_per_second: f64,
}

#[derive(Clone)]
pub struct TlsMaterial {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl fmt::Debug for TlsMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsMaterial")
            .field("cert_der_len", &self.cert_der.len())
            .field("key_der", &"[redacted]")
            .finish()
    }
}

impl TlsMaterial {
    /// A throwaway self-signed leaf for the spike.  A deployed relay presents an
    /// ordinary WebPKI certificate instead.
    pub fn self_signed(hosts: &[String]) -> anyhow::Result<TlsMaterial> {
        let names = if hosts.is_empty() {
            vec!["localhost".to_string()]
        } else {
            hosts.to_vec()
        };
        let key = rcgen::KeyPair::generate()?;
        let cert = rcgen::CertificateParams::new(names)?.self_signed(&key)?;
        Ok(TlsMaterial {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        })
    }

    /// SHA-256 over the DER leaf, which is what a client pins in the spike.
    pub fn fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        hex_lower(&Sha256::digest(&self.cert_der))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            ws_bind: "127.0.0.1:0".parse().expect("literal"),
            udp_bind: "127.0.0.1:0".parse().expect("literal"),
            hosts: vec!["127.0.0.1".into()],
            tls: None,
            bytes_per_second: 0,
            max_sessions: 1024,
            max_sessions_per_source: 16,
            reflector_per_second: 20.0,
        }
    }
}

/// A running relay.  Dropping the handle leaves it running; call `shutdown`.
pub struct RelayHandle {
    pub ws_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub tls_fingerprint: Option<String>,
    stop: watch::Sender<bool>,
}

impl RelayHandle {
    /// The `ws://` or `wss://` URL a node should dial, using the first host.
    pub fn url(&self, host: &str) -> String {
        let scheme = if self.tls_fingerprint.is_some() {
            "wss"
        } else {
            "ws"
        };
        format!("{scheme}://{host}:{}/link", self.ws_addr.port())
    }

    /// Stop accepting and close every live session.  Used by the relay-loss test.
    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }
}

#[derive(Default)]
struct Registry {
    /// Identity-mode sessions, spec 3.1: node ID to outbound queue.
    sessions: HashMap<NodeId, mpsc::Sender<Frame>>,
    /// Tag-mode sessions, spec 9: tag to (session id, outbound queue).  In
    /// practice a tag has the two ends of one pair; the Vec covers the epoch
    /// and card-rotation transition windows.
    tags: HashMap<Tag, Vec<(u64, mpsc::Sender<Frame>)>>,
    /// Connections currently inside `serve_session`, both modes, counted from
    /// accept so unauthenticated handshakes cannot slip under the cap.
    live: usize,
    /// Live connections per source address, for the per-source cap.  An
    /// entry leaves the map when its count reaches zero, so the map never
    /// grows with the history of addresses seen.
    by_source: HashMap<IpAddr, usize>,
    activity: RelayActivity,
}

type Shared = Arc<Mutex<Registry>>;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct RelayActivity {
    accepted: u64,
    refused_capacity: u64,
    refused_source: u64,
    session_errors: u64,
    accept_errors: u64,
    reflector_errors: u64,
    traffic: TrafficCounts,
}

#[derive(Default, PartialEq, Eq)]
struct TrafficCounts {
    frames_in: u64,
    frames_out: u64,
    bytes_in: u64,
    dropped: u64,
}

impl TrafficCounts {
    /// Batch on the session's existing idle tick and when the session ends,
    /// so reporting adds no shared lock or atomic operation per datagram.
    fn flush(&mut self, registry: &Shared) {
        if *self == Self::default() {
            return;
        }
        let mut guard = registry.lock().expect("registry");
        let total = &mut guard.activity.traffic;
        total.frames_in += self.frames_in;
        total.frames_out += self.frames_out;
        total.bytes_in += self.bytes_in;
        total.dropped += self.dropped;
        *self = Self::default();
    }
}

fn report_activity(registry: &Shared) {
    let (active, activity) = {
        let mut guard = registry.lock().expect("registry");
        (guard.live, std::mem::take(&mut guard.activity))
    };
    if activity.accept_errors != 0 || activity.reflector_errors != 0 {
        warn!(
            target: LOG_TARGET,
            accept_errors = activity.accept_errors,
            reflector_errors = activity.reflector_errors,
            "relay socket errors"
        );
    }
    info!(
        target: LOG_TARGET,
        active,
        accepted = activity.accepted,
        refused_capacity = activity.refused_capacity,
        refused_source = activity.refused_source,
        session_errors = activity.session_errors,
        accept_errors = activity.accept_errors,
        reflector_errors = activity.reflector_errors,
        frames_in = activity.traffic.frames_in,
        frames_out = activity.traffic.frames_out,
        bytes_in = activity.traffic.bytes_in,
        dropped = activity.traffic.dropped,
        "relay activity"
    );
}

/// Start both services. Returns once the sockets are bound.
pub async fn start(config: RelayConfig) -> anyhow::Result<RelayHandle> {
    start_inner(config, None).await
}

/// Start a relay that admits only tag connections proving an operator-issued key.
/// A loopback listener can sit behind the operator's TLS reverse proxy.
pub async fn start_with_admission(
    config: RelayConfig,
    admission: RelayAdmission,
) -> anyhow::Result<RelayHandle> {
    anyhow::ensure!(
        config.tls.is_some() || config.ws_bind.ip().is_loopback(),
        "an admission-controlled listener needs TLS or a loopback bind"
    );
    start_inner(config, Some(admission)).await
}

async fn start_inner(
    mut config: RelayConfig,
    admission: Option<RelayAdmission>,
) -> anyhow::Result<RelayHandle> {
    let listener = TcpListener::bind(config.ws_bind).await?;
    let ws_addr = listener.local_addr()?;
    let udp = Arc::new(UdpSocket::bind(config.udp_bind).await?);
    let udp_addr = udp.local_addr()?;
    let (stop, _) = watch::channel(false);
    let (acceptor, tls_fingerprint) = match config.tls.take() {
        Some(material) => {
            let fingerprint = material.fingerprint();
            (Some(build_acceptor(material)?), Some(fingerprint))
        }
        None => (None, None),
    };

    let registry: Shared = Arc::new(Mutex::new(Registry::default()));
    let config = Arc::new(config);

    // WebSocket accept loop.
    {
        let registry = registry.clone();
        let config = config.clone();
        let mut stop_rx = stop.subscribe();
        let session_stop = stop.subscribe();
        let mut report_tick = tokio::time::interval_at(
            tokio::time::Instant::now() + ACTIVITY_INTERVAL,
            ACTIVITY_INTERVAL,
        );
        report_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = stop_rx.changed() => break,
                    _ = report_tick.tick() => {
                        report_activity(&registry);
                        continue;
                    }
                    accepted = listener.accept() => accepted,
                };
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => {
                        registry.lock().expect("registry").activity.accept_errors += 1;
                        continue;
                    }
                };
                let upgrade_deadline = tokio::time::Instant::now() + UPGRADE_TIMEOUT;
                let source_ip = peer.ip();
                {
                    let mut guard = registry.lock().expect("registry");
                    if guard.live >= config.max_sessions {
                        guard.activity.refused_capacity += 1;
                        continue;
                    }
                    let from_source = guard.by_source.get(&source_ip).copied().unwrap_or(0);
                    if config.max_sessions_per_source > 0
                        && from_source >= config.max_sessions_per_source
                    {
                        // Refused before any frame, so it costs the relay a
                        // TCP accept and nothing else.
                        guard.activity.refused_source += 1;
                        continue;
                    }
                    *guard.by_source.entry(source_ip).or_insert(0) += 1;
                    guard.live += 1;
                    guard.activity.accepted += 1;
                }
                let registry = registry.clone();
                let config = config.clone();
                let acceptor = acceptor.clone();
                let admission = admission.clone();
                let stop_rx = session_stop.clone();
                tokio::spawn(async move {
                    let result = serve_session(
                        stream,
                        acceptor,
                        config,
                        registry.clone(),
                        stop_rx,
                        upgrade_deadline,
                        admission,
                    )
                    .await;
                    let mut guard = registry.lock().expect("registry");
                    if result.is_err() {
                        guard.activity.session_errors += 1;
                    }
                    guard.live -= 1;
                    if let Some(count) = guard.by_source.get_mut(&source_ip) {
                        *count -= 1;
                        if *count == 0 {
                            guard.by_source.remove(&source_ip);
                        }
                    }
                });
            }
        });
    }

    // UDP reflector.
    {
        let config = config.clone();
        let mut stop_rx = stop.subscribe();
        tokio::spawn(async move {
            let mut limiter = SourceLimiter::new(config.reflector_per_second);
            let mut buf = [0u8; 64];
            loop {
                let received = tokio::select! {
                    _ = stop_rx.changed() => break,
                    received = udp.recv_from(&mut buf) => received,
                };
                let (len, from) = match received {
                    Ok(pair) => pair,
                    Err(_) => {
                        registry.lock().expect("registry").activity.reflector_errors += 1;
                        continue;
                    }
                };
                if len != REFLECT_REQUEST_BYTES {
                    continue;
                }
                let Some(nonce) = parse_reflect_request(&buf[..len]) else {
                    continue;
                };
                if !limiter.allow(from.ip()) {
                    continue;
                }
                let reply = reflect_reply(&nonce, from);
                let _ = udp.send_to(&reply, from).await;
            }
        });
    }

    info!(target: LOG_TARGET, %ws_addr, %udp_addr, "relay listening");
    Ok(RelayHandle {
        ws_addr,
        udp_addr,
        tls_fingerprint,
        stop,
    })
}

fn build_acceptor(material: TlsMaterial) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert = CertificateDer::from(material.cert_der);
    let key =
        PrivateKeyDer::try_from(material.key_der).map_err(|e| anyhow::anyhow!("relay key: {e}"))?;
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// A token bucket per source address for the reflector, spec 3.2.
struct SourceLimiter {
    per_second: f64,
    seen: HashMap<IpAddr, (f64, Instant)>,
}

impl SourceLimiter {
    fn new(per_second: f64) -> Self {
        SourceLimiter {
            per_second,
            seen: HashMap::new(),
        }
    }

    fn allow(&mut self, source: IpAddr) -> bool {
        if self.seen.len() > 10_000 {
            let cutoff = Instant::now() - Duration::from_secs(60);
            self.seen.retain(|_, (_, last)| *last > cutoff);
        }
        let now = Instant::now();
        let burst = self.per_second * 2.0;
        let entry = self.seen.entry(source).or_insert((burst, now));
        let elapsed = now.duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.per_second).min(burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Which kind of session the first frame chose.
enum Mode {
    Identity(NodeId),
    Tags(Vec<Tag>),
}

/// Replace `session_id`'s registrations: drop `current`, add `next`.  A later
/// `Register` carries the full replacement set, which is how an endpoint
/// rotates epochs and cards.
fn register_tags(
    registry: &Shared,
    session_id: u64,
    tx: &mpsc::Sender<Frame>,
    current: &[Tag],
    next: &[Tag],
) {
    let mut guard = registry.lock().expect("registry");
    for tag in current {
        let empty = match guard.tags.get_mut(tag) {
            Some(entries) => {
                entries.retain(|(id, _)| *id != session_id);
                entries.is_empty()
            }
            None => false,
        };
        if empty {
            guard.tags.remove(tag);
        }
    }
    for tag in next {
        let entries = guard.tags.entry(*tag).or_default();
        if !entries.iter().any(|(id, _)| *id == session_id) {
            entries.push((session_id, tx.clone()));
            // A tag has two ends.  A third registrant is either an end that
            // reconnected before its old session died, or someone else who
            // holds the tag; in both cases the oldest session is the one to
            // go, and it is told why.
            while entries.len() > TAG_ENDS {
                let oldest = entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (id, _))| *id)
                    .map(|(index, _)| index)
                    .expect("more than two entries");
                let (_, evicted) = entries.remove(oldest);
                let _ = evicted.try_send(Frame::Close(CLOSE_REASON_SUPERSEDED));
            }
        }
    }
}

/// A rendezvous tag names one pair, so at most two sessions hold it.
const TAG_ENDS: usize = 2;

async fn open_websocket(
    stream: TcpStream,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    private: bool,
) -> anyhow::Result<RelayWebSocket> {
    stream.set_nodelay(true).ok();
    let transport: Box<dyn Duplex> = match acceptor {
        Some(acceptor) => Box::new(acceptor.accept(stream).await?),
        None => Box::new(stream),
    };
    let limit = MAX_MESSAGE_BYTES + if private { ADMISSION_PROOF_BYTES } else { 0 };
    let config = WebSocketConfig {
        max_frame_size: Some(limit),
        max_message_size: Some(limit),
        ..WebSocketConfig::default()
    };
    Ok(tokio_tungstenite::accept_async_with_config(transport, Some(config)).await?)
}

async fn close_on_capacity_error(ws: &mut RelayWebSocket, error: &WebSocketError) {
    if matches!(error, WebSocketError::Capacity(_)) {
        close_link(ws, CLOSE_REASON_MALFORMED).await;
    }
}

async fn send_message(
    ws: &mut RelayWebSocket,
    message: Message,
    limit: Duration,
) -> anyhow::Result<()> {
    // Poll the same send future through completion. Start a timer only if
    // the writer stalls, so a ready datagram needs no clock or timer work.
    let mut send = pin!(ws.send(message));
    match poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await {
        Poll::Ready(result) => Ok(result?),
        Poll::Pending => Ok(tokio::time::timeout(limit, send).await??),
    }
}

async fn close_link(ws: &mut RelayWebSocket, reason: u16) {
    let _ = send_message(ws, binary(Frame::Close(reason)), CLOSE_TIMEOUT).await;
}

async fn serve_session(
    stream: TcpStream,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    config: Arc<RelayConfig>,
    registry: Shared,
    mut stop_rx: watch::Receiver<bool>,
    upgrade_deadline: tokio::time::Instant,
    admission: Option<RelayAdmission>,
) -> anyhow::Result<()> {
    let handshake = async {
        let mut ws = tokio::time::timeout_at(
            upgrade_deadline,
            open_websocket(stream, acceptor, admission.is_some()),
        )
        .await??;
        // An identity session signs the challenge. An admitted tag session
        // uses it to prove an operator-issued key.
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut challenge);
        let challenge_frame = if admission.is_some() {
            Frame::AdmissionChallenge(challenge)
        } else {
            Frame::Challenge(challenge)
        };
        let first = tokio::time::timeout(FIRST_FRAME_TIMEOUT, async {
            ws.send(binary(challenge_frame)).await?;
            match ws.next().await {
                Some(Ok(message)) => Ok(message),
                Some(Err(error)) => {
                    close_on_capacity_error(&mut ws, &error).await;
                    Err(error.into())
                }
                None => Err(anyhow::anyhow!("closed before the first frame")),
            }
        })
        .await??;
        Ok::<_, anyhow::Error>((ws, challenge, first))
    };
    let (ws, challenge, first) = tokio::select! {
        biased;
        _ = stop_rx.changed() => return Ok(()),
        result = handshake => result?,
    };
    serve_registration(ws, challenge, first, config, registry, stop_rx, admission).await
}

async fn serve_registration(
    mut ws: RelayWebSocket,
    challenge: [u8; 32],
    first: Message,
    config: Arc<RelayConfig>,
    registry: Shared,
    mut stop_rx: watch::Receiver<bool>,
    admission: Option<RelayAdmission>,
) -> anyhow::Result<()> {
    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    // Bounded outbound queue, spec 3.1: at most 64 queued frames per session.
    let (tx, mut rx) = mpsc::channel::<Frame>(MAX_QUEUED_FRAMES);

    let (mut mode, mut active_grant) = match (decode_binary(&first), admission) {
        (Some(Frame::Auth { node_id, signature }), None) => {
            let ok = config
                .hosts
                .iter()
                .any(|host| verify_relay_auth(&node_id, host, &challenge, &signature));
            if !ok {
                close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
                anyhow::bail!("auth signature refused");
            }
            if let Some(previous) = registry
                .lock()
                .expect("registry")
                .sessions
                .insert(node_id, tx.clone())
            {
                // Newest wins.  The old session is told why, so a node that
                // reconnected before its old session died does not leave a
                // dead route behind, and a node that was replaced knows to
                // back off rather than fight for the slot.
                let _ = previous.try_send(Frame::Close(CLOSE_REASON_SUPERSEDED));
            }
            (Mode::Identity(node_id), None)
        }
        (Some(Frame::Register { tags }), None) if !tags.is_empty() => {
            register_tags(&registry, session_id, &tx, &[], &tags);
            (Mode::Tags(tags), None)
        }
        (Some(Frame::RegisterAdmitted { proof, tags }), Some(admission)) if !tags.is_empty() => {
            let Some(active) = admission.admit(&challenge, &tags, &proof, || {
                register_tags(&registry, session_id, &tx, &[], &tags);
            }) else {
                close_link(&mut ws, CLOSE_REASON_ADMISSION).await;
                anyhow::bail!("relay admission refused");
            };
            (Mode::Tags(tags), Some(active))
        }
        (_, Some(_)) => {
            close_link(&mut ws, CLOSE_REASON_ADMISSION).await;
            anyhow::bail!("relay admission required");
        }
        (_, None) => {
            close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
            anyhow::bail!("first frame was not an auth or a register");
        }
    };

    let mut token = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let mut traffic = TrafficCounts::default();

    // The session is registered from here on.  Every exit, an I/O error's `?`
    // included, leaves this block and reaches the cleanup below, so a socket
    // reset cannot leave a ghost registration behind (issue #58).
    let registered = async {
        send_message(&mut ws, binary(Frame::Welcome(token)), WRITE_TIMEOUT).await?;

        let mut last_ping = Instant::now();
        let mut idle_check = tokio::time::interval(Duration::from_secs(5));
        idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut budget = ByteBudget::new(config.bytes_per_second);

        loop {
            tokio::select! {
                _ = idle_check.tick() => {
                    traffic.flush(&registry);
                    if last_ping.elapsed() > Duration::from_secs(IDLE_CLOSE_SECONDS) {
                        close_link(&mut ws, 0).await;
                        break Ok(());
                    }
                }
                outbound = rx.recv() => {
                    match outbound {
                        Some(frame) => {
                            let closing = matches!(frame, Frame::Close(_));
                            let limit = if closing { CLOSE_TIMEOUT } else { WRITE_TIMEOUT };
                            send_message(&mut ws, binary(frame), limit).await?;
                            traffic.frames_out += 1;
                            if closing {
                                // A queued Close means a newer registration
                                // superseded this session; the frame said why and
                                // there is nothing left to route.
                                break Ok(());
                            }
                        }
                        None => break Ok(()),
                    }
                }
                incoming = ws.next() => {
                    let Some(message) = incoming else { break Ok(()) };
                    let message = match message {
                        Ok(message) => message,
                        Err(error) => {
                            close_on_capacity_error(&mut ws, &error).await;
                            break Err(error.into());
                        }
                    };
                    match message {
                        Message::Binary(_) => {}
                        Message::Ping(p) => {
                            send_message(&mut ws, Message::Pong(p), WRITE_TIMEOUT).await?;
                            continue;
                        }
                        Message::Pong(_) => continue,
                        Message::Close(_) => break Ok(()),
                        // Text and continuation frames are malformed for this protocol.
                        _ => {
                            close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
                            break Err(anyhow::anyhow!("non-binary frame"));
                        }
                    }
                    let Some(frame) = decode_binary(&message) else {
                        close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
                        break Err(anyhow::anyhow!("oversize or malformed frame"));
                    };
                    traffic.frames_in += 1;
                    match frame {
                        Frame::Send { destination, datagram } => {
                            let Mode::Identity(node_id) = &mode else {
                                close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
                                break Err(anyhow::anyhow!("identity frame on a tag session"));
                            };
                            let source = *node_id;
                            traffic.bytes_in += datagram.len() as u64;
                            if !budget.allow(datagram.len() as u64) {
                                traffic.dropped += 1;
                                continue;
                            }
                            let target = registry
                                .lock()
                                .expect("registry")
                                .sessions
                                .get(&destination)
                                .cloned();
                            // A destination with no session is dropped silently, which
                            // QUIC treats as loss.  So is a full queue.
                            match target {
                                Some(target) => {
                                    if target
                                        .try_send(Frame::Recv { source, datagram })
                                        .is_err()
                                    {
                                        traffic.dropped += 1;
                                    }
                                }
                                None => traffic.dropped += 1,
                            }
                        }
                        Frame::SendTag { tag, datagram } => {
                            if !matches!(mode, Mode::Tags(_)) {
                                close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
                                break Err(anyhow::anyhow!("tag frame on an identity session"));
                            }
                            traffic.bytes_in += datagram.len() as u64;
                            if !budget.allow(datagram.len() as u64) {
                                traffic.dropped += 1;
                                continue;
                            }
                            // Deliver to every other session registered with this
                            // tag.  A tag nobody has registered is dropped silently,
                            // so the relay never amplifies.
                            let targets: Vec<mpsc::Sender<Frame>> = registry
                                .lock()
                                .expect("registry")
                                .tags
                                .get(&tag)
                                .map(|entries| {
                                    entries
                                        .iter()
                                        .filter(|(id, _)| *id != session_id)
                                        .map(|(_, sender)| sender.clone())
                                        .collect()
                                })
                                .unwrap_or_default();
                            if targets.is_empty() {
                                traffic.dropped += 1;
                            } else {
                                for target in targets {
                                    if target
                                        .try_send(Frame::RecvTag { tag, datagram: datagram.clone() })
                                        .is_err()
                                    {
                                        traffic.dropped += 1;
                                    }
                                }
                            }
                        }
                        Frame::Register { tags: next } => {
                            let Mode::Tags(current) = &mode else {
                                close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
                                break Err(anyhow::anyhow!("register on an identity session"));
                            };
                            register_tags(&registry, session_id, &tx, current, &next);
                            mode = Mode::Tags(next);
                        }
                        Frame::Ping(opaque) => {
                            last_ping = Instant::now();
                            send_message(&mut ws, binary(Frame::Pong(opaque)), WRITE_TIMEOUT).await?;
                        }
                        Frame::Pong(_) => last_ping = Instant::now(),
                        Frame::Close(_) => break Ok(()),
                        // A client may only send, register, ping, pong or close.
                        _ => {
                            close_link(&mut ws, CLOSE_REASON_MALFORMED).await;
                            break Err(anyhow::anyhow!("unexpected frame from client"));
                        }
                    }
                }
            }
        }
    };
    // Observe shutdown and grant removal even while a write awaits capacity.
    let mut revoked = false;
    let result: anyhow::Result<()> = tokio::select! {
        biased;
        _ = stop_rx.changed() => {
            close_link(&mut ws, 0).await;
            Ok(())
        }
        _ = admission::revoked(&mut active_grant) => {
            revoked = true;
            Ok(())
        }
        result = registered => result,
    };

    // Whatever the session registered leaves the relay's memory with it.
    match &mode {
        Mode::Identity(node_id) => {
            let mut guard = registry.lock().expect("registry");
            if let Some(existing) = guard.sessions.get(node_id)
                && existing.same_channel(&tx)
            {
                guard.sessions.remove(node_id);
            }
        }
        Mode::Tags(current) => {
            register_tags(&registry, session_id, &tx, current, &[]);
        }
    }
    traffic.flush(&registry);
    if revoked {
        close_link(&mut ws, CLOSE_REASON_ADMISSION).await;
    }
    result
}

struct ByteBudget {
    per_second: u64,
    tokens: f64,
    last: Instant,
}

impl ByteBudget {
    fn new(per_second: u64) -> Self {
        ByteBudget {
            per_second,
            tokens: per_second as f64,
            last: Instant::now(),
        }
    }

    fn allow(&mut self, bytes: u64) -> bool {
        if self.per_second == 0 {
            return true;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second as f64).min(self.per_second as f64);
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

fn binary(frame: Frame) -> Message {
    Message::Binary(frame.encode())
}

fn decode_binary(message: &Message) -> Option<Frame> {
    match message {
        Message::Binary(bytes) => Frame::decode(bytes),
        _ => None,
    }
}

/// Convenience for the binary and for tests that want the process to stay up.
pub async fn wait_for_ctrl_c() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use link_core::wire::MAX_DATAGRAM;
    use tokio_tungstenite::tungstenite::protocol::Role;

    #[tokio::test(start_paused = true)]
    async fn a_blocked_registered_write_releases_the_route_on_timeout_and_shutdown() {
        for shutdown in [false, true] {
            // The in-memory peer reads the Welcome, then pauses its reads.
            // One ordinary data frame fills the fixture's small I/O buffer.
            let (relay, peer) = tokio::io::duplex(64);
            let relay = WebSocketStream::from_raw_socket(
                Box::new(relay) as Box<dyn Duplex>,
                Role::Server,
                None,
            )
            .await;
            let mut peer = WebSocketStream::from_raw_socket(peer, Role::Client, None).await;
            let registry: Shared = Arc::default();
            let (stop, stop_rx) = watch::channel(false);
            let tag = Tag([7; TAG_BYTES]);
            let mut session = tokio::spawn(serve_registration(
                relay,
                [0; 32],
                binary(Frame::Register { tags: vec![tag] }),
                Arc::new(RelayConfig::default()),
                registry.clone(),
                stop_rx,
                None,
            ));
            let welcome = peer.next().await.unwrap().unwrap();
            assert!(matches!(decode_binary(&welcome), Some(Frame::Welcome(_))));
            registry.lock().unwrap().tags[&tag][0]
                .1
                .try_send(Frame::RecvTag {
                    tag,
                    datagram: vec![0; MAX_DATAGRAM],
                })
                .unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(1), &mut session)
                    .await
                    .is_err()
            );
            assert!(registry.lock().unwrap().tags.contains_key(&tag));

            let limit = if shutdown {
                stop.send(true).unwrap();
                CLOSE_TIMEOUT
            } else {
                WRITE_TIMEOUT
            };
            let result = tokio::time::timeout(limit + Duration::from_millis(100), session)
                .await
                .expect("registered connection stopped within its write deadline")
                .unwrap();
            if shutdown {
                result.unwrap();
            } else {
                assert!(result.unwrap_err().is::<tokio::time::error::Elapsed>());
            }
            assert!(!registry.lock().unwrap().tags.contains_key(&tag));
        }
    }
}
