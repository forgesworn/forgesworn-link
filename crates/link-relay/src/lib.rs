//! `link-relay`: the WebSocket datagram relay and the UDP reflector of spec
//! section 3, plus the tag-mode sessions of spec section 9.  One self-hostable
//! binary, two services, no persistence.
//!
//! A session speaks one of two modes, chosen by its first frame.  An identity
//! session authenticates a node ID and routes by it (spec 3.1, the deployed
//! behaviour).  A tag session registers pair-scoped rendezvous tags and routes
//! by them (spec 9): no node ID, no Nostr key and no signature ever reach the
//! relay on that path, and the relay never logs a tag.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use link_core::id::NodeId;
use link_core::rendezvous::Tag;
use link_core::wire::{
    CLOSE_REASON_MALFORMED, CLOSE_REASON_SUPERSEDED, Frame, IDLE_CLOSE_SECONDS, MAX_QUEUED_FRAMES,
    REFLECT_REQUEST_BYTES, parse_reflect_request, reflect_reply, verify_relay_auth,
};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

/// Anything the relay can speak WebSocket over: plain TCP or TLS.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

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

#[derive(Clone, Debug)]
pub struct TlsMaterial {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
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
}

type Shared = Arc<Mutex<Registry>>;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Start both services.  Returns once the sockets are bound.
pub async fn start(config: RelayConfig) -> anyhow::Result<RelayHandle> {
    let listener = TcpListener::bind(config.ws_bind).await?;
    let ws_addr = listener.local_addr()?;
    let udp = Arc::new(UdpSocket::bind(config.udp_bind).await?);
    let udp_addr = udp.local_addr()?;
    let (stop, _) = watch::channel(false);
    let tls_fingerprint = config.tls.as_ref().map(TlsMaterial::fingerprint);

    let acceptor = match &config.tls {
        Some(material) => Some(build_acceptor(material)?),
        None => None,
    };

    let registry: Shared = Arc::new(Mutex::new(Registry::default()));
    let config = Arc::new(config);

    // WebSocket accept loop.
    {
        let registry = registry.clone();
        let config = config.clone();
        let mut stop_rx = stop.subscribe();
        let session_stop = stop.subscribe();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = stop_rx.changed() => break,
                    accepted = listener.accept() => accepted,
                };
                let (stream, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        warn!(error = %e, "relay accept failed");
                        continue;
                    }
                };
                let source_ip = peer.ip();
                {
                    let mut guard = registry.lock().expect("registry");
                    if guard.live >= config.max_sessions {
                        debug!(
                            live = guard.live,
                            "relay at session cap, dropping connection"
                        );
                        continue;
                    }
                    let from_source = guard.by_source.get(&source_ip).copied().unwrap_or(0);
                    if config.max_sessions_per_source > 0
                        && from_source >= config.max_sessions_per_source
                    {
                        // Refused before any frame, so it costs the relay a
                        // TCP accept and nothing else.  The address is not
                        // logged: it is the one thing a tag-mode relay holds.
                        debug!(
                            from_source,
                            "relay at per-source session cap, dropping connection"
                        );
                        continue;
                    }
                    *guard.by_source.entry(source_ip).or_insert(0) += 1;
                    guard.live += 1;
                }
                let registry = registry.clone();
                let config = config.clone();
                let acceptor = acceptor.clone();
                let stop_rx = session_stop.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        serve_session(stream, peer, acceptor, config, registry.clone(), stop_rx)
                            .await
                    {
                        debug!(error = %e, "relay session ended");
                    }
                    let mut guard = registry.lock().expect("registry");
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
                    Err(e) => {
                        warn!(error = %e, "reflector recv failed");
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

    info!(%ws_addr, %udp_addr, "relay listening");
    Ok(RelayHandle {
        ws_addr,
        udp_addr,
        tls_fingerprint,
        stop,
    })
}

fn build_acceptor(material: &TlsMaterial) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let cert = CertificateDer::from(material.cert_der.clone());
    let key = PrivateKeyDer::try_from(material.key_der.clone())
        .map_err(|e| anyhow::anyhow!("relay key: {e}"))?;
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

async fn serve_session(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    config: Arc<RelayConfig>,
    registry: Shared,
    mut stop_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    stream.set_nodelay(true).ok();
    let transport: Box<dyn Duplex> = match acceptor {
        Some(acceptor) => Box::new(acceptor.accept(stream).await?),
        None => Box::new(stream),
    };
    let mut ws = tokio_tungstenite::accept_async(transport).await?;

    // First contact.  The relay always issues a challenge; an identity session
    // answers it with a signature (spec 3.1), a tag session ignores it and
    // registers its tags instead (spec 9), so no identity ever reaches the tag
    // path.
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    ws.send(binary(Frame::Challenge(challenge))).await?;

    let first = tokio::time::timeout(Duration::from_secs(10), ws.next())
        .await
        .map_err(|_| anyhow::anyhow!("first frame timed out"))?
        .ok_or_else(|| anyhow::anyhow!("closed before the first frame"))??;

    let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    // Bounded outbound queue, spec 3.1: at most 64 queued frames per session.
    let (tx, mut rx) = mpsc::channel::<Frame>(MAX_QUEUED_FRAMES);

    let mut mode = match decode_binary(&first) {
        Some(Frame::Auth { node_id, signature }) => {
            let ok = config
                .hosts
                .iter()
                .any(|host| verify_relay_auth(&node_id, host, &challenge, &signature));
            if !ok {
                let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
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
            Mode::Identity(node_id)
        }
        Some(Frame::Register { tags }) => {
            register_tags(&registry, session_id, &tx, &[], &tags);
            Mode::Tags(tags)
        }
        _ => {
            let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
            anyhow::bail!("first frame was not an auth or a register");
        }
    };

    let mut token = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let token_hex = hex_lower(&token);
    ws.send(binary(Frame::Welcome(token))).await?;
    // Tokens and counters only in the journal, spec 3.1: no node ID, no tag,
    // and no source address at info, so an operator running at info holds no
    // address ledger.  The source stays visible at debug for local diagnosis.
    info!(token = %token_hex, "relay session up");
    debug!(token = %token_hex, source = %peer.ip(), "relay session source");

    let mut last_ping = Instant::now();
    let mut idle_check = tokio::time::interval(Duration::from_secs(5));
    idle_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut budget = ByteBudget::new(config.bytes_per_second);
    let mut frames_in = 0u64;
    let mut frames_out = 0u64;
    let mut bytes_in = 0u64;
    let mut dropped = 0u64;

    let result: anyhow::Result<()> = loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                let _ = ws.send(binary(Frame::Close(0))).await;
                break Ok(());
            }
            _ = idle_check.tick() => {
                if last_ping.elapsed() > Duration::from_secs(IDLE_CLOSE_SECONDS) {
                    let _ = ws.send(binary(Frame::Close(0))).await;
                    break Err(anyhow::anyhow!("idle"));
                }
            }
            outbound = rx.recv() => {
                match outbound {
                    Some(frame) => {
                        frames_out += 1;
                        let closing = matches!(frame, Frame::Close(_));
                        ws.send(binary(frame)).await?;
                        if closing {
                            // A queued Close means a newer registration
                            // superseded this session; the frame said why and
                            // there is nothing left to route.
                            break Err(anyhow::anyhow!("superseded"));
                        }
                    }
                    None => break Ok(()),
                }
            }
            incoming = ws.next() => {
                let Some(message) = incoming else { break Ok(()) };
                let message = message?;
                match message {
                    Message::Binary(_) => {}
                    Message::Ping(p) => { ws.send(Message::Pong(p)).await?; continue }
                    Message::Pong(_) => continue,
                    Message::Close(_) => break Ok(()),
                    // Text and continuation frames are malformed for this protocol.
                    _ => {
                        let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
                        break Err(anyhow::anyhow!("non-binary frame"));
                    }
                }
                let Some(frame) = decode_binary(&message) else {
                    let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
                    break Err(anyhow::anyhow!("oversize or malformed frame"));
                };
                frames_in += 1;
                match frame {
                    Frame::Send { destination, datagram } => {
                        let Mode::Identity(node_id) = &mode else {
                            let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
                            break Err(anyhow::anyhow!("identity frame on a tag session"));
                        };
                        let source = *node_id;
                        bytes_in += datagram.len() as u64;
                        if !budget.allow(datagram.len() as u64) {
                            dropped += 1;
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
                                    dropped += 1;
                                }
                            }
                            None => dropped += 1,
                        }
                    }
                    Frame::SendTag { tag, datagram } => {
                        if !matches!(mode, Mode::Tags(_)) {
                            let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
                            break Err(anyhow::anyhow!("tag frame on an identity session"));
                        }
                        bytes_in += datagram.len() as u64;
                        if !budget.allow(datagram.len() as u64) {
                            dropped += 1;
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
                            dropped += 1;
                        } else {
                            for target in targets {
                                if target
                                    .try_send(Frame::RecvTag { tag, datagram: datagram.clone() })
                                    .is_err()
                                {
                                    dropped += 1;
                                }
                            }
                        }
                    }
                    Frame::Register { tags: next } => {
                        let Mode::Tags(current) = &mode else {
                            let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
                            break Err(anyhow::anyhow!("register on an identity session"));
                        };
                        register_tags(&registry, session_id, &tx, current, &next);
                        mode = Mode::Tags(next);
                    }
                    Frame::Ping(opaque) => {
                        last_ping = Instant::now();
                        ws.send(binary(Frame::Pong(opaque))).await?;
                    }
                    Frame::Pong(_) => last_ping = Instant::now(),
                    Frame::Close(_) => break Ok(()),
                    // A client may only send, register, ping, pong or close.
                    _ => {
                        let _ = ws.send(binary(Frame::Close(CLOSE_REASON_MALFORMED))).await;
                        break Err(anyhow::anyhow!("unexpected frame from client"));
                    }
                }
            }
        }
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
    info!(
        token = %token_hex,
        frames_in,
        frames_out,
        bytes_in,
        dropped,
        "relay session down"
    );
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
